/*
	Copyright (c) 2020-2024 Technica Engineering GmbH
	GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
*/

#include <array>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>

#include <tecmp/tecmp.h>
#include <light_pcapng_ext.h>
#include "pcapng_exporter/endianness.h"
#include "pcapng_exporter/lin.h"
#include "pcapng_exporter/linktype.h"
#include "pcapng_exporter/pcapng_exporter.hpp"
#include "pcap.h"
#include <args.hxx>

//AnAm: NOTE: Since the proper flag could not be found in the
// TECMP documentation a temporary variable has been generated
// to provide a temporary logic.
#define TMP_ERROR_NODE_ACTIVE 0x0002
#define TMP_ERROR_MESSAGE 0x0008
#define TMP_BITRATE_SWITCH 0x0010
// The following fields must be shifted by 1 bit in CAN-FD frames
#define TMP_BITSTUFF_ERROR 0x0010
#define TMP_CRC_DEL_ERROR 0x0020
#define TMP_ACK_DEL_ERROR 0x0040
#define TMP_EOF_ERROR 0x0080
// No more bitshifting required
#define TMP_CRC_ERROR 0x2000
#define TMP_OVERFLOW 0x8000
#define NANOS_PER_SEC 1000000000

#define PCAP_NG_MAGIC_NUMBER 0x0A0D0D0A
#define PCAP_MAGIC_NUMBER 0xA1B2C3D4
#define PCAP_MAGIC_NUMBER_LITTLE_ENDIAN 0xD4C3B2A1

using namespace pcapng_exporter;

#if _WIN32
// From https://nmap.org/npcap/guide/npcap-tutorial.html
#include <Windows.h>
#include <tchar.h>
bool LoadNpcapDlls()
{
	TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return false;
	}
	_tcscat_s(npcap_dir, 512, TEXT("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return false;
	}
	return true;
}
#endif

uint32_t create_can_error_frame(uint8_t* data, uint16_t flags, bool is_canfd) {
	uint32_t can_id = 0x20000000;
	int bitshift = is_canfd ? 1 : 0;
	data[2] |= (flags & (TMP_BITSTUFF_ERROR << bitshift)) != 0 ? 0x04 : 0;
	data[3] |= (flags & TMP_CRC_ERROR) != 0 ? 0x08 : 0;
	data[3] |= (flags & (TMP_CRC_DEL_ERROR << bitshift)) != 0 ? 0x18 : 0;
	data[3] |= (flags & (TMP_ACK_DEL_ERROR << bitshift)) != 0 ? 0x1B : 0;
	data[3] |= (flags & (TMP_EOF_ERROR << bitshift)) != 0 ? 0x1A : 0;
	if ((data[2] != 0) || (data[3] != 0)) {
		can_id |= 0x00000008;
	}
	return can_id;
}

void transform(
	PcapngExporter exporter,
	bool tecmp_only,
	bool drop_replay_data,
	light_packet_interface packet_interface,
	light_packet_header packet_header,
	const uint8_t* packet_data
) {
	int32_t iterator = 0;
	tecmp_header header;
	uint8_t* data;
	int res = tecmp_next(packet_data, packet_header.captured_length, &iterator, &header, &data);
	if (res == EINVAL) {
		// not a tecmp packet, copy it as it is
		if (!tecmp_only)
		{
			exporter.write_packet(packet_interface, packet_header, packet_data);
		}
	}
	// if we need to drop replay data
	if (drop_replay_data && header.message_type == TECMP_TYPE_REPLAY_DATA) {
		return;
	}
	// tecmp packet
	while (res == 0) {
		packet_interface.timestamp_resolution = NANOS_PER_SEC;
		packet_header.timestamp = tecmp_get_timespec(header);

		frame_header hdr = { 0 };
		hdr.channel_id = header.channel_id;
		hdr.timestamp_resolution = packet_interface.timestamp_resolution;
		hdr.timestamp = packet_header.timestamp;
		auto tx = (header.data_flags & 0x4000) != 0;
		hdr.flags = tx ? 2 : 1;
		hdr.queue = tx ? 1 : 0;

		// append packet_header info
		// in case of can, lin or ethernet packets, drop tecmp header
		if (header.data_type == TECMP_DATA_CAN || header.data_type == TECMP_DATA_CANFD) {
			struct canfd_frame can = { 0 };
			can.can_id = ntoh32(*((uint32_t*)data));
			if (header.data_type == TECMP_DATA_CANFD)
			{
				can.flags |= CANFD_FDF;
				can.flags |= header.data_flags & TMP_BITRATE_SWITCH ? CANFD_BRS : 0;
				can.flags |= header.data_flags & TMP_ERROR_NODE_ACTIVE ? CANFD_ESI : 0;
			}
			if ((header.data_flags & (TMP_ERROR_MESSAGE | TMP_BITSTUFF_ERROR |
				TMP_ACK_DEL_ERROR | TMP_CRC_DEL_ERROR | TMP_CRC_ERROR | TMP_EOF_ERROR)) != 0) {
				can.len = 8;
				// If the data type is CAN-FD, force the frame to be a Classical CAN error frame
				bool is_canfd = header.data_type == TECMP_DATA_CANFD;

				if (is_canfd) {
					const uint8_t CANFD_TO_CAN_ERROR_MASK = 0x02;
					can.flags &= CANFD_TO_CAN_ERROR_MASK;
				}
				can.can_id = create_can_error_frame(can.data, header.data_flags, is_canfd);
			}
			else {
				can.len = data[4];
				memcpy(can.data, data + 5, can.len);
			}
			exporter.write_can(hdr, can);
		}
		else if (header.data_type == TECMP_DATA_LIN)
		{
			uint8_t len = data[1];
			lin_frame lin;
			lin.pid = data[0];
			lin.payload_length = len;
			if (len) {
				memcpy(lin.data, data + 2, len);
				lin.checksum = data[len + 2];
			}
			else
			{
				lin.errors |= LIN_ERROR_NOSLAVE;
			}
			exporter.write_lin(hdr, lin);
		}
		else if (header.data_type == TECMP_DATA_ETHERNET)
		{
			std::vector<uint8_t>frame(data, data + header.length);
			exporter.write_ethernet(hdr, frame);
		}
		else if (header.data_type == TECMP_DATA_FLEXRAY)
		{
			flexray_frame fr;
			fr.channel = 0;
			fr.err_flags = 0;
			fr.fr_flags =
				(header.data_flags & 1 ? 0 : FR_NFI) |
				(header.data_flags & 2 ? FR_STFI : 0) |
				(header.data_flags & 4 ? FR_SFI : 0) |
				(header.data_flags & 16 ? FR_PPI : 0);

			fr.cc = data[0];
			fr.fid = ntoh16(*((uint16_t*)(data + 1)));
			fr.hcrc = 0;
			uint8_t len = data[3];
			fr.len = len / 2;
			memcpy(fr.data, data + 4, len);

			exporter.write_flexray(hdr, fr);
		}
		else
		{
			exporter.write_packet(header.channel_id, packet_interface, packet_header, packet_data);
		}
		res = tecmp_next(packet_data, packet_header.captured_length, &iterator, &header, &data);

	}
}

int main(int argc, char* argv[]) {

#if _WIN32
	LoadNpcapDlls();
#endif

	args::ArgumentParser parser("This tool is intended for converting TECMP packets to plain PCAPNG packets.");
	parser.helpParams.showTerminator = false;
	parser.helpParams.proglineShowFlags = true;

	args::HelpFlag help(parser, "help", "", { 'h', "help" }, args::Options::HiddenFromUsage);
	args::ValueFlag<std::string> maparg(parser, "map-file", "Configuration file for channel mapping", { "channel-map" });

	args::Positional<std::string> inarg(parser, "infile", "Input File", args::Options::Required);
	args::Positional<std::string> outarg(parser, "outfile", "Output File", args::Options::Required);
	args::Flag tecmp_only(parser, "tecmp-only", "Only process TECMP packets, drop others", { "tecmp-only" }, args::Options::Single);
	args::Flag drop_replay_data(parser, "drop-replay-data", "Drop replay data messages", { "drop-replay-data" }, args::Options::Single);

	try
	{
		parser.ParseCLI(argc, argv);
	}
	catch (args::Help)
	{
		std::cout << parser;
		return 0;
	}
	catch (args::Error e)
	{
		std::cerr << e.what() << std::endl;
		std::cerr << parser;
		return 1;
	}
	// determine file type
	int magic = 0;
	std::ifstream file_check;
	file_check.open(args::get(inarg), std::ios::binary | std::ios::in);
	file_check.read((char*)&magic, 4);
	file_check.close();

	PcapngExporter exporter = PcapngExporter(args::get(outarg), maparg.Get());

	if (magic == PCAP_NG_MAGIC_NUMBER) {
		light_pcapng infile = light_pcapng_open(args::get(inarg).c_str(), "rb");
		if (!infile) {
			std::cerr << "Unable to open: " << args::get(inarg) << std::endl;
			return 1;
		}

		// the packet 
		light_packet_interface packet_interface = { 0 };
		light_packet_header packet_header = { 0 };
		const uint8_t* packet_data = nullptr;

		while (light_read_packet(infile, &packet_interface, &packet_header, &packet_data)) {
			transform(exporter, tecmp_only.Get(), drop_replay_data.Get(), packet_interface, packet_header, packet_data);
		}

		light_pcapng_close(infile);
	}
	else if (magic == PCAP_MAGIC_NUMBER || magic == PCAP_MAGIC_NUMBER_LITTLE_ENDIAN) {
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_t* infile = pcap_open_offline(args::get(inarg).c_str(), errbuf);
		int link_layer = pcap_datalink(infile);
		if (!infile) {
			std::cerr << "Unable to open: " << args::get(inarg) << std::endl;
			return 1;
		}
		// the packet
		pcap_pkthdr pkthdr;
		const uint8_t* packet_data = pcap_next(infile, &pkthdr);
		while (packet_data) {
			// light pcapng packet
			light_packet_interface packet_interface = { 0 };
			light_packet_header packet_header = { 0 };
			packet_interface.link_type = link_layer;
			packet_header.captured_length = pkthdr.caplen;
			packet_header.original_length = pkthdr.len;
			packet_header.timestamp.tv_sec = pkthdr.ts.tv_sec;
			packet_header.timestamp.tv_nsec = pkthdr.ts.tv_usec * 1000;

			transform(exporter, tecmp_only.Get(), drop_replay_data.Get(), packet_interface, packet_header, packet_data);

			packet_data = pcap_next(infile, &pkthdr);
		}
	}
	else {
		exporter.close();
		std::remove(args::get(outarg).c_str());
		std::cerr << "Not valid input file: " << args::get(inarg) << std::endl;
		return 1;
	}
	return 0;
}
