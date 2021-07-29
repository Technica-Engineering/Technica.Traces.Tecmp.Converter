/*
	Copyright (c) 2020-2021 Technica Engineering GmbH
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

#define NANOS_PER_SEC 1000000000

#define PCAP_NG_MAGIC_NUMBER 0x0A0D0D0A
#define PCAP_MAGIC_NUMBER 0xA1B2C3D4
#define PCAP_MAGIC_NUMBER_LITTLE_ENDIAN 0xD4C3B2A1

using namespace pcapng_exporter;

void transform(
	PcapngExporter exporter,
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
		exporter.write_packet(packet_interface, packet_header, packet_data);
	}
	else {
		// tecmp packet
		while (res == 0) {
			packet_interface.timestamp_resolution = NANOS_PER_SEC;
			packet_header.timestamp = tecmp_get_timespec(header);

			frame_header hdr = { 0 };
			hdr.channel_id = header.channel_id;
			hdr.timestamp_resolution = packet_interface.timestamp_resolution;
			hdr.timestamp = packet_header.timestamp;

			// append packet_header info
			// in case of can, lin or ethernet packets, drop tecmp header
			if (header.data_type == TECMP_DATA_CAN || header.data_type == TECMP_DATA_CANFD) {
				struct canfd_frame can = { 0 };
				can.can_id = ntoh32(*((uint32_t*)data));
				can.len = data[4];
				memcpy(can.data, data + 5, can.len);
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
			else
			{
				exporter.write_packet(header.channel_id, packet_interface, packet_header, packet_data);
			}
			res = tecmp_next(packet_data, packet_header.captured_length, &iterator, &header, &data);

		}
	}
}

int main(int argc, char* argv[]) {

	args::ArgumentParser parser("This tool is intended for converting TECMP packets to plain PCAPNG packets.");
	parser.helpParams.showTerminator = false;
	parser.helpParams.proglineShowFlags = true;

	args::HelpFlag help(parser, "help", "", { 'h', "help" }, args::Options::HiddenFromUsage);
	args::ValueFlag<std::string> maparg(parser, "map-file", "Configuration file for channel mapping", { "channel-map" });

	args::Positional<std::string> inarg(parser, "infile", "Input File", args::Options::Required);
	args::Positional<std::string> outarg(parser, "outfile", "Output File", args::Options::Required);

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
			transform(exporter, packet_interface, packet_header, packet_data);
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

			transform(exporter, packet_interface, packet_header, packet_data);

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
