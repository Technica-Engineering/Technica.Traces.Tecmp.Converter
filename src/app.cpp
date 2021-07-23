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
#include "endianness.h"
#include "lin.h"
#include "pcap.h"
#include "mapping.hpp"
#include <args.hxx>
#include <nlohmann/json.hpp>

#define NANOS_PER_SEC 1000000000
#define LINKTYPE_ETHERNET 1 
#define LINKTYPE_CAN_SOCKETCAN 227 
#define LINKTYPE_LIN 212 

#define DIR_IN    1
#define DIR_OUT   2
#define PCAP_NG_MAGIC_NUMBER 0x0A0D0D0A
#define PCAP_MAGIC_NUMBER 0xA1B2C3D4
#define PCAP_MAGIC_NUMBER_LITTLE_ENDIAN 0xD4C3B2A1

#if _WIN32
#define strdup _strdup
#endif

char* new_str(const std::string str) {
	char* writable = new char[str.size() + 1];
	std::copy(str.begin(), str.end(), writable);
	writable[str.size()] = '\0';
	return writable;
}

void transform(
	const light_pcapng outfile,
	light_packet_interface packet_interface,
	light_packet_header packet_header,
	const uint8_t* packet_data,
	std::vector<channel_mapping> mappings
) {
	int32_t iterator = 0;
	tecmp_header header;
	uint8_t* data;
	int res = tecmp_next(packet_data, packet_header.captured_length, &iterator, &header, &data);
	if (res == EINVAL) {
		// not a tecmp packet, copy it as it is
		light_write_packet(outfile, &packet_interface, &packet_header, packet_data);
	}
	else {
		// tecmp packet
		while (res == 0) {
			channel_info info = mapping_resolve(mappings, packet_interface, header);
			char* inf_name = new_str(info.inf_name.value());
			// append packet_interface info
			packet_interface.name = inf_name;
			packet_interface.description = inf_name;
			packet_interface.timestamp_resolution = NANOS_PER_SEC;
			packet_header.timestamp = tecmp_get_timespec(header);

			// append packet_header info
			// in case of can, lin or ethernet packets, drop tecmp header
			if (header.data_type == TECMP_DATA_CAN || header.data_type == TECMP_DATA_CANFD) {
				packet_interface.link_type = LINKTYPE_CAN_SOCKETCAN;
				const uint8_t can_length = data[4];
				packet_header.captured_length = can_length + 8;
				packet_header.original_length = can_length + 8;
				uint8_t can_data[72] = { 0 };
				memcpy(can_data, data, 5);
				uint8_t reserved[3] = { 0,0,0 };
				memcpy(can_data + 5, reserved, 3);
				memcpy(can_data + 8, data + 5, can_length);
				light_write_packet(outfile, &packet_interface, &packet_header, can_data);
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
				packet_interface.link_type = LINKTYPE_LIN;
				uint8_t lin_length = sizeof(lin_frame) + len - 8;
				packet_header.captured_length = lin_length;
				packet_header.original_length = lin_length;
				light_write_packet(outfile, &packet_interface, &packet_header, (uint8_t*)&lin);
			}
			else if (header.data_type == TECMP_DATA_ETHERNET)
			{
				packet_interface.link_type = LINKTYPE_ETHERNET;
				packet_header.captured_length = header.length;
				packet_header.original_length = header.length;
				light_write_packet(outfile, &packet_interface, &packet_header, data);
			}
			else {
				light_write_packet(outfile, &packet_interface, &packet_header, packet_data);
			}
			res = tecmp_next(packet_data, packet_header.captured_length, &iterator, &header, &data);
			delete[] inf_name;
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
	std::vector<channel_mapping> mappings;
	if (maparg) {
		std::ifstream ifs(maparg.Get());
		nlohmann::json jm = nlohmann::json::parse(ifs);
		auto version = jm.at("version").get<uint16_t>();
		if (version != 1) {
			std::cerr << "Invalid mapping version" << std::endl;
			return 1;
		}
		mappings = jm.at("mappings").get<std::vector<channel_mapping>>();
	}
	// determine file type
	int x;
	std::ifstream file_check;
	file_check.open(args::get(inarg), std::ios::binary | std::ios::in);
	file_check.read((char*)&x, 4);
	file_check.close();

	if (x == PCAP_NG_MAGIC_NUMBER) {
		light_pcapng infile = light_pcapng_open(args::get(inarg).c_str(), "rb");
		if (!infile) {
			std::cerr << "Unable to open: " << args::get(inarg) << std::endl;
			return 1;
		}

		light_pcapng outfile = light_pcapng_open(args::get(outarg).c_str(), "wb");
		if (!outfile) {
			std::cerr << "Unable to open: " << args::get(outarg) << std::endl;
			return 1;
		}
		// the packet 
		light_packet_interface packet_interface = { 0 };
		light_packet_header packet_header = { 0 };
		const uint8_t* packet_data = nullptr;

		while (light_read_packet(infile, &packet_interface, &packet_header, &packet_data)) {
			transform(outfile, packet_interface, packet_header, packet_data, mappings);
		}

		light_pcapng_close(infile);
		light_pcapng_close(outfile);
	}
	else if (x == PCAP_MAGIC_NUMBER || x == PCAP_MAGIC_NUMBER_LITTLE_ENDIAN) {
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_t* infile = pcap_open_offline(args::get(inarg).c_str(), errbuf);
		int link_layer = pcap_datalink(infile);
		if (!infile) {
			std::cerr << "Unable to open: " << args::get(inarg) << std::endl;
			return 1;
		}

		light_pcapng outfile = light_pcapng_open(args::get(outarg).c_str(), "wb");
		if (!outfile) {
			std::cerr << "Unable to open: " << args::get(outarg) << std::endl;
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

			transform(outfile, packet_interface, packet_header, packet_data, mappings);

			packet_data = pcap_next(infile, &pkthdr);
		}
	}
	else {
		std::cerr << "Not valid input file: " << args::get(inarg) << std::endl;
		return 1;
	}
	return 0;
}
