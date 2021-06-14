/*
	Copyright (c) 2020-2021 Technica Engineering GmbH
	GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
*/

#include <array>
#include <codecvt>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <locale>
#include <map>
#include <sstream>

#include <tecmp/tecmp.h>
#include <light_pcapng_ext.h>
#include "endianness.h"
#include "pcap.h"

#define NANOS_PER_SEC 1000000000
#define LINKTYPE_ETHERNET 1 
#define LINKTYPE_CAN_SOCKETCAN 227 

#define DIR_IN    1
#define DIR_OUT   2
#define PCAP_NG_MAGIC_NUMBER 0x0A0D0D0A
#define PCAP_MAGIC_NUMBER 0xA1B2C3D4
#define PCAP_MAGIC_NUMBER_LITTLE_ENDIAN 0xD4C3B2A1

#if _WIN32
#define strdup _strdup
#endif

char* get_interface_name(uint32_t channel_id) {
	std::stringstream sstream;
	sstream << std::hex << channel_id;
	std::string hex_channel = sstream.str();
	char* tmp = strdup(hex_channel.c_str());
	return tmp;
}

int main(int argc, char* argv[]) {
	if (argc != 3) {
		fprintf(stderr, "Usage %s [infile] [outfile]\n", argv[0]);
		return 1;
	}
	// determine file type
	int x;
	std::ifstream file_check;
	file_check.open(argv[1], std::ios::binary | std::ios::in);
	file_check.read((char*)&x, 4);
	file_check.close();

	if (x == PCAP_NG_MAGIC_NUMBER) {
		light_pcapng infile = light_pcapng_open(argv[1], "rb");
		if (!infile) {
			fprintf(stderr, "Unable to open: %s\n", argv[1]);
			return 1;
		}

		light_pcapng outfile = light_pcapng_open(argv[2], "wb");
		if (!outfile) {
			fprintf(stderr, "Unable to open: %s\n", argv[2]);
			return 1;
		}
		// the packet 
		light_packet_interface packet_interface = { 0 };
		light_packet_header packet_header = { 0 };
		const uint8_t* packet_data = nullptr;

		while (light_read_packet(infile, &packet_interface, &packet_header, &packet_data)) {
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
					// append packet_interface info
					char* interface_name = get_interface_name(header.channel_id);
					packet_interface.name = interface_name;
					packet_interface.description = interface_name;
					packet_interface.timestamp_resolution = NANOS_PER_SEC;
					packet_header.timestamp = tecmp_get_timespec(header);

					// append packet_header info
					// in case of can or ethernet packets, drop tecmp header
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
					free(interface_name);
				}
			}
		}

		light_pcapng_close(infile);
		light_pcapng_close(outfile);
	}
	else if (x == PCAP_MAGIC_NUMBER || x == PCAP_MAGIC_NUMBER_LITTLE_ENDIAN) {
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_t* infile = pcap_open_offline(argv[1], errbuf);
		int link_layer = pcap_datalink(infile);
		if (!infile) {
			fprintf(stderr, "Unable to open: %s\n", argv[1]);
			return 1;
		}

		light_pcapng outfile = light_pcapng_open(argv[2], "wb");
		if (!outfile) {
			fprintf(stderr, "Unable to open: %s\n", argv[2]);
			return 1;
		}
		// the packet
		pcap_pkthdr pkthdr;
		const uint8_t* pPacketData = pcap_next(infile, &pkthdr);
		while (pPacketData) {
			// data
			uint8_t* pMyPacketData = new uint8_t[pkthdr.caplen];
			memcpy(pMyPacketData, pPacketData, pkthdr.caplen);
			// light pcapng packet
			light_packet_interface packet_interface = { 0 };
			light_packet_header packet_header = { 0 };
			packet_interface.link_type = link_layer;
			packet_header.captured_length = pkthdr.caplen;
			packet_header.original_length = pkthdr.len;
			packet_header.timestamp.tv_sec = pkthdr.ts.tv_sec;
			packet_header.timestamp.tv_nsec = pkthdr.ts.tv_usec * 1000;
			// tecmp packet
			int32_t iterator = 0;
			tecmp_header header;
			uint8_t* data;
			int res = tecmp_next(pMyPacketData, pkthdr.caplen, &iterator, &header, &data);
			if (res == EINVAL) {
				// not a tecmp packet, copy it as it is
				light_write_packet(outfile, &packet_interface, &packet_header, pMyPacketData);
			}
			else {
				// tecmp packet
				while (res == 0) {
					// append packet_interface info
					char* interface_name = get_interface_name(header.channel_id);
					packet_interface.name = interface_name;
					packet_interface.description = interface_name;
					packet_interface.timestamp_resolution = NANOS_PER_SEC;
					packet_header.timestamp = tecmp_get_timespec(header);

					// append packet_header info
					// in case of can or ethernet packets, drop tecmp header
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
					else if (header.data_type == TECMP_DATA_ETHERNET)
					{
						packet_interface.link_type = LINKTYPE_ETHERNET;
						packet_header.captured_length = header.length;
						packet_header.original_length = header.length;
						light_write_packet(outfile, &packet_interface, &packet_header, data);
					}
					else {
						light_write_packet(outfile, &packet_interface, &packet_header, pMyPacketData);
					}
					res = tecmp_next(pMyPacketData, packet_header.captured_length, &iterator, &header, &data);
					free(interface_name);
				}
			}
			pPacketData = pcap_next(infile, &pkthdr);
		}
	}
	else {
		fprintf(stderr, "Not valid input file: %s\n", argv[1]);
		return 1;
	}
	return 0;
}
