/*
	Copyright (c) 2020-2021 Technica Engineering GmbH
	GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
*/

#include <array>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>

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

void transform(
	PcapngExporter exporter,
	light_packet_interface packet_interface,
	light_packet_header packet_header,
	const uint8_t* packet_data
) {
	char *data;
	memcpy(data,packet_data,packet_header.captured_length);
	if (data[12] == 0x99 && data[13] == 0xFE)
	{
		data[12] = 0x20;
		data[13] = 0x90;
	}
	exporter.write_packet(packet_interface, packet_header, packet_data);
}

int main(int argc, char* argv[]) {

#if _WIN32
	LoadNpcapDlls();
#endif

	args::ArgumentParser parser("This tool is intended for converting TECMP packets to plain PCAPNG packets.");
	parser.helpParams.showTerminator = false;
	parser.helpParams.proglineShowFlags = true;

	args::HelpFlag help(parser, "help", "", { 'h', "help" }, args::Options::HiddenFromUsage);

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

	PcapngExporter exporter = PcapngExporter(args::get(outarg), "");

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
