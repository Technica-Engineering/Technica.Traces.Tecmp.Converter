/*
	Copyright (c) 2020-2021 Technica Engineering GmbH
	GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
*/
#include <iostream>
#include <fstream>
#include <nlohmann/json.hpp>
#include "pcapng_exporter/endianness.h"
#include "pcapng_exporter/linktype.h"
#include "pcapng_exporter/lin.h"
#include "pcapng_exporter/pcapng_exporter.hpp"

namespace pcapng_exporter {

	// JSON parsing logic
	void from_json(const nlohmann::json& j, channel_info& i)
	{
		if (j.contains("chl_id")) {
			auto chl_id = j.at("chl_id");
			if (chl_id.is_string()) {
				i.chl_id = std::stoull(chl_id.get<std::string>(), nullptr, 0);
			}
			else {
				i.chl_id = chl_id.get<std::uint32_t>();
			}
		}
		if (j.contains("inf_name")) {
			i.inf_name = j.at("inf_name").get<std::string>();
		}
		if (j.contains("direction")) {
			i.direction = j.at("direction").get<std::string>();
		}
	}

	void to_json(nlohmann::json& j, const channel_info& i)
	{
		throw std::logic_error("Not Implemented");
	}

	NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(channel_mapping, when, change)

}

char* new_str(const std::string str) {
	char* writable = new char[str.size() + 1];
	std::copy(str.begin(), str.end(), writable);
	writable[str.size()] = '\0';
	return writable;
}

namespace pcapng_exporter {

	PcapngExporter::PcapngExporter(std::string pcapng_file, std::string mapping_file) {
		if (!mapping_file.empty()) {
			std::ifstream ifs(mapping_file);
			nlohmann::json jm = nlohmann::json::parse(ifs);
			auto version = jm.at("version").get<uint16_t>();
			if (version != 1) {
				throw std::invalid_argument("Invalid mapping version");
			}
			mappings = jm.at("mappings").get<std::vector<channel_mapping>>();
		}
		file = light_pcapng_open(pcapng_file.c_str(), "wb");
		if (!file) {
			throw std::invalid_argument((std::string("Unable to open: ") + pcapng_file).c_str());
		}
	}

	void PcapngExporter::write_packet(
		uint32_t channel_id,
		const light_packet_interface packet_interface,
		light_packet_header packet_header,
		const uint8_t* packet_data
	)
	{
		light_packet_interface inf = packet_interface;
		channel_info info = mapping_resolve(this->mappings, inf, channel_id);
		char* inf_name = new_str(info.inf_name.value());
		// append packet_interface info
		inf.name = inf_name;
		inf.description = inf_name;
		int dir = 0;
		if (info.direction == "Tx") {
			dir = 2;
		}
		else if (info.direction == "Rx") {
			dir = 1;
		}
		packet_header.flags = (packet_header.flags & 0xfffffffc) + dir;
		this->write_packet(inf, packet_header, packet_data);
		delete[] inf_name;
	}

	void PcapngExporter::write_frame(
		frame_header header,
		uint16_t link_type,
		const std::vector<uint8_t> frame
	)
	{
		light_packet_interface inf_header = { 0 };
		inf_header.timestamp_resolution = header.timestamp_resolution;
		inf_header.link_type = link_type;

		light_packet_header pkt_header = { 0 };

		uint32_t cap_len = frame.size();
		pkt_header.captured_length = cap_len;
		pkt_header.original_length = cap_len;
		pkt_header.timestamp = header.timestamp;
		pkt_header.flags = header.flags;
		pkt_header.comment = header.comment;

		this->write_packet(header.channel_id, inf_header, pkt_header, frame.data());
	}

	void PcapngExporter::write_ethernet(frame_header header, const std::vector<uint8_t> frame)
	{
		this->write_frame(header, LINKTYPE_ETHERNET, frame);
	}

	void PcapngExporter::write_packet(
		const light_packet_interface packet_interface,
		const light_packet_header packet_header,
		const uint8_t* packet_data
	)
	{
		light_write_packet(this->file, &packet_interface, &packet_header, packet_data);
	}

	void PcapngExporter::write_lin(
		const frame_header header,
		const lin_frame frame
	)
	{
		size_t len = sizeof(lin_frame) - 8 + frame.payload_length;
		uint8_t* ptr = (uint8_t*)&frame;
		std::vector<uint8_t> data(ptr, ptr + len);
		this->write_frame(header, LINKTYPE_LIN, data);
	}

	void PcapngExporter::write_can(frame_header header, const canfd_frame frame)
	{
		canfd_frame can = frame;
		size_t len = sizeof(canfd_frame) - 64 + can.len;
		can.can_id = hton32(can.can_id);
		uint8_t* ptr = (uint8_t*)&can;
		std::vector<uint8_t> data(ptr, ptr + len);
		this->write_frame(header, LINKTYPE_CAN, data);
	}

	void PcapngExporter::close()
	{
		light_pcapng_close(this->file);
	}

}