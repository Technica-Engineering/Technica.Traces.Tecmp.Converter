/*
	Copyright (c) 2020-2021 Technica Engineering GmbH
	GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
*/

#ifndef _PCAPNG_EXPORTER_H
#define _PCAPNG_EXPORTER_H

#include <string>
#include <vector>
#include <stdint.h>
#include <light_pcapng_ext.h>
#include "mapping.hpp"
#include "pcapng_exporter/can.h"

namespace pcapng_exporter {

	typedef struct frame_header {
		uint32_t channel_id;
		uint64_t timestamp_resolution;
		struct timespec timestamp;

		char* comment;
		uint32_t flags;
		uint32_t queue;
	} packet_header;

	class PcapngExporter {
	private:
		light_pcapng file;
		std::vector<channel_mapping> mappings;
	public:
		PcapngExporter(std::string pcapng_file, std::string mapping_file);

		void write_packet(
			const light_packet_interface packet_interface,
			const light_packet_header packet_header,
			const uint8_t* packet_data
		);

		void write_packet(
			uint32_t channel_id,
			const light_packet_interface packet_interface,
			const light_packet_header packet_header,
			const uint8_t* packet_data
		);

		void write_frame(frame_header header, uint16_t link_type, const std::vector<uint8_t> frame);

		void write_ethernet(frame_header header, const std::vector<uint8_t> frame);

		void write_lin(frame_header header, const lin_frame frame);

		void write_can(frame_header header, const canfd_frame frame);

		void close();
	};

}

#endif