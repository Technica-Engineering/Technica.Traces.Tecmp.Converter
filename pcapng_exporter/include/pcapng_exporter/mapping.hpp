/*
	Copyright (c) 2020-2021 Technica Engineering GmbH
	GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
*/
#ifndef _MAPPING_H
#define _MAPPING_H

#include <stdint.h>
#include <optional>
#include <vector>
#include <string>
#include <light_pcapng_ext.h>

namespace pcapng_exporter {

	struct channel_info {
		std::optional<std::uint32_t> chl_id = std::nullopt;
		std::optional<std::string> inf_name = std::nullopt;
	};

	struct channel_mapping {
		channel_info when;
		channel_info change;
	};

	channel_info mapping_resolve(std::vector<channel_mapping> mappings, light_packet_interface packet_interface, uint32_t channel_id);
}

#endif