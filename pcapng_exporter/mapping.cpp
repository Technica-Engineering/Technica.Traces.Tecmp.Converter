/*
	Copyright (c) 2020-2021 Technica Engineering GmbH
	GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
*/
#include "pcapng_exporter/mapping.hpp"
#include <sstream>

template <class T>
void merge_value(
	std::optional<T>* value,
	std::optional<T> change
) {
	if (change.has_value()) {
		*value = change;
	}
}

namespace pcapng_exporter {

	std::string get_interface_name(uint32_t channel_id) {
		channel_info info;
		info.chl_id = channel_id;
		std::stringstream sstream;
		sstream << std::hex << channel_id;

		std::string hex_channel = sstream.str();
		for (auto& c : hex_channel) {
			c = toupper(c);
		}
		return hex_channel;
	}

	bool mapping_match(channel_info target, channel_info when) {
		if (when.chl_id.has_value() && when.chl_id != target.chl_id) {
			return false;
		}
		if (when.inf_name.has_value() && when.inf_name != target.inf_name) {
			return false;
		}
		if (when.pkt_dir.has_value() && when.pkt_dir != target.pkt_dir){
			return false;
		}
		return true;
	}

	channel_info mapping_resolve(std::vector<channel_mapping> mappings, light_packet_interface packet_interface, light_packet_header packet_header, uint32_t channel_id) {
		// What to test against
		channel_info target;
		target.chl_id = channel_id;
		target.inf_name = packet_interface.name
			? std::optional(std::string(packet_interface.name))
			: std::nullopt;
		target.pkt_dir = (pkt_dir_enum)(packet_header.flags & 0x00000003);
		// Result
		channel_info result;
		result.chl_id = channel_id;
		for (channel_mapping mapping : mappings) {
			if (mapping_match(target, mapping.when)) {
				merge_value(&result.chl_id, mapping.change.chl_id);
				merge_value(&result.inf_name, mapping.change.inf_name);
				merge_value(&result.pkt_dir, mapping.change.pkt_dir);
				break;
			}
		}
		if (!result.inf_name.has_value()) {
			result.inf_name = get_interface_name(channel_id);
		}
		return result;
	}
}