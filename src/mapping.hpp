
#ifndef _MAPPING_H
#define _MAPPING_H

#include <nlohmann/json.hpp>
#include <tecmp/tecmp.h>
#include <light_pcapng_ext.h>
#include <optional>

struct channel_info {
	std::optional<std::uint32_t> chl_id = std::nullopt;
	std::optional <std::string> inf_name = std::nullopt;
};

struct channel_mapping {
	channel_info when;
	channel_info change;
};

void from_json(const nlohmann::json& j, channel_info& i);

void to_json(nlohmann::json& j, const channel_info& i);

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(channel_mapping, when, change)

channel_info mapping_resolve(std::vector<channel_mapping> mappings, light_packet_interface packet_interface, tecmp_header header);

#endif