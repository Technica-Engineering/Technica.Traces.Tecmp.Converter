
#include "mapping.hpp"
#include <sstream>

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
	return true;
}

template <class T>
void merge_value(
	std::optional<T>* value,
	std::optional<T> change
) {
	if (change.has_value()) {
		*value = change;
	}
}

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
}

void to_json(nlohmann::json& j, const channel_info& i)
{
	throw std::logic_error("Not Implemented");
}

channel_info mapping_resolve(std::vector<channel_mapping> mappings, light_packet_interface packet_interface, tecmp_header header) {
	// What to test against
	channel_info target;
	target.chl_id = header.channel_id;
	target.inf_name = packet_interface.name
		? std::optional(std::string(packet_interface.name))
		: std::nullopt;
	// Result
	channel_info result;
	result.chl_id = header.channel_id;
	for (channel_mapping mapping : mappings) {
		if (mapping_match(target, mapping.when)) {
			merge_value(&result.chl_id, mapping.change.chl_id);
			merge_value(&result.inf_name, mapping.change.inf_name);
			break;
		}
	}
	if (!result.inf_name.has_value()) {
		result.inf_name = get_interface_name(header.channel_id);
	}
	return result;
}
