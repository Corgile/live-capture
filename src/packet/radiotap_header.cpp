#include "radiotap_header.hpp"

void *RadiotapHeader::get_raw() {
    return (void *) raw;
}

void RadiotapHeader::set_raw(void *raw_data) {
	this->raw = (struct radiotap_header *) raw_data;
}

void RadiotapHeader::print_header(FILE *out) {
	if (raw == nullptr) {
		fprintf(out, "RadiotapHeader: raw data not set\n");
	} else {
		fprintf(out, "RadiotapHeader: %d bytes\n", get_header_len());
	}
}

uint32_t RadiotapHeader::get_header_len() {
    return SIZE_RADIOTAP_HEADER_BITSTRING;
}

void RadiotapHeader::get_bitstring(std::vector<int8_t> &to_fill, int8_t fill_with) {
    make_bitstring(SIZE_RADIOTAP_HEADER_BITSTRING, raw, to_fill, fill_with);
}

void RadiotapHeader::get_bitstring_header(std::vector<std::string> &to_fill) {
	std::vector<std::tuple<std::string, uint32_t>> v(15);

	v.emplace_back("radiotap_reversion", 1 * 8);
	v.emplace_back("radiotap_pad0", 1 * 8);
	v.emplace_back("radiotap_len", 2 * 8);
	v.emplace_back("radiotap_present", 12 * 8);
	v.emplace_back("radiotap_mactimestamp", 8 * 8);
	v.emplace_back("radiotap_flags", 1 * 8);
	v.emplace_back("radiotap_rate", 1 * 8);
	v.emplace_back("radiotap_channel", 2 * 8);
	v.emplace_back("radiotap_channelflags", 2 * 8);
	v.emplace_back("radiotap_antennasignal", 1 * 8);
	v.emplace_back("radiotap_pad1", 1 * 8);
	v.emplace_back("radiotap_rxflags", 2 * 8);
	v.emplace_back("radiotap_pad2", 6 * 8);
	v.emplace_back("radiotap_timestamp", 12 * 8);
	v.emplace_back("radiotap_antennas", 4 * 8);

	PacketHeader::make_bitstring_header(v, to_fill);
}
