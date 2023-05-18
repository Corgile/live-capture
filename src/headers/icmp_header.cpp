#include "headers/icmp_header.hpp"

/* Required Functions */
void *ICMPHeader::get_raw() {
    return (void *)raw;
}

void ICMPHeader::set_raw(void *raw_data) {
	this->raw = (struct icmp *) raw_data;
}

void ICMPHeader::print_header(FILE *out) {
	if (raw == nullptr) {
		fprintf(out, "ICMPHeader:: raw data not set\n");
	} else {
		fprintf(out, "icmp: type: %u, code: %u\n", raw->icmp_type, raw->icmp_code);
	}
}

void ICMPHeader::get_bitstring(std::vector<int8_t> &to_fill, int8_t fill_with) {
	if (raw == nullptr) {
		make_bitstring(SIZE_ICMP_HEADER_BITSTRING, nullptr, to_fill, fill_with);
		return;
	}
	make_bitstring(SIZE_ICMP_HEADER_BITSTRING, (void *) raw, to_fill, fill_with);
}

void ICMPHeader::get_bitstring_header(std::vector<std::string> &to_fill) {
	std::vector<std::tuple<std::string, uint32_t>> v(4);
	v.emplace_back("icmp_type", 8);
	v.emplace_back("icmp_code", 8);
	v.emplace_back("icmp_cksum", 16);
	v.emplace_back("icmp_roh", 32);

	PacketHeader::make_bitstring_header(v, to_fill);
}
