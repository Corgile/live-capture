#include "packet/header/icmp_header.hpp"

/* Required Functions */
raw_data_t ICMPHeader::get_raw() {
    return reinterpret_cast<raw_data_t>(raw);
}

void ICMPHeader::set_raw(raw_data_t raw_data) {
    this->raw = reinterpret_cast<icmp_packet_t>(raw_data);
}

void ICMPHeader::print_header(FILE *out) {
    if (raw == nullptr) {
        fprintf(out, "ICMPHeader:: raw data not set\n");
    } else {
        fprintf(out, "icmp: type: %u, code: %u\n", raw->icmp_type, raw->icmp_code);
    }
}

void ICMPHeader::fill_bit_vec(std::vector<float> &bit_vec, int8_t bit) {
    if (raw == nullptr) {
        make_bitstring(SIZE_ICMP_HEADER_BITSTRING, nullptr, bit_vec, bit);
        return;
    }
    make_bitstring(SIZE_ICMP_HEADER_BITSTRING, (void *) raw, bit_vec, bit);
}

void ICMPHeader::get_bitstring_header(std::vector<std::string> &to_fill) {
    std::vector<std::tuple<std::string, uint32_t>> v(4);
    v.emplace_back("icmp_type", 8);
    v.emplace_back("icmp_code", 8);
    v.emplace_back("icmp_cksum", 16);
    v.emplace_back("icmp_roh", 32);

    PacketHeader::make_bitstring_header(v, to_fill);
}
