#include "packet/header/udp_header.hpp"

raw_data_t UDPHeader::get_raw() {
    return reinterpret_cast<raw_data_t>(raw);
}

void UDPHeader::set_raw(raw_data_t raw_data) {
    this->raw = reinterpret_cast<udp_header_t>(raw_data);
}

void UDPHeader::print_header(FILE *out) {
    if (raw == nullptr) {
        fprintf(out, "UDPHeader: raw data not set\n");
        return;
    }

    fprintf(out, "UDP header: srcprt: %u, dstprt: %u, len: %u, cksum: %u\n",
            ntohs(raw->uh_sport), ntohs(raw->uh_dport), ntohs(raw->uh_ulen),
            ntohs(raw->uh_sum));
}

uint32_t UDPHeader::header_len() {
    return 8;
}

void UDPHeader::fill_bit_vec(std::vector<float> &bit_vec, int8_t bit) {
    make_bitstring(SIZE_UDP_HEADER_BITSTRING, raw, bit_vec, bit);
}

void UDPHeader::get_bitstring_header(std::vector<std::string> &to_fill) {
    std::vector<std::tuple<std::string, uint32_t>> v(4);
    v.emplace_back("udp_sport", 16);
    v.emplace_back("udp_dport", 16);
    v.emplace_back("udp_len", 16);
    v.emplace_back("udp_cksum", 16);

    PacketHeader::make_bitstring_header(v, to_fill);
}

std::string UDPHeader::get_port(bool src) {
    if (raw == nullptr) {
        return "nullptr";
    } else if (src) {
        return std::to_string(ntohs(raw->uh_sport));
    } else {
        return std::to_string(ntohs(raw->uh_dport));
    }
}
