#include "packet/header/ipv6_header.hpp"

raw_data_t IPv6Header::get_raw() {
    return reinterpret_cast<raw_data_t>(raw);
}

void IPv6Header::set_raw(raw_data_t raw_data) {
    this->raw = reinterpret_cast<ipv6_header_t>(raw_data);
}

void IPv6Header::print_header(FILE *out) {
}

uint32_t IPv6Header::header_len() {
    return 40;
}

std::string IPv6Header::get_src_ip() {
    char s[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, (void *) &raw->ip6_src, s, INET6_ADDRSTRLEN);

    return std::string{s};
}

std::string IPv6Header::get_dst_ip() {
    char s[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, (void *) &raw->ip6_dst, s, INET6_ADDRSTRLEN);

    return std::string{s};
}

void IPv6Header::fill_bit_vec(std::vector<float> &bit_vec, int8_t bit) {
    if (raw == nullptr) {
        make_bitstring(SIZE_IPV6_HEADER_BITSTRING, nullptr, bit_vec, bit);
        return;
    }

    make_bitstring(SIZE_IPV6_HEADER_BITSTRING, (void *) raw, bit_vec, bit);
}

void IPv6Header::get_bitstring_header(std::vector<std::string> &to_fill) {
    std::vector<std::tuple<std::string, uint32_t>> v(8);
    v.emplace_back("ipv6_ver", 4);
    v.emplace_back("ipv6_tc", 8);
    v.emplace_back("ipv6_fl", 20);
    v.emplace_back("ipv6_len", 16);
    v.emplace_back("ipv6_nh", 8);
    v.emplace_back("ipv6_hl", 8);
    v.emplace_back("ipv6_src", 128);
    v.emplace_back("ipv6_dst", 128);

    PacketHeader::make_bitstring_header(v, to_fill);
}

/* Header Specific */
uint8_t IPv6Header::get_ip_proto() {
    return raw->ip6_nxt;
}

uint32_t IPv6Header::get_total_len() {
    return ntohs(raw->ip6_plen) + 40;
}
