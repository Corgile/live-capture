#include "packet/header/ipv4_header.hpp"

raw_data_t IPv4Header::get_raw() {
    return reinterpret_cast<raw_data_t>(raw);
}

void IPv4Header::set_raw(raw_data_t raw_data) { this->raw = reinterpret_cast<ip_packet_t>(raw_data); }

void IPv4Header::print_header(FILE *out) {
    if (raw == nullptr) {
        fprintf(out, "IPv4Header: raw data not set\n");
    } else {
        fprintf(out, "IPv4Header: src_ip: %s, dst_ip: %s\n", inet_ntoa(raw->ip_src),
                inet_ntoa(raw->ip_dst));
    }
}

uint32_t IPv4Header::header_len() {
    return raw->ip_hl * 4;
}

void IPv4Header::fill_bit_vec(std::vector<float> &bit_vec, int8_t bit) {
    uint32_t ip_header_byte_size, zero_byte_width;

    if (raw == nullptr) {
        make_bitstring(SIZE_IPV4_HEADER_BITSTRING, nullptr, bit_vec, bit);
        return;
    }

    ip_header_byte_size = raw->ip_hl * 4;
    zero_byte_width = SIZE_IPV4_HEADER_BITSTRING - ip_header_byte_size;

    make_bitstring(ip_header_byte_size, (void *) raw, bit_vec, bit);
    make_bitstring(zero_byte_width, nullptr, bit_vec, bit);
}

void IPv4Header::get_bitstring_header(std::vector<std::string> &to_fill) {
    std::vector<std::tuple<std::string, uint32_t>> v(15);
    // field    bits
    v.emplace_back("ipv4_version", 4);
    v.emplace_back("ipv4_header_length", 4);
    v.emplace_back("ipv4_type_of_service", 8);
    v.emplace_back("ipv4_total_length", 16);
    v.emplace_back("ipv4_id", 16);
    v.emplace_back("ipv4_r_bit", 1);
    v.emplace_back("ipv4_df_bit", 1);
    v.emplace_back("ipv4_mf_bit", 1);
    v.emplace_back("ipv4_frag_offset", 13);
    v.emplace_back("ipv4_ttl", 8);
    v.emplace_back("ipv4_protocol", 8);
    v.emplace_back("ipv4_checksum", 16);
    v.emplace_back("ipv4_src_ip", 32);
    v.emplace_back("ipv4_dst_ip", 32);
    v.emplace_back("ipv4_optional", 320);

    PacketHeader::make_bitstring_header(v, to_fill);
}

/* Header Specific */

std::string IPv4Header::get_src_ip() { return {inet_ntoa(raw->ip_src)}; }

std::string IPv4Header::get_dst_ip() { return {inet_ntoa(raw->ip_dst)}; }

uint8_t IPv4Header::get_ip_proto() { return raw->ip_p; }

uint16_t IPv4Header::get_total_len() { return ntohs(raw->ip_len); }
