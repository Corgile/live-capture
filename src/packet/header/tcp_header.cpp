#include "packet/header/tcp_header.hpp"

raw_data_t TCPHeader::get_raw() {
    return reinterpret_cast<raw_data_t>(raw);
}

void TCPHeader::set_raw(raw_data_t raw_data) {
    this->raw = reinterpret_cast<tcp_header_t>(raw_data);
}

void TCPHeader::print_header(FILE *out) {
    if (raw == nullptr) {
        fprintf(out, "TCPHeader: raw data not set\n");
        return;
    }
    fprintf(out, "TCPHeader: src_prt: %d, dst_prt: %d\n", ntohs(raw->th_sport),
            ntohs(raw->th_dport));
}

uint32_t TCPHeader::header_len() {
    return raw->th_off * 4;
}

void TCPHeader::fill_bit_vec(std::vector<float> &bit_vec, int8_t bit) {
    uint32_t tcp_header_byte_size, zero_byte_width;

    if (raw == nullptr) {
        make_bitstring(SIZE_TCP_HEADER_BITSTRING, nullptr, bit_vec, bit);
        return;
    }
    tcp_header_byte_size = raw->th_off << 2;
    zero_byte_width = SIZE_TCP_HEADER_BITSTRING - tcp_header_byte_size;
    make_bitstring(tcp_header_byte_size, (void *) raw, bit_vec, bit);
    make_bitstring(zero_byte_width, nullptr, bit_vec, bit);
}

void TCPHeader::get_bitstring_header(std::vector<std::string> &to_fill) {
    std::vector<std::tuple<std::string, uint32_t>> v;
    v.reserve(19);
    v.emplace_back("tcp_sprt", 16);
    v.emplace_back("tcp_dprt", 16);
    v.emplace_back("tcp_seq", 32);
    v.emplace_back("tcp_ackn", 32);
    v.emplace_back("tcp_doff", 4);
    v.emplace_back("tcp_res", 3);
    v.emplace_back("tcp_ns", 1);
    v.emplace_back("tcp_cwr", 1);
    v.emplace_back("tcp_ece", 1);
    v.emplace_back("tcp_urg", 1);
    v.emplace_back("tcp_ackf", 1);
    v.emplace_back("tcp_psh", 1);
    v.emplace_back("tcp_rst", 1);
    v.emplace_back("tcp_syn", 1);
    v.emplace_back("tcp_fin", 1);
    v.emplace_back("tcp_wsize", 16);
    v.emplace_back("tcp_cksum", 16);
    v.emplace_back("tcp_urp", 16);
    v.emplace_back("tcp_opt", 320);

    PacketHeader::make_bitstring_header(v, to_fill);
}

std::string TCPHeader::get_port(bool src) {
    if (raw == nullptr) {
        return "nullptr";
    } else if (src) {
        return std::to_string(ntohs(raw->th_sport));
    } else {
        return std::to_string(ntohs(raw->th_dport));
    }
}
