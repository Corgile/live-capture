#ifndef LIVE_CAPTURE_IPv4_HEADER_HPP
#define LIVE_CAPTURE_IPv4_HEADER_HPP

#include <netinet/ip.h>

#include "packet/header/packet_header.hpp"
#include "common.hpp"


class IPv4Header : public PacketHeader {
public:
    /* Required Functions */
    raw_data_t get_raw() override;

    void set_raw(raw_data_t raw) override;

    void print_header(FILE *out) override;

    uint32_t header_len() override;

    void fill_bit_vec(std::vector<float> &bit_vec, int8_t bit) override;

    void get_bitstring_header(std::vector<std::string> &to_fill) override;

    /* Header Specific */
    std::string get_src_ip();

    std::string get_dst_ip();

    uint8_t get_ip_proto();

    uint16_t get_total_len();

private:
    ip_packet_t raw{ };
};

#endif
