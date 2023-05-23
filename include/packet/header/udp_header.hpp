#ifndef LIVE_CAPTURE_UDP_HEADER_HPP
#define LIVE_CAPTURE_UDP_HEADER_HPP

#include <netinet/udp.h>

#include "packet/header/packet_header.hpp"
#include "common.hpp"


class UDPHeader : public PacketHeader {
public:
    /* Required Functions */
    raw_data_t get_raw() override;

    void set_raw(raw_data_t raw) override;

    void print_header(FILE *out) override;

    uint32_t header_len() override;

    std::string get_port(bool src);

    void fill_bit_vec(std::vector<float> &bit_vec, int8_t bit) override;

    void get_bitstring_header(std::vector<std::string> &to_fill) override;
    /* Header Specific */
private:
    udp_header_t raw{ };
};

#endif
