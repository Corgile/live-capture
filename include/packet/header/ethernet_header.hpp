#ifndef LIVE_CAPTURE_ETH_HEADER_HPP
#define LIVE_CAPTURE_ETH_HEADER_HPP

#include <netinet/if_ether.h>

#include "packet/header/packet_header.hpp"
#include "common.hpp"


class EthHeader : public PacketHeader {
public:
    /* Required Functions */
    raw_data_t get_raw() override;

    void set_raw(raw_data_t raw) override;

    void print_header(FILE *out) override;

    uint32_t header_len() override;

    void fill_bit_vec(std::vector<float> &bit_vec, int8_t bit) override;

    void get_bitstring_header(std::vector<std::string> &to_fill) override;

private:
    eth_header_t raw{ };
};

#endif
