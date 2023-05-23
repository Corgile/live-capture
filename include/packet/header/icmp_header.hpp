#ifndef LIVE_CAPTURE_ICMP_HEADER_HPP
#define LIVE_CAPTURE_ICMP_HEADER_HPP

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include "packet/header/packet_header.hpp"
#include "common.hpp"


/**
 * We consider the ICMP header to always be 8 bytes, with the rest of the data
 * being part of the payload. Some consider it "ICMP data", it simplifies things
 * for us if its just abstracted as a payload
 */

class ICMPHeader : public PacketHeader {
public:
    /* Required Functions */
    raw_data_t get_raw() override;

    void set_raw(raw_data_t raw) override;

    void print_header(FILE *out) override;

    uint32_t header_len() override {
        return 8;
    };

    void fill_bit_vec(std::vector<float> &bit_vec, int8_t bit) override;

    void get_bitstring_header(std::vector<std::string> &to_fill) override;

private:
    icmp_packet_t raw{ };
};

#endif
