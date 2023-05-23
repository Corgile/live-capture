#ifndef LIVE_CAPTURE_PACKET_HEADER_HPP
#define LIVE_CAPTURE_PACKET_HEADER_HPP

#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/types.h>
#include <tuple>
#include <vector>
#include "common.hpp"
/*
 * Packet header abstract class, used for every header and the payload
 */

class PacketHeader {
public:
    /* Virtual Functions */
    virtual raw_data_t get_raw() = 0;

    virtual void set_raw(raw_data_t raw) = 0;

    virtual void print_header(FILE *out) = 0;

    virtual uint32_t header_len() = 0;

    virtual void fill_bit_vec(std::vector<float> &bit_vec, int8_t bit) = 0;

    virtual void get_bitstring_header(std::vector<std::string> &to_fill) = 0;

    /* Shared Functions */
    static void ascii_encode(unsigned char *ptr, uint32_t num_bytes,
                             std::vector<std::string> &to_fill);

    static void make_bitstring(uint32_t num_bytes, raw_data_t raw_data,
                               std::vector<float> &bit_vec,
                               int8_t vec = 0);

    static void make_bitstring_header(
            const std::vector<std::tuple<std::string, uint32_t>> &v,
            std::vector<std::string> &to_fill);
};

#endif
