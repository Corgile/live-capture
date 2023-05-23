#ifndef LIVE_CAPTURE_PAYLOAD_HPP
#define LIVE_CAPTURE_PAYLOAD_HPP

#include "packet/header/packet_header.hpp"
#include "common.hpp"

/**
 * Payload is currently defined as any application level data, expressed as a
 * vector of bytes with no semantic structure
 */

class Payload : public PacketHeader {
public:
    /** Required Functions */
    raw_data_t get_raw() override;

    void set_raw(raw_data_t raw) override;

    void print_header(FILE *out) override;

    uint32_t header_len() override;

    void fill_bit_vec(std::vector<float> &bit_vec, int8_t bit) override;

    void get_bitstring_header(std::vector<std::string> &to_fill) override;

    /** Header Specific Functions */
    void set_info(uint32_t n_bytes, uint32_t max_payload_len);

private:
    raw_data_t raw{ };
    uint32_t n_bytes = 0;
    uint32_t max_payload_len = 0;
};

#endif
