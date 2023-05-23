#include "packet/payload.hpp"

raw_data_t Payload::get_raw() {
    return raw;
}

void Payload::set_raw(raw_data_t raw_data) { this->raw = raw_data; }

void Payload::print_header(FILE *out) {
    fprintf(out, "Payload: length: %d\n", n_bytes);
}

uint32_t Payload::header_len() {
    return n_bytes;
}

void Payload::fill_bit_vec(std::vector<float> &bit_vec, int8_t bit) {
    int32_t zero_byte_width;
    zero_byte_width = max_payload_len - n_bytes;
    /* If no payload fill with max payload bytes */
    if (n_bytes == 0) {
        make_bitstring(max_payload_len, nullptr, bit_vec, bit);
    }
        /* If payload but payload is smaller than maximum payload length */
    else if (zero_byte_width > 0) {
        make_bitstring(n_bytes, raw, bit_vec, bit);
        make_bitstring(zero_byte_width, nullptr, bit_vec, bit);
    }
        /* Payload is larger or as large as maximum payload length, */
    else {
        make_bitstring(max_payload_len, raw, bit_vec, bit);
    }
}

void Payload::get_bitstring_header(std::vector<std::string> &to_fill) {
    std::vector<std::tuple<std::string, uint32_t>> v;

    if (max_payload_len == 0)
        return;

    v.emplace_back("payload_bit", max_payload_len * 8);
    PacketHeader::make_bitstring_header(v, to_fill);
}

/* Specific to Payload */

void Payload::set_info(uint32_t num_bytes, uint32_t _max_payload_len) {
    this->n_bytes = num_bytes;
    this->max_payload_len = _max_payload_len;
}
