#include "packet/header/packet_header.hpp"

void PacketHeader::ascii_encode(unsigned char *ptr, uint32_t num_bytes,
                                std::vector<std::string> &to_fill) {

    char *t, *s;
    s = new char[num_bytes * 2 + 1];

    t = s;
    for (uint32_t i = 0; i < num_bytes; i++) {
        sprintf(t, "%c", (ptr[i]));
        t++;
    }
    to_fill.emplace_back(s);
    delete[] s;
}

void PacketHeader::make_bitstring(uint32_t num_bytes, raw_data_t raw_data,
                                  std::vector<float> &bit_vec,
                                  int8_t vec) {
    if (raw_data == nullptr) {
        for (uint32_t i = 0; i < num_bytes * 8; i++)
            bit_vec.push_back(vec);
        return;
    }

    auto byte = (uint8_t *) raw_data;
    for (uint32_t i = 0; i < num_bytes; i++) {
        for (int32_t j = 7; j >= 0; j--) {
            uint8_t bit = (byte[i] >> j) & 1;
            bit_vec.push_back(bit);
        }
    }
}

void PacketHeader::make_bitstring_header(
        const std::vector<std::tuple<std::string, uint32_t>> &v,
        std::vector<std::string> &to_fill) {
    uint32_t i;
    std::vector<std::tuple<std::string, uint32_t>>::const_iterator vit;
    for (vit = v.begin(); vit != v.end(); vit++) {
        for (i = 0; i < std::get<1>(*vit); i++) {
            to_fill.push_back(std::get<0>(*vit) + "_" + std::to_string(i));
        }
    }
}
