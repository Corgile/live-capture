#include "headers/packet_header.hpp"

void PacketHeader::ascii_encode(unsigned char *ptr, uint32_t num_bytes,
                                std::vector<std::string> &to_fill) {
	uint32_t i;
	char *s, *t;

	s = new char[num_bytes * 2 + 1];

	t = s;
	for (i = 0; i < num_bytes; i++) {
		sprintf(t, "%c", (ptr[i]));
		t++;
	}
	to_fill.emplace_back(s);
	delete s;
}

void PacketHeader::make_bitstring(uint32_t num_bytes, void *raw_data,
                                  std::vector<int8_t> &to_fill,
                                  int8_t fill_with) {
	uint8_t *byte, bit;
	uint32_t i;
	int32_t j;

	if (raw_data == nullptr) {
		for (i = 0; i < num_bytes * 8; i++)
			to_fill.push_back(fill_with);
		return;
	}

	byte = (uint8_t *) raw_data;
	for (i = 0; i < num_bytes; i++) {
		for (j = 7; j >= 0; j--) {
			bit = (byte[i] >> j) & 1;
			to_fill.push_back(bit);
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
