#ifndef ETH_HEADER
#define ETH_HEADER

#include <netinet/if_ether.h>

#include "packet_header.hpp"

#define SIZE_ETH_HEADER_BITSTRING 14

class EthHeader : public PacketHeader {
public:
	/* Required Functions */
	void *get_raw() override;

	void set_raw(void *raw) override;

	void print_header(FILE *out) override;

	uint32_t get_header_len() override;

	void get_bitstring(std::vector<int8_t> &to_fill, int8_t fill_with) override;

	void get_bitstring_header(std::vector<std::string> &to_fill) override;

private:
	struct ether_header *raw = nullptr;
};

#endif
