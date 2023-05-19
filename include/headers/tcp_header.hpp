#ifndef TCP_HEADER
#define TCP_HEADER

#include <netinet/tcp.h>

#include "headers/packet_header.hpp"

#define SIZE_TCP_HEADER_BITSTRING 60

class TCPHeader : public PacketHeader {
public:
	/* Required Functions */
	void *get_raw() override;

	void set_raw(void *raw_data) override;

	void print_header(FILE *out) override;

	uint32_t get_header_len() override;

	std::string get_port(bool src);

	void get_bitstring(std::vector<float> &to_fill, int8_t fill_with) override;

	void get_bitstring_header(std::vector<std::string> &to_fill) override;

	/* Header Specific */
private:
	struct tcphdr *raw = nullptr;
};

#endif
