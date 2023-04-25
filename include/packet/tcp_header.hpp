#ifndef TCP_HEADER
#define TCP_HEADER

#include <netinet/tcp.h>

#include "packet_header.hpp"

#define SIZE_TCP_HEADER_BITSTRING 60

class TCPHeader : public PacketHeader {
public:
	/* Required Functions */
	void *get_raw();

	void set_raw(void *raw_data);

	void print_header(FILE *out);

	uint32_t get_header_len();

	std::string get_port(bool src);

	void get_bitstring(std::vector<int8_t> &to_fill, int8_t fill_with);

	void get_bitstring_header(std::vector<std::string> &to_fill);

	/* Header Specific */
private:
	struct tcphdr *raw = nullptr;
};

#endif
