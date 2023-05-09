#ifndef PACKET_HEADER
#define PACKET_HEADER

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/types.h>
#include <tuple>
#include <vector>

/*
 * Packet header abstract class, used for every header and the payload
 */

class PacketHeader {
public:
	/* Virtual Functions */
	virtual void *get_raw() = 0;

	virtual void set_raw(void *raw) = 0;

	virtual void print_header(FILE *out) = 0;

	virtual uint32_t get_header_len() = 0;

	virtual void get_bitstring(std::vector<int8_t> &to_fill,
	                           int8_t fill_with) = 0;

	virtual void get_bitstring_header(std::vector<std::string> &to_fill) = 0;

	/* Shared Functions */
	static void ascii_encode(unsigned char *ptr, uint32_t num_bytes,
	                         std::vector<std::string> &to_fill);

	static void make_bitstring(uint32_t num_bytes, void *raw_data,
	                           std::vector<int8_t> &to_fill,
	                           int8_t fill_with = 0);

	static void make_bitstring_header(
			const std::vector<std::tuple<std::string, uint32_t>> &v,
			std::vector<std::string> &to_fill);
};

#endif
