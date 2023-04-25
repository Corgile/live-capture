#ifndef PAYLOAD
#define PAYLOAD

#include "packet_header.hpp"

/**
 * Payload is currently defined as any application level data, expressed as a
 * vector of bytes with no semantic structure
 */

class Payload : public PacketHeader {
public:
	/** Required Functions */
	void *get_raw() override;

	void set_raw(void *raw) override;

	void print_header(FILE *out) override;

	uint32_t get_header_len() override;

	void get_bitstring(std::vector<int8_t> &to_fill, int8_t fill_with) override;

	void get_bitstring_header(std::vector<std::string> &to_fill) override;

	/** Header Specific Functions */
	void set_info(uint32_t n_bytes, uint32_t max_payload_len);

private:
	void *raw = nullptr;
	uint32_t n_bytes = 0;
	uint32_t max_payload_len = 0;
};

#endif
