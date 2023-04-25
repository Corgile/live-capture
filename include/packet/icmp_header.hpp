#ifndef ICMP_HEADER
#define ICMP_HEADER

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include "packet_header.hpp"

#define SIZE_ICMP_HEADER_BITSTRING 8

/**
 * We consider the ICMP header to always be 8 bytes, with the rest of the data
 * being part of the payload. Some consider it "ICMP data", it simplifies things
 * for us if its just abstracted as a payload
 */

class ICMPHeader : public PacketHeader {
  public:
    /* Required Functions */
    void *get_raw();
    void set_raw(void *raw);
    void print_header(FILE *out);
    uint32_t get_header_len() {
        return 8;
    };
    void get_bitstring(std::vector<int8_t> &to_fill, int8_t fill_with);
    void get_bitstring_header(std::vector<std::string> &to_fill);

  private:
    struct icmp *raw = nullptr;
};

#endif
