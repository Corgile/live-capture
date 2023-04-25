#ifndef UDP_HEADER
#define UDP_HEADER

#include <netinet/udp.h>

#include "packet_header.hpp"

#define SIZE_UDP_HEADER_BITSTRING 8

class UDPHeader : public PacketHeader {
  public:
    /* Required Functions */
    void *get_raw();
    void set_raw(void *raw);
    void print_header(FILE *out);
    uint32_t get_header_len();
    std::string get_port(bool src);
    void get_bitstring(std::vector<int8_t> &to_fill, int8_t fill_with);
    void get_bitstring_header(std::vector<std::string> &to_fill);
    /* Header Specific */
  private:
    struct udphdr *raw = nullptr;
};

#endif
