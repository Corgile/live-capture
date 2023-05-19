#ifndef UDP_HEADER
#define UDP_HEADER

#include <netinet/udp.h>

#include "headers/packet_header.hpp"

#define SIZE_UDP_HEADER_BITSTRING 8

class UDPHeader : public PacketHeader {
  public:
    /* Required Functions */
    void *get_raw() override;
    void set_raw(void *raw) override;
    void print_header(FILE *out) override;
    uint32_t get_header_len() override;
    std::string get_port(bool src);
    void get_bitstring(std::vector<float> &to_fill, int8_t fill_with) override;
    void get_bitstring_header(std::vector<std::string> &to_fill) override;
    /* Header Specific */
  private:
    struct udphdr *raw = nullptr;
};

#endif
