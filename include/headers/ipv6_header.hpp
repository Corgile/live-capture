#ifndef IPv6_HEADER
#define IPv6_HEADER

#include <netinet/ip.h>
#include <netinet/ip6.h>

#include "headers/packet_header.hpp"

#define SIZE_IPV6_HEADER_BITSTRING 40

/*
 * Currently only supported fixed (first) IPv6 Header parsing
 */

class IPv6Header : public PacketHeader {
  public:
    /* Required Functions */
    void *get_raw() override;
    void set_raw(void *raw) override;
    void print_header(FILE *out) override;
    uint32_t get_header_len() override;
    void get_bitstring(std::vector<int8_t> &to_fill, int8_t fill_with) override;
    void get_bitstring_header(std::vector<std::string> &to_fill) override;

    /* Header Specific */
    std::string get_src_ip();
    std::string get_dst_ip();
    uint8_t get_ip_proto();
    uint32_t get_total_len();

  private:
    struct ip6_hdr *raw = nullptr;
};

#endif
