#ifndef IPv4_HEADER
#define IPv4_HEADER

#include <netinet/ip.h>

#include "headers/packet_header.hpp"

#define IP_RF 0x8000      /* reserved fragment flag */
#define IP_DF 0x4000      /* dont fragment flag */
#define IP_MF 0x2000      /* more fragments flag */
#define IP_OFFMASK 0x1fff /* mask for fragmenting bits */

#define SIZE_IPV4_HEADER_BITSTRING 60

class IPv4Header : public PacketHeader {
  public:
    /* Required Functions */
    void *get_raw() override;
    void set_raw(void *raw) override;
    void print_header(FILE *out) override;
    uint32_t get_header_len() override;
    void get_bitstring(std::vector<float> &to_fill, int8_t fill_with) override;
    void get_bitstring_header(std::vector<std::string> &to_fill) override;

    /* Header Specific */
    std::string get_src_ip();
    std::string get_dst_ip();
    uint8_t get_ip_proto();
    uint16_t get_total_len();

  private:
    struct ip *raw = nullptr;
};

#endif
