#ifndef SUPERPACKET
#define SUPERPACKET

#include <tuple>
#include <iostream>
#include <cstdlib>
#include <string>
#include <arpa/inet.h>
#include <pcap.h>

#include "config.hpp"

#include "ethernet_header.hpp"
#include "icmp_header.hpp"
#include "ipv4_header.hpp"
#include "ipv6_header.hpp"
#include "payload.hpp"
#include "tcp_header.hpp"
#include "udp_header.hpp"

class SuperPacket {
  public:
    SuperPacket(void *pkt, uint32_t max_payload_len, uint32_t linktype);
    std::string get_port(bool src);
    std::string get_ip_address(bool src);
    static std::string get_tx_mac_address();
    void print_packet(FILE *out);
    bool check_parseable() const;
    std::tuple<uint8_t, uint8_t> get_packet_type();
    void get_bitstring(Config *c, std::vector<int8_t> &bit_string_vec);
    std::string get_index(Config *c);

  private:
    bool process_v4(void *pkt);
    bool process_v6(void *pkt);

    bool parseable;
    uint32_t max_payload_len;
    EthHeader ethernet_header;
    IPv4Header ipv4_header;
    IPv6Header ipv6_header;
    TCPHeader tcp_header;
    UDPHeader udp_header;
    ICMPHeader icmp_header;
    Payload payload;
};

#endif
