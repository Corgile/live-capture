#ifndef LIVE_CAPTURE_SUPER_PACKET_HPP
#define LIVE_CAPTURE_SUPER_PACKET_HPP

#include <tuple>
#include <iostream>
#include <cstdlib>
#include <string>
#include <arpa/inet.h>
#include <pcap.h>

#include "config.hpp"
#include "common.hpp"

#include "packet/payload.hpp"
#include "packet/header/ethernet_header.hpp"
#include "packet/header/icmp_header.hpp"
#include "packet/header/ipv4_header.hpp"
#include "packet/header/ipv6_header.hpp"
#include "packet/header/tcp_header.hpp"
#include "packet/header/udp_header.hpp"

class SuperPacket {
public:
    SuperPacket(raw_data_t pkt, uint32_t max_payload_len, uint32_t link_type);

    std::string get_port(bool src);

    std::string get_ip_address(bool src);

    static std::string get_mac_address();

    void print_packet(FILE *out);

    [[nodiscard]] bool check_parseable() const;

    std::tuple<uint8_t, uint8_t> get_packet_type();

    void fill_bit_vec(Config *c, std::vector<float> &bit_vec);

    std::string get_index(Config *c);

private:
    bool process_v4(ip_packet_t ipv4_packet);

    bool process_v6(ip_packet_t ipv6_packet);

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
