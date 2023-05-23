#include "packet/superpacket.hpp"

void SuperPacket::print_packet(FILE *out) {
    fprintf(out, "Superpacket {\n");
    ethernet_header.print_header(out);
    ipv4_header.print_header(out);
    ipv6_header.print_header(out);
    tcp_header.print_header(out);
    udp_header.print_header(out);
    icmp_header.print_header(out);
    payload.print_header(out);
    fprintf(out, "}\n");
}

SuperPacket::SuperPacket(raw_data_t pkt, uint32_t max_payload_len, uint32_t link_type) {

    ip_packet_t ip_packet;

    this->max_payload_len = max_payload_len;
    auto eth = reinterpret_cast<eth_header_t> (pkt);

    /** Check if packet has an ethernet header */
    if ((ntohs(eth->ether_type) == ETHERTYPE_IP) ||
        ((ntohs(eth->ether_type) == ETHERTYPE_IPV6))) {
        ethernet_header.set_raw(eth);
        ip_packet = reinterpret_cast<ip_packet_t>(&eth[1]);
    } else {
        ip_packet = reinterpret_cast<ip_packet_t>(pkt);
    }

    if (ip_packet->ip_v == 4) {
        parseable = process_v4(ip_packet);
    } else if (ip_packet->ip_v == 6) {
        parseable = process_v6(ip_packet);
    } else {
        parseable = false;
    }
}

bool SuperPacket::process_v4(ip_packet_t ipv4_packet) {
    struct ip *ipv4h;
    struct tcphdr *tcph;
    struct udphdr *udph;
    struct icmp *icmph;
    void *pload;
    uint32_t pload_len;

    ipv4h = (struct ip *) ipv4_packet;
    ipv4_header.set_raw(ipv4h);
    if (ipv4_header.get_ip_proto() == IPPROTO_TCP) {
        tcph = (struct tcphdr *) ((u_char *) ipv4h + ipv4_header.header_len());
        tcp_header.set_raw(tcph);
        pload = ((u_char *) tcph + tcp_header.header_len());
        pload_len = ipv4_header.get_total_len() - (tcp_header.header_len() + ipv4_header.header_len());
    } else if (ipv4_header.get_ip_proto() == IPPROTO_UDP) {
        udph = (struct udphdr *) ((u_char *) ipv4h + ipv4_header.header_len());
        udp_header.set_raw(udph);
        pload = ((u_char *) udph + udp_header.header_len());
        pload_len = ipv4_header.get_total_len() - (ipv4_header.header_len() + udp_header.header_len());
    } else if (ipv4_header.get_ip_proto() == IPPROTO_ICMP) {
        icmph = (struct icmp *) ((u_char *) ipv4h + ipv4_header.header_len());
        icmp_header.set_raw(icmph);
        pload = ((u_char *) icmph + icmp_header.header_len());
        pload_len = ipv4_header.get_total_len() - (ipv4_header.header_len() + icmp_header.header_len());
    } else {
        return false;
    }
    payload.set_raw(pload);
    payload.set_info(pload_len, max_payload_len);

    return true;
}

bool SuperPacket::process_v6(ip_packet_t ipv6_packet) {
    struct ip6_hdr *ipv6h;
    struct tcphdr *tcph;
    struct udphdr *udph;
    struct icmp *icmph;
    void *pload;
    uint32_t pload_len;

    ipv6h = (struct ip6_hdr *) ipv6_packet;
    ipv6_header.set_raw(ipv6_packet);

    if (ipv6_header.get_ip_proto() == IPPROTO_TCP) {
        tcph =
                (struct tcphdr *) ((u_char *) ipv6h + ipv6_header.header_len());
        tcp_header.set_raw(tcph);
        pload = tcph + tcp_header.header_len();
        pload_len =
                ipv6_header.get_total_len() -
                (tcp_header.header_len() + ipv6_header.header_len());
    } else if (ipv6_header.get_ip_proto() == IPPROTO_UDP) {
        udph =
                (struct udphdr *) ((u_char *) ipv6h + ipv6_header.header_len());
        udp_header.set_raw(udph);
        pload = ((u_char *) udph + 8);
        pload_len =
                ipv6_header.get_total_len() -
                (udp_header.header_len() + ipv6_header.header_len());
    } else if (ipv6_header.get_ip_proto() == IPPROTO_ICMP) {
        icmph = (struct icmp *) ((u_char *) ipv6h + ipv6_header.header_len());
        icmp_header.set_raw(icmph);
        pload = ((u_char *) icmph + 8);
        pload_len =
                ipv6_header.get_total_len() -
                (ipv6_header.header_len() + icmp_header.header_len());
    } else {
        return false;
    }
    payload.set_raw(pload);
    payload.set_info(pload_len, max_payload_len);

    return true;
}

void SuperPacket::fill_bit_vec(Config *c, std::vector<float> &bit_vec) {
    if (c->eth == 1)
        ethernet_header.fill_bit_vec(bit_vec, c->fill_with);
    if (c->ipv4 == 1)
        ipv4_header.fill_bit_vec(bit_vec, c->fill_with);
    if (c->ipv6 == 1)
        ipv6_header.fill_bit_vec(bit_vec, c->fill_with);
    if (c->tcp == 1)
        tcp_header.fill_bit_vec(bit_vec, c->fill_with);
    if (c->udp == 1)
        udp_header.fill_bit_vec(bit_vec, c->fill_with);
    if (c->icmp == 1)
        icmp_header.fill_bit_vec(bit_vec, c->fill_with);
    if (c->max_payload_len != 0)
        payload.fill_bit_vec(bit_vec, c->fill_with);
}

std::string SuperPacket::get_index(Config *c) {
    std::string rv;
    /* Source IP */
    /* Could switch here... */
    if (c->output_index == 0) {
        rv = get_ip_address(true);
    }
        /* DST IP */
    else if (c->output_index == 1) {
        rv = get_ip_address(false);
    }
        /* Source Port */
    else if (c->output_index == 2) {
        rv = get_port(true);
    }
        /* Dest Port */
    else if (c->output_index == 3) {
        rv = get_port(false);
    }
        /* Flow */
    else if (c->output_index == 4) {
        /* There is 99% probability a better way to do this. */
        rv = get_ip_address(true);
        rv += std::string("_") + get_ip_address(false);
        rv += std::string("_") + get_port(true);
        rv += std::string("_") + get_port(false);
        if (tcp_header.get_raw() != nullptr) {
            rv += std::string("_") + "TCP";
        } else if (udp_header.get_raw() != nullptr) {
            rv += std::string("_") + "UDP";
        } else {
            rv += std::string("_") + "nullptr";
        }
    }
        /* Wlan TX Mac Address */
    else if (c->output_index == 5) {
        rv = get_mac_address();
    }

    return rv;
}

std::string SuperPacket::get_ip_address(bool src) {
    if (ipv4_header.get_raw() != nullptr) {
        if (src) {
            return ipv4_header.get_src_ip();
        } else {
            return ipv4_header.get_dst_ip();
        }
    } else if (ipv6_header.get_raw() != nullptr) {
        if (src) {
            return ipv6_header.get_src_ip();
        } else {
            return ipv6_header.get_dst_ip();
        }
    } else {
        return "nullptr";
    }
}

std::string SuperPacket::get_port(bool src) {
    if (tcp_header.get_raw() != nullptr) {
        return tcp_header.get_port(src);
    } else if (udp_header.get_raw() != nullptr) {
        return udp_header.get_port(src);
    } else {
        return "nullptr";
    }
}

std::string SuperPacket::get_mac_address() {
    return "nullptr";
}

std::tuple<uint8_t, uint8_t> SuperPacket::get_packet_type() {
    uint8_t network_layer, transport_layer;

    if (ipv4_header.get_raw() != nullptr) {
        network_layer = 4;
        transport_layer = ipv4_header.get_ip_proto();
    } else if (ipv6_header.get_raw() != nullptr) {
        network_layer = 6;
        transport_layer = ipv6_header.get_ip_proto();
    } else {
        network_layer = 0;
        transport_layer = 0;
    }

    return {network_layer, transport_layer};
}

bool SuperPacket::check_parseable() const {
    return parseable;
}