//
// Created by gzhuadmin on 23-5-13.
//

#ifndef LIVE_CAPTURE_COMMON_HPP
#define LIVE_CAPTURE_COMMON_HPP

#define SIZE_UDP_HEADER_BITSTRING 8
#define SIZE_ETH_HEADER_BITSTRING 14
#define SIZE_ICMP_HEADER_BITSTRING 8
#define SIZE_IPV4_HEADER_BITSTRING 60
#define SIZE_IPV6_HEADER_BITSTRING 40
#define SIZE_TCP_HEADER_BITSTRING 60

using callback_data_t = u_char *;

using raw_data_t = const void *;

using eth_header_t = const struct ether_header *;

using tcp_header_t = const struct tcphdr *;

using ip_header_t = const struct iphdr *;
using ip_packet_t = const struct ip *;

using ipv6_header_t = const struct ip6_hdr *;

using udp_header_t = const struct udphdr *;

using icmp_header_t = const struct icmphdr *;
using icmp_packet_t = const struct icmp *;

#ifdef ENABLE_DEBUG
#define DEBUG_CALL(x)   x
#else
#define DEBUG_CALL(x)
#endif


#ifdef ENABLE_INFO
#define INFO_CALL(x)   x
#else
#define INFO_CALL(x)
#endif

#ifdef ENABLE_WARN
#define WARN_CALL(x)   x
#else
#define WARN_CALL(x)
#endif

#define RED(x) std::cout << "\n\33[31m=================" << x << "=================\033[0m\n\n"

#endif //LIVE_CAPTURE_COMMON_HPP
