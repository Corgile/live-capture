#include "stats.hpp"

#define R(a, b) (100.0 * float((a)) / float((b)))
#define A(a) ((unsigned long long)(a))
#define RATIO(a) (100.0 * float((a)) / float((parsed)))

void Stats::print_stats() const {
	fprintf(stderr, "General Statistics\n");
	fprintf(stderr, "  Packets processed: %10llu\n", A(processed));
	fprintf(stderr, "  Packets skipped:   %10llu (%.2f%%)\n", A(skipped), R(skipped, processed));
	fprintf(stderr, "  Packets parsed:    %10llu (%.2f%%)\n", A(parsed), R(parsed, processed));
	fprintf(stderr, "Network Layer Statistics (of packets parsed)\n");
	fprintf(stderr, "  IPv4:              %10llu (%.2f%%)\n", A(ipv4), RATIO(ipv4));
	fprintf(stderr, "  IPv6:              %10llu (%.2f%%)\n", A(ipv6), RATIO(ipv6));
	fprintf(stderr, "Transport Layer Statistics (of packets parsed)\n");
	fprintf(stderr, "  TCP:               %10llu (%.2f%%)\n", A(tcp), RATIO(tcp));
	fprintf(stderr, "  UDP:               %10llu (%.2f%%)\n", A(udp), RATIO(udp));
	fprintf(stderr, "  ICMP:              %10llu (%.2f%%)\n", A(icmp), RATIO(icmp));
}

void Stats::update(bool _parsed, uint8_t network_layer, uint8_t transport_layer) {
	processed++;
	if (!_parsed) {
		skipped++;
		return;
	}
	parsed++;
	ipv4 += network_layer == 4;
	ipv6 += network_layer == 6;
	tcp += transport_layer == IPPROTO_TCP;
	udp += transport_layer == IPPROTO_UDP;
	icmp += transport_layer == IPPROTO_ICMP;
}

uint64_t Stats::get_packets_processed() const { return processed; }
