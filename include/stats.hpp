#ifndef STATS
#define STATS

#include <arpa/inet.h>
#include <cstdint>
#include <cstdio>
#include <tuple>

class Stats {
public:
	void print_stats() const;

	void update(bool parsed, uint8_t network_layer = 0,
	            uint8_t transport_layer = 0);

	[[nodiscard]] uint64_t get_packets_processed() const;

private:
	uint64_t processed = 0;
	uint64_t parsed = 0;
	uint64_t skipped = 0;
	uint64_t ipv4 = 0;
	uint64_t ipv6 = 0;
	uint64_t tcp = 0;
	uint64_t udp = 0;
	uint64_t icmp = 0;
};

#endif
