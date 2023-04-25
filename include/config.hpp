#ifndef CONF
#define CONF

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>

/*
 * Config class is a container to hold command line arguments
 */

class Config {
public:
	Config();

	/* Protocol flags */
	uint8_t radiotap;
	uint8_t wlan;
	uint8_t eth;
	uint8_t ipv4;
	uint8_t ipv6;
	uint8_t tcp;
	uint8_t udp;
	uint8_t icmp;
	uint32_t payload;

	/*  Output modification */
	uint8_t stats;
	uint8_t csv;
	uint8_t pcap;
	uint8_t nprint;
	uint8_t verbose;
	uint8_t live_capture;
	uint8_t output_index;
	uint8_t absolute_timestamps;
	uint8_t relative_timestamps;
	int8_t fill_with;
	uint64_t num_packets;
	std::string device;
	std::string filter;
	std::string regex;
	std::string infile;
	std::string ip_file;
	std::string outfile;
	std::map<int8_t, std::string> index_map = {
			{0, "src_ip"},
			{1, "dst_ip"},
			{2, "src_port"},
			{3, "dst_port"},
			{4, "flow"},
			{5, "tx_mac"}};
	static Config get_instance();

	void set_radiotap(bool _radiotap) { this->radiotap = _radiotap; }
	void set_wlan(bool _wlan) { this->wlan = _wlan; }
	void set_eth(bool _eth) { this->eth = _eth; }
	void set_ipv4(bool _ipv4) { this->ipv4 = _ipv4; }
	void set_ipv6(bool _ipv6) { this->ipv6 = _ipv6; }
	void set_tcp(bool _tcp) { this->tcp = _tcp; }
	void set_udp(bool _udp) { this->udp = _udp; }
	void set_icmp(bool _icmp) { this->icmp = _icmp; }
	void set_payload(uint32_t _payload) { this->payload = _payload; }
	void set_stats(bool _stats) { this->stats = _stats; }
	void set_csv(bool _csv) { this->csv = _csv; }
	void set_pcap(bool _pcap) { this->pcap = _pcap; }
	void set_nprint(bool _nprint) { this->nprint = _nprint; }
	void set_verbose(bool _verbose) { this->verbose = _verbose; }
	void set_live_capture(bool _live_capture) { this->live_capture = _live_capture; }
	void set_output_index(bool _output_index) { this->output_index = _output_index; }
	void set_absolute_timestamps(bool _absolute_timestamps) { this->absolute_timestamps = _absolute_timestamps; }
	void set_relative_timestamps(bool _relative_timestamps) { this->relative_timestamps = _relative_timestamps; }
	void set_fill_with(int8_t _fill_with) { this->fill_with = _fill_with; }
	void set_num_packets(uint64_t _num_packets) { this->num_packets = _num_packets; }
	void set_device(const std::string& _device) { this->device = _device; }
	void set_filter(const std::string& _filter) { this->filter = _filter; }
	void set_regex(const std::string& _regex) { this->regex = _regex; }
	void set_infile(const std::string& _infile) { this->infile = _infile; }
	void set_ip_file(const std::string& _ip_file) { this->ip_file = _ip_file; }
	void set_outfile(const std::string& _outfile) { this->outfile = _outfile; }

};

#endif
