#include "config.hpp"

Config::Config() {
	this->radiotap = 0;
	this->wlan = 0;
	this->eth = 0;
	this->ipv4 = 0;
	this->ipv6 = 0;
	this->tcp = 0;
	this->udp = 0;
	this->icmp = 0;
	this->payload = 0;
	this->fill_with = -1;
	this->num_packets = 0;
	this->absolute_timestamps = 0;
	this->relative_timestamps = 0;
	this->pcap = 0;
	this->csv = 0;
	this->stats = 0;
	this->nprint = 0;
	this->verbose = 0;
	this->live_capture = 0;
	this->output_index = 0;
	this->regex = "";
	this->infile = "";
	this->filter = "";
	this->ip_file = "";
	this->outfile = "";
	this->device = "";
}

// tuip20
Config Config::get_instance() {
	Config config;
	config.set_live_capture(true);
	config.set_tcp(true);
	config.set_udp(true);
	config.set_icmp(true);
	config.set_stats(true);
	config.set_payload(20);
	// 20 bytes of payload
	config.set_infile("");
//	config.set_infile("/home/gzhuadmin/workspace/live-capture/target/192.168.8.68.pcapng");
	return config;
}
