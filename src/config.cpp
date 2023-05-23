#include "config.hpp"

Config::Config() {

    this->eth = 0;
    this->ipv4 = 0;
    this->ipv6 = 0;
    this->tcp = 0;
    this->udp = 0;
    this->icmp = 0;
    this->max_payload_len = 0;
    this->relative_timestamps = 0;
    this->fill_with = -1;
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

Config Config::get_instance() {
    Config config;
    config.set_live_capture(true);
    config.set_tcp(true);
    config.set_udp(true);
    config.set_icmp(true);
    config.set_payload(20);
    config.set_infile("");
    return config;
}
