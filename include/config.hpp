#ifndef LIVE_CAPTURE_CONF_HPP
#define LIVE_CAPTURE_CONF_HPP

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
    uint8_t eth;
    uint8_t ipv4;
    uint8_t ipv6;
    uint8_t tcp;
    uint8_t udp;
    uint8_t icmp;
    uint32_t max_payload_len;

    /*  Output modification */
    uint8_t verbose;
    uint8_t live_capture;
    uint8_t output_index;
    uint8_t relative_timestamps;
    int8_t fill_with;
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

    void set_tcp(bool _tcp) { this->tcp = _tcp; }

    void set_udp(bool _udp) { this->udp = _udp; }

    void set_icmp(bool _icmp) { this->icmp = _icmp; }

    void set_payload(uint32_t _payload) { this->max_payload_len = _payload; }

    void set_live_capture(bool _live_capture) { this->live_capture = _live_capture; }

    void set_filter(const std::string &_filter) { this->filter = _filter; }

    void set_infile(const std::string &_infile) { this->infile = _infile; }


};

#endif
