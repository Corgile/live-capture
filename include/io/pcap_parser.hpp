#ifndef PCAP_PARSER
#define PCAP_PARSER

#if defined(__NetBSD__)
#include <net/if_ether.h>
#else

#include <net/ethernet.h>

#endif

#define LINUX_COOKED_HEADER_SIZE 16

#include <pcap.h>

#include <fdeep/fdeep.hpp>
#include "config.hpp"
#include "file_writer.hpp"
#include "superpacket.hpp"

/**
 * Parses a PCAP from a written file
 */

class PCAPParser {
public:

    PCAPParser(Config config, FileWriter file_writer);

    void perform();

    void set_model(fdeep::model *);


private:
    struct timeval mrt{};
    std::vector<std::string> to_fill;
    Config m_config;
    FileWriter m_file_writer;
    fdeep::model *m_model_file;
    uint32_t linktype;

    std::vector<std::string> custom_output;
    std::vector<int8_t> bitstring_vec;
    std::vector<std::string> fields_vec;

    pcap_t *open_live_handle();

    void set_filter(pcap_t *handle, char *filter) const;

    void perform_predict(const u_char *packet);

    static void packet_handler(u_char *user_data, const struct pcap_pkthdr *packet_header, const u_char *packet);

    static std::string get_protocol_name(u_char * packet);

};

#endif
