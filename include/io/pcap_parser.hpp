#ifndef PCAP_PARSER
#define PCAP_PARSER

#if defined(__NetBSD__)
#include <net/if_ether.h>
#else
#include <net/ethernet.h>
#endif

#define LINUX_COOKED_HEADER_SIZE 16

#include <pcap.h>

#include "io_parser.hpp"
#include "config.hpp"
#include "file_writer.hpp"
#include "superpacket.hpp"
#include "call_python.hpp"

/**
 * Parses a PCAP from a written file
 */

class PCAPParser : public IOParser {
public:

	PCAPParser(const Config &config, const FileWriter &file_writer);

	void perform() override;

	void format_and_write_header() override;

	static void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);

	int64_t process_timestamp(struct timeval ts);

private:
	struct timeval mrt{};
	std::vector<std::string> to_fill;
    Python *python_context;

	pcap_t *get_pcap_handle();

	pcap_t *open_live_handle();

	void set_filter(pcap_t *handle, char *filter);

	void perform_predict(const u_char *packet);

    std::string get_protocol_name(u_char *packet);

};

#endif
