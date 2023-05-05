#ifndef PCAP_PARSER
#define PCAP_PARSER

#if defined(__NetBSD__)
#include <net/if_ether.h>
#else
#include <net/ethernet.h>
#endif

#define LINUX_COOKED_HEADER_SIZE 16

#include <pcap.h>

#include "config.hpp"
//#include "file_writer.hpp"
#include "superpacket.hpp"
#include "call_python.hpp"
#include <memory>

/**
 * Parses a PCAP from a written file
 */

class PCAPParser{//; : public IOParser {
public:

//	explicit PCAPParser(FileWriter file_writer);
	explicit PCAPParser(Config config);

	void perform();

//	void format_and_write_header();

	static void packet_handler(u_char *user_data, const struct pcap_pkthdr *packet_header, const u_char *packet);

//	int64_t process_timestamp(struct timeval ts);

    std::shared_ptr<SuperPacket> process_packet(void *packet);

private:
	struct timeval m_TimeVal{};
//	std::vector<std::string> to_fill;
    Python *m_PythonContext;

//	pcap_t *get_device_handle();

	[[nodiscard]] pcap_t *open_live_handle();

//	void set_filter(pcap_t *handle, char *filter) const;

	void perform_predict(const u_char *packet);

    static std::string get_protocol_name(u_char *packet);

//    Stats m_Stat;
    Config m_Config;
//    FileWriter m_FileWriter;
    uint32_t m_LinkType{};

    void write_output(const std::shared_ptr<SuperPacket>& sp);
    // static void signal_handler(int signum);

    std::vector<std::string> custom_output;
    std::vector<int8_t> bitstring_vec;
    std::vector<std::string> fields_vec;

};

#endif
