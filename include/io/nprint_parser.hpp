#ifndef NPRINT_PARSER
#define NPRINT_PARSER

#include <tuple>

#include <netinet/ip.h>
#include <pcap.h>

#include "io_parser.hpp"
#include "superpacket.hpp"

/**
 * NprintParser is used to transform any nPrint back to a PCAP
 */

class NprintParser : public IOParser {
public:
	NprintParser(const Config &config, const FileWriter &fileWriter);

	void perform() override;

	void format_and_write_header() override;

private:
	static std::string clean_line(std::string &line);

	static uint8_t *transform_bitstring(std::string &bits);

	std::tuple<void *, uint64_t> parse_packet(std::string &bits);
};

#endif
