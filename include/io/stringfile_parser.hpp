#ifndef STRINGFILE_PARSER
#define STRINGFILE_PARSER

#include "io_parser.hpp"

/**
 * StringfileParser parses hex encoded packets in a CSV.For example, the
 * output of a zmap scan
 */

class StringfileParser : public IOParser {
public:

	StringfileParser(const Config &config, const FileWriter &writer);

	void perform();

	void format_and_write_header();

private:

	uint32_t num_cols;

	static int hex_value(char hex_digit);

	void format_custom_output(std::vector<std::string> &tokens);

	static std::string hex_to_string(std::string input);
};

#endif
