#ifndef FILE_PARSER
#define FILE_PARSER

#include <algorithm>
#include <arpa/inet.h>
#include <csignal>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "config.hpp"
#include "file_writer.hpp"
#include "stats.hpp"
#include "superpacket.hpp"

/**
 * File parser abstract class, any input file type that is new must conform to
 * this abstract class definition
 */

class IOParser {
public:
	IOParser(const Config &config, const FileWriter &fileWriter);

	virtual ~IOParser() = default;

	virtual void perform() = 0;

	virtual void format_and_write_header() = 0;

	void print_stats();

	void set_conf(const Config &c);

	void set_filewriter(const FileWriter &writer);

	SuperPacket *process_packet(void *pkt);

	static void tokenize_line(const std::string &line, std::vector<std::string> &to_fill, char delimiter = ',');

	[[nodiscard]] const std::vector<int8_t>& get_bitstring_vec() const;

protected:
	Stats stat;
	Config config;
	FileWriter file_writer;
	uint32_t linktype;

	void write_output(SuperPacket *sp);
	// static void signal_handler(int signum);

	std::vector<std::string> custom_output;
	std::vector<int8_t> bitstring_vec;
	std::vector<std::string> fields_vec;

private:
	std::string output_type;
};

#endif
