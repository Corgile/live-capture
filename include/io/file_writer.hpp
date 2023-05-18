#ifndef FILE_WRITER
#define FILE_WRITER

#include <regex>
#include <cerrno>
#include <iostream>
#include <cstdlib>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>

#include "config.hpp"
#include "headers/ethernet_header.hpp"
#include "headers/icmp_header.hpp"
#include "headers/ipv4_header.hpp"
#include "headers/ipv6_header.hpp"
#include "headers/payload.hpp"
#include "headers/tcp_header.hpp"
#include "headers/udp_header.hpp"

/**
 * FileWriter takes care of output for all nPrints
 */

class FileWriter {
public:

	explicit FileWriter(const Config &);

	void set_conf(const Config &);

	void write_header(std::vector<std::string> header);

	void write_csv_stringvec(std::vector<std::string> &v);

	void write_bitstring_line(std::vector<std::string> &prefix, std::vector<int8_t> &bistring_vec);

    Config get_config();

private:
	void recursive_mkdir(char *path);

	FILE *fopen_mkdir(char *path);

	Config config;
	std::vector<uint32_t> keep_indexes;

	std::vector<std::string> build_bitstring_header(std::vector<std::string> header);

	uint32_t payload_len{};
	FILE *outfile = nullptr;
};

#endif
