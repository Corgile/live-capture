#ifndef FILE_WRITER
#define FILE_WRITER

#include <regex>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "config.hpp"
#include "radiotap_header.hpp"
#include "wlan_header.hpp"
#include "ethernet_header.hpp"
#include "icmp_header.hpp"
#include "ipv4_header.hpp"
#include "ipv6_header.hpp"
#include "payload.hpp"
#include "tcp_header.hpp"
#include "udp_header.hpp"

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
