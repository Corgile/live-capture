//
// Created by linyikai on 4/24/23.
//

#ifndef NPRINT_CLI_UTIL_H
#define NPRINT_CLI_UTIL_H

#include <getopt.h>
#include <iostream>
#include "config.hpp"

#ifdef i_want_to_perform_offline_file_handling

#include "stringfile_parser.hpp"
#include "nprint_parser.hpp"
#include "pcap_parser.hpp"

#define PARSE_INT(arg, dst)                                                    \
  do {                                                                         \
    char *end_ptr;                                                             \
    dst = strtol((arg), &end_ptr, 10);                                         \
    if (*end_ptr != '\0') {                                                    \
      std::cout << "Invalid input: " << (arg) << std::endl;                    \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)



static void show_help() {
	std::cout << R"""(
  -4, --ipv4                 include ipv4 headers
  -6, --ipv6                 include ipv6 headers
  -A, --absolute_timestamps  include absolute timestmap field
  -c, --count=INTEGER        number of packets to parse (if not all)
  -C, --csv_file=FILE        csv (hex packets) infile
  -d, --device=STRING        device to capture from if live capture
  -e, --eth                  include eth headers
  -f, --filter=STRING        filter for libpcap
  -F, --fill_int=INT8_T      integer to fill missing bits with
  -h, --nprint_filter_help   print regex possibilities
  -i, --icmp                 include icmp headers
  -N, --nPrint_file=FILE     nPrint infile
  -O, --write_index=INTEGER  Output file Index (first column) Options:
                             0: source IP (default)
                             1: destination IP
                             2: source port
                             3: destination port
                             4: flow (5-tuple)
                             5: wlan tx mac
  -p, --payload=PAYLOAD_SIZE include n bytes of payload
  -P, --pcap_file=FILE       pcap infile
  -r, --radiotap             include radiotap headers
  -R, --relative_timestamps  include relative timestamp field
  -S, --stats                print stats about packets processed when finished
  -t, --tcp                  include tcp headers
  -u, --udp                  include udp headers
  -V, --verbose              print human readable packets with nPrints
  -w, --wlan                 include wlan headers
  -W, --write_file=FILE      file for output, else stdout
  -x, --nprint_filter=STRING regex to filter bits out of nPrint. nprint -h for
                             details
  -?, --help                 Give this help list
      --usage                Give a short usage message
      --version              Print program version
)""" << std::endl;
}

Config parse_args(const int &argc, char **argv) {
	Config config;
	int opt;
	int long_index = 0;
	const char *short_options = "46Ac:C:d:ef:F:hNi:Nop:Pr:RStuVwW:x:?";
	struct option long_options[] = {
			{"ipv4",                no_argument,       nullptr, '4'},
			{"ipv6",                no_argument,       nullptr, '6'},
			{"absolute_timestamps", no_argument,       nullptr, 'A'},
			{"count",               required_argument, nullptr, 'c'},
			{"csv_file",            required_argument, nullptr, 'C'},
			{"device",              required_argument, nullptr, 'd'},
			{"eth",                 no_argument,       nullptr, 'e'},
			{"filter",              required_argument, nullptr, 'f'},
			{"fill_int",            required_argument, nullptr, 'F'},
			{"nprint_filter_help",  no_argument,       nullptr, 'h'},
			{"icmp",                no_argument,       nullptr, 'i'},
			{"nPrint_file",         required_argument, nullptr, 'N'},
			{"write_index",         required_argument, nullptr, 'O'},
			{"payload",             required_argument, nullptr, 'p'},
			{"pcap_file",           required_argument, nullptr, 'P'},
			{"radiotap",            no_argument,       nullptr, 'r'},
			{"relative_timestamps", no_argument,       nullptr, 'R'},
			{"stats",               no_argument,       nullptr, 'S'},
			{"tcp",                 no_argument,       nullptr, 't'},
			{"udp",                 no_argument,       nullptr, 'u'},
			{"verbose",             no_argument,       nullptr, 'V'},
			{"wlan",                no_argument,       nullptr, 'w'},
			{"write_file",          required_argument, nullptr, 'W'},
			{"nprint_filter",       required_argument, nullptr, 'x'},
			{"help",                no_argument,       nullptr, '?'},
			{"usage",               no_argument,       nullptr, '?'},
			{nullptr, 0,                               nullptr, 0}};
	const char *filter_help = R"""(
################################################################################
### nPrint Regex Filter Help:
### All field names follow syntax: proto_field_bit
### Each protocol in help follow syntax: proto field numbits

# Ethernet
eth eth_dhost      48
eth eth_shost      48
eth eth_ethertype  16

# IPv4
ipv4 ipv4_version         4
ipv4 ipv4_header_length   4
ipv4 ipv4_type_of_service 8
ipv4 ipv4_total_length    16
ipv4 ipv4_id	       		  16
ipv4 ipv4_r_bit	      		1
ipv4 ipv4_df_bit	     	  1
ipv4 ipv4_mf_bit	     	  1
ipv4 ipv4_frag_offset	    13
ipv4 ipv4_ttl	       		  8
ipv4 ipv4_protocol	     	8
ipv4 ipv4_checksum	    	16
ipv4 ipv4_src_ip	      	32
ipv4 ipv4_dst_ip	      	32
ipv4 ipv4_optional	     	320

# IPv6
ipv6 ipv6_ver       4
ipv6 ipv6_tc        8
ipv6 ipv6_fl       20
ipv6 ipv6_len      16
ipv6 ipv6_nh        8
ipv6 ipv6_hl        8
ipv6 ipv6_src     128
ipv6 ipv6_dst     128

# TCP
tcp tcp_sprt       16
tcp tcp_dprt       16
tcp tcp_seq        32
tcp tcp_ackn       32
tcp tcp_doff        4
tcp tcp_res         3
tcp tcp_ns          1
tcp tcp_cwr         1
tcp tcp_ece         1
tcp tcp_urg         1
tcp tcp_ackf        1
tcp tcp_psh         1
tcp tcp_rst         1
tcp tcp_syn         1
tcp tcp_wsize      16
tcp tcp_cksum      16
tcp tcp_urp        16
tcp tcp_opt       320

# UDP
udp udp_sport      16
udp udp_dport      16
udp udp_len        16
udp udp_cksum      16

# ICMP
icmp icmp_type     8
icmp icmp_code     8
icmp icmp_cksum    16
icmp icmp_roh      32

# Payload
payload payload_bit n


### End of nPrint regex filter help, exiting
################################################################################)""";

	while ((opt = getopt_long(argc, argv, short_options, long_options, &long_index)) != -1) {
		switch (opt) {
			case 'h':
				std::cout << filter_help << std::endl;
				exit(0);
			case '?':
				show_help();
				exit(0);
			case 'A':
				config.absolute_timestamps = 1;
				break;
			case 'V':
				config.verbose = 1;
				break;
			case 'd':
				config.device = optarg;
				break;
			case 'f':
				config.filter = optarg;
				break;
#ifdef handle_offline_file
				case 'c':
				PARSE_INT(optarg, config.num_packets);
				break;
			case 'F':
				PARSE_INT(optarg, config.fill_with);
				break;
			case 'p':
				PARSE_INT(optarg, config.payload);
				break;
			case 'O':
				PARSE_INT(optarg, config.output_index);
				if (config.output_index > 5 || config.output_index < 0) {
					fprintf(stderr, "Invalid index configuration, exiting\n");
					exit(EXIT_FAILURE);
				}
				break;
#endif
			case 'x':
				config.regex = optarg;
				break;
			case 'P':
				config.infile = optarg;
				config.pcap = 1;
				break;
			case 'N':
				config.infile = optarg;
				config.nprint = 1;
				break;
			case 'C':
				config.infile = optarg;
				config.csv = 1;
				break;
			case 'W':
				config.outfile = optarg;
				break;
			case 'S':
				config.stats = 1;
				break;
			case 'e':
				config.eth = 1;
				break;
			case 'r':
				config.radiotap = 1;
				break;
			case 'w':
				config.wlan = 1;
				break;
			case '4':
				config.ipv4 = 1;
				break;
			case '6':
				config.ipv6 = 1;
				break;
			case 'u':
				config.udp = 1;
				break;
			case 't':
				config.tcp = 1;
				break;
			case 'i':
				config.icmp = 1;
				break;
			case 'R':
				config.relative_timestamps = 1;
				break;
			default:;
		}
	}
	return config;
}


static void process(const int & argc, char** argv) {
	Config config = parse_args(argc, argv);
	FileWriter file_writer(config);
	if (config.infile.empty()) {
		config.live_capture = 1;
		auto pcap_parser = new PCAPParser(config, file_writer);
		pcap_parser->format_and_write_header();
		pcap_parser->perform();
		if (config.stats == 1) {
			pcap_parser->print_stats();
		}
		delete pcap_parser;
	} else {
		if ((config.pcap + config.csv + config.nprint) > 1) {
			fprintf(stderr, "Only one of {pcap, csv, nprint} input files can be selected\n");
			exit(1);
		} else if (config.pcap == 1) {
			IOParser *pcap_parser = new PCAPParser(config, file_writer);
			pcap_parser->format_and_write_header();
			pcap_parser->perform();
			if (config.stats == 1) {
				pcap_parser->print_stats();
			}
			delete pcap_parser;
		} else if (config.csv == 1) {
			IOParser *stringfile_parser = new StringfileParser(config, file_writer);
			stringfile_parser->format_and_write_header();
			stringfile_parser->perform();
			if (config.stats == 1) {
				stringfile_parser->print_stats();
			}
			delete stringfile_parser;
		} else if (config.nprint == 1) {
			/* need an outfile for nprint, can't print pcap to stdout */
			if (config.outfile.empty()) {
				fprintf(stderr, "nprint infile option requires outfile for writing reversed pcap\n");
				exit(1);
			} else {
				IOParser *nprint_parser = new NprintParser(config, file_writer);
				nprint_parser->format_and_write_header();
				nprint_parser->perform();
				if (config.stats == 1) {
					nprint_parser->print_stats();
				}
				delete nprint_parser;
			}
		} else {
			fprintf(stderr, "Unsupported option configuration\n");
			exit(1);
		}
	}
}

#endif


#endif //NPRINT_CLI_UTIL_H
