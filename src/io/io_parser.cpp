#include "io_parser.hpp"

#define CUSTOM_OUTPUT_RESERVE_SIZE 50
#define BITSTRING_RESERVE_SIZE 10000

void IOParser::set_conf(const Config &c) {
	this->config = c;
	/** Reserve vectors and use them the entire time */
	this->custom_output.reserve(CUSTOM_OUTPUT_RESERVE_SIZE);
	this->bitstring_vec.reserve(BITSTRING_RESERVE_SIZE);
}

void IOParser::set_filewriter(const FileWriter &writer) { this->file_writer = writer; }

void IOParser::tokenize_line(const std::string &line, std::vector<std::string> &to_fill, char delimiter) {
	std::string token;
	std::stringstream ss;
	to_fill.clear();
	ss.str(line);
	while (getline(ss, token, delimiter)) {
		to_fill.push_back(token);
	}
}

SuperPacket *IOParser::process_packet(void *pkt) {
	bool parseable;
	SuperPacket *sp;
	std::string src_ip;
	std::vector<std::string> to_fill;
	uint8_t network_layer, transport_layer;
	to_fill.clear();
	sp = new SuperPacket(pkt, this->config.payload, this->linktype);
	parseable = sp->check_parseable();
	if (parseable) {
		if (this->config.verbose) {
			sp->print_packet(stderr);
		}
		/** Exit when done */
		auto ge = this->stat.get_packets_processed() >= this->config.num_packets;
		if (this->config.num_packets && ge) exit(0);
		std::tie(network_layer, transport_layer) = sp->get_packet_type();
	} else {
		delete sp;
		sp = nullptr;
		network_layer = 0;
		transport_layer = 0;
	}
	this->stat.update(parseable, network_layer, transport_layer);

	return sp;
}

void IOParser::write_output(SuperPacket *sp) {
//    std::cout << "sp->get_bitstring(&(this->config), this->bitstring_vec);" << std::endl;
	sp->get_bitstring(&(this->config), this->bitstring_vec);
//    for (const auto &item: this->bitstring_vec) {
//        std::cout << int(item) <<" ";
//    }

//	this->file_writer.write_bitstring_line(this->custom_output, this->bitstring_vec);
//	this->file_writer.write_csv_stringvec(this->bitstring_vec);
//	this->bitstring_vec.clear();
	this->custom_output.clear();
	delete sp;
}

void IOParser::print_stats() {
	this->stat.print_stats();
}

IOParser::IOParser(const Config &config, const FileWriter &fileWriter)
		: file_writer(fileWriter) {
	this->set_conf(config);
}

const std::vector<int8_t> &IOParser::get_bitstring_vec() const  {
	return bitstring_vec;
}

