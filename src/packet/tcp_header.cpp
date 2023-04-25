#include "tcp_header.hpp"

void *TCPHeader::get_raw() {
    return (void *)raw;
}

void TCPHeader::set_raw(void *raw_data) {
	this->raw = (struct tcphdr *) raw_data;
}

void TCPHeader::print_header(FILE *out) {
	if (raw == nullptr) {
		fprintf(out, "TCPHeader: raw data not set\n");
		return;
	}
	fprintf(out, "TCPHeader: src_prt: %d, dst_prt: %d\n", ntohs(raw->th_sport),
	        ntohs(raw->th_dport));
}

uint32_t TCPHeader::get_header_len() {
    return raw->th_off * 4;
}

void TCPHeader::get_bitstring(std::vector<int8_t> &to_fill, int8_t fill_with) {
	uint32_t tcp_header_byte_size, zero_byte_width;

	if (raw == nullptr) {
		make_bitstring(SIZE_TCP_HEADER_BITSTRING, nullptr, to_fill, fill_with);
		return;
	}
	tcp_header_byte_size = raw->th_off * 4;
	zero_byte_width = SIZE_TCP_HEADER_BITSTRING - tcp_header_byte_size;
	make_bitstring(tcp_header_byte_size, (void *) raw, to_fill, fill_with);
	make_bitstring(zero_byte_width, nullptr, to_fill, fill_with);
}

void TCPHeader::get_bitstring_header(std::vector<std::string> &to_fill) {
	std::vector<std::tuple<std::string, uint32_t>> v;
	v.reserve(18);
	v.emplace_back("tcp_sprt", 16);
	v.emplace_back("tcp_dprt", 16);
	v.emplace_back("tcp_seq", 32);
	v.emplace_back("tcp_ackn", 32);
	v.emplace_back("tcp_doff", 4);
	v.emplace_back("tcp_res", 3);
	v.emplace_back("tcp_ns", 1);
	v.emplace_back("tcp_cwr", 1);
	v.emplace_back("tcp_ece", 1);
	v.emplace_back("tcp_urg", 1);
	v.emplace_back("tcp_ackf", 1);
	v.emplace_back("tcp_psh", 1);
	v.emplace_back("tcp_rst", 1);
	v.emplace_back("tcp_syn", 1);
	v.emplace_back("tcp_fin", 1);
	v.emplace_back("tcp_wsize", 16);
	v.emplace_back("tcp_cksum", 16);
	v.emplace_back("tcp_urp", 16);
	v.emplace_back("tcp_opt", 320);

	PacketHeader::make_bitstring_header(v, to_fill);
}

std::string TCPHeader::get_port(bool src) {
	if (raw == nullptr) {
		return "nullptr";
	} else if (src) {
		return std::to_string(ntohs(raw->th_sport));
	} else {
		return std::to_string(ntohs(raw->th_dport));
	}
}
