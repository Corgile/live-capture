#include "ethernet_header.hpp"

void *EthHeader::get_raw() {
    return (void *)raw;
}

void EthHeader::set_raw(void *raw_data) {
	this->raw = (struct ether_header *) raw_data;
}

void EthHeader::print_header(FILE *out) {
	if (raw == nullptr) {
		fprintf(out, "EthHeader: raw data not set\n");
		return;
	}
	fprintf(out, "Eth Header: src: %02x:%02x:%02x:%02x:%02x:%02x, ",
	        raw->ether_shost[0], raw->ether_shost[1], raw->ether_shost[2],
	        raw->ether_shost[3], raw->ether_shost[4], raw->ether_shost[5]);
	fprintf(out, "dst: %02x:%02x:%02x:%02x:%02x:%02x, ether_type: %u\n",
	        raw->ether_dhost[0], raw->ether_dhost[1], raw->ether_dhost[2],
	        raw->ether_dhost[3], raw->ether_dhost[4], raw->ether_dhost[5],
	        ntohs(raw->ether_type));
}

uint32_t EthHeader::get_header_len() {
    return 14;
}

void EthHeader::get_bitstring(std::vector<int8_t> &to_fill, int8_t fill_with) {
    make_bitstring(SIZE_ETH_HEADER_BITSTRING, raw, to_fill, fill_with);
}

void EthHeader::get_bitstring_header(std::vector<std::string> &to_fill) {
	std::vector<std::tuple<std::string, uint32_t>> v(3);
	v.emplace_back("eth_dhost", 48);
	v.emplace_back("eth_shost", 48);
	v.emplace_back("eth_ethertype", 16);

	PacketHeader::make_bitstring_header(v, to_fill);
}
