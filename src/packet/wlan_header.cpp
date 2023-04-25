#include "wlan_header.hpp"

void *WlanHeader::get_raw() {
    return (void *) raw;
}

void WlanHeader::set_raw(void *_raw) { this->raw = (struct wlan_header *) _raw; }

void WlanHeader::print_header(FILE *out) {
	if (raw == nullptr) {
		printf("WlanHeader: raw data not set\n");
	} else {
		fprintf(out, "Wlan Header: rx-addr: %02x:%02x:%02x:%02x:%02x:%02x, ",
		        raw->rx_addr[0], raw->rx_addr[1], raw->rx_addr[2], raw->rx_addr[3],
		        raw->rx_addr[4], raw->rx_addr[5]);
		fprintf(out, "wlan-type: %u\n", raw->type);
	}
}

uint32_t WlanHeader::get_header_len() {
    return SIZE_WLAN_HEADER_BITSTRING;  // TODO: we only parse the first 10 bytes at this time 
}

void WlanHeader::get_bitstring(std::vector<int8_t> &to_fill, int8_t fill_with) {
    make_bitstring(SIZE_WLAN_HEADER_BITSTRING, raw, to_fill, fill_with);
}

std::string WlanHeader::get_tx_mac() {
    switch (raw->type) {
        //  3 subtypes have no TX max address
        case 0xc4:  // CTS Clear To Send
        case 0xd4:  // ACK
        case 0xe4:  // CF-End
            return "None";
        default:
            char buf[18];
            sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
              raw->tx_addr[0],
              raw->tx_addr[1],
              raw->tx_addr[2],
              raw->tx_addr[3],
              raw->tx_addr[4],
              raw->tx_addr[5]);
            return buf;
    }
}

void WlanHeader::get_bitstring_header(std::vector<std::string> &to_fill) {
	std::vector<std::tuple<std::string, uint32_t>> v(4);
	v.emplace_back("wlan_type", 1 * 8);
	v.emplace_back("wlan_flag", 1 * 8);
	v.emplace_back("wlan_duration", 2 * 8);
	v.emplace_back("wlan_rx_addr", 6 * 8);

	PacketHeader::make_bitstring_header(v, to_fill);
}
