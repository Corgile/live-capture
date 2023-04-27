#include "pcap_parser.hpp"
#include <iostream>
#include <python3.7m/Python.h>


void PCAPParser::perform() {
    pcap_t *live_cap = this->open_live_handle();
    this->set_filter(live_cap, const_cast<char *>(m_config.filter.c_str()));
    this->linktype = pcap_datalink(live_cap);
    pcap_loop(live_cap, 0, packet_handler, reinterpret_cast<u_char *>(this));
    pcap_close(live_cap);
}

void PCAPParser::packet_handler(u_char *user_data, const struct pcap_pkthdr *packet_header, const u_char *packet) {
    auto pcp = reinterpret_cast<PCAPParser *>(user_data);
    if (pcp->linktype == DLT_LINUX_SLL) {
        packet = reinterpret_cast<const uint8_t *>(packet) + LINUX_COOKED_HEADER_SIZE;
    }

    pcp->perform_predict(packet);

}

pcap_t *PCAPParser::open_live_handle() {
    pcap_if_t *l;
    char err_buf[PCAP_ERRBUF_SIZE];
    /* get device */
    if (m_config.device.empty()) {
        int32_t rv = pcap_findalldevs(&l, err_buf);
        if (rv == -1) {
            std::cerr << "Failure looking up default device: " << err_buf << std::endl;
            exit(2);
        }
        m_config.device = l->name;
    }
    /* open device */
    auto handle = pcap_open_live(m_config.device.c_str(), BUFSIZ, 1, 1000, err_buf);
    if (handle == nullptr) {
        std::cerr << "Couldn't open device: " << err_buf << std::endl;
        exit(2);
    }

    return handle;
}

void PCAPParser::set_filter(pcap_t *handle, char *filter) const {
    if (!filter) return;

    bpf_u_int32 net = 0, mask = 0;
    struct bpf_program fp{};
    char err_buf[PCAP_ERRBUF_SIZE];

    if (m_config.live_capture != 0) {
        /** get mask*/
        if (pcap_lookupnet(m_config.device.c_str(), &net, &mask, err_buf) == -1) {
            std::cerr << "Can't get netmask for device: " << m_config.device << std::endl;
        }
    }

    if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
        std::cerr << "Couldn't parse filter " << filter << ": " << pcap_geterr(handle) << std::endl;
        exit(2);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Couldn't install filter " << filter << ": " << pcap_geterr(handle) << std::endl;
        exit(2);
    }
}

PCAPParser::PCAPParser(Config config, FileWriter file_writer)
        : m_config(std::move(config)),
          m_file_writer(std::move(file_writer)) {
    mrt.tv_sec = 0;
    mrt.tv_usec = 0;
    auto size = SIZE_IPV4_HEADER_BITSTRING
                + SIZE_TCP_HEADER_BITSTRING
                + SIZE_UDP_HEADER_BITSTRING
                + SIZE_ICMP_HEADER_BITSTRING;
    to_fill.reserve(size << 5);
    this->linktype = -1;
}

void PCAPParser::perform_predict(const u_char *packet) {

	Py_Initialize();
	PyRun_SimpleString("print('Hello World')");
	Py_Finalize();
	return;

    std::vector<int> most_important_indices = {
            1, 107, 231, 25, 109, 15, 233, 0, 2, 3, 235, 4,
            29, 234, 232, 199, 239, 5, 230, 16, 180, 98, 236,
            6, 31, 238, 237, 30, 24, 9, 11, 126, 13, 7, 198,
            10, 43, 56, 50, 28, 608, 202, 318, 201, 117, 8,
            23, 34, 111, 12, 48, 33, 51, 32, 27, 45, 14, 46,
            54, 74, 119, 40, 228, 125, 37, 224, 35, 44, 61,
            248, 118, 70, 121, 60, 49, 52, 96, 206, 17, 39,
            36, 18, 38, 123, 41, 241, 57, 240, 66, 222, 20,
            122, 62, 134, 204, 42, 69, 59, 192, 229, 203, 226,
            120, 65, 55, 129, 26, 130, 19, 127, 227, 21, 99,
            139, 58, 64, 68, 213, 113, 140, 135, 141, 53, 67, 200, 22, 72, 63
    };
    std::vector<int> samples(768);
    std::vector<std::string> labels{
            "benign",
            "ddos",
            "dos",
            "ftp-patator",
            "infiltration",
            "port-scan",
            "ssh-patator",
            "web-attack"
    };
    for (const auto &item: this->bitstring_vec) {
        samples.emplace_back(int(item));
    }

    std::vector<float> X(128);
    for (int i = 0; i < 128; ++i) {
        X[i] = float(samples[most_important_indices[i]]);
    }


    //auto result = this->m_model_file->predict(inputs);

	// FIXME
    auto vec = std::vector<int>(); //result[0].as_vector();
    auto values = vec.data();
    size_t _size = vec.size(), index = 0;
    float _max = values[index];
    for (int i = 0; i < _size; ++i) {
        if (_max >= values[i]) continue;
        _max = values[i];
        index = i;
    }

#pragma region 处理 MAC 地址
//	struct ether_header *eth = (struct ether_header *)packet;
//	char src_mac[18], dst_mac[18];
//	sprintf(src_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
//	        eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
//	        eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
//
//	sprintf(dst_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
//	        eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
//	        eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
//	printf("Source MAC: %s\n", src_mac);
//	printf("Destination MAC: %s\n", dst_mac);
#pragma endregion

#pragma region 处理 IP 地址

    auto ip = (struct iphdr *) (packet + sizeof(struct ether_header));
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->saddr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->daddr), dst_ip, INET_ADDRSTRLEN);
#pragma endregion

    std::cout << " |" << PCAPParser::get_protocol_name((u_char*)packet)
              << " |  Source IP: " << src_ip << " -> "
              << labels[index]
              << " -> Destination IP: " << dst_ip << std::endl;
}


std::string PCAPParser::get_protocol_name(u_char *packet) {
    u_char *ip_data;
    u_char protocol;
    auto ether_header = (u_char *) packet;
    int ether_type = ((int) ether_header[12] << 8) + ether_header[13];
    if (ether_type == 0x0800) { // IPv4 数据报
        ip_data = (u_char *) (packet) + 14;
        protocol = ip_data[9];

        switch (protocol) {
            case IPPROTO_TCP:
//                std::cout << "TCP" << ", Source: "
//                          << (int) ip_data[12] << "." << (int) ip_data[13] << "." << (int) ip_data[14] << "." << (int) ip_data[15] << ":" << ((int) ip_data[20] << 8 | (int) ip_data[21]) << ", Destination: "
//                          << (int) ip_data[16] << "." << (int) ip_data[17] << "." << (int) ip_data[18] << "." << (int) ip_data[19] << ":" << ((int) ip_data[22] << 8 | (int) ip_data[23])
//                          << std::endl;
//                  break;
                return "TCP";

            case IPPROTO_UDP:
//                std::cout << "UDP" << ", Source: "
//                          << (int) ip_data[12] << "." << (int) ip_data[13] << "." << (int) ip_data[14] << "." << (int) ip_data[15] << ":" << ((int) ip_data[20] << 8 | (int) ip_data[21]) << ", Destination: "
//                          << (int) ip_data[16] << "." << (int) ip_data[17] << "." << (int) ip_data[18] << "." << (int) ip_data[19] << ":" << ((int) ip_data[22] << 8 | (int) ip_data[23])
//                          << std::endl;
//                break;
                return "UDP";

            case IPPROTO_ICMP:
//                std::cout << "ICMP" << ", Source: "
//                          << (int) ip_data[12] << "." << (int) ip_data[13] << "." << (int) ip_data[14] << "." << (int) ip_data[15] << ", Destination: "
//                          << (int) ip_data[16] << "." << (int) ip_data[17] << "." << (int) ip_data[18] << "." << (int) ip_data[19]
//                          << std::endl;
//                break;
                return "ICMP";

            default:
//                std::cout << "Unknown protocol" << std::endl;
                return "Unkown";
        }
    }
    return "NaP";
}
