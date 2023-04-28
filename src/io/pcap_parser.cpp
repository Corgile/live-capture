#include "pcap_parser.hpp"
#include<algorithm>


void PCAPParser::perform() {
    pcap_t *f = get_pcap_handle();
    this->linktype = pcap_datalink(f);
    pcap_loop(f, 0, packet_handler, (u_char *) this);
    pcap_close(f);
}

void PCAPParser::packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
//    std::cout
//    << "\033[34m"
//    << "void PCAPParser::packet_handler(u_char *, const struct pcap_pkthdr *, const u_char *)"
//    << "\033[0m" << std::endl;
    auto pcap_parser = (PCAPParser *) user_data;
    if (pcap_parser->linktype == DLT_LINUX_SLL) {
        packet = (uint8_t *) packet + LINUX_COOKED_HEADER_SIZE;
    }
    auto sp = pcap_parser->process_packet((void *) packet);
    if (sp == nullptr) return;

    auto rts = pcap_parser->process_timestamp(pkthdr->ts);
    pcap_parser->custom_output.push_back(sp->get_index(&(pcap_parser->config)));
    if (rts != -1) {
        pcap_parser->custom_output.push_back(std::to_string(rts));
    }
    if (pcap_parser->config.absolute_timestamps) {
        pcap_parser->custom_output.push_back(std::to_string(pkthdr->ts.tv_sec));
        pcap_parser->custom_output.push_back(std::to_string(pkthdr->ts.tv_usec));
    }
    pcap_parser->write_output(sp);
    pcap_parser->perform_predict(packet);
    pcap_parser->bitstring_vec.clear();
}

void PCAPParser::format_and_write_header() {
    std::vector<std::string> header(4);
    header.emplace_back(config.index_map.find(config.output_index)->second);
    if (config.relative_timestamps == 1) {
        header.emplace_back("rts");
    }
    if (config.absolute_timestamps == 1) {
        header.emplace_back("tv_sec");
        header.emplace_back("tv_usec");
    }

    file_writer.write_header(header);
}

int64_t PCAPParser::process_timestamp(struct timeval ts) {
    int64_t rts;

    if (config.relative_timestamps == 0) return -1;

    if (mrt.tv_sec == 0) {
        rts = 0;
    } else {
        auto diff = ts.tv_sec - mrt.tv_sec;
        int ratio = (diff << 19) + (diff << 18) + (diff << 17) +
                    (diff << 16) + (diff << 14) + (diff << 9) + (diff << 6);
        rts = ratio + ts.tv_usec - mrt.tv_usec;
    }
    this->mrt = ts;
    return rts;
}

pcap_t *PCAPParser::get_pcap_handle() {

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *f;

    if (config.live_capture == 0) {
        f = pcap_open_offline_with_tstamp_precision(config.infile.c_str(), PCAP_TSTAMP_PRECISION_MICRO, errbuf);
    } else {
        f = this->open_live_handle();
    }
    this->set_filter(f, const_cast<char *>(config.filter.c_str()));

    return f;
}

pcap_t *PCAPParser::open_live_handle() {
//	pcap_t *handle;
    pcap_if_t *l;
    char errbuf[PCAP_ERRBUF_SIZE];

    /* get device */
    if (config.device.empty()) {
        int32_t rv = pcap_findalldevs(&l, errbuf);
        if (rv == -1) {
            std::cerr << "Failure looking up default device: " << errbuf << std::endl;
            exit(2);
        }
        config.device = l->name;
    }
    /* open device */
    auto handle = pcap_open_live(config.device.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Couldn't open device: " << errbuf << std::endl;
        exit(2);
    }

    return handle;
}

void PCAPParser::set_filter(pcap_t *handle, char *filter) {
    if (!filter) return;

    bpf_u_int32 net = 0, mask = 0;
    struct bpf_program fp{};
    char errbuf[PCAP_ERRBUF_SIZE];

    if (config.live_capture != 0) {
        /** get mask*/
        if (pcap_lookupnet(config.device.c_str(), &net, &mask, errbuf) == -1) {
            std::cerr << "Can't get netmask for device: " << config.device << std::endl;
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

PCAPParser::PCAPParser(const Config &config, const FileWriter &file_writer)
        : IOParser(config, file_writer) {
    mrt.tv_sec = 0;
    mrt.tv_usec = 0;
    auto size =
            SIZE_IPV4_HEADER_BITSTRING
            + SIZE_TCP_HEADER_BITSTRING
            + SIZE_UDP_HEADER_BITSTRING
            + SIZE_ICMP_HEADER_BITSTRING;
    to_fill.reserve(size << 5);
//	PCAPParser::format_and_write_header();
    this->python_context = new Python();
}

void PCAPParser::perform_predict(const u_char *packet) {

    std::ostringstream oss;

    for (int i = 0; i < this->bitstring_vec.size(); ++i) {
        if (i != 0) {
            oss << ",";
        }
        oss << int(this->bitstring_vec[i]);
    }

//    std::cout << "数据包长度: "
//              << this->bitstring_vec.size() << "->"
//              << oss.str().length() << std::endl;

    auto bitstring = oss.str();
    std::string label = this->python_context->predict(bitstring);

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

#define FUCK
#ifdef FUCK
#pragma region 处理 IP 地址
    auto ip = (struct iphdr *) (packet + sizeof(struct ether_header));
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->saddr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->daddr), dst_ip, INET_ADDRSTRLEN);
#pragma endregion

    std::ostringstream out;

#ifdef WITH_BENIGN
    if (label != "benign") {
        out << "\033[1;37;41m";
    }

    out << PCAPParser::get_protocol_name((u_char *) packet)
        << " |  Source IP: " << src_ip << " -> " << label
        << " -> Destination IP: " << dst_ip << "\033[0m";

    std::cout << out.str() << std::endl;
#else
    if (label != "benign") {
        out << "\033[1;37;41m";
         out << PCAPParser::get_protocol_name((u_char *) packet)
        << " |  Source IP: " << src_ip << " -> " << label
        << " -> Destination IP: " << dst_ip << "\033[0m";

        std::cout << out.str() << std::endl;
    }
#endif

#endif
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
