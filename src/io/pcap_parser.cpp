#include "pcap_parser.hpp"
#include <sstream>
#include <utility>
#include <thread>

using CallbackData = u_char*;

void PCAPParser::perform() {
    std::unique_ptr<pcap_t, void(*)(pcap_t*)> device {this->open_live_handle(), &pcap_close};
    this->m_LinkType = pcap_datalink(device.get());
    pcap_loop(device.get(), 0, packet_handler, (CallbackData)this);
}

void PCAPParser::packet_handler(CallbackData callbackData, const struct pcap_pkthdr *packet_header, const u_char *packet) {
    auto callback_data = (PCAPParser *) callbackData;

    auto ip = (struct iphdr*)(packet + sizeof(struct ethhdr));
    auto pkt_hdr = packet + sizeof(struct ethhdr) + sizeof(struct iphdr);

    if (callback_data->m_LinkType == DLT_LINUX_SLL) {
        packet = (uint8_t *) packet + LINUX_COOKED_HEADER_SIZE;
    }
    auto pSuperPacket = callback_data->process_packet((void *) packet);
    if (pSuperPacket == nullptr) return;

    callback_data->write_output(pSuperPacket);
    callback_data->perform_predict(packet);
    callback_data->bitstring_vec.clear();
}

#ifdef MYTIMESTANP
int64_t PCAPParser::process_timestamp(struct timeval ts) {

    if (m_Config.relative_timestamps == 0) return -1;
    if (m_TimeVal.tv_sec == 0) return 0;
    int64_t diff = ts.tv_sec - m_TimeVal.tv_sec;
    int64_t ratio = (diff << 19) + (diff << 18) + (diff << 17) +
                (diff << 16) + (diff << 14) + (diff << 9) + (diff << 6);
    auto rts = ratio + ts.tv_usec - m_TimeVal.tv_usec;
    this->m_TimeVal = ts;
    return rts;
}
#endif

std::shared_ptr<SuperPacket> PCAPParser::process_packet(void *packet) {

    auto pSuperPacket =
            std::make_shared<SuperPacket>(packet, this->m_Config.max_payload_len, this->m_LinkType);

    if (pSuperPacket->check_parseable()) {
        if (this->m_Config.verbose) {
            pSuperPacket->print_packet(stderr);
        }
    } else {
        pSuperPacket.reset();
    }

    return pSuperPacket;
}

#ifdef MY_SETFILTER
pcap_t *PCAPParser::get_device_handle() {

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *device_handle;

    if (m_Config.live_capture == 0) {
        device_handle = pcap_open_offline_with_tstamp_precision(m_Config.infile.c_str(), PCAP_TSTAMP_PRECISION_MICRO, errbuf);
    } else {
        device_handle = this->open_live_handle();
    }
//    this->set_filter(device_handle, const_cast<char *>(m_Config.filter.c_str()));

    return device_handle;
}
#endif

pcap_t *PCAPParser::open_live_handle() {
    pcap_if_t *find_device_handle;
    // TODO 有太多个err_buf了
    char err_buf[PCAP_ERRBUF_SIZE];

    // get device_handle
    if (m_Config.device.empty()) {
        int32_t rv = pcap_findalldevs(&find_device_handle, err_buf);
        if (rv == -1) {
            std::cerr << "默认设备查询失败: " << err_buf << std::endl;
            exit(EXIT_FAILURE);
        }
        m_Config.device = find_device_handle->name;
    }

    std::cout << "\n ===== \033[1;31m 使用默认网卡设备: " << m_Config.device << "\033[0m\n\n";

    auto dev_name = m_Config.device.c_str();

    pcap_t *device_handle = pcap_create(dev_name, err_buf);
    if (device_handle == nullptr) {
        std::cerr << "创建设备的handle失败 " << dev_name << ": " << err_buf << "\n";
        exit(EXIT_FAILURE);
    }

    int ret = pcap_activate(device_handle);
    if (ret != 0) {
        std::cerr << "监听网卡失败 " << dev_name << ": " << pcap_statustostr(ret) << "\n";
        pcap_close(device_handle);
        exit(EXIT_FAILURE);
    }
    return device_handle;
}

#ifdef MY_SETFILTER
void PCAPParser::set_filter(pcap_t *handle, char *filter) const {
    if (!filter) return;

    bpf_u_int32 net = 0, mask = 0;
    struct bpf_program fp{};
    char errbuf[PCAP_ERRBUF_SIZE];

    if (m_Config.live_capture != 0) {
        // get mask
        if (pcap_lookupnet(m_Config.device.c_str(), &net, &mask, errbuf) == -1) {
            std::cerr << "Can't get netmask for device: " << m_Config.device << std::endl;
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
#endif

//PCAPParser::PCAPParser(FileWriter file_writer) : m_FileWriter(std::move(file_writer)) {
//    m_TimeVal.tv_sec = 0;
//    m_TimeVal.tv_usec = 0;
//    auto size = SIZE_IPV4_HEADER_BITSTRING
//                + SIZE_TCP_HEADER_BITSTRING
//                + SIZE_UDP_HEADER_BITSTRING
//                + SIZE_ICMP_HEADER_BITSTRING;
//    this->bitstring_vec.reserve(size << 5);
//    this->m_PythonContext = new Python();
//    this->m_Config = this->m_FileWriter.get_config();
//}

void PCAPParser::perform_predict(const u_char *packet) {

    std::ostringstream oss;
    for (int i = 0; i < this->bitstring_vec.size(); ++i) {
        if (i != 0) oss << ",";
        oss << int(this->bitstring_vec[i]);
    }
    auto bitstring = oss.str();
    std::string label = this->m_PythonContext->predict(bitstring);

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


#ifdef WITH_BENIGN
    std::ostringstream out;
    if (label != "benign") {
        out << "\033[1;37;41m";
    }

    out << "| " << PCAPParser::get_protocol_name((u_char *) packet)
        << " |  FROM IP: " << src_ip << " -> " << label
        << " -> TO IP: " << dst_ip << "\033[0m";

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
                return "TCP";
            case IPPROTO_UDP:
                return "UDP";
            case IPPROTO_ICMP:
                return "ICMP";
            default:
                return "Unknown";
        }
    }
    return "NaP";
}

void PCAPParser::write_output(const std::shared_ptr<SuperPacket> &sp) {
    sp->get_bitstring(&(this->m_Config), this->bitstring_vec);
}

PCAPParser::PCAPParser(Config config):m_Config(std::move(config)) {
    m_TimeVal.tv_sec = 0;
    m_TimeVal.tv_usec = 0;
    auto size = SIZE_IPV4_HEADER_BITSTRING
                + SIZE_TCP_HEADER_BITSTRING
                + SIZE_UDP_HEADER_BITSTRING
                + SIZE_ICMP_HEADER_BITSTRING;
    this->bitstring_vec.reserve(size << 5);
    this->m_PythonContext = new Python();
}
