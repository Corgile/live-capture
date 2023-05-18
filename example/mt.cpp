//
// Created by gzhuadmin on 5/5/23.
//

#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <pcap.h>

char errbuf[PCAP_ERRBUF_SIZE];

void packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body) {

    auto ether_header = (u_char *) packet_body;
    int ether_type = ((int) ether_header[12] << 8) + ether_header[13];
    if (ether_type != 0x0800) { // IPv4 数据报
        return;
    }
    const u_char *header_ptr = (const u_char *)packet_header;
    u_char *ip_data = (u_char *) (packet_body) + 14;
    u_char protocol = ip_data[9];
    if(protocol != IPPROTO_TCP && protocol != IPPROTO_ICMP && protocol != IPPROTO_UDP)
        return;

    // 获取IP头的长度，以计算TCP/UDP/ICMP头部的字节数
    int ip_header_length = ((*header_ptr) & 0x0f) << 2;

    // 获取捕获时间戳
    time_t t_packet = packet_header->ts.tv_sec;
    tm *packet_time_info = localtime(&t_packet);

    // 打印时间
    char time_str[80];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", packet_time_info);
    std::cout << "\n\033[31m-----------------------------------------------\033[0m\n";
    std::cout << "Time: " << time_str << "." << packet_header->ts.tv_usec;

    // 获取数据包长度
    std::cout << " Length: " << packet_header->len << " bytes";

    // 打印数据包头
    std::cout << " Header:" << std::endl;


    switch(protocol) {
        case IPPROTO_TCP:
            std::cout << "Protocol: TCP, header data:" << std::endl;
            for(int i=0; i<20; i++) {
                printf("%02X ", *(header_ptr+ip_header_length+i));
            }
            std::cout << "\n\033[33m+++++++++++++++++++++++++++++++++++++++++\033[0m\n";
            break;
        case IPPROTO_UDP:
            std::cout << "Protocol: UDP, header data:" << std::endl;
            for(int i=0; i<8; i++) {
                printf("%02X ", *(header_ptr+ip_header_length+i));
            }
            std::cout << "\n\033[33m+++++++++++++++++++++++++++++++++++++++++\033[0m\n";
            break;
        case IPPROTO_ICMP:
            std::cout << "Protocol: ICMP, header data:" << std::endl;
            for(int i=0; i<8; i++) {
                printf("%02X ", *(header_ptr+ip_header_length+i));
            }
            std::cout << "\n\033[33m+++++++++++++++++++++++++++++++++++++++++\033[0m\n";
            break;
        default:
            break;
    }
    std::cout << "\n\n";
}

std::vector<std::string> get_all_nic() {
    pcap_if_t *interfaces, *temp;
    std::vector<std::string> devices;

    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        std::cerr << "Failed to get the list of devices: " << errbuf << std::endl;
        return devices;
    }
    for (temp = interfaces; temp != nullptr; temp = temp->next) {
        devices.push_back(temp->name);
    }
    pcap_freealldevs(interfaces);
    return devices;
//    return {"ens16f0"};
}

// 执行每个网卡的抓包函数
void capture(const std::string& device) {

    pcap_t* handle = pcap_open_live(device.c_str(), 65536, 1, 0, errbuf);
    if (handle == nullptr) { // 打开网卡失败
        std::cerr << "pcap_open_live failed: " << errbuf << std::endl;
        return;
    }
    // 创建过滤器
    struct bpf_program fp{};
    char filter_exp[] = "tcp or udp or icmp";
    bpf_u_int32 net{};
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        std::cerr << "====== "<< device << " Could not compile filter" << std::endl;
        return ;
    }
    // 应用过滤器
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Could not set filter" << std::endl;
        return ;
    }

    while (true) {
        pcap_pkthdr* packet_header;
        const u_char* packet_body;
        int res = pcap_next_ex(handle, &packet_header, &packet_body); // 从网卡中读取一个数据包
        if (res == 0) continue;
        if (res == -1) break; // 出错
        // 处理数据包，例如输出它的长度
        packet_handler(nullptr, packet_header, packet_body);
//        std::cout << device << " Captured a headers of length " << packet_header->len <<  std::endl;
    }

    pcap_close(handle);
}


int main() {
    std::vector<std::string> devices = get_all_nic();

    std::vector<std::thread> threads;
    for (const auto& device : devices) {
        threads.emplace_back(capture, device);
    }

    for (auto& thread : threads) {
        thread.join();
    }

    return 0;
}
