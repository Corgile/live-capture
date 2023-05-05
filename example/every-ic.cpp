#include <iostream>
#include <thread>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

struct PacketData {
    std::string dev_name;
    const struct pcap_pkthdr* header;
    const u_char* packet;
};

void packet_handler(u_char* arg, const struct pcap_pkthdr* header, const u_char* packet) {
    std::cout << "void packet_handler(u_char* arg, const struct pcap_pkthdr* header, const u_char* packet)\n";
    PacketData* data = (PacketData*)arg;
    std::cout << "DEVICE: " << data->dev_name
    << " Timestamp: " << header->ts.tv_sec
    << "." << header->ts.tv_usec << "\n";

    struct iphdr* ip = (struct iphdr*)(packet + sizeof(struct ethhdr));

    std::cout << "struct iphdr* ip = (struct iphdr*)(packet + sizeof(struct ethhdr));";
    if(ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP && ip->protocol != IPPROTO_ICMP){
        return;
    }

    switch (ip->protocol) {
        case IPPROTO_TCP: {
            struct tcphdr* tcp = (struct tcphdr*)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
            std::cout << " TCP : " << inet_ntoa(*(in_addr*)&ip->saddr) << ":" << ntohs(tcp->source);
            std::cout << "->" << inet_ntoa(*(in_addr*)&ip->daddr) << ":" << ntohs(tcp->dest) << "\n";
            break;
        }
        case IPPROTO_UDP: {
            struct udphdr* udp = (struct udphdr*)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
            std::cout << " UDP : " << inet_ntoa(*(in_addr*)&ip->saddr) << ":" << ntohs(udp->source);
            std::cout << "->" << inet_ntoa(*(in_addr*)&ip->daddr) << ":" << ntohs(udp->dest) << "\n";
            break;
        }
        case IPPROTO_ICMP: {
            struct icmphdr* icmp = (struct icmphdr*)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
            std::cout << "ICMP("<<(int)icmp->type<<"): " << inet_ntoa(*(in_addr*)&ip->saddr);
            std::cout << "->" << inet_ntoa(*(in_addr*)&ip->daddr) << "\n";
            break;
        }
        default:
            std::cout << "currently not supported protocol" << "\n";
            break;
    }
}

void capture_thread(std::string& dev_name) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* device = pcap_create(dev_name.c_str(), errbuf);
    if (device == NULL) {
        std::cerr << "Error creating handle for device " << dev_name << ": " << errbuf << "\n";
        return;
    }

    int ret = pcap_activate(device);
    if (ret != 0) {
        std::cerr << "Error activating handle for device " << dev_name << ": " << pcap_statustostr(ret) << "\n";
        pcap_close(device);
        return;
    }

//    std::cout << "Capturing on device " << dev_name << "\n";
    PacketData data = {dev_name, nullptr, nullptr};
    pcap_loop(device, 0, packet_handler, (u_char*)&data);
    pcap_close(device);
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* devices;

    if (pcap_findalldevs(&devices, errbuf) != 0) {
        std::cerr << "Error finding devices: " << errbuf << "\n";
        return 1;
    }

    for (pcap_if_t* device = devices; device != NULL; device = device->next) {
        std::string dev_name(device->name);
       std::cout << "Starting capture on device " << dev_name << "\n";
        std::thread capture(capture_thread, std::ref(dev_name));
        capture.detach();
    }

//    pcap_freealldevs(devices);

//    std::cin.get();
    return 0;
}
/*
    switch (ip->protocol) {
        case IPPROTO_TCP: {
            auto tcp = (struct tcphdr*)pkt_hdr;
            std::cout << " TCP : " << inet_ntoa(*(in_addr*)&ip->saddr) << ":" << ntohs(tcp->source);
            std::cout << "->" << inet_ntoa(*(in_addr*)&ip->daddr) << ":" << ntohs(tcp->dest) << "\n";
            break;
        }
        case IPPROTO_UDP: {
            auto udp = (struct udphdr*)pkt_hdr;
            std::cout << " UDP : " << inet_ntoa(*(in_addr*)&ip->saddr) << ":" << ntohs(udp->source);
            std::cout << "->" << inet_ntoa(*(in_addr*)&ip->daddr) << ":" << ntohs(udp->dest) << "\n";
            break;
        }
        case IPPROTO_ICMP: {
            auto icmp = (struct icmphdr*)pkt_hdr;
            std::cout << "ICMP("<<(int)icmp->type<<"): " << inet_ntoa(*(in_addr*)&ip->saddr);
            std::cout << "->" << inet_ntoa(*(in_addr*)&ip->daddr) << "\n";
            break;
        }
        default:
            std::cout << "currently not supported protocol" << "\n";
            break;
    }
*/