//
// Created by gzhuadmin on 23-5-9.
//
#include <pcap.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>


void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

char errbuf[PCAP_ERRBUF_SIZE];

int main(int argc, char **argv) {

    struct bpf_program fp;
    char filter_exp[] = "icmp";
    bpf_u_int32 net;
    bpf_u_int32 mask;

    // 打开网卡
    auto handle = pcap_open_live("ens16f0", BUFSIZ, 1, 1000, errbuf);
    // 获取网卡的网络地址和掩码
    pcap_lookupnet("ens16f0", &net, &mask, errbuf);
    // 编译过滤器
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);
    // 开始捕获流量包
    pcap_loop(handle, -1, packet_handler, nullptr);
    // 关闭网卡
    pcap_close(handle);
    return 0;
}


void packet_handler(u_char *callback, const struct pcap_pkthdr *pkt_description, const u_char *packet_data) {

    const struct iphdr *ip_header;
    char src_ip_buf[INET_ADDRSTRLEN], dst_ip_buf[INET_ADDRSTRLEN];
    /**
     * <h2>以太网头部</h2>
     * <img src="https://img-blog.csdn.net/20161013182456810">
     * */
    struct vlan_hdr { uint32_t v1; };
    const struct ether_header *ethernet_header = (struct ether_header *) packet_data;
    if (ntohs(ethernet_header->ether_type) == ETHERTYPE_VLAN) {
        packet_data = (u_char *) (packet_data + sizeof(struct vlan_hdr));
    }
    ip_header = (struct iphdr *) (packet_data + sizeof(struct ether_header));

    /**
     * <h2>IP头部</h2>
     * <img src="https://img-blog.csdn.net/20161013182606405">
     */

    inet_ntop(AF_INET, &(ip_header->saddr), src_ip_buf, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->daddr), dst_ip_buf, INET_ADDRSTRLEN);
    printf("[ %s -> %s; check sum: %04x ]\n", src_ip_buf, dst_ip_buf, ip_header->check);

    return;
}
