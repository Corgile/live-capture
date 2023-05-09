#include "pcap_parser.hpp"
#include <sstream>
#include <utility>
#include <thread>
#include <spdlog/spdlog.h>


using CallbackData = u_char *;
char err_buf[PCAP_ERRBUF_SIZE];

void PCAPParser::perform() {
    std::unique_ptr<pcap_t, void (*)(pcap_t *)> handle{this->open_live_handle(), &pcap_close};
    auto device = handle.get();
    this->m_LinkType = pcap_datalink(device);
    pcap_set_promisc(device, 1);
    pcap_loop(device, 0, packet_handler, (CallbackData) this);
}

void
PCAPParser::packet_handler(CallbackData callbackData, const struct pcap_pkthdr *packet_header, const u_char *packet) {
    struct vlan_hdr {
        uint32_t v1;
    };
    auto ethernet_header = (struct ether_header *) packet;
    if (ntohs(ethernet_header->ether_type) == ETHERTYPE_VLAN) {
        packet = (u_char *) (packet + sizeof(struct vlan_hdr));
    }
    auto callback_data = (PCAPParser *) callbackData;
    if (callback_data->m_LinkType == DLT_LINUX_SLL) {
        packet = (uint8_t *) packet + LINUX_COOKED_HEADER_SIZE;
    }
    std::shared_ptr<SuperPacket> pSuperPacket = callback_data->process_packet((void *) packet);
    if (pSuperPacket == nullptr) return;

    callback_data->write_output(pSuperPacket);
    callback_data->perform_predict(packet);
    callback_data->bitstring_vec.clear();
}

std::shared_ptr<SuperPacket> PCAPParser::process_packet(void *packet) {

    std::shared_ptr<SuperPacket> pSuperPacket =
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


pcap_t *PCAPParser::open_live_handle() {
    pcap_if_t *find_device_handle;
    // get device_handle
    if (m_Config.device.empty()) {
        int32_t rv = pcap_findalldevs(&find_device_handle, err_buf);
        if (rv == -1) {
            std::cerr << "默认设备查询失败: " << err_buf << std::endl;
            exit(EXIT_FAILURE);
        }
        m_Config.device = find_device_handle->name;
    }

    std::cout << "\n ===== \033[1;31m 使用默认网卡: " << m_Config.device << "\033[0m\n\n";

    const char *dev_name = m_Config.device.c_str();
    struct bpf_program fp;
    char filter_exp[] = "tcp or udp or icmp";
    bpf_u_int32 net, mask;
    pcap_t *device_handle = pcap_open_live(dev_name, BUFSIZ, 1, 1000, err_buf);
    pcap_lookupnet(dev_name, &net, &mask, err_buf);
    pcap_compile(device_handle, &fp, filter_exp, 0, net);
    pcap_setfilter(device_handle, &fp);
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

PCAPParser::PCAPParser(Config config) : m_Config(std::move(config)) {
    std::cout << "\n\t\033[31m =================== Init Captor Args ============\033[0m\n";
    this->init_captor_args();
    //    std::cout << "\n\t\033[31m =================== Load MQ Context ============\033[0m\n";
    //    if (NOT this->load_mq_context()) exit(EXIT_FAILURE);
    std::cout << "\n\t\033[31m =================== Load Python Context ============\n\033[0m";
    this->m_PythonContext = new Python();
}

PCAPParser::~PCAPParser() {
    this->cleanup_mq_transactions();
    delete this->m_PythonContext;
}

void PCAPParser::perform_predict(const u_char *packet) {
    auto ethernet_header = (struct ether_header *) packet;
    //    std::cout << "ntohs(ethernet_header->ether_type) != ETHERTYPE_IP" << std::endl;
    //    if (ntohs(ethernet_header->ether_type) != ETHERTYPE_IP) return;
    //    std::cout << "ntohs(ethernet_header->ether_type) == ETHERTYPE_IP" << std::endl;
#pragma region 处理 IP 地址
    auto ip_header = (struct iphdr *) (packet + sizeof(struct ether_header));
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->saddr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->daddr), dst_ip, INET_ADDRSTRLEN);
#pragma endregion
    std::ostringstream oss;
    for (int i = 0; i < this->bitstring_vec.size(); ++i) {
        if (i != 0) oss << ",";
        oss << int(this->bitstring_vec[i]);
    }
    auto bitstring = oss.str();
    std::string label = this->m_PythonContext->predict(bitstring);

    std::ostringstream out;
    if (label != "benign") {
        out << "\033[31m";
    }

    out << "| " << PCAPParser::get_protocol_name((u_char *) packet)
        << " |  FROM IP: " << src_ip << " -> " << label
        << " -> TO IP: " << dst_ip << "\033[0m";
#define mq
#ifdef mq
    //    if (label != "benign") {
    // this->publish_message(out.str().c_str());
    std::cout << out.str() << std::endl;
    //    }

#endif
    //#ifndef mq
    //#endif

}

std::string PCAPParser::get_protocol_name(u_char *packet) {
    u_char *ip_data = (u_char *) (packet) + 14;;
    u_char protocol = ip_data[9];

    switch (protocol) {
        case IPPROTO_TCP:
            return "TCP";
        case IPPROTO_UDP:
            return "UDP";
        case IPPROTO_ICMP:
            return "ICMP";
        default:
            return std::to_string(protocol);
    }
}

void PCAPParser::write_output(const std::shared_ptr<SuperPacket> &sp) {
    sp->get_bitstring(&(this->m_Config), this->bitstring_vec);
}

void PCAPParser::cleanup_mq_transactions() {
    // Cleanup and close connection
    amqp_channel_close(state_buff, channel, AMQP_REPLY_SUCCESS);
    amqp_connection_close(state_buff, AMQP_REPLY_SUCCESS);
    amqp_destroy_connection(state_buff);
}

void PCAPParser::init_captor_args() {
    m_TimeVal.tv_sec = 0;
    m_TimeVal.tv_usec = 0;
    auto size = SIZE_IPV4_HEADER_BITSTRING
                + SIZE_TCP_HEADER_BITSTRING
                + SIZE_UDP_HEADER_BITSTRING
                + SIZE_ICMP_HEADER_BITSTRING;
    this->bitstring_vec.reserve(size << 5);
}

bool PCAPParser::init_connection() {
    this->state_buff = amqp_new_connection();
    //    std::cout << "\033[36m >>>> " << __LINE__ << std::endl;
    //    amqp_response_type_enum status = amqp_get_rpc_reply(state_buff).reply_type;
    //    std::cout << "\033[36m >>>> " << __LINE__ << std::endl;
    //    std::string out(__PRETTY_FUNCTION__);
    //    std::cout << "\033[36m >>>> " << __LINE__ << std::endl;
    return true;
    //    return PCAPParser::check_last_status(status, out);
}

bool PCAPParser::configure_socket() {
    this->socket = amqp_tcp_socket_new(state_buff);
    if (!socket) {
        std::cout << "Error creating TCP socket\n";
        return false;
    }
    return true;
    amqp_response_type_enum status = amqp_get_rpc_reply(state_buff).reply_type;
    std::string out(__PRETTY_FUNCTION__);
    return PCAPParser::check_last_status(status, out);
}

bool PCAPParser::connect_to_server() {
    if (amqp_socket_open(this->socket, "172.22.105.151", 5672)) {
        std::cout << "Error connecting to RabbitMQ server\n";
        return false;
    }
    return true;
    amqp_response_type_enum status = amqp_get_rpc_reply(state_buff).reply_type;
    std::string out(__PRETTY_FUNCTION__);
    return PCAPParser::check_last_status(status, out);
}

bool PCAPParser::login() {
    // Login
    amqp_login(state_buff, "/",
               0,
               131072,
               0,
               amqp_sasl_method_enum::AMQP_SASL_METHOD_PLAIN,
               "user", "password");
    //    amqp_response_type_enum status = amqp_get_rpc_reply(state_buff).reply_type;
    //    std::string out(__PRETTY_FUNCTION__);
    //    bool login_succeed = PCAPParser::check_last_status(status, out);
    //    if (!login_succeed) {
    //        std::cout << "login failed!\n";
    //        return false;
    //    }
    amqp_channel_open(state_buff, 1);
    return true;
    //    status = amqp_get_rpc_reply(state_buff).reply_type;
    //    return PCAPParser::check_last_status(status, out);
}

bool PCAPParser::declare_queue() {
    // Declare queue
    amqp_queue_declare_ok_t *res = amqp_queue_declare(state_buff, channel, queue,
                                                      0,
                                                      true, 0, 1, amqp_empty_table);
    queue = amqp_bytes_malloc_dup(res->queue);
    if (queue.bytes == nullptr) {
        std::cout << "Error duplicating queue name\n";
        return false;
    }
    return true;
}

bool PCAPParser::bind_queue_to_exchange() {
    // Bind queue to exchange
    auto arguments = amqp_empty_table;
    amqp_queue_bind(state_buff, channel, queue, exchange, routing_key, arguments);
    return true;
    auto status = amqp_get_rpc_reply(state_buff).reply_type;
    std::string out(__PRETTY_FUNCTION__);
    return PCAPParser::check_last_status(status, out);
}

bool PCAPParser::publish_message(const char *message) {
    // Publish message
    amqp_bytes_t body = amqp_str(message);
    amqp_basic_publish(state_buff, channel, exchange, routing_key, 0, 0, &(this->properties), body);
    return true;
    auto status = amqp_get_rpc_reply(state_buff).reply_type;
    std::string out(__PRETTY_FUNCTION__);
    return PCAPParser::check_last_status(status, out);
}

bool PCAPParser::load_mq_context() {
    if (NOT this->init_connection()) return false;
    if (NOT this->configure_socket()) return false;
    if (NOT this->connect_to_server()) return false;
    if (NOT this->login()) return false;
    if (NOT this->declare_queue()) return false;
    if (NOT this->bind_queue_to_exchange()) return false;
    return true;
}

bool PCAPParser::check_last_status(amqp_response_type_enum status, std::string &out) {
    bool ret = false;
    switch (status) {
        case AMQP_RESPONSE_NORMAL:
            out += "\u001B[36m response normal, the RPC completed successfully033[0m\n";
            ret = true;
        case AMQP_RESPONSE_NONE:
            out += "\u001B[31m last operation got AMQP_RESPONSE_NONE，the library got an EOF from the socket\033[0m\n";
            break;
        case AMQP_RESPONSE_LIBRARY_EXCEPTION:
            out += "\u001B[31m last operation got an error occurred in the library\u001B[0m\n";
            break;
        case AMQP_RESPONSE_SERVER_EXCEPTION:
            out += "\u001B[31m last operation got an server exception, the broker returned an error\u001B[0m\n";
            break;
        default:
            out += "\u001B[31m last operation got an unknown error \u001B[0m\n";
            break;
    }
    std::cout << out << std::endl;
    return ret;
}
