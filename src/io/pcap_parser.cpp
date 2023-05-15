#include <sstream>
#include <utility>
#include <thread>
#include <nlohmann/json.hpp>
#include "pcap_parser.hpp"
#include "common_macros.hpp"

#define ETH_HEADER_LEN  sizeof(struct ether_header)
#define SCOPE_START {
#define SCOPE_END   }

using callback_data_t = u_char *;
using tcp_header_t = const struct tcphdr *;
using eth_header_t = const struct ether_header *;
using ip_header_t = const struct iphdr *;
using udp_header_t = const struct udphdr *;
using icmp_header_t = const struct icmphdr *;

char err_buf[PCAP_ERRBUF_SIZE];


void PCAPParser::perform() {
    std::unique_ptr<pcap_t, void (*)(pcap_t *)> handle{this->open_live_handle(), &pcap_close};
    auto device = handle.get();
    this->m_LinkType = pcap_datalink(device);
    pcap_set_promisc(device, 1);
    pcap_loop(device, 0, packet_handler, reinterpret_cast<callback_data_t>(this));
}

void PCAPParser::packet_handler(callback_data_t callbackData, const struct pcap_pkthdr *packet_header,
                                const u_char *packet) {
    struct vlan_hdr {
        uint32_t v1;
    };
    auto ethernet_header = reinterpret_cast<eth_header_t>(packet);
    if (ntohs(ethernet_header->ether_type) == ETHERTYPE_VLAN) {
        packet = (u_char *) (packet + sizeof(struct vlan_hdr));
    }
    auto callback_data = reinterpret_cast<PCAPParser *>(callbackData);
    if (callback_data->m_LinkType == DLT_LINUX_SLL) {
        packet = (uint8_t *) packet + LINUX_COOKED_HEADER_SIZE;
    }
    std::shared_ptr<SuperPacket> pSuperPacket = callback_data->process_packet((void *) packet);
    if (pSuperPacket == nullptr) return;

    callback_data->write_output(pSuperPacket);
    callback_data->perform_predict(packet, packet_header);
    callback_data->bitstring_vec.clear();
}

std::shared_ptr<SuperPacket> PCAPParser::process_packet(void *packet) {
    return std::make_shared<SuperPacket>(packet, this->m_Config.max_payload_len, this->m_LinkType);
}


pcap_t *PCAPParser::open_live_handle() {
    std::unique_ptr<pcap_if_t, pcap_if_t_deleter> find_device_handle;

    if (this->m_Properties[keys::DEVICE_NAME].empty()) {
        auto device = find_device_handle.get();
        int32_t rv = pcap_findalldevs(&device, err_buf);
        if (rv == -1) {
            DEBUG_CALL(std::cerr << "默认设备查询失败: " << err_buf << std::endl);
            logger->error("默认设备查询失败: {}", err_buf);
            exit(EXIT_FAILURE);
        }
        this->m_Properties[keys::DEVICE_NAME] = device->name;

        DEBUG_CALL(std::cout << "\n ===== \033[1;31m 使用默认网卡: " << device->name << "\033[0m\n\n");
        logger->debug("使用默认网卡: {}", device->name);
    } else {
        DEBUG_CALL(std::cout << "\n ===== \033[1;31m 使用网卡: "
                             << this->m_Properties[keys::DEVICE_NAME]
                             << " =====\033[0m\n\n");
        logger->debug("使用网卡: {}", this->m_Properties[keys::DEVICE_NAME]);
    }
    const char *dev_name = this->m_Properties[keys::DEVICE_NAME].c_str();
    struct bpf_program fp{};
    char filter_exp[] = "tcp or udp or icmp";
    bpf_u_int32 net, mask;
    pcap_t *device_handle = pcap_open_live(dev_name, BUFSIZ, 1, 1000, err_buf);
    pcap_lookupnet(dev_name, &net, &mask, err_buf);
    pcap_compile(device_handle, &fp, filter_exp, 0, net);
    pcap_setfilter(device_handle, &fp);
    return device_handle;
}

PCAPParser::PCAPParser(Config config, const std::string &config_file_path)
        : m_Config(std::move(config)) {

    logger->debug(" >>>>>>>>>>>>>>>>>>> Loading properties: {}", config_file_path);
    SCOPE_START
        auto loader = std::make_unique<ConfigLoader>(config_file_path);
        this->m_Properties = loader->get_conf();
    SCOPE_END
    logger->debug("Loading {} has done", config_file_path);

    std::unique_ptr<pcap_if_t, pcap_if_t_deleter> alldevs;
    auto devices = alldevs.get();
    int ret = pcap_findalldevs(&devices, err_buf);
    if (ret != 0) {
        std::cout << "查找网卡设备失败, pcap_findalldevs() failed: " << err_buf << std::endl;
        logger->error("查找网卡设备失败: {}", err_buf);
        exit(EXIT_FAILURE);
    }

    // 输出网卡列表
    if (!this->m_Properties[keys::DEVICE_NAME].empty()) {
        bool found{false};
        for (auto d = alldevs.get(); d != nullptr; d = d->next) {
            found = d->name == this->m_Properties[keys::DEVICE_NAME];
            if (found) break;
        }
        if (!found) {
            std::cout << "找不到网卡设备: [" << this->m_Properties[keys::DEVICE_NAME] << "]\n";
            logger->error("找不到网卡设备: {}", this->m_Properties[keys::DEVICE_NAME]);
            exit(EXIT_FAILURE);
        }
    }
    alldevs.reset();
    logger->debug("{}", " >>>>>>>>>>>>>>>>>>> Init Captor Args");
    this->init_captor_args();
    logger->debug("{}", " <<<<<<<<<<<<<<<<<<< done");
    logger->debug("{}", " >>>>>>>>>>>>>>>>>>> Loading Kafka context");
    this->m_kafkaProducer = std::make_unique<KafkaProducer>(
            this->m_Properties[keys::KAFKA_BROKER],
            this->m_Properties[keys::KAFKA_TOPIC],
            std::stoi(this->m_Properties[keys::KAFKA_PARTITION])
    );
    logger->debug("{}", " <<<<<<<<<<<<<<<<<<< done");
    logger->debug("{}", " >>>>>>>>>>>>>>>>>>> Loading Python context");
    this->m_PythonContext = std::make_unique<Python>(
            this->m_Properties[keys::MODEL_PATH],
            this->m_Properties[keys::SCRIPT_PATH],
            this->m_Properties[keys::SCRIPT_NAME]
    );
    logger->debug("{}", " <<<<<<<<<<<<<<<<<<< done");

#ifdef RABBITMQ
    std::cout << "\n\t\033[31m =================== Load MQ Context ============\033[0m\n";
    if (NOT this->load_mq_context()) exit(EXIT_FAILURE);
#endif
}

PCAPParser::~PCAPParser() {
#ifdef RABBITMQ
    this->cleanup_mq_transactions();
#endif
    DEBUG_CALL(std::cout << "");
}

void PCAPParser::perform_predict(const u_char *packet, const struct pcap_pkthdr *pcap_header) {

    /** extract as IP packet and resolve the IPs */
    auto ip_packet_header = reinterpret_cast<ip_header_t> (packet + ETH_HEADER_LEN);
    /** 处理 IP 地址 */
    logger->debug("{}", "处理 IP 地址");
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_packet_header->saddr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_packet_header->daddr), dst_ip, INET_ADDRSTRLEN);
    logger->debug("src IP: {}", src_ip);
    logger->debug("dst IP: {}", dst_ip);

    /** get_conf the IP header length */
    size_t ip_hdr_len = (ip_packet_header->ihl) * 4;
    uint16_t src_port, dst_port;
    std::string protocol;
    /** determine the protocol */
    switch (ip_packet_header->protocol) {
        case IPPROTO_TCP:
            /** extract as TCP */
            tcp_header_t tcp_hdr;
            tcp_hdr = reinterpret_cast<tcp_header_t>(packet + ETH_HEADER_LEN + ip_hdr_len);
            src_port = ntohs(tcp_hdr->source);
            dst_port = ntohs(tcp_hdr->dest);
            protocol = "TCP";
            break;
        case IPPROTO_UDP:
            /** extract as UDP */
            udp_header_t udp_hdr;
            udp_hdr = reinterpret_cast<udp_header_t>(packet + ETH_HEADER_LEN + ip_hdr_len);
            src_port = ntohs(udp_hdr->source);
            dst_port = ntohs(udp_hdr->dest);
            protocol = "UDP";
            break;
        case IPPROTO_ICMP:
            /** extract the ICMP message type and code */
            icmp_header_t icmp_hdr;
            icmp_hdr = reinterpret_cast<icmp_header_t>(packet + ETH_HEADER_LEN + ip_hdr_len);
            src_port = icmp_hdr->type;
            dst_port = icmp_hdr->code;
            protocol = "ICMP";
            break;
        default:
            /** OTHER */
            src_port = -1;
            dst_port = -1;
            protocol = "OTHER";
            break;
    }

#pragma endregion

#pragma region Jsonify
    std::ostringstream oss;
    for (int i = 0; i < this->bitstring_vec.size(); ++i) {
        if (i != 0) oss << ",";
        oss << int(this->bitstring_vec[i]);
    }
    auto bitstring = oss.str();
    logger->debug("in function: {}", __PRETTY_FUNCTION__);
    std::string label = this->m_PythonContext->predict(bitstring);

    nlohmann::json result = {
            {"timestamp",  pcap_header->ts.tv_sec},
            {"u_sec",      pcap_header->ts.tv_usec},
            {"attackType", label},
            {"dstIp",      dst_ip},
            {"dstPort",    dst_port},
            {"srcIp",      src_ip},
            {"srcPort",    src_port},
            {"protocol",   protocol}
    };
#pragma endregion

    if (label != "benign") {
#ifdef RABBITMQ
        this->publish_message(out.str().c_str());
#endif
        logger->debug("分类结果: {}", label);
        this->m_kafkaProducer->pushMessage(result.dump(), "");
        DEBUG_CALL(std::cout << result.dump() << std::endl);
        logger->debug("json -> kafka: {}", result.dump());
    }
}

void PCAPParser::write_output(const std::shared_ptr<SuperPacket> &sp) {
    sp->get_bitstring(&(this->m_Config), this->bitstring_vec);
}

#ifdef RABBIMQ
void PCAPParser::cleanup_mq_transactions() {
    // Cleanup and close connection
    amqp_channel_close(state_buff, channel, AMQP_REPLY_SUCCESS);
    amqp_connection_close(state_buff, AMQP_REPLY_SUCCESS);
    amqp_destroy_connection(state_buff);
}
#endif

void PCAPParser::init_captor_args() {
    m_TimeVal.tv_sec = 0;
    m_TimeVal.tv_usec = 0;
    auto size = SIZE_IPV4_HEADER_BITSTRING
                + SIZE_TCP_HEADER_BITSTRING
                + SIZE_UDP_HEADER_BITSTRING
                + SIZE_ICMP_HEADER_BITSTRING;
    this->bitstring_vec.reserve(size << 5);
}

void *PCAPParser::operator new(size_t size) {
    DEBUG_CALL(std::cout << "\n\t\033[34m ----------------- 分配 " << size
                         << " bytes 内存 -------------------- \033[0m\n");
    return malloc(size);
}

#ifdef RABBIMQ
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
#endif