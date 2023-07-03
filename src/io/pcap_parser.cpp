#include <sstream>
#include <utility>
#include <thread>
// #include <nlohmann/json.hpp>
#include <ifaddrs.h>

#include <netinet/in.h>

#include "io/pcap_parser.hpp"
#include "packet/superpacket.hpp"
#include "common.hpp"

#define ETH_HEADER_LEN      sizeof(struct ether_header)
#define SCOPE_START         {
#define SCOPE_END           }
#define PROMIDCUOUS_MODE    1
#define READ_PKT_TIMEOUT    200

char err_buf[PCAP_ERRBUF_SIZE];

Captor::Captor(Config config, const std::string &config_file_path) : m_config(std::move(config)) {

  m_logger->debug(" >>>>>>>>>>>>>>>>>>> Loading properties: {}", config_file_path);
  SCOPE_START
    auto loader = std::make_unique<ConfigLoader>(config_file_path);
    this->m_props = loader->get_conf();
  SCOPE_END
  m_logger->debug("Loading {} has done", config_file_path);
  std::unique_ptr<pcap_if_t, pcap_if_t_deleter> alldevs;
  auto device_buffer = alldevs.get();
  int ret = pcap_findalldevs(&device_buffer, err_buf);
  if (ret != 0) {
    m_logger->error("查找网卡设备失败: {}", err_buf);
    exit(EXIT_FAILURE);
  }

  // get all ipv4 addresses
  for (auto nic = device_buffer; nic != nullptr; nic = nic->next) {
    if (nic->addresses == nullptr) {
      continue;
    }
    for (auto addr = nic->addresses; addr != nullptr; addr = addr->next) {
      if (addr->addr->sa_family != AF_INET) {
        continue;
      }
      // 将地址结构转换为 sockaddr_in 结构
      auto sa = reinterpret_cast<struct sockaddr_in *>(addr->addr);
      char ipAddressBuffer[INET_ADDRSTRLEN];
      if (inet_ntop(AF_INET, &(sa->sin_addr), ipAddressBuffer, INET_ADDRSTRLEN) != nullptr) {
        std::string ipAddress = ipAddressBuffer;
        this->m_skip_addr.emplace_back(ipAddressBuffer);
        std::cout << "IPv4 Address: " << ipAddress << std::endl;
      }
    }
  }
  if (!this->m_props[keys::DEVICE_NAME].empty()) {
    bool found{false};
    for (auto d = alldevs.get(); d != nullptr; d = d->next) {
      found = d->name == this->m_props[keys::DEVICE_NAME];
      if (found) break;
    }
    if (!found) {
      m_logger->error("找不到网卡设备: {}", this->m_props[keys::DEVICE_NAME]);
      exit(EXIT_FAILURE);
    }
  }
  alldevs.reset();
  m_logger->debug("{}", " >>>>>>>>>>>>>>>>>>> Init Captor Args");

  auto size = SIZE_IPV4_HEADER_BITSTRING
              + SIZE_TCP_HEADER_BITSTRING
              + SIZE_UDP_HEADER_BITSTRING
              + SIZE_ICMP_HEADER_BITSTRING;
  this->bit_vec.reserve(size << 5);
  m_logger->debug("{}", " <<<<<<<<<<<<<<<<<<< done");
  m_logger->debug("{}", " >>>>>>>>>>>>>>>>>>> Loading Kafka context");
  this->m_kafka_producer = std::make_unique<KafkaProducer>(
      this->m_props[keys::KAFKA_BROKERS],
      this->m_props[keys::KAFKA_TOPIC],
      std::stoi(this->m_props[keys::KAFKA_PARTITION])
  );
  m_logger->debug("{}", " <<<<<<<<<<<<<<<<<<< done");
  m_logger->debug("{}", " >>>>>>>>>>>>>>>>>>> Loading torch_api");
  this->m_torch_api = std::make_unique<TorchAPI>(
      this->m_props[keys::MODEL_PATH]
  );
  m_logger->debug("{}", " <<<<<<<<<<<<<<<<<<< done");

}

void Captor::perform() {
  this->init_live_handle();
  this->m_link_type = pcap_datalink(m_handle.get());
#ifdef FOR_TEST
  m_start_time = std::chrono::steady_clock::now();
#endif
  pcap_loop(m_handle.get(), 0, packet_handler, reinterpret_cast<callback_data_t>(this));
  pcap_close(this->m_handle.get());
}

void Captor::packet_handler(callback_data_t callbackData,
                            const struct pcap_pkthdr *pcap_header,
                            const u_char *packet) {
  struct vlan_hdr {
    uint32_t v1;
  };
  auto ethernet_header = reinterpret_cast<eth_header_t>(packet);
  if (ntohs(ethernet_header->ether_type) == ETHERTYPE_VLAN) {
    packet = packet + sizeof(struct vlan_hdr);
  }
  auto callback = reinterpret_cast<Captor *>(callbackData);
  if (callback->m_link_type == DLT_LINUX_SLL) {
    packet = packet + LINUX_COOKED_HEADER_SIZE;
  }
  callback->perform_predict(packet, pcap_header);
}


void Captor::init_live_handle() {
  std::unique_ptr<pcap_if_t, pcap_if_t_deleter> find_device_handle;
  if (this->m_props[keys::DEVICE_NAME].empty()) {
    auto device = find_device_handle.get();
    int32_t rv = pcap_findalldevs(&device, err_buf);
    if (rv == -1) {
      m_logger->error("默认设备查询失败: {}", err_buf);
      exit(EXIT_FAILURE);
    }
    this->m_props[keys::DEVICE_NAME] = device->name;
    DEBUG_CALL(std::cout << "\n ===== \033[1;31m 使用默认网卡: " << device->name << "\033[0m\n\n");
    m_logger->debug("使用默认网卡: {}", device->name);
  } else {
    DEBUG_CALL(std::cout << "\n ===== \033[1;31m 使用网卡: "
                         << this->m_props[keys::DEVICE_NAME]
                         << " =====\033[0m\n\n");
    m_logger->debug("使用网卡: {}", this->m_props[keys::DEVICE_NAME]);
  }
  const char *dev_name = this->m_props[keys::DEVICE_NAME].c_str();
  struct bpf_program fp{};
  char filter_exp[] = "tcp or udp or icmp";
  bpf_u_int32 net, mask;
  //    pcap_t *device_handle = pcap_open_live(dev_name, BUFSIZ, PROMIDCUOUS_MODE, READ_PKT_TIMEOUT, err_buf);
  this->m_handle = {pcap_open_live(dev_name, BUFSIZ, PROMIDCUOUS_MODE, READ_PKT_TIMEOUT, err_buf), pcap_close};
  pcap_set_promisc(m_handle.get(), PROMIDCUOUS_MODE);
  pcap_lookupnet(dev_name, &net, &mask, err_buf);
  pcap_compile(m_handle.get(), &fp, filter_exp, 0, net);
  pcap_setfilter(m_handle.get(), &fp);
}

void Captor::perform_predict(raw_data_t packet, const struct pcap_pkthdr *pcap_header) {
#ifdef FOR_TEST
  using std::chrono::duration_cast;
  using std::chrono::seconds;
  using std::chrono::steady_clock;
  if (duration_cast<seconds>(steady_clock::now() - m_start_time).count() >= 300) {
      pcap_breakloop(m_handle.get());
  }
#endif

#pragma region SOMETHING
  /** extract as IP packet and resolve the IPs */
  auto ip_packet_header = reinterpret_cast<ip_header_t> ((const u_char *) packet + ETH_HEADER_LEN);
  /** 处理 IP 地址 */
  m_logger->debug("{}", "处理 IP 地址");
  char src_ip[INET_ADDRSTRLEN];
  char dst_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(ip_packet_header->saddr), src_ip, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(ip_packet_header->daddr), dst_ip, INET_ADDRSTRLEN);
  m_logger->debug("src IP: {}", src_ip);
  m_logger->debug("dst IP: {}", dst_ip);

  if ("0.0.0.0" == std::string(src_ip) || "0.0.0.0" == std::string(dst_ip)) return;
  auto src_is_localhost = m_skip_addr.end() != std::find(m_skip_addr.begin(), m_skip_addr.end(), src_ip);
  auto dst_is_in_broker = this->m_props[keys::KAFKA_BROKERS].find(dst_ip) != std::string::npos;
  auto dst_is_localhost = m_skip_addr.end() != std::find(m_skip_addr.begin(), m_skip_addr.end(), dst_ip);
  auto src_is_in_broker = this->m_props[keys::KAFKA_BROKERS].find(src_ip) != std::string::npos;
  if (src_is_localhost && dst_is_in_broker || dst_is_localhost && src_is_in_broker) {
    return;
  }

  /** get_conf the IP header length */
  size_t ip_hdr_len = (ip_packet_header->ihl) << 2;
  uint16_t src_port, dst_port;
  std::string protocol;
  /** determine the protocol */
  switch (ip_packet_header->protocol) {
    case IPPROTO_TCP:
      /** extract as TCP */
      tcp_header_t tcp_hdr;
      tcp_hdr = reinterpret_cast<tcp_header_t>((const u_char *) packet + ETH_HEADER_LEN + ip_hdr_len);
      src_port = ntohs(tcp_hdr->source);
      dst_port = ntohs(tcp_hdr->dest);
      protocol = "TCP";
      break;
    case IPPROTO_UDP:
      /** extract as UDP */
      udp_header_t udp_hdr;
      udp_hdr = reinterpret_cast<udp_header_t>((const u_char *) packet + ETH_HEADER_LEN + ip_hdr_len);
      src_port = ntohs(udp_hdr->source);
      dst_port = ntohs(udp_hdr->dest);
      protocol = "UDP";
      break;
    case IPPROTO_ICMP:
      /** extract the ICMP message type and code */
      icmp_header_t icmp_hdr;
      icmp_hdr = reinterpret_cast<icmp_header_t>((const u_char *) packet + ETH_HEADER_LEN + ip_hdr_len);
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

  auto sp = std::make_shared<SuperPacket>(packet, this->m_config.max_payload_len, this->m_link_type);
  sp->fill_bit_vec(&(this->m_config), this->bit_vec);
  auto tensor{torch::from_blob(this->bit_vec.data(), {1, 1, 128}, at::kFloat)};
  std::vector<torch::jit::IValue> inputs(1, tensor);
  std::string label{this->m_torch_api->predict(inputs)};
  this->bit_vec.clear();

  std::string result{
      R"({"srcIp":")" + std::string(src_ip) +
      R"(","attackType":")" + label +
      R"(","dstIp":")" + std::string(dst_ip) +
      R"(","srcPort":)" + std::to_string(src_port) +
      R"(,"dstPort":)" + std::to_string(dst_port) +
      R"(,"protocol":")" + std::string(protocol) +
      R"(","timestamp":)" + std::to_string(pcap_header->ts.tv_sec) +
      R"(,"uSec":)" + std::to_string(pcap_header->ts.tv_usec) + "}"
  };
#pragma endregion

  if (label != "benign") {
    m_logger->debug("分类结果: {}", label);
    this->m_kafka_producer->pushMessage(result, "");
    DEBUG_CALL(std::cout << "\033[31m" << result.dump() << "\033[0m" << std::endl);
    m_logger->debug("json -> kafka: {}", result);
  }
}


