#ifndef PCAP_PARSER
#define PCAP_PARSER

#if defined(__NetBSD__)
#include <net/if_ether.h>
#else

#include <net/ethernet.h>

#endif

#define LINUX_COOKED_HEADER_SIZE 16

#include <pcap.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>


#include <memory>
#include <map>

#ifdef RABBITMQ
#include <rabbitmq-c/tcp_socket.h>
#include <rabbitmq-c/amqp.h>
#endif

#include "config.hpp"
#include "packet/superpacket.hpp"
#include "io/torch_api.hpp"
#include "io/kafka_producer.hpp"
#include "io/config_loader.hpp"
#include "io/daily_logger.hpp"
#include "constants.hpp"
#include "common.hpp"

#define amqp_str amqp_cstring_bytes
#define NOT !


/**
 * Parses a PCAP from a written file
 */

class Captor {
public:

    explicit Captor(Config config, const std::string &);

    ~Captor() = default;

    void perform();


private:

    static void packet_handler(u_char *user_data, const struct pcap_pkthdr *packet_header, const u_char *packet);

    void init_live_handle();

    void perform_predict(raw_data_t packet, const struct pcap_pkthdr *);

    struct pcap_if_t_deleter {
        void operator()(pcap_if_t *p) const {
            pcap_freealldevs(p);
        }
    };

private:

    std::shared_ptr<DailyLogger> m_logger = DailyLogger::getInstance();

    std::vector<float> bit_vec;
    Config m_config;
    uint32_t m_link_type{ };
    std::map<std::string, std::string> m_props;

    // ===============  Prediction  ===============
    std::unique_ptr<TorchAPI> m_torch_api;
    // ===============  Publish Kafka  ============
    std::unique_ptr<KafkaProducer> m_kafka_producer;
#ifdef FOR_TEST
    std::chrono::steady_clock::time_point m_start_time;
#endif
    //    pcap_t *m_handle;
    std::shared_ptr<pcap_t> m_handle;
#ifdef RABBITMQ
    // ===============  Publish MQ  ===============
    amqp_socket_t *socket;
    amqp_connection_state_t state_buff{};
    amqp_bytes_t queue = amqp_cstring_bytes("test");
    const amqp_channel_t channel = 1;
    const amqp_bytes_t routing_key = amqp_cstring_bytes("attack");
    const amqp_bytes_t exchange = amqp_cstring_bytes("attackAlarmExchange");
    const amqp_basic_properties_t properties {
            ._flags= AMQP_BASIC_CONTENT_TYPE_FLAG | AMQP_BASIC_DELIVERY_MODE_FLAG,
            .content_type = amqp_str("text/plain"),
            // persistent delivery mode
            .delivery_mode = 2
    };
#endif

};

#endif
