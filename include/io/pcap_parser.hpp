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
#include "superpacket.hpp"
#include "call_python.hpp"
#include "kafka_producer.hpp"
#include "config_loader.hpp"
#include "constants.hpp"
#include "daily_logger.hpp"

#define amqp_str amqp_cstring_bytes
#define NOT !


/**
 * Parses a PCAP from a written file
 */

class PCAPParser {
public:

    explicit PCAPParser(Config config, const std::string &);

    ~PCAPParser();

    void perform();


private:

    void init_captor_args();

    static void packet_handler(u_char *user_data, const struct pcap_pkthdr *packet_header, const u_char *packet);

    [[nodiscard]] pcap_t *open_live_handle();

    std::shared_ptr<SuperPacket> process_packet(void *packet);

    void perform_predict(const u_char *packet, const struct pcap_pkthdr *);

    void write_output(const std::shared_ptr<SuperPacket> &sp);

    void *operator new(size_t size);

    struct pcap_if_t_deleter {
        void operator()(pcap_if_t *p) const {
            pcap_freealldevs(p);
        }
    };

#ifdef RABBITMQ
    //=========== Publish MQ =============
    bool load_mq_context();

    bool init_connection();
    bool configure_socket();
    bool connect_to_server();
    bool login();
    bool declare_queue();
    bool bind_queue_to_exchange();
    bool publish_message(const char*);
    void cleanup_mq_transactions();

    static bool check_last_status(amqp_response_type_enum, std::string&);
#endif


private:

    std::shared_ptr<DailyLogger> logger = DailyLogger::getInstance();

    struct timeval m_TimeVal{};
    std::vector<int8_t> bitstring_vec;
    Config m_Config;
    uint32_t m_LinkType{};
    using mss = std::map<std::string, std::string>;
    mss m_Properties;

    // ===============  Prediction  ===============
    //    Python *m_PythonContext;
    std::unique_ptr<Python> m_PythonContext;
    // ===============  Publish Kafka  ============
    //    KafkaProducer *m_kafkaProducer;
    std::unique_ptr<KafkaProducer> m_kafkaProducer;

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
