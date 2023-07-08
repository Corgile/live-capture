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
* @brief 程序核心部分，采用组合模式，在此类中注入了其他类（日志、kafka）
* 功能是：<br/>
*   - 处理网络流量包<br/>
*   - 构造tensor输入到算法中进行预测<br/>
*   - 得到返回值并附带一些信息发送到Kafka
*/
class Captor {
public:

    /**
    * @brief 构造函数，需要根据配置项来实例化，所以需要一个配置文件路径
    * @param config 配置类
    * @param path   配置文件路径
    */
    explicit Captor(Config config, const std::string &path);

    /**
    * @brief 析构函数
    */
    ~Captor() = default;

    /**
    * @brief 工作方法，包含核心逻辑
    */
    void perform();


private:

    /**
    * @brief 流量包处理方法
    * @param user_data 用户自定义参数
    * @param packet_header pcap包头部，包含包长度、时间戳等信息
    * @param packet 流量包本体
    */
    static void packet_handler(u_char *user_data, const struct pcap_pkthdr *packet_header, const u_char *packet);

    /**
    * @brief 初始化一个实时监听网卡的handler
    */
    void init_live_handle();

    /**
    * @brief 进行预测工作
    * @param packet 流量包
    * @param pcaphdr pcap头部
    */
    void perform_predict(raw_data_t packet, const struct pcap_pkthdr * pcaphdr);

    /**
    * @brief 自定义智能指针的deleter
    */
    struct pcap_if_t_deleter {
        void operator()(pcap_if_t *p) const {
            pcap_freealldevs(p);
        }
    };

private:

    /**
    * @brief 依然是注入一个日志记录器
    */
    std::shared_ptr<DailyLogger> m_logger = DailyLogger::getInstance();

    /**
    * @brief 这个数组存放应当被忽略掉的IP，比如0.0.0.0
    */
    std::vector<std::string> m_skip_addr{"0.0.0.0"};

    /**
    * @brief 用于存储将流量包进行转换后的向量
    */
    std::vector<float> bit_vec;
    /**
    * @brief 配置类
    */
    Config m_config;
    /**
    * @brief linktype, pcap参数
    */
    uint32_t m_link_type{ };
    /**
    * @brief 配置项
    */
    std::map<std::string, std::string> m_props;

    // ===============  Prediction  ===============
    /**
    * @brief pytorch API,用于分类/检测
    */
    std::unique_ptr<TorchAPI> m_torch_api;
    // ===============  Publish Kafka  ============
    /**
    * @brief kafka消息发送器
    */
    std::unique_ptr<KafkaProducer> m_kafka_producer;
#ifdef FOR_TEST
    std::chrono::steady_clock::time_point m_start_time;
#endif
    //    pcap_t *m_handle;
    /**
    * @brief 网卡监听handler
    */
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
