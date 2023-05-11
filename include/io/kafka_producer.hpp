//
// Created by gzhuadmin on 23-5-11.
//

#ifndef KAFKA_DEMO_KAFKA_PRODUCER_HPP
#define KAFKA_DEMO_KAFKA_PRODUCER_HPP

#include <iostream>
#include <string>
#include <librdkafka/rdkafkacpp.h>

#include "producer_event_cb.hpp"
#include "producer_delivery_report_cb.hpp"
#include "hash_partitioner_cb.hpp"


class KafkaProducer {
public:
    /**
     * @brief KafkaProducer
     * @param brokers
     * @param topic
     * @param partition
     */
    explicit KafkaProducer(const std::string &brokers, const std::string &topic, int partition);

    /**
     * @brief push Message to Kafka
     * @param str, message data
     */
    void pushMessage(const std::string &str, const std::string &key);

    ~KafkaProducer();

protected:
    std::string m_brokers;          // Broker 列表，多个使用逗号分隔
    std::string m_topicStr;         // Topic 名称
    int m_partition;                // 分区
    RdKafka::Conf *m_config;        // Kafka Conf 对象
    RdKafka::Conf *m_topicConfig;   // Topic Conf 对象

    RdKafka::Topic *m_topic;              // Topic对象
    RdKafka::Producer *m_producer;        // Producer对象
    RdKafka::DeliveryReportCb *m_dr_cb;   // 设置传递回调
    RdKafka::EventCb *m_event_cb;         // 设置事件回调
    RdKafka::PartitionerCb *m_partitioner_cb; // 设置自定义分区回调
};


#endif //KAFKA_DEMO_KAFKA_PRODUCER_HPP