//
// Created by gzhuadmin on 23-5-11.
//

#ifndef KAFKA_DEMO_PRODUCER_EVENT_CB_HPP
#define KAFKA_DEMO_PRODUCER_EVENT_CB_HPP

#include <iostream>
#include <librdkafka/rdkafkacpp.h>
#include "io/daily_logger.hpp"

// 生产者事件回调函数
class ProducerEventCb : public RdKafka::EventCb {
public:
    void event_cb(RdKafka::Event &event) override;

private:
    std::shared_ptr<DailyLogger> logger = DailyLogger::getInstance();
};


#endif //KAFKA_DEMO_PRODUCER_EVENT_CB_HPP
