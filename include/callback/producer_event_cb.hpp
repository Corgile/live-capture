//
// Created by gzhuadmin on 23-5-11.
//

#ifndef KAFKA_DEMO_PRODUCER_EVENT_CB_HPP
#define KAFKA_DEMO_PRODUCER_EVENT_CB_HPP

#include <librdkafka/rdkafkacpp.h>
#include <iostream>


// 生产者事件回调函数
class ProducerEventCb : public RdKafka::EventCb {
public:
    void event_cb(RdKafka::Event &event) override;
};


#endif //KAFKA_DEMO_PRODUCER_EVENT_CB_HPP
