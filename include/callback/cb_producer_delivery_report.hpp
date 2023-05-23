//
// Created by gzhuadmin on 23-5-11.
//

#ifndef KAFKA_DEMO_PRODUCER_DELIVERY_REPORT_CB_HPP
#define KAFKA_DEMO_PRODUCER_DELIVERY_REPORT_CB_HPP

#include <iostream>
#include <librdkafka/rdkafkacpp.h>
#include "io/daily_logger.hpp"

// 生产者投递报告回调
class ProducerDeliveryReportCb : public RdKafka::DeliveryReportCb {
public:
    void dr_cb(RdKafka::Message &message) override;

private:
    std::shared_ptr<DailyLogger> logger = DailyLogger::getInstance();
};


#endif //KAFKA_DEMO_PRODUCER_DELIVERY_REPORT_CB_HPP
