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
    /**
     * @brief 一个日志记录器，会根据日志的等级（debug,info,warn,error,fatal）
     * 创建独立的日志文件，并且每天的日志会自动放在不同的目录
     */
    std::shared_ptr<DailyLogger> logger = DailyLogger::getInstance();
};


#endif //KAFKA_DEMO_PRODUCER_DELIVERY_REPORT_CB_HPP
