//
// Created by gzhuadmin on 23-5-11.
//

#include "producer_delivery_report_cb.hpp"

void ProducerDeliveryReportCb::dr_cb(RdKafka::Message &message) {
    // 发送出错的回调
    if (message.err()) {
        std::cerr << "Message delivery failed: " << message.errstr() << std::endl;
    }
        // 发送正常的回调
        // Message delivered to topic test [2] at offset 4169
    else {
        std::cout << "Message delivered to topic " << message.topic_name()
                  << " [" << message.partition() << "] at offset "
                  << message.offset() << std::endl;
    }
}
