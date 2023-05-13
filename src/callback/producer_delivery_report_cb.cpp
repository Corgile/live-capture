//
// Created by gzhuadmin on 23-5-11.
//

#include "producer_delivery_report_cb.hpp"
#include "common_macros.hpp"

void ProducerDeliveryReportCb::dr_cb(RdKafka::Message &message) {
    // 发送出错的回调
    if (message.err()) {
        WARN_CALL(std::cerr << "\033[33mMessage delivery failed: \033[0m" << message.errstr() << std::endl);
    }
        // 发送正常的回调
        // Message delivered to topic test [2] at offset 4169
    else {
        INFO_CALL(std::cout << "Message delivered to topic " << message.topic_name()
                  << " [" << message.partition() << "] at offset "
                  << message.offset() << std::endl);
    }
}
