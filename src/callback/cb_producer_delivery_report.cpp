//
// Created by gzhuadmin on 23-5-11.
//

#include "callback/cb_producer_delivery_report.hpp"
#include "common.hpp"

void ProducerDeliveryReportCb::dr_cb(RdKafka::Message &message) {
    // 发送出错的回调
    if (message.err()) {
        WARN_CALL(std::cerr << "\033[33mMessage delivery failed: \033[0m" << message.errstr() << std::endl);
        logger->warn("Message delivery failed: {}", message.errstr());
    }
        // 发送正常的回调
        // Message delivered to topic test [2] at offset 4169
    else {
        INFO_CALL(std::cout << "Message delivered to topic " << message.topic_name()
                            << " [" << message.partition() << "] at offset "
                            << message.offset() << std::endl);
        auto _fmt = "Message delivered to topic " + message.topic_name()
                    + "[" + std::to_string(message.partition()) + "] , at offset {}";
        logger->info(_fmt.c_str(), std::to_string(message.offset()));
    }
}
