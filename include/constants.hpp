//
// Created by gzhuadmin on 23-5-12.
//

#ifndef LIVE_CAPTURE_CONSTANTS_HPP
#define LIVE_CAPTURE_CONSTANTS_HPP

#include <iostream>


namespace keys {

    static const std::string DEVICE_NAME      = "device.name";
    static const std::string MODEL_PATH       = "model.path";
    static const std::string SCRIPT_NAME      = "py.script.name";
    static const std::string SCRIPT_PATH      = "py.script.path";
    static const std::string KAFKA_BROKER     = "kafka.brokers";
    static const std::string KAFKA_TOPIC      = "kafka.topic";
    static const std::string KAFKA_PARTITION  = "kafka.partition";

}
#endif //LIVE_CAPTURE_CONSTANTS_HPP