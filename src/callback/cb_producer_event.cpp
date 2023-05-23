//
// Created by gzhuadmin on 23-5-11.
//

#include "callback/cb_producer_event.hpp"
#include "common.hpp"

void ProducerEventCb::event_cb(RdKafka::Event &event) {
    switch (event.type()) {
        case RdKafka::Event::EVENT_ERROR:
            WARN_CALL(std::cout << "RdKafka::Event::EVENT_ERROR: "
                                << RdKafka::err2str(event.err()) << std::endl);
            logger->warn("RdKafka::Event::EVENT_ERROR: {}", RdKafka::err2str(event.err()));
            break;
        case RdKafka::Event::EVENT_STATS:
            WARN_CALL(std::cout << "RdKafka::Event::EVENT_STATS: " << event.str()
                                << std::endl);
            logger->warn("RdKafka::Event::EVENT_STATS: {}", event.str());
            break;
        case RdKafka::Event::EVENT_LOG:
            WARN_CALL(std::cout << "RdKafka::Event::EVENT_LOG " << event.fac()
                                << std::endl);
            logger->warn("RdKafka::Event::EVENT_LOG: {}", event.fac());
            break;
        case RdKafka::Event::EVENT_THROTTLE:
            WARN_CALL(std::cout << "RdKafka::Event::EVENT_THROTTLE "
                                << event.broker_name() << std::endl);
            logger->warn("RdKafka::Event::EVENT_THROTTLE: {}", event.broker_name());
            break;
    }
}
