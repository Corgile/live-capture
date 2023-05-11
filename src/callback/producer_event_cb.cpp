//
// Created by gzhuadmin on 23-5-11.
//

#include "producer_event_cb.hpp"

void ProducerEventCb::event_cb(RdKafka::Event &event) {
    switch (event.type()) {
        case RdKafka::Event::EVENT_ERROR:
            std::cout << "RdKafka::Event::EVENT_ERROR: "
                      << RdKafka::err2str(event.err()) << std::endl;
            break;
        case RdKafka::Event::EVENT_STATS:
            std::cout << "RdKafka::Event::EVENT_STATS: " << event.str()
                      << std::endl;
            break;
        case RdKafka::Event::EVENT_LOG:
            std::cout << "RdKafka::Event::EVENT_LOG " << event.fac()
                      << std::endl;
            break;
        case RdKafka::Event::EVENT_THROTTLE:
            std::cout << "RdKafka::Event::EVENT_THROTTLE "
                      << event.broker_name() << std::endl;
            break;
    }
}
