//
// Created by gzhuadmin on 23-5-11.
//

#include "producer_event_cb.hpp"
#include "common_macros.hpp"

void ProducerEventCb::event_cb(RdKafka::Event &event) {
    switch (event.type()) {
        case RdKafka::Event::EVENT_ERROR:
            WARN_CALL(std::cout << "RdKafka::Event::EVENT_ERROR: "
                                 << RdKafka::err2str(event.err()) << std::endl);
            break;
        case RdKafka::Event::EVENT_STATS:
            WARN_CALL(std::cout << "RdKafka::Event::EVENT_STATS: " << event.str()
                                 << std::endl);
            break;
        case RdKafka::Event::EVENT_LOG:
            WARN_CALL(std::cout << "RdKafka::Event::EVENT_LOG " << event.fac()
                                 << std::endl);
            break;
        case RdKafka::Event::EVENT_THROTTLE:
            WARN_CALL(std::cout << "RdKafka::Event::EVENT_THROTTLE "
                                 << event.broker_name() << std::endl);
            break;
    }
}
