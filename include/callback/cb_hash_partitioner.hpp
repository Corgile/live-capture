//
// Created by gzhuadmin on 23-5-11.
//

#ifndef KAFKA_DEMO_HASH_PARTITIONER_CB_HPP
#define KAFKA_DEMO_HASH_PARTITIONER_CB_HPP

#include <librdkafka/rdkafkacpp.h>
#include <iostream>
#include "io/daily_logger.hpp"


// 生产者自定义分区策略回调：partitioner_cb
class HashPartitionerCb : public RdKafka::PartitionerCb {
public:
    // @brief 返回 topic 中使用 key 的分区，msg_opaque 置 NULL
    // @return 返回分区，(0, partition_cnt)
    int32_t partitioner_cb(const RdKafka::Topic *topic, const std::string *key,
                           int32_t partition_cnt, void *msg_opaque) override;

private:
    // 自定义哈希函数
    static inline unsigned int generate_hash(const char *str, size_t len);
    std::shared_ptr<DailyLogger> logger = DailyLogger::getInstance();
};


#endif //KAFKA_DEMO_HASH_PARTITIONER_CB_HPP
