//
// Created by gzhuadmin on 23-5-11.
//

#include "callback/cb_hash_partitioner.hpp"

int32_t HashPartitionerCb::partitioner_cb(const RdKafka::Topic *topic,
                                          const std::string *key,
                                          int32_t partition_cnt,
                                          void *msg_opaque) {
    char msg[128] = {0};
    // 用于自定义分区策略：这里用 hash。例：轮询方式：p_id++ % partition_cnt
    int32_t partition_id = (int32_t) generate_hash(key->c_str(), key->size()) % partition_cnt;
    sprintf(msg, "HashPartitionerCb:topic:[%s], key:[%s], partition_cnt:[%d], partition_id:[%d]",
            topic->name().c_str(), key->c_str(), partition_cnt, partition_id);
    logger->debug("{}", msg);
    return partition_id;
}

unsigned int
HashPartitionerCb::generate_hash(const char *str, size_t len) {
    unsigned int hash = 5381;
    for (size_t i = 0; i < len; i++) {
        hash = ((hash << 5) + hash) + str[i];
    }
    return hash;
}
