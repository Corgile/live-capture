//
// Created by gzhuadmin on 23-5-11.
//

#include "hash_partitioner_cb.hpp"

int32_t
HashPartitionerCb::partitioner_cb(const RdKafka::Topic *topic,
                                  const std::string *key,
                                  int32_t partition_cnt,
                                  void *msg_opaque) {
    char msg[128] = {0};
    // 用于自定义分区策略：这里用 hash。例：轮询方式：p_id++ % partition_cnt
    int32_t partition_id = generate_hash(key->c_str(), key->size()) % partition_cnt;
    // 输出：[topic][key][partition_cnt][partition_id]，例 [test][6419][2][1]
    sprintf(msg, "HashPartitionerCb:topic:[%s], key:[%s], partition_cnt:[%d], partition_id:[%d]",
            topic->name().c_str(), key->c_str(), partition_cnt, partition_id);
    std::cout << msg << std::endl;
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
