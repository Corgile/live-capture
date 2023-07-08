#ifndef LIVE_CAPTURE_ETH_HEADER_HPP
#define LIVE_CAPTURE_ETH_HEADER_HPP

#include <netinet/if_ether.h>

#include "packet/header/packet_header.hpp"
#include "common.hpp"

/**
* @brief 以太头部的一些操作接口，其他头文件同理
*/
class EthHeader : public PacketHeader {
public:
    /* Required Functions */
    /**
    * @brief get 流量的raw数据
    * @return 流量的raw数据
    */
    raw_data_t get_raw() override;

    /**
    * @brief 同理， @see EthHeader::get_raw()
    * @param raw
    */
    void set_raw(raw_data_t raw) override;

    /**
    * @brief 输出头部信息，在开发阶段用作调试功能
    * @param out out是一个指针，可以指定到文件或控制台
    */
    void print_header(FILE *out) override;

    /**
    * @brief 获取头部长度
    * @return 头部长度
    */
    uint32_t header_len() override;

    /**
    * @brief 填充bit_vec
    * @param bit_vec raw数据的一部分
    * @param bit raw数据的一些位，在文档里有介绍
    */
    void fill_bit_vec(std::vector<float> &bit_vec, int8_t bit) override;

    /**
    * @brief 生成头部字段
    * @param to_fill
    */
    void get_bitstring_header(std::vector<std::string> &to_fill) override;

private:
    eth_header_t raw{ };
};

#endif
