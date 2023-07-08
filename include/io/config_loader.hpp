//
// Created by gzhuadmin on 23-5-12.
//

#ifndef LIVE_CAPTURE_CONFIG_LOADER_HPP
#define LIVE_CAPTURE_CONFIG_LOADER_HPP

#include <iostream>
#include <map>
#include <string>
#include <fstream>
#include "io/daily_logger.hpp"

class ConfigLoader {
private:
    /**
    * @brief 配置文件的配置项，用map存储
    */
    std::map<std::string, std::string> m_configs;

    /**
    * @brief 检查必要配置项是否存在且符合要求
    * @param key  配置项的key
    */
    void check_config(const std::string &key);

    /**
    * @brief 一个日志记录器，会根据日志的等级（debug,info,warn,error,fatal）
    * 创建独立的日志文件，并且每天的日志会自动放在不同的目录
    */
    std::shared_ptr<DailyLogger> logger = DailyLogger::getInstance();

public:
    /**
    * @brief 配置加载器的构造函数
    * @param config_file_path 配置文件的位置，绝对路径
    */
    explicit ConfigLoader(const std::string &config_file_path);

    /**
    * @brief 获取配置项目，会返回一个map
    * @return this->m_configs
    */
    std::map<std::string, std::string> get_conf();
};


#endif //LIVE_CAPTURE_CONFIG_LOADER_HPP
