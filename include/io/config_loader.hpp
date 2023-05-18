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
    std::map<std::string, std::string> m_configs;

    void check_config(const std::string &key);

    std::shared_ptr<DailyLogger> logger = DailyLogger::getInstance();

public:
    explicit ConfigLoader(const std::string &config_file_path);

    std::map<std::string, std::string> get_conf();
};


#endif //LIVE_CAPTURE_CONFIG_LOADER_HPP
