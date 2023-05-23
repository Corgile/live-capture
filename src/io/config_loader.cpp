//
// Created by gzhuadmin on 23-5-12.
//

#include "io/config_loader.hpp"
#include "constants.hpp"

ConfigLoader::ConfigLoader(const std::string &m_config_file_path) {

    std::ifstream config_file(m_config_file_path);
    if (!config_file.is_open()) {
        std::cout << "无法打开配置文件" << std::endl;
        exit(EXIT_FAILURE);
    }

    // 解析配置文件内容
    std::string line;
    while (getline(config_file, line)) {
        if (line.empty() || line[0] == '#') {
            continue;
        }
        // 解析 key=value 类型的配置项
        size_t pos = line.find('=');
        if (pos == std::string::npos) {
            std::cout << "配置项格式错误：" << line << std::endl;
            exit(EXIT_FAILURE);
        }
        std::string key = line.substr(0, pos);
        std::string value = line.substr(pos + 1);
        this->m_configs[key] = value;
    }
    for (const auto &p: this->m_configs) {
        std::cout << "加载配置： " << p.first << "=" << p.second << std::endl;
        logger->debug("加载配置 {}", p.first + p.second);
    }
    this->check_config(keys::MODEL_PATH);
    this->check_config(keys::KAFKA_BROKERS);
    this->check_config(keys::KAFKA_TOPIC);
    this->check_config(keys::KAFKA_PARTITION);
}

void ConfigLoader::check_config(const std::string &key) {
    if (this->m_configs[key].empty()) {
        std::cout << "缺少配置项： " << key << std::endl;
        logger->error("缺少配置项: {}", key);
        exit(EXIT_FAILURE);
    }
    if (key != keys::KAFKA_PARTITION) {
        return;
    }
    try {
        std::stoi(this->m_configs[key]);
    } catch (const std::invalid_argument &e) {
        std::cerr << "[" << keys::KAFKA_PARTITION << "] 配置错误" << e.what() << std::endl;
        logger->error("[{}] 配置错误 ", keys::KAFKA_PARTITION);
        exit(EXIT_FAILURE);
    } catch (const std::out_of_range &e) {
        std::cerr << "[" << keys::KAFKA_PARTITION << "] 配置错误" << e.what() << std::endl;
        logger->error("[{}] 配置错误 ", keys::KAFKA_PARTITION);
        exit(EXIT_FAILURE);
    }
}


std::map<std::string, std::string> ConfigLoader::get_conf() {
    return this->m_configs;
}
