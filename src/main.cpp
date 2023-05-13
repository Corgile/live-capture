//
// Created by iot-xhl on 2023/4/21.
//
#include "config.hpp"
#include "file_writer.hpp"
#include "pcap_parser.hpp"
#include "config_loader.hpp"

int main(int argc, char **argv) {
    if (argc < 2) {
        std::cout << "缺少配置文件 config file is missing.  eg. `sudo live-capture /path/to/config.properties` " << std::endl;
        exit(EXIT_FAILURE);
    }
    std::string config_properties = argv[1];
    std::ifstream file(config_properties.c_str());
    if(!file.good()) {
        std::cout << "文件[" << config_properties << "]不存在或打不开" << std::endl;
        exit(EXIT_FAILURE);
    }

    Config pcapConfig = Config::get_instance();
    FileWriter file_writer(pcapConfig);
    PCAPParser pcap_parser(pcapConfig, config_properties);
    pcap_parser.perform();
    return 0;
}

