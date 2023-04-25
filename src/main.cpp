//
// Created by iot-xhl on 2023/4/21.
//
#include "config.hpp"
#include "file_writer.hpp"

#include <vector>
#include "pcap_parser.hpp"


int main(int argc, char **argv) {
// TODO 使用选项参数实例化config
    auto model = fdeep::load_model("./model/m2_128.json");
	Config config = Config::get_instance();
	FileWriter file_writer(config);
	auto pcap_parser = new PCAPParser(config, file_writer);
	pcap_parser->set_model(&model);
	pcap_parser->perform();
	delete pcap_parser;
	return 0;
}

