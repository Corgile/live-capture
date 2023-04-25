#include "pcap_parser.hpp"
#include<algorithm>


void PCAPParser::perform() {
	pcap_t *f = get_pcap_handle();
	this->linktype = pcap_datalink(f);
	pcap_loop(f, 0, packet_handler, (u_char *) this);
	pcap_close(f);
}

void PCAPParser::packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	auto pcp = (PCAPParser *) user_data;
	if (pcp->linktype == DLT_LINUX_SLL) {
		packet = (uint8_t *) packet + LINUX_COOKED_HEADER_SIZE;
	}
	auto sp = pcp->process_packet((void *) packet);
	if (sp == nullptr) return;

	auto rts = pcp->process_timestamp(pkthdr->ts);
	pcp->custom_output.push_back(sp->get_index(&(pcp->config)));
	if (rts != -1) {
		pcp->custom_output.push_back(std::to_string(rts));
	}
	if (pcp->config.absolute_timestamps) {
		pcp->custom_output.push_back(std::to_string(pkthdr->ts.tv_sec));
		pcp->custom_output.push_back(std::to_string(pkthdr->ts.tv_usec));
	}
//	pcp->write_output(sp);
//	auto vec = pcp->get_bitstring_vec();
	pcp->perform_predict(packet);

}

void PCAPParser::format_and_write_header() {
	std::vector<std::string> header(4);
	header.emplace_back(config.index_map.find(config.output_index)->second);
	if (config.relative_timestamps == 1) {
		header.emplace_back("rts");
	}
	if (config.absolute_timestamps == 1) {
		header.emplace_back("tv_sec");
		header.emplace_back("tv_usec");
	}

	file_writer.write_header(header);
}

int64_t PCAPParser::process_timestamp(struct timeval ts) {
	int64_t rts;

	if (config.relative_timestamps == 0) return -1;

	if (mrt.tv_sec == 0) {
		rts = 0;
	} else {
		auto diff = ts.tv_sec - mrt.tv_sec;
		int ratio = (diff << 19) + (diff << 18) + (diff << 17) +
		            (diff << 16) + (diff << 14) + (diff << 9) + (diff << 6);
		rts = ratio + ts.tv_usec - mrt.tv_usec;
	}
	this->mrt = ts;
	return rts;
}

pcap_t *PCAPParser::get_pcap_handle() {

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *f;

	if (config.live_capture == 0) {
		f = pcap_open_offline_with_tstamp_precision(config.infile.c_str(), PCAP_TSTAMP_PRECISION_MICRO, errbuf);
	} else {
		f = this->open_live_handle();
	}
	this->set_filter(f, const_cast<char *>(config.filter.c_str()));

	return f;
}

pcap_t *PCAPParser::open_live_handle() {
//	pcap_t *handle;
	pcap_if_t *l;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* get device */
	if (config.device == "") {
		int32_t rv = pcap_findalldevs(&l, errbuf);
		if (rv == -1) {
			std::cerr << "Failure looking up default device: " << errbuf << std::endl;
			exit(2);
		}
		config.device = l->name;
	}
	/* open device */
	auto handle = pcap_open_live(config.device.c_str(), BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		std::cerr << "Couldn't open device: " << errbuf << std::endl;
		exit(2);
	}

	return handle;
}

void PCAPParser::set_filter(pcap_t *handle, char *filter) {
	if (!filter) return;

	bpf_u_int32 net = 0, mask = 0;
	struct bpf_program fp{};
	char errbuf[PCAP_ERRBUF_SIZE];

	if (config.live_capture != 0) {
		/** get mask*/
		if (pcap_lookupnet(config.device.c_str(), &net, &mask, errbuf) == -1) {
			std::cerr << "Can't get netmask for device: " << config.device << std::endl;
		}
	}

	if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
		std::cerr << "Couldn't parse filter " << filter << ": " << pcap_geterr(handle) << std::endl;
		exit(2);
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		std::cerr << "Couldn't install filter " << filter << ": " << pcap_geterr(handle) << std::endl;
		exit(2);
	}
}

PCAPParser::PCAPParser(const Config &config, const FileWriter &file_writer, fdeep::model modelFile)
		: IOParser(config, file_writer), _model_file(modelFile) {
	mrt.tv_sec = 0;
	mrt.tv_usec = 0;
	auto size =
			SIZE_IPV4_HEADER_BITSTRING
			+ SIZE_TCP_HEADER_BITSTRING
			+ SIZE_UDP_HEADER_BITSTRING
			+ SIZE_ICMP_HEADER_BITSTRING;
	to_fill.reserve(size << 5);
	PCAPParser::format_and_write_header();
}

void PCAPParser::perform_predict(const u_char *packet) {

	std::vector<int> most_important_indecies = {1, 107, 231, 25, 109, 15, 233, 0, 2, 3, 235, 4, 29, 234, 232, 199, 239, 5, 230, 16, 180, 98, 236, 6, 31, 238, 237, 30, 24, 9, 11, 126, 13, 7, 198, 10, 43, 56, 50, 28, 608, 202, 318, 201, 117, 8, 23, 34, 111, 12, 48, 33, 51, 32, 27, 45, 14, 46, 54, 74, 119, 40, 228, 125, 37, 224, 35, 44, 61, 248, 118, 70, 121, 60, 49, 52, 96, 206, 17, 39, 36, 18, 38, 123, 41, 241, 57, 240, 66, 222, 20, 122, 62, 134, 204, 42, 69, 59, 192, 229, 203, 226, 120, 65, 55, 129, 26, 130, 19, 127, 227, 21, 99, 139, 58, 64, 68, 213, 113, 140, 135, 141, 53, 67, 200, 22, 72, 63};
	std::vector<int> samples(768);
	std::vector<std::string> labels{
			"benign",
			"ddos",
			"dos",
			"ftp-patator",
			"infiltration",
			"port-scan",
			"ssh-patator",
			"web-attack"
	};
	for (const auto &item: this->bitstring_vec) {
		samples.emplace_back(int(item));
	}

	std::vector<float> X(128);
	for (int i = 0; i < 128; ++i) {
		X[i] = samples[most_important_indecies[i]];
	}

	const fdeep::tensor_shape shape{128, 1};
	fdeep::tensor __vec(shape, X);

	const std::vector<fdeep::tensor> inputs{__vec};

	auto result = this->_model_file.predict(inputs);

	int index = 0;
	for (const auto &_tensor: result) {
		auto vec = _tensor.as_vector();
//		auto _size = vec->size(); // 8

		auto values = vec->data();
		auto _size = vec->size();

		float _max = values[index];

		for (int i = 0; i < _size; ++i) {
			if(_max < values[i]) {
				_max = values[i];
				index = i;
			}
		}
		//std::cout << labels[index] << std::endl;
	}

#pragma region 处理 MAC 地址
//	struct ether_header *eth = (struct ether_header *)packet;
//	char src_mac[18], dst_mac[18];
//	sprintf(src_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
//	        eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
//	        eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
//
//	sprintf(dst_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
//	        eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
//	        eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
//	printf("Source MAC: %s\n", src_mac);
//	printf("Destination MAC: %s\n", dst_mac);
#pragma endregion

#pragma region 处理 IP 地址
	struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ether_header));
	char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(ip->saddr), src_ip, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(ip->daddr), dst_ip, INET_ADDRSTRLEN);
#pragma endregion

	std::cout << "Source IP: " << src_ip << " -> "
	<< labels[index]
	<< " -> Destnation IP: " << dst_ip << std::endl;
}

void PCAPParser::set_model(const fdeep::model & _model) {
	this->_model_file = _model;
}
