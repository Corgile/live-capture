//
// Created by gzhuadmin on 23-5-16.
//

#include "io/torch_api.hpp"

#include <utility>

char const *labels[8]={
        "benign",
        "ddos",
        "dos",
        "ftp-patator",
        "infiltration",
        "port-scan",
        "ssh-patator",
        "web-attack"
};

TorchAPI::TorchAPI(std::string model_path) : m_model_path(std::move(model_path)) {
}

std::string TorchAPI::predict(std::vector<torch::jit::IValue> &inputs) {
    torch::Device device(torch::kCPU);
    torch::jit::script::Module model=torch::jit::load(this->m_model_path);
    model.to(device);
    at::Tensor output=model.forward(inputs).toTensor();
    auto index=torch::argmax(output, 1).item<long>();
    return labels[index];
}

//int TorchAPI::argmax(at::Tensor &tensor) {
//    int max_index=0;
//    float max_val=
//    for (int i=0; i < tensor.size(1); ++i) {
//        max_index=()
//    }
//}
