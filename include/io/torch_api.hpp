//
// Created by gzhuadmin on 23-5-16.
//

#ifndef LIVE_CAPTURE_TORCH_API_HPP
#define LIVE_CAPTURE_TORCH_API_HPP

#include <string>
#include <vector>
#include <torch/script.h>

class TorchAPI {

public:
    explicit TorchAPI(std::string);

    std::string predict(std::vector<torch::jit::IValue> &);

private:

    std::string m_model_path;
    std::vector<torch::jit::IValue> m_inputs;

};

#endif //LIVE_CAPTURE_TORCH_API_HPP
