//
// Created by gzhuadmin on 23-5-16.
//

#ifndef LIVE_CAPTURE_TORCH_API_HPP
#define LIVE_CAPTURE_TORCH_API_HPP

#include <string>
#include <vector>
#include <torch/script.h>

/**
* @brief LibTorch API
*/
class TorchAPI {

public:
    /**
    * @brief 构造函数，需要一个与训练模型文件
    * @param path 模型路径
    */
    explicit TorchAPI(std::string path);

    /**
    * @brief 分类函数
    * @return  流量包的分类结果（标签）
    */
    std::string predict(std::vector<torch::jit::IValue> &);

private:

    std::string m_model_path;
    /**
    * @brief 模型的输入，是一个张量
    */
    std::vector<torch::jit::IValue> m_inputs;

};

#endif //LIVE_CAPTURE_TORCH_API_HPP
