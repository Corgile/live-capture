//
// Created by gzhuadmin on 4/27/23.
//

#include "call_python.hpp"

#include <utility>

std::string Python::predict(const std::string &bit_string) {
    return this->_call_perform_predict(bit_string);
}

void Python::_init_required_module() {
    //引入当前路径,否则下面模块不能正常导入
    char tempPath[256] = {};
    sprintf(tempPath, "sys.path.append('%s')", this->m_Py_module_path.c_str());
    PyRun_SimpleString("import sys");
    PyRun_SimpleString("import numpy as np");
    PyRun_SimpleString("from keras.models import load_model");
    PyRun_SimpleString("sys.path.append('./')");
    PyRun_SimpleString(tempPath);

    this->m_RequiredModules = PyImport_ImportModule(this->m_Py_module_name.c_str());

    if (py_object(this->m_RequiredModules) == nullptr) {
        PyErr_Print();
        std::cout << __FILE__ << ":" << __LINE__
                  << " PyImport_ImportModule '" << this->m_Py_module_name << "' not found" << std::endl;
        exit(EXIT_FAILURE);
    }
}


Python::~Python() {
    delete this->m_Model;
    delete this->m_Functions;
    delete this->m_RequiredModules;
    Python::FreePythonInterpreter();

    Py_DECREF(this->m_Model);
    Py_DECREF(this->m_Functions);
    Py_DECREF(this->m_RequiredModules);
}

Python::Python(std::string model_path,
               std::string module_path,
               std::string module_name)
        : m_Model_path(std::move(model_path)),
          m_Py_module_path(std::move(module_path)),
          m_Py_module_name(std::move(module_name)) {

    Python::InitPythonInterpreter();
    this->_init_required_module();
//    //获取模块字典属性
    PythonObject py_module_dict(_functions) = PyModule_GetDict(this->m_RequiredModules);
    if (py_module_dict(_functions) == nullptr) {
        std::cout << __FILE__ << ":" << __LINE__ << " PyModule_GetDict error" << std::endl;
        PyErr_Print();
        exit(EXIT_FAILURE);
    }
    this->m_Functions = py_module_dict(_functions);

#ifdef FUCK
#pragma region TEST
    PyObject *pDict = PyModule_GetDict(this->m_RequiredModules);

    PyObject *pFunc, *pKeys, *pKey;
    pKeys = PyDict_Keys(pDict);

    for (Py_ssize_t i = 0; i < PyList_Size(pKeys); i++) {
        pKey = PyList_GetItem(pKeys, i);
        std::string key_str = PyUnicode_AsUTF8(pKey);
        pFunc = PyDict_GetItemString(pDict, key_str.c_str());

        if (PyCallable_Check(pFunc)) {
            std::cout << "Found Python function: " << key_str << std::endl;
            // 在这里可以调用 pFunc 对应的 Python 函数
        }
    }
#pragma endregion
#endif
    //直接获取模块中的函数
    PythonObject py_function(load_model) = PyDict_GetItemString(this->m_Functions, "load_model");
    if (py_function(load_model) == nullptr) {
        std::cout << __FILE__ << ":" << __LINE__
                  << "PyDict_GetItemString 'load_model' not found" << std::endl;
        PyErr_Print();
        exit(EXIT_FAILURE);
    }
    PythonObject pArg_model_path = Py_BuildValue("s", this->m_Model_path.c_str());

    this->m_Model = PyObject_CallFunction(load_model, "O", pArg_model_path);
}

std::string Python::_call_perform_predict(const std::string &bit_string) {
    //直接获取模块中的函数
    PythonObject py_function(prediction) = PyDict_GetItemString(this->m_Functions, "perform_predict");
    if (py_function(prediction) == nullptr) {
        std::cout << __FILE__ << ":" << __LINE__
                  << ": PyDict_GetItemString 'perform_predict' not found" << std::endl;
        PyErr_Print();
        exit(-1);
    }
    PythonObject py_object(pBitString) = PyUnicode_FromString(bit_string.c_str());
    PythonObject py_object(pArgs) = PyTuple_New(2);
    PyTuple_SetItem(py_object(pArgs), 0, this->m_Model);
    PyTuple_SetItem(py_object(pArgs), 1, py_object(pBitString));

    //    PyArg_Parse(ret, "O", this->m_Model);
    //    PythonObject pArg = Py_BuildValue("(s)", bit_string.c_str());
    //调用函数，并得到python类型的返回值
//    exit(EXIT_FAILURE);
    PythonObject py_object(result) = PyObject_CallObject(prediction, pArgs);

    // 检查返回值类型是否为字符串类型
    if (!PyUnicode_Check(result)) {
        PyErr_Print();
        exit(EXIT_FAILURE);
    }
    // 将 Python 字符串转换为 C 字符串
    auto label = PyUnicode_AsUTF8(result);
    if (label == nullptr) {
        PyErr_Print();
        std::cout << __FILE__ << ":" << __LINE__ << std::endl;
        exit(EXIT_FAILURE);
    }
    return label;
}

void Python::InitPythonInterpreter() {
    Py_Initialize();
}

void Python::FreePythonInterpreter() {
    Py_Finalize();
}

