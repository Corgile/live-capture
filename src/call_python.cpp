//
// Created by gzhuadmin on 4/27/23.
//

#include "call_python.hpp"
#include "common_macros.hpp"

#include <utility>

std::string Python::predict(std::string &bit_string) {
    return this->_call_perform_predict(bit_string);
}

void Python::_init_required_module() {
    //引入当前路径,否则下面模块不能正常导入
    char tempPath[256]={ };
    sprintf(tempPath, "sys.path.append('%s')", this->m_Py_module_path);
    delete this->m_Py_module_path;
    this->m_Py_module_path=nullptr;

    std::cout << __PRETTY_FUNCTION__ << ":" << __LINE__ << std::endl;
    PyRun_SimpleString("import sys");
    PyRun_SimpleString("import numpy as np");
    PyRun_SimpleString("from keras.models import load_model");
    PyRun_SimpleString("sys.path.append('./')");
    PyRun_SimpleString(tempPath);

    this->m_RequiredModules=PyImport_ImportModule(this->m_Py_module_name);

    if (py_object(this->m_RequiredModules) == nullptr) {
        PyErr_Print();
        std::cout << __FILE__ << ":" << __LINE__
                  << " PyImport_ImportModule '" << this->m_Py_module_name << "' not found" << std::endl;
        logger->error("Python Import Module Error: {}", __PRETTY_FUNCTION__);
        exit(EXIT_FAILURE);
    }
}


Python::~Python() {
    Py_DecRef(this->m_Model);
    Py_DecRef(this->m_RequiredModules);
    delete this->m_Model;
    delete this->m_RequiredModules;
    Python::FreePythonInterpreter();
}

Python::Python(char *model_path, char *module_path, char *module_name)
        : m_Model_path(model_path),
          m_Py_module_path(module_path),
          m_Py_module_name(module_name) {

    Python::InitPythonInterpreter();
    std::cout << __PRETTY_FUNCTION__ << ":" << __LINE__ << std::endl;
    this->_init_required_module();
    //    //获取模块字典属性
    PythonObject _functions=PyModule_GetDict(this->m_RequiredModules);
    if (_functions == nullptr) {
        std::cout << __FILE__ << ":" << __LINE__ << " PyModule_GetDict error" << std::endl;
        PyErr_Print();
        logger->error("Get Module_Dict Error: {}", __PRETTY_FUNCTION__);
        exit(EXIT_FAILURE);
    }
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
    m_load_model=PyDict_GetItemString(_functions, "load_model");
    std::cout << __PRETTY_FUNCTION__ << ":" << __LINE__ << std::endl;
    if (m_load_model == nullptr) {
        std::cout << __FILE__ << ":" << __LINE__
                  << "PyDict_GetItemString 'load_model' not found" << std::endl;
        PyErr_Print();
        logger->error("Get Dict Item(String) `load_model` Error: {}", __PRETTY_FUNCTION__);
        exit(EXIT_FAILURE);
    }

    {
        pArg_model_path=Py_BuildValue("s", this->m_Model_path);
        this->m_Model=PyObject_CallFunction(m_load_model, "O", pArg_model_path);
        Py_DecRef(pArg_model_path);
    }

    this->m_prediction=PyDict_GetItemString(_functions, "perform_predict");
    if (py_function(m_prediction) == nullptr) {
        std::cout << __FILE__ << ":" << __LINE__
                  << ": PyDict_GetItemString 'perform_predict' not found" << std::endl;
        PyErr_Print();
        logger->error("Get Dict Item(String) `perform_predict` Error: {}", __PRETTY_FUNCTION__);
        exit(EXIT_FAILURE);
    }

    pArgs=PyTuple_New(2);
    PyTuple_SetItem(pArgs, 0, this->m_Model);
}

std::string Python::_call_perform_predict(std::string &bit_string) {

    PyGILState_STATE g_state {PyGILState_Ensure()};
    PythonObject bitstring {PyUnicode_FromString(bit_string.c_str())};
    PyTuple_SetItem(pArgs, 1, bitstring);

    PyGILState_Release(g_state);
    result=PyObject_CallObject(this->m_prediction, pArgs);
    // 检查返回值类型是否为字符串类型
    if (!PyUnicode_Check(result)) {
        PyErr_Print();
        logger->error("返回值错误: {}", __PRETTY_FUNCTION__);
        exit(EXIT_FAILURE);
    }
    auto label=PyUnicode_AsUTF8(result);
    if (label == nullptr) {
        PyErr_Print();
        std::cout << __FILE__ << ":" << __LINE__ << std::endl;
        logger->error("将 Python 字符串转换为 C 字符串，错误: {}", __PRETTY_FUNCTION__);
        exit(EXIT_FAILURE);
    }
    Py_XDECREF(result);
    return label;
}

void Python::InitPythonInterpreter() {
    Py_Initialize();
}

void Python::FreePythonInterpreter() {
    Py_Finalize();
}

void *Python::operator new(size_t size) {
    DEBUG_CALL(std::cout << "\n\t\033[34m ----------------- 分配 " << size
                         << " bytes 内存 -------------------- \033[0m\n");
    return malloc(size);
}

void Python::operator delete(void *p) {
    DEBUG_CALL(std::cout << "\n\t\033[31m ----------------- 释放内存 -------------------- \033[0m\n");
    free(p);
}

