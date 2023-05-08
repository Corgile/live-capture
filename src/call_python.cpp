//
// Created by gzhuadmin on 4/27/23.
//

#include "call_python.hpp"

std::string Python::predict(const std::string &bit_string) {
    return this->_call_perform_predict(bit_string);
}

PythonObject Python::_init_required_module() {
    const char *pyDir = "/home/gzhuadmin/workspace/live-capture/target/";
    const char *module_name = "damn";
    //引入当前路径,否则下面模块不能正常导入
    char tempPath[256] = {};
    sprintf(tempPath, "sys.path.append('%s')", pyDir);
    PyRun_SimpleString("import sys");
    PyRun_SimpleString("import numpy as np");
    PyRun_SimpleString("from keras.models import load_model");
    PyRun_SimpleString("sys.path.append('./')");
//    PyRun_SimpleString("/usr/local/lib/python3.8/dist-packages/");
    PyRun_SimpleString(tempPath);

    PythonObject py_object(module) = PyImport_ImportModule(module_name);

    if (py_object(module) == nullptr) {
        PyErr_Print();
        std::cout << __FILE__ << " : " << __LINE__
                  << "PyImport_ImportModule '" << module_name << "' not found" << std::endl;
        exit(-1);
    }
    this->m_RequiredModules = module;
    return module;
}

//// TODO
//PythonObject *Python::_call_python_function(char *func_name, PythonObject *pArgs, const char *type) {
//// TODO  重构
////    //直接获取模块中的函数
////    PythonObject py_function(func) = PyDict_GetItemString(this->m_Functions, func_name);
////    if (py_function(func) == nullptr) {
////        std::cout << "PyDict_GetItemString '[" << func_name << "]' not found" << std::endl;
////        return nullptr;
////    }
////
//////    PythonObject pArg = Py_BuildValue("(s)", pArgs);
////    PythonObject args = pArgs ? Py_BuildValue(type, pArgs) : nullptr;
////    // 调用函数，并得到python类型的返回值
////    PythonObject result = PyObject_CallObject(func, args);
////    PyArg_Parse(result, "s", ref_out);
////
////    return result;
//    return nullptr;
//}

Python::~Python() {
    delete this->m_Model;
    delete this->m_Functions;
    delete this->m_RequiredModules;
    Python::FreePythonInterpreter();

    Py_DECREF(this->m_Model);
    Py_DECREF(this->m_Functions);
    Py_DECREF(this->m_RequiredModules);
}

Python::Python() {
    Python::InitPythonInterpreter();
    this->m_RequiredModules = this->_init_required_module();
    //获取模块字典属性
    PythonObject py_module_dict(_functions) = PyModule_GetDict(this->m_RequiredModules);
    if (py_module_dict(_functions) == nullptr) {
        std::cout << __FILE__ << " : " << __LINE__ << " PyModule_GetDict error" << std::endl;
        PyErr_Print();
        exit(-1);
    }
    this->m_Functions = py_module_dict(_functions);
    // Py_DECREF(_functions);

    //直接获取模块中的函数
    PythonObject py_function(get_model) = PyDict_GetItemString(this->m_Functions, "get_model");
    if (py_function(get_model) == nullptr) {
        std::cout << __FILE__ << " : " << __LINE__
                  << "PyDict_GetItemString 'get_model' not found" << std::endl;
        PyErr_Print();
        exit(-1);
    }
    //调用函数，并得到python类型的返回值
    this->m_Model = PyObject_CallObject(py_function(get_model), nullptr);
    // Py_DECREF(py_function(get_model));
}

std::string Python::_call_perform_predict(const std::string &bit_string) {
    //直接获取模块中的函数
    PythonObject py_function(prediction) = PyDict_GetItemString(this->m_Functions, "perform_predict");
    if (py_function(prediction) == nullptr) {
        std::cout << __FILE__ << " : " << __LINE__
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
    PythonObject py_object(result) = PyObject_CallObject(prediction, pArgs);

    // 检查返回值类型是否为字符串类型
    if (!PyUnicode_Check(result)) {
        PyErr_Print();
        exit(-1);
    }
    // 将 Python 字符串转换为 C 字符串
    auto label = PyUnicode_AsUTF8(result);
    if (label == nullptr) {
        PyErr_Print();
        std::cout << __FILE__ << " : " << __LINE__ << std::endl;
        exit(-1);
    }
    // Py_DECREF(py_object(result));
    // Py_DECREF(py_function(prediction));
    // Py_DECREF(py_object(pBitString));
    // Py_DECREF(py_object(pArgs));
    return label;
}

void Python::InitPythonInterpreter() {
    Py_Initialize();
}

void Python::FreePythonInterpreter() {
    Py_Finalize();
}

