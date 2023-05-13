//
// Created by gzhuadmin on 4/27/23.
//

#ifndef LIVE_CAPTURE_CALL_PYTHON_HPP
#define LIVE_CAPTURE_CALL_PYTHON_HPP

#include <Python.h> // Python头文件
#include <iostream>

#define py_function(x)      x
#define py_module_dict(x)   x
#define py_object(x)        x

using PythonObject = PyObject *;

class Python {

public:
    Python(std::string , std::string , std::string );

    ~Python();

    std::string predict(const std::string &bit_string);

    void *operator new(size_t size);

    void operator delete(void* p);

private:
    static void InitPythonInterpreter();

    static void FreePythonInterpreter();

    void _init_required_module();

    std::string _call_perform_predict(const std::string &bit_string);

    PythonObject m_Model;
    PythonObject m_Functions;
    PythonObject m_RequiredModules{};

    std::string m_Model_path;
    std::string m_Py_module_path;
    std::string m_Py_module_name;

};


#endif //LIVE_CAPTURE_CALL_PYTHON_HPP
