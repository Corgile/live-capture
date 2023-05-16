//
// Created by gzhuadmin on 4/27/23.
//

#ifndef LIVE_CAPTURE_CALL_PYTHON_HPP
#define LIVE_CAPTURE_CALL_PYTHON_HPP

#include <Python.h> // Python头文件
#include <iostream>
#include "daily_logger.hpp"

#define py_function(x)      x
#define py_module_dict(x)   x
#define py_object(x)        x

using PythonObject = PyObject *;

class Python {

public:
    Python(char *, char *, char *);

    ~Python();

    std::string predict(std::string &bit_string);

    void *operator new(size_t size);

    void operator delete(void *p);

private:
    static void InitPythonInterpreter();

    static void FreePythonInterpreter();

    void _init_required_module();

    std::string _call_perform_predict(std::string &bit_string);

    PythonObject m_Model;
    PythonObject m_RequiredModules{};

    char *m_Model_path;
    char *m_Py_module_path;
    char *m_Py_module_name;
    std::shared_ptr<DailyLogger> logger = DailyLogger::getInstance();
    // ======
    PythonObject m_prediction;
    PythonObject m_load_model;
    PythonObject pArgs;
    PythonObject result;
    PythonObject pArg_model_path;

};


#endif //LIVE_CAPTURE_CALL_PYTHON_HPP
