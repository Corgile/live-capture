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
//#pragma comment(lib,"libpython3.8.so")

using PythonObject = PyObject *;

class Python {

public:
    Python();
    ~Python();

    std::string predict(const std::string &bit_string);
//    Python& operator=(const Python* other);

private:
    static void InitPythonInterpreter();
    static void FreePythonInterpreter();

    PythonObject _init_required_module();

    // TODO
//    PythonObject* _call_python_function(char *func_name, PythonObject *pArgs, const char* type);

    std::string _call_perform_predict(const std::string &bit_string);

    PythonObject m_Model;
    PythonObject m_Functions;
    PythonObject m_RequiredModules;

};


#endif //LIVE_CAPTURE_CALL_PYTHON_HPP
