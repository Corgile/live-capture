//
// Created by linyikai on 4/27/23.
//

#ifndef LIVE_CAPTURE_CALL_PYTHON_HPP
#define LIVE_CAPTURE_CALL_PYTHON_HPP

#include <Python.h> // Python头文件
#include <iostream>
#pragma comment(lib,"libpython3.8.so")


class CallPython {

public:
    static void Method(const char* bit_string, std::string label);
private:
    static PyObject *ImportPythonModule(const char *pyDir, const char *name);


    static PyObject * CallPredict(PyObject *pymodule, const std::string& in_arg, std::string& ref_out);
};


#endif //LIVE_CAPTURE_CALL_PYTHON_HPP
