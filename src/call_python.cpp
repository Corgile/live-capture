//
// Created by linyikai on 4/27/23.
//

#include "call_python.hpp"

void CallPython::Method(const char *bit_string, std::string label) {
    PyRun_SimpleString("print('----------hello Python form C/C++')");
    Py_Initialize();
    PyObject * python_module = CallPython::ImportPythonModule("/home/linyikai/live-capture/target", "damn");
    CallPython::CallPredict(python_module, bit_string, label);
    Py_Finalize();
}

PyObject *CallPython::ImportPythonModule(const char *pyDir, const char *name) {
    //引入当前路径,否则下面模块不能正常导入
    char tempPath[256] = {};
    sprintf(tempPath, "sys.path.append('%s')", pyDir);
    PyRun_SimpleString("import sys");
    //PyRun_SimpleString("sys.path.append('./')");
    PyRun_SimpleString(tempPath);
    PyRun_SimpleString("print('curr sys.path = ', sys.path)");

    //引入模块, hello.py
    PyObject *module = PyImport_ImportModule(name);
    if (module == nullptr) {
        PyErr_Print(); // print stack
        std::cout << "PyImport_ImportModule 'damn.py' not found" << std::endl;
        return nullptr;
    }

    return module;
}

PyObject *CallPython::CallPredict(PyObject *pymodule, const std::string &in_arg, std::string &ref_out) {
    //获取模块字典属性
    PyObject *pDict = PyModule_GetDict(pymodule);
    if (pDict == nullptr) {
        PyErr_Print();
        std::cout << "PyModule_GetDict error" << std::endl;
        return nullptr;
    }

    //直接获取模块中的函数
    PyObject *pred_func = PyDict_GetItemString(pDict, "perform_predict");
    if (pred_func == nullptr) {
        std::cout << "PyDict_GetItemString 'perform_predict' not found" << std::endl;
        return nullptr;
    }

    PyObject *pArg = Py_BuildValue("(s)", in_arg.c_str());
    //调用函数，并得到python类型的返回值
    PyObject *result = PyObject_CallObject(pred_func, pArg);
    PyArg_Parse(result, "s", &ref_out);
    return result;
}
