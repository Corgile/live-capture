cmake_minimum_required(VERSION 3.24)
project(live-capture)

set(CMAKE_CXX_STANDARD 17)
set(binary_target live-capture)

find_package(Python3 COMPONENTS Interpreter Development REQUIRED)

message("Python3 可执行文件: ${Python3_EXECUTABLE}")
message("Python3 头文件路径: ${Python3_INCLUDE_DIRS}")
message("Python3 动态库路径: ${Python3_LIBRARY_DIRS}")
message("Python3 现有动态库: ${Python3_LIBRARIES}")
message("Python3 详细的版本: ${Python3_VERSION}")

# include路径
include_directories(${Python3_INCLUDE_DIRS})

# lib路径
link_directories(${Python3_LIBRARY_DIRS})



set(IF_DEBUG "" CACHE STRING "是否打印调试信息")
set(IF_INFO "" CACHE STRING "是否打印一般信息")
set(IF_WARN "" CACHE STRING "是否打印警告信息")
# 使用变量来设置宏定义
add_compile_definitions(${IF_DEBUG} ${IF_WARN} ${IF_INFO})


# all public header for all source files
include_directories(
        /usr/include/
        /usr/local/lib/
        /usr/local/include/
        ${PROJECT_SOURCE_DIR}/include/
        ${PROJECT_SOURCE_DIR}/include/io/
        ${PROJECT_SOURCE_DIR}/include/packet/
        ${PROJECT_SOURCE_DIR}/include/callback/
)

add_subdirectory(src)