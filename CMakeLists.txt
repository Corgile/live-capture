cmake_minimum_required(VERSION 3.24)
project(live-capture VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 14)
set(binary_target live-capture)


set(IF_DEBUG "" CACHE STRING "是否打印调试信息")
set(IF_INFO "" CACHE STRING "是否打印一般信息")
set(IF_WARN "" CACHE STRING "是否打印警告信息")
set(IF_TEST "" CACHE STRING "是否打印警告信息")

# 使用变量来设置宏定义
add_compile_definitions(${IF_DEBUG})
add_compile_definitions(${IF_WARN})
add_compile_definitions(${IF_INFO})
add_compile_definitions(${IF_TEST})


# all public header for all source files
include_directories(
        /usr/include/
        /usr/local/lib/
        /usr/local/include/
        ${TORCH_INCLUDE_DIRS}
        ${PROJECT_SOURCE_DIR}/include/
        ${PROJECT_SOURCE_DIR}/include/vendor/spdlog/include/
)


aux_source_directory(src ALL_SOURCES)
aux_source_directory(src/io ALL_SOURCES)
aux_source_directory(src/packet ALL_SOURCES)
aux_source_directory(src/callback ALL_SOURCES)
aux_source_directory(src/packet/header ALL_SOURCES)

foreach (file ${ALL_SOURCES})
    message(STATUS "adding source file ${file} to ${binary_target}")
endforeach ()

add_executable(${binary_target} ${ALL_SOURCES})


# Libtorch
find_package(Torch REQUIRED)
message(STATUS "Torch Libraries: ${TORCH_LIBRARIES}")
message(STATUS "Torch Includes: ${TORCH_INCLUDE_DIRS}")


#target_link_libraries(${binary_target} PRIVATE io)
#target_link_libraries(${binary_target} PRIVATE packet)
target_link_libraries(${binary_target} PRIVATE librdkafka++.so)
target_link_libraries(${binary_target} PRIVATE libpcap.so.1.10.4)
target_link_libraries(${binary_target} PRIVATE ${TORCH_LIBRARIES})