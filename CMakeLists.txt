cmake_minimum_required(VERSION 3.24)
project(live-capture VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 14)
set(binary_target live-capture)


list(APPEND CMAKE_PREFIX_PATH /home/gzhuadmin/workspace/libtorch)

# all public header for all source files
include_directories(
        /usr/include/
        /usr/local/lib/
        /usr/local/include/
        ${TORCH_INCLUDE_DIRS}
        ${PROJECT_SOURCE_DIR}/include/
        ${PROJECT_SOURCE_DIR}/include/vendor/spdlog/include/
)


aux_source_directory(src                ALL_SOURCES)
aux_source_directory(src/io             ALL_SOURCES)
aux_source_directory(src/packet         ALL_SOURCES)
aux_source_directory(src/callback       ALL_SOURCES)
aux_source_directory(src/packet/header  ALL_SOURCES)

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