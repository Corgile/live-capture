cmake_minimum_required(VERSION 3.24)
project(live-capture)

set(CMAKE_CXX_STANDARD 17)
set(binary_target live-capture)

# macros
#add_compile_definitions(i_want_to_perform_live_traffic_capture)

# all public header for all source files
include_directories(
        /usr/include/
        /usr/local/lib/
        /usr/local/include/
        /Users/alejandra/.pyenv/versions/3.7.16/include/
        ${PROJECT_SOURCE_DIR}/include/
        ${PROJECT_SOURCE_DIR}/include/io/
        ${PROJECT_SOURCE_DIR}/include/packet/
)

add_subdirectory(src)
