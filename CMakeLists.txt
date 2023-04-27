cmake_minimum_required(VERSION 3.24)
project(live-capture)

set(CMAKE_CXX_STANDARD 17)
set(binary_target live-capture)

find_package(Python3 COMPONENTS Interpreter Development REQUIRED)

message("Python3_EXECUTABLE: ${Python3_EXECUTABLE}")
message("Python3_INCLUDE_DIRS: ${Python3_INCLUDE_DIRS}")
message("Python3_LIBRARY_DIRS: ${Python3_LIBRARY_DIRS}")
message("Python3_LIBRARIES: ${Python3_LIBRARIES}")
message("Python3_VERSION: ${Python3_VERSION}")

# include路径
include_directories(${Python3_INCLUDE_DIRS})

# lib路径
link_directories(${Python3_LIBRARY_DIRS})






# macros
#add_compile_definitions(i_want_to_perform_live_traffic_capture)

# all public header for all source files
include_directories(
        /usr/include/
        /usr/local/lib/
        /usr/local/include/
        ${PROJECT_SOURCE_DIR}/include/
        ${PROJECT_SOURCE_DIR}/include/io/
        ${PROJECT_SOURCE_DIR}/include/packet/
)

add_subdirectory(src)
