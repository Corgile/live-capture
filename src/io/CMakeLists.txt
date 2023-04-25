# src/io/CMakeLists.txt

# set(SRC_FILES xxx.cpp yyy.cpp)

file(GLOB_RECURSE SRC_FILES ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)

add_library(io STATIC ${SRC_FILES} ${HDR_FILES})
