# src/CMakeLists.txt
# set(SRC_FILES xxx.cpp yyy.cpp)

add_subdirectory(io)
add_subdirectory(packet)

file(GLOB_RECURSE SRC_FILES ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)

add_executable(${binary_target} ${SRC_FILES})

target_compile_definitions(${binary_target} PRIVATE WITH_BENIGN)
target_link_libraries(${binary_target} io packet libpcap.so.1.10.4 ${Python3_LIBRARIES})