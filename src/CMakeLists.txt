## src/CMakeLists.txt
## set(SRC_FILES xxx.cpp yyy.cpp)
#
#add_subdirectory(io)
#add_subdirectory(headers)
#
#file(GLOB_RECURSE SRC_FILES ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)
#add_executable(${binary_target} ${SRC_FILES})
#
#target_link_libraries(${binary_target} PRIVATE io)
#target_link_libraries(${binary_target} PRIVATE headers)
#target_link_libraries(${binary_target} PRIVATE librdkafka++.so)
#target_link_libraries(${binary_target} PRIVATE libpcap.so.1.10.4)
#target_link_libraries(${binary_target} PRIVATE ${TORCH_LIBRARIES})
#
#
#install(TARGETS ${binary_target} DESTINATION bin)
#install(FILES ${PROJECT_SOURCE_DIR}/README.md DESTINATION bin)
#
#include(InstallRequiredSystemLibraries)
#set(CPACK_PACKAGE_VERSION_MAJOR "${PROJECT_VERSION_MAJOR}")
#set(CPACK_PACKAGE_VERSION_MINOR "${PROJECT_VERSION_MINOR}")
#set(CPACK_PACKAGE_VERSION_PATCH "${PROJECT_VERSION_PATCH}")
#set(CPACK_GENERATOR "ZIP")
#include(CPack)