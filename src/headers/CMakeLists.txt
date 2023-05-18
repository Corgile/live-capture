## src/headers/CMakeLists.txt
#
## set(SRC_FILES xxx.cpp yyy.cpp)
#
#file(GLOB_RECURSE SRC_FILES
#        ${CMAKE_CURRENT_SOURCE_DIR}/ethernet_header.cpp
#        ${CMAKE_CURRENT_SOURCE_DIR}/icmp_header.cpp
#        ${CMAKE_CURRENT_SOURCE_DIR}/ipv4_header.cpp
#        ${CMAKE_CURRENT_SOURCE_DIR}/ipv6_header.cpp
#        ${CMAKE_CURRENT_SOURCE_DIR}/packet_header.cpp
#        ${CMAKE_CURRENT_SOURCE_DIR}/payload.cpp
#        ${CMAKE_CURRENT_SOURCE_DIR}/superpacket.cpp
#        ${CMAKE_CURRENT_SOURCE_DIR}/tcp_header.cpp
#        ${CMAKE_CURRENT_SOURCE_DIR}/udp_header.cpp
#        )
#
#add_library(headers SHARED ${SRC_FILES} ${HDR_FILES})
