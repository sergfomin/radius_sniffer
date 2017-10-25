project(radius_sniffer)
cmake_minimum_required(VERSION 2.8)

set(SERVER_NAME "thrift_service_server")

set(Boost_USE_STATIC_LIBS ON)

include_directories(SYSTEM ${Boost_INCLUDE_DIR}
    /usr/include/pcap
    /usr/include/thrift
    /usr/include/libxml2
)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DHAVE_INTTYPES_H")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DHAVE_NETINET_IN_H")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --std=c++14")

set(GENERIC_SOURCES
    ThriftService.cpp
    radius_constants.cpp
    radius_types.cpp
)

set(GENERIC_HEADERS
    ThriftService.h
    radius_constants.h
    radius_types.h
)

set(CLIENT_SOURCES
    main.cpp
    sniffer.cpp
    parser.cpp
    process.cpp
    logger.cpp
    config.cpp
    xmlutils.cpp
)

set(CLIENT_HEADERS
    sniffer.h
    packet.h
    queue.h
    process.h
    parser.h
    logger.h
    config.h
    xmlutils.h
)

set(SERVER_SOURCES
    ThriftService_server.cpp
)

add_executable(${PROJECT_NAME} ${CLIENT_SOURCES} ${GENERIC_SOURCES} ${CLIENT_HEADERS} ${GENERIC_HEADERS})
target_link_libraries (${PROJECT_NAME} pcap pthread thrift xml2 ${Boost_LIBRARIES})

add_executable(${SERVER_NAME} ${SERVER_SOURCES} ${GENERIC_SOURCES} ${GENERIC_HEADERS})
target_link_libraries (${SERVER_NAME} thrift ${Boost_LIBRARIES})
