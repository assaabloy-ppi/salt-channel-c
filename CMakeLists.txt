cmake_minimum_required(VERSION 2.8)

project(salt-channel-c)
enable_language(C)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
find_package(Sanitizers)

add_definitions(-O0 -g -ggdb -DSALT_DEBUG=1 -Wall -Werror -Wpedantic  -std=c99)

add_subdirectory(src)
add_subdirectory(examples)

option(BUILD_TESTS "Build tests" ON)

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif(BUILD_TESTS)

