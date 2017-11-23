cmake_minimum_required(VERSION 2.8)

project(salt-channel-c)
enable_testing()
enable_language(C)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
find_package(Sanitizers)

#set(CMAKE_C_FLAGS_DEBUG " -O0 -g -ggdb -DSALT_DEBUG=1 -Wall -Werror -Wpedantic -fprofile-arcs -ftest-coverage -std=c99 ${CMAKE_CXX_FLAGS_DEBUG}")
#add_definitions(-Wall -Wextra -Werror -fno-stack-protector -Wpedantic -std=c99 -g -ggdb -DSALT_DEBUG=1)
add_definitions(-O0 -g -ggdb -DSALT_DEBUG=1 -Wall -Werror -Wpedantic  -std=c99)

add_subdirectory(src)
add_subdirectory(examples)
add_subdirectory(tests)
