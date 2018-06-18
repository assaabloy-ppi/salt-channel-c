cmake_minimum_required(VERSION 2.8)

project(salt-channel-c)
enable_language(C)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
find_package(Sanitizers)


option(USE_SODIUM "Use Libsodium as crypto native" ON)

if(USE_SODIUM)
	include_directories ("${PROJECT_SOURCE_DIR}/src")
	add_library(sodium_wrapper src/external/libsodium/libsodium_wrapper.c)
	target_link_libraries(sodium_wrapper sodium)
	add_sanitizers(sodium_wrapper)
	set(EXTRA_LIBS ${EXTRA_LIBS} sodium_wrapper)
	add_definitions(-DUSE_SODIUM=1)
else(USE_SODIUM)
	include_directories ("${PROJECT_SOURCE_DIR}/src/external/tweetnacl_modified")
	include_directories ("${PROJECT_SOURCE_DIR}/src")
	set(EXTRA_LIBS ${EXTRA_LIBS} tweetnacl_modified)
	set_source_files_properties(src/external/tweetnacl_modified/tweetnacl_modified.c PROPERTIES COMPILE_FLAGS -Wno-sign-compare)
	add_library(tweetnacl_modified src/external/tweetnacl_modified/tweetnacl_modified.c examples/randombytes_linux.c src/external/tweetnacl_modified/tweetnacl_modified_wrapper.c)
	add_sanitizers(tweetnacl_modified)
endif(USE_SODIUM)

set(CMAKE_C_FLAGS_DEBUG "-fprofile-arcs -ftest-coverage -std=c99 ${CMAKE_CXX_FLAGS_DEBUG}")
add_definitions(-O0 -g -ggdb -DSALT_DEBUG=1 -Wall -Werror -Wpedantic -Wshadow -std=c99)

add_subdirectory(src)
add_subdirectory(examples)

option(BUILD_TESTS "Build tests" ON)

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif(BUILD_TESTS)

