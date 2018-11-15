cmake_minimum_required(VERSION 2.8)

project(salt-channel-c)
enable_language(C)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
find_package(Sanitizers)

find_path(LIBSODIUM_INCLUDE_DIR
	NAMES sodium.h
	PATHS ${LIBSODIUM_ROOT_DIR}/include)

find_library(LIBSODIUM_LIBRARY
    NAMES sodium
    PATHS ${LIBSODIUM_ROOT_DIR}/lib)

if(LIBSODIUM_LIBRARY)
	message("Using libsodium as crypto native.")
	include_directories("${PROJECT_SOURCE_DIR}/src")
	include_directories(${LIBSODIUM_INCLUDE_DIR})
	add_library(sodium_wrapper src/external/libsodium/libsodium_wrapper.c)
	add_sanitizers(sodium_wrapper)
	target_link_libraries(sodium_wrapper ${LIBSODIUM_LIBRARY})
	set(EXTRA_LIBS ${EXTRA_LIBS} sodium_wrapper)
else(LIBSODIUM_LIBRARY)
	message("Using TweetNaCl as crypto native, this is not recommended.")
	include_directories ("${PROJECT_SOURCE_DIR}/src/external/tweetnacl_modified")
	include_directories ("${PROJECT_SOURCE_DIR}/src")
	set(EXTRA_LIBS ${EXTRA_LIBS} tweetnacl_modified)
	set_source_files_properties(src/external/tweetnacl_modified/tweetnacl_modified.c PROPERTIES COMPILE_FLAGS -Wno-sign-compare)
	add_library(tweetnacl_modified src/external/tweetnacl_modified/tweetnacl_modified.c examples/randombytes_linux.c src/external/tweetnacl_modified/tweetnacl_modified_wrapper.c)
endif(LIBSODIUM_LIBRARY)

set(CMAKE_C_FLAGS_DEBUG "-fprofile-arcs -ftest-coverage -std=c99 ${CMAKE_CXX_FLAGS_DEBUG}")
add_definitions(-O0 -g -ggdb -DSALT_DEBUG=1 -Wall -Werror -Wpedantic -Wshadow -std=c99)

add_subdirectory(src)
add_subdirectory(examples)
add_subdirectory(benchmark)

option(BUILD_TESTS "Build tests" ON)

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif(BUILD_TESTS)

