cmake_minimum_required(VERSION 2.8)

project(salt-channel-c)
enable_testing()
enable_language(C)

option(USE_SODIUM "Use TweetNaCl as crypto native" OFF)

if(USE_SODIUM)
	#message("Using libsodium as crypto native, not configured")
	include_directories ("${PROJECT_SOURCE_DIR}/src/external/libsodium")
	include_directories ("${PROJECT_SOURCE_DIR}/src/external/libsodium/include")
	set(EXTRA_LIBS ${EXTRA_LIBS} libsodium.a)
	return()
else(USE_SODIUM)
	include_directories ("${PROJECT_SOURCE_DIR}/src/external/tweetnacl")
	# TweetNaCl library
	add_library(tweetnacl src/external/tweetnacl/tweetnacl.c)
	#message("Using TweetNaCl as crypto native")
	set(EXTRA_LIBS ${EXTRA_LIBS} tweetnacl)
endif(USE_SODIUM)

set(CMAKE_C_FLAGS_DEBUG " -O0 -g -ggdb -DSALT_DEBUG=1 -Wall -Werror -Wpedantic -fprofile-arcs -ftest-coverage ${CMAKE_CXX_FLAGS_DEBUG}")

add_subdirectory(src)
add_subdirectory(examples)
add_subdirectory(tests)