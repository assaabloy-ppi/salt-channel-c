cmake_minimum_required(VERSION 2.8)

project(salt-channel-c)
enable_testing()
enable_language(C)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
find_package(Sanitizers)


option(USE_SODIUM "Use TweetNaCl as crypto native" OFF)

if(USE_SODIUM)
	include_directories ("${PROJECT_SOURCE_DIR}/src/external/libsodium")
	include_directories ("${PROJECT_SOURCE_DIR}/src/external/libsodium/include")
	set(EXTRA_LIBS ${EXTRA_LIBS} libsodium.a)
	return()
else(USE_SODIUM)
	include_directories ("${PROJECT_SOURCE_DIR}/src/external/tweetnacl")
    set_source_files_properties(src/external/tweetnacl/tweetnacl.c PROPERTIES COMPILE_FLAGS -Wno-sign-compare)
	add_library(tweetnacl src/external/tweetnacl/tweetnacl.c)
	add_sanitizers(tweetnacl)
	set(EXTRA_LIBS ${EXTRA_LIBS} tweetnacl)
endif(USE_SODIUM)

#set(CMAKE_C_FLAGS_DEBUG " -O0 -g -ggdb -DSALT_DEBUG=1 -Wall -Werror -Wpedantic -fprofile-arcs -ftest-coverage -std=c99 ${CMAKE_CXX_FLAGS_DEBUG}")
#add_definitions(-Wall -Wextra -Werror -fno-stack-protector -Wpedantic -std=c99 -g -ggdb -DSALT_DEBUG=1)
add_definitions(-O0 -g -ggdb -DSALT_DEBUG=1 -Wall -Werror -Wpedantic  -std=c99)

add_subdirectory(src)
add_subdirectory(examples)
add_subdirectory(tests)
