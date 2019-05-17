cmake_minimum_required(VERSION 2.8)

project(salt-channel-c)
enable_language(C)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
find_package(Sanitizers)
include(cmake/coverage.cmake)


OPTION(BUILD_EXAMPLES "Build examples" OFF)
OPTION(BUILD_BENCHMARK "Build benchmark" OFF)
option(BUILD_TESTS "Build tests" OFF)

if(UNIX AND (BUILD_EXAMPLES OR BUILD_BENCHMARK OR BUILD_TESTS))

    # Cryptographic library used for examples, tests and benchmark
    find_path(LIBSODIUM_INCLUDE_DIR
        NAMES sodium.h
        PATHS ${LIBSODIUM_ROOT_DIR}/include)

    find_library(LIBSODIUM_LIBRARY
        NAMES sodium
        PATHS ${LIBSODIUM_ROOT_DIR}/lib)

    if(LIBSODIUM_LIBRARY)
        message("Using libsodium as crypto native.")
        include_directories(${LIBSODIUM_INCLUDE_DIR})
        add_library(crypto_wrapper src/external/libsodium/libsodium_wrapper.c)
        add_sanitizers(crypto_wrapper)
        target_link_libraries(crypto_wrapper ${LIBSODIUM_LIBRARY})
        target_include_directories(crypto_wrapper PRIVATE src)
    else(LIBSODIUM_LIBRARY)
        message("Using TweetNaCl as crypto native, this is not recommended.")
        set_source_files_properties(src/external/tweetnacl_modified/tweetnacl_modified.c
            PROPERTIES
            COMPILE_FLAGS
            -Wno-sign-compare)
        add_library(crypto_wrapper
            src/external/tweetnacl_modified/tweetnacl_modified.c 
            examples/randombytes_linux.c src/external/tweetnacl_modified/tweetnacl_modified_wrapper.c)
        target_include_directories(crypto_wrapper PRIVATE src)
    endif(LIBSODIUM_LIBRARY)
endif(UNIX AND (BUILD_EXAMPLES OR BUILD_BENCHMARK OR BUILD_TESTS))

add_subdirectory(src)

if(UNIX)
    if(BUILD_EXAMPLES)
        add_subdirectory(examples)
    endif(BUILD_EXAMPLES)

    if(BUILD_BENCHMARK)
        add_subdirectory(benchmark)
    endif(BUILD_BENCHMARK)

    if(BUILD_TESTS)
        enable_testing()
        add_subdirectory(tests)
        if(UNIX AND NOT APPLE)
            add_test(java_echo COMMAND
                sh ${CMAKE_CURRENT_SOURCE_DIR}/test_echo_with_java.sh
                ${CMAKE_CURRENT_BINARY_DIR}/examples/host_echo
                ${CMAKE_CURRENT_SOURCE_DIR}/salt-channel-2.5.jar)
        endif(UNIX AND NOT APPLE)
    endif(BUILD_TESTS)
endif(UNIX)