cmake_minimum_required(VERSION 2.8)
project(pot-c-fuzz)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/../cmake" ${CMAKE_MODULE_PATH})
find_package(Sanitizers)

include_directories(../src)
include_directories(../tests)
include_directories(../src/external/tweetnacl_modified)
include_directories(.)

option(USE_SANITIZERS "Use Adress sanitizers" OFF)

set(SOURCES
    ../src/salt.c
    ../src/salti_handshake.c
    ../src/salti_util.c
    crypt_mock.c
    test_data_mock.c
)

add_library(salt ${SOURCES})

if(USE_SANITIZERS)
    add_sanitizers(salt)
else(USE_SANITIZERS)
endif(USE_SANITIZERS)


macro(add_fuzz arg)
    add_executable(${arg} ${arg}.c)
    if(USE_SANITIZERS)
        add_sanitizers(${arg})
    else(USE_SANITIZERS)
    endif(USE_SANITIZERS)
    target_link_libraries(${arg} salt)

endmacro(add_fuzz)

add_fuzz(fuzz_client)
add_fuzz(fuzz_host)

