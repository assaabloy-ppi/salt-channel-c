cmake_minimum_required(VERSION 3.5)
project(salt-taste C)
enable_testing()

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
MESSAGE( STATUS "Using HAL: " ${HAL} )

# options
option(HAL_TEST_TIMER "When testing HAL layer, also test elapsed timer" OFF)
option(HAL_TEST_RNG "When testing HAL layer, also test random generator" OFF)
option(HAL_TEST_IMPL "When testing HAL layer, also test HAL-implemented custom tests" ON)

# dependancy: HAL library
set(HAL_DIR ${PROJECT_SOURCE_DIR}/src/hal/${HAL})
add_subdirectory(${HAL_DIR})

# dependancy: crypro abstraction layer
add_subdirectory(../../src/crypto crypto)  # second arg is name of binary subdirectory

# [TODO] fix next to add_subdirectory(.... salt)
add_library(salt ../../src/salt.c ../../src/salti_util.c ../../src/salti_handshake.c)
target_link_libraries(salt crypto)

add_executable(salt_taste src/salt_taste.c src/salt_taste_event.c)
hal_update_exe_target(salt_taste)  # HAL macro - add custom postprocessing, etc

target_link_libraries(salt_taste salt)
target_compile_definitions(salt_taste PRIVATE HAL_TEST_TIMER=${HAL_TEST_TIMER}
											  HAL_TEST_RNG=${HAL_TEST_RNG})
target_include_directories(salt_taste PRIVATE src ../../src)

set_target_properties(salt_taste PROPERTIES
	C_STANDARD_REQUIRED ON
	C_STANDARD 99
	C_EXTENSIONS NO
)
target_compile_options(salt_taste PRIVATE -O0 -g -Wall -Wpedantic -pedantic -Wno-unused)

