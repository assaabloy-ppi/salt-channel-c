cmake_minimum_required(VERSION 3.5)
project(salt-taste C)
enable_testing()

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

MESSAGE( STATUS "Using HAL: " ${HAL} )
set(HAL_DIR ${PROJECT_SOURCE_DIR}/src/hal/${HAL})

# options
option(HAL_TEST_TIMER "When testing HAL layer, also test elapsed timer" ON)
option(HAL_TEST_RNG "When testing HAL layer, also test random generator" ON)

# dependancy: crypro abstraction layer
add_subdirectory(../../src/crypto crypto)

file(GLOB SRC ${PROJECT_SOURCE_DIR}/src/*.c
	          ${HAL_DIR}/*.c)

add_executable(salt_taste ${SRC})
target_link_libraries(crypto)
target_compile_definitions(salt_taste PRIVATE HAL_TEST_TIMER=${HAL_TEST_TIMER}
											  HAL_TEST_RNG=${HAL_TEST_RNG})
target_include_directories(salt_taste PRIVATE src ${HAL_DIR})
set_target_properties(salt_taste PROPERTIES
	C_STANDARD_REQUIRED ON
	C_STANDARD 99
	C_EXTENSIONS NO
)
target_compile_options(salt_taste PRIVATE -O0 -g -Wall -Wpedantic -pedantic -Wno-unused)

#	add_dependencies(${arg} ${arg} ${ARGN})
#	add_test(${arg} ${arg})
#	target_link_libraries(${arg} ${ARGN} cmocka_lib ${EXTRA_LIBS})
