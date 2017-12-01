cmake_minimum_required(VERSION 3.5)
project(salt-taste)
enable_language(C)

MESSAGE( STATUS "Using HAL: " ${HAL} )
set(HAL_DIR ${PROJECT_SOURCE_DIR}/src/hal/${HAL})

file(GLOB SRC ${PROJECT_SOURCE_DIR}/src/*.c
	          ${HAL_DIR}/*.c)

add_executable(salt_taste ${SRC})
target_include_directories(salt_taste PUBLIC src ${HAL_DIR})
target_compile_options(salt_taste PUBLIC -std=c99 -Wno-unused-parameter)


#	add_dependencies(${arg} ${arg} ${ARGN})
#	add_test(${arg} ${arg})
#	target_link_libraries(${arg} ${ARGN} cmocka_lib ${EXTRA_LIBS})
