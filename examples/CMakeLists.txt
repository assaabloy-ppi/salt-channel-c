project(salt-channel-c)


#add_definitions(-Wall -Wextra -Werror -fno-stack-protector -Wpedantic -g -ggdb -DSALT_DEBUG=1)

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  SET(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -lpthread")
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
  SET(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -pthread")
endif()

include_directories(../src ./)

add_executable(host_echo host_echo.c salt_io.c randombytes_linux.c)
add_sanitizers(host_echo)
target_link_libraries(host_echo salt)

add_executable(client_echo client_echo.c salt_io.c randombytes_linux.c)
add_sanitizers(client_echo)
target_link_libraries(client_echo salt)

add_executable(client client.c salt_io.c randombytes_linux.c binson_light.c)
add_sanitizers(client)
target_link_libraries(client salt)