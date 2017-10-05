project(salt-channel-c)

add_definitions(-Wall -Wextra -Werror -fno-stack-protector -Wpedantic -g -ggdb -DSALT_DEBUG=1)
SET(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -pthread")

include_directories(../src ./)

add_executable(host_echo host_echo.c salt_io.c randombytes_linux.c)
target_link_libraries(host_echo salt)

add_executable(client_echo client_echo.c salt_io.c randombytes_linux.c)
target_link_libraries(client_echo salt)