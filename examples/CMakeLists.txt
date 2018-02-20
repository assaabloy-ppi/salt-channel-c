project(salt-channel-c)

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  SET(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -lpthread")
else ()
  SET(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -pthread")
endif()

include_directories(../src ./)

set(HOST_ECHO_SRC host_echo.c salt_io.c randombytes_linux.c)
set(CLIENT_ECHO_SRC client_echo.c salt_io.c randombytes_linux.c)

add_executable(host_echo ${HOST_ECHO_SRC})
add_sanitizers(host_echo)
target_link_libraries(host_echo crypto salt )

add_executable(client_echo ${CLIENT_ECHO_SRC})
add_sanitizers(client_echo)
target_link_libraries(client_echo crypto salt )

