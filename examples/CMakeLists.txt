project(salt-channel-c)

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  SET(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -lpthread")
else ()
  SET(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -pthread")
endif()

include_directories(../src ./)

set(HOST_ECHO_SRC host_echo.c salt_io.c)
set(CLIENT_ECHO_SRC client_echo.c salt_io.c)

if(USE_SODIUM) 
else (USE_SODIUM)
  set(HOST_ECHO_SRC ${HOST_ECHO_SRC} randombytes_linux.c)
  set(CLIENT_ECHO_SRC ${CLIENT_ECHO_SRC} randombytes_linux.c)
endif(USE_SODIUM)

add_executable(host_echo ${HOST_ECHO_SRC})
add_sanitizers(host_echo)
target_link_libraries(host_echo salt ${EXTRA_LIBS})

add_executable(client_echo ${CLIENT_ECHO_SRC})
add_sanitizers(client_echo)
target_link_libraries(client_echo salt ${EXTRA_LIBS})

