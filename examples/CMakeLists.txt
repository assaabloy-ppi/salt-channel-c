project(salt-channel-c)


include_directories(../src ./)

add_executable(host_echo host_echo.c salt_io.c)
add_sanitizers(host_echo)
target_link_libraries(host_echo salt crypto_wrapper pthread)

add_executable(client_echo client_echo.c salt_io.c)
add_sanitizers(client_echo)
target_link_libraries(client_echo salt crypto_wrapper pthread)