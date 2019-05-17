project(salt-channel-c)

include_directories (../src)

set(SOURCES
    client_handshake_benchmark.c
    crypto_benchmark.c
    main.c
    time_stamp.c
    time_stamp_linux.c
    host_handshake_benchmark.c)

add_executable(benchmark_test ${SOURCES})
add_sanitizers(benchmark_test)
target_link_libraries(benchmark_test salt crypto_wrapper)
