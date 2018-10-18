project(salt-channel-c)
find_path(CMOCKA_INCLUDE_DIR
    NAMES cmocka.h
    PATHS ${CMOCKA_ROOT_DIR}/include)

find_library(CMOCKA_LIBRARY
    NAMES cmocka
    PATHS ${CMOCKA_ROOT_DIR}/lib)

if(CMOCKA_LIBRARY)
    set(CMOCKA_LIBRARIES
        ${CMOCKA_LIBRARIES}
        ${CMOCKA_LIBRARY})
endif(CMOCKA_LIBRARY)

include_directories("${CMOCKA_INCLUDE_DIR}")

macro(do_test arg)
    add_definitions(-std=c99 -Wno-unused-parameter)
    add_executable(${arg} ${arg}.c)
    add_sanitizers(${arg})
    add_dependencies(${arg} ${arg} ${ARGN})
    add_test(${arg} ${arg})
    target_link_libraries(${arg} ${ARGN} ${CMOCKA_LIBRARIES} ${EXTRA_LIBS})
endmacro(do_test)

include_directories (../src)
include_directories (cfifo)

add_library(cfifo cfifo/cfifo.c)
add_sanitizers(cfifo)
add_library(test_data test_data.c)
add_sanitizers(test_data)
add_library(salt_mock salt_mock.c)
add_sanitizers(salt_mock)

# Test runners
do_test(host_handshake      salt test_data salt_mock cfifo)
do_test(host_a1a2           salt test_data salt_mock cfifo)
do_test(client_handshake    salt test_data salt_mock cfifo)
do_test(salt_init           salt test_data salt_mock cfifo)
do_test(hostclient_session  salt test_data salt_mock cfifo)
do_test(session             salt test_data salt_mock cfifo)
do_test(host_time           salt test_data salt_mock cfifo)
do_test(a1a2                salt test_data salt_mock cfifo)
do_test(multimessage        salt test_data salt_mock cfifo)
do_test(salt_read           salt cfifo)
do_test(salt_write          salt cfifo)
do_test(time_check          salt)
do_test(sign_test           salt)
do_test(crypto_api_test     salt salt_test)
