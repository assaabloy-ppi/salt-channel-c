project(salt-channel-c)

INCLUDE(FindCMocka.cmake)

macro(do_test arg)
	add_executable(${arg} ${arg}.c)
	add_dependencies(${arg} ${arg} ${ARGN})
	add_test(${arg} ${arg})
	target_link_libraries(${arg} ${ARGN} ${CMOCKA_LIBRARIES} ${EXTRA_LIBS})
endmacro(do_test)

include_directories (../src)
include_directories (cfifo)

add_library(cfifo cfifo/cfifo.c)
add_library(test_data test_data.c)
add_library(salt_mock salt_mock.c)

# Test runners
do_test(host_handshake 		salt test_data salt_mock cfifo)
do_test(host_a1a2           salt test_data salt_mock cfifo)
do_test(client_handshake 	salt test_data salt_mock cfifo)
do_test(salt_init           salt test_data salt_mock cfifo)
do_test(hostclient_session  salt test_data salt_mock cfifo)
do_test(session             salt test_data salt_mock cfifo)
do_test(host_time           salt test_data salt_mock cfifo)
do_test(a1a2 		        salt test_data salt_mock cfifo)
do_test(multimessage 		salt test_data salt_mock cfifo)
do_test(salt_read           salt cfifo)
do_test(salt_write          salt cfifo)
