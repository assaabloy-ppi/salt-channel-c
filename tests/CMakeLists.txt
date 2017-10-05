project(salt-channel-c)


INCLUDE(CodeCoverage.cmake)
INCLUDE(FindCMocka.cmake)

macro(do_test arg)
	add_executable(${arg} ${arg}.c)
	add_dependencies(${arg} ${arg} salt ${ARGN})
	add_test(${arg} ${arg})
	target_link_libraries(${arg} salt ${ARGN} ${CMOCKA_LIBRARIES} ${EXTRA_LIBS})
endmacro(do_test)

include_directories (../src)
include_directories (cfifo)

add_library(cfifo cfifo/cfifo.c)
add_library(test_data test_data.c)
add_library(io_mock salt_mock.c)

# Test runners
do_test(host_handshake 		test_data io_mock cfifo)
do_test(client_handshake 	test_data io_mock cfifo)
do_test(salt_init           test_data io_mock cfifo)
do_test(hostclient_session 	cfifo)
do_test(host_time  cfifo)
do_test(a1a2handshake 		cfifo)
do_test(multimessage 		cfifo)
do_test(salt_read)
do_test(salt_write)

SETUP_TARGETS_FOR_COVERAGE(host_handshake_coverage host_handshake client_handshake a1a2handshake)