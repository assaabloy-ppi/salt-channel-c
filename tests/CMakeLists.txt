project(salt-channel-c)

include(ExternalProject)

#INCLUDE(FindCMocka.cmake)
ExternalProject_Add (
        cmocka
        GIT_REPOSITORY "git://git.cryptomilk.org/projects/cmocka.git"
        GIT_TAG "master"
        UPDATE_COMMAND ""
        INSTALL_COMMAND ""
        DOWNLOAD_DIR ""
        CMAKE_ARGS "-DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}/external/cmocka"
        INSTALL_DIR ${CMAKE_BINARY_DIR}/external/cmocka
        INSTALL_COMMAND
          "cmake"
          --build .
          --target install
        )
        
add_library(cmocka_lib SHARED IMPORTED)       
set_target_properties( cmocka_lib PROPERTIES IMPORTED_LOCATION "${CMAKE_BINARY_DIR}/external/cmocka/lib/libcmocka.so" )
add_dependencies( cmocka_lib cmocka )


macro(do_test arg)
	add_definitions(-std=c99 -Wno-unused-parameter)
	add_executable(${arg} ${arg}.c)
	add_dependencies(${arg} ${arg} ${ARGN})
	add_test(${arg} ${arg})
	target_link_libraries(${arg} ${ARGN} cmocka_lib ${EXTRA_LIBS})
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
