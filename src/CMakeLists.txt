project(salt-channel-c)

add_subdirectory(crypto)

# Salt channel implementation
add_library(salt salt.c salti_util.c salti_handshake.c)
target_link_libraries(salt crypto ${EXTRA_LIBS})