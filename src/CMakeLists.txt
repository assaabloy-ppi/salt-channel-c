project(salt-channel-c)

# Salt channel implementation
add_library(salt salt.c salti_util.c salti_handshake.c)
target_link_libraries(salt ${EXTRA_LIBS})