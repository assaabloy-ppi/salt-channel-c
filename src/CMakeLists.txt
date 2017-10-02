project(salt-channel-c)

# Salt channel implementation
add_library(salt salt_v2.c salt_util.c)
target_link_libraries(salt ${EXTRA_LIBS})