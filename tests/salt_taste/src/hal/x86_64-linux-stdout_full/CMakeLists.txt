cmake_minimum_required(VERSION 3.5)
project(salt-taste-hal C)

add_library(hal salt_taste_hal.c)
target_include_directories(hal PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
									   ${CMAKE_CURRENT_SOURCE_DIR}/../..   # for 'salt_taste_hal.h'
)

# INTERFACE lib is preferred over above since it allows to promote own
# target_include_directories to parent target(-s)
add_library(hal_iface INTERFACE)
target_link_libraries(hal_iface INTERFACE hal)
target_include_directories(hal_iface INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})