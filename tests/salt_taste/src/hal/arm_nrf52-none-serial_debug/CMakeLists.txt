cmake_minimum_required(VERSION 3.5)
project(salt-taste-hal C)

nRF5x_setup()
nRF5x_addAppTimer()
nRF5x_addAppFIFO()
nRF5x_addAppUART()
nRF5x_addRNG()
nRF5x_addTimer()
#nRF5x_addRTC()
#nRF5x_addPPI()
#nRF5x_addAppButton()
#nRF5x_addBSP(OFF OFF OFF)

add_library(hal ${SDK_SOURCE_FILES} ${CMAKE_CURRENT_SOURCE_DIR}/salt_taste_hal.c)
target_include_directories(hal PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
									   ${CMAKE_CURRENT_SOURCE_DIR}/../..   # for 'salt_taste_hal.h'
)

# INTERFACE lib is preferred over above since it allows to promote own
# target_include_directories to parent target(-s)
add_library(hal_iface INTERFACE)
target_link_libraries(hal_iface INTERFACE hal)
target_include_directories(hal_iface INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

#########################################################
# hal_update_exe_target defines custom exe target actions
macro(hal_update_exe_target target )
	enable_language(ASM)
	target_sources(${target} PRIVATE ${SDK_SOURCE_FILES})  # add NRF SDK deps
	target_link_libraries(${target} hal_iface) # for HAL-dependant include directories, etc
    set_target_properties(${target} PROPERTIES SUFFIX ".out")
    #set_target_properties(${target} PROPERTIES LINK_FLAGS "-Wl,-Map=${target}.map")

    # additional POST BUILD setps to create the .bin and .hex files
    add_custom_command(TARGET ${target}
            POST_BUILD
            COMMAND arm-none-eabi-size ${target}.out
            COMMAND arm-none-eabi-objcopy -O binary ${target}.out "${target}.bin"
            COMMAND arm-none-eabi-objcopy -O ihex ${target}.out "${target}.hex"
            COMMENT "post build steps for ${target}")

    add_nrf_targets(${target})
endmacro()