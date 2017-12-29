include(CMakeForceCompiler)

set(CMAKE_SYSTEM_NAME Generic)

if (NRF_TARGET MATCHES "NRF51")
  set(CMAKE_SYSTEM_PROCESSOR cortex-m0)
elseif (NRF_TARGET MATCHES "NRF52")
  set(CMAKE_SYSTEM_PROCESSOR cortex-m4)
endif ()

cmake_force_c_compiler(arm-none-eabi-gcc GNU)

execute_process(
  COMMAND ${CMAKE_C_COMPILER} -print-file-name=libc.a
  OUTPUT_VARIABLE CMAKE_INSTALL_PREFIX
  OUTPUT_STRIP_TRAILING_WHITESPACE
  )

# Strip the filename off
get_filename_component(CMAKE_INSTALL_PREFIX
  "${CMAKE_INSTALL_PREFIX}" PATH
)

# Then find the canonical path to the directory one up from there
get_filename_component(CMAKE_INSTALL_PREFIX
  "${CMAKE_INSTALL_PREFIX}/.." REALPATH
)
set(CMAKE_INSTALL_PREFIX  ${CMAKE_INSTALL_PREFIX} CACHE FILEPATH
    "Install path prefix, prepended onto install directories.")

message(STATUS "Cross-compiling with the gcc-arm-embedded toolchain")
message(STATUS "Toolchain prefix: ${CMAKE_INSTALL_PREFIX}")

set(CMAKE_FIND_ROOT_PATH  ${CMAKE_INSTALL_PREFIX})

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

set(ARM_NONE_EABI_TOOLCHAIN_PATH  ${CMAKE_INSTALL_PREFIX})

# Nordic specific stuff
set(NRF5_SDK_ROOT "" CACHE STRING "SDK root folder")
set(SOFTDEVICE_REL_PATH "" CACHE STRING "Path relative to NRF5_SDK_ROOT to SoftDevice .hex file")

if (EXISTS "${NRF5_SDK_ROOT}/components/toolchain/system_nrf52.c")
  message(STATUS "Using SDK from ${NRF5_SDK_ROOT}")
else ()
  message(FATAL_ERROR "${NRF5_SDK_ROOT} is not a valid path to the nRF52 SDK...")
endif ()

########################
# utility functions 
function (add_nrf_targets target)
  set(SOFTDEVICE_PATH ${NRF5_SDK_ROOT}/${SOFTDEVICE_REL_PATH})

  add_custom_target(f_${target}
    COMMAND  nrfjprog -f ${NRF_TARGET} --program ${CMAKE_CURRENT_BINARY_DIR}/${target}.hex --sectorerase
    COMMAND  nrfjprog -f ${NRF_TARGET} --reset
    )

  add_custom_target(f_softdevice 
    COMMAND nrfjprog -f ${NRF_TARGET} --eraseall
    COMMAND nrfjprog -f ${NRF_TARGET} --program ${SOFTDEVICE_PATH} --sectorerase
    COMMAND sleep 0.5s
    COMMAND nrfjprog -f ${NRF_TARGET} --reset
    COMMENT "Flashing SoftDevice"
    )

  add_custom_target(erase
    COMMAND nrfjprog -f ${NRF_TARGET} --eraseall
    )  

  add_custom_target(sdk_config
    COMMAND  java -jar ${NRF5_SDK_ROOT}/external_tools/cmsisconfig/CMSIS_Configuration_Wizard.jar 
                  ${CMAKE_CURRENT_SOURCE_DIR}/include/sdk_config.h
    )  
endfunction ()

function(create_hex executable)
  add_custom_command(
    TARGET ${executable}
    POST_BUILD
    COMMAND arm-none-eabi-objcopy -O ihex ${CMAKE_CURRENT_BINARY_DIR}/${executable}.elf ${CMAKE_CURRENT_BINARY_DIR}/${executable}.hex
    )
endfunction(create_hex)
########################


set(BUILD_SHARED_LIBS OFF)


#if (CMAKE_SYSTEM_PROCESSOR MATCHES "cortex-m0")
# set(CMAKE_C_FLAGS
#    "-mcpu=cortex-m0 -mthumb -mabi=aapcs -mfloat-abi=soft"
#    "-std=gnu99"
#    "-Wall"
#    "-fno-common -ffunction-sections -fdata-sections -fno-strict-aliasing"
#    "-fno-builtin --short-enums -O3"
#    )
#  string(REGEX REPLACE ";" " " CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
#elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "cortex-m4")
#  message(FATAL_ERROR "Target not supported")
#endif ()

macro(nRF5x_config)
    # CPU specyfic settings
    if (NRF_TARGET MATCHES "NRF51")
        # nRF51 (nRF51-DK => PCA10028)

        set(NRF5_LINKER_SCRIPT "${CMAKE_SOURCE_DIR}/gcc_nrf51.ld")
        set(CPU_FLAGS "-mcpu=cortex-m0 -mfloat-abi=soft")
        add_definitions(-DBOARD_PCA10028 -DNRF51 -DNRF51422)
        add_definitions(-DSOFTDEVICE_PRESENT -DS130 -DNRF_SD_BLE_API_VERSION=2 -DSWI_DISABLE0 -DBLE_STACK_SUPPORT_REQD)
        include_directories(
                "${NRF5_SDK_ROOT}/components/softdevice/s130/headers"
                "${NRF5_SDK_ROOT}/components/softdevice/s130/headers/nrf51"
        )
        list(APPEND SDK_SOURCE_FILES
                "${NRF5_SDK_ROOT}/components/toolchain/system_nrf51.c"
                "${NRF5_SDK_ROOT}/components/toolchain/gcc/gcc_startup_nrf51.S"
                )
        set(SOFTDEVICE_PATH "${NRF5_SDK_ROOT}/components/softdevice/s130/hex/s130_nrf51_2.0.1_softdevice.hex")
    elseif (NRF_TARGET MATCHES "NRF52")
        # nRF52 (nRF52-DK => PCA10040)

        set(NRF5_LINKER_SCRIPT "${CMAKE_SOURCE_DIR}/src/hal/arm_nrf52-none-serial_debug/gcc_nrf52.ld") # [TODO]
        set(CPU_FLAGS "-mcpu=cortex-m4 -mfloat-abi=hard -mfpu=fpv4-sp-d16")
        add_definitions(-DNRF52 -DNRF52832 -DNRF52_PAN_64 -DNRF52_PAN_12 -DNRF52_PAN_58 -DNRF52_PAN_54 -DNRF52_PAN_31 -DNRF52_PAN_51 -DNRF52_PAN_36 -DNRF52_PAN_15 -DNRF52_PAN_20 -DNRF52_PAN_55 -DBOARD_PCA10040)
        add_definitions(-DSOFTDEVICE_PRESENT -DS132 -DBLE_STACK_SUPPORT_REQD -DNRF_SD_BLE_API_VERSION=3)
        include_directories(
                "${NRF5_SDK_ROOT}/components/softdevice/s132/headers"
                "${NRF5_SDK_ROOT}/components/softdevice/s132/headers/nrf52"
                "${NRF5_SDK_ROOT}/components/toolchain/gcc"
        )

        list(APPEND SDK_SOURCE_FILES
                "${NRF5_SDK_ROOT}/components/toolchain/system_nrf52.c"
                "${NRF5_SDK_ROOT}/components/toolchain/gcc/gcc_startup_nrf52.S"
                )
        set(SOFTDEVICE_PATH "${NRF5_SDK_ROOT}/components/softdevice/s132/hex/s132_nrf52_3.0.0_softdevice.hex")
    endif ()

    set(COMMON_FLAGS "-MP -MD -mthumb -mabi=aapcs -Wall -Werror -O3 -g3 -ffunction-sections -fdata-sections -fno-strict-aliasing -fno-builtin --short-enums ${CPU_FLAGS}")

    # compiler/assambler/linker flags
    set(CMAKE_C_FLAGS "${COMMON_FLAGS}" CACHE STRING "" FORCE)
    set(CMAKE_CXX_FLAGS "${COMMON_FLAGS}" CACHE STRING "" FORCE)
    set(CMAKE_ASM_FLAGS "-MP -MD -std=c99 -x assembler-with-cpp" CACHE STRING "" FORCE)
    set(CMAKE_EXE_LINKER_FLAGS "-mthumb -mabi=aapcs -std=c99 -L${NRF5_SDK_ROOT}/components/toolchain/gcc "
                              "-T${NRF5_LINKER_SCRIPT} ${CPU_FLAGS} -Wl,--gc-sections --specs=nano.specs -lc -lnosys -lm"
                              CACHE STRING "" FORCE)
    string(REGEX REPLACE ";" " " CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS}")
    # note: we must override the default cmake linker flags so that CMAKE_C_FLAGS are not added implicitly
    set(CMAKE_C_LINK_EXECUTABLE "${CMAKE_C_COMPILER} <LINK_FLAGS> <OBJECTS> -o <TARGET>")
    set(CMAKE_CXX_LINK_EXECUTABLE "${CMAKE_C_COMPILER} <LINK_FLAGS> <OBJECTS> -lstdc++ -o <TARGET>")  

endmacro(nRF5x_config)


macro(nRF5x_setup)
    # fix on macOS: prevent cmake from adding implicit parameters to Xcode
    set(CMAKE_OSX_SYSROOT "/")
    set(CMAKE_OSX_DEPLOYMENT_TARGET "")

    # language standard/version settings
    set(CMAKE_C_STANDARD 99)
    set(CMAKE_CXX_STANDARD 98)

    # configure cmake to use the arm-none-eabi-gcc
    set(CMAKE_C_COMPILER "arm-none-eabi-gcc")
    set(CMAKE_CXX_COMPILER "arm-none-eabi-c++")
    set(CMAKE_ASM_COMPILER "arm-none-eabi-gcc")

    include_directories(
            "${NRF5_SDK_ROOT}/components/softdevice/common/softdevice_handler"
    )

    list(APPEND SDK_SOURCE_FILES
            "${NRF5_SDK_ROOT}/components/softdevice/common/softdevice_handler/softdevice_handler.c"
            )

    nRF5x_config()

    include_directories(".")

    # basic board definitions and drivers
    include_directories(
            "${NRF5_SDK_ROOT}/components/boards"
            "${NRF5_SDK_ROOT}/components/device"
            "${NRF5_SDK_ROOT}/components/libraries/util"
            "${NRF5_SDK_ROOT}/components/drivers_nrf/hal"
            "${NRF5_SDK_ROOT}/components/drivers_nrf/common"
            "${NRF5_SDK_ROOT}/components/drivers_nrf/delay"
            "${NRF5_SDK_ROOT}/components/drivers_nrf/uart"
            "${NRF5_SDK_ROOT}/components/drivers_nrf/clock"
            "${NRF5_SDK_ROOT}/components/drivers_nrf/rtc"
            "${NRF5_SDK_ROOT}/components/drivers_nrf/gpiote"
    )

    # toolchain specyfic
    include_directories(
            "${NRF5_SDK_ROOT}/components/toolchain/"
            "${NRF5_SDK_ROOT}/components/toolchain/gcc"
            "${NRF5_SDK_ROOT}/components/toolchain/cmsis/include"
    )

    # log
    include_directories(
            "${NRF5_SDK_ROOT}/components/libraries/log"
            "${NRF5_SDK_ROOT}/components/libraries/log/src"
            "${NRF5_SDK_ROOT}/components/libraries/timer"
    )

    # Segger RTT
    include_directories(
            "${NRF5_SDK_ROOT}/external/segger_rtt/"
    )

    # basic board support and drivers
    list(APPEND SDK_SOURCE_FILES
            "${NRF5_SDK_ROOT}/components/boards/boards.c"
            "${NRF5_SDK_ROOT}/components/drivers_nrf/common/nrf_drv_common.c"
            "${NRF5_SDK_ROOT}/components/drivers_nrf/clock/nrf_drv_clock.c"
            "${NRF5_SDK_ROOT}/components/drivers_nrf/uart/nrf_drv_uart.c"
            "${NRF5_SDK_ROOT}/components/drivers_nrf/rtc/nrf_drv_rtc.c"
            "${NRF5_SDK_ROOT}/components/drivers_nrf/gpiote/nrf_drv_gpiote.c"
            )

    # drivers and utils
    list(APPEND SDK_SOURCE_FILES
            "${NRF5_SDK_ROOT}/components/libraries/hardfault/hardfault_implementation.c"
            "${NRF5_SDK_ROOT}/components/libraries/util/nrf_assert.c"
            "${NRF5_SDK_ROOT}/components/libraries/util/sdk_errors.c"
            "${NRF5_SDK_ROOT}/components/libraries/util/app_error.c"
            "${NRF5_SDK_ROOT}/components/libraries/util/app_error_weak.c"
            "${NRF5_SDK_ROOT}/components/libraries/util/app_util_platform.c"
            "${NRF5_SDK_ROOT}/components/libraries/log/src/nrf_log_backend_serial.c"
            "${NRF5_SDK_ROOT}/components/libraries/log/src/nrf_log_frontend.c"
            "${NRF5_SDK_ROOT}/components/libraries/util/app_util_platform.c"
            "${NRF5_SDK_ROOT}/components/libraries/util/sdk_mapped_flags.c"
            )

    # Segger RTT
    list(APPEND SDK_SOURCE_FILES
            "${NRF5_SDK_ROOT}/external/segger_rtt/RTT_Syscalls_GCC.c"
            "${NRF5_SDK_ROOT}/external/segger_rtt/SEGGER_RTT.c"
            "${NRF5_SDK_ROOT}/external/segger_rtt/SEGGER_RTT_printf.c"
            )

    # Common Bluetooth Low Energy files
    include_directories(
            "${NRF5_SDK_ROOT}/components/ble"
            "${NRF5_SDK_ROOT}/components/ble/common"
    )

    list(APPEND SDK_SOURCE_FILES
            "${NRF5_SDK_ROOT}/components/ble/common/ble_advdata.c"
            "${NRF5_SDK_ROOT}/components/ble/common/ble_conn_params.c"
            "${NRF5_SDK_ROOT}/components/ble/common/ble_conn_state.c"
            "${NRF5_SDK_ROOT}/components/ble/common/ble_srv_common.c"
            )

    # adds target for erasing and flashing the board with a softdevice
    #add_custom_target(FLASH_SOFTDEVICE ALL
    #        COMMAND ${NRFJPROG} --program ${SOFTDEVICE_PATH} -f ${NRF_TARGET} --sectorerase
    #        COMMAND sleep 0.5s
    #        COMMAND ${NRFJPROG} --reset -f ${NRF_TARGET}
    #        COMMENT "flashing SoftDevice"
    #        )

    #add_custom_target(FLASH_ERASE ALL
    #        COMMAND ${NRFJPROG} --eraseall -f ${NRF_TARGET}
    #        COMMENT "erasing flashing"
    #        )
endmacro(nRF5x_setup)

# adds a target for comiling and flashing an executable
macro(nRF5x_addExecutable EXECUTABLE_NAME SOURCE_FILES)
    # executable
    add_executable(${EXECUTABLE_NAME} ${SDK_SOURCE_FILES} ${SOURCE_FILES})
    set_target_properties(${EXECUTABLE_NAME} PROPERTIES SUFFIX ".out")
    set_target_properties(${EXECUTABLE_NAME} PROPERTIES LINK_FLAGS "-Wl,-Map=${EXECUTABLE_NAME}.map")

    # additional POST BUILD setps to create the .bin and .hex files
    add_custom_command(TARGET ${EXECUTABLE_NAME}
            POST_BUILD
            COMMAND ${ARM_NONE_EABI_TOOLCHAIN_PATH}/bin/arm-none-eabi-size ${EXECUTABLE_NAME}.out
            COMMAND ${ARM_NONE_EABI_TOOLCHAIN_PATH}/bin/arm-none-eabi-objcopy -O binary ${EXECUTABLE_NAME}.out "${EXECUTABLE_NAME}.bin"
            COMMAND ${ARM_NONE_EABI_TOOLCHAIN_PATH}/bin/arm-none-eabi-objcopy -O ihex ${EXECUTABLE_NAME}.out "${EXECUTABLE_NAME}.hex"
            COMMENT "post build steps for ${EXECUTABLE_NAME}")

    # custom target for flashing the board
    add_custom_target("FLASH_${EXECUTABLE_NAME}" ALL
            COMMAND ${NRFJPROG} --program ${EXECUTABLE_NAME}.hex -f ${NRF_TARGET} --sectorerase
            COMMAND sleep 0.5s
            COMMAND ${NRFJPROG} --reset -f ${NRF_TARGET}
            DEPENDS ${EXECUTABLE_NAME}
            COMMENT "flashing ${EXECUTABLE_NAME}.hex"
            )
endmacro()

# adds app-level scheduler library
macro(nRF5x_addAppScheduler)
    include_directories(
            "${NRF5_SDK_ROOT}/components/libraries/scheduler"
    )

    list(APPEND SDK_SOURCE_FILES
            "${NRF5_SDK_ROOT}/components/libraries/scheduler/app_scheduler.c"
            "${NRF5_SDK_ROOT}/components/softdevice/common/softdevice_handler/softdevice_handler_appsh.c"
            )

endmacro(nRF5x_addAppScheduler)

# adds app-level FIFO libraries
macro(nRF5x_addAppFIFO)
    include_directories(
            "${NRF5_SDK_ROOT}/components/libraries/fifo"
    )

    list(APPEND SDK_SOURCE_FILES
            "${NRF5_SDK_ROOT}/components/libraries/fifo/app_fifo.c"
            )

endmacro(nRF5x_addAppFIFO)

# adds app-level Timer libraries
macro(nRF5x_addAppTimer)
    list(APPEND SDK_SOURCE_FILES
            "${NRF5_SDK_ROOT}/components/libraries/timer/app_timer.c"
            )
endmacro(nRF5x_addAppTimer)

# adds app-level UART libraries
macro(nRF5x_addAppUART)
    include_directories(
            "${NRF5_SDK_ROOT}/components/libraries/uart"
    )

    list(APPEND SDK_SOURCE_FILES
            "${NRF5_SDK_ROOT}/components/libraries/uart/app_uart_fifo.c"
            )

endmacro(nRF5x_addAppUART)

# adds app-level Button library
macro(nRF5x_addAppButton)
    include_directories(
            "${NRF5_SDK_ROOT}/components/libraries/button"
    )

    list(APPEND SDK_SOURCE_FILES
            "${NRF5_SDK_ROOT}/components/libraries/button/app_button.c"
            )

endmacro(nRF5x_addAppButton)

# adds BSP (board support package) library
macro(nRF5x_addBSP WITH_BLE_BTN WITH_ANT_BTN WITH_NFC)
    include_directories(
            "${NRF5_SDK_ROOT}/components/libraries/bsp"
    )

    list(APPEND SDK_SOURCE_FILES
            "${NRF5_SDK_ROOT}/components/libraries/bsp/bsp.c"
            )

    if (${WITH_BLE_BTN})
        list(APPEND SDK_SOURCE_FILES
                "${NRF5_SDK_ROOT}/components/libraries/bsp/bsp_btn_ble.c"
                )
    endif ()

    if (${WITH_ANT_BTN})
        list(APPEND SDK_SOURCE_FILES
                "${NRF5_SDK_ROOT}/components/libraries/bsp/bsp_btn_ant.c"
                )
    endif ()

    if (${WITH_NFC})
        list(APPEND SDK_SOURCE_FILES
                "${NRF5_SDK_ROOT}/components/libraries/bsp/bsp_nfc.c"
                )
    endif ()

endmacro(nRF5x_addBSP)

# adds Bluetooth Low Energy GATT support library
macro(nRF5x_addBLEGATT)
    include_directories(
            "${NRF5_SDK_ROOT}/components/ble/nrf_ble_gatt"
    )

    list(APPEND SDK_SOURCE_FILES
            "${NRF5_SDK_ROOT}/components/ble/nrf_ble_gatt/nrf_ble_gatt.c"
            )

endmacro(nRF5x_addBLEGATT)

# adds Bluetooth Low Energy advertising support library
macro(nRF5x_addBLEAdvertising)
    include_directories(
            "${NRF5_SDK_ROOT}/components/ble/ble_advertising"
    )

    list(APPEND SDK_SOURCE_FILES
            "${NRF5_SDK_ROOT}/components/ble/ble_advertising/ble_advertising.c"
            )

endmacro(nRF5x_addBLEAdvertising)

# adds Bluetooth Low Energy advertising support library
macro(nRF5x_addBLEPeerManager)
    include_directories(
            "${NRF5_SDK_ROOT}/components/ble/peer_manager"
    )

    list(APPEND SDK_SOURCE_FILES
            "${NRF5_SDK_ROOT}/components/ble/peer_manager/gatt_cache_manager.c"
            "${NRF5_SDK_ROOT}/components/ble/peer_manager/gatts_cache_manager.c"
            "${NRF5_SDK_ROOT}/components/ble/peer_manager/id_manager.c"
            "${NRF5_SDK_ROOT}/components/ble/peer_manager/peer_data.c"
            "${NRF5_SDK_ROOT}/components/ble/peer_manager/peer_data_storage.c"
            "${NRF5_SDK_ROOT}/components/ble/peer_manager/peer_database.c"
            "${NRF5_SDK_ROOT}/components/ble/peer_manager/peer_id.c"
            "${NRF5_SDK_ROOT}/components/ble/peer_manager/peer_manager.c"
            "${NRF5_SDK_ROOT}/components/ble/peer_manager/pm_buffer.c"
            "${NRF5_SDK_ROOT}/components/ble/peer_manager/pm_mutex.c"
            "${NRF5_SDK_ROOT}/components/ble/peer_manager/security_dispatcher.c"
            "${NRF5_SDK_ROOT}/components/ble/peer_manager/security_manager.c"
            )

endmacro(nRF5x_addBLEPeerManager)

# adds app-level FDS (flash data storage) library
macro(nRF5x_addAppFDS)
    include_directories(
            "${NRF5_SDK_ROOT}/components/libraries/fds"
            "${NRF5_SDK_ROOT}/components/libraries/fstorage"
            "${NRF5_SDK_ROOT}/components/libraries/experimental_section_vars"
    )

    list(APPEND SDK_SOURCE_FILES
            "${NRF5_SDK_ROOT}/components/libraries/fds/fds.c"
            "${NRF5_SDK_ROOT}/components/libraries/fstorage/fstorage.c"
            )

endmacro(nRF5x_addAppFDS)


nRF5x_config()
