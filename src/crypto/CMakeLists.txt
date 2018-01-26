cmake_minimum_required(VERSION 3.5)
project(salt-crypto C)

# OPTION
# CRYPTO_BACKEND is one of the directory names in 'lib' directory 
set(CRYPTO_BACKEND "tweetnacl_modified" CACHE STRING "Crypro library backend")

# passed as preprocessor definition to let C code know which crypto backend is used
set(CRYPTO_BACKEND_ID ${CRYPTO_BACKEND})


# BACKEND LIBRARY - libsodium
if(CRYPTO_BACKEND MATCHES "libsodium")
    message(STATUS "CRYPTO_BACKEND set to libsodium type (${CRYPTO_BACKEND_ID})")
    file(GLOB BACKEND_SRC wrap/${CRYPTO_BACKEND}/*.c)
    add_library(crypto_backend ${BACKEND_SRC})
    target_include_directories(crypto_backend PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
                                                     ${CMAKE_CURRENT_SOURCE_DIR}/lib/${CRYPTO_BACKEND}/include
                                                     ${CMAKE_CURRENT_SOURCE_DIR}/wrap/${CRYPTO_BACKEND})

    # find correct prebuilt libsodium.a (according to target arch)
    set(CMAKE_PREFIX_PATH ${CMAKE_CURRENT_SOURCE_DIR}/lib/libsodium)
    find_library(LIBSODIUM NAMES sodium)
    set(BACKEND_LIBS ${LIBSODIUM})

else()
    # BACKEND LIBRARY - generic / tweetnacl
    message(STATUS "CRYPTO_BACKEND set to generic type (${CRYPTO_BACKEND_ID})")
	file(GLOB BACKEND_SRC lib/${CRYPTO_BACKEND}/*.c
		                  wrap/${CRYPTO_BACKEND}/*.c)
	add_library(crypto_backend ${BACKEND_SRC})
    target_include_directories(crypto_backend PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
                                                     ${CMAKE_CURRENT_SOURCE_DIR}/wrap/${CRYPTO_BACKEND}
                                                     ${CMAKE_CURRENT_SOURCE_DIR}/lib/${CRYPTO_BACKEND})
endif()

add_library(crypto_api INTERFACE)
target_include_directories(crypto_api INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/wrap/${CRYPTO_BACKEND})
target_link_libraries(crypto_api INTERFACE crypto_backend ${BACKEND_LIBS})
set(EXTRA_LIBS ${EXTRA_LIBS} crypto_api)

# CRYPTO 
add_library(crypto salt_crypto.c)
target_include_directories(crypto PUBLIC . lib/${CRYPTO_BACKEND} wrap/${CRYPTO_BACKEND})
target_compile_definitions(crypto PUBLIC CRYPTO_BACKEND_ID=${CRYPTO_BACKEND_ID})
target_link_libraries(crypto crypto_api)
