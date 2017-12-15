cmake_minimum_required(VERSION 3.5)
project(salt-crypto C)

# OPTION
# CRYPTO_BACKEND is one of the directory names in 'lib' directory 
set(CRYPTO_BACKEND "tweetnacl_modified" CACHE STRING "Crypro library backend")

# passed as preprocessor definition to let C code know which crypto backend is used
set(CRYPTO_BACKEND_ID ${CRYPTO_BACKEND})

# Directory where api wrapper for selected backend is located 
set(WRAPPER_DIR wrap/${CRYPTO_BACKEND})


# BACKEND LIBRARY
if(CRYPTO_BACKEND MATCHES "libsodium")
    message("NOTE: CRYPTO_BACKEND set to libsodium type (${CRYPTO_BACKEND_ID})")
    file(GLOB BACKEND_SRC ${WRAPPER_DIR}/*.c)
    add_library(crypto_backend ${BACKEND_SRC})
    target_include_directories(crypto_backend PRIVATE . wrap libsodium libsodium/include)
    set(EXTRA_LIBS ${EXTRA_LIBS} libsodium.a)
else()
    message("NOTE: CRYPTO_BACKEND set to generic type (${CRYPTO_BACKEND_ID})")
	file(GLOB BACKEND_SRC lib/${CRYPTO_BACKEND}/*.c
		                  ${WRAPPER_DIR}/*.c)
	add_library(crypto_backend ${BACKEND_SRC})
	target_include_directories(crypto_backend PRIVATE . lib/${CRYPTO_BACKEND} wrap)
endif()

# CRYPTO 
add_library(crypto salt_crypto.c)
target_link_libraries(crypto crypto_backend ${EXTRA_LIBS})
target_compile_definitions(crypto PRIVATE CRYPTO_BACKEND_ID=${CRYPTO_BACKEND_ID})
