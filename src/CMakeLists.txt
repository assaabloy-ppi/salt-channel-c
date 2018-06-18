project(salt-channel-c)

# Salt channel implementation
add_library(salt salt.c salti_util.c salti_handshake.c)
add_sanitizers(salt)

add_library(salt_test salt_crypto_wrapper_test.c)
add_sanitizers(salt_test)