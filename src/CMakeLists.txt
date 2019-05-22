project(salt-channel-c)

# Salt channel implementation
add_library(salt salt.c salti_util.c salti_handshake.c)
add_sanitizers(salt)

add_library(salt_test salt_crypto_wrapper_test.c)
add_sanitizers(salt_test)

target_compile_options(salt PRIVATE -Werror -Wall -Wextra -Wpedantic -Wshadow -Wcast-qual -std=c99)
target_compile_options(salt_test PRIVATE -Werror -Wall -Wextra -Wpedantic -Wshadow -Wcast-qual -std=c99)

set_target_properties(salt PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}"
)
