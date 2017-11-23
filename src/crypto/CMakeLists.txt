project(salt-channel-c C)


include_directories ("libsodium")
include_directories ("libsodium/include")
set(EXTRA_LIBS ${EXTRA_LIBS} libsodium.a)
include_directories ("tweetnacl_modified")
set(EXTRA_LIBS ${EXTRA_LIBS} tweetnacl_modified)

#set_source_files_properties(tweetnacl_modified.c PROPERTIES COMPILE_FLAGS -Wno-sign-compare)
add_library(tweetnacl_modified tweetnacl_modified/tweetnacl_modified.c)
add_sanitizers(tweetnacl_modified)

add_library(crypto salt_crypto.c salt_crypto_sodium.c salt_crypto_tweet.c)
target_link_libraries(crypto libsodium.a tweetnacl_modified)
