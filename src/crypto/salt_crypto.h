#ifndef _SALT_CRYPTO_H_
#define _SALT_CRYPTO_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file salt_crypto.h
 *
 * Salt Crypto abstraction layer header file.
 *
 * Abstraction above specific crypto libraries like TweetNaCl, libsodium.
 * Allows to access any of it (or both) with unified API
 *
 */

/*======= Includes ============================================================*/

#include <stdint.h>
#include <stdbool.h>

#include "salt_crypto_api.h"

#define crypto_sign_PUBLICKEYBYTES  32
#define crypto_sign_SECRETKEYBYTES  64
#define crypto_sign_BYTES           64
#define crypto_sign_SEEDBYTES       32

#define crypto_box_PUBLICKEYBYTES   32
#define crypto_box_SECRETKEYBYTES   32
#define crypto_box_SHAREDKEYBYTES   32
#define crypto_box_BEFORENMBYTES    32
#define crypto_box_NONCEBYTES       24
#define crypto_box_ZEROBYTES        32
#define crypto_box_BOXZEROBYTES     16
#define crypto_box_OVERHEADBYTES    16
#define crypto_box_INTERNALOVERHEADBYTES            32

#define crypto_secretbox_KEYBYTES                   32
#define crypto_secretbox_NONCEBYTES                 24
#define crypto_secretbox_ZEROBYTES                  32
#define crypto_secretbox_BOXZEROBYTES               16

//#define crypto_secretbox_OVERHEADBYTES             16
//#define crypto_secretbox_INTERNAL_OVERHEAD_BYTES    32

void salt_crypto_init(randombytes_t rng);
void salt_crypto_set_rng(salt_crypto_api_t *api, randombytes_t rng);


#ifdef __cplusplus
}
#endif

#endif /* _SALT_CRYPTO_H_ */