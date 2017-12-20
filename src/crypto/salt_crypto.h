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


void salt_crypto_init(randombytes_t rng);
void salt_crypto_set_rng(salt_crypto_api_t *api, randombytes_t rng);


#ifdef __cplusplus
}
#endif

#endif /* _SALT_CRYPTO_H_ */
