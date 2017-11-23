
#ifndef _SALT_CRYPTO_TWEET_H_
#define _SALT_CRYPTO_TWEET_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "salt_crypto_api.h"

void salt_crypto_api_tweet_init(salt_crypto_api_t *tweet_api, randombytes_t rng);

#ifdef __cplusplus
}
#endif

#endif /* _SALT_CRYPTO_TWEET_H_ */

