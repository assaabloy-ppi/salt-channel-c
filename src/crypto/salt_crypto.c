/**
 * @file salt_crypto.c
 *
 * Description
 *
 */

/*======= Includes ==========================================================*/
#include "salt_crypto.h"

#include "salt_crypto_tweet.h"
#include "salt_crypto_sodium.h"

/* global structure */
salt_crypto_t crypto;

/* used in tweetnacl_modified.c */
//extern void randombytes(unsigned char *p_bytes, unsigned long long length);

void salt_crypto_init(randombytes_t rng)
{
    salt_crypto_api_tweet_init(&crypto.api[SALT_CRYPTO_API_TWEETNACL], rng);
	salt_crypto_api_sodium_init(&crypto.api[SALT_CRYPTO_API_LIBSODIUM], rng);
}

void salt_crypto_set_rng(int api_idx, randombytes_t rng)
{
	crypto.api[api_idx].randombytes = rng;
}

salt_crypto_api_t* salt_crypto_api(int api_idx)
{
	return &(crypto.api[api_idx]);
}

salt_crypto_api_t* salt_crypto_api_default()
{
	//return salt_crypto_api(SALT_CRYPTO_API_DEFAULT);
	return salt_crypto_api(SALT_CRYPTO_API_LIBSODIUM);
}

/*======= private functions  =================================================*/