/**
 * @file salt_crypto.c
 *
 * Description
 *
 */

/*======= Includes ==========================================================*/
#include "salt_crypto.h"
#include "salt_crypto_wrap.h"

/* global structure */
salt_crypto_api_t crypto;


void salt_crypto_init(randombytes_t rng)
{
    salt_crypto_api_init(&crypto, rng);
}

void salt_crypto_set_rng(salt_crypto_api_t *api, randombytes_t rng)
{
	api->randombytes = rng;
}

