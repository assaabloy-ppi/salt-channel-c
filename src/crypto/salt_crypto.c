/**
 * @file salt_crypto.c
 *
 * Description
 *
 */

/*======= Includes ==========================================================*/
#include "salt_crypto.h"
#include "salt_crypto_wrap.h"

#define STR_EXPAND(tok) #tok
#define STR(tok) STR_EXPAND(tok)

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

const char* salt_crypto_get_name(salt_crypto_api_t *api)
{
#ifdef CRYPTO_BACKEND_ID
	return STR(CRYPTO_BACKEND_ID);
#else
	return "";
#endif
}



