#include <string.h>

#include "sodium.h"
#include "salt_crypto_api.h"
#include "salt_crypto_wrap.h" /* must be last included header */

/* libsodium already defined own randombytes() */
/*extern void randombytes(unsigned char *p_bytes, unsigned long long length); */

/* wrapper to make crypto_sign_keypair() deterministic */
int my_crypto_sign_keypair(unsigned char *pk, unsigned char *sk)
{
    uint8_t seed[32];
    memcpy(seed, sk, 32);
    return crypto_sign_seed_keypair(pk, sk, seed);
}

/* override libsodium default randombytes*/
/*void my_randombytes(unsigned char *p_bytes, unsigned long long length)
{
    if (crypto.randombytes) 
        crypto.randombytes(p_bytes, length);
}*/

static randombytes_t rng_tmp;  // used to access from static libsodium functions

static void randombytes_salt_crypto_wrap_buf(void * const buf, const size_t size)
{
    if (rng_tmp)
        rng_tmp(buf, size);
}

static uint32_t randombytes_salt_crypto_wrap_random(void)
{
    uint32_t r;
    randombytes_salt_crypto_wrap_buf(&r, sizeof(r));
    return r;
}

static const char* randombytes_salt_crypto_wrap_implementation_name(void) {
    return "salt_crypto_wrapper";
}

struct randombytes_implementation randombytes_salt_crypto_wrap_implementation = {
    .implementation_name = randombytes_salt_crypto_wrap_implementation_name,
    .random = randombytes_salt_crypto_wrap_random,
    .stir = NULL,
    .uniform = NULL,
    .buf = randombytes_salt_crypto_wrap_buf,
    .close = NULL
};


void salt_crypto_api_init(salt_crypto_api_t *api, randombytes_t rng)
{
    rng_tmp = rng;

    randombytes_set_implementation(&randombytes_salt_crypto_wrap_implementation);
    int res = sodium_init();
    (void)res;

	salt_crypto_api_t _api = {
		.crypto_sign_keypair = crypto_sign_keypair,  // [NONDETERMINISTIC]
    	.crypto_sign = crypto_sign,
    	.crypto_sign_open = crypto_sign_open,
    	.crypto_box_keypair = crypto_box_keypair,   // [NONDETERMINISTIC]
    	.crypto_box_beforenm = crypto_box_beforenm,
    	.crypto_box_afternm = crypto_box_afternm,
    	.crypto_box_open_afternm = crypto_box_open_afternm,
    	.crypto_hash = crypto_hash,
    	.randombytes = rng,

        /* detached calls */
        .crypto_hash_sha512_init = crypto_hash_sha512_init,
        .crypto_hash_sha512_update = crypto_hash_sha512_update,
        .crypto_hash_sha512_final = crypto_hash_sha512_final,
        .crypto_sign_verify_detached = crypto_sign_verify_detached
	};	

    /* if deterministic mode requested */
    if (!rng) { 
        _api.crypto_sign_keypair = my_crypto_sign_keypair;
        _api.crypto_box_keypair = (f_crypto_box_keypair)crypto_scalarmult_base;
    }


	*api = _api;
}
