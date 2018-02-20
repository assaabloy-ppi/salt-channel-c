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


void salt_crypto_api_init(salt_crypto_api_t *api, randombytes_t rng)
{
    /* sodium init will block if no RNG impl. defined */
    /* but in deterministic scenario it's not required so leaved commented for now */
    //randombytes_set_implementation(&randombytes_salsa20_implementation);
    //int res = sodium_init();
    //(void)res;
    
	salt_crypto_api_t _api = {
		//.crypto_sign_keypair = crypto_sign_keypair,       // [NONDETERMINISTIC]
        .crypto_sign_keypair = my_crypto_sign_keypair,  // [DETERMINISTIC]
    	.crypto_sign = crypto_sign,
    	.crypto_sign_open = crypto_sign_open,
    	//.crypto_box_keypair = crypto_box_keypair,   // [NONDETERMINISTIC]
        .crypto_box_keypair = (f_crypto_box_keypair)crypto_scalarmult_base, // [DETERMINISTIC]
    	.crypto_box_beforenm = crypto_box_beforenm,
    	.crypto_box_afternm = crypto_box_afternm,
    	.crypto_box_open_afternm = crypto_box_open_afternm,
    	.crypto_hash = crypto_hash,
    	.randombytes = rng? rng : randombytes, /* allows to override implementation specific RNG */	

        /* detached calls */
        .crypto_hash_sha512_init = crypto_hash_sha512_init,
        .crypto_hash_sha512_update = crypto_hash_sha512_update,
        .crypto_hash_sha512_final = crypto_hash_sha512_final,
        .crypto_sign_verify_detached = crypto_sign_verify_detached
	};	

	*api = _api;
}
