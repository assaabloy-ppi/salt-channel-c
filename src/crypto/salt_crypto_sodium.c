#include "sodium.h"
#include "salt_crypto_sodium.h"

//extern void randombytes(unsigned char *p_bytes, unsigned long long length);

void salt_crypto_api_sodium_init(salt_crypto_api_t *sodium_api, randombytes_t rng)
{

	salt_crypto_api_t api = {
		.crypto_sign_keypair = crypto_sign_keypair, 
    	.crypto_sign = crypto_sign,
    	.crypto_sign_open = crypto_sign_open,
    	.crypto_box_keypair = crypto_box_keypair,
    	.crypto_box_beforenm = crypto_box_beforenm,
    	.crypto_box_afternm = crypto_box_afternm,
    	.crypto_box_open_afternm = crypto_box_open_afternm,
    	.crypto_hash = crypto_hash,
    	.randombytes = rng? rng : randombytes	
	};	

	*sodium_api = api;
}