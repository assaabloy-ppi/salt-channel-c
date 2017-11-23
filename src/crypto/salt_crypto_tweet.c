#include <stddef.h>

#include "tweetnacl_modified.h"
#include "salt_crypto_tweet.h"

extern void randombytes(unsigned char *p_bytes, unsigned long long length);

void salt_crypto_api_tweet_init(salt_crypto_api_t *tweet_api, randombytes_t rng)
{
	salt_crypto_api_t api = {
		.crypto_sign_keypair = crypto_sign_ed25519_tweet_keypair, 
    	.crypto_sign = crypto_sign_ed25519_tweet,
    	.crypto_sign_open = crypto_sign_ed25519_tweet_open,
    	.crypto_box_keypair = crypto_box_curve25519xsalsa20poly1305_tweet_keypair,
    	.crypto_box_beforenm = crypto_box_curve25519xsalsa20poly1305_tweet_beforenm,
    	.crypto_box_afternm = crypto_box_curve25519xsalsa20poly1305_tweet_afternm,
    	.crypto_box_open_afternm = crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm,
    	.crypto_hash = crypto_hash_sha512_tweet,
    	.randombytes = rng? rng : randombytes
	};

	*tweet_api = api;
}