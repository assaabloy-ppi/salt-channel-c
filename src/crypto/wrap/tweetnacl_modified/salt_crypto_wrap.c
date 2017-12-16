#include "tweetnacl_modified.h"
#include "salt_crypto_api.h"
#include "salt_crypto_wrap.h" /* must be last included header */

extern salt_crypto_api_t crypto;


/* TweetNaCl doesn't provide RNG so use externally defined */
void randombytes(unsigned char *p_bytes, unsigned long long length){
    crypto.randombytes(p_bytes, length);
}

void salt_crypto_api_init(salt_crypto_api_t *api, randombytes_t rng)
{

	salt_crypto_api_t _api = {
		.crypto_sign_keypair = crypto_sign_ed25519_tweet_keypair, 
    	.crypto_sign = crypto_sign_ed25519_tweet,
    	.crypto_sign_open = crypto_sign_ed25519_tweet_open,
    	.crypto_box_keypair = crypto_box_curve25519xsalsa20poly1305_tweet_keypair,
    	.crypto_box_beforenm = crypto_box_curve25519xsalsa20poly1305_tweet_beforenm,
    	.crypto_box_afternm = crypto_box_curve25519xsalsa20poly1305_tweet_afternm,
    	.crypto_box_open_afternm = crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm,
    	.crypto_hash = crypto_hash_sha512_tweet,
    	.randombytes = rng,  /* allows to override implementation specific RNG */

        /* detached calls */
        .crypto_hash_sha512_init = (f_crypto_hash_sha512_init)crypto_hash_sha512_init_tweet,
        .crypto_hash_sha512_update = (f_crypto_hash_sha512_update)crypto_hash_sha512_update_tweet,
        .crypto_hash_sha512_final = (f_crypto_hash_sha512_final)crypto_hash_sha512_final_tweet,
        .crypto_sign_verify_detached = (f_crypto_sign_verify_detached)crypto_sign_verify_detached_tweet
	};


	*api = _api;
}
