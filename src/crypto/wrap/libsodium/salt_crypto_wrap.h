
#ifndef _SALT_CRYPTO_WRAP_H_
#define _SALT_CRYPTO_WRAP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "sodium.h"  /* required to define 'crypto_hash_sha512_state' */

/* to redefine API names we must undefine them first */
#undef crypto_sign_keypair
#undef crypto_sign
#undef crypto_sign_open
#undef crypto_box_keypair
#undef crypto_box_beforenm
#undef crypto_box_afternm
#undef crypto_box_open_afternm
#undef crypto_hash
#undef randombytes  

//#include "../salt_crypto_api.h"

//typedef struct crypto_hash_sha512_state crypto_hash_sha512_state;

#ifdef __cplusplus
}
#endif

#endif /* _SALT_CRYPTO_WRAP_H_ */

