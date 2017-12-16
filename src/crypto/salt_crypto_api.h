
#ifndef _SALT_CRYPTO_API_H_
#define _SALT_CRYPTO_API_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/* required for impl-dependant structures definitions */  
#include "salt_crypto_wrap.h"


typedef unsigned long long crypto_len_t;

typedef void (*randombytes_t)(uint8_t *const buf, const crypto_len_t buf_len);

typedef     int (*f_crypto_sign_keypair)(uint8_t *pk, uint8_t *sk);    
    
typedef     int (*f_crypto_sign)(uint8_t *sm, crypto_len_t *smlen_p,
                        const uint8_t *m, crypto_len_t mlen,
                        const uint8_t *sk);

typedef     int (*f_crypto_sign_open)(uint8_t *m, crypto_len_t *mlen_p,
                         const uint8_t *sm, crypto_len_t smlen,
                         const uint8_t *pk);

typedef     int (*f_crypto_box_keypair)(uint8_t *pk, uint8_t *sk);
typedef     int (*f_crypto_box_beforenm)(uint8_t *k, const uint8_t *pk, const uint8_t *sk);

typedef     int (*f_crypto_box_afternm)(uint8_t *c, const uint8_t *m,
                               crypto_len_t mlen, const uint8_t *n,
                               const uint8_t *k);

typedef     int (*f_crypto_box_open_afternm)(uint8_t *m, const uint8_t *c,
                                    crypto_len_t clen, const uint8_t *n,
                                    const uint8_t *k);
typedef     int (*f_crypto_hash)(uint8_t *out, const uint8_t *in, crypto_len_t inlen);    
typedef     void (*f_randombytes)(uint8_t *const buf, const crypto_len_t buf_len);

    /* detached mode calls */
typedef     int (*f_crypto_hash_sha512_init)(crypto_hash_sha512_state *state);

typedef     int (*f_crypto_hash_sha512_update)(crypto_hash_sha512_state *state,
                                    const unsigned char *in,
                                    unsigned long long inlen);

typedef     int (*f_crypto_hash_sha512_final)(crypto_hash_sha512_state *state,
                                    unsigned char *out);

typedef     int (*f_crypto_sign_verify_detached)(const unsigned char *sig,
                                     const unsigned char *m,
                                      unsigned long long mlen,
                                      const unsigned char *pk);

struct salt_crypto_api_s {
  f_crypto_sign_keypair         crypto_sign_keypair;
  f_crypto_sign                 crypto_sign;
  f_crypto_sign_open            crypto_sign_open;
  f_crypto_box_keypair          crypto_box_keypair;
  f_crypto_box_beforenm         crypto_box_beforenm;
  f_crypto_box_afternm          crypto_box_afternm;
  f_crypto_box_open_afternm     crypto_box_open_afternm;
  f_crypto_hash                 crypto_hash;
  f_randombytes                 randombytes;

  f_crypto_hash_sha512_init     crypto_hash_sha512_init;
  f_crypto_hash_sha512_update   crypto_hash_sha512_update;
  f_crypto_hash_sha512_final    crypto_hash_sha512_final;
  f_crypto_sign_verify_detached crypto_sign_verify_detached;
};
typedef struct salt_crypto_api_s salt_crypto_api_t;


void salt_crypto_api_init(salt_crypto_api_t *api, randombytes_t rng);


#ifdef __cplusplus
}
#endif

#endif /* _SALT_CRYPTO_API_H_ */

