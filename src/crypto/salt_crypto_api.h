
#ifndef _SALT_CRYPTO_API_H_
#define _SALT_CRYPTO_API_H_

#ifdef __cplusplus
extern "C" {
#endif


typedef unsigned long long crypto_len_t;

typedef void (*randombytes_t)(uint8_t *const buf, const crypto_len_t buf_len);



struct salt_crypto_api_s {
    int (*crypto_sign_keypair)(uint8_t *pk, uint8_t *sk);    
    
    int (*crypto_sign)(uint8_t *sm, crypto_len_t *smlen_p,
                        const uint8_t *m, crypto_len_t mlen,
                        const uint8_t *sk);

    int (*crypto_sign_open)(uint8_t *m, crypto_len_t *mlen_p,
                         const uint8_t *sm, crypto_len_t smlen,
                         const uint8_t *pk);

    int (*crypto_box_keypair)(uint8_t *pk, uint8_t *sk);
    int (*crypto_box_beforenm)(uint8_t *k, const uint8_t *pk, const uint8_t *sk);

    int (*crypto_box_afternm)(uint8_t *c, const uint8_t *m,
                               crypto_len_t mlen, const uint8_t *n,
                               const uint8_t *k);

    int (*crypto_box_open_afternm)(uint8_t *m, const uint8_t *c,
                                    crypto_len_t clen, const uint8_t *n,
                                    const uint8_t *k);
    int (*crypto_hash)(uint8_t *out, const uint8_t *in, crypto_len_t inlen);
    void (*randombytes)(uint8_t *const buf, const crypto_len_t buf_len);
};
typedef struct salt_crypto_api_s salt_crypto_api_t;


#ifdef __cplusplus
}
#endif

#endif /* _SALT_CRYPTO_API_H_ */

