/**
 * @file crypt_mock.c
 *
 *
 * Description
 *
 */

/*======= Includes ==========================================================*/

#include <stdint.h>
#include "salt_crypto_wrapper.h"

/*======= Local Macro Definitions ===========================================*/
/*======= Type Definitions ==================================================*/
/*======= Local variable declarations =======================================*/
/*======= Local function prototypes =========================================*/
/*======= Global function implementations ===================================*/

int crypto_box_keypair(unsigned char *y,unsigned char *x)
{
    (void) y;
    (void) x;
    return 0;
}

int crypto_box_beforenm(unsigned char *k,const unsigned char *y,const unsigned char *x)
{
    (void) k;
    (void) y;
    (void) x;
    return 0;
}

int crypto_box_afternm(unsigned char *c,const unsigned char *m,unsigned long long d,const unsigned char *n,const unsigned char *k)
{
    (void) c;
    (void) m;
    (void) d;
    (void) n;
    (void) k;

    return 0;
}

int crypto_box_open_afternm(unsigned char *m,const unsigned char *c,unsigned long long d,const unsigned char *n,const unsigned char *k)
{
    (void) m;
    (void) c;
    (void) d;
    (void) n;
    (void) k;
    return 0;
}

int crypto_sign_keypair(unsigned char *pk, unsigned char *sk) {
    (void) pk;
    (void) sk;
    return 0;
}

int crypto_hash(unsigned char *out,const unsigned char *m,unsigned long long n)
{
    (void) out;
    (void) m;
    (void) n;
    return 0;
}

int crypto_sign(unsigned char *sm,unsigned long long *smlen,const unsigned char *m,unsigned long long n,const unsigned char *sk)
{
    (void) sm;
    (void) smlen;
    (void) m;
    (void) n;
    (void) sk;
    return 0;
}

int crypto_sign_open(unsigned char *m,unsigned long long *mlen,const unsigned char *sm,unsigned long long n,const unsigned char *pk)
{
    (void) m;
    (void) mlen;
    (void) sm;
    (void) n;
    (void) pk;
    return 0;
}

int crypto_hash_sha512_init(crypto_hash_sha512_state *state) {
    (void) state;
    return 0;
}

int crypto_hash_sha512_update(crypto_hash_sha512_state *state,
                              const unsigned char *in,
                              unsigned long long inlen)
{
    (void) state;
    (void) in;
    (void) inlen;
    return 0;
}

int crypto_hash_sha512_final(crypto_hash_sha512_state *state,
                             unsigned char *out)
{
    (void) state;
    (void) out;
    return 0;
}

int crypto_sign_verify_detached(const unsigned char *sig,
                                const unsigned char *m,
                                unsigned long long mlen,
                                const unsigned char *pk)
{
    (void) sig;
    (void) m;
    (void) mlen;
    (void) pk;
    return 0;
}

/*======= Local function implementations ====================================*/
