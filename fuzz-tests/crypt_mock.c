/**
 * @file crypt_mock.c
 *
 *
 * Description
 *
 */

/*======= Includes ==========================================================*/

#include <stdint.h>
#include "tweetnacl.h"

/*======= Local Macro Definitions ===========================================*/
/*======= Type Definitions ==================================================*/
/*======= Local variable declarations =======================================*/
/*======= Local function prototypes =========================================*/
/*======= Global function implementations ===================================*/

int crypto_box_keypair(unsigned char *y,unsigned char *x) { return 0; }
int crypto_box_beforenm(unsigned char *k,const unsigned char *y,const unsigned char *x) { return 0; }
int crypto_box_afternm(unsigned char *c,const unsigned char *m,unsigned long long d,const unsigned char *n,const unsigned char *k) { return 0; }
int crypto_box_open_afternm(unsigned char *m,const unsigned char *c,unsigned long long d,const unsigned char *n,const unsigned char *k) { return 0; }
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk) { return 0; }
int crypto_hash(unsigned char *out,const unsigned char *m,unsigned long long n) { return 0; }
int crypto_sign(unsigned char *sm,unsigned long long *smlen,const unsigned char *m,unsigned long long n,const unsigned char *sk) { return 0; }
int crypto_sign_open(unsigned char *m,unsigned long long *mlen,const unsigned char *sm,unsigned long long n,const unsigned char *pk) { return 0; }

/*======= Local function implementations ====================================*/
