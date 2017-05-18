#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>

#include "tweetnacl.h"

void randombytes(unsigned char *p_bytes, unsigned long long length)
{
    unsigned long long i;
    for (i = 0; i < length; i++) {
        p_bytes[i] = (uint8_t) i;
    }
}

void crypt_test(void)
{
    /* Test if we can put the hash where the actual message to hash is placed. */
    uint8_t tmp_bytes[1024];
    uint8_t tmp_bytes_hash[crypto_hash_BYTES];
    randombytes(tmp_bytes, sizeof(tmp_bytes));

    crypto_hash(tmp_bytes_hash, tmp_bytes, sizeof(tmp_bytes));
    crypto_hash(tmp_bytes, tmp_bytes, sizeof(tmp_bytes));

    assert(memcmp(tmp_bytes, tmp_bytes_hash, crypto_hash_BYTES) == 0);

    printf("A hash of a message can be put on the message itself.\r\n");
}

void sign_test(void) {
    
    /* Test if we can sign a message and put the signed message on the message itself. */

    uint8_t msg_to_sign[1024 + crypto_sign_BYTES];
    uint8_t tmp_msg[1024];
    uint8_t signed_msg[1024 + crypto_sign_BYTES];
    randombytes(msg_to_sign, 1024);
    memcpy(tmp_msg, msg_to_sign, 1024);

    uint8_t sk_pub[crypto_sign_PUBLICKEYBYTES];
    uint8_t sk_sec[crypto_sign_SECRETKEYBYTES];

    crypto_sign_keypair(sk_pub, sk_sec);

    unsigned long long signed_msg_size1;
    unsigned long long signed_msg_size2;

    /* Sign and put in a temporary buffer. */
    crypto_sign(signed_msg, &signed_msg_size1, msg_to_sign, 1024, sk_sec);
    assert(memcmp(tmp_msg, msg_to_sign, 1024) == 0);
    /* Sign and put on the message, requires crypto_sign_BYTES longer buffer. */
    crypto_sign(msg_to_sign, &signed_msg_size2, msg_to_sign, 1024, sk_sec);

    assert(signed_msg_size1 == signed_msg_size2);

    if (memcmp(msg_to_sign, signed_msg, signed_msg_size1) == 0) {
        printf("The signature can be put on the original message.\r\n");
    } else {
        printf("The signature can NOT be put on the original message.\r\n");
    }

    memset(msg_to_sign, 0x00, sizeof(signed_msg));

    assert(crypto_sign_open(msg_to_sign, &signed_msg_size1,
        signed_msg, signed_msg_size2, sk_pub) == 0);

    assert(memcmp(msg_to_sign, tmp_msg, 1024) == 0);

    if (crypto_sign_open(signed_msg, &signed_msg_size1,
        signed_msg, signed_msg_size2, sk_pub) == 0) {
        printf("Signed message can be verified on the message itself.\r\n");
    } else {
        printf("Signed message can NOT be verified on the message itself.\r\n");
    }


}

int main(void)
{

    printf("=== TweetNaCl API test begin ===\r\n");

    printf("=== Hash test ===\r\n");
    crypt_test();
    printf("=== Sign test ===\r\n");
    sign_test();

    uint8_t sk_pub[crypto_sign_PUBLICKEYBYTES];
    uint8_t sk_sec[crypto_sign_SECRETKEYBYTES];

    crypto_sign_keypair(sk_pub, sk_sec);

    uint8_t tmp[192]; uint8_t tmp2[192];
    memset(&tmp[64], 0xEE, 128);

    unsigned long long signed_msg_size2;
    crypto_sign(tmp2, &signed_msg_size2, &tmp[64], 128, sk_sec);
    crypto_sign(tmp, &signed_msg_size2, &tmp[64], 128, sk_sec);
    assert(memcmp(tmp, tmp2, 192) == 0);
    printf("=== TweetNaCl API test end ===\r\n");

    return 0;
}