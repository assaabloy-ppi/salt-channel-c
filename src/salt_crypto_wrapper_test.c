/**
 * @file salt_crypto_wrapper_test.c
 *
 * Simple test suite for crypto API.
 * Test data from: https://github.com/assaabloy-ppi/salt-channel/blob/master/files/spec/salt-channel-v2-final1.md
 *
 */

/*======= Includes ==========================================================*/

#include <string.h> /* memcmp */
#include "salt_crypto_wrapper_test.h"

/*======= Local Macro Definitions ===========================================*/

#define VERIFY(x) if (!(x)) return -1

/*======= Type Definitions ==================================================*/
/*======= Local function prototypes =========================================*/
/*======= Local variable declarations =======================================*/

static const uint8_t bob_sk_sec[api_crypto_sign_SECRETKEYBYTES] = {
    0x55, 0xf4, 0xd1, 0xd1, 0x98, 0x09, 0x3c, 0x84,
    0xde, 0x9e, 0xe9, 0xa6, 0x29, 0x9e, 0x0f, 0x68,
    0x91, 0xc2, 0xe1, 0xd0, 0xb3, 0x69, 0xef, 0xb5,
    0x92, 0xa9, 0xe3, 0xf1, 0x69, 0xfb, 0x0f, 0x79,
    0x55, 0x29, 0xce, 0x8c, 0xcf, 0x68, 0xc0, 0xb8,
    0xac, 0x19, 0xd4, 0x37, 0xab, 0x0f, 0x5b, 0x32,
    0x72, 0x37, 0x82, 0x60, 0x8e, 0x93, 0xc6, 0x26,
    0x4f, 0x18, 0x4b, 0xa1, 0x52, 0xc2, 0x35, 0x7b
};

static const uint8_t bob_ek_sec[api_crypto_box_SECRETKEYBYTES] = {
    0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
    0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
    0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
    0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
};

static const uint8_t bob_ek_pub[api_crypto_box_PUBLICKEYBYTES] = {
    0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
    0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
    0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
    0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a
};

static const uint8_t alice_sk_sec[api_crypto_sign_SECRETKEYBYTES] = {
    0x7a, 0x77, 0x2f, 0xa9, 0x01, 0x4b, 0x42, 0x33,
    0x00, 0x07, 0x6a, 0x2f, 0xf6, 0x46, 0x46, 0x39,
    0x52, 0xf1, 0x41, 0xe2, 0xaa, 0x8d, 0x98, 0x26,
    0x3c, 0x69, 0x0c, 0x0d, 0x72, 0xee, 0xd5, 0x2d,
    0x07, 0xe2, 0x8d, 0x4e, 0xe3, 0x2b, 0xfd, 0xc4,
    0xb0, 0x7d, 0x41, 0xc9, 0x21, 0x93, 0xc0, 0xc2,
    0x5e, 0xe6, 0xb3, 0x09, 0x4c, 0x62, 0x96, 0xf3,
    0x73, 0x41, 0x3b, 0x37, 0x3d, 0x36, 0x16, 0x8b 
};

static const uint8_t alice_ek_sec[api_crypto_box_SECRETKEYBYTES] = {
    0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
    0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
    0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
    0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb
};

static const uint8_t alice_ek_pub[api_crypto_box_PUBLICKEYBYTES] = {
    0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
    0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
    0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
    0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f
};

static const uint8_t ek_common[api_crypto_box_BEFORENMBYTES] = {
    0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4,
    0x62, 0xcd, 0x51, 0x19, 0x7a, 0x9a, 0x46, 0xc7,
    0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
    0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89
};



/*======= Global function implementations ===================================*/

int salt_crypto_wrapper_test(void)
{
    VERIFY(test_api_crypto_box_beforenm() == 0);
    VERIFY(test_api_crypto_box_afternm() == 0);

    (void) bob_sk_sec;
    (void) alice_sk_sec;

    return 0;
}

int test_api_crypto_box_beforenm(void)
{
    /*
     * Test key agreement between alice and bob from predefined keys.
     */

    uint8_t expected_common[api_crypto_box_BEFORENMBYTES];

    VERIFY(api_crypto_box_beforenm(expected_common, alice_ek_pub, bob_ek_sec) == 0);
    VERIFY(memcmp(expected_common, ek_common, api_crypto_box_BEFORENMBYTES) == 0);

    VERIFY(api_crypto_box_beforenm(expected_common, bob_ek_pub, alice_ek_sec) == 0);
    VERIFY(memcmp(expected_common, ek_common, api_crypto_box_BEFORENMBYTES) == 0);


    /*
     * Test key agreement with generated keys.
     */

    uint8_t host_ek_pub[api_crypto_box_PUBLICKEYBYTES];
    uint8_t host_ek_sec[api_crypto_box_SECRETKEYBYTES];

    uint8_t client_ek_pub[api_crypto_box_PUBLICKEYBYTES];
    uint8_t client_ek_sec[api_crypto_box_SECRETKEYBYTES];

    uint8_t common1[api_crypto_box_BEFORENMBYTES];
    uint8_t common2[api_crypto_box_BEFORENMBYTES];

    VERIFY(api_crypto_box_keypair(host_ek_pub, host_ek_sec) == 0);
    VERIFY(api_crypto_box_keypair(client_ek_pub, client_ek_sec) == 0);
    VERIFY(api_crypto_box_beforenm(common1, host_ek_pub, client_ek_sec) == 0);
    VERIFY(api_crypto_box_beforenm(common2, client_ek_pub, host_ek_sec) == 0);
    VERIFY(memcmp(common1, common2, api_crypto_box_BEFORENMBYTES) == 0);

    return 0;
}

#if 0
#include <stdio.h>
void hexdump(uint8_t *ptr, uint32_t size)
{
    printf("0x");
    for (uint32_t i = 0; i < size; i++)
    {
        printf("%02x", ptr[i]);
    } printf("\r\n");
}

#define HEXDUMP(data) \
    do {    \
        printf("%s: ", #data);      \
        hexdump(data, sizeof(data));    \
    } while(0)
#endif

int test_api_crypto_box_afternm(void)
{
    int ret;

    uint8_t clear_text[42] = {
        /* Zero padded (32 bytes) message with
         * { 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd }
         */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
        0xdd, 0xdd
    };

    uint8_t expected_cipher[42] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x63, 0x62, 0xde, 0x1a, 0xd9, 0xf8, 0xe1, 0xa1,
        0x78, 0x09, 0x76, 0x8b, 0x75, 0xb5, 0xd0, 0xdf,
        0xdb, 0x0d, 0xff, 0xba, 0xb5, 0x1e, 0xc3, 0x19,
        0xf4, 0xe1
    };

    uint8_t calculated_cipher[42];

    uint8_t nonce[24] = { 0x00 };

    /* Tests with separated buffers for cipher and clear text */
    ret = api_crypto_box_afternm(calculated_cipher,
                                 clear_text,
                                 sizeof(clear_text),
                                 nonce,
                                 ek_common);

    VERIFY(0 == ret);

    VERIFY(memcmp(calculated_cipher, expected_cipher, 42) == 0);

    uint8_t calculated_clear_text[42];
    memset(calculated_clear_text, 0x00, api_crypto_box_BOXZEROBYTES);

    ret = api_crypto_box_open_afternm(calculated_clear_text,
                                      calculated_cipher,
                                      sizeof(clear_text),
                                      nonce,
                                      ek_common);

    VERIFY(0 == ret);
    VERIFY(memcmp(calculated_clear_text, clear_text, 42) == 0);

    nonce[0] = ~nonce[0];
    ret = api_crypto_box_open_afternm(calculated_clear_text,
                                      calculated_cipher,
                                      sizeof(clear_text),
                                      nonce,
                                      ek_common);

    VERIFY(0 != ret);
    nonce[0] = ~nonce[0];
    calculated_cipher[16] = ~calculated_cipher[16];
    ret = api_crypto_box_open_afternm(calculated_clear_text,
                                      calculated_cipher,
                                      sizeof(clear_text),
                                      nonce,
                                      ek_common);

    VERIFY(0 != ret);
    calculated_cipher[16] = ~calculated_cipher[16];


    /* Test in-place functionality decryption */
    ret = api_crypto_box_open_afternm(calculated_cipher,
                                      calculated_cipher,
                                      sizeof(clear_text),
                                      nonce,
                                      ek_common);

    VERIFY(0 == ret);
    VERIFY(memcmp(calculated_cipher, clear_text, 42) == 0);

    ret = api_crypto_box_afternm(clear_text,
                                 clear_text,
                                 sizeof(clear_text),
                                 nonce,
                                 ek_common);

    VERIFY(0 == ret);
    VERIFY(memcmp(clear_text, expected_cipher, 42) == 0);

    return 0;
}

/*======= Local function implementations ====================================*/
