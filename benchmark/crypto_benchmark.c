/**
 * @file crypto_benchmark.c
 *
 * Description
 *
 */

/*======= Includes ==========================================================*/

#include <string.h>
#include "salt.h"
#include "time_stamp.h"
#include "crypto_benchmark.h"

/*======= Local Macro Definitions ===========================================*/

#define NUM_ITERATIONS      1000
#define SHORT_MESSAGE_SIZE  20
#define LONG_MESSAGE_SIZE   1000
#define str(s) #s
#define xstr(s) str(s)

/*======= Type Definitions ==================================================*/
/*======= Local function prototypes =========================================*/
/*======= Local variable declarations =======================================*/

static bool crypto_hash_benchmark(time_stamps_t *stamps);
static bool crypto_sign_benchmark(time_stamps_t *stamps);
static bool crypto_box_benchmark(time_stamps_t *stamps);

/*======= Global function implementations ===================================*/

bool run_crypto_benchmark(time_stamps_t *stamps)
{

    if (!crypto_hash_benchmark(stamps)) {
        return false;
    }

    if (!crypto_sign_benchmark(stamps)) {
        return false;
    }

    if (!crypto_box_benchmark(stamps)) {
        return false;
    }

    return true;
}

/*======= Local function implementations ====================================*/

static bool crypto_hash_benchmark(time_stamps_t *stamps)
{
    int ret;
    uint8_t hash[api_crypto_hash_sha512_BYTES];
    uint8_t short_message[SHORT_MESSAGE_SIZE];

    STAMP_BEGIN(stamps, "api_crypto_hash_sha512, message size: " xstr(SHORT_MESSAGE_SIZE));
    for (uint16_t i = 0; i < NUM_ITERATIONS; i++) {
        ret = api_crypto_hash_sha512(hash, short_message, sizeof(short_message));
        if (ret != 0) {
            return false;
        }
    }
    STAMP_END(stamps, NUM_ITERATIONS);


    uint8_t long_message[LONG_MESSAGE_SIZE];

    STAMP_BEGIN(stamps, "api_crypto_hash_sha512, message size: " xstr(LONG_MESSAGE_SIZE));
    for (uint16_t i = 0; i < NUM_ITERATIONS; i++) {
        ret = api_crypto_hash_sha512(hash, long_message, sizeof(long_message));
        if (ret != 0) {
            return false;
        }
    }
    STAMP_END(stamps, NUM_ITERATIONS);

    return true;
}

static bool crypto_sign_benchmark(time_stamps_t *stamps)
{

    /* Signing keypair generation */
    int ret;
    uint8_t host_sk_pub[api_crypto_sign_PUBLICKEYBYTES];
    uint8_t host_sk_sec[api_crypto_sign_SECRETKEYBYTES];

    STAMP_BEGIN(stamps, "api_crypto_sign_keypair");
    for (uint16_t i = 0; i < NUM_ITERATIONS; i++) {
        ret = api_crypto_sign_keypair(host_sk_pub, host_sk_sec);
        if (ret != 0) {
            return false;
        }
    }
    STAMP_END(stamps, NUM_ITERATIONS);

    /* Signing a SHORT_MESSAGE_SIZE bytes long message */
    uint8_t message1[SHORT_MESSAGE_SIZE];
    uint8_t signed_message1[SHORT_MESSAGE_SIZE + api_crypto_sign_BYTES];
    STAMP_BEGIN(stamps, "api_crypto_sign, message size: " xstr(SHORT_MESSAGE_SIZE));
    for (uint16_t i = 0; i < NUM_ITERATIONS; i++) {
        ret = api_crypto_sign(signed_message1,
                              NULL, message1,
                              sizeof(message1),
                              host_sk_sec);
        if (ret != 0) {
            return false;
        }
    }
    STAMP_END(stamps, NUM_ITERATIONS);

    /* Verifying a SHORT_MESSAGE_SIZE bytes long message */
    uint8_t verified_message1[SHORT_MESSAGE_SIZE + api_crypto_sign_BYTES];
    STAMP_BEGIN(stamps, "api_crypto_sign_open, message size: " xstr(SHORT_MESSAGE_SIZE));
    for (uint16_t i = 0; i < NUM_ITERATIONS; i++) {
        ret = api_crypto_sign_open(verified_message1,
                                   NULL,
                                   signed_message1,
                                   sizeof(signed_message1),
                                   host_sk_pub);
        if (ret != 0) {
            return false;
        }
    }
    STAMP_END(stamps, NUM_ITERATIONS);



    /* Signing a LONG_MESSAGE_SIZE bytes long message */
    uint8_t message2[LONG_MESSAGE_SIZE];
    uint8_t signed_message2[LONG_MESSAGE_SIZE + api_crypto_sign_BYTES];
    STAMP_BEGIN(stamps, "api_crypto_sign, message size: " xstr(LONG_MESSAGE_SIZE));
    for (uint16_t i = 0; i < NUM_ITERATIONS; i++) {
        ret = api_crypto_sign(signed_message2,
                              NULL, message2,
                              sizeof(message2),
                              host_sk_sec);
        if (ret != 0) {
            return false;
        }
    }
    STAMP_END(stamps, NUM_ITERATIONS);

    /* Verifying a LONG_MESSAGE_SIZE bytes long message */
    uint8_t verified_message2[LONG_MESSAGE_SIZE + api_crypto_sign_BYTES];
    STAMP_BEGIN(stamps, "api_crypto_sign_open, message size: " xstr(LONG_MESSAGE_SIZE));
    for (uint16_t i = 0; i < NUM_ITERATIONS; i++) {
        ret = api_crypto_sign_open(verified_message2,
                                   NULL,
                                   signed_message2,
                                   sizeof(signed_message2),
                                   host_sk_pub);
        if (ret != 0) {
            return false;
        }
    }
    STAMP_END(stamps, NUM_ITERATIONS);


    /* Verifying a LONG_MESSAGE_SIZE bytes long message detached */
    STAMP_BEGIN(stamps, "api_crypto_sign_verify_detached, message size: " xstr(LONG_MESSAGE_SIZE));
    for (uint16_t i = 0; i < NUM_ITERATIONS; i++) {
        ret = api_crypto_sign_verify_detached(signed_message2,
                                   &signed_message2[api_crypto_sign_BYTES],
                                   sizeof(signed_message2) - api_crypto_sign_BYTES,
                                   host_sk_pub);
        if (ret != 0) {
            return false;
        }
    }
    STAMP_END(stamps, NUM_ITERATIONS);

    return true;
}

static bool crypto_box_benchmark(time_stamps_t *stamps)
{

    int ret;
    uint8_t host_ek_pub[api_crypto_box_PUBLICKEYBYTES];
    uint8_t host_ek_sec[api_crypto_box_SECRETKEYBYTES];
    uint8_t client_ek_pub[api_crypto_box_PUBLICKEYBYTES];
    uint8_t client_ek_sec[api_crypto_box_SECRETKEYBYTES];
    uint8_t common[api_crypto_box_BEFORENMBYTES];

    /* Ephemeral key pair generation */
    STAMP_BEGIN(stamps, "api_crypto_box_keypair");
    for (uint16_t i = 0; i < NUM_ITERATIONS; i++) {
        ret = api_crypto_box_keypair(host_ek_pub, host_ek_sec);
        if (ret != 0) {
            return false;
        }
    }
    STAMP_END(stamps, NUM_ITERATIONS);

    /* Generating a new one for calculating shared secret. */
    api_crypto_box_keypair(client_ek_pub, client_ek_sec);



    /* Calculating shared secret */
    STAMP_BEGIN(stamps, "api_crypto_box_beforenm");
    for (uint16_t i = 0; i < NUM_ITERATIONS; i++) {
        ret = api_crypto_box_beforenm(common, host_ek_pub, client_ek_sec);
        if (ret != 0) {
            return false;
        }
    }
    STAMP_END(stamps, NUM_ITERATIONS);


    /* Encrypt 20 bytes long message */
    uint8_t clear1[20 + api_crypto_box_ZEROBYTES];
    memset(clear1, 0x00, api_crypto_box_ZEROBYTES);
    uint8_t cipher1[20 + api_crypto_box_ZEROBYTES];
    uint8_t nonce1[24] = { 0x00 };
    STAMP_BEGIN(stamps, "api_crypto_box_afternm, message size: " xstr(SHORT_MESSAGE_SIZE));
    for (uint16_t i = 0; i < NUM_ITERATIONS; i++) {
        ret = api_crypto_box_afternm(cipher1, clear1, sizeof(clear1), nonce1, common);
        if (ret != 0) {
            return false;
        }
    }
    STAMP_END(stamps, NUM_ITERATIONS);

    /* Decrypt 20 bytes long message */
    STAMP_BEGIN(stamps, "api_crypto_box_open_afternm, message size: " xstr(SHORT_MESSAGE_SIZE));
    for (uint16_t i = 0; i < NUM_ITERATIONS; i++) {
        ret = api_crypto_box_open_afternm(clear1, cipher1, sizeof(clear1), nonce1, common);
        if (ret != 0) {
            return false;
        }
    }
    STAMP_END(stamps, NUM_ITERATIONS);


    /* Encrypt LONG_MESSAGE_SIZE bytes long message */
    uint8_t clear2[LONG_MESSAGE_SIZE + api_crypto_box_ZEROBYTES];
    memset(clear2, 0x00, api_crypto_box_ZEROBYTES);
    uint8_t cipher2[LONG_MESSAGE_SIZE + api_crypto_box_ZEROBYTES];
    uint8_t nonce2[24] = { 0x01 };
    STAMP_BEGIN(stamps, "api_crypto_box_afternm, message size: " xstr(LONG_MESSAGE_SIZE));
    for (uint16_t i = 0; i < NUM_ITERATIONS; i++) {
        ret = api_crypto_box_afternm(cipher2, clear2, sizeof(clear2), nonce2, common);
        if (ret != 0) {
            return false;
        }
    }
    STAMP_END(stamps, NUM_ITERATIONS);

    /* Decrypt LONG_MESSAGE_SIZE bytes long message */
    STAMP_BEGIN(stamps, "api_crypto_box_open_afternm, message size: " xstr(LONG_MESSAGE_SIZE));
    for (uint16_t i = 0; i < NUM_ITERATIONS; i++) {
        ret = api_crypto_box_open_afternm(clear2, cipher2, sizeof(clear2), nonce2, common);
        if (ret != 0) {
            return false;
        }
    }
    STAMP_END(stamps, NUM_ITERATIONS);

    return true;

}
