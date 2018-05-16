#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdint.h>

#include "salt_crypto_wrapper.h"

#ifndef USE_SODIUM
void randombytes(unsigned char *p_bytes, unsigned long long length)
{
    FILE* fr = fopen("/dev/urandom", "r");

    if (fr != NULL) {
        size_t tmp = 0;
        if (p_bytes != NULL) {
            tmp = fread(p_bytes, sizeof(unsigned char), length, fr);
        }
        fclose(fr);
        assert_true(tmp == length);
        return;
    }
    
}
#endif

static uint8_t signed_data[187] = { /* 0x5fc0d0e476aaf6e62a8b89ad53f728aa29aa810cbf356cc19e37aa027c3354949339858b36b76d1b06293e4f9a3b1953a7ee5867af2c045b02ff58df456aed05401401611801001402667218205529ce8ccf68c0b8ac19d437ab0f5b32723782608e93c6264f184ba152c2357b1401704218010b14026c754314027463180c500100000000ffffff7f00001402746e1403426f621402746f182007e28d4ee32bfdc4b07d41c92193c0c25ee6b3094c6296f373413b373d36168b41 */
    0x5f, 0xc0, 0xd0, 0xe4, 0x76, 0xaa, 0xf6, 0xe6,
    0x2a, 0x8b, 0x89, 0xad, 0x53, 0xf7, 0x28, 0xaa,
    0x29, 0xaa, 0x81, 0x0c, 0xbf, 0x35, 0x6c, 0xc1,
    0x9e, 0x37, 0xaa, 0x02, 0x7c, 0x33, 0x54, 0x94,
    0x93, 0x39, 0x85, 0x8b, 0x36, 0xb7, 0x6d, 0x1b,
    0x06, 0x29, 0x3e, 0x4f, 0x9a, 0x3b, 0x19, 0x53,
    0xa7, 0xee, 0x58, 0x67, 0xaf, 0x2c, 0x04, 0x5b,
    0x02, 0xff, 0x58, 0xdf, 0x45, 0x6a, 0xed, 0x05,
    0x40, 0x14, 0x01, 0x61, 0x18, 0x01, 0x00, 0x14,
    0x02, 0x66, 0x72, 0x18, 0x20, 0x55, 0x29, 0xce,
    0x8c, 0xcf, 0x68, 0xc0, 0xb8, 0xac, 0x19, 0xd4,
    0x37, 0xab, 0x0f, 0x5b, 0x32, 0x72, 0x37, 0x82,
    0x60, 0x8e, 0x93, 0xc6, 0x26, 0x4f, 0x18, 0x4b,
    0xa1, 0x52, 0xc2, 0x35, 0x7b, 0x14, 0x01, 0x70,
    0x42, 0x18, 0x01, 0x0b, 0x14, 0x02, 0x6c, 0x75,
    0x43, 0x14, 0x02, 0x74, 0x63, 0x18, 0x0c, 0x50,
    0x01, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
    0x7f, 0x00, 0x00, 0x14, 0x02, 0x74, 0x6e, 0x14,
    0x03, 0x42, 0x6f, 0x62, 0x14, 0x02, 0x74, 0x6f,
    0x18, 0x20, 0x07, 0xe2, 0x8d, 0x4e, 0xe3, 0x2b,
    0xfd, 0xc4, 0xb0, 0x7d, 0x41, 0xc9, 0x21, 0x93,
    0xc0, 0xc2, 0x5e, 0xe6, 0xb3, 0x09, 0x4c, 0x62,
    0x96, 0xf3, 0x73, 0x41, 0x3b, 0x37, 0x3d, 0x36,
    0x16, 0x8b, 0x41
};

static uint8_t sk_pub[32] = { /* 5529ce8ccf68c0b8ac19d437ab0f5b32723782608e93c6264f184ba152c2357b*/
    0x55, 0x29, 0xce, 0x8c, 0xcf, 0x68, 0xc0, 0xb8,
    0xac, 0x19, 0xd4, 0x37, 0xab, 0x0f, 0x5b, 0x32,
    0x72, 0x37, 0x82, 0x60, 0x8e, 0x93, 0xc6, 0x26,
    0x4f, 0x18, 0x4b, 0xa1, 0x52, 0xc2, 0x35, 0x7b
};


static void test_sign_open(void **state)
{
    uint8_t signed_msg[sizeof(signed_data)];
    memcpy(signed_msg, signed_data, sizeof(signed_data));
    uint8_t tmp[512];
    assert_int_equal(api_crypto_sign_open(
                         tmp,
                         NULL,
                         signed_msg,
                         sizeof(signed_msg),
                         sk_pub), 0);

    signed_msg[64] = ~signed_msg[64];

    assert_int_not_equal(api_crypto_sign_open(
                             tmp,
                             NULL,
                             signed_msg,
                             sizeof(signed_msg),
                             sk_pub), 0);

}

static void test_hash_state(void **state)
{

    uint8_t tweet_hash[64];
    api_crypto_hash_sha512(tweet_hash, signed_data, sizeof(signed_data));

    uint8_t sodium_hash[64];
    uint8_t hash_state[208];
    assert_int_equal(api_crypto_hash_sha512_init(hash_state, sizeof(hash_state)), 0);
    assert_int_equal(api_crypto_hash_sha512_update(hash_state, signed_data, sizeof(signed_data)), 0);
    assert_int_equal(api_crypto_hash_sha512_final(hash_state, sodium_hash), 0);

    assert_memory_equal(tweet_hash, sodium_hash, 64);
}


static void test_sign_open_detached(void **state)
{
    uint8_t signed_msg[sizeof(signed_data)];
    memcpy(signed_msg, signed_data, sizeof(signed_data));
    assert_int_equal(api_crypto_sign_verify_detached(signed_msg,
                     &signed_msg[64],
                     sizeof(signed_msg) - 64,
                     sk_pub), 0);

    /* Modify one byte of message. */
    signed_msg[64] = ~signed_msg[64];

    assert_int_not_equal(api_crypto_sign_verify_detached(signed_msg,
                         &signed_msg[64],
                         sizeof(signed_msg) - 64,
                         sk_pub), 0);

}

static void open_and_detached(void **state) {

    uint8_t signature_and_data[82] = { /* cfff45c2397b0a107c6d6424d0f4832af905d64143bc8c4fdf755857e4d1d0617ac5cd52e2f9fe2cbd56f2dc265d8b995dbee10cbb5b8e13d772e064d28166034014076d657373616765140548656c6c6f41*/
        0xcf, 0xff, 0x45, 0xc2, 0x39, 0x7b, 0x0a, 0x10,
        0x7c, 0x6d, 0x64, 0x24, 0xd0, 0xf4, 0x83, 0x2a,
        0xf9, 0x05, 0xd6, 0x41, 0x43, 0xbc, 0x8c, 0x4f,
        0xdf, 0x75, 0x58, 0x57, 0xe4, 0xd1, 0xd0, 0x61,
        0x7a, 0xc5, 0xcd, 0x52, 0xe2, 0xf9, 0xfe, 0x2c,
        0xbd, 0x56, 0xf2, 0xdc, 0x26, 0x5d, 0x8b, 0x99,
        0x5d, 0xbe, 0xe1, 0x0c, 0xbb, 0x5b, 0x8e, 0x13,
        0xd7, 0x72, 0xe0, 0x64, 0xd2, 0x81, 0x66, 0x03,
        0x40, 0x14, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61,
        0x67, 0x65, 0x14, 0x05, 0x48, 0x65, 0x6c, 0x6c,
        0x6f, 0x41
    };
    uint8_t data[sizeof(signature_and_data)];
    uint8_t pub[32] = { /* 73b5a24e61aeaffddbabed3eaca86ab20681e9734994a10f16ad0f60dcd5d355*/
        0x73, 0xb5, 0xa2, 0x4e, 0x61, 0xae, 0xaf, 0xfd,
        0xdb, 0xab, 0xed, 0x3e, 0xac, 0xa8, 0x6a, 0xb2,
        0x06, 0x81, 0xe9, 0x73, 0x49, 0x94, 0xa1, 0x0f,
        0x16, 0xad, 0x0f, 0x60, 0xdc, 0xd5, 0xd3, 0x55
    };

    uint8_t tmp_pub[32];
    memcpy(tmp_pub, pub, sizeof(pub));
    uint8_t tmp_msg[sizeof(signature_and_data)];
    memcpy(tmp_msg, signature_and_data, sizeof(signature_and_data));

    assert_int_equal(api_crypto_sign_open(
                         data,
                         NULL,
                         signature_and_data,
                         sizeof(signature_and_data),
                         pub), 0);

    assert_memory_equal(tmp_msg, signature_and_data, sizeof(signature_and_data));
    assert_memory_equal(tmp_pub, pub, sizeof(pub));

    assert_int_equal(api_crypto_sign_verify_detached(signature_and_data,
                     &signature_and_data[64],
                     sizeof(signature_and_data) - 64,
                     pub), 0);
}

#if 0
static void sign_detached(void **state)
{

    uint8_t sk_sec[64] = {
        0x55, 0xf4, 0xd1, 0xd1, 0x98, 0x09, 0x3c, 0x84,
        0xde, 0x9e, 0xe9, 0xa6, 0x29, 0x9e, 0x0f, 0x68,
        0x91, 0xc2, 0xe1, 0xd0, 0xb3, 0x69, 0xef, 0xb5,
        0x92, 0xa9, 0xe3, 0xf1, 0x69, 0xfb, 0x0f, 0x79,
        0x55, 0x29, 0xce, 0x8c, 0xcf, 0x68, 0xc0, 0xb8,
        0xac, 0x19, 0xd4, 0x37, 0xab, 0x0f, 0x5b, 0x32,
        0x72, 0x37, 0x82, 0x60, 0x8e, 0x93, 0xc6, 0x26,
        0x4f, 0x18, 0x4b, 0xa1, 0x52, 0xc2, 0x35, 0x7b
    };
    uint8_t sig[64];
    unsigned long long siglen;
    assert_int_equal(api_crypto_sign_detached(sig,
        &siglen, &signed_data[64], sizeof(signed_data)-64, sk_sec), 0);

    assert_memory_equal(sig, signed_data, sizeof(sig));


    uint8_t sec[64];
    uint8_t pub[32];

    uint8_t data[128];
    uint8_t data_and_signature[128 + 64];
    uint8_t signature[64];

    for (uint8_t i = 0; i < 100; i++)
    {
        api_crypto_sign_keypair(pub, sec);
        memset(data, i, sizeof(data));
        siglen = 128;
        unsigned long long siglen_;
        assert_int_equal(api_crypto_sign(data_and_signature, 
            &siglen_, data, sizeof(data), sec), 0);

        assert_int_equal(api_crypto_sign_detached(signature,
            &siglen, data, sizeof(data), sec), 0);

        assert_memory_equal(signature, data_and_signature, sizeof(signature));

    }

}
#endif

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_sign_open),
        cmocka_unit_test(test_hash_state),
        cmocka_unit_test(test_sign_open_detached),
        cmocka_unit_test(open_and_detached),
        //cmocka_unit_test(sign_detached)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

