#ifndef SALT_TEST_DATA_H
#define SALT_TEST_DATA_H

#include <stdint.h>

typedef struct salt_test_data_s {
    uint8_t client_sk_sec[64];
    uint8_t client_ek_sec[32];
    uint8_t client_ek_pub[32];
    uint8_t host_sk_sec[64];
    uint8_t host_ek_sec[32];
    uint8_t host_ek_pub[32];
    uint8_t a1[6];
    uint8_t a2[27];
    uint8_t m1[46];
    uint8_t m2[42];
    uint8_t m3[124];
    uint8_t m4[124];
    uint8_t msg1[34];
    uint8_t msg2[34];
} salt_test_data_t;

extern salt_test_data_t salt_test_data;

#endif /* SALT_TEST_DATA_H */
