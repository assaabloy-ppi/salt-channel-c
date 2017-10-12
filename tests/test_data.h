#ifndef SALT_TEST_DATA_H
#define SALT_TEST_DATA_H

#include <stdint.h>

typedef struct salt_example_session_1_s {
    uint8_t client_sk_sec[64];
    uint8_t client_ek_sec[32];
    uint8_t client_ek_pub[32];
    uint8_t host_sk_sec[64];
    uint8_t host_ek_sec[32];
    uint8_t host_ek_pub[32];
    uint8_t m1[46];
    uint8_t m2[42];
    uint8_t m3[124];
    uint8_t m4[124];
    uint8_t msg1[34];
    uint8_t msg2[34];
} salt_example_session_1_t;

extern salt_example_session_1_t salt_example_session_1_data;

typedef struct salt_example_session_2_s {
    uint8_t client_sk_sec[64];
    uint8_t client_ek_sec[32];
    uint8_t client_ek_pub[32];
    uint8_t host_sk_sec[64];
    uint8_t host_ek_sec[32];
    uint8_t host_ek_pub[32];
    uint8_t a1[9];
    uint8_t a2[27];
} salt_example_session_2_t;

extern salt_example_session_2_t salt_example_session_2_data;

typedef struct salt_example_session_3_s {
    uint8_t client_sk_sec[64];
    uint8_t client_ek_sec[32];
    uint8_t client_ek_pub[32];
    uint8_t host_sk_sec[64];
    uint8_t host_ek_sec[32];
    uint8_t host_ek_pub[32];
    uint8_t m1[46];
    uint8_t m2[42];
    uint8_t m3[124];
    uint8_t m4[124];
    uint8_t msg1[34];
    uint8_t msg2[34];
    uint8_t msg3[43];
    uint8_t msg4[43];
    uint32_t host_time[8];
    uint32_t client_time[8];
} salt_example_session_3_t;

extern salt_example_session_3_t salt_example_session_3_data;


#endif /* SALT_TEST_DATA_H */
