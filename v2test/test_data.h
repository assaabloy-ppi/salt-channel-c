#ifndef SALT_V2_TEST_DATA_H
#define SALT_V2_TEST_DATA_H

#include <stdint.h>

extern uint8_t client_ek_sec[32];
extern uint8_t client_ek_pub[32];
extern uint8_t client_sk_sec[64];
extern uint8_t *client_sk_pub;


extern uint8_t host_ek_sec[32];
extern uint8_t host_ek_pub[32];
extern uint8_t host_sk_sec[64];
extern uint8_t *host_sk_pub;

extern uint8_t common_ek[32];

extern uint8_t m1[35];
extern uint8_t m2[33];
extern uint8_t m3[114];

#endif
