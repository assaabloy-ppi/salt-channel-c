#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include "../../pot-c/salt.h"

static uint8_t rx_buffer[2052];
uint32_t revc_size;
uint8_t state = 0;
/*
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk)
{
    return 0;
}
int crypto_sign(unsigned char *sm, unsigned long long *smlen_p,
                const unsigned char *m, unsigned long long mlen,
                const unsigned char *sk)
{
    return 0;
}
int crypto_sign_open(unsigned char *m, unsigned long long *mlen_p,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk)
{
    return 0;
}
int crypto_secretbox_open(unsigned char *m, const unsigned char *c,
                          unsigned long long clen, const unsigned char *n,
                          const unsigned char *k)
{
    return 0;
}
int crypto_secretbox(unsigned char *c, const unsigned char *m,
                     unsigned long long mlen, const unsigned char *n,
                     const unsigned char *k)
{
    return 0;
}
int crypto_box_keypair(unsigned char *pk, unsigned char *sk)
{
    return 0;
}
int crypto_box_beforenm(unsigned char *k, const unsigned char *pk,
                        const unsigned char *sk) {
    return 0;
}
*/

void my_logf(char *format, ...)
{
  va_list args;
  va_start(args, format);
  vprintf(format, args);
  va_end(args);
}

static salt_channel_t *channel;

uint8_t my_read(uint8_t *p_data, uint16_t length)
{

    switch (state)
    {
        case 0:
            memcpy(p_data, &rx_buffer[0], length);
            state = 1;
            break;
        case 1:
            channel->state = 0;
            memcpy(p_data, &rx_buffer[4], length);
            state = 2;
            break;
        case 2:
            return SALT_ERROR;
    }

    return SALT_SUCCESS;
}

uint8_t my_write(uint8_t *p_data, uint16_t length)
{
    return SALT_ERROR;
}

uint8_t my_ek_sec[] = {
    0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 
    0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6, 
    0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 
    0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb, 
};

uint8_t my_ek_pub[] = {
    0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 
    0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37, 
    0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 
    0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f, 
};



uint8_t peek_ek_pub[] = {
    0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 
    0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a, 
    0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 
    0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a, 
};

uint8_t shared_key[] = {
    0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 
    0x62, 0xcd, 0x51, 0x19, 0x7a, 0x9a, 0x46, 0xc7, 
    0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2, 
    0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89, 
};


int main(void)
{

    int ret_code = 0;
   
    ssize_t size = read(0, rx_buffer, sizeof(rx_buffer));

    if (size < 4)
    {
        return ret_code;
    }

    
    SALT_CHANNEL_CREATE(&channel, 2048, my_read, my_write, my_logf);

    salt_init_session(channel);
    channel->state = 0x05U; //SALTI_STATE_M4
    memcpy(channel->my_ek_sec, my_ek_sec, 32);
    memcpy(channel->my_ek_pub, my_ek_pub, 32);
    memcpy(channel->peer_ek_pub, peek_ek_pub, 32);
    memcpy(channel->shared_key, shared_key, 32);

    uint8_t rest_code = salt_handshake(channel);
    while (rest_code == SALT_PENDING)
    {
      rest_code = salt_handshake(channel);
    }

    return ret_code;

}

// \x10\x00\x00\x00\x00\x00\x00\x00\x\x50\x01\x00\x00\x00\x00\xff\xff\xff\x7f\x00\x00