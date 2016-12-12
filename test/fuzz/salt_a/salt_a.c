#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include "../../src/salt.h"

static uint8_t rx_buffer[2052];
uint32_t revc_size;
uint8_t state = 0;

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


void my_logf(char *format, ...)
{
  va_list args;
  va_start(args, format);
  vprintf(format, args);
  va_end(args);
}

uint8_t my_read(uint8_t *p_data, uint16_t length)
{
    switch (state)
    {
        case 0:
            memcpy(p_data, &rx_buffer[0], length);
            state = 1;
            break;
        case 1:
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



int main(void)
{

    int ret_code = 0;
   
    ssize_t size = read(0, rx_buffer, sizeof(rx_buffer));

    if (size < 4)
    {
        return ret_code;
    }

    static salt_channel_t *channel;
    SALT_CHANNEL_CREATE(&channel, 2048, my_read, my_write, my_logf);

    salt_init_session(channel);
    while (salt_handshake(channel) != SALT_ERROR)
    {

    }

    return ret_code;

}

