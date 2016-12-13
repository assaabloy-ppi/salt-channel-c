#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include "../../../src/salt.h"

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

int crypto_box_afternm(unsigned char *c,const unsigned char *m,unsigned long long d,const unsigned char *n,const unsigned char *k)
{
    return 0;
}

int crypto_box_open_afternm(unsigned char *m,const unsigned char *c,unsigned long long d,const unsigned char *n,const unsigned char *k)
{
    return 0;
}


salt_ret_t my_read(void *p_context, uint8_t *p_data, uint32_t length)
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

salt_ret_t my_write(void *p_context, uint8_t *p_data, uint32_t length)
{
    return SALT_ERROR;
}



int main(void)
{

    int ret_code = 0;
    salt_ret_t ret;
   
    uint32_t size = read(0, rx_buffer, sizeof(rx_buffer));

    if (size < 4)
    {
        return ret_code;
    }

    memcpy(rx_buffer, &size, 4);

    uint8_t buffer[2048];

    salt_channel_t channel;


    ret = salt_init(&channel, buffer, sizeof(buffer), my_read, my_write);
    assert(ret == SALT_SUCCESS);

    uint8_t host_sec_key[64] = {0};
    salt_set_signature(&channel, host_sec_key);

    ret = salt_init_session(&channel, SALT_SERVER);
    assert(ret == SALT_SUCCESS);

    ret = salt_handshake(&channel);

    return ret_code;

}

