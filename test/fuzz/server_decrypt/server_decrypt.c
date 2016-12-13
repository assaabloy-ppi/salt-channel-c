#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include "../../../src/salt.h"
#include "../../../src/external/binson-c-light/binson_light.h"

static uint8_t rx_buffer[2052];
uint32_t revc_size;
uint8_t state = 0;

void randombytes(unsigned char *msg,unsigned long long len)
{

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

uint8_t shared_key[] = {
    0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 
    0x62, 0xcd, 0x51, 0x19, 0x7a, 0x9a, 0x46, 0xc7, 
    0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2, 
    0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89, 
};

int main(void)
{

    int ret_code = 0;
    salt_ret_t ret;

    memset(rx_buffer, 0, sizeof(rx_buffer));
    uint32_t size = read(0, &rx_buffer[4], sizeof(rx_buffer)-4);

    if (size < 4)
    {
        return ret_code;
    }

    memcpy(rx_buffer, &size, 4);


    /*for (uint8_t i = 0; i < size; i++)
    {
        printf("%02x", rx_buffer[i+4]);
    }
    printf("\r\n");*/

    uint8_t buffer[2048];

    salt_channel_t channel;


    ret = salt_init(&channel, buffer, sizeof(buffer), my_read, my_write);
    assert(ret == SALT_SUCCESS);

    uint8_t host_sec_key[64] = {0};
    salt_set_signature(&channel, host_sec_key);

    ret = salt_init_session(&channel, SALT_SERVER);
    assert(ret == SALT_SUCCESS);

    memcpy(channel.ek_common, shared_key, 32);
    channel.state = 8;

    ret = salt_handshake(&channel);

    return ret_code;

}

