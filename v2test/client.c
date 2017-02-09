#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "test_data.h"

#include "../test/util.h"
#include "salt_v2.h"


void randombytes(unsigned char *p_bytes, unsigned long long length)
{
    /*FILE* fr = fopen("/dev/urandom", "r");
    if (!fr) perror("urandom"), exit(EXIT_FAILURE);
    fread(p_bytes, sizeof(unsigned char), length, fr);
    fclose(fr);*/
    memcpy(p_bytes, client_ek_sec, length);
}

salt_ret_t my_write(salt_io_channel_t *p_wchannel)
{
    static uint8_t i = 0;
    PRINT_BYTES_C(p_wchannel->p_data, p_wchannel->size);

    switch (i)
    {
        case 0:
            assert(p_wchannel->size == sizeof(m1));
            assert(memcmp(p_wchannel->p_data, m1, sizeof(m1)) == 0);
            break;
        case 1:
            assert(p_wchannel->size == sizeof(m4));
            assert(memcmp(p_wchannel->p_data, m4, sizeof(m4)) == 0);
            break;
        default:
            assert(0);
            break;

    }
    
    i++;
    
    return SALT_SUCCESS;
}

salt_ret_t my_read(salt_io_channel_t *p_rchannel)
{
    static uint8_t i = 0;
    switch (i)
    {
        case 0:
            memcpy(p_rchannel->p_data, m2, sizeof(m2));
            p_rchannel->size = sizeof(m2);
            break;
        case 1:
            memcpy(p_rchannel->p_data, m3, sizeof(m3));
            p_rchannel->size = sizeof(m3);
            break;
        default:
            assert(0);
            break;
    }

    i++;

    return SALT_SUCCESS;
}


int main(void)
{

    salt_channel_t channel;
    salt_ret_t ret;
    uint8_t hndsk_buffer[400];
    memset(hndsk_buffer, 0xcc, 400);

    ret = salt_create(&channel, SALT_CLIENT, my_write, my_read);
    ret = salt_set_signature(&channel, client_sk_sec);
    ret = salt_init_session(&channel, hndsk_buffer, 322);
    ret = salt_handshake(&channel);
    assert(ret == SALT_SUCCESS);
    PRINT_BYTES(&hndsk_buffer[322], 400-322);

    return 0;
}