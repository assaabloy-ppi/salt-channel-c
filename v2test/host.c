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
    memcpy(p_bytes, host_ek_sec, length);
}

salt_ret_t my_write(salt_io_channel_t *p_wchannel)
{
    static uint8_t i = 0;
    PRINT_BYTES(p_wchannel->p_data, p_wchannel->size);
    switch (i)
    {
        case 0:
            assert(p_wchannel->size == 34);
            assert(memcmp(&p_wchannel->p_data[2], host_ek_pub, 32) == 0);
            break;
        case 1:
            assert(p_wchannel->size == 114);
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
    p_rchannel->p_data[0] = 'S';
    p_rchannel->p_data[1] = '2';
    p_rchannel->p_data[2] = 0x00;
    p_rchannel->p_data[3] = 0x00;
    memcpy(&p_rchannel->p_data[4], client_ek_pub, 32);
    p_rchannel->size = 36;
    return SALT_SUCCESS;
}


int main(void)
{

    salt_channel_t channel;
    salt_ret_t ret;

    ret = salt_create(&channel, SALT_SERVER, my_write, my_read);
    ret = salt_set_signature(&channel, host_sk_sec);
    ret = salt_init_session(&channel);
    ret = salt_handshake(&channel);

    assert(ret == SALT_SUCCESS);

    return 0;
}