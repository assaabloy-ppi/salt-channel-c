#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "test_data.c"

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

    assert(host_write_counter + p_wchannel->size_expected <= sizeof(host_write_buffer));

    if (memcmp(&host_write_buffer[host_write_counter], p_wchannel->p_data, p_wchannel->size_expected) != 0)
    {
        PRINT_BYTES_C(p_wchannel->p_data, p_wchannel->size_expected);
        PRINT_BYTES_C(&host_write_buffer[host_write_counter], p_wchannel->size_expected);
        assert(0);
    }
    
    p_wchannel->size = p_wchannel->size_expected;
    host_write_counter += p_wchannel->size;
    
    return SALT_SUCCESS;
}

salt_ret_t my_read(salt_io_channel_t *p_rchannel)
{

    assert(p_rchannel->size_expected <= (sizeof(host_read_buffer) - host_read_counter));
    memcpy(p_rchannel->p_data, &host_read_buffer[host_read_counter], p_rchannel->size_expected);
    p_rchannel->size = p_rchannel->size_expected;
    host_read_counter += p_rchannel->size;

    return SALT_SUCCESS;
}


int main(void)
{

    init_salt_test_data();

    salt_channel_t channel;
    salt_ret_t ret;
    uint8_t hndsk_buffer[400];
    memset(hndsk_buffer, 0xcc, 400);

    ret = salt_create(&channel, SALT_SERVER, my_write, my_read);
    ret = salt_set_signature(&channel, host_sk_sec);
    ret = salt_init_session(&channel, hndsk_buffer, SALT_HNDSHK_BUFFER_SIZE);
    ret = salt_handshake(&channel);
    for (uint32_t i = SALT_HNDSHK_BUFFER_SIZE; i < sizeof(hndsk_buffer); i++)
    {
        assert(hndsk_buffer[i] == 0xcc);
    }
    assert(ret == SALT_SUCCESS);

    return 0;
}