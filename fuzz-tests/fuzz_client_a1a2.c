#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "salt.h"
#include "test_data.h"

#define MAX_READ_SIZE 8192

static uint8_t read_buf[MAX_READ_SIZE];

void randombytes(unsigned char *p_bytes, unsigned long long length)
{
    (void) p_bytes;
    (void) length;
}

salt_ret_t my_write(salt_io_channel_t *p_wchannel)
{
    p_wchannel->size = p_wchannel->size_expected;
    return SALT_SUCCESS;
}

salt_ret_t my_read(salt_io_channel_t *p_rchannel)
{
    
    uint32_t size;

    if (p_rchannel->size_expected > MAX_READ_SIZE)
    {
        return SALT_ERROR;
    }

    size = read(0, read_buf, p_rchannel->size_expected);
    if (size == 0) {
        return SALT_ERROR;
    }

    memcpy(p_rchannel->p_data, read_buf, size);
    p_rchannel->size += size;

    if (p_rchannel->size == p_rchannel->size_expected) {
        return SALT_SUCCESS;
    }

    return SALT_PENDING;

}
int main(void) {

    salt_channel_t channel;
    salt_ret_t ret;
    uint8_t hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE];
    memset(hndsk_buffer, 0xcc, sizeof(hndsk_buffer));

    salt_create(&channel, SALT_CLIENT, my_write, my_read, NULL);
    salt_set_signature(&channel, salt_example_session_1_data.client_sk_sec);
    salt_init_session_using_key(&channel,
                                hndsk_buffer,
                                SALT_HNDSHK_BUFFER_SIZE,
                                salt_example_session_1_data.client_ek_pub,
                                salt_example_session_1_data.client_ek_sec);
    salt_protocols_t host_protocols;
    

    do {
        ret = salt_a1a2(&channel, hndsk_buffer, SALT_HNDSHK_BUFFER_SIZE, &host_protocols, NULL);
    } while (ret == SALT_PENDING);

    if (ret == SALT_ERROR)
    {
        return -1;
    }
    
    for (uint8_t i = 0; i < host_protocols.count; i+= 2) {
        printf("Protocol %i: %*.*s\r\n", i, 0, (int) sizeof(salt_protocol_t), host_protocols.p_protocols[i+1]);
    }

    return 0;

}


