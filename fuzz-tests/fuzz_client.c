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
    if (size == 0 || size > p_rchannel->size_expected) {
        return SALT_ERROR;
    }

    memcpy(p_rchannel->p_data, read_buf, p_rchannel->size_expected);
    p_rchannel->size = p_rchannel->size_expected;

    return SALT_SUCCESS;

}

int main(void) {

    salt_channel_t channel;
    salt_ret_t ret;
    uint8_t hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE + 1];
    memset(hndsk_buffer, 0xcc, sizeof(hndsk_buffer));

    salt_create(&channel, SALT_CLIENT, my_write, my_read, NULL);
    salt_set_signature(&channel, salt_example_session_1_data.client_sk_sec);
    salt_init_session_using_key(&channel,
                                hndsk_buffer,
                                SALT_HNDSHK_BUFFER_SIZE,
                                salt_example_session_1_data.client_ek_pub,
                                salt_example_session_1_data.client_ek_sec);

    do {
        ret = salt_handshake(&channel, NULL);
    } while (ret == SALT_PENDING);

    assert(hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE] == 0xcc);
    
    if (ret == SALT_ERROR) {
        return -1;
    }

    salt_msg_t read_msg;

    uint8_t *buffer = malloc(MAX_READ_SIZE);

    if (buffer == NULL) {
        return -1;
    }

    do {
        ret = salt_read_begin(&channel, buffer, MAX_READ_SIZE, &read_msg);
    } while (ret == SALT_PENDING);

    if (ret == SALT_SUCCESS) {
        uint16_t num_messages = 1;
        do {
            printf("Message %d: ", num_messages);
            for (uint32_t i = 0; i < read_msg.read.message_size; i++) {
                printf("%02x", read_msg.read.p_payload[i]);
            }
            num_messages++;
        } while (salt_read_next(&read_msg) == SALT_SUCCESS);
        ret = SALT_SUCCESS;
    }

    free(buffer);

    return (ret == SALT_SUCCESS) ? 0 : -1;
}


