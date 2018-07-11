#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "salt.h"
#include "util.h"
#include "test_data.h"

#define MAX_READ_SIZE 8192

static int _main(void) {

    salt_channel_t channel;
    salt_ret_t ret;
    uint8_t hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE + 1];
    memset(hndsk_buffer, 0xcc, sizeof(hndsk_buffer));

    salt_create(&channel, SALT_SERVER, fuzz_write, fuzz_read, &mock_time);
    salt_set_delay_threshold(&channel, 1000);
    salt_set_signature(&channel, salt_example_session_1_data.client_sk_sec);
    salt_init_session_using_key(&channel,
                                hndsk_buffer,
                                SALT_HNDSHK_BUFFER_SIZE,
                                salt_example_session_1_data.host_ek_pub,
                                salt_example_session_1_data.host_ek_sec);

    do {
        ret = salt_handshake(&channel, NULL);
    } while (ret == SALT_PENDING);

    assert(hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE] == 0xcc);
    
    if (ret == SALT_ERROR) {
        return -1;
    }

    salt_msg_t read_msg;

    uint16_t num_messages = 0;

    do {
        uint8_t *buffer = malloc(MAX_READ_SIZE);

        if (buffer == NULL) {
            return -1;
        }

        do {
            ret = salt_read_begin(&channel, buffer, MAX_READ_SIZE, &read_msg);
        } while (ret == SALT_PENDING);

        if (ret == SALT_SUCCESS) {
            
            do {
                printf("Message %d: ", num_messages);
                hexprint(read_msg.read.p_payload, read_msg.read.message_size);
                printf("\r\n");
                num_messages++;
            } while (salt_read_next(&read_msg) == SALT_SUCCESS);
            ret = SALT_SUCCESS;
        }

        free(buffer);
    } while (ret == SALT_SUCCESS);

    printf("err_code: 0x%02x\r\n", channel.err_code);
    if (channel.err_code == SALT_ERR_DELAY_DETECTED) {
        printf("delay detected.\r\n");
    }
    printf("num_messages: %d\r\n", num_messages);

    return (num_messages > 0 && channel.read_channel.err_code == SALT_ERR_CONNECTION_CLOSED) ? 0 : -1;
}

int main(void)
{
    #ifdef __AFL_LOOP
        while (__AFL_LOOP(1000))
        {
            _main();
        }
    #else
        return _main();
    #endif

    return 0;
}
