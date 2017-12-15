#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "cfifo.h"
#include "salt.h"
#include "salti_util.h"

#include "salti_util.h"
#include "salt.h"
#include "salt_mock.h"
#include "test_data.h"

extern void my_randombytes(unsigned char *p_bytes, unsigned long long length);

static int setup(void **state) {
    salt_mock_t *mock = salt_mock_create();
    *state = mock;
    return (mock == NULL) ? -1 : 0;
}
static int teardown(void **state) {
    salt_mock_t *mock = (salt_mock_t *) *state;
    salt_mock_delete(mock);
    return 0;
}

static void multimessage(void **state)
{
    salt_mock_t *mock = (salt_mock_t *) *state;
    salt_channel_t  *host_channel = mock->host_channel;
    salt_channel_t  *client_channel = mock->client_channel;
    salt_ret_t      host_ret;
    salt_ret_t      client_ret;

    uint8_t host_buffer[SALT_HNDSHK_BUFFER_SIZE + 1U];
    uint8_t client_buffer[SALT_HNDSHK_BUFFER_SIZE + 1U];

    memset(host_buffer, 0xCC, sizeof(host_buffer));
    memset(client_buffer, 0xEE, sizeof(client_buffer));

    host_ret = salt_create_signature(host_channel);
    assert_true(host_ret == SALT_SUCCESS);
    host_ret = salt_init_session(host_channel, host_buffer, SALT_HNDSHK_BUFFER_SIZE);
    assert_true(host_ret == SALT_SUCCESS);

    client_ret = salt_create_signature(client_channel);
    assert_true(client_ret == SALT_SUCCESS);
    client_ret = salt_init_session(client_channel, client_buffer, SALT_HNDSHK_BUFFER_SIZE);
    assert_true(client_ret == SALT_SUCCESS);

    host_ret = SALT_PENDING;
    client_ret = SALT_PENDING;

    while ((host_ret | client_ret) != SALT_SUCCESS)
    {
        client_ret = salt_handshake(client_channel, NULL);
        assert_true(client_buffer[SALT_HNDSHK_BUFFER_SIZE] == 0xEE);
        assert_true(client_ret != SALT_ERROR);

        host_ret = salt_handshake(host_channel, NULL);
        assert_true(host_buffer[SALT_HNDSHK_BUFFER_SIZE] == 0xCC);
        assert_true(host_ret != SALT_ERROR);
    }

    assert_true(memcmp(host_channel->my_sk_pub, client_channel->peer_sk_pub, 32) == 0);
    assert_true(memcmp(host_channel->peer_sk_pub, client_channel->my_sk_pub, 32) == 0);

    //client_buffer
    salt_msg_t client_to_write;
    client_ret = salt_write_begin(client_buffer, sizeof(client_buffer), &client_to_write);
    assert_true(client_ret == SALT_SUCCESS);
    client_ret = salt_write_next(&client_to_write, (uint8_t *) "Client message 1", sizeof("Client message 1"));
    assert_true(client_ret == SALT_SUCCESS);
    client_ret = salt_write_next(&client_to_write, (uint8_t *) "Client message 2", sizeof("Client message 2"));
    assert_true(client_ret == SALT_SUCCESS);
    client_ret = salt_write_next(&client_to_write, (uint8_t *) "Client message 3", sizeof("Client message 3"));
    assert_true(client_ret == SALT_SUCCESS);
    client_ret = salt_write_next(&client_to_write, (uint8_t *) "Client message 4", sizeof("Client message 4"));
    assert_true(client_ret == SALT_SUCCESS);
    client_ret = SALT_PENDING;
    while (client_ret != SALT_SUCCESS) {
        client_ret = salt_write_execute(client_channel, &client_to_write, false);
        assert_true(client_ret != SALT_ERROR);
    }

    salt_msg_t host_to_read;
    host_ret = SALT_PENDING;
    while (host_ret != SALT_SUCCESS) {
        host_ret = salt_read_begin(host_channel, host_buffer, sizeof(host_buffer), &host_to_read);
        assert_true(host_ret != SALT_ERROR);
    }

    assert_true(host_to_read.read.messages_left == 3);
    assert_true(host_to_read.read.message_size == sizeof("Client message 1"));
    assert_true(memcmp("Client message 1", host_to_read.read.p_payload, sizeof("Client message 1")) == 0);

    host_ret = salt_read_next(&host_to_read);
    assert_true(host_ret == SALT_SUCCESS);
    assert_true(host_to_read.read.messages_left == 2);
    assert_true(host_to_read.read.message_size == sizeof("Client message 2"));
    assert_true(memcmp("Client message 2", host_to_read.read.p_payload, sizeof("Client message 2")) == 0);

    host_ret = salt_read_next(&host_to_read);
    assert_true(host_ret == SALT_SUCCESS);
    assert_true(host_to_read.read.messages_left == 1);
    assert_true(host_to_read.read.message_size == sizeof("Client message 3"));
    assert_true(memcmp("Client message 3", host_to_read.read.p_payload, sizeof("Client message 3")) == 0);

    host_ret = salt_read_next(&host_to_read);
    assert_true(host_ret == SALT_SUCCESS);
    assert_true(host_to_read.read.messages_left == 0);
    assert_true(host_to_read.read.message_size == sizeof("Client message 4"));
    assert_true(memcmp("Client message 4", host_to_read.read.p_payload, sizeof("Client message 4")) == 0);

    host_ret = salt_read_next(&host_to_read);
    assert_true(host_ret == SALT_ERROR);

}

int main(void) {
    salt_crypto_init(my_randombytes);
    
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(multimessage, setup, teardown),

    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
