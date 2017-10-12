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

static void hostclient_session(void **state)
{
    salt_mock_t *mock = (salt_mock_t *) *state;
    salt_channel_t  *host_channel = mock->host_channel;
    salt_channel_t  *client_channel = mock->client_channel;
    salt_ret_t      host_ret;
    salt_ret_t      client_ret;
    salt_msg_t      host_msg;
    salt_msg_t      client_msg;

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

    uint8_t host_message[16];
    uint8_t client_message[16];

    memset(host_message, 0x13, sizeof(host_message));
    memset(client_message, 0x23, sizeof(client_message));

    /* Test single app package */
    client_ret = salt_write_begin(client_buffer, sizeof(client_buffer), &client_msg);
    assert_true(SALT_SUCCESS == client_ret);
    client_ret = salt_write_next(&client_msg, client_message, sizeof(client_message));
    assert_true(SALT_SUCCESS == client_ret);
    do {
        client_ret = salt_write_execute(client_channel, &client_msg, false);
    } while (client_ret == SALT_PENDING);

    /* Test multi app package */
    client_ret = salt_write_begin(client_buffer, sizeof(client_buffer), &client_msg);
    assert_true(SALT_SUCCESS == client_ret);
    client_ret = salt_write_next(&client_msg, client_message, 1);
    assert_true(SALT_SUCCESS == client_ret);
    client_ret = salt_write_next(&client_msg, client_message, 2);
    assert_true(SALT_SUCCESS == client_ret);
    client_ret = salt_write_next(&client_msg, client_message, 10);
    assert_true(SALT_SUCCESS == client_ret);
    client_ret = salt_write_next(&client_msg, client_message, 7);
    assert_true(SALT_SUCCESS == client_ret);
    client_ret = salt_write_next(&client_msg, client_message, 16);
    assert_true(SALT_SUCCESS == client_ret);
    do {
        client_ret = salt_write_execute(client_channel, &client_msg, false);
    } while (client_ret == SALT_PENDING);

    /* Host reads first message */
    do {
        host_ret = salt_read_begin(host_channel, host_buffer, sizeof(host_buffer), &host_msg);
    } while (host_ret == SALT_PENDING);

    assert_true(host_ret == SALT_SUCCESS);
    assert_int_equal(16, host_msg.read.message_size);

    /* Host reads next messages */
    do {
        host_ret = salt_read_begin(host_channel, host_buffer, sizeof(host_buffer), &host_msg);
    } while (host_ret == SALT_PENDING);

    assert_true(host_ret == SALT_SUCCESS);
    assert_int_equal(4, host_msg.read.messages_left);
    assert_int_equal(1, host_msg.read.message_size);
    assert_memory_equal(host_msg.read.p_payload, client_message, host_msg.read.message_size);

    host_ret = salt_read_next(&host_msg);
    assert_true(host_ret == SALT_SUCCESS);
    assert_int_equal(3, host_msg.read.messages_left);
    assert_int_equal(2, host_msg.read.message_size);
    assert_memory_equal(host_msg.read.p_payload, client_message, host_msg.read.message_size);

    host_ret = salt_read_next(&host_msg);
    assert_true(host_ret == SALT_SUCCESS);
    assert_int_equal(2, host_msg.read.messages_left);
    assert_int_equal(10, host_msg.read.message_size);
    assert_memory_equal(host_msg.read.p_payload, client_message, host_msg.read.message_size);

    host_ret = salt_read_next(&host_msg);
    assert_true(host_ret == SALT_SUCCESS);
    assert_int_equal(1, host_msg.read.messages_left);
    assert_int_equal(7, host_msg.read.message_size);
    assert_memory_equal(host_msg.read.p_payload, client_message, host_msg.read.message_size);

    host_ret = salt_read_next(&host_msg);
    assert_true(host_ret == SALT_SUCCESS);
    assert_int_equal(0, host_msg.read.messages_left);
    assert_int_equal(16, host_msg.read.message_size);
    assert_memory_equal(host_msg.read.p_payload, client_message, host_msg.read.message_size);

    host_ret = salt_read_next(&host_msg);
    assert_true(host_ret == SALT_ERROR);

    /* Test single app package */
    host_ret = salt_write_begin(host_buffer, sizeof(host_buffer), &host_msg);
    assert_true(SALT_SUCCESS == host_ret);
    host_ret = salt_write_next(&host_msg, host_message, sizeof(host_message));
    assert_true(SALT_SUCCESS == host_ret);
    do {
        host_ret = salt_write_execute(host_channel, &host_msg, false);
    } while (host_ret == SALT_PENDING);

    /* Test multi app package */
    host_ret = salt_write_begin(host_buffer, sizeof(host_buffer), &host_msg);
    assert_true(SALT_SUCCESS == host_ret);
    host_ret = salt_write_next(&host_msg, host_message, 1);
    assert_true(SALT_SUCCESS == host_ret);
    host_ret = salt_write_next(&host_msg, host_message, 2);
    assert_true(SALT_SUCCESS == host_ret);
    host_ret = salt_write_next(&host_msg, host_message, 10);
    assert_true(SALT_SUCCESS == host_ret);
    host_ret = salt_write_next(&host_msg, host_message, 7);
    assert_true(SALT_SUCCESS == host_ret);
    host_ret = salt_write_next(&host_msg, host_message, 16);
    assert_true(SALT_SUCCESS == host_ret);
    do {
        host_ret = salt_write_execute(host_channel, &host_msg, false);
    } while (host_ret == SALT_PENDING);

    /* Host reads first message */
    do {
        client_ret = salt_read_begin(client_channel, client_buffer, sizeof(client_buffer), &client_msg);
    } while (client_ret == SALT_PENDING);

    assert_true(client_ret == SALT_SUCCESS);
    assert_int_equal(16, client_msg.read.message_size);

    /* Host reads next messages */
    do {
        client_ret = salt_read_begin(client_channel, client_buffer, sizeof(client_buffer), &client_msg);
    } while (client_ret == SALT_PENDING);

    assert_true(client_ret == SALT_SUCCESS);
    assert_int_equal(4, client_msg.read.messages_left);
    assert_int_equal(1, client_msg.read.message_size);
    assert_memory_equal(client_msg.read.p_payload, host_message, client_msg.read.message_size);

    client_ret = salt_read_next(&client_msg);
    assert_true(client_ret == SALT_SUCCESS);
    assert_int_equal(3, client_msg.read.messages_left);
    assert_int_equal(2, client_msg.read.message_size);
    assert_memory_equal(client_msg.read.p_payload, host_message, client_msg.read.message_size);

    client_ret = salt_read_next(&client_msg);
    assert_true(client_ret == SALT_SUCCESS);
    assert_int_equal(2, client_msg.read.messages_left);
    assert_int_equal(10, client_msg.read.message_size);
    assert_memory_equal(client_msg.read.p_payload, host_message, client_msg.read.message_size);

    client_ret = salt_read_next(&client_msg);
    assert_true(client_ret == SALT_SUCCESS);
    assert_int_equal(1, client_msg.read.messages_left);
    assert_int_equal(7, client_msg.read.message_size);
    assert_memory_equal(client_msg.read.p_payload, host_message, client_msg.read.message_size);

    client_ret = salt_read_next(&client_msg);
    assert_true(client_ret == SALT_SUCCESS);
    assert_int_equal(0, client_msg.read.messages_left);
    assert_int_equal(16, client_msg.read.message_size);
    assert_memory_equal(client_msg.read.p_payload, host_message, client_msg.read.message_size);

    client_ret = salt_read_next(&client_msg);
    assert_true(client_ret == SALT_ERROR);

}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(hostclient_session, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
