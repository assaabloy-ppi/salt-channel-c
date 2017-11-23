#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

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

static void host_client_session_handshake(void **state)
{

    salt_mock_t *mock = (salt_mock_t *) *state;

    uint8_t host_buffer[SALT_HNDSHK_BUFFER_SIZE];
    memset(host_buffer, 0x00, sizeof(host_buffer));
    uint8_t client_buffer[SALT_HNDSHK_BUFFER_SIZE];
    memset(client_buffer, 0x00, sizeof(client_buffer));

    salt_ret_t client_ret;
    salt_ret_t host_ret;

    client_ret = salt_create_signature(mock->client_channel);
    assert_int_equal(SALT_SUCCESS, client_ret);
    client_ret = salt_init_session(mock->client_channel, client_buffer, SALT_HNDSHK_BUFFER_SIZE);
    assert_int_equal(SALT_SUCCESS, client_ret);

    host_ret = salt_create_signature(mock->host_channel);
    assert_int_equal(SALT_SUCCESS, host_ret);
    host_ret = salt_init_session(mock->host_channel, host_buffer, SALT_HNDSHK_BUFFER_SIZE);
    assert_int_equal(SALT_SUCCESS, host_ret);

    host_ret = SALT_PENDING;
    client_ret = SALT_PENDING;

    uint32_t timeout = 0;

    while (host_ret == SALT_PENDING && client_ret == SALT_PENDING)
    {
        if (client_ret == SALT_PENDING) {
            client_ret = salt_handshake(mock->client_channel, NULL);
            assert_int_not_equal(SALT_ERROR, client_ret);
        }

        if (host_ret == SALT_PENDING) {
            host_ret = salt_handshake(mock->host_channel, NULL);
            assert_int_not_equal(SALT_ERROR, host_ret);
        }
        timeout++;
        assert_true(timeout < 1000);

    }

    assert_memory_equal(mock->client_channel->peer_sk_pub,
                        mock->host_channel->my_sk_pub, 32);

    assert_memory_equal(mock->host_channel->peer_sk_pub,
                        mock->client_channel->my_sk_pub, 32);

}

static void host_client_session_handshake_with(void **state)
{

    salt_mock_t *mock = (salt_mock_t *) *state;

    uint8_t host_buffer[SALT_HNDSHK_BUFFER_SIZE];
    memset(host_buffer, 0x00, sizeof(host_buffer));
    uint8_t client_buffer[SALT_HNDSHK_BUFFER_SIZE];
    memset(client_buffer, 0x00, sizeof(client_buffer));

    salt_ret_t client_ret;
    salt_ret_t host_ret;

    client_ret = salt_create_signature(mock->client_channel);
    assert_int_equal(SALT_SUCCESS, client_ret);
    client_ret = salt_init_session(mock->client_channel, client_buffer, SALT_HNDSHK_BUFFER_SIZE);
    assert_int_equal(SALT_SUCCESS, client_ret);

    host_ret = salt_create_signature(mock->host_channel);
    assert_int_equal(SALT_SUCCESS, host_ret);
    host_ret = salt_init_session(mock->host_channel, host_buffer, SALT_HNDSHK_BUFFER_SIZE);
    assert_int_equal(SALT_SUCCESS, host_ret);

    host_ret = SALT_PENDING;
    client_ret = SALT_PENDING;

    uint32_t timeout = 0;

    while (host_ret == SALT_PENDING && client_ret == SALT_PENDING)
    {
        if (client_ret == SALT_PENDING) {
            client_ret = salt_handshake(mock->client_channel, mock->host_channel->my_sk_pub);
            assert_int_not_equal(SALT_ERROR, client_ret);
        }

        if (host_ret == SALT_PENDING) {
            host_ret = salt_handshake(mock->host_channel, NULL);
            assert_int_not_equal(SALT_ERROR, host_ret);
        }

        timeout++;

        assert_true(timeout < 1000);

    }

    assert_memory_equal(mock->client_channel->peer_sk_pub,
                        mock->host_channel->my_sk_pub, 32);

    assert_memory_equal(mock->host_channel->peer_sk_pub,
                        mock->client_channel->my_sk_pub, 32);

}

static void host_client_session_handshake_bad_peer(void **state)
{

    salt_mock_t *mock = (salt_mock_t *) *state;

    uint8_t host_buffer[SALT_HNDSHK_BUFFER_SIZE];
    memset(host_buffer, 0x00, sizeof(host_buffer));
    uint8_t client_buffer[SALT_HNDSHK_BUFFER_SIZE];
    memset(client_buffer, 0x00, sizeof(client_buffer));

    salt_ret_t client_ret;
    salt_ret_t host_ret;

    client_ret = salt_create_signature(mock->client_channel);
    assert_int_equal(SALT_SUCCESS, client_ret);
    client_ret = salt_init_session(mock->client_channel, client_buffer, SALT_HNDSHK_BUFFER_SIZE);
    assert_int_equal(SALT_SUCCESS, client_ret);

    host_ret = salt_create_signature(mock->host_channel);
    assert_int_equal(SALT_SUCCESS, host_ret);
    host_ret = salt_init_session(mock->host_channel, host_buffer, SALT_HNDSHK_BUFFER_SIZE);
    assert_int_equal(SALT_SUCCESS, host_ret);

    host_ret = SALT_PENDING;
    client_ret = SALT_PENDING;

    uint8_t dummy[32];
    memcpy(dummy, mock->client_channel, 32);
    dummy[5] += 1;
    uint32_t timeout = 0;

    while (host_ret == SALT_PENDING && client_ret == SALT_PENDING)
    {
        if (client_ret == SALT_PENDING) {
            client_ret = salt_handshake(mock->client_channel, NULL);
            assert_int_not_equal(SALT_ERROR, client_ret);
        }

        if (host_ret == SALT_PENDING) {
            host_ret = salt_handshake(mock->host_channel, dummy);
        }

        timeout++;
        assert_true(timeout < 1000);

    }

    assert_int_equal(host_ret, SALT_ERROR);
    assert_int_equal(mock->host_channel->err_code, SALT_ERR_BAD_PEER);

}

static void host_client_session_handshake_with_no_such(void **state)
{

    salt_mock_t *mock = (salt_mock_t *) *state;

    uint8_t host_buffer[SALT_HNDSHK_BUFFER_SIZE];
    memset(host_buffer, 0x00, sizeof(host_buffer));
    uint8_t client_buffer[SALT_HNDSHK_BUFFER_SIZE];
    memset(client_buffer, 0x00, sizeof(client_buffer));

    salt_ret_t client_ret;
    salt_ret_t host_ret;

    client_ret = salt_create_signature(mock->client_channel);
    assert_int_equal(SALT_SUCCESS, client_ret);
    client_ret = salt_init_session(mock->client_channel, client_buffer, SALT_HNDSHK_BUFFER_SIZE);
    assert_int_equal(SALT_SUCCESS, client_ret);

    host_ret = salt_create_signature(mock->host_channel);
    assert_int_equal(SALT_SUCCESS, host_ret);
    host_ret = salt_init_session(mock->host_channel, host_buffer, SALT_HNDSHK_BUFFER_SIZE);
    assert_int_equal(SALT_SUCCESS, host_ret);

    host_ret = SALT_PENDING;
    client_ret = SALT_PENDING;

    uint8_t dummy[32];
    memcpy(dummy, mock->host_channel->my_sk_pub, 32);
    dummy[5] += 1;
    uint32_t timeout = 0;

    while (host_ret == SALT_PENDING && client_ret == SALT_PENDING)
    {
        if (client_ret == SALT_PENDING) {
            client_ret = salt_handshake(mock->client_channel, dummy);
        }

        if (host_ret == SALT_PENDING) {
            host_ret = salt_handshake(mock->host_channel, NULL);
        }

        timeout++;
        assert_true(timeout < 1000);

    }

    while (client_ret == SALT_PENDING) {
        client_ret = salt_handshake(mock->client_channel, dummy);
    }

    while (host_ret == SALT_PENDING) {
        host_ret = salt_handshake(mock->host_channel, NULL);
    }

    assert_int_equal(host_ret, SALT_ERROR);
    assert_int_equal(client_ret, SALT_ERROR);
    assert_int_equal(mock->client_channel->err_code, SALT_ERR_NO_SUCH_SERVER);
    assert_int_equal(mock->host_channel->err_code, SALT_ERR_NO_SUCH_SERVER);


}

int main(void) {
    salt_crypto_init(NULL);
    
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(host_client_session_handshake, setup, teardown),
        cmocka_unit_test_setup_teardown(host_client_session_handshake_with, setup, teardown),
        cmocka_unit_test_setup_teardown(host_client_session_handshake_with_no_such, setup, teardown),
        cmocka_unit_test_setup_teardown(host_client_session_handshake_bad_peer, setup, teardown)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
