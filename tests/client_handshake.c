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


static void client_handshake(void **state)
{

    (void) state;
    salt_channel_t channel;
    salt_ret_t ret;
    salt_mock_t *mock = (salt_mock_t *) *state;
    uint8_t hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE];
    memset(hndsk_buffer, 0xcc, SALT_HNDSHK_BUFFER_SIZE);

    salt_create(&channel, SALT_CLIENT, salt_write_mock, salt_read_mock, NULL);
    salt_set_signature(&channel, salt_example_session_1_data.client_sk_sec);
    salt_init_session_using_key(&channel,
                                hndsk_buffer,
                                SALT_HNDSHK_BUFFER_SIZE,
                                salt_example_session_1_data.client_ek_pub,
                                salt_example_session_1_data.client_ek_sec);

    salt_set_context(&channel, mock->io->expected_write, mock->io->next_read);

    salt_io_mock_set_next_read(mock->io, salt_example_session_1_data.m2, sizeof(salt_example_session_1_data.m2), false);
    salt_io_mock_set_next_read(mock->io, salt_example_session_1_data.m3, sizeof(salt_example_session_1_data.m3), false);
    salt_io_mock_set_next_read(mock->io, salt_example_session_1_data.msg2, sizeof(salt_example_session_1_data.msg2), false);

    salt_io_mock_expect_next_write(mock->io, salt_example_session_1_data.m1, sizeof(salt_example_session_1_data.m1), false);
    salt_io_mock_expect_next_write(mock->io, salt_example_session_1_data.m4, sizeof(salt_example_session_1_data.m4), false);
    salt_io_mock_expect_next_write(mock->io, salt_example_session_1_data.msg1, sizeof(salt_example_session_1_data.msg1), false);

    ret = salt_handshake(&channel, NULL);
    assert_true(ret == SALT_SUCCESS);

}

static void client_handshake_single_echo(void **state)
{

    (void) state;
    salt_channel_t channel;
    salt_ret_t ret;
    salt_mock_t *mock = (salt_mock_t *) *state;
    uint8_t hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE];
    memset(hndsk_buffer, 0xcc, SALT_HNDSHK_BUFFER_SIZE);

    salt_create(&channel, SALT_CLIENT, salt_write_mock, salt_read_mock, NULL);
    salt_set_signature(&channel, salt_example_session_1_data.client_sk_sec);
    salt_init_session_using_key(&channel,
                                hndsk_buffer,
                                SALT_HNDSHK_BUFFER_SIZE,
                                salt_example_session_1_data.client_ek_pub,
                                salt_example_session_1_data.client_ek_sec);
    salt_set_context(&channel, mock->io->expected_write, mock->io->next_read);

    salt_io_mock_set_next_read(mock->io, salt_example_session_1_data.m2, sizeof(salt_example_session_1_data.m2), false);
    salt_io_mock_set_next_read(mock->io, salt_example_session_1_data.m3, sizeof(salt_example_session_1_data.m3), false);
    salt_io_mock_set_next_read(mock->io, salt_example_session_1_data.msg2, sizeof(salt_example_session_1_data.msg2), false);

    salt_io_mock_expect_next_write(mock->io, salt_example_session_1_data.m1, sizeof(salt_example_session_1_data.m1), false);
    salt_io_mock_expect_next_write(mock->io, salt_example_session_1_data.m4, sizeof(salt_example_session_1_data.m4), false);
    salt_io_mock_expect_next_write(mock->io, salt_example_session_1_data.msg1, sizeof(salt_example_session_1_data.msg1), false);

    ret = salt_handshake(&channel, NULL);
    assert_true(ret == SALT_SUCCESS);

    /* Check that we did not overflow handshake buffer */
    for (uint32_t i = SALT_HNDSHK_BUFFER_SIZE; i < sizeof(hndsk_buffer); i++) {
        assert_true(hndsk_buffer[i] == 0xcc);
    }

    /* Write echo bytes 010505050505 */
    uint8_t echo_bytes[6] = {0x01, 0x05, 0x05, 0x05, 0x05, 0x05};
    salt_msg_t msg_out;
    ret = salt_write_begin(hndsk_buffer, sizeof(hndsk_buffer), &msg_out);
    assert_true(ret == SALT_SUCCESS);
    ret = salt_write_next(&msg_out, echo_bytes, sizeof(echo_bytes));
    assert_true(ret == SALT_SUCCESS);
    ret = salt_write_execute(&channel, &msg_out, false);
    assert_true(ret == SALT_SUCCESS);

    salt_msg_t msg_in;
    ret = salt_read_begin(&channel, hndsk_buffer, sizeof(hndsk_buffer), &msg_in);
    assert_true(ret == SALT_SUCCESS);
    assert_true(msg_in.read.messages_left == 0);
    assert_true(msg_in.read.message_size == sizeof(echo_bytes));
    assert_true(memcmp(echo_bytes, msg_in.read.p_payload, sizeof(echo_bytes)) == 0);

}

static void client_handshake_multi_echo(void **state)
{

    (void) state;
    salt_channel_t channel;
    salt_ret_t ret;
    salt_mock_t *mock = (salt_mock_t *) *state;
    uint8_t hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE];
    memset(hndsk_buffer, 0xcc, SALT_HNDSHK_BUFFER_SIZE);

    salt_create(&channel, SALT_CLIENT, salt_write_mock, salt_read_mock, mock->client_time);
    salt_set_signature(&channel, salt_example_session_3_data.client_sk_sec);
    salt_init_session_using_key(&channel,
                                hndsk_buffer,
                                SALT_HNDSHK_BUFFER_SIZE,
                                salt_example_session_1_data.client_ek_pub,
                                salt_example_session_1_data.client_ek_sec);
    salt_set_context(&channel, mock->io->expected_write, mock->io->next_read);

    salt_io_mock_set_next_read(mock->io, salt_example_session_3_data.m2, sizeof(salt_example_session_3_data.m2), false);
    salt_io_mock_set_next_read(mock->io, salt_example_session_3_data.m3, sizeof(salt_example_session_3_data.m3), false);
    salt_io_mock_set_next_read(mock->io, salt_example_session_3_data.msg2, sizeof(salt_example_session_3_data.msg2), false);
    salt_io_mock_set_next_read(mock->io, salt_example_session_3_data.msg4, sizeof(salt_example_session_3_data.msg4), false);

    salt_io_mock_expect_next_write(mock->io, salt_example_session_3_data.m1, sizeof(salt_example_session_3_data.m1), false);
    salt_io_mock_expect_next_write(mock->io, salt_example_session_3_data.m4, sizeof(salt_example_session_3_data.m4), false);
    salt_io_mock_expect_next_write(mock->io, salt_example_session_3_data.msg1, sizeof(salt_example_session_3_data.msg1), false);
    salt_io_mock_expect_next_write(mock->io, salt_example_session_3_data.msg3, sizeof(salt_example_session_3_data.msg3), false);


    for (size_t i = 0; i < sizeof(salt_example_session_3_data.client_time) / sizeof(uint32_t); i++) {
        salt_time_mock_set_next(mock->client_time, salt_example_session_3_data.client_time[i]);
    }

    ret = salt_set_delay_threshold(&channel, 100);
    assert_true(ret == SALT_SUCCESS);

    ret = salt_handshake(&channel, NULL);
    assert_true(ret == SALT_SUCCESS);

    /* Check that we did not overflow handshake buffer */
    for (uint32_t i = SALT_HNDSHK_BUFFER_SIZE; i < sizeof(hndsk_buffer); i++) {
        assert_true(hndsk_buffer[i] == 0xcc);
    }

    /* Write echo bytes 010505050505 */
    uint8_t echo_bytes[6] = {0x01, 0x05, 0x05, 0x05, 0x05, 0x05};
    salt_msg_t msg_out;
    salt_msg_t msg_in;

    ret = salt_write_begin(hndsk_buffer, sizeof(hndsk_buffer), &msg_out);
    assert_true(ret == SALT_SUCCESS);
    ret = salt_write_next(&msg_out, echo_bytes, sizeof(echo_bytes));
    assert_true(ret == SALT_SUCCESS);
    ret = salt_write_execute(&channel, &msg_out, false);
    assert_true(ret == SALT_SUCCESS);


    ret = salt_read_begin(&channel, hndsk_buffer, sizeof(hndsk_buffer), &msg_in);
    assert_true(ret == SALT_SUCCESS);
    assert_true(msg_in.read.messages_left == 0);
    assert_true(msg_in.read.message_size == sizeof(echo_bytes));
    assert_true(memcmp(echo_bytes, msg_in.read.p_payload, sizeof(echo_bytes)) == 0);

    uint8_t multi1[5] = { 0x01, 0x04, 0x04, 0x04, 0x04 };
    uint8_t multi2[4] = { 0x03, 0x03, 0x03, 0x03 };
    ret = salt_write_begin(hndsk_buffer, sizeof(hndsk_buffer), &msg_out);
    assert_true(ret == SALT_SUCCESS);
    ret = salt_write_next(&msg_out, multi1, sizeof(multi1));
    assert_true(ret == SALT_SUCCESS);
    ret = salt_write_next(&msg_out, multi2, sizeof(multi2));
    assert_true(ret == SALT_SUCCESS);
    ret = salt_write_execute(&channel, &msg_out, false);
    assert_true(ret == SALT_SUCCESS);

    ret = salt_read_begin(&channel, hndsk_buffer, sizeof(hndsk_buffer), &msg_in);
    assert_true(ret == SALT_SUCCESS);
    assert_true(msg_in.read.messages_left == 1);

    assert_int_equal(sizeof(multi1), msg_in.read.message_size);
    assert_memory_equal(msg_in.read.p_payload, multi1, msg_in.read.message_size);

    ret = salt_read_next(&msg_in);
    assert_true(ret == SALT_SUCCESS);
    assert_true(msg_in.read.messages_left == 0);

    assert_int_equal(sizeof(multi2), msg_in.read.message_size);
    assert_memory_equal(msg_in.read.p_payload, multi2, msg_in.read.message_size);

    ret = salt_read_next(&msg_in);
    assert_true(ret == SALT_ERROR);

    ret = salt_read_begin(&channel, hndsk_buffer, sizeof(hndsk_buffer), &msg_in);
    assert_true(ret == SALT_ERROR);
    assert_int_equal(channel.err_code, SALT_ERR_INVALID_STATE);
    assert_int_equal(channel.state, SALT_SESSION_CLOSED);

}

int main(void)
{
    salt_crypto_init(my_randombytes);

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(client_handshake, setup, teardown),
        cmocka_unit_test_setup_teardown(client_handshake_single_echo, setup, teardown),
        cmocka_unit_test_setup_teardown(client_handshake_multi_echo, setup, teardown)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
