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

static void host_handshake_m1(void **state)
{
    salt_channel_t channel;
    salt_ret_t ret;
    salt_mock_t *mock = (salt_mock_t *) *state;
    uint8_t hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE];
    memset(hndsk_buffer, 0xcc, SALT_HNDSHK_BUFFER_SIZE);

    ret = salt_create(&channel, SALT_SERVER, salt_write_mock, salt_read_mock, NULL);
    ret = salt_set_signature(&channel, salt_example_session_1_data.host_sk_sec);
    ret = salt_set_context(&channel, mock->io->expected_write, mock->io->next_read);

    ret = salt_init_session_using_key(&channel,
                                      hndsk_buffer,
                                      SALT_HNDSHK_BUFFER_SIZE,
                                      salt_example_session_1_data.host_ek_pub,
                                      salt_example_session_1_data.host_ek_sec);

    salt_io_mock_set_next_read(mock->io, &salt_example_session_1_data.m1[4], sizeof(salt_example_session_1_data.m1) - 5, true);
    ret = salt_handshake(&channel, NULL);
    assert_true(ret == SALT_ERROR);
    assert_true(SALT_ERR_BAD_PROTOCOL == channel.err_code);


    ret = salt_init_session(&channel, hndsk_buffer, SALT_HNDSHK_BUFFER_SIZE);
    salt_io_mock_set_next_read(mock->io, hndsk_buffer, sizeof(salt_example_session_1_data.m1) + 10, true);
    ret = salt_handshake(&channel, NULL);
    assert_true(ret == SALT_ERROR);
    assert_true(SALT_ERR_BAD_PROTOCOL == channel.err_code);


    ret = salt_init_session(&channel, hndsk_buffer, SALT_HNDSHK_BUFFER_SIZE);
    uint8_t tmp[sizeof(salt_example_session_1_data.m1)];
    memcpy(tmp, salt_example_session_1_data.m1, sizeof(salt_example_session_1_data.m1));
    tmp[5] = 0x00;
    salt_io_mock_set_next_read(mock->io, tmp, sizeof(salt_example_session_1_data.m1), false);

    ret = salt_handshake(&channel, NULL);
    assert_true(ret == SALT_ERROR);
    assert_true(SALT_ERR_BAD_PROTOCOL == channel.err_code);


}

static void host_handshake(void **state) {

    salt_channel_t channel;
    salt_ret_t ret;
    salt_mock_t *mock = (salt_mock_t *) *state;
    uint8_t hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE];
    memset(hndsk_buffer, 0xcc, SALT_HNDSHK_BUFFER_SIZE);

    ret = salt_create(&channel, SALT_SERVER, salt_write_mock, salt_read_mock, NULL);
    ret = salt_set_signature(&channel, salt_example_session_1_data.host_sk_sec);
    ret = salt_set_context(&channel, mock->io->expected_write, mock->io->next_read);
    ret = salt_init_session_using_key(&channel,
                                      hndsk_buffer,
                                      SALT_HNDSHK_BUFFER_SIZE,
                                      salt_example_session_1_data.host_ek_pub,
                                      salt_example_session_1_data.host_ek_sec);

    salt_io_mock_set_next_read(mock->io, salt_example_session_1_data.m1, sizeof(salt_example_session_1_data.m1), false);
    salt_io_mock_set_next_read(mock->io, salt_example_session_1_data.m4, sizeof(salt_example_session_1_data.m4), false);

    salt_io_mock_expect_next_write(mock->io, salt_example_session_1_data.m2, sizeof(salt_example_session_1_data.m2), false);
    salt_io_mock_expect_next_write(mock->io, salt_example_session_1_data.m3, sizeof(salt_example_session_1_data.m3), false);

    ret = salt_handshake(&channel, NULL);
    assert_true(ret == SALT_SUCCESS);

    /* Check that we did not overflow handshake buffer */
    for (uint32_t i = SALT_HNDSHK_BUFFER_SIZE; i < sizeof(hndsk_buffer); i++)
    {
        assert_true(hndsk_buffer[i] == 0xcc);
    }


}

static void host_handshake_single_echo(void **state) {

    salt_channel_t channel;
    salt_ret_t ret;
    salt_mock_t *mock = (salt_mock_t *) *state;
    uint8_t hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE * 2];
    memset(hndsk_buffer, 0xcc, sizeof(hndsk_buffer));

    ret = salt_create(&channel, SALT_SERVER, salt_write_mock, salt_read_mock, NULL);
    ret = salt_set_signature(&channel, salt_example_session_1_data.host_sk_sec);
    ret = salt_set_context(&channel, mock->io->expected_write, mock->io->next_read);
    ret = salt_init_session_using_key(&channel,
                                      hndsk_buffer,
                                      SALT_HNDSHK_BUFFER_SIZE,
                                      salt_example_session_1_data.host_ek_pub,
                                      salt_example_session_1_data.host_ek_sec);
    salt_io_mock_set_next_read(mock->io, salt_example_session_1_data.m1, sizeof(salt_example_session_1_data.m1), false);
    salt_io_mock_set_next_read(mock->io, salt_example_session_1_data.m4, sizeof(salt_example_session_1_data.m4), false);
    salt_io_mock_set_next_read(mock->io, salt_example_session_1_data.msg1, sizeof(salt_example_session_1_data.msg1), false);

    salt_io_mock_expect_next_write(mock->io, salt_example_session_1_data.m2, sizeof(salt_example_session_1_data.m2), false);
    salt_io_mock_expect_next_write(mock->io, salt_example_session_1_data.m3, sizeof(salt_example_session_1_data.m3), false);
    salt_io_mock_expect_next_write(mock->io, salt_example_session_1_data.msg2, sizeof(salt_example_session_1_data.msg2), false);

    ret = salt_handshake(&channel, NULL);
    assert_true(ret == SALT_SUCCESS);

    /* Check that we did not overflow handshake buffer */
    for (uint32_t i = SALT_HNDSHK_BUFFER_SIZE; i < sizeof(hndsk_buffer); i++)
    {
        assert_true(hndsk_buffer[i] == 0xcc);
    }

    uint8_t echo_bytes[6] = {0x01, 0x05, 0x05, 0x05, 0x05, 0x05};

    salt_msg_t msg_in;
    ret = salt_read_begin(&channel, hndsk_buffer, sizeof(hndsk_buffer), &msg_in);
    assert_true(ret == SALT_SUCCESS);
    assert_true(msg_in.read.messages_left == 0);
    assert_true(msg_in.read.message_size == sizeof(echo_bytes));
    assert_true(memcmp(echo_bytes, msg_in.read.p_payload, sizeof(echo_bytes)) == 0);

    /* Write echo bytes 010505050505 */

    salt_msg_t msg_out;
    ret = salt_write_begin(hndsk_buffer, sizeof(hndsk_buffer), &msg_out);
    assert_true(ret == SALT_SUCCESS);
    ret = salt_write_next(&msg_out, echo_bytes, sizeof(echo_bytes));
    ret = salt_write_execute(&channel, &msg_out, false);
    assert_true(ret == SALT_SUCCESS);

}

static void host_handshake_multi_echo(void **state) {

    salt_channel_t channel;
    salt_ret_t ret;
    salt_mock_t *mock = (salt_mock_t *) *state;
    uint8_t hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE];
    memset(hndsk_buffer, 0xcc, SALT_HNDSHK_BUFFER_SIZE);

    ret = salt_create(&channel, SALT_SERVER, salt_write_mock, salt_read_mock, mock->host_time);
    ret = salt_set_signature(&channel, salt_example_session_3_data.host_sk_sec);
    ret = salt_set_context(&channel, mock->io->expected_write, mock->io->next_read);
    ret = salt_init_session_using_key(&channel,
                                      hndsk_buffer,
                                      SALT_HNDSHK_BUFFER_SIZE,
                                      salt_example_session_1_data.host_ek_pub,
                                      salt_example_session_1_data.host_ek_sec);
    salt_io_mock_set_next_read(mock->io, salt_example_session_3_data.m1, sizeof(salt_example_session_3_data.m1), false);
    salt_io_mock_set_next_read(mock->io, salt_example_session_3_data.m4, sizeof(salt_example_session_3_data.m4), false);
    salt_io_mock_set_next_read(mock->io, salt_example_session_3_data.msg1, sizeof(salt_example_session_3_data.msg1), false);
    salt_io_mock_set_next_read(mock->io, salt_example_session_3_data.msg3, sizeof(salt_example_session_3_data.msg3), false);

    salt_io_mock_expect_next_write(mock->io, salt_example_session_3_data.m2, sizeof(salt_example_session_3_data.m2), false);
    salt_io_mock_expect_next_write(mock->io, salt_example_session_3_data.m3, sizeof(salt_example_session_3_data.m3), false);
    salt_io_mock_expect_next_write(mock->io, salt_example_session_3_data.msg2, sizeof(salt_example_session_3_data.msg2), false);
    salt_io_mock_expect_next_write(mock->io, salt_example_session_3_data.msg4, sizeof(salt_example_session_3_data.msg4), false);

    for (size_t i = 0; i < sizeof(salt_example_session_3_data.host_time) / sizeof(uint32_t); i++) {
        salt_time_mock_set_next(mock->host_time, salt_example_session_3_data.host_time[i]);
    }

    ret = salt_set_delay_threshold(&channel, 100);
    assert_true(ret == SALT_SUCCESS);

    ret = salt_handshake(&channel, NULL);
    assert_true(ret == SALT_SUCCESS);

    /* Check that we did not overflow handshake buffer */
    for (uint32_t i = SALT_HNDSHK_BUFFER_SIZE; i < sizeof(hndsk_buffer); i++)
    {
        assert_true(hndsk_buffer[i] == 0xcc);
    }

    salt_msg_t msg_in;
    salt_ret_t write_ret;
    uint8_t out_buffer[sizeof(hndsk_buffer)];
    salt_msg_t msg_out;

    ret = salt_read_begin(&channel, hndsk_buffer, sizeof(hndsk_buffer), &msg_in);
    assert_true(ret == SALT_SUCCESS);
    assert_true(msg_in.read.messages_left == 0);

    ret = salt_write_begin(out_buffer, sizeof(out_buffer), &msg_out);
    assert_true(ret == SALT_SUCCESS);


    do {
        memcpy(msg_out.write.p_payload, msg_in.read.p_payload, msg_in.read.message_size);
        write_ret = salt_write_commit(&msg_out, msg_in.read.message_size);
        assert_true(write_ret == SALT_SUCCESS);

        ret = salt_read_next(&msg_in);
    } while (ret == SALT_SUCCESS);

    ret = salt_write_execute(&channel, &msg_out, false);
    assert_true(ret == SALT_SUCCESS);

    ret = salt_read_begin(&channel, hndsk_buffer, sizeof(hndsk_buffer), &msg_in);

    ret = salt_write_begin(out_buffer, sizeof(out_buffer), &msg_out);
    assert_true(ret == SALT_SUCCESS);

    do {
        SALT_HEXDUMP_DEBUG(msg_in.read.p_payload, msg_in.read.message_size);
        memcpy(msg_out.write.p_payload, msg_in.read.p_payload, msg_in.read.message_size);
        write_ret = salt_write_commit(&msg_out, msg_in.read.message_size);
        assert_true(write_ret == SALT_SUCCESS);

        ret = salt_read_next(&msg_in);
    } while (ret == SALT_SUCCESS);

    ret = salt_write_execute(&channel, &msg_out, true);
    assert_true(ret == SALT_SUCCESS);

}

int main(void) {
    salt_crypto_init(my_randombytes);
    
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(host_handshake, setup, teardown),
        cmocka_unit_test_setup_teardown(host_handshake_m1, setup, teardown),
        cmocka_unit_test_setup_teardown(host_handshake_single_echo, setup, teardown),
        cmocka_unit_test_setup_teardown(host_handshake_multi_echo, setup, teardown)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
