#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "salt_util.h"
#include "salt_v2.h"
#include "salt_io_mock.h"
#include "test_data.h"

void randombytes(unsigned char *p_bytes, unsigned long long length)
{
    memcpy(p_bytes, salt_test_data.host_ek_sec, length);
}

static void my_time_impl(uint32_t *p_time) {
    memset(p_time, 0, 4);
}

static void host_handshake(void **state) {
    
    (void) state;
    salt_channel_t channel;
    salt_ret_t ret;
    salt_mock_t *mock;
    uint8_t hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE];
    memset(hndsk_buffer, 0xcc, SALT_HNDSHK_BUFFER_SIZE);

    SALT_IO_MOCK_CREATE(&channel, mock, 10);

    salt_io_mock_set_next_read(mock, salt_test_data.m1, sizeof(salt_test_data.m1), false);
    salt_io_mock_set_next_read(mock, salt_test_data.m4, sizeof(salt_test_data.m4), false);
    salt_io_mock_set_next_read(mock, salt_test_data.msg1, sizeof(salt_test_data.msg1), false);

    salt_io_mock_expect_next_write(mock, salt_test_data.m2, sizeof(salt_test_data.m2), false);
    salt_io_mock_expect_next_write(mock, salt_test_data.m3, sizeof(salt_test_data.m3), false);
    salt_io_mock_expect_next_write(mock, salt_test_data.msg2, sizeof(salt_test_data.msg2), false);


    ret = salt_create(&channel, SALT_SERVER, salt_write_mock, salt_read_mock, my_time_impl);
    ret = salt_set_signature(&channel, salt_test_data.host_sk_sec);
    ret = salt_init_session(&channel, hndsk_buffer, SALT_HNDSHK_BUFFER_SIZE);
    ret = salt_handshake(&channel);
    assert_true(ret == SALT_SUCCESS);

    /* Check that we did not overflow handshake buffer */
    for (uint32_t i = SALT_HNDSHK_BUFFER_SIZE; i < sizeof(hndsk_buffer); i++)
    {
        assert_true(hndsk_buffer[i] == 0xcc);
    }

    /* Write echo bytes 010505050505 */
    uint8_t echo_bytes[6] = {0x01, 0x05, 0x05, 0x05, 0x05, 0x05};
    salt_msg_t msg_out;
    ret = salt_write_begin(hndsk_buffer, sizeof(hndsk_buffer), &msg_out);
    assert_true(ret == SALT_SUCCESS);
    ret = salt_write_next(&msg_out, echo_bytes, sizeof(echo_bytes));
    ret = salt_write_execute(&channel, &msg_out);
    assert_true(ret == SALT_SUCCESS);

    salt_msg_t msg_in;
    ret = salt_read_begin(&channel, hndsk_buffer, sizeof(hndsk_buffer), &msg_in);
    assert_true(ret == SALT_SUCCESS);
    assert_true(msg_in.read.messages_left == 0);
    assert_true(msg_in.read.message_size == sizeof(echo_bytes));
    assert_true(memcmp(echo_bytes, msg_in.read.p_message, sizeof(echo_bytes)) == 0);

}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(host_handshake),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
