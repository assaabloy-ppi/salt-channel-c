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


static void test_salt_create(void **state)
{

    salt_channel_t channel;
    salt_ret_t ret;

    ret = salt_create(NULL, SALT_CLIENT, salt_write_mock, salt_read_mock, NULL);
    assert_true(SALT_ERROR == ret);

    ret = salt_create(&channel, SALT_CLIENT, NULL, salt_read_mock, NULL);
    assert_true(SALT_ERROR == ret);
    assert_true(SALT_ERR_NULL_PTR == channel.err_code);

    ret = salt_create(&channel, SALT_CLIENT, NULL, NULL, NULL);
    assert_true(SALT_ERROR == ret);
    assert_true(SALT_ERR_NULL_PTR == channel.err_code);

    ret = salt_create(&channel, SALT_CLIENT, salt_write_mock, NULL, NULL);
    assert_true(SALT_ERROR == ret);
    assert_true(SALT_ERR_NULL_PTR == channel.err_code);

    ret = salt_create(&channel, SALT_CLIENT, salt_write_mock, salt_read_mock, NULL);
    assert_true(SALT_SUCCESS == ret);
    assert_true(SALT_ERR_NONE == channel.err_code);

    ret = salt_create(&channel, 2, salt_write_mock, salt_read_mock, NULL);
    assert_true(SALT_ERROR == ret);
    assert_true(SALT_ERR_NOT_SUPPORTED == channel.err_code);

}

static void test_salt_set_signature(void **state)
{
    salt_channel_t channel;
    salt_ret_t ret;

    salt_create(&channel, SALT_CLIENT, salt_write_mock, salt_read_mock, NULL);
    ret = salt_set_signature(NULL, salt_example_session_1_data.client_sk_sec);
    assert_true(SALT_ERROR == ret);

    salt_create(&channel, SALT_CLIENT, salt_write_mock, salt_read_mock, NULL);
    ret = salt_set_signature(&channel, NULL);
    assert_true(SALT_ERROR == ret);
    assert_true(SALT_ERR_NULL_PTR == channel.err_code);

    salt_create(&channel, SALT_CLIENT, salt_write_mock, salt_read_mock, NULL);
    ret = salt_set_signature(&channel, salt_example_session_1_data.client_sk_sec);
    assert_true(SALT_SUCCESS == ret);
    assert_true(SALT_ERR_NONE == channel.err_code);

    assert_memory_equal(channel.my_sk_sec,
                        salt_example_session_1_data.client_sk_sec,
                        sizeof(salt_example_session_1_data.client_sk_sec));

}

static void test_salt_set_context(void **state)
{
    salt_channel_t channel;
    salt_ret_t ret;

    salt_create(&channel, SALT_CLIENT, salt_write_mock, salt_read_mock, NULL);
    ret = salt_set_context(NULL, NULL, NULL);
    assert_true(SALT_ERROR == ret);

    salt_create(&channel, SALT_CLIENT, salt_write_mock, salt_read_mock, NULL);
    ret = salt_set_context(&channel, NULL, NULL);
    assert_true(SALT_SUCCESS == ret);
    assert_null(channel.write_channel.p_context);
    assert_null(channel.read_channel.p_context);

    salt_create(&channel, SALT_CLIENT, salt_write_mock, salt_read_mock, NULL);
    ret = salt_set_context(&channel, &channel, &ret);
    assert_ptr_equal(channel.write_channel.p_context, &channel);
    assert_ptr_equal(channel.read_channel.p_context, &ret);

}

static void test_salt_init_session(void **state)
{
    salt_channel_t channel;
    salt_ret_t ret;
    uint8_t hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE];
    salt_create(&channel, SALT_CLIENT, salt_write_mock, salt_read_mock, NULL);

    ret = salt_init_session(&channel, NULL, SALT_HNDSHK_BUFFER_SIZE);
    assert_true(SALT_ERROR == ret);
    assert_true(SALT_ERR_NO_SIGNATURE == channel.err_code);

    salt_set_signature(&channel, salt_example_session_1_data.client_sk_sec);
    ret = salt_init_session(&channel, NULL, SALT_HNDSHK_BUFFER_SIZE);
    assert_true(SALT_ERROR == ret);
    assert_true(SALT_ERR_NULL_PTR == channel.err_code);

    ret = salt_init_session(&channel, hndsk_buffer, SALT_HNDSHK_BUFFER_SIZE - 1);
    assert_true(SALT_ERROR == ret);
    assert_true(SALT_ERR_BUFF_TO_SMALL == channel.err_code);

    ret = salt_init_session(&channel, hndsk_buffer, SALT_HNDSHK_BUFFER_SIZE);
    assert_true(SALT_SUCCESS == ret);
    assert_true(SALT_ERR_NONE == channel.err_code);

    ret = salt_init_session(&channel, hndsk_buffer, SALT_HNDSHK_BUFFER_SIZE * 2);
    assert_true(SALT_SUCCESS == ret);
    assert_true(SALT_ERR_NONE == channel.err_code);

}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_salt_create),
        cmocka_unit_test(test_salt_set_signature),
        cmocka_unit_test(test_salt_set_context),
        cmocka_unit_test(test_salt_init_session),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
