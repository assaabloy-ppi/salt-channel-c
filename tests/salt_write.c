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
#include "salti_handshake.h"

#ifndef USE_SODIUM
void randombytes(unsigned char *p_bytes, unsigned long long length)
{
    (void) p_bytes;
    (void) length;
}
#endif

static void salt_write_begin_buffer_size(void **state)
{
    uint8_t buffer[256];
    uint8_t msg[256];
    salt_msg_t message;
    assert_true(salt_write_begin(buffer, sizeof(buffer), &message) == SALT_SUCCESS);
    assert_true(salt_write_begin(buffer, SALT_WRITE_OVERHEAD_SIZE, &message) == SALT_SUCCESS);
    assert_true(salt_write_begin(buffer, SALT_WRITE_OVERHEAD_SIZE-1, &message) == SALT_ERROR);

    /* Check empty message */
    salt_write_begin(buffer, SALT_WRITE_OVERHEAD_SIZE, &message);
    assert_true(salt_write_next(&message, msg, 0) == SALT_SUCCESS);

    /* Check one message full buffer message */
    salt_write_begin(buffer, SALT_WRITE_OVERHEAD_SIZE + 5, &message);
    assert_true(salt_write_next(&message, msg, 5) == SALT_SUCCESS);

}

static void salt_write_message_buff_size(void **state)
{
    uint8_t buffer[256];
    uint8_t dummy[256];
    salt_msg_t message;
    salt_ret_t ret;
    for (uint8_t i = 0; i < SALT_WRITE_OVERHEAD_SIZE; i++) {
        ret = salt_write_begin(buffer, i, &message);
        assert_true(SALT_ERROR == ret);
    }

    ret = salt_write_begin(buffer, SALT_WRITE_OVERHEAD_SIZE, &message);
    assert_true(ret == SALT_SUCCESS);
    ret = salt_write_next(&message, (uint8_t *)"tjenare", 0);
    assert_true(SALT_SUCCESS == ret);
    ret = salt_write_next(&message, (uint8_t *)"tjenare", 0);
    assert_true(SALT_ERROR == ret);

    ret = salt_write_begin(buffer, SALT_WRITE_OVERHEAD_SIZE, &message);
    assert_true(ret == SALT_SUCCESS);
    ret = salt_write_next(&message, (uint8_t *)"tjenare", 1);
    assert_true(SALT_ERROR == ret);

    ret = salt_write_begin(buffer, SALT_WRITE_OVERHEAD_SIZE + 1, &message);
    assert_true(ret == SALT_SUCCESS);
    ret = salt_write_next(&message, (uint8_t *)"tjenare", 1);
    assert_true(SALT_SUCCESS == ret);

    ret = salt_write_begin(buffer, 128, &message);
    assert_true(ret == SALT_SUCCESS);
    ret = salt_write_next(&message, dummy, 128 - SALT_WRITE_OVERHEAD_SIZE);
    assert_true(SALT_SUCCESS == ret);

    ret = salt_write_begin(buffer, 128, &message);
    assert_true(ret == SALT_SUCCESS);
    ret = salt_write_next(&message, dummy, 128 - SALT_WRITE_OVERHEAD_SIZE + 1);
    assert_true(SALT_ERROR == ret);

    ret = salt_write_begin(buffer, SALT_WRITE_OVERHEAD_SIZE + 3, &message);
    assert_true(ret == SALT_SUCCESS);
    ret = salt_write_next(&message, (uint8_t *)"tjenare", 1);
    assert_true(SALT_SUCCESS == ret);
    ret = salt_write_next(&message, (uint8_t *)"tjenare", 0);
    assert_true(SALT_SUCCESS == ret);

    ret = salt_write_begin(buffer, SALT_WRITE_OVERHEAD_SIZE + 5, &message);
    assert_true(ret == SALT_SUCCESS);
    ret = salt_write_next(&message, (uint8_t *)"tjenare", 1);
    assert_true(SALT_SUCCESS == ret);
    ret = salt_write_next(&message, (uint8_t *)"tjenare", 2);
    assert_true(SALT_SUCCESS == ret);

}

static void salt_write_messages(void **state)
{
    uint8_t buffer[256];
    salt_msg_t message;
    salt_write_begin(buffer, sizeof(buffer), &message);
    salt_write_next(&message, (uint8_t *)"tjenare", 7);
    assert_int_equal(SALT_APP_PKG_MSG_HEADER_VALUE, salt_write_create(&message));
    assert_int_equal(1, message.write.message_count);

    salt_write_begin(buffer, sizeof(buffer), &message);
    salt_write_next(&message, (uint8_t *)"tjenare", 7);
    salt_write_next(&message, (uint8_t *)"tjenare", 7);
    assert_int_equal(SALT_MULTI_APP_PKG_MSG_HEADER_VALUE, salt_write_create(&message));
    assert_int_equal(2, message.write.message_count);

}

static void write_begin_null_args(void **state)
{
    uint8_t buffer[256];
    salt_msg_t message;
    assert_true(salt_write_begin(NULL, sizeof(buffer), &message) == SALT_ERROR);
    assert_true(salt_write_begin(buffer, sizeof(buffer), NULL) == SALT_ERROR);
    assert_true(salt_write_begin(NULL, sizeof(buffer), NULL) == SALT_ERROR);
}

static void write_append_no_copy_single(void **state)
{
    uint8_t buffer[256];
    uint16_t size;
    salt_msg_t message;
    salt_write_begin(buffer, sizeof(buffer), &message);
    size = snprintf((char*)message.write.p_payload,
        message.write.buffer_available,
        "Cool message 1");
    assert_true(salt_write_commit(&message, size) == SALT_SUCCESS);

    uint8_t type = salt_write_create(&message);
    assert_int_equal(type, SALT_APP_PKG_MSG_HEADER_VALUE);

    assert_int_equal(
        salt_read_init(type, message.write.p_payload, message.write.buffer_size, &message),
        SALT_ERR_NONE);

    assert_memory_equal(message.read.p_payload, "Cool message 1", 5);
    assert_true(SALT_ERROR == salt_read_next(&message));

}

static void write_append_no_copy(void **state)
{
    uint8_t buffer[256];
    salt_msg_t message;
    salt_write_begin(buffer, sizeof(buffer), &message);

    memset(message.write.p_payload, 0xCC, 2);
    assert_true(salt_write_commit(&message, 2) == SALT_SUCCESS);

    memset(message.write.p_payload, 0xEE, 3);
    assert_true(salt_write_commit(&message, 3) == SALT_SUCCESS);

    memset(message.write.p_payload, 0xFF, 4);
    assert_true(salt_write_commit(&message, 4) == SALT_SUCCESS);

    uint8_t type = salt_write_create(&message);

    uint8_t expected[17] = {
        0x03 , 0x00,                                /* Count */
        0x02 , 0x00 , 0xCC , 0XCC ,                 /* Msg = 2 bytes length */
        0x03 , 0x00 , 0xEE , 0xEE , 0xEE,           /* Msg = 3 bytes length */
        0x04 , 0x00 , 0xFF , 0xFF , 0xFF, 0xFF      /* Msg = 4 bytes length */
    };

    assert_int_equal(sizeof(expected), message.write.buffer_size);
    assert_memory_equal(expected, message.write.p_payload, sizeof(expected));


    assert_int_equal(
        salt_read_init(type, message.write.p_payload, message.write.buffer_size, &message),
        SALT_ERR_NONE);

    assert_memory_equal(message.read.p_payload, "\xcc\xcc", 2);
    assert_int_equal(message.read.messages_left, 2);

    assert_true(SALT_SUCCESS == salt_read_next(&message));
    assert_memory_equal(message.read.p_payload, "\xee\xee\xee", 3);
    assert_int_equal(message.read.messages_left, 1);

    assert_true(SALT_SUCCESS == salt_read_next(&message));
    assert_int_equal(message.read.messages_left, 0);
    assert_memory_equal(message.read.p_payload, "\xff\xff\xff\xff", 4);

    assert_true(SALT_ERROR == salt_read_next(&message));

}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(salt_write_begin_buffer_size),
        cmocka_unit_test(salt_write_messages),
        cmocka_unit_test(write_begin_null_args),
        cmocka_unit_test(write_append_no_copy_single),
        cmocka_unit_test(write_append_no_copy),
        cmocka_unit_test(salt_write_message_buff_size)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
