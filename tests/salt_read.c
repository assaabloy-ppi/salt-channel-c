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

void my_randombytes(unsigned char *p_bytes, unsigned long long length)
{
    (void) p_bytes;
    (void) length;
}

static void read_test(void **state)
{
    uint8_t buffer[256];
    salt_msg_t message;

    salt_write_begin(buffer, sizeof(buffer), &message);
    salt_write_next(&message, (uint8_t *) "12345", 5);
    salt_write_next(&message, (uint8_t *) "678", 3);
    salt_write_next(&message, (uint8_t *) "87641258", 8);
    uint8_t type = salt_write_create(&message);
    assert_int_equal(type, SALT_MULTI_APP_PKG_MSG_HEADER_VALUE);

    assert_int_equal(
        salt_read_init(type, message.write.p_payload, message.write.buffer_size, &message),
        SALT_ERR_NONE);

    assert_memory_equal(message.read.p_payload, "12345", 5);
    assert_int_equal(message.read.messages_left, 2);

    assert_true(SALT_SUCCESS == salt_read_next(&message));
    assert_memory_equal(message.read.p_payload, "678", 3);
    assert_int_equal(message.read.messages_left, 1);

    assert_true(SALT_SUCCESS == salt_read_next(&message));
    assert_int_equal(message.read.messages_left, 0);
    assert_memory_equal(message.read.p_payload, (uint8_t *) "87641258", 8);

    assert_true(SALT_ERROR == salt_read_next(&message));
}

static void second_test(void **state) {
    uint8_t buffer[256];
    salt_msg_t message;

    uint8_t msg1[17] = { /* 0x40140141140a506f5456312d2d2d2d2d41 */
        0x40, 0x14, 0x01, 0x41,
        0x14, 0x0a, 0x50, 0x6f,
        0x54, 0x56, 0x31, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d,
        0x41
    };

    uint8_t msg2[32] = { /* 0x4014016314096765745468696e6773140169100a14017418010014017a404141 */
        0x40, 0x14, 0x01, 0x63,
        0x14, 0x09, 0x67, 0x65,
        0x74, 0x54, 0x68, 0x69,
        0x6e, 0x67, 0x73, 0x14,
        0x01, 0x69, 0x10, 0x0a,
        0x14, 0x01, 0x74, 0x18,
        0x01, 0x00, 0x14, 0x01,
        0x7a, 0x40, 0x41, 0x41
    };

    salt_write_begin(buffer, sizeof(buffer), &message);
    salt_write_next(&message, msg1, sizeof(msg1));
    salt_write_next(&message, msg2, sizeof(msg2));
    uint8_t type = salt_write_create(&message);
    assert_int_equal(type, SALT_MULTI_APP_PKG_MSG_HEADER_VALUE);

    assert_int_equal(
        salt_read_init(type, message.write.p_payload, message.write.buffer_size, &message),
        SALT_ERR_NONE);

    assert_memory_equal(message.read.p_payload, msg1, sizeof(msg1));
    assert_int_equal(message.read.messages_left, 1);

    assert_true(SALT_SUCCESS == salt_read_next(&message));
    assert_memory_equal(message.read.p_payload, msg2, sizeof(msg2));
    assert_int_equal(message.read.messages_left, 0);

    assert_true(SALT_ERROR == salt_read_next(&message));
}

int main(void)
{
    salt_crypto_init(my_randombytes);

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(read_test),
        cmocka_unit_test(second_test),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
