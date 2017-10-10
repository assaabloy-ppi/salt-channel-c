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

void randombytes(unsigned char *p_bytes, unsigned long long length)
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


int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(read_test),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
