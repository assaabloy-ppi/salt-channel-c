#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "cfifo.h"
#include "salt_v2.h"
#include "salt_util.h"

void randombytes(unsigned char *p_bytes, unsigned long long length)
{
    (void) p_bytes;
    (void) length;
}

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

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(salt_write_begin_buffer_size),
        cmocka_unit_test(salt_write_messages),
        cmocka_unit_test(write_begin_null_args)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
