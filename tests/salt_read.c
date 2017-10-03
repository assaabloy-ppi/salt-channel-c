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

void read_test(void **state)
{
    uint8_t buffer[256];
    //uint8_t msg[256];
    salt_msg_t message;
    
    salt_write_begin(buffer, sizeof(buffer), &message);
    salt_write_next(&message, (uint8_t *) "12345", 5);
    salt_write_next(&message, (uint8_t *) "678", 3);
    salt_write_next(&message, (uint8_t *) "87641258", 8);
    salt_write_create(&message);

    assert_int_equal(salt_read_init(message.read.p_buffer, message.read.buffer_size, &message), SALT_ERR_NONE);

}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(read_test),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}