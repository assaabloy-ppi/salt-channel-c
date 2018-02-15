#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "salti_util.h"
#include "salt.h"

static void dummy(void **state)
{
    (void) state;

    printf("UINT32_MAX: %d\r\n", INT32_MAX);

    printf("%u\r\n", (uint32_t ) -500);

    /*
     * bool time_check(uint32_t first,
     *                 uint32_t now,
     *                 uint32_t peer_time,
     *                 uint32_t thresh)
     *
     */

    assert_true(time_check(0, 0, 0, 1000));
    assert_true(time_check(0, 1000, 0, 1000));
    assert_false(time_check(0, 1001, 0, 1000));

    assert_true(time_check(UINT16_MAX, UINT16_MAX, UINT16_MAX, 1000));
    assert_true(time_check(UINT16_MAX, UINT16_MAX+1000, UINT16_MAX, 1000));
    assert_false(time_check(UINT16_MAX, UINT16_MAX+1001, 0, 1000));

    assert_true(time_check(5000, 5000, 0, 1000));
    assert_true(time_check(5000, 5000, 0, 1000));
    assert_false(time_check(5000, 6001, 0, 1000));

}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(dummy),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
