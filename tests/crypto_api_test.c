#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "salt_crypto_wrapper_test.h"
#include "salt.h"

static void crypto_api_test(void **state)
{
    assert_int_equal(salt_crypto_wrapper_test(), 0);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(crypto_api_test),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
