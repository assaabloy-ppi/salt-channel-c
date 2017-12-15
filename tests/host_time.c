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
#include "salt_mock.h"

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


static void host_delay_threshold_m1_m4(void **state)
{
    salt_mock_t *mock = (salt_mock_t *) *state;
    salt_channel_t  *host_channel = mock->host_channel;
    salt_channel_t  *client_channel = mock->client_channel;
    salt_ret_t      host_ret;
    salt_ret_t      client_ret;

    uint8_t host_buffer[SALT_HNDSHK_BUFFER_SIZE + 1U];
    uint8_t client_buffer[SALT_HNDSHK_BUFFER_SIZE + 1U];

    memset(host_buffer, 0xCC, sizeof(host_buffer));
    memset(client_buffer, 0xEE, sizeof(client_buffer));

    host_ret = salt_create_signature(host_channel);
    host_ret = salt_init_session(host_channel, host_buffer, SALT_HNDSHK_BUFFER_SIZE);

    client_ret = salt_create_signature(client_channel);
    client_ret = salt_init_session(client_channel, client_buffer, SALT_HNDSHK_BUFFER_SIZE);

    host_ret = SALT_PENDING;
    client_ret = SALT_PENDING;

    salt_set_delay_threshold(host_channel, 5);

    salt_time_mock_set_next(mock->client_time, 1);
    salt_time_mock_set_next(mock->client_time, 5);
    salt_time_mock_set_next(mock->client_time, 15);
    salt_time_mock_set_next(mock->client_time, 20);

    salt_time_mock_set_next(mock->host_time, 10);
    salt_time_mock_set_next(mock->host_time, 12);
    salt_time_mock_set_next(mock->host_time, 20);
    salt_time_mock_set_next(mock->host_time, 40);


    client_ret = salt_handshake(client_channel, NULL); /* Client sends M1, waiting for M2 */
    assert_true(client_ret == SALT_PENDING);
    host_ret = salt_handshake(host_channel, NULL); /* Host receives M1, sends M2, M3 waiting for M4 */
    assert_true(host_ret == SALT_PENDING);
    client_ret = salt_handshake(client_channel, NULL); /* Received M2, M3, sends M4 */
    assert_true(client_ret == SALT_SUCCESS);
    host_ret = salt_handshake(host_channel, NULL);   /* Recieved M4, expected delay_threshold */

    assert_true(host_ret == SALT_ERROR);
    assert_int_equal(host_channel->err_code, SALT_ERR_DELAY_DETECTED);

}

int main(void) {
    salt_crypto_init(my_randombytes);

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(host_delay_threshold_m1_m4, setup, teardown)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
