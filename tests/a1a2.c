/**
 * @file a1a2.c
 *
 * Tests the a1a2 sequence using the mock channels created by salt_mock.
 *
 */

/*======= Includes ==========================================================*/

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

#include "salti_util.h"
#include "salt.h"
#include "salt_mock.h"
#include "test_data.h"

/*======= Local Macro Definitions ===========================================*/
/*======= Type Definitions ==================================================*/
/*======= Local variable declarations =======================================*/
/*======= Local function prototypes =========================================*/
/*======= Global function implementations ===================================*/
/*======= Local function implementations ====================================*/

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

static void a1a2_any_host_no_prot(void **state)
{

}

static void a1a2_any_host_defined_prot(void **state)
{
    salt_mock_t *mock = (salt_mock_t *) *state;
    salt_channel_t  *host_channel = mock->host_channel;
    salt_channel_t  *client_channel = mock->client_channel;
    salt_ret_t      host_ret;
    salt_ret_t      client_ret;

    uint8_t host_buffer[SALT_HNDSHK_BUFFER_SIZE + 1U];
    uint8_t client_buffer[SALT_HNDSHK_BUFFER_SIZE + 1U];
    uint8_t client_a1a2_buffer[200];

    memset(host_buffer, 0xCC, sizeof(host_buffer));
    memset(client_buffer, 0xEE, sizeof(client_buffer));

    host_ret = salt_create_signature(host_channel);
    assert_true(host_ret == SALT_SUCCESS);
    host_ret = salt_init_session(host_channel, host_buffer, SALT_HNDSHK_BUFFER_SIZE);
    assert_true(host_ret == SALT_SUCCESS);

    client_ret = salt_create_signature(client_channel);
    assert_true(client_ret == SALT_SUCCESS);
    client_ret = salt_init_session(client_channel, client_buffer, SALT_HNDSHK_BUFFER_SIZE);
    assert_true(client_ret == SALT_SUCCESS);

    host_ret = SALT_PENDING;
    client_ret = SALT_PENDING;
    salt_protocols_t host_protocols;

    do {
        if (client_ret != SALT_SUCCESS) {
            client_ret = salt_a1a2(client_channel, client_a1a2_buffer, sizeof(client_a1a2_buffer), &host_protocols, NULL);
        }

        assert_int_not_equal(client_ret, SALT_ERROR);

        if (host_ret != SALT_SUCCESS) {
            host_ret = salt_handshake(host_channel, NULL);
        }

        assert_int_not_equal(host_ret, SALT_ERROR);

    } while (client_ret == SALT_PENDING);

    assert_true(2 == host_protocols.count);

    assert_true(memcmp("SCv2------",
                       host_protocols.p_protocols[0],
                       sizeof(salt_protocol_t)) == 0);

    assert_true(memcmp("----------",
                       host_protocols.p_protocols[1],
                       sizeof(salt_protocol_t)) == 0);

}

static void a1a2_known_host(void **state)
{
    salt_mock_t *mock = (salt_mock_t *) *state;
    salt_channel_t  *host_channel = mock->host_channel;
    salt_channel_t  *client_channel = mock->client_channel;
    salt_ret_t      host_ret;
    salt_ret_t      client_ret;

    uint8_t host_buffer[SALT_HNDSHK_BUFFER_SIZE + 1U];
    uint8_t client_buffer[SALT_HNDSHK_BUFFER_SIZE + 1U];
    uint8_t client_a1a2_buffer[200];

    memset(host_buffer, 0xCC, sizeof(host_buffer));
    memset(client_buffer, 0xEE, sizeof(client_buffer));

    host_ret = salt_create_signature(host_channel);
    assert_true(host_ret == SALT_SUCCESS);
    host_ret = salt_init_session(host_channel, host_buffer, SALT_HNDSHK_BUFFER_SIZE);
    assert_true(host_ret == SALT_SUCCESS);

    uint8_t protocol_buf[128];
    salt_protocols_t my_protocols;
    host_ret = salt_protocols_init(host_channel, &my_protocols, protocol_buf, sizeof(protocol_buf));
    assert_true(host_ret == SALT_SUCCESS);
    host_ret = salt_protocols_append(&my_protocols, "Echo", 4);
    assert_true(host_ret == SALT_SUCCESS);
    host_ret = salt_protocols_append(&my_protocols, "Temp", 4);
    assert_true(host_ret == SALT_SUCCESS);
    host_ret = salt_protocols_append(&my_protocols, "Sensor", 6);
    assert_true(host_ret == SALT_SUCCESS);

    client_ret = salt_create_signature(client_channel);
    assert_true(client_ret == SALT_SUCCESS);
    client_ret = salt_init_session(client_channel, client_buffer, SALT_HNDSHK_BUFFER_SIZE);
    assert_true(client_ret == SALT_SUCCESS);

    host_ret = SALT_PENDING;
    client_ret = SALT_PENDING;
    salt_protocols_t host_protocols;

    do {
        if (client_ret != SALT_SUCCESS) {
            client_ret = salt_a1a2(client_channel,
                                   client_a1a2_buffer,
                                   sizeof(client_a1a2_buffer),
                                   &host_protocols, host_channel->my_sk_pub);
        }

        assert_int_not_equal(client_ret, SALT_ERROR);

        if (host_ret != SALT_SUCCESS) {
            host_ret = salt_handshake(host_channel, NULL);
        }

        assert_int_not_equal(host_ret, SALT_ERROR);

    } while (client_ret == SALT_PENDING);

    assert_true(my_protocols.count == host_protocols.count);

    for (uint8_t i = 0; i < host_protocols.count; i++) {
        assert_true(memcmp(my_protocols.p_protocols[i],
                           host_protocols.p_protocols[i], sizeof(salt_protocol_t)) == 0);
    }

}

static void a1a2_no_such_host(void **state)
{
    salt_mock_t *mock = (salt_mock_t *) *state;
    salt_channel_t  *host_channel = mock->host_channel;
    salt_channel_t  *client_channel = mock->client_channel;
    salt_ret_t      host_ret;
    salt_ret_t      client_ret;

    uint8_t host_buffer[SALT_HNDSHK_BUFFER_SIZE + 1U];
    uint8_t client_buffer[SALT_HNDSHK_BUFFER_SIZE + 1U];
    uint8_t client_a1a2_buffer[200];

    memset(host_buffer, 0xCC, sizeof(host_buffer));
    memset(client_buffer, 0xEE, sizeof(client_buffer));

    host_ret = salt_create_signature(host_channel);
    assert_true(host_ret == SALT_SUCCESS);
    host_ret = salt_init_session(host_channel, host_buffer, SALT_HNDSHK_BUFFER_SIZE);
    assert_true(host_ret == SALT_SUCCESS);


    client_ret = salt_create_signature(client_channel);
    assert_true(client_ret == SALT_SUCCESS);
    client_ret = salt_init_session(client_channel, client_buffer, SALT_HNDSHK_BUFFER_SIZE);
    assert_true(client_ret == SALT_SUCCESS);

    host_ret = SALT_PENDING;
    client_ret = SALT_PENDING;
    salt_protocols_t host_protocols;
    uint8_t dummy[32];
    memset(dummy, 0x00, 32);

    do {
        if (client_ret != SALT_SUCCESS) {
            client_ret = salt_a1a2(client_channel,
                                   client_a1a2_buffer,
                                   sizeof(client_a1a2_buffer),
                                   &host_protocols, dummy);
        }

        if (host_ret != SALT_SUCCESS) {
            host_ret = salt_handshake(host_channel, NULL);
        }

        assert_int_not_equal(host_ret, SALT_ERROR);

    } while (client_ret == SALT_PENDING);

    assert_int_equal(client_ret, SALT_ERROR);
    assert_int_equal(client_channel->err_code, SALT_ERR_NO_SUCH_SERVER);


}

int main(void) {
    salt_crypto_init(my_randombytes);
        
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(a1a2_any_host_no_prot, setup, teardown),
        cmocka_unit_test_setup_teardown(a1a2_any_host_defined_prot, setup, teardown),
        cmocka_unit_test_setup_teardown(a1a2_known_host, setup, teardown),
        cmocka_unit_test_setup_teardown(a1a2_no_such_host, setup, teardown),

    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
