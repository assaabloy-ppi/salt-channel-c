#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "salt_util.h"
#include "salt_v2.h"
#include "salt_mock.h"
#include "test_data.h"

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

void randombytes(unsigned char *p_bytes, unsigned long long length)
{
    memcpy(p_bytes, salt_test_data.host_ek_sec, length);
}

static void host_a1a2(void **state) {
    
    salt_channel_t channel;
    salt_ret_t ret;
    salt_mock_t *mock = (salt_mock_t *) *state;
    uint8_t hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE];
    memset(hndsk_buffer, 0xcc, SALT_HNDSHK_BUFFER_SIZE);

    ret = salt_create(&channel, SALT_SERVER, salt_write_mock, salt_read_mock, NULL);
    ret = salt_set_signature(&channel, salt_test_data.host_sk_sec);
    ret = salt_set_context(&channel, mock->io->expected_write, mock->io->next_read);
    ret = salt_init_session(&channel, hndsk_buffer, SALT_HNDSHK_BUFFER_SIZE);

    uint8_t protocol_buf[128];
    salt_protocols_t my_protocols;
    ret = salt_protocols_init(&channel, &my_protocols, protocol_buf, sizeof(protocol_buf));
    assert_true(ret == SALT_SUCCESS);
    ret = salt_protocols_append(&my_protocols, "ECHO", 4);
    assert_true(ret == SALT_SUCCESS);

    salt_io_mock_set_next_read(mock->io, salt_test_data.a1, sizeof(salt_test_data.a1), false);

    salt_io_mock_expect_next_write(mock->io, salt_test_data.a2, sizeof(salt_test_data.a2), false);

    ret = salt_handshake(&channel);
    assert_true(ret == SALT_PENDING);

    /* Check that we did not overflow handshake buffer */
    for (uint32_t i = SALT_HNDSHK_BUFFER_SIZE; i < sizeof(hndsk_buffer); i++)
    {
        assert_true(hndsk_buffer[i] == 0xcc);
    }

}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(host_a1a2, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
