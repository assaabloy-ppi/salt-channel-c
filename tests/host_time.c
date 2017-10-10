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

typedef struct salt_test_s {
    salt_channel_t  *channel;
    cfifo_t         *write_queue;
    cfifo_t         *read_queue;
} salt_test_t;

static cfifo_t *client_fifo;
static cfifo_t *host_fifo;

void randombytes(unsigned char *p_bytes, unsigned long long length)
{
   FILE* fr = fopen("/dev/urandom", "r");
   if (!fr) perror("urandom"), exit(EXIT_FAILURE);
   size_t tmp = fread(p_bytes, sizeof(unsigned char), length, fr);
   (void) tmp;
   fclose(fr);
}

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

static salt_ret_t my_write(salt_io_channel_t *p_wchannel)
{


    salt_test_t *context = (salt_test_t *) p_wchannel->p_context;
    cfifo_t *write_queue = context->write_queue;
    uint32_t size = p_wchannel->size_expected;

    assert_true(cfifo_write(write_queue, p_wchannel->p_data,
        &size) == CFIFO_SUCCESS);
    assert_true(size == p_wchannel->size_expected);
    p_wchannel->size = p_wchannel->size_expected;
    return SALT_SUCCESS;
    
}

static salt_ret_t my_read(salt_io_channel_t *p_rchannel)
{
    salt_test_t *context = (salt_test_t *) p_rchannel->p_context;
    cfifo_t *read_queue = context->read_queue;
    uint32_t size = p_rchannel->size_expected;

    if (cfifo_size(context->read_queue) < size) {
        return SALT_PENDING;
    }

    assert_true(cfifo_read(read_queue, p_rchannel->p_data,
        &size) == CFIFO_SUCCESS);

    assert_true(size == p_rchannel->size_expected);
    p_rchannel->size = p_rchannel->size_expected;

    return SALT_SUCCESS;
}


static void host_delay_threshold_m1_m4(void **state)
{
    salt_mock_t *mock = (salt_mock_t *) *state;
    salt_channel_t  host_channel;
    salt_channel_t  client_channel;
    salt_ret_t      host_ret;
    salt_ret_t      client_ret;
    salt_test_t     host_context;
    salt_test_t     client_context;

    uint8_t host_buffer[SALT_HNDSHK_BUFFER_SIZE + 1U];
    uint8_t client_buffer[SALT_HNDSHK_BUFFER_SIZE + 1U];

    memset(host_buffer, 0xCC, sizeof(host_buffer));
    memset(client_buffer, 0xEE, sizeof(client_buffer));

    setbuf(stdout, NULL);

    host_ret = salt_create(&host_channel, SALT_SERVER, my_write, my_read, mock->host_time);
    host_context.channel = &host_channel;
    host_context.write_queue = host_fifo;
    host_context.read_queue = client_fifo;
    host_ret = salt_create_signature(&host_channel);
    host_ret = salt_init_session(&host_channel, host_buffer, SALT_HNDSHK_BUFFER_SIZE);
    host_ret = salt_set_context(&host_channel, &host_context, &host_context); /* Write, read */

    client_ret = salt_create(&client_channel, SALT_CLIENT, my_write, my_read, mock->client_time);
    client_context.channel = &client_channel;
    client_context.write_queue = client_fifo;
    client_context.read_queue = host_fifo;
    client_ret = salt_create_signature(&client_channel);
    client_ret = salt_init_session(&client_channel, client_buffer, SALT_HNDSHK_BUFFER_SIZE);
    client_ret = salt_set_context(&client_channel, &client_context, &client_context); /* Write, read */

    host_ret = SALT_PENDING;
    client_ret = SALT_PENDING;

    salt_set_delay_threshold(&host_channel, 5);

    salt_time_mock_set_next(mock->client_time, 1);
    salt_time_mock_set_next(mock->client_time, 5);
    salt_time_mock_set_next(mock->client_time, 15);
    salt_time_mock_set_next(mock->client_time, 20);

    salt_time_mock_set_next(mock->host_time, 10);
    salt_time_mock_set_next(mock->host_time, 12);
    salt_time_mock_set_next(mock->host_time, 20);
    salt_time_mock_set_next(mock->host_time, 40);


    client_ret = salt_handshake(&client_channel, NULL); /* Client sends M1, waiting for M2 */
    assert_true(client_ret == SALT_PENDING);
    host_ret = salt_handshake(&host_channel, NULL); /* Host receives M1, sends M2, M3 waiting for M4 */
    assert_true(host_ret == SALT_PENDING);
    client_ret = salt_handshake(&client_channel, NULL); /* Received M2, M3, sends M4 */
    assert_true(client_ret == SALT_SUCCESS);
    host_ret = salt_handshake(&host_channel, NULL);   /* Recieved M4, expected delay_threshold */

    assert_true(host_ret == SALT_ERROR);
    assert_int_equal(host_channel.err_code, SALT_ERR_TIMEOUT);

}

int main(void) {

    CFIFO_CREATE(client_fifo, 1, 1024);
    CFIFO_CREATE(host_fifo, 1, 1024);

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(host_delay_threshold_m1_m4, setup, teardown)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
