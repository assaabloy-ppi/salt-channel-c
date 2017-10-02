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

typedef struct salt_test_s {
    salt_channel_t  *channel;
    cfifo_t         *write_queue;
    cfifo_t         *read_queue;
} salt_test_t;

void randombytes(unsigned char *p_bytes, unsigned long long length)
{
    FILE* fr = fopen("/dev/urandom", "r");
    if (!fr) perror("urandom"), exit(EXIT_FAILURE);
    fread(p_bytes, sizeof(unsigned char), length, fr);
    fclose(fr);
}

salt_ret_t my_write(salt_io_channel_t *p_wchannel)
{

    static uint8_t i = 0;

    i++;
    /* Simulate polling and slow I/O */
    if (i > 10) {
        salt_test_t *context = (salt_test_t *) p_wchannel->p_context;
        cfifo_t *write_queue = context->write_queue;
        uint32_t size = p_wchannel->size_expected;

        assert_true(cfifo_write(write_queue, p_wchannel->p_data,
            &size) == CFIFO_SUCCESS);
        assert_true(size == p_wchannel->size_expected);
        p_wchannel->size = p_wchannel->size_expected;
        return SALT_SUCCESS;
        i = 0;
    }

    return SALT_PENDING;
    
}

salt_ret_t my_read(salt_io_channel_t *p_rchannel)
{
    static uint8_t i = 0;

    i++;
    /* Simulate polling and slow I/O */
    if (i > 10) {
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
    return SALT_PENDING;
}


void hostclient_session(void **state)
{
    (void) state;
    uint32_t size;
    salt_channel_t  host_channel;
    salt_channel_t  client_channel;
    salt_ret_t      host_ret;
    salt_ret_t      client_ret;
    cfifo_t         *host_fifo;
    cfifo_t         *client_fifo;
    salt_test_t     host_context;
    salt_test_t     client_context;

    uint8_t host_buffer[SALT_HNDSHK_BUFFER_SIZE + 1U];
    uint8_t client_buffer[SALT_HNDSHK_BUFFER_SIZE + 1U];

    memset(host_buffer, 0xCC, sizeof(host_buffer));
    memset(client_buffer, 0xEE, sizeof(client_buffer));

    CFIFO_CREATE(client_fifo, 1, 1024);
    CFIFO_CREATE(host_fifo, 1, 1024);

    setbuf(stdout, NULL);

    host_ret = salt_create(&host_channel, SALT_SERVER, my_write, my_read, NULL);
    host_context.channel = &host_channel;
    host_context.write_queue = host_fifo;
    host_context.read_queue = client_fifo;
    assert_true(host_ret == SALT_SUCCESS);
    host_ret = salt_create_signature(&host_channel);
    assert_true(host_ret == SALT_SUCCESS);
    host_ret = salt_init_session(&host_channel, host_buffer, SALT_HNDSHK_BUFFER_SIZE);
    assert_true(host_ret == SALT_SUCCESS);
    host_ret = salt_set_context(&host_channel, &host_context, &host_context); /* Write, read */
    assert_true(host_ret == SALT_SUCCESS);

    client_ret = salt_create(&client_channel, SALT_CLIENT, my_write, my_read, NULL);
    client_context.channel = &client_channel;
    client_context.write_queue = client_fifo;
    client_context.read_queue = host_fifo;
    assert_true(client_ret == SALT_SUCCESS);
    client_ret = salt_create_signature(&client_channel);
    assert_true(client_ret == SALT_SUCCESS);
    client_ret = salt_init_session(&client_channel, client_buffer, SALT_HNDSHK_BUFFER_SIZE);
    assert_true(client_ret == SALT_SUCCESS);
    client_ret = salt_set_context(&client_channel, &client_context, &client_context); /* Write, read */
    assert_true(client_ret == SALT_SUCCESS);

    host_ret = SALT_PENDING;
    client_ret = SALT_PENDING;

    while ((host_ret | client_ret) != SALT_SUCCESS)
    {
        client_ret = salt_handshake(&client_channel);
        assert_true(client_buffer[SALT_HNDSHK_BUFFER_SIZE] == 0xEE);
        assert_true(client_ret != SALT_ERROR);

        host_ret = salt_handshake(&host_channel);
        assert_true(host_buffer[SALT_HNDSHK_BUFFER_SIZE] == 0xCC);
        assert_true(host_ret != SALT_ERROR);
    }

    assert_true(memcmp(host_channel.my_sk_pub, client_channel.peer_sk_pub, 32) == 0);
    assert_true(memcmp(host_channel.peer_sk_pub, client_channel.my_sk_pub, 32) == 0);

    uint8_t host_new_buffer[65];
    uint8_t client_new_buffer[65];

    memset(&host_new_buffer[SALT_OVERHEAD_SIZE], 0x13, sizeof(host_new_buffer) - SALT_OVERHEAD_SIZE);

    do {
        host_ret = salt_write(&host_channel, host_new_buffer, sizeof(host_new_buffer));
        assert_true(host_ret != SALT_ERROR);    
    } while (host_ret != SALT_SUCCESS);

    memset(&client_new_buffer[SALT_OVERHEAD_SIZE], 0x23, sizeof(client_new_buffer) - SALT_OVERHEAD_SIZE);

    do {
        client_ret = salt_write(&client_channel, client_new_buffer, sizeof(host_new_buffer));
        assert_true(client_ret != SALT_ERROR);    
    } while (client_ret != SALT_SUCCESS);

    do {
        client_ret = salt_read(&client_channel, client_new_buffer, &size, sizeof(client_new_buffer));
        assert_true(client_ret != SALT_ERROR);    
    } while (client_ret != SALT_SUCCESS);

    assert_true(size == sizeof(client_new_buffer) - SALT_OVERHEAD_SIZE);

    for (uint32_t i = 0; i < size; i++) {
        assert_true(client_new_buffer[SALT_OVERHEAD_SIZE+i] == 0x13);
    }

    do {
        host_ret = salt_read(&host_channel, host_new_buffer, &size, sizeof(host_new_buffer));
        assert_true(host_ret != SALT_ERROR);    
    } while (host_ret != SALT_SUCCESS);

    assert_true(size == sizeof(client_new_buffer) - SALT_OVERHEAD_SIZE);

    for (uint32_t i = 0; i < size; i++) {
        assert_true(host_new_buffer[SALT_OVERHEAD_SIZE+i] == 0x23);
    }

    /* To big msg test */
    memset(host_buffer, 0x2e, sizeof(host_buffer));
    do {
        host_ret = salt_write(&host_channel, host_buffer, 40);
        assert_true(host_ret != SALT_ERROR);    
    } while (host_ret != SALT_SUCCESS);

    memset(client_new_buffer, 0x2d, sizeof(client_new_buffer));
    do {
        client_ret = salt_read(&client_channel, client_new_buffer, &size, 39);
    } while (client_ret == SALT_PENDING);

    for (uint32_t i = 0; i < sizeof(client_new_buffer)-39; i++) {
        assert_true(client_new_buffer[i+39] == 0x2d);
    }

    /* We expect an error here, not that we will get an error print out if debug mode is enabled, */
    assert_true(client_ret == SALT_ERROR);
    assert_true(client_channel.err_code == SALT_ERR_BUFF_TO_SMALL);

}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(hostclient_session),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}