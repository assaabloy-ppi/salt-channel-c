#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

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

        //printf("%s - ", mode2str(context->channel->mode));
        //SALT_HEXDUMP(p_wchannel->p_data, p_wchannel->size_expected);

        assert(cfifo_write(write_queue, p_wchannel->p_data,
            &size) == CFIFO_SUCCESS);
        assert(size == p_wchannel->size_expected);
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

        assert(cfifo_read(read_queue, p_rchannel->p_data,
            &size) == CFIFO_SUCCESS);

        //printf("%s - ", mode2str(context->channel->mode));
        //SALT_HEXDUMP(p_rchannel->p_data, p_rchannel->size_expected);

        assert(size == p_rchannel->size_expected);
        p_rchannel->size = p_rchannel->size_expected;

        return SALT_SUCCESS;
    }
    return SALT_PENDING;
}


int main(void)
{

    printf("=== Salt v2 test begin ===\r\n");

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

    host_ret = salt_create(&host_channel, SALT_SERVER, my_write, my_read);
    host_context.channel = &host_channel;
    host_context.write_queue = host_fifo;
    host_context.read_queue = client_fifo;
    assert(host_ret == SALT_SUCCESS);
    host_ret = salt_create_signature(&host_channel);
    assert(host_ret == SALT_SUCCESS);
    host_ret = salt_init_session(&host_channel, host_buffer, SALT_HNDSHK_BUFFER_SIZE);
    assert(host_ret == SALT_SUCCESS);
    host_ret = salt_set_context(&host_channel, &host_context, &host_context); /* Write, read */
    assert(host_ret == SALT_SUCCESS);

    client_ret = salt_create(&client_channel, SALT_CLIENT, my_write, my_read);
    client_context.channel = &client_channel;
    client_context.write_queue = client_fifo;
    client_context.read_queue = host_fifo;
    assert(client_ret == SALT_SUCCESS);
    client_ret = salt_create_signature(&client_channel);
    assert(client_ret == SALT_SUCCESS);
    client_ret = salt_init_session(&client_channel, client_buffer, SALT_HNDSHK_BUFFER_SIZE);
    assert(client_ret == SALT_SUCCESS);
    client_ret = salt_set_context(&client_channel, &client_context, &client_context); /* Write, read */
    assert(client_ret == SALT_SUCCESS);

    host_ret = SALT_PENDING;
    client_ret = SALT_PENDING;

    while ((host_ret | client_ret) != SALT_SUCCESS)
    {
        client_ret = salt_handshake(&client_channel);
        assert(client_buffer[SALT_HNDSHK_BUFFER_SIZE] == 0xEE);
        assert(client_ret != SALT_ERROR);

        host_ret = salt_handshake(&host_channel);
        assert(host_buffer[SALT_HNDSHK_BUFFER_SIZE] == 0xCC);
        assert(host_ret != SALT_ERROR);
    }

    assert(memcmp(host_channel.my_sk_pub, client_channel.peer_sk_pub, 32) == 0);
    assert(memcmp(host_channel.peer_sk_pub, client_channel.my_sk_pub, 32) == 0);

    uint8_t host_new_buffer[65];
    uint8_t client_new_buffer[65];

    memset(&host_new_buffer[SALT_OVERHEAD_SIZE], 0x13, sizeof(host_new_buffer) - SALT_OVERHEAD_SIZE);

    do {
        host_ret = salt_write(&host_channel, host_new_buffer, sizeof(host_new_buffer));
        assert(host_ret != SALT_ERROR);    
    } while (host_ret != SALT_SUCCESS);

    memset(&client_new_buffer[SALT_OVERHEAD_SIZE], 0x23, sizeof(client_new_buffer) - SALT_OVERHEAD_SIZE);

    do {
        client_ret = salt_write(&client_channel, client_new_buffer, sizeof(host_new_buffer));
        assert(client_ret != SALT_ERROR);    
    } while (client_ret != SALT_SUCCESS);

    do {
        client_ret = salt_read(&client_channel, client_new_buffer, &size, sizeof(client_new_buffer));
        assert(client_ret != SALT_ERROR);    
    } while (client_ret != SALT_SUCCESS);

    assert(size == sizeof(client_new_buffer) - SALT_OVERHEAD_SIZE);

    for (uint32_t i = 0; i < size; i++) {
        assert(client_new_buffer[SALT_OVERHEAD_SIZE+i] == 0x13);
    }

    do {
        host_ret = salt_read(&host_channel, host_new_buffer, &size, sizeof(host_new_buffer));
        assert(host_ret != SALT_ERROR);    
    } while (host_ret != SALT_SUCCESS);

    assert(size == sizeof(client_new_buffer) - SALT_OVERHEAD_SIZE);

    for (uint32_t i = 0; i < size; i++) {
        assert(host_new_buffer[SALT_OVERHEAD_SIZE+i] == 0x23);
    }

    /* To big msg test */
    do {
        host_ret = salt_write(&host_channel, host_buffer, sizeof(client_new_buffer) + 1);
        assert(host_ret != SALT_ERROR);    
    } while (host_ret != SALT_SUCCESS);

    do {
        client_ret = salt_read(&client_channel, client_new_buffer, &size, sizeof(client_new_buffer));
    } while (client_ret == SALT_PENDING);
    assert(client_ret == SALT_ERROR);    

    printf("=== Salt v2 test succeeded ===\r\n");

    return 0;
}
