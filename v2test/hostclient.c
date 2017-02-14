#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "test_data.c"

#include "../test/util.h"
#include "salt_v2.h"

typedef struct salt_test_s salt_test_t;

struct salt_test_s {
    uint8_t     *buffer;
    uint32_t    pointer;
    uint32_t    buffer_size;
    salt_test_t *next;
};

void randombytes(unsigned char *p_bytes, unsigned long long length)
{
    FILE* fr = fopen("/dev/urandom", "r");
    if (!fr) perror("urandom"), exit(EXIT_FAILURE);
    fread(p_bytes, sizeof(unsigned char), length, fr);
    fclose(fr);
}

salt_ret_t my_write(salt_io_channel_t *p_wchannel)
{
    static uint8_t i;
    if (i < 30) {
        /* Simulate some polling */
        i++;
        return SALT_PENDING;
    }
    i = 0;
    assert(p_wchannel != 0);
    assert(p_wchannel->p_data != 0);

    salt_test_t **pp_write_queue = (salt_test_t **) p_wchannel->p_context;
    salt_test_t *write_queue = *pp_write_queue;

    if (write_queue != 0)
    {
        write_queue->next = malloc(sizeof(salt_test_t));
        write_queue = write_queue->next;
    }
    else {
        write_queue = malloc(sizeof(salt_test_t));
        *pp_write_queue = write_queue;
    }
    
    write_queue->pointer = 0;
    write_queue->next = 0;
    write_queue->buffer = malloc(p_wchannel->size_expected);
    write_queue->buffer_size = p_wchannel->size_expected;
    memcpy(write_queue->buffer, p_wchannel->p_data, p_wchannel->size_expected);
    p_wchannel->size = p_wchannel->size_expected;

    return SALT_SUCCESS;
}

salt_ret_t my_read(salt_io_channel_t *p_rchannel)
{
    static uint8_t i;
    if (i < 30) {
        /* Simulate some polling */
        i++;
        return SALT_PENDING;
    }
    i = 0;
    uint32_t bytes_left;
    uint32_t to_copy;

    assert(p_rchannel != 0);
    assert(p_rchannel->p_data != 0);

    salt_test_t **pp_read_queue = (salt_test_t **) p_rchannel->p_context;
    salt_test_t *read_queue = *pp_read_queue;

    if (read_queue == 0)
    {
        return SALT_PENDING;
    }

    bytes_left = p_rchannel->size_expected-p_rchannel->size;
    to_copy = (bytes_left <= (read_queue->buffer_size-read_queue->pointer)) ? bytes_left : read_queue->buffer_size;
    memcpy(&p_rchannel->p_data[p_rchannel->size], &read_queue->buffer[read_queue->pointer], to_copy);
    p_rchannel->size += to_copy;
    read_queue->pointer += to_copy;

    if (read_queue->pointer == read_queue->buffer_size)
    {
        *pp_read_queue = read_queue->next;
        free(read_queue->buffer);
        free(read_queue);
    }

    if (p_rchannel->size == p_rchannel->size_expected)
    {
        return SALT_SUCCESS;
    }

    return SALT_PENDING;
}


int main(void)
{

    uint32_t size;
    salt_channel_t  host_channel, client_channel;
    salt_ret_t      host_ret, client_ret;
    salt_test_t     *write_message = 0;
    salt_test_t     *read_message = 0;

    uint8_t host_buffer[SALT_HNDSHK_BUFFER_SIZE], client_buffer[SALT_HNDSHK_BUFFER_SIZE];

    host_ret = salt_create(&host_channel, SALT_SERVER, my_write, my_read);
    assert(host_ret == SALT_SUCCESS);
    host_ret = salt_create_signature(&host_channel);
    assert(host_ret == SALT_SUCCESS);
    host_ret = salt_init_session(&host_channel, host_buffer, sizeof(host_buffer));
    assert(host_ret == SALT_SUCCESS);
    host_ret = salt_set_context(&host_channel, &write_message, &read_message); /* Write, read */
    assert(host_ret == SALT_SUCCESS);

    client_ret = salt_create(&client_channel, SALT_CLIENT, my_write, my_read);
    assert(client_ret == SALT_SUCCESS);
    client_ret = salt_create_signature(&client_channel);
    assert(client_ret == SALT_SUCCESS);
    client_ret = salt_init_session(&client_channel, client_buffer, sizeof(client_buffer));
    assert(client_ret == SALT_SUCCESS);
    client_ret = salt_set_context(&client_channel, &read_message, &write_message); /* Write, read */
    assert(client_ret == SALT_SUCCESS);

    host_ret = SALT_PENDING;
    client_ret = SALT_PENDING;

    while ((host_ret | client_ret) != SALT_SUCCESS)
    {
        client_ret = salt_handshake(&client_channel);
        assert(client_ret != SALT_ERROR);
        host_ret = salt_handshake(&host_channel);
        assert(host_ret != SALT_ERROR);
    }

    assert(memcmp(host_channel.my_sk_pub, client_channel.peer_sk_pub, 32) == 0);
    assert(memcmp(host_channel.peer_sk_pub, client_channel.my_sk_pub, 32) == 0);

    size = sprintf((char*) &host_buffer[SALT_WRITE_OVERHEAD_SIZE], "This is a secret message from host!");
    do {
        host_ret = salt_write(&host_channel, host_buffer, size + SALT_WRITE_OVERHEAD_SIZE);
        assert(host_ret != SALT_ERROR);    
    } while (host_ret != SALT_SUCCESS);

    size = sprintf((char*) &client_buffer[SALT_WRITE_OVERHEAD_SIZE], "This is a secret message from client!");
    do {
        client_ret = salt_write(&client_channel, client_buffer, size + SALT_WRITE_OVERHEAD_SIZE);
        assert(client_ret != SALT_ERROR);    
    } while (client_ret != SALT_SUCCESS);

    do {
        client_ret = salt_read(&client_channel, client_buffer, &size, sizeof(client_buffer) - SALT_READ_OVERHEAD_SIZE);
        assert(client_ret != SALT_ERROR);    
    } while (client_ret != SALT_SUCCESS);

    assert(memcmp("This is a secret message from host!", &client_buffer[SALT_WRITE_OVERHEAD_SIZE], size) == 0);

    do {
        host_ret = salt_read(&host_channel, host_buffer, &size, sizeof(host_buffer) - SALT_READ_OVERHEAD_SIZE);
        assert(host_ret != SALT_ERROR);    
    } while (host_ret != SALT_SUCCESS);

    assert(memcmp("This is a secret message from client!", &host_buffer[SALT_WRITE_OVERHEAD_SIZE], size) == 0);


    return 0;
}
