/**
 * @file salt_io_mock.c
 *
 *
 * Description
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
#include "salt_mock.h"
#include "salti_util.h"

/*======= Local Macro Definitions ===========================================*/
/*======= Type Definitions ==================================================*/
/*======= Local variable declarations =======================================*/
/*======= Local function prototypes =========================================*/


static salt_ret_t salt_mock_get_time(salt_time_t *p_time, uint32_t *time);
static salt_ret_t salt_channel_read(salt_io_channel_t *p_rchannel);
static salt_ret_t salt_channel_write(salt_io_channel_t *p_wchannel);

/*======= Global function implementations ===================================*/


void my_randombytes(unsigned char *p_bytes, unsigned long long length)
{
   FILE* fr = fopen("/dev/urandom", "r");
   if (!fr) perror("urandom"), exit(EXIT_FAILURE);
   size_t tmp = fread(p_bytes, sizeof(unsigned char), length, fr);
   assert_true(tmp == length);
   fclose(fr);
}

salt_mock_t *salt_mock_create(void)
{
    salt_mock_t *mock = malloc(sizeof(salt_mock_t));
    memset(mock, 0x00, sizeof(salt_mock_t));
    assert_non_null(mock);
    mock->time = salt_time_mock_create();
    mock->io = salt_io_mock_create();

    mock->client_time = salt_time_mock_create();
    mock->host_time = salt_time_mock_create();
    salt_channels_create(mock);

    return mock;
}
void salt_mock_delete(salt_mock_t* mock)
{
    salt_time_mock_delete(mock->time);
    salt_time_mock_delete(mock->client_time);
    salt_time_mock_delete(mock->host_time);
    salt_io_mock_delete(mock->io);
    salt_channels_delete(mock);
    free(mock);
}

salt_time_t *salt_time_mock_create(void)
{
    salt_time_t *mock;
    mock = malloc(sizeof(salt_time_t));
    assert_non_null(mock);
    cfifo_t *time_queue = malloc(sizeof(cfifo_t));
    assert_non_null(time_queue);
    uint8_t *time_queue_data = malloc(sizeof(uint32_t) * 10);
    assert_non_null(time_queue_data);
    cfifo_init(time_queue, time_queue_data, 10, sizeof(uint32_t));
    mock->get_time = salt_mock_get_time;
    mock->p_context = time_queue;
    return mock;
}

void salt_time_mock_set_next(salt_time_t *mock, uint32_t time)
{
    cfifo_t *time_queue = (cfifo_t *) mock->p_context;
    if (time_queue != NULL) {
        cfifo_put(time_queue, &time);
    }
}

void salt_time_mock_delete(salt_time_t *mock)
{
    cfifo_t *time_queue = (cfifo_t *) mock->p_context;
    free(time_queue->p_buf);
    free(time_queue);
    free(mock);
}

salt_io_mock_t *salt_io_mock_create(void)
{
    salt_io_mock_t *mock;
    mock = malloc(sizeof(salt_io_mock_t));
    assert_non_null(mock);
    mock->expected_write = malloc(sizeof(cfifo_t));
    assert_non_null(mock->expected_write);
    mock->next_read = malloc(sizeof(cfifo_t));
    assert_non_null(mock->next_read );

    uint8_t *expected_write = malloc(sizeof(test_data_t) * 10);
    assert_non_null(expected_write);
    uint8_t *next_read = malloc(sizeof(test_data_t) * 10);
    assert_non_null(next_read);
    
    cfifo_init(mock->expected_write, expected_write, 10, sizeof(test_data_t));
    cfifo_init(mock->next_read, next_read, 10, sizeof(test_data_t));

    return mock;
}


void salt_io_mock_delete(salt_io_mock_t *mock)
{
    salt_io_mock_reset(mock);
    free(mock->expected_write->p_buf);
    free(mock->next_read->p_buf);
    free(mock->expected_write);
    free(mock->next_read);
    free(mock);
}

void salt_io_mock_reset(salt_io_mock_t *mock)
{
    test_data_t next;
    while (cfifo_get(mock->expected_write, &next) == CFIFO_SUCCESS) {
        free(next.data);
    }
    while (cfifo_get(mock->next_read, &next) == CFIFO_SUCCESS) {
        free(next.data);
    }
}

void salt_io_mock_set_next_read(salt_io_mock_t *mock, uint8_t *p_data, uint32_t size, bool add_size)
{
    test_data_t next;

    if (add_size) {
        next.data = malloc(4);
        next.size = 4;
        memcpy(next.data, &size, 4);
        cfifo_put(mock->next_read, &next);

        next.data = malloc(size);
        next.size = size;
        memcpy(next.data, p_data, size);
        cfifo_put(mock->next_read, &next);
    } else {
        next.data = malloc(4);
        next.size = 4;
        memcpy(next.data, p_data, 4);
        cfifo_put(mock->next_read, &next);
        next.data = malloc(size - 4);
        next.size = size - 4;
        memcpy(next.data, &p_data[4], size - 4);
        cfifo_put(mock->next_read, &next);
    }
}

void salt_io_mock_expect_next_write(salt_io_mock_t *mock, uint8_t *p_data, uint32_t size, bool add_size)
{

    test_data_t next;

    if (add_size) {
        next.data = malloc(size + 4);
        next.size = size + 4;
        memcpy(next.data, &size, 4);
        memcpy(&next.data[4], p_data, size);
    }
    else {
        next.data = malloc(size);
        next.size = size;
        memcpy(next.data, p_data, size);
    }

    cfifo_put(mock->expected_write, &next);
}


salt_ret_t salt_write_mock(salt_io_channel_t *p_wchannel)
{

    test_data_t next;
    cfifo_t *cfifo = (cfifo_t *) p_wchannel->p_context;

    if (cfifo_get(cfifo, &next) == CFIFO_SUCCESS) {
        assert_int_equal(next.size, p_wchannel->size_expected);
        assert_memory_equal(next.data, p_wchannel->p_data, p_wchannel->size_expected);
        free(next.data);
    }

    return SALT_SUCCESS;
}

void salt_channels_create(salt_mock_t *mock)
{
    mock->client_channel = malloc(sizeof(salt_channel_t));
    memset(mock->client_channel, 0x00, sizeof(salt_channel_t));
    assert_non_null(mock->client_channel);
    mock->host_channel = malloc(sizeof(salt_channel_t));
    memset(mock->host_channel, 0x00, sizeof(salt_channel_t));
    assert_non_null(mock->host_channel);

    mock->host_to_client = malloc(sizeof(cfifo_t));
    assert_non_null(mock->host_to_client);
    uint8_t *host_to_client_data = malloc(2048);
    assert_non_null(host_to_client_data);
    cfifo_init(mock->host_to_client, host_to_client_data, 2048, sizeof(uint8_t));

    mock->client_to_host = malloc(sizeof(cfifo_t));
    assert_non_null(mock->client_to_host);
    uint8_t *client_to_host_data = malloc(2048);
    assert_non_null(client_to_host_data);
    cfifo_init(mock->client_to_host, client_to_host_data, 2048, sizeof(uint8_t));

    salt_create(mock->client_channel,
                SALT_CLIENT,
                salt_channel_write,
                salt_channel_read, mock->client_time);
    salt_set_context(mock->client_channel,
                     mock->client_to_host,  /* Write */
                     mock->host_to_client); /* read */

    salt_create(mock->host_channel,
                SALT_SERVER,
                salt_channel_write,
                salt_channel_read, mock->host_time);
    salt_set_context(mock->host_channel,
                     mock->host_to_client,  /* Write */
                     mock->client_to_host); /* read */

}

void salt_channels_delete(salt_mock_t *mock)
{
    free(mock->host_to_client->p_buf);
    free(mock->host_to_client);
    free(mock->client_to_host->p_buf);
    free(mock->client_to_host);
    free(mock->host_channel);
    free(mock->client_channel);
}

salt_ret_t salt_read_mock(salt_io_channel_t *p_rchannel)
{
    test_data_t next;
    cfifo_t *cfifo = (cfifo_t *) p_rchannel->p_context;

    if (cfifo_get(cfifo, &next) == CFIFO_SUCCESS) {
        assert_int_equal(next.size, p_rchannel->size_expected);
        p_rchannel->size = next.size;
        memcpy(p_rchannel->p_data, next.data, next.size);
        free(next.data);
        return SALT_SUCCESS;
    }

    return SALT_ERROR;;
}

void salt_io_mock_time_impl(uint32_t *p_time)
{
    memset(p_time, 0, 4);
}

/*======= Local function implementations ====================================*/

static salt_ret_t salt_channel_read(salt_io_channel_t *p_rchannel)
{
    cfifo_t *read_queue = (cfifo_t*) p_rchannel->p_context;
    uint32_t size = p_rchannel->size_expected - p_rchannel->size;

    cfifo_read(read_queue, &p_rchannel->p_data[p_rchannel->size],
        &size);

    p_rchannel->size += size;

    if (p_rchannel->size == p_rchannel->size_expected) {
        SALT_HEXDUMP_DEBUG(p_rchannel->p_data, p_rchannel->size_expected);
        return SALT_SUCCESS;
    }

    return SALT_PENDING;

}

static salt_ret_t salt_channel_write(salt_io_channel_t *p_wchannel)
{
    cfifo_t *write_queue = (cfifo_t*) p_wchannel->p_context;
    uint32_t size = p_wchannel->size_expected - p_wchannel->size;
    cfifo_write(write_queue, &p_wchannel->p_data[p_wchannel->size], &size);
    p_wchannel->size += size;
    if (p_wchannel->size == p_wchannel->size_expected) {
        p_wchannel->size_expected = p_wchannel->size;
        SALT_HEXDUMP_DEBUG(p_wchannel->p_data, p_wchannel->size_expected);
        return SALT_SUCCESS;
    }

    return SALT_PENDING;
}

static salt_ret_t salt_mock_get_time(salt_time_t *p_time, uint32_t *time)
{
    cfifo_t *time_queue = (cfifo_t *) p_time->p_context;
    uint32_t next;
    if (cfifo_get(time_queue, &next) == CFIFO_SUCCESS) {
        *time = next;
        return SALT_SUCCESS;
    }
    return SALT_ERROR;
}

