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
#include "salt_util.h"

/*======= Local Macro Definitions ===========================================*/
/*======= Type Definitions ==================================================*/
/*======= Local variable declarations =======================================*/
/*======= Local function prototypes =========================================*/


static salt_ret_t salt_mock_get_time(salt_time_t *p_time, uint32_t *time);

/*======= Global function implementations ===================================*/

salt_mock_t *salt_mock_create(void)
{
    salt_mock_t *mock = malloc(sizeof(salt_mock_t));
    mock->time = salt_time_mock_create();
    mock->io = salt_io_mock_create();

    mock->client_time = salt_time_mock_create();
    mock->host_time = salt_time_mock_create();

    return mock;
}
void salt_mock_delete(salt_mock_t* mock)
{
    salt_time_mock_delete(mock->time);
    salt_time_mock_delete(mock->client_time);
    salt_time_mock_delete(mock->host_time);
    salt_io_mock_delete(mock->io);
    free(mock);
}

salt_time_t *salt_time_mock_create(void)
{
    salt_time_t *mock;
    mock = malloc(sizeof(salt_time_t));
    cfifo_t *time_queue = malloc(sizeof(cfifo_t));
    uint8_t *time_queue_data = malloc(sizeof(uint32_t) * 10);
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
    mock->expected_write = malloc(sizeof(cfifo_t));
    mock->next_read = malloc(sizeof(cfifo_t));

    uint8_t *expected_write = malloc(sizeof(test_data_t) * 10);
    uint8_t *next_read = malloc(sizeof(test_data_t) * 10);

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

