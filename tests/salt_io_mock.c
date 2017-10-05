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
#include "salt_io_mock.h"
#include "salt_util.h"

/*======= Local Macro Definitions ===========================================*/
/*======= Type Definitions ==================================================*/
/*======= Local variable declarations =======================================*/
/*======= Local function prototypes =========================================*/
/*======= Global function implementations ===================================*/


void salt_io_mock_reset(salt_mock_t *mock)
{
    test_data_t next;
    while (cfifo_get(mock->expected_write, &next) == CFIFO_SUCCESS) {
        free(next.data);
    }
    while (cfifo_get(mock->next_read, &next) == CFIFO_SUCCESS) {
        free(next.data);
    }
}

void salt_io_mock_set_next_read(salt_mock_t *mock, uint8_t *p_data, uint32_t size, bool add_size)
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

void salt_io_mock_expect_next_write(salt_mock_t *mock, uint8_t *p_data, uint32_t size, bool add_size)
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


/*======= Local function implementations ====================================*/
