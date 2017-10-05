#ifndef _SALT_MOCK_H_
#define _SALT_MOCK_H_

/**
 * @file salt_mock.h
 *
 * Description
 *
 */

/*======= Includes ==========================================================*/

#include <stdint.h>
#include <stdbool.h>
#include "salt_v2.h"
#include "cfifo.h"

/*======= Public macro definitions ==========================================*/

/*======= Type Definitions and declarations =================================*/

typedef struct test_data_s {
    uint8_t *data;
    uint32_t size;
} test_data_t;

typedef struct salt_mock_s {
    cfifo_t *expected_write;
    cfifo_t *next_read;
} salt_mock_t;

/*======= Public function declarations ======================================*/

salt_mock_t *salt_io_mock_create(void);
void salt_io_mock_delete(salt_mock_t *mock);
void salt_io_mock_reset(salt_mock_t *mock);
void salt_io_mock_init(salt_channel_t *channel, salt_mock_t *mock);

void salt_io_mock_set_next_read(salt_mock_t *mock, uint8_t *p_data, uint32_t size, bool add_size);
void salt_io_mock_expect_next_write(salt_mock_t *mock, uint8_t *p_data, uint32_t size, bool add_size);


salt_ret_t salt_write_mock(salt_io_channel_t *p_wchannel);
salt_ret_t salt_read_mock(salt_io_channel_t *p_rchannel);
void salt_mock_time_impl(uint32_t *p_time);

#endif /* _SALT_MOCK_H_ */

