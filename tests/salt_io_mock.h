#ifndef _SALT_IO_MOCK_H_
#define _SALT_IO_MOCK_H_

/**
 * @file salt_io_mock.h
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

#define SALT_IO_MOCK_CREATE(p_channel, p_mock, num_items)                   \
    do {                                                                    \
        static salt_mock_t salt_mock;                                       \
        CFIFO_CREATE(salt_mock.expected_write, sizeof(test_data_t), num_items);   \
        CFIFO_CREATE(salt_mock.next_read, sizeof(test_data_t), num_items);  \
        p_mock = &salt_mock;                                                \
        salt_channel_t *tmp = p_channel;                                    \
        salt_set_context(tmp,                                               \
                         salt_mock.expected_write,                          \
                         salt_mock.next_read);                              \
    } while(0)

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

void salt_io_mock_reset(salt_mock_t *mock);
void salt_io_mock_set_next_read(salt_mock_t *mock, uint8_t *p_data, uint32_t size, bool add_size);
void salt_io_mock_expect_next_write(salt_mock_t *mock, uint8_t *p_data, uint32_t size, bool add_size);


salt_ret_t salt_write_mock(salt_io_channel_t *p_wchannel);
salt_ret_t salt_read_mock(salt_io_channel_t *p_rchannel);

#endif /* _SALT_IO_MOCK_H_ */

