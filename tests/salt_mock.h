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
#include "salt.h"
#include "cfifo.h"

/*======= Public macro definitions ==========================================*/

/*======= Type Definitions and declarations =================================*/

typedef struct test_data_s {
    uint8_t *data;
    uint32_t size;
} test_data_t;

typedef struct salt_io_mock_s {
    cfifo_t *expected_write;
    cfifo_t *next_read;
} salt_io_mock_t;

typedef struct salt_mock_s {
    salt_time_t *time;
    salt_io_mock_t *io;

    /* Simulate next time for client and host */
    salt_time_t     *client_time;
    salt_time_t     *host_time;

    /* To test expected I/O for host and client */
    salt_io_mock_t  *expected_client_io;
    salt_io_mock_t  *expected_host_io;

    /* Queues to simulate I/O client and host */
    cfifo_t         *host_to_client;
    cfifo_t         *client_to_host;

    /* Channels that talks to eachother */
    salt_channel_t  *client_channel;
    salt_channel_t  *host_channel;

} salt_mock_t;

/*======= Public function declarations ======================================*/

salt_mock_t *salt_mock_create(void);
void salt_mock_delete(salt_mock_t* mock);

salt_time_t *salt_time_mock_create(void);
void salt_time_mock_set_next(salt_time_t *mock, uint32_t time);
void salt_time_mock_delete(salt_time_t *mock);

salt_io_mock_t *salt_io_mock_create(void);
void salt_io_mock_delete(salt_io_mock_t *mock);
void salt_io_mock_reset(salt_io_mock_t *mock);
void salt_io_mock_init(salt_channel_t *channel, salt_io_mock_t *mock);

void salt_io_mock_set_next_read(salt_io_mock_t *mock, uint8_t *p_data, uint32_t size, bool add_size);
void salt_io_mock_expect_next_write(salt_io_mock_t *mock, uint8_t *p_data, uint32_t size, bool add_size);

void salt_channels_create(salt_mock_t *mock);
void salt_channels_delete(salt_mock_t *mock);

salt_ret_t salt_write_mock(salt_io_channel_t *p_wchannel);
salt_ret_t salt_read_mock(salt_io_channel_t *p_rchannel);

#endif /* _SALT_MOCK_H_ */

