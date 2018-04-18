/**
 * @file util.c
 *
 * Description
 *
 */

/*======= Includes ==========================================================*/

#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

/*======= Local Macro Definitions ===========================================*/
/*======= Type Definitions ==================================================*/
/*======= Local function prototypes =========================================*/

static salt_ret_t get_time(salt_time_t *p_time, uint32_t *time);

/*======= Local variable declarations =======================================*/
/*======= Global function implementations ===================================*/

salt_time_t mock_time = {
    get_time,
    NULL
};

void randombytes(unsigned char *p_bytes, unsigned long long length)
{
    (void) p_bytes;
    (void) length;
}

void hexprint(const uint8_t *ptr, uint32_t size)
{
    for (uint32_t i = 0; i < size; i++) {
        printf("%02x", ptr[i]);
    }
}

salt_ret_t fuzz_write(salt_io_channel_t *p_wchannel)
{
    printf("fuzz_write: ");
    hexprint(p_wchannel->p_data, p_wchannel->size_expected);
    printf("\r\n");
    memset(p_wchannel->p_data, 0x00, p_wchannel->size_expected);
    p_wchannel->size = p_wchannel->size_expected;
    return SALT_SUCCESS;
}

salt_ret_t fuzz_read(salt_io_channel_t *p_rchannel)
{

    salt_ret_t ret;
    uint8_t *data = malloc(p_rchannel->size_expected);

    if (data == NULL) {
        p_rchannel->err_code = SALT_ERR_CONNECTION_CLOSED;
        return SALT_ERROR;
    }

    uint32_t size = read(0, data, p_rchannel->size_expected);

    if (size == 0) {
        p_rchannel->err_code = SALT_ERR_CONNECTION_CLOSED;
        ret = SALT_ERROR;
    }

    else {
        memcpy(p_rchannel->p_data, data, size);
        p_rchannel->size += size;
        ret = (p_rchannel->size == p_rchannel->size_expected) ? SALT_SUCCESS : SALT_ERROR;
    }

    free(data);

    return ret;

}

/*======= Local function implementations ====================================*/

static salt_ret_t get_time(salt_time_t *p_time, uint32_t *time)
{
    (void) p_time;
    static uint32_t m_time = 0;
    *time = m_time;
    m_time += 1000;
    return SALT_SUCCESS;
}
