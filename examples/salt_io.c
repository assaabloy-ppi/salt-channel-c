#include "salt_io.h"

#include <unistd.h>
#include <stdio.h>
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <sys/time.h>
#include <string.h>
#include "salt_util.h"

static salt_ret_t get_time(salt_time_t *p_time, uint32_t *time);

salt_time_t my_time = {
    get_time,
    NULL
};

salt_ret_t my_write(salt_io_channel_t *p_wchannel)
{
    int sock = *((int *) p_wchannel->p_context);
    int n = write(sock, p_wchannel->p_data, p_wchannel->size_expected);

    if (n < 0 || (uint32_t) n != p_wchannel->size_expected) {
        if (n == 0)
        {
            p_wchannel->err_code = SALT_ERR_CONNECTION_CLOSED;
        }
        return SALT_ERROR;
    }

    p_wchannel->size = p_wchannel->size_expected;

    return SALT_SUCCESS;
}

salt_ret_t my_read(salt_io_channel_t *p_rchannel)
{
    int sock = *((int *) p_rchannel->p_context);
    int n = read(sock, p_rchannel->p_data, p_rchannel->size_expected);

    if (n < 0 || (uint32_t) n != p_rchannel->size_expected) {
        p_rchannel->err_code = SALT_ERR_CONNECTION_CLOSED;
        return SALT_ERROR;
    }

    p_rchannel->size = p_rchannel->size_expected;

    return SALT_SUCCESS;
}

static salt_ret_t get_time(salt_time_t *p_time, uint32_t *time)
{
    (void) *p_time;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t curr_time = (tv.tv_sec) * 1000 + (tv.tv_usec) / 1000;
    uint32_t rel_time = curr_time % 0xFFFFFFFF;
    *time = rel_time;
    return SALT_SUCCESS;
}
