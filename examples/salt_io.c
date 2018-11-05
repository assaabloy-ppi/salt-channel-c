#include "salt_io.h"

#include <unistd.h>
#include <stdio.h>
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <sys/time.h>
#include <string.h>
#include "salti_util.h"

static salt_ret_t get_time(salt_time_t *p_time, uint32_t *time);

salt_time_t my_time = {
    get_time,
    NULL
};

salt_ret_t my_write(salt_io_channel_t *p_wchannel)
{
    int sock = *((int *) p_wchannel->p_context);
    uint32_t to_write = p_wchannel->size_expected - p_wchannel->size;

    if (sock <= 0) {
        return SALT_ERROR;
    }

    printf("p_rchannel->p_data: 0x%p\r\n", (void *) p_wchannel->p_data);

    int n = write(sock,
                  &p_wchannel->p_data[p_wchannel->size],
                  to_write);

    if (n <= 0) {
        p_wchannel->err_code = SALT_ERR_CONNECTION_CLOSED;
        return SALT_ERROR;
    }

    SALT_HEXDUMP_DEBUG(&p_wchannel->p_data[p_wchannel->size], n);

    p_wchannel->size += n;

    return (p_wchannel->size == p_wchannel->size_expected) ? SALT_SUCCESS : SALT_PENDING;
}

salt_ret_t my_read(salt_io_channel_t *p_rchannel)
{
    int sock = *((int *) p_rchannel->p_context);
    uint32_t to_read = p_rchannel->size_expected - p_rchannel->size;

    if (sock <= 0) {
        return SALT_ERROR;
    }

    int n = read(sock,
                 &p_rchannel->p_data[p_rchannel->size],
                 to_read);

    if (n <= 0) {
        p_rchannel->err_code = SALT_ERR_CONNECTION_CLOSED;
        return SALT_ERROR;
    }

    SALT_HEXDUMP_DEBUG(&p_rchannel->p_data[p_rchannel->size], n);

    p_rchannel->size += n;

    return (p_rchannel->size == p_rchannel->size_expected) ? SALT_SUCCESS : SALT_PENDING;

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
