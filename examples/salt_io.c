#include "salt_io.h"

#include <unistd.h>
#include <stdio.h>
#include "salt_util.h"

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

    SALT_HEXDUMP(p_wchannel->p_data, p_wchannel->size_expected);

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

    SALT_HEXDUMP(p_rchannel->p_data, p_rchannel->size_expected);

    p_rchannel->size = p_rchannel->size_expected;

    return SALT_SUCCESS;
}
