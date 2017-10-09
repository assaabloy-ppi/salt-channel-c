#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "salt_v2.h"

int main(void) {

    uint8_t buf[1024];
    uint8_t cpy[1024];
    salt_msg_t msg;

    uint32_t size = read(0, buf, sizeof(buf));
    salt_err_t ret = salt_read_init(SALT_APP_PKG_MSG_HEADER_VALUE, buf, size, &msg);

    if (ret != SALT_ERR_NONE) {
        return 0;
    }

    do {
        memcpy(cpy, msg.read.p_payload, msg.read.message_size);
    } while (salt_read_next(&msg) == SALT_SUCCESS);

    ret = salt_read_init(SALT_MULTI_APP_PKG_MSG_HEADER_VALUE, buf, size, &msg);

    if (ret != SALT_ERR_NONE) {
        return 0;
    }

    do {
        memcpy(cpy, msg.read.p_payload, msg.read.message_size);
    } while (salt_read_next(&msg) == SALT_SUCCESS);

    return 0;
}