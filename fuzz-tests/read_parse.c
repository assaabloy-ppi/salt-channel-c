#include <string.h>
#include <stdlib.h>
#include "libfuzzer.inc"

#include "salt.h"
#include "salti_util.h"

int main(void) {

    uint8_t buf[1024];
    salt_msg_t msg;

    uint32_t size = read(0, buf, sizeof(buf));

    uint8_t *data = malloc(size);

    if (data == NULL) {
        return 0;
    }

    uint32_t cpy_used = 0;
    uint8_t *cpy = malloc(size);
    if (cpy == NULL) {
        free(data);
        return 0;
    }

    memcpy(data, buf, size);

    salt_err_t ret = salt_read_init(SALT_APP_PKG_MSG_HEADER_VALUE, data, size, &msg);

    if (ret != SALT_ERR_NONE) {
        free(data);
        free(cpy);
        return 0;
    }

    do {
        memcpy(&cpy[cpy_used], msg.read.p_payload, msg.read.message_size);
        cpy_used += msg.read.message_size;
    } while (salt_read_next(&msg) == SALT_SUCCESS);

    cpy_used = 0;
    ret = salt_read_init(SALT_MULTI_APP_PKG_MSG_HEADER_VALUE, data, size, &msg);

    if (ret != SALT_ERR_NONE) {
        free(data);
        free(cpy);
        return 0;
    }

    do {
        memcpy(&cpy[cpy_used], msg.read.p_payload, msg.read.message_size);
        cpy_used += msg.read.message_size;
    } while (salt_read_next(&msg) == SALT_SUCCESS);

    free(data);
    free(cpy);
    return 0;
}
