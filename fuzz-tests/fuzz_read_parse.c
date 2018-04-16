#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "salt.h"
#include "salti_util.h"

#define MAX_READ_SIZE 8192

static uint8_t read_buf[MAX_READ_SIZE];

int main(void)
{

    salt_msg_t msg;
    uint32_t size = read(0, read_buf, sizeof(read_buf));

    if (size == 0) {
        return -1;
    }

    uint8_t *data = malloc(size);

    if (data == NULL) {
        return -1;
    }

    memcpy(data, read_buf, size);

    salt_err_t ret = salt_read_init(SALT_MULTI_APP_PKG_MSG_HEADER_VALUE, data, size, &msg);

    if (ret != SALT_ERR_NONE) {
        free(data);
        return -1;
    }

    uint16_t num_messages = 0;
    printf("=== Multi message ===\r\n");

    do {
        printf("Message %d: ", num_messages);
        for (uint32_t i = 0; i < msg.read.message_size; i++) {
            printf("%02x", msg.read.p_payload[i]);
        }
        printf("\r\n");
    } while (salt_read_next(&msg) == SALT_SUCCESS);

    free(data);
    return 0;

}