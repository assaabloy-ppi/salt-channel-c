#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "salt_v2.h"
#include "test_data.h"

void randombytes(unsigned char *p_bytes, unsigned long long length)
{
    memcpy(p_bytes, salt_test_data.host_ek_sec, length);
}


static uint8_t m4[124] = {
    0x78, 0x00, 0x00, 0x00, // 120
    0x06, 0x00, 0xb4, 0xc3, 0xe5, 0xc6, 0xe4, 0xa4,
    0x05, 0xe9, 0x1e, 0x69, 0xa1, 0x13, 0xb3, 0x96,
    0xb9, 0x41,
    /* Crypt is mocked, this is M4 in clear text */  
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25, 0x07,
    0x86, 0x8e, 0x97, 0x77, 0x0d, 0x72, 0x49, 0x7b,
    0x32, 0xee, 0x6b, 0x54, 0x26, 0xa3, 0x67, 0x9d,
    0x33, 0xa7, 0x6b, 0xc9, 0x36, 0x3d, 0x81, 0x8f,
    0x7e, 0xbc, 0x7a, 0x48, 0x48, 0x9a, 0x4c, 0x54,
    0x2f, 0x50, 0xb3, 0xeb, 0x34, 0x43, 0x96, 0xfc,
    0xcd, 0x3f, 0xc5, 0x01, 0x8e, 0x46, 0x77, 0x0c,
    0xcf, 0xff, 0x56, 0x5a, 0x07, 0xa1, 0xde, 0x16,
    0xd1, 0xd5, 0xab, 0x26, 0xf4, 0xa5, 0x93, 0x7e,
    0x72, 0xb8, 0x2a, 0x65, 0xe4, 0x3b, 0x8d, 0x96,
    0x4a, 0x54, 0xdc, 0x3c, 0xf3, 0x27, 0xab, 0x69,
    0x57, 0xc9, 0xe4, 0x68, 0x24, 0x1f, 0x3b, 0x7f,
    0xac, 0x64, 0x05, 0x08, 0x28, 0x03
};

salt_ret_t my_write(salt_io_channel_t *p_wchannel)
{
    return SALT_SUCCESS;
}

salt_ret_t my_read(salt_io_channel_t *p_rchannel)
{
    static uint8_t i = 0;
    static uint32_t size;

    static uint8_t buf[SALT_HNDSHK_BUFFER_SIZE];

    switch (i) {
        case 0:
            memcpy(p_rchannel->p_data, salt_test_data.m1, 4);
            p_rchannel->size = 4;
            break;
        case 1:
            memcpy(p_rchannel->p_data, &salt_test_data.m1[4], p_rchannel->size_expected);
            p_rchannel->size = p_rchannel->size_expected;
            break;
        case 2:
            memcpy(p_rchannel->p_data, m4, 4);
            p_rchannel->size = 4;
            break;
        case 3:
            memcpy(p_rchannel->p_data, &m4[4], p_rchannel->size_expected);
            p_rchannel->size = p_rchannel->size_expected;
            break;
        case 4:
            size = read(0, buf, SALT_HNDSHK_BUFFER_SIZE);
            p_rchannel->size = 4;
            memcpy(p_rchannel->p_data, &size, 4);
            break;
        case 5:
            memcpy(p_rchannel->p_data, buf, p_rchannel->size_expected);
            p_rchannel->size = p_rchannel->size_expected;
            break;
        default:
            return SALT_ERROR;
    }

    i++;

    return SALT_SUCCESS;
}

void my_time_impl(uint32_t *p_time) {
    memset(p_time, 0, 4);
}

int main(void) {

    salt_channel_t channel;
    salt_ret_t ret;
    uint8_t hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE];
    memset(hndsk_buffer, 0xcc, SALT_HNDSHK_BUFFER_SIZE);
    uint8_t sig[64];

    ret = salt_create(&channel, SALT_SERVER, my_write, my_read, my_time_impl);
    ret = salt_set_signature(&channel, sig);
    ret = salt_init_session(&channel, hndsk_buffer, SALT_HNDSHK_BUFFER_SIZE);
    ret = salt_handshake(&channel);

    salt_msg_t read_msg;
    ret = salt_read_begin(&channel, hndsk_buffer, sizeof(hndsk_buffer), &read_msg);

    if (ret == SALT_ERROR) {
        return 0;
    }

    do {
        memset(read_msg.read.p_message, 0x00, read_msg.read.message_size);
    } while (salt_read_next(&read_msg) == SALT_SUCCESS);

    if (ret == SALT_SUCCESS) {
        return 0;
    }

    return 0;
}