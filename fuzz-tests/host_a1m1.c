#include <string.h>
#include "libfuzzer.inc"

#include "salt.h"
#include "test_data.h"

void randombytes(unsigned char *p_bytes, unsigned long long length)
{
    memcpy(p_bytes, salt_example_session_1_data.host_ek_sec, length);
}


salt_ret_t my_write(salt_io_channel_t *p_wchannel)
{
    (void) p_wchannel;
    return SALT_ERROR;
}

salt_ret_t my_read(salt_io_channel_t *p_rchannel)
{
    static uint8_t i = 0;
    static uint32_t size;

    static uint8_t buf[SALT_HNDSHK_BUFFER_SIZE];

    switch (i) {
        case 0:
            size = read(0, buf, SALT_HNDSHK_BUFFER_SIZE);
            p_rchannel->size = 4;
            memcpy(p_rchannel->p_data, &size, 4);
            break;
        case 1:
            memcpy(p_rchannel->p_data, buf, p_rchannel->size_expected);
            p_rchannel->size = p_rchannel->size_expected;
            break;
        default:
            return SALT_ERROR;
    }

    i++;

    return SALT_SUCCESS;
}

int main(void)
{

    salt_channel_t channel;
    salt_ret_t ret;
    uint8_t hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE];
    memset(hndsk_buffer, 0xcc, SALT_HNDSHK_BUFFER_SIZE);
    uint8_t sig[64];

    ret = salt_create(&channel, SALT_SERVER, my_write, my_read, NULL);

    uint8_t protocol_buf[128];
    salt_protocols_t my_protocols;
    ret = salt_protocols_init(&channel, &my_protocols, protocol_buf, sizeof(protocol_buf));
    ret = salt_protocols_append(&my_protocols, "Echo", 4);
    ret = salt_protocols_append(&my_protocols, "Temp", 4);
    ret = salt_protocols_append(&my_protocols, "Sensor", 6);

    ret = salt_set_signature(&channel, sig);
    ret = salt_init_session(&channel, hndsk_buffer, SALT_HNDSHK_BUFFER_SIZE);
    ret = salt_handshake(&channel, NULL);

    if (ret == SALT_ERROR) {
        return 0;
    }

    return 0;
}
