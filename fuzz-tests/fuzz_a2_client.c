#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "salt.h"
#include "util.h"
#include "test_data.h"

static int _main(void) {

    salt_channel_t channel;
    salt_ret_t ret;
    uint8_t hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE];
    memset(hndsk_buffer, 0xcc, sizeof(hndsk_buffer));

    salt_create(&channel, SALT_CLIENT, fuzz_write, fuzz_read, &mock_time);
    salt_set_delay_threshold(&channel, 1000);
    salt_set_signature(&channel, salt_example_session_1_data.client_sk_sec);
    salt_init_session_using_key(&channel,
                                hndsk_buffer,
                                SALT_HNDSHK_BUFFER_SIZE,
                                salt_example_session_1_data.client_ek_pub,
                                salt_example_session_1_data.client_ek_sec);
    salt_protocols_t host_protocols;
    

    do {
        ret = salt_a1a2(&channel, hndsk_buffer, SALT_HNDSHK_BUFFER_SIZE, &host_protocols, NULL);
    } while (ret == SALT_PENDING);

    if (ret == SALT_ERROR)
    {
        return -1;
    }
    
    for (uint8_t i = 0; i < host_protocols.count; i+= 2) {
        printf("Protocol %i: %*.*s\r\n", i, 0, (int) sizeof(salt_protocol_t), host_protocols.p_protocols[i+1]);
    }

    return 0;

}

int main(void)
{
    #ifdef __AFL_LOOP
        while (__AFL_LOOP(1000))
        {
            _main();
        }
    #else
        return _main();
    #endif

    return 0;
}
