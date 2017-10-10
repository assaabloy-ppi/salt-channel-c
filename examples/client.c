/**
 * @file client.c
 *
 *
 * Description
 *
 */

/*======= Includes ==========================================================*/

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>

#include "salt.h"
#include "salti_util.h"
#include "binson_light.h"
#include "salt_io.h"

/*======= Local Macro Definitions ===========================================*/
/*======= Type Definitions ==================================================*/
/*======= Local variable declarations =======================================*/
/*======= Local function prototypes =========================================*/
/*======= Global function implementations ===================================*/

int main(int argc, char **argv)
{

    int sock_desc;
    struct sockaddr_in serv_addr;
    setbuf(stdout, NULL);
    char localhost[] = "127.0.0.1";
    char *addr = localhost;

    if (argc > 1)
    {
        addr = argv[1];
    }

    if ((sock_desc = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        printf("Failed creating socket\n");

    bzero((char *) &serv_addr, sizeof (serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(addr);
    serv_addr.sin_port = htons(2033);

    printf("Connecting to %s\r\n", addr);
    if (connect(sock_desc, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        printf("Failed to connect to server\n");
        return -1;
    }

    printf("Connected.\r\n");

    salt_channel_t channel;
    salt_ret_t ret;
    uint8_t hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE];
    salt_msg_t msg_out;

    ret = salt_create(&channel, SALT_CLIENT, my_write, my_read, &my_time);
    assert(ret == SALT_SUCCESS);
    ret = salt_create_signature(&channel); /* Creates a new signature. */
    assert(ret == SALT_SUCCESS);
    ret = salt_init_session(&channel, hndsk_buffer, sizeof(hndsk_buffer));
    assert(ret == SALT_SUCCESS);

    ret = salt_set_context(&channel, &sock_desc, &sock_desc);
    assert(ret == SALT_SUCCESS);

    salt_set_delay_threshold(&channel, 1000);

    ret = salt_handshake(&channel, NULL);

    while (ret != SALT_SUCCESS) {

        if (ret == SALT_ERROR) {
            printf("Salt error: 0x%02x\r\n", channel.err_code);
            printf("Salt error read: 0x%02x\r\n", channel.read_channel.err_code);
            printf("Salt error write: 0x%02x\r\n", channel.write_channel.err_code);
        }

        assert(ret != SALT_ERROR);

        salt_handshake(&channel, NULL);

    }

    uint8_t t[2] = { 0x02, 0x02 };
    ret = salt_write_begin(hndsk_buffer, sizeof(hndsk_buffer), &msg_out);
    binson_writer  w;

    binson_writer_init(&w, msg_out.write.p_payload, msg_out.write.buffer_available);
    binson_write_object_begin(&w);
    binson_write_name(&w, "c");
    binson_write_string(&w, "getInfo");
    binson_write_name(&w, "i");
    binson_write_integer(&w, 1);
    binson_write_name(&w, "t");
    binson_write_bytes(&w, t, 2);
    binson_write_object_end(&w);

    printf("Sending data:\r\n");
    SALT_HEXDUMP_DEBUG(w.io.pbuf, binson_writer_get_counter(&w));

    salt_write_commit(&msg_out, binson_writer_get_counter(&w));

    binson_writer_init(&w, msg_out.write.p_payload, msg_out.write.buffer_available);
    binson_write_object_begin(&w);
    binson_write_name(&w, "c");
    binson_write_string(&w, "u");
    binson_write_name(&w, "i");
    binson_write_integer(&w, 1);
    binson_write_name(&w, "t");
    binson_write_bytes(&w, t, 2);
    binson_write_object_end(&w);

    printf("Sending data:\r\n");
    SALT_HEXDUMP_DEBUG(w.io.pbuf, binson_writer_get_counter(&w));

    salt_write_commit(&msg_out, binson_writer_get_counter(&w));
    
    ret = SALT_PENDING;
    do {
        ret = salt_write_execute(&channel, &msg_out, false);
    } while (ret == SALT_PENDING);
    

    ret = SALT_PENDING;

    while (1) {
        do {
            ret = salt_read_begin(&channel, hndsk_buffer, sizeof(hndsk_buffer), &msg_out);
        } while (ret == SALT_PENDING);

        if (ret == SALT_ERROR) {
            break;
        }

        do {
            printf("Received data:\r\n");
            SALT_HEXDUMP_DEBUG(msg_out.read.p_payload, msg_out.read.message_size);
        } while (salt_read_next(&msg_out) == SALT_SUCCESS);
    }

    close(sock_desc);

}

/*======= Local function implementations ====================================*/
