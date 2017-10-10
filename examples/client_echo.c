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
#include "salt_io.h"

static void *connection_handler(void *context);
static void *write_handler(void *context);

int main(int argc, char **argv)
{
    //test();
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

    printf("Connection to %s\r\n", addr);
    if (connect(sock_desc, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        printf("Failed to connect to server\n");
        return -1;
    }

    pthread_t sniffer_thread;

    if (pthread_create(&sniffer_thread, NULL,  connection_handler, (void*) &sock_desc) < 0)
    {
        perror("could not create thread");
        return 1;
    }

    printf("Connected successfully - Please enter string\n");

    pthread_join(sniffer_thread, NULL);

    close(sock_desc);

    return 0;

}

static void *connection_handler(void *context)
{
    int sock = *(int*) context;
    salt_channel_t channel;
    salt_ret_t ret;
    uint8_t hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE];
    salt_msg_t msg_in;

    ret = salt_create(&channel, SALT_CLIENT, my_write, my_read, &my_time);
    assert(ret == SALT_SUCCESS);
    ret = salt_create_signature(&channel); /* Creates a new signature. */
    assert(ret == SALT_SUCCESS);
    ret = salt_init_session(&channel, hndsk_buffer, sizeof(hndsk_buffer));
    assert(ret == SALT_SUCCESS);

    ret = salt_set_context(&channel, &sock, &sock);
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

    printf("Salt handshake succeeded.\r\n");
    pthread_t write_thread;
    if (pthread_create(&write_thread, NULL,  write_handler, (void*) &channel) < 0)
    {
        puts("could not create write thread");
        pthread_exit(NULL);
    }

    do
    {
        memset(hndsk_buffer, 0, sizeof(hndsk_buffer));
        ret = salt_read_begin(&channel, hndsk_buffer, sizeof(hndsk_buffer), &msg_in);
        if (ret == SALT_SUCCESS)
        {
            do {
                printf("\33[2K\rhost: %*.*s", 0, msg_in.read.message_size - 1, &msg_in.read.p_payload[1]);
                printf("Enter message: ");
            } while (salt_read_next(&msg_in) == SALT_SUCCESS);

        }
    } while (ret == SALT_SUCCESS);

    pthread_exit(NULL);
}

static void *write_handler(void *context)
{
    salt_channel_t *channel = (salt_channel_t *) context;
    int tx_size;
    char input[256];
    uint8_t tx_buffer[1024];
    salt_ret_t ret_code;
    salt_msg_t out_msg;

    do
    {
        printf("Enter message: ");
        tx_size = read(0, &input[1], sizeof(input) - 1);
        input[0] = 0x01;
        if (tx_size > 0) {
            salt_write_begin(tx_buffer, sizeof(tx_buffer), &out_msg);
            salt_write_next(&out_msg, (uint8_t *)input, tx_size + 1);
            printf("\r\n\033[A\33[2K\rclient: %*.*s\r\n", 0, tx_size - 1, &input[1]);
            ret_code = salt_write_execute(channel, &out_msg, false);
        }
    } while (ret_code == SALT_SUCCESS);


    pthread_exit(NULL);
}
