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

#include "salt_v2.h"
#include "../v2test/test_data.c"
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

    if((sock_desc = socket(AF_INET, SOCK_STREAM, 0)) < 0)
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

    if(pthread_create(&sniffer_thread, NULL,  connection_handler, (void*) &sock_desc) < 0)
    {
        perror("could not create thread");
        return 1;
    }

    printf("Connected successfully - Please enter string\n");

    while (1)
    {
        /*printf("Enter message: ");
        tx_size = read(0, tx_buffer, sizeof(tx_buffer));
        if (tx_size > 0) {
            printf("\033[A\33[2K\rclient: %*.*s", 0, tx_size, tx_buffer);
            write(sock_desc, tx_buffer, tx_size);
        }*/
    }

    close(sock_desc);

    return 0;

}

static void *connection_handler(void *context)
{
    int sock = *(int*) context;
    salt_channel_t channel;
    salt_ret_t ret;
    uint8_t hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE];
    uint32_t size;

    ret = salt_create(&channel, SALT_CLIENT, my_write, my_read, NULL);
    assert(ret == SALT_SUCCESS);
    ret = salt_create_signature(&channel); /* Creates a new signature. */
    assert(ret == SALT_SUCCESS);
    ret = salt_init_session(&channel, hndsk_buffer, sizeof(hndsk_buffer));
    assert(ret == SALT_SUCCESS);

    ret = salt_set_context(&channel, &sock, &sock);
    assert(ret == SALT_SUCCESS);

    ret = salt_handshake(&channel);

    while (ret != SALT_SUCCESS) {

        if (ret == SALT_ERROR) {
            printf("Salt error: 0x%02x\r\n", channel.err_code);
            printf("Salt error read: 0x%02x\r\n", channel.read_channel.err_code);
            printf("Salt error write: 0x%02x\r\n", channel.write_channel.err_code);
        }

        assert(ret != SALT_ERROR);

        salt_handshake(&channel);

    }

    printf("Salt handshake succeeded.\r\n");
    pthread_t write_thread;
    if(pthread_create(&write_thread, NULL,  write_handler, (void*) &channel) < 0)
    {
        puts("could not create write thread");
        pthread_exit(NULL);
    }

    do
    {
        memset(hndsk_buffer, 0, sizeof(hndsk_buffer));
        ret = salt_read(&channel, hndsk_buffer, &size, SALT_HNDSHK_BUFFER_SIZE);
        if (ret == SALT_SUCCESS)
        {
            printf("\33[2K\rhost: %*.*s", 0, size-1, &hndsk_buffer[SALT_OVERHEAD_SIZE+1]);
            printf("Enter message: ");
        }
    } while(ret == SALT_SUCCESS);


    close(sock);

    printf("Connection closed.\r\n");

    return 0;
}

static void *write_handler(void *context)
{
    salt_channel_t *channel = (salt_channel_t *) context;
    int tx_size;
    char tx_buffer[256];
    salt_ret_t ret_code;

    do
    {
        printf("Enter message: ");
        tx_size = read(0, &tx_buffer[SALT_OVERHEAD_SIZE+1], sizeof(tx_buffer)-SALT_OVERHEAD_SIZE-1);
        tx_buffer[SALT_OVERHEAD_SIZE] = 0x01;
        if (tx_size > 0) {
            printf("\r\n\033[A\33[2K\rclient: %*.*s\r\n", 0, tx_size-1, &tx_buffer[SALT_OVERHEAD_SIZE+1]);
            ret_code = salt_write(channel, (uint8_t*) tx_buffer, tx_size + SALT_OVERHEAD_SIZE + 1);
        }
    } while (ret_code == SALT_SUCCESS);


    pthread_exit(NULL);
}
