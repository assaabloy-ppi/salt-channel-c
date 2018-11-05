#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <semaphore.h>

#include "salt.h"
#include "salt_io.h"
#include "salti_util.h"

static void *connection_handler(void *context);

static uint8_t host_sk_sec[64] = {
    0x7a, 0x77, 0x2f, 0xa9, 0x01, 0x4b, 0x42, 0x33,
    0x00, 0x07, 0x6a, 0x2f, 0xf6, 0x46, 0x46, 0x39,
    0x52, 0xf1, 0x41, 0xe2, 0xaa, 0x8d, 0x98, 0x26,
    0x3c, 0x69, 0x0c, 0x0d, 0x72, 0xee, 0xd5, 0x2d,
    0x07, 0xe2, 0x8d, 0x4e, 0xe3, 0x2b, 0xfd, 0xc4,
    0xb0, 0x7d, 0x41, 0xc9, 0x21, 0x93, 0xc0, 0xc2,
    0x5e, 0xe6, 0xb3, 0x09, 0x4c, 0x62, 0x96, 0xf3,
    0x73, 0x41, 0x3b, 0x37, 0x3d, 0x36, 0x16, 0x8b
};

struct clientInfo {
    int sock_fd;
    char ip_addr[16];
    struct sockaddr_in client;
    salt_channel_t channel;
};

int main(void)
{

    int socket_desc;


    struct clientInfo *client_info;

    int c;
    struct sockaddr_in server;
    setbuf(stdout, NULL);

    socket_desc = socket(AF_INET , SOCK_STREAM , 0);

    if (socket_desc == -1)
    {
        printf("Could not create socket");
    }

    int reuse = 1;
    if (setsockopt(socket_desc, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0) {
        printf("setsockopt(SO_REUSEADDR) failed");
        return 1;
    }

    puts("Socket created");

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(2033);

    if (bind(socket_desc, (struct sockaddr *)&server , sizeof(server)) < 0)
    {
        perror("bind failed. Error");
        return 1;
    }
    puts("bind done");

    listen(socket_desc , 3);

    while (1)
    {
        puts("Waiting for incoming connections...");
        c = sizeof(struct sockaddr_in);

        client_info = malloc(sizeof(struct clientInfo));

        client_info->sock_fd = accept(socket_desc, (struct sockaddr*)&client_info->client, (socklen_t*)&c);
        puts("Connection accepted");

        if (client_info->sock_fd < 0) {
            printf("Accept error.\r\n");
            continue;
        }

        snprintf(client_info->ip_addr, 16, "%d.%d.%d.%d",
                 client_info->client.sin_addr.s_addr & 0xFF,
                 ((client_info->client.sin_addr.s_addr & 0xFF00) >> 8),
                 ((client_info->client.sin_addr.s_addr & 0xFF0000) >> 16),
                 ((client_info->client.sin_addr.s_addr & 0xFF000000) >> 24));

        pthread_t salt_thread;

        if (pthread_create(&salt_thread, NULL,  connection_handler, (void*) client_info) < 0)
        {
            puts("could not create thread");
            return 1;
        }

        printf("Waiting for client to disconnect.\r\n");

    }

    pthread_exit(NULL);
}

static void *connection_handler(void *context)
{
    //Get the socket descriptor
    struct clientInfo *client = (struct clientInfo *) context;
    int sock = client->sock_fd;
    salt_ret_t ret;

    uint8_t hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE];
    uint8_t rx_buffer[UINT16_MAX * 4];
    salt_msg_t msg_in;
    uint8_t tx_buffer[UINT16_MAX * 4];
    salt_msg_t msg_out;

    uint8_t protocol_buffer[128];
    salt_protocols_t protocols;
    uint8_t version[2] = { 0x00, 0x01 };

    ret = salt_create(&client->channel, SALT_SERVER, my_write, my_read, &my_time);
    assert(ret == SALT_SUCCESS);
    ret = salt_protocols_init(&client->channel, &protocols, protocol_buffer, sizeof(protocol_buffer));
    assert(ret == SALT_SUCCESS);
    ret = salt_protocols_append(&protocols, "ECHO", 4);
    assert(ret == SALT_SUCCESS);
    ret = salt_set_signature(&client->channel, host_sk_sec);
    assert(ret == SALT_SUCCESS);
    ret = salt_init_session(&client->channel, hndsk_buffer, sizeof(hndsk_buffer));
    assert(ret == SALT_SUCCESS);

    ret = salt_set_context(&client->channel, &client->sock_fd, &client->sock_fd);
    assert(ret == SALT_SUCCESS);
    salt_set_delay_threshold(&client->channel, 20000);
    ret = salt_handshake(&client->channel, NULL);

    uint32_t size;

    while (ret != SALT_SUCCESS) {

        if (ret == SALT_ERROR) {
            printf("Error during handshake:\r\n");
            printf("Salt error: 0x%02x\r\n", client->channel.err_code);
            printf("Salt error read: 0x%02x\r\n", client->channel.read_channel.err_code);
            printf("Salt error write: 0x%02x\r\n", client->channel.write_channel.err_code);

            close(sock);

            printf("Connection closed.\r\n");

            free(client);
            pthread_exit(NULL);

            break;
        }

        ret = salt_handshake(&client->channel, NULL);
    }

    printf("Salt handshake succeeded.\r\n");

    do
    {
        memset(hndsk_buffer, 0, sizeof(hndsk_buffer));

        do {
            ret = salt_read_begin(&client->channel, rx_buffer, sizeof(rx_buffer), &msg_in);
        } while (ret == SALT_PENDING);

        if (ret == SALT_ERROR) {
            printf("Error during read:\r\n");
            printf("Salt error: 0x%02x\r\n", client->channel.err_code);
            printf("Salt error read: 0x%02x\r\n", client->channel.read_channel.err_code);
            printf("Salt error write: 0x%02x\r\n", client->channel.write_channel.err_code);
            break;
        }

        ret = salt_write_begin(tx_buffer, sizeof(tx_buffer), &msg_out);
        assert(ret == SALT_SUCCESS);
        bool last = false;

        do {
            if (msg_in.read.message_size > 0) {
                switch (msg_in.read.p_payload[0]) {
                    case 0x00:
                        ret = salt_write_next(&msg_out, version, sizeof(version));
                        assert(ret == SALT_SUCCESS);
                        break;
                    case 0x01:
                        ret = salt_write_next(&msg_out, msg_in.read.p_payload, msg_in.read.message_size);
                        assert(ret == SALT_SUCCESS);
                        break;
                    case 0x02:
                        if (msg_in.read.message_size < 6) {
                            assert(false);
                        }
                        size = salti_bytes_to_u32(&msg_in.read.p_payload[1]);
                        printf("size: %d, 0x%02x\r\n", size, msg_in.read.p_payload[5]);
                        if (size > msg_out.write.buffer_available) {
                            assert(false);
                        }
                        SALT_HEXDUMP_DEBUG(msg_out.write.p_payload, size + 1);
                        msg_out.write.p_payload[0] = 0x02;
                        memset(&msg_out.write.p_payload[1], msg_in.read.p_payload[5], size);
                        SALT_HEXDUMP_DEBUG(msg_out.write.p_payload, size + 1);
                        salt_write_commit(&msg_out, size + 1);
                        break;
                    case 0x03:
                        msg_out.write.p_payload[0] = 0x03;
                        salt_write_commit(&msg_out, 1);
                        last = true;
                        break;
                }
            }
        } while (salt_read_next(&msg_in) == SALT_SUCCESS);

        do {
            ret = salt_write_execute(&client->channel, &msg_out, last);
        } while (ret == SALT_PENDING);

        if (last) {
            break;
        }

    } while (ret == SALT_SUCCESS);


    close(sock);

    printf("Connection closed.\r\n");

    free(client);

    pthread_exit(NULL);
}

