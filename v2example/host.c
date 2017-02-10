#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>

#include "salt_v2.h"

static void *connection_handler(void *context);

struct clientInfo {
    int sock_fd;
    char ip_addr[16];
    struct sockaddr_in client;
};

int main(int argc , char *argv[])
{

    (void) argc;
    (void) argv;

    int socket_desc;
    int client_sock;
    struct clientInfo client_info;
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
    server.sin_port = htons(3000);

    if(bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
    {
        perror("bind failed. Error");
        return 1;
    }
    puts("bind done");

    listen(socket_desc , 3);

    puts("Waiting for incoming connections...");
    c = sizeof(struct sockaddr_in);

    //puts("\033[A\33[2K");

    client_info.sock_fd = accept(socket_desc,(struct sockaddr*)&client_info.client, (socklen_t*)&c);
    puts("Connection accepted");

    snprintf(client_info.ip_addr, 16, "%d.%d.%d.%d",
                        client_info.client.sin_addr.s_addr & 0xFF,
                        ((client_info.client.sin_addr.s_addr&0xFF00)>>8),
                        ((client_info.client.sin_addr.s_addr&0xFF0000)>>16),
                        ((client_info.client.sin_addr.s_addr&0xFF000000)>>24));

    pthread_t sniffer_thread;

    if(pthread_create(&sniffer_thread, NULL,  connection_handler, (void*) &client_info) < 0)
    {
        perror("could not create thread");
        return 1;
    }

    int tx_size;
    char tx_buffer[256];

    while (1)
    {
        printf("Enter message: ");
        tx_size = read(0, tx_buffer, sizeof(tx_buffer));
        if (tx_size > 0) {
            printf("\033[A\33[2K\rhost: %*.*s", 0, tx_size, tx_buffer);
            write(client_info.sock_fd, tx_buffer, tx_size);
        }
    }

    if (client_sock < 0)
    {
        perror("accept failed");
        return 1;
    }
    return 0;
}
/*
  This will handle connection for each client
  */
static void *connection_handler(void *context)
{
    //Get the socket descriptor
    struct clientInfo *client = (struct clientInfo *) context;
    int sock = client->sock_fd;
    int n;

    char client_message[2000];

    while((n = read(sock, client_message, 2000)) > 0)
    {
        printf("\33[2K\rclient (%s): %*.*s", client->ip_addr, 0, n, client_message);
        printf("Enter message: ");
    }

    close(sock);

    if(n == 0)
    {
        printf("\33[2K\rClient Disconnected");
    }
    else
    {
        perror("recv failed");
    }
    return 0;
}