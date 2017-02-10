#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

static void *connection_handler(void *context);

int main()
{
    int sock_desc;
    struct sockaddr_in serv_addr;
    setbuf(stdout, NULL);

    if((sock_desc = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        printf("Failed creating socket\n");

    bzero((char *) &serv_addr, sizeof (serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serv_addr.sin_port = htons(3000);

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
    int tx_size;
    char tx_buffer[256];

    while (1)
    {
        printf("Enter message: ");
        tx_size = read(0, tx_buffer, sizeof(tx_buffer));
        if (tx_size > 0) {
            printf("\033[A\33[2K\rclient: %*.*s", 0, tx_size, tx_buffer);
            write(sock_desc, tx_buffer, tx_size);
        }
    }

    close(sock_desc);

    return 0;

}

static void *connection_handler(void *context)
{
    char client_message[2000];
    int n;
    int sock = *(int*) context;
    while((n = read(sock, client_message, 2000)) > 0)
    {
        printf("\33[2K\rhost: %*.*s", 0, n, client_message);
        printf("Enter message: ");    }
    close(sock);
    return 0;
}