#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include "../src/salt.h"

void handle_connection(int sock);
void error(const char *msg)
{
    perror(msg);
    exit(1);
}

salt_ret_t my_read(void *p_context, uint8_t *p_data, uint32_t length)
{
   int n = 0;
   int sock = *((int *) p_context);

   while ((n = read(sock, p_data, length)) > 0) {
      if (n < 0) return SALT_ERROR;
      length -= n;
      p_data += n;
   }

   return SALT_SUCCESS;
}

salt_ret_t my_write(void *p_context, uint8_t *p_data, uint32_t length)
{

   int n;
   int sock = *((int *) p_context);

   while ((n = write(sock, p_data, length))) {
      if (n < 0) {
         return SALT_ERROR;
      }
         length -= n;
         p_data += n;
   }

   return SALT_SUCCESS; 
}

int main(void)
{
   int sockfd, newsockfd, portno, pid;
   socklen_t clilen;
   struct sockaddr_in serv_addr, cli_addr;

   sockfd = socket(AF_INET, SOCK_STREAM, 0);
   if (sockfd < 0) 
      error("ERROR opening socket");

   int reuse = 1;

   if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0) {
      printf("setsockopt(SO_REUSEADDR) failed");
      exit(-1);
   }

   bzero((char *) &serv_addr, sizeof(serv_addr));
   portno = 2033;
   serv_addr.sin_family = AF_INET;
   serv_addr.sin_addr.s_addr = INADDR_ANY;
   serv_addr.sin_port = htons(portno);

   if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) 
      error("ERROR on binding");

   listen(sockfd,5);
   clilen = sizeof(cli_addr);
   while (1) {
      newsockfd = accept(sockfd, 
      (struct sockaddr *) &cli_addr, &clilen);

      if (newsockfd < 0) 
         error("ERROR on accept");

      pid = fork();
      if (pid < 0)
         error("ERROR on fork");

      if (pid == 0)  {
         close(sockfd);
         handle_connection(newsockfd);
         exit(0);
      }
      else close(newsockfd);
   } /* end of while */

   close(sockfd);

   return 0; /* we never get here */
}

void handle_connection(int sock)
{

   uint8_t tmp_buffer[512];
   uint8_t buffer[512];
   salt_channel_t channel;

   salt_ret_t ret = salt_init(&channel, tmp_buffer, sizeof(tmp_buffer), my_read, my_write);
   salt_set_read_context(&channel, &sock);
   salt_set_write_context(&channel, &sock);
   salt_create_signature(&channel);

   ret = salt_init_session(&channel, SALT_SERVER);
   if (ret != SALT_SUCCESS) {
      close(sock);
      return;
   }

   ret = salt_handshake(&channel);
   while (ret == SALT_PENDING) {
      ret = salt_handshake(&channel);
   }

   if (ret != SALT_SUCCESS) {
      close(sock);
      return;
   }

   while (1)
   {
      uint32_t rx_size;
      ret = salt_read(&channel, &buffer[50], &rx_size, sizeof(buffer)-50);
      if (ret != SALT_SUCCESS) {
         close(sock);
         return;
      }
      printf("Received (pid %d): %*.*s", getpid(), 0, rx_size, &buffer[50]);
      rx_size = sprintf((char *)buffer, "I received: %*.*s", 0, rx_size, (char *)&buffer[50]);
      ret = salt_write(&channel, buffer, rx_size);
      if (ret != SALT_SUCCESS) {
         close(sock);
         return;
      }
   }


}