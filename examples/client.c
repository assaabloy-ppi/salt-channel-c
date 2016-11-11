#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>
#include <assert.h>
#include "../salt.h"

static int m_sockfd;
static int port;
static struct sockaddr_in serv_addr;

salt_ret_t my_read(void *p_context, uint8_t *p_data, uint32_t length)
{
   int n = 0;

   while ((n = read(m_sockfd, p_data, length)) > 0) {
      if (n < 0) return SALT_ERROR;
      length -= n;
      p_data += n;
   }

   return SALT_SUCCESS;
}

salt_ret_t my_write(void *p_context, uint8_t *p_data, uint32_t length)
{

   int n;

   while ((n = write(m_sockfd, p_data, length))) {
      if (n < 0) {
         return SALT_ERROR;
      }
         length -= n;
         p_data += n;
   }

   return SALT_SUCCESS;
}

void intHandler(int dummy) {

   shutdown(m_sockfd, SHUT_RDWR);
   close(m_sockfd);
   printf("\rClosing salt linux client.\r\n");
   exit(0);
}

int main(void)
{

   m_sockfd = 0;

   port = 2033;

   m_sockfd = socket(AF_INET, SOCK_STREAM, 0);
   int reuse = 1;
   if (setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0) {
      printf("setsockopt(SO_REUSEADDR) failed");
      exit(-1);
   }

   memset(&serv_addr, '0', sizeof(serv_addr));

   serv_addr.sin_family = AF_INET;
   serv_addr.sin_port = htons(port);

   char ip_addr[] = "127.0.0.1";

   if(inet_pton(AF_INET, ip_addr, &serv_addr.sin_addr) <= 0)
   {
      printf("\n inet_pton error occured\n");
      return 1;
   } 

   signal(SIGINT, intHandler);

   uint8_t buffer[512];
   uint8_t tx_buffer[512];
   uint32_t tx_size;

   salt_channel_t channel;

   salt_ret_t ret = salt_init(&channel, buffer, sizeof(buffer), my_read, my_write);
   assert(ret == SALT_SUCCESS);

   salt_create_signature(&channel);

   printf("Conneting to %s.\r\n", ip_addr);

   if( connect(m_sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
   {
      printf("Error: Connect Failed \r\n");
      return 1;
   }

   printf("Connetion succeeded.\r\n");

   ret = salt_init_session(&channel, SALT_CLIENT);
   assert(ret == SALT_SUCCESS);

   ret = salt_handshake(&channel);
   while (ret == SALT_PENDING) {
      ret = salt_handshake(&channel);
   }

   assert(ret == SALT_SUCCESS);

   printf("Salt handshake succeeded.\r\n");

   salt_ret_t sret;

   while (1)
   {
      printf("Client: "); fflush(stdout);
      tx_size = read(0, tx_buffer, sizeof(tx_buffer));
      sret = salt_write(&channel, tx_buffer, tx_size);
      if (sret != SALT_SUCCESS) { break; }
      printf("Waiting for message...");  fflush(stdout);
      sret = salt_read(&channel, tx_buffer, &tx_size, 512);
      if (sret != SALT_SUCCESS) { break; }
      printf("\r                                          "); fflush(stdout);
      printf("\rServer: %*.*s", 0, tx_size, tx_buffer);
   }

   close(m_sockfd);

   return 0;
}