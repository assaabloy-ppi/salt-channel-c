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
#include "../src/salt.h"

static int m_sockfd;
static int m_connfd;
static int port;
static struct sockaddr_in serv_addr;


salt_ret_t my_read(void *p_context, uint8_t *p_data, uint32_t length)
{
   (void ) p_context;
   int n = 0;

   while ((n = read(m_connfd, p_data, length)) > 0) {
      if (n < 0) return SALT_ERROR;
      length -= n;
      p_data += n;
   }

   return SALT_SUCCESS;
}

salt_ret_t my_write(void *p_context, uint8_t *p_data, uint32_t length)
{
   (void ) p_context;
   int n;

   while ((n = write(m_connfd, p_data, length))) {
      if (n < 0) {
         return SALT_ERROR;
      }
         length -= n;
         p_data += n;
   }

   return SALT_SUCCESS; 
}

void intHandler(int dummy) {

   (void) dummy;
   shutdown(m_sockfd, SHUT_RDWR);

   shutdown(m_connfd, SHUT_RDWR);

   close(m_sockfd);
   close(m_connfd);
   printf("\rClosing salt linux host.\r\n");
   exit(0);
}

int main(void)
{

   m_sockfd = 0;
   m_connfd = 0;

   port = 2033;

   m_sockfd = socket(AF_INET, SOCK_STREAM, 0);
   int reuse = 1;
   if (setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0) {
      printf("setsockopt(SO_REUSEADDR) failed");
      exit(-1);
   }

   memset(&serv_addr, '0', sizeof(serv_addr));

   serv_addr.sin_family = AF_INET;
   serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
   serv_addr.sin_port = htons(port);

   int ret;
   ret = bind(m_sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)); 
   if (ret != 0)
   {
      printf("Bind failed.\r\n");
      exit(-1);
   }

   ret = listen(m_sockfd, 10);
   if (ret != 0)
   {
      printf("Listen failed.\r\n");
      exit(-1);
   }

   signal(SIGINT, intHandler);

   uint8_t buffer[512];

   salt_channel_t channel;

   ret = salt_init(&channel, buffer, sizeof(buffer), my_read, my_write);
   assert(ret == SALT_SUCCESS);

   salt_create_signature(&channel);
   
   assert(ret == SALT_SUCCESS);
   uint8_t rx_buffer[512];
   uint32_t rx_size = 123;

   while (1)
   {

      m_connfd = accept(m_sockfd, (struct sockaddr*)NULL, NULL);
      printf("Client connected.\r\n");

      ret = salt_init_session(&channel, SALT_SERVER);

      ret = salt_handshake(&channel);
      while (ret == SALT_PENDING) {
         ret = salt_handshake(&channel);
      }
      assert(ret == SALT_SUCCESS);

      printf("Salt handshake succeeded.\r\n");

      while (1)
      {
         printf("Waiting for message...");  fflush(stdout);
         salt_ret_t sret = salt_read(&channel, rx_buffer, &rx_size, 512);
         if (sret != SALT_SUCCESS) { break; }
         printf("\r                                          "); fflush(stdout);
         printf("\rClient: %*.*s", 0, rx_size, rx_buffer);
         printf("Server: "); fflush(stdout);
         rx_size = read(0, rx_buffer, sizeof(rx_buffer));
         salt_write(&channel, rx_buffer, rx_size);
      }

      close(m_connfd);

   }

   return 0;
}