#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "salt.h"

void randombytes(uint8_t *p_bytes, uint64_t length)
{
   for (uint64_t i = 0; i < length; i++)
   {
      p_bytes[i] = i;
   }
}

uint8_t read_state = 0;
uint8_t write_state = 0;

#include "test_data.c"

uint8_t  *handshake_read_bytes[4];
uint32_t handshake_read_sizes[4];
uint8_t  *handshake_write_bytes[4];
uint32_t handshake_write_sizes[4];

void init(void)
{
   handshake_write_bytes[0] = (uint8_t *) &m1_size;
   handshake_write_sizes[0] = sizeof(m1_size);
   handshake_write_bytes[1] = m1;
   handshake_write_sizes[1] = sizeof(m1);
   handshake_write_bytes[2] = (uint8_t *) &m4enc_size;
   handshake_write_sizes[2] = sizeof(m4enc_size);
   handshake_write_bytes[3] = m4enc;
   handshake_write_sizes[3] = sizeof(m4enc);

   handshake_read_bytes[0] = (uint8_t *) &m2_size;
   handshake_read_sizes[0] = sizeof(m2_size);
   handshake_read_bytes[1] = m2;
   handshake_read_sizes[1] = sizeof(m2);
   handshake_read_bytes[2] = (uint8_t *) &m3enc_size;
   handshake_read_sizes[2] = sizeof(m3enc_size);
   handshake_read_bytes[3] = m3enc;
   handshake_read_sizes[3] = sizeof(m3enc);
}




salt_ret_t my_read(void *p_context, uint8_t *p_data, uint32_t length)
{
   (void) p_context;
   if (read_state < 4)
   {
      assert(length == handshake_read_sizes[read_state]);
      memcpy(p_data, handshake_read_bytes[read_state], length);  
   }

   read_state++;

   return SALT_SUCCESS;
}

salt_ret_t my_write(void *p_context, uint8_t *p_data, uint32_t length)
{

   (void) p_context;
   if (write_state < 4)
   {
      assert(length == handshake_write_sizes[write_state]);
      assert(memcmp(p_data, handshake_write_bytes[write_state], length) == 0);
   }

   write_state++;

   return SALT_SUCCESS;
}

int main(void)
{

   init();
   printf("Salt client test program.\r\n");

   salt_ret_t ret;

   uint8_t buffer[512];

   salt_channel_t channel;

   ret = salt_init(&channel, buffer, sizeof(buffer), my_read, my_write);
   assert(ret == SALT_SUCCESS);

   salt_set_signature(&channel, client_sec_key);

   ret = salt_init_session(&channel, SALT_CLIENT);
   assert(ret == SALT_SUCCESS);

   memcpy(channel.my_ek_pub, client_ek_pub, 32);
   memcpy(channel.my_ek_sec, client_ek_sec, 32);
   
   ret = salt_handshake(&channel);
   while (ret == SALT_PENDING) {
      ret = salt_handshake(&channel);
   }
   assert(ret == SALT_SUCCESS);
   assert(write_state == 4);
   assert(read_state == 4);

   printf("Test succeeded.\r\n");

   return 0;
}