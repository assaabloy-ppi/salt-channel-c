#include "salt.h"
#include "external/binson-c-light/binson_light.h"

#include <string.h>
#include <sys/types.h>

//=====================================================================
// Local Macro Definitions
//=====================================================================
#define NULL_PTR ( (void *) 0)

#ifdef SALT_DEBUG
   #include <stdio.h>
   #define ASSERT(x, ret_code)                                                            \
   do {                                                                                   \
      if (!(x)) {                                                                         \
         printf("Runtime error: %s at %s:%d, %s.\r\n", #x, __FILE__, __LINE__, __func__); \
         return ret_code;                                                                 \
      }                                                                                   \
   } while (0)

#else
   #define ASSERT(x, ret_code) if (!(x)) return ret_code
#endif

#define ASSERT_NOT_NULL(x) ASSERT(((x) != NULL_PTR), SALT_ERROR_NULL_PTR)
#define MEMSET_ZERO(x) memset((x), 0, sizeof((x)))

/* Salt channel states */
#define SALT_STATE_INITIATED                 (0U)
#define SALT_STATE_SIGNATURE_SET             (1U)
#define SALT_STATE_SESSION_INITIATED         (2U)
#define SALT_STATE_SESSION_ESTABLISHED       (10U)

#define SALT_WRITE_NONCE_INCR_SERVER         (2U)
#define SALT_WRITE_NONCE_INCR_CLIENT         (2U)

#define SALT_WRITE_NONCE_INIT_SERVER         (2U)
#define SALT_WRITE_NONCE_INIT_CLIENT         (1U)

#define SALT_READ_NONCE_INCR_SERVER          (2U)
#define SALT_READ_NONCE_INCR_CLIENT          (2U)

#define SALT_READ_NONCE_INIT_SERVER          (1U)
#define SALT_READ_NONCE_INIT_CLIENT          (2U)

#define SALT_MIN_BUFFER_SIZE                 (512U)

//=====================================================================
// Type Definitions
//=====================================================================

//=====================================================================
// Local variable declarations
//=====================================================================

//=====================================================================
// Local function prototypes
//=====================================================================
static void salti_init_read_channel(salt_io_channel_t *p_io_channel, salt_mode_t mode);
static void salti_init_write_channel(salt_io_channel_t *p_io_channel, salt_mode_t mode);
static void salti_increase_nonce(salt_io_channel_t *p_io_channel);

static salt_ret_t salti_handshake_server(salt_channel_t *p_channel);
static salt_ret_t salti_handshake_client(salt_channel_t *p_channel);
static salt_ret_t salti_io_read(salt_channel_t *p_channel, uint8_t *p_buffer, uint32_t *p_recv_size, uint32_t max_size, uint8_t decrypt);
static salt_ret_t salti_io_write(salt_channel_t *p_channel, uint8_t *p_buffer, uint32_t size, uint8_t encrypt);

static salt_ret_t salti_encrypt(salt_channel_t *p_channel, uint8_t *p_msg, uint32_t size, uint32_t *enc_size);
static salt_ret_t salti_decrypt(salt_channel_t *p_channel, uint8_t *p_msg, uint32_t size, uint32_t *clr_size);

static salt_ret_t salti_parse_m1(salt_channel_t *p_channel, uint8_t *p_buf, uint32_t size);
static salt_ret_t salti_create_m1(salt_channel_t *p_channel, uint8_t *p_buf, uint32_t max_size, uint32_t *size);
static salt_ret_t salti_parse_m2(salt_channel_t *p_channel, uint8_t *p_buf, uint32_t size);
static salt_ret_t salti_create_m2(salt_channel_t *p_channel, uint8_t *p_buf, uint32_t max_size, uint32_t *size);
static salt_ret_t salti_verify_m3m4_signature(salt_channel_t *p_channel, uint8_t *p_sign);
static salt_ret_t salti_create_m3m4_signature(salt_channel_t *p_channel, uint8_t *p_buf);
static salt_ret_t salti_parse_m3(salt_channel_t *p_channel, uint8_t *p_buf, uint32_t size);
static salt_ret_t salti_create_m3(salt_channel_t *p_channel, uint8_t *p_buf, uint32_t max_size, uint32_t *size);
static salt_ret_t salti_parse_m4(salt_channel_t *p_channel, uint8_t *p_buf, uint32_t size);
static salt_ret_t salti_create_m4(salt_channel_t *p_channel, uint8_t *p_buf, uint32_t max_size, uint32_t *size);
static salt_ret_t salti_parse_binson_bytes(binson_parser *p, const char *field, bbuf **bbytes);

//=====================================================================
// Global function implementations
//=====================================================================

salt_ret_t salt_init(
   salt_channel_t *p_channel,
   uint8_t *p_buffer,
   uint32_t buffer_size,
   salt_io_implementation read_impl,
   salt_io_implementation write_impl)
{

   ASSERT_NOT_NULL(p_channel);
   ASSERT_NOT_NULL(p_buffer);
   ASSERT_NOT_NULL(read_impl);
   ASSERT_NOT_NULL(write_impl);

   ASSERT(buffer_size >= SALT_MIN_BUFFER_SIZE, SALT_ERROR_BUFFER_TO_SMALL);

   memset(p_channel, 0, sizeof(salt_channel_t));

   p_channel->p_buffer = p_buffer;
   p_channel->buffer_size = buffer_size;
   p_channel->read_channel.io = read_impl;
   p_channel->write_channel.io = write_impl;

   memset(p_channel->p_buffer, 0, p_channel->buffer_size);

   /* Last 32 bytes of secret sign key is the public. */
   p_channel->my_sk_pub = &p_channel->my_sk_sec[32];

   return SALT_SUCCESS;
}

salt_ret_t salt_set_read_context(salt_channel_t *p_channel, void *p_context)
{
   ASSERT_NOT_NULL(p_channel);
   ASSERT_NOT_NULL(p_context);
   p_channel->read_channel.p_context = p_context;
   return SALT_SUCCESS;
}

salt_ret_t salt_set_write_context(salt_channel_t *p_channel, void *p_context)
{
   ASSERT_NOT_NULL(p_channel);
   ASSERT_NOT_NULL(p_context);
   p_channel->write_channel.p_context = p_context;
   return SALT_SUCCESS;
}

salt_ret_t salt_set_signature(salt_channel_t *p_channel, const uint8_t *p_signature)
{
   ASSERT_NOT_NULL(p_channel);
   ASSERT_NOT_NULL(p_signature);

   memcpy(p_channel->my_sk_sec, p_signature, crypto_sign_SECRETKEYBYTES);
   p_channel->state = SALT_STATE_SIGNATURE_SET;

   return SALT_SUCCESS;
}

salt_ret_t salt_create_signature(salt_channel_t *p_channel)
{
   ASSERT_NOT_NULL(p_channel);
   uint8_t pk[crypto_sign_PUBLICKEYBYTES];
   crypto_sign_keypair(pk,p_channel->my_sk_sec);
   p_channel->state = SALT_STATE_SIGNATURE_SET;
   return SALT_SUCCESS;
}

salt_ret_t salt_init_session(salt_channel_t *p_channel, salt_mode_t mode)
{

   ASSERT_NOT_NULL(p_channel);

   ASSERT(p_channel->state >= SALT_STATE_SIGNATURE_SET, SALT_ERROR_NO_SIGNATURE);

   MEMSET_ZERO(p_channel->my_ek_sec);
   MEMSET_ZERO(p_channel->my_ek_pub);
   MEMSET_ZERO(p_channel->peer_ek_pub);
   MEMSET_ZERO(p_channel->ek_common);
   MEMSET_ZERO(p_channel->peer_sk_pub);

   p_channel->state = SALT_STATE_SESSION_INITIATED;
   p_channel->mode = mode;
   p_channel->buffer_locked = 0;

   /* Create ephemeral keypair used for only this session. */
   crypto_box_keypair(p_channel->my_ek_pub, p_channel->my_ek_sec);

   salti_init_read_channel(&p_channel->read_channel, mode);
   salti_init_write_channel(&p_channel->write_channel, mode);

   return SALT_SUCCESS;

}

salt_ret_t salt_handshake(salt_channel_t *p_channel)
{

   ASSERT_NOT_NULL(p_channel);

   if (p_channel->mode == SALT_SERVER) {
      return salti_handshake_server(p_channel);
   } else {
      return salti_handshake_client(p_channel);
   }

}

salt_ret_t salt_read(salt_channel_t *p_channel, uint8_t *p_buffer, uint32_t *p_recv_size, uint32_t max_size)
{

   ASSERT_NOT_NULL(p_channel);
   ASSERT_NOT_NULL(p_buffer);
   ASSERT_NOT_NULL(p_recv_size);

   ASSERT(p_channel->state >= SALT_STATE_SESSION_ESTABLISHED, SALT_ERROR_SESSION_NOT_ESTABLISHED);

   salt_ret_t ret = salti_io_read(
      p_channel,
      p_buffer,
      p_recv_size,
      max_size, 1);

   return ret;

}

salt_ret_t salt_write(salt_channel_t *p_channel, uint8_t *p_buffer, uint32_t size)
{
   ASSERT_NOT_NULL(p_channel);
   ASSERT_NOT_NULL(p_buffer);

   return salti_io_write(
      p_channel,
      p_buffer,
      size, 1);

}

//=====================================================================
// Local function implementations
//=====================================================================
static salt_ret_t salti_handshake_server(salt_channel_t *p_channel)
{
   ASSERT(p_channel->state >= SALT_STATE_SESSION_INITIATED, SALT_ERROR_SESSION_NOT_INITIATED);

   uint8_t proceed = 1;
   uint32_t size;
   salt_ret_t ret_code = SALT_ERROR;

   while (proceed)
   {
      proceed = 0;
      switch (p_channel->state)
      {
         case 2:
            ret_code = salti_io_read(
               p_channel,
               &p_channel->p_buffer[crypto_secretbox_ZEROBYTES],
               &size,
               p_channel->buffer_size-crypto_secretbox_ZEROBYTES, 0);
            if (ret_code == SALT_SUCCESS)
            {
               p_channel->state = 3;
               proceed = 1;
            }
            break;
         case 3:
            ret_code = salti_parse_m1(p_channel, &p_channel->p_buffer[crypto_secretbox_ZEROBYTES], size);
            if (ret_code == SALT_SUCCESS)
            {
               p_channel->state = 4;
               proceed = 1;
            }
            break;
         case 4:
            ret_code = salti_create_m2(
               p_channel,
               &p_channel->p_buffer[crypto_secretbox_ZEROBYTES],
               p_channel->buffer_size-crypto_secretbox_ZEROBYTES,
               &size);
            if (ret_code == SALT_SUCCESS)
            {
               p_channel->state = 5;
               proceed = 1;
            }
            break;
         case 5:
            ret_code = salti_io_write(
               p_channel,
               &p_channel->p_buffer[crypto_secretbox_ZEROBYTES],
               size, 0);
            if (ret_code == SALT_SUCCESS)
            {
               p_channel->state = 6;
               proceed = 1;
            }
            break;
         case 6:
            ret_code = salti_create_m3(
               p_channel,
               &p_channel->p_buffer[256],
               p_channel->buffer_size-256,
               &size);
            if (ret_code == SALT_SUCCESS)
            {
               p_channel->state = 7;
               proceed = 1;
            }
            break;
         case 7:
            ret_code = salti_io_write(
               p_channel,
               &p_channel->p_buffer[256],
               size, 1);
            if (ret_code == SALT_SUCCESS)
            {
               p_channel->state = 8;
               proceed = 1;
            }
            break;
         case 8:
            ret_code = salti_io_read(
               p_channel,
               &p_channel->p_buffer[256],
               &size,
               p_channel->buffer_size-256, 1);
            if (ret_code == SALT_SUCCESS)
            {
               p_channel->state = 9;
               proceed = 1;
            }
            break;
         case 9:
            ret_code = salti_parse_m4(p_channel, &p_channel->p_buffer[256], size);
            if (ret_code == SALT_SUCCESS)
            {
               p_channel->state = SALT_STATE_SESSION_ESTABLISHED;
            }
            break;
         default:
            return SALT_ERROR;
      }
   }

   return ret_code;
}

static salt_ret_t salti_handshake_client(salt_channel_t *p_channel)
{
   ASSERT(p_channel->state >= SALT_STATE_SESSION_INITIATED, SALT_ERROR_SESSION_NOT_INITIATED);

   uint8_t proceed = 1;
   uint32_t size;
   salt_ret_t ret_code = SALT_ERROR;

   while (proceed)
   {
      proceed = 0;
      switch (p_channel->state)
      {
         case 2:
            ret_code = salti_create_m1(
               p_channel,
               &p_channel->p_buffer[crypto_secretbox_ZEROBYTES],
               p_channel->buffer_size-crypto_secretbox_ZEROBYTES,
               &size);
            if (ret_code == SALT_SUCCESS)
            {
               p_channel->state = 3;
               proceed = 1;
            }
         case 3:
            ret_code = salti_io_write(
               p_channel,
               &p_channel->p_buffer[crypto_secretbox_ZEROBYTES],
               size, 0);
            if (ret_code == SALT_SUCCESS)
            {
               p_channel->state = 4;
               proceed = 1;
            }
            break;
         case 4:
            ret_code = salti_io_read(
               p_channel,
               &p_channel->p_buffer[crypto_secretbox_ZEROBYTES],
               &size,
               p_channel->buffer_size-crypto_secretbox_ZEROBYTES, 0);
            if (ret_code == SALT_SUCCESS)
            {
               p_channel->state = 5;
               proceed = 1;
            }
            break;
         case 5:
            ret_code = salti_parse_m2(p_channel, &p_channel->p_buffer[crypto_secretbox_ZEROBYTES], size);
            if (ret_code == SALT_SUCCESS)
            {
               p_channel->state = 6;
               proceed = 1;
            }
            break;
         case 6:
            ret_code = salti_io_read(
               p_channel,
               &p_channel->p_buffer[256],
               &size,
               p_channel->buffer_size-256, 1);
            if (ret_code == SALT_SUCCESS)
            {
               p_channel->state = 7;
               proceed = 1;
            }
            break;
         case 7:
            ret_code = salti_parse_m3(p_channel, &p_channel->p_buffer[256], size);
            if (ret_code == SALT_SUCCESS)
            {
               p_channel->state = 8;
               proceed = 1;
            }
            break;
         case 8:
            ret_code = salti_create_m4(p_channel, &p_channel->p_buffer[256], p_channel->buffer_size-256, &size);
            if (ret_code == SALT_SUCCESS)
            {
               p_channel->state = 9;
               proceed = 1;
            }
            break;
         case 9:
            ret_code = salti_io_write(
               p_channel,
               &p_channel->p_buffer[256],
               size, 1);
            if (ret_code == SALT_SUCCESS)
            {
               p_channel->state = SALT_STATE_SESSION_ESTABLISHED;
            }
            break;
         default:
            return SALT_ERROR;
      }
   }

   return ret_code;
}

static void salti_init_read_channel(salt_io_channel_t *p_io_channel, salt_mode_t mode)
{
   p_io_channel->state = 0;
   MEMSET_ZERO(p_io_channel->nonce);
   if (mode == SALT_SERVER)
   {
      p_io_channel->nonce_increment = SALT_READ_NONCE_INCR_SERVER;
      p_io_channel->nonce[0]  = SALT_READ_NONCE_INIT_SERVER;
   }
   else
   {
      p_io_channel->nonce_increment = SALT_READ_NONCE_INCR_CLIENT;
      p_io_channel->nonce[0]  = SALT_READ_NONCE_INIT_CLIENT;
   }
   
}

static void salti_init_write_channel(salt_io_channel_t *p_io_channel, salt_mode_t mode)
{
   p_io_channel->state = 0;
   MEMSET_ZERO(p_io_channel->nonce);
   if (mode == SALT_SERVER)
   {
      p_io_channel->nonce_increment = SALT_WRITE_NONCE_INCR_SERVER;
      p_io_channel->nonce[0]  = SALT_WRITE_NONCE_INIT_SERVER;
   }
   else
   {
      p_io_channel->nonce_increment = SALT_WRITE_NONCE_INCR_CLIENT;
      p_io_channel->nonce[0]  = SALT_WRITE_NONCE_INIT_CLIENT;
   }
}

static void salti_increase_nonce(salt_io_channel_t *p_io_channel)
{
   uint_fast16_t c = p_io_channel->nonce_increment;

   for (size_t i = 0; i < crypto_box_NONCEBYTES; i++) {
      c += (uint_fast16_t) p_io_channel->nonce[i];
      p_io_channel->nonce[i] = (uint8_t) c;
      c >>= 8;
   }

}

static salt_ret_t salti_io_read(salt_channel_t *p_channel, uint8_t *p_buffer, uint32_t *p_recv_size, uint32_t max_size, uint8_t decrypt)
{

   salt_ret_t ret_code = SALT_SUCCESS;
   salt_io_channel_t *pr_channel = &p_channel->read_channel;
   uint8_t proceed = 1;

   while (proceed)
   {
      proceed = 0;
      switch (pr_channel->state)
      {
         case 0:
            ASSERT(max_size <= p_channel->buffer_size, SALT_ERROR_MAX_SIZE_TO_LARGE);
            pr_channel->p_data = p_buffer;
            pr_channel->size = max_size;
            pr_channel->state = 1;
            proceed = 1;
            break;
         case 1:
            ret_code = pr_channel->io(
               pr_channel->p_context,
               (uint8_t *) &pr_channel->size,
               sizeof(pr_channel->size));
            if (ret_code == SALT_SUCCESS)
            {
               //pr_channel->size = __ntohl(pr_channel->size);
               ASSERT(pr_channel->size <= max_size, SALT_ERROR_MSG_TO_LONG);
               pr_channel->state = 2;
               proceed = 1;
            }
            break;
         case 2:
            ret_code = pr_channel->io(
               pr_channel->p_context,
               pr_channel->p_data,
               pr_channel->size);

            if (ret_code == SALT_SUCCESS)
            {
               *p_recv_size = pr_channel->size;
               if (decrypt) {
                  ret_code = salti_decrypt(
                     p_channel,
                     p_buffer,
                     pr_channel->size,
                     p_recv_size);
               }
               pr_channel->state = 0;
            }
            break;
         default:
            ret_code = SALT_ERROR;
            break;
      }
   }
   return ret_code;
}

static salt_ret_t salti_io_write(salt_channel_t *p_channel, uint8_t *p_buffer, uint32_t size, uint8_t encrypt)
{
   salt_ret_t ret_code = SALT_SUCCESS;
   salt_io_channel_t *pw_channel = &p_channel->write_channel;
   uint8_t proceed = 1;

   while (proceed)
   {
      proceed = 0;
      switch (pw_channel->state)
      {
         case 0:
            ASSERT(size <= p_channel->buffer_size, SALT_ERROR_MAX_SIZE_TO_LARGE);
            pw_channel->size = size;
            if (encrypt)
            {
               ret_code = salti_encrypt(
                  p_channel,
                  p_buffer,
                  size,
                  &pw_channel->size);
            }
            pw_channel->p_data = p_buffer;
            //pw_channel->size = __ntohl(pw_channel->size);
            pw_channel->state = 1;
            proceed = 1;
            break;
         case 1:
            ret_code = pw_channel->io(
               pw_channel->p_context,
               (uint8_t *) &pw_channel->size,
               4);
            if (ret_code == SALT_SUCCESS)
            {
               pw_channel->state = 2;
               proceed = 1;
            }
            break;
         case 2:
            ret_code = pw_channel->io(
               pw_channel->p_context,
               pw_channel->p_data,
               pw_channel->size);
            if (ret_code == SALT_SUCCESS)
            {
               pw_channel->size = 0;
               pw_channel->state = 0;
               proceed = 0;
            }
            break;
         default:
            ret_code = SALT_ERROR;
            break;
      }
   }

   return ret_code;

}

static salt_ret_t salti_encrypt(salt_channel_t *p_channel, uint8_t *p_msg, uint32_t size, uint32_t *enc_size)
{

   memcpy(&p_channel->p_buffer[crypto_secretbox_ZEROBYTES], p_msg, size);

   int ret = crypto_box_afternm(
      p_msg,
      p_channel->p_buffer,
      size + crypto_secretbox_ZEROBYTES,
      p_channel->write_channel.nonce,
      p_channel->ek_common
   );

   ASSERT(ret == 0, SALT_ERROR_ENCRYPTION_FAILED);

   *enc_size = size + crypto_secretbox_BOXZEROBYTES;

   memcpy(&p_channel->p_buffer[crypto_secretbox_ZEROBYTES], &p_msg[crypto_secretbox_BOXZEROBYTES], *enc_size);

   binson_writer w;
   binson_writer_init(&w, p_msg, size+SALT_OVERHEAD);
   binson_write_object_begin(&w);
   binson_write_name(&w, "b");
   binson_write_bytes(&w, &p_channel->p_buffer[crypto_secretbox_ZEROBYTES], *enc_size);
   binson_write_object_end(&w);
   ASSERT(w.error_flags == BINSON_ID_OK, SALT_ERROR_FORMAT);

   *enc_size = binson_writer_get_counter(&w);

   salti_increase_nonce(&p_channel->write_channel);

   return SALT_SUCCESS;

}

static salt_ret_t salti_decrypt(salt_channel_t *p_channel, uint8_t *p_msg, uint32_t size, uint32_t *clr_size)
{

   binson_parser p;
   binson_parser_init(&p, p_msg, size);

   bbuf *binson_bytes;
   ASSERT(salti_parse_binson_bytes(&p, "b", &binson_bytes) == SALT_SUCCESS, SALT_ERROR_FORMAT);

   memcpy(&p_channel->p_buffer[crypto_secretbox_ZEROBYTES], binson_bytes->bptr, binson_bytes->bsize);

   int r = crypto_box_open_afternm(
      p_msg,
      &p_channel->p_buffer[crypto_secretbox_ZEROBYTES-crypto_secretbox_BOXZEROBYTES],
      binson_bytes->bsize + crypto_secretbox_BOXZEROBYTES,
      p_channel->read_channel.nonce,
      p_channel->ek_common
   );

   ASSERT(r == 0, SALT_ERROR_DECRYPTION_FAILED);

   *clr_size = binson_bytes->bsize - crypto_secretbox_BOXZEROBYTES;
   memmove(p_msg, &p_msg[crypto_secretbox_ZEROBYTES], *clr_size);

   salti_increase_nonce(&p_channel->read_channel);

   return SALT_SUCCESS;
}

static salt_ret_t salti_parse_m1(salt_channel_t *p_channel, uint8_t *p_buf, uint32_t size)
{
   binson_parser p;
   binson_parser_init(&p, p_buf, size);

   bbuf *binson_bytes;
   ASSERT(salti_parse_binson_bytes(&p, "e", &binson_bytes) == SALT_SUCCESS, SALT_ERROR_FORMAT);
   ASSERT(binson_bytes->bsize == crypto_box_PUBLICKEYBYTES, SALT_ERROR_FORMAT);

   memcpy(p_channel->peer_ek_pub, binson_bytes->bptr, crypto_box_PUBLICKEYBYTES);

   binson_parser_field(&p, "p");
   ASSERT(p.error_flags == BINSON_ID_OK, SALT_ERROR_FORMAT);
   ASSERT(binson_parser_get_type(&p) == BINSON_ID_STRING, SALT_ERROR_FORMAT);

   binson_bytes = binson_parser_get_bytes_bbuf(&p);
   ASSERT(p.error_flags == BINSON_ID_OK, SALT_ERROR_FORMAT);
   ASSERT(binson_bytes->bptr != NULL, SALT_ERROR_NULL_PTR);
   ASSERT(memcmp("S1", binson_bytes->bptr, 2) == 0, SALT_ERROR_PROT_VERSION);

   /* Calculate shared key. */
   int ret = crypto_box_beforenm(p_channel->ek_common, p_channel->peer_ek_pub, p_channel->my_ek_sec);
   ASSERT(ret == 0, SALT_ERROR);

   return SALT_SUCCESS;
}

static salt_ret_t salti_create_m1(salt_channel_t *p_channel, uint8_t *p_buf, uint32_t max_size, uint32_t *size)
{

   binson_writer w;
   binson_writer_init(&w, p_buf, max_size);

   binson_write_object_begin(&w);
   binson_write_name(&w, "e");
   binson_write_bytes(&w, p_channel->my_ek_pub, crypto_box_PUBLICKEYBYTES);
   binson_write_name(&w, "p");
   binson_write_string(&w, "S1");
   binson_write_object_end(&w);

   *size = binson_writer_get_counter(&w);

   return SALT_SUCCESS;
}

static salt_ret_t salti_parse_m2(salt_channel_t *p_channel, uint8_t *p_buf, uint32_t size)
{

   binson_parser p;
   binson_parser_init(&p, p_buf, size);

   bbuf *binson_bytes;
   ASSERT(salti_parse_binson_bytes(&p, "e", &binson_bytes) == SALT_SUCCESS, SALT_ERROR_FORMAT);
   ASSERT(binson_bytes->bsize == crypto_box_PUBLICKEYBYTES, SALT_ERROR_FORMAT);

   memcpy(p_channel->peer_ek_pub, binson_bytes->bptr, crypto_box_PUBLICKEYBYTES);

   /* Calculate shared key. */
   int ret = crypto_box_beforenm(p_channel->ek_common, p_channel->peer_ek_pub, p_channel->my_ek_sec);
   ASSERT(ret == 0, SALT_ERROR);

   return SALT_SUCCESS;
}

static salt_ret_t salti_create_m2(salt_channel_t *p_channel, uint8_t *p_buf, uint32_t max_size, uint32_t *size)
{

   binson_writer w;
   binson_writer_init(&w, p_buf, max_size);

   binson_write_object_begin(&w);
   binson_write_name(&w, "e");
   binson_write_bytes(&w, p_channel->my_ek_pub, crypto_box_PUBLICKEYBYTES);
   binson_write_object_end(&w);

   *size = binson_writer_get_counter(&w);

   return SALT_SUCCESS;
}

static salt_ret_t salti_verify_m3m4_signature(salt_channel_t *p_channel, uint8_t *p_sign)
{
   uint8_t *signed_msg = &p_channel->p_buffer[crypto_secretbox_ZEROBYTES];

   memcpy(&signed_msg[0], p_sign, crypto_sign_BYTES);

   memcpy(
      &signed_msg[crypto_sign_BYTES],
      p_channel->peer_ek_pub,
      crypto_box_PUBLICKEYBYTES);
   memcpy(
      &signed_msg[crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES],
      p_channel->my_ek_pub,
      crypto_box_PUBLICKEYBYTES);
   long long unsigned int sign_msg_size;

   int r = crypto_sign_open(
      &signed_msg[crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES*2],
      &sign_msg_size,
      signed_msg,
      crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES*2,
      p_channel->peer_sk_pub);

   ASSERT(r == 0, SALT_ERROR_BAD_SIGNATURE);

   return SALT_SUCCESS;

}

static salt_ret_t salti_create_m3m4_signature(salt_channel_t *p_channel, uint8_t *p_buf)
{
   uint8_t msg_to_sign[crypto_box_PUBLICKEYBYTES*2];
   memcpy(msg_to_sign, p_channel->my_ek_pub, crypto_box_PUBLICKEYBYTES);
   memcpy(&msg_to_sign[crypto_box_PUBLICKEYBYTES], p_channel->peer_ek_pub, crypto_box_PUBLICKEYBYTES);

   unsigned long long sign_msg_size;

   crypto_sign(
      p_buf,
      &sign_msg_size,
      msg_to_sign,
      crypto_box_PUBLICKEYBYTES*2,
      p_channel->my_sk_sec);

   return SALT_SUCCESS;
}

static salt_ret_t salti_parse_m3(salt_channel_t *p_channel, uint8_t *p_buf, uint32_t size)
{

   /* The client parses m3 */

   binson_parser p;
   binson_parser_init(&p, p_buf, size);

   bbuf *binson_bytes;
   ASSERT(salti_parse_binson_bytes(&p, "g", &binson_bytes) == SALT_SUCCESS, SALT_ERROR_FORMAT);
   ASSERT(binson_bytes->bsize == crypto_sign_BYTES, SALT_ERROR_FORMAT);

   uint8_t *signed_msg = binson_bytes->bptr;

   ASSERT(salti_parse_binson_bytes(&p, "s", &binson_bytes) == SALT_SUCCESS, SALT_ERROR_FORMAT);
   ASSERT(binson_bytes->bsize == crypto_sign_PUBLICKEYBYTES, SALT_ERROR_FORMAT);

   memcpy(p_channel->peer_sk_pub, binson_bytes->bptr, crypto_sign_PUBLICKEYBYTES);

   ASSERT(salti_verify_m3m4_signature(p_channel, signed_msg) == SALT_SUCCESS, SALT_ERROR_BAD_SIGNATURE);

   return SALT_SUCCESS;
}

static salt_ret_t salti_create_m3(salt_channel_t *p_channel, uint8_t *p_buf, uint32_t max_size, uint32_t *size)
{

   memcpy(p_buf, p_channel->my_ek_pub, crypto_box_PUBLICKEYBYTES);
   memcpy(&p_buf[crypto_box_PUBLICKEYBYTES], p_channel->peer_ek_pub, crypto_box_PUBLICKEYBYTES);
   
   uint8_t signed_msg[crypto_box_PUBLICKEYBYTES*2 + crypto_sign_BYTES];
   salti_create_m3m4_signature(p_channel, signed_msg);

   binson_writer w;
   binson_writer_init(&w, p_buf, max_size);

   binson_write_object_begin(&w);

   binson_write_name(&w, "g");
   binson_write_bytes(&w, signed_msg, crypto_box_PUBLICKEYBYTES*2);

   binson_write_name(&w, "s");
   binson_write_bytes(&w, p_channel->my_sk_pub, crypto_sign_PUBLICKEYBYTES);

   binson_write_object_end(&w);

   *size = binson_writer_get_counter(&w);

   return SALT_SUCCESS;
}

static salt_ret_t salti_parse_m4(salt_channel_t *p_channel, uint8_t *p_buf, uint32_t size)
{

   binson_parser p;
   binson_parser_init(&p, p_buf, size);

   bbuf *binson_bytes;
   ASSERT(salti_parse_binson_bytes(&p, "c", &binson_bytes) == SALT_SUCCESS, SALT_ERROR_FORMAT);
   
   ASSERT(binson_bytes->bsize == crypto_sign_PUBLICKEYBYTES, SALT_ERROR_FORMAT);
   memcpy(p_channel->peer_sk_pub, binson_bytes->bptr, crypto_sign_PUBLICKEYBYTES);

   ASSERT(salti_parse_binson_bytes(&p, "g", &binson_bytes) == SALT_SUCCESS, SALT_ERROR_FORMAT);
   ASSERT(binson_bytes->bsize == crypto_sign_BYTES, SALT_ERROR_FORMAT);

   ASSERT(salti_verify_m3m4_signature(p_channel, binson_bytes->bptr) == SALT_SUCCESS, SALT_ERROR_BAD_SIGNATURE);

   return SALT_SUCCESS;

}

static salt_ret_t salti_create_m4(salt_channel_t *p_channel, uint8_t *p_buf, uint32_t max_size, uint32_t *size)
{

   memcpy(p_buf, p_channel->my_ek_pub, crypto_box_PUBLICKEYBYTES);
   memcpy(&p_buf[crypto_box_PUBLICKEYBYTES], p_channel->peer_ek_pub, crypto_box_PUBLICKEYBYTES);
   
   uint8_t signed_msg[crypto_box_PUBLICKEYBYTES*2 + crypto_sign_BYTES];
   salti_create_m3m4_signature(p_channel, signed_msg);

   binson_writer w;
   binson_writer_init(&w, p_buf, max_size);

   binson_write_object_begin(&w);

   binson_write_name(&w, "c");
   binson_write_bytes(&w, p_channel->my_sk_pub, crypto_sign_PUBLICKEYBYTES);

   binson_write_name(&w, "g");
   binson_write_bytes(&w, signed_msg, crypto_box_PUBLICKEYBYTES*2);

   binson_write_object_end(&w);

   *size = binson_writer_get_counter(&w);

   return SALT_SUCCESS;
}

static salt_ret_t salti_parse_binson_bytes(binson_parser *p, const char *field, bbuf **bbytes)
{
   binson_parser_field(p, field);
   ASSERT(p->error_flags == BINSON_ID_OK, SALT_ERROR_FORMAT);
   ASSERT(binson_parser_get_type(p) == BINSON_ID_BYTES, SALT_ERROR_FORMAT);
   *bbytes = binson_parser_get_bytes_bbuf(p);
   ASSERT((*bbytes)->bptr != NULL, SALT_ERROR_FORMAT);
   return SALT_SUCCESS;
}
