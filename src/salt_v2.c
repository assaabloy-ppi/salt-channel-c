/**
 * @file salt_v2.c
 *
 * Salt channel version 2 implementation.
 *
 */

/*======= Includes ============================================================*/
#include "salt_v2.h"
#include "../test/util.h"

#include <string.h> /* memcpy, memset */

/*======= Local Macro Definitions =============================================*/
#ifdef SALT_DEBUG
    #include <stdio.h>
    #define SALT_ASSERT(x, err_code, error)                                     \
    do {                                                                        \
        if (!(x)) {                                                             \
            err_code = error;                                                   \
            printf(                                                             \
                "Runtime error (0x%04x): %s at %s:%d, %s.\r\n",                 \
                err_code, #x, __FILE__, __LINE__, __func__);                    \
            return SALT_ERROR;                                                  \
        }                                                                       \
    } while (0)

#else
    #define SALT_ASSERT(x, ret_code)                                            \
    do {                                                                        \
        if (!(x)) {                                                             \
            err_code = error;                                                   \
            return ret_code;                                                    \
        }                                                                       \
    } while (0)
#endif

#define NULL_PTR ( (void *) 0)
#define SALT_ASSERT_NOT_NULL(x, error_code)                                     \
    SALT_ASSERT(((x) != NULL_PTR), error_code, SALT_ERR_NULL_PTR)

#define SALT_ASSERT_VALID_CHANNEL(x) if ((x) == NULL_PTR) return SALT_ERROR 
#define MEMSET_ZERO(x) memset((x), 0, sizeof((x)))

#define SALT_WRITE_NONCE_INCR_SERVER            (2U)
#define SALT_WRITE_NONCE_INCR_CLIENT            (2U)
#define SALT_WRITE_NONCE_INIT_SERVER            (2U)
#define SALT_WRITE_NONCE_INIT_CLIENT            (1U)
#define SALT_READ_NONCE_INCR_SERVER             (2U)
#define SALT_READ_NONCE_INCR_CLIENT             (2U)
#define SALT_READ_NONCE_INIT_SERVER             (1U)
#define SALT_READ_NONCE_INIT_CLIENT             (2U)

#define SALT_M1_RESUME_BYTE                     (0x00U)

/*======= Type Definitions ====================================================*/

/*======= Local variable declarations =========================================*/
static const uint8_t SALTI_M1_PROTOCOL[2] =      {0x83U,0x50U};     /**< Protocol, always "S2". */
static const uint8_t SALTI_M1_HEADER[2]   =      {0x11U,0x22U};     /**< M1 Header bytes. */
static const uint8_t SALTI_M2_HEADER[2]   =      {0x33U,0x44U};     /**< M2 Header bytes. */ 
static const uint8_t SALTI_M3_HEADER[2]   =      {0x55U,0x66U};     /**< M3 Header bytes. */ 

/*======= Local function prototypes ===========================================*/
static salt_ret_t salti_handshake_server(salt_channel_t *p_channel);
static salt_ret_t salti_handshake_client(salt_channel_t *p_channel);
static salt_ret_t salti_create_m1(salt_channel_t *p_channel, uint8_t *p_data, uint32_t *size);
static salt_ret_t salti_parse_m1(salt_channel_t *p_channel, uint8_t *p_data, uint8_t size);
static salt_ret_t salti_create_m2(salt_channel_t *p_channel, uint8_t *p_data, uint32_t *size);
static salt_ret_t salti_parse_m2(salt_channel_t *p_channel, uint8_t *p_data, uint8_t size);
static salt_ret_t salti_create_m3(salt_channel_t *p_channel, uint8_t *p_data, uint32_t *size);
static salt_ret_t salti_parse_m3(salt_channel_t *p_channel, uint8_t *p_data, uint8_t size);
static salt_ret_t salti_parse_m4(salt_channel_t *p_channel, uint8_t *p_data, uint8_t size);
static salt_ret_t salti_encrypt(salt_channel_t *p_channel, uint8_t *p_data, uint32_t size);
static salt_ret_t salti_decrypt(salt_channel_t *p_channel, uint8_t *p_data, uint32_t size);
static void salti_increase_nonce(uint8_t *p_nonce, uint8_t increment);

/*======= Global function implementations =====================================*/
salt_ret_t salt_create(
   salt_channel_t *p_channel,
   salt_mode_t mode,
   salt_io_impl write_impl,
   salt_io_impl read_impl)
{

    SALT_ASSERT_VALID_CHANNEL(p_channel);

    SALT_ASSERT(
        mode <= SALT_CLIENT_STREAM,
        p_channel->err_code,
        SALT_ERR_NOT_SUPPORTED);

    SALT_ASSERT_NOT_NULL(write_impl, p_channel->err_code);
    SALT_ASSERT_NOT_NULL(read_impl, p_channel->err_code);

    p_channel->write_impl = write_impl;
    p_channel->read_impl = read_impl;
    p_channel->mode = mode;
    p_channel->state = SALT_CREATED;
    p_channel->err_code = SALT_ERR_NONE;
    p_channel->my_sk_pub = &p_channel->my_sk_sec[32];

    return SALT_SUCCESS;
}

salt_ret_t salt_set_context(
    salt_channel_t *p_channel,
    void *p_write_context,
    void *p_read_context)
{
    SALT_ASSERT_VALID_CHANNEL(p_channel);
    p_channel->write_channel.p_context = p_write_context;
    p_channel->read_channel.p_context = p_read_context;

    return SALT_SUCCESS;
}

salt_ret_t salt_set_signature(salt_channel_t *p_channel, const uint8_t *p_signature)
{

    SALT_ASSERT_VALID_CHANNEL(p_channel);
    SALT_ASSERT_NOT_NULL(p_signature, p_channel->err_code);

    memcpy(p_channel->my_sk_sec, p_signature, crypto_sign_SECRETKEYBYTES);

    p_channel->state = SALT_SIGNATURE_SET;

    return SALT_SUCCESS;

}


salt_ret_t salt_create_signature(salt_channel_t *p_channel)
{
    SALT_ASSERT_VALID_CHANNEL(p_channel);
    p_channel->err_code = SALT_ERR_NOT_SUPPORTED;
    return SALT_ERROR;
}

salt_ret_t salt_init_session(salt_channel_t *p_channel)
{
    SALT_ASSERT_VALID_CHANNEL(p_channel);
    SALT_ASSERT(p_channel->state >= SALT_SIGNATURE_SET,
        p_channel->err_code,
        SALT_ERR_NO_SIGNATURE);

    /* Clear precious history */
    MEMSET_ZERO(p_channel->my_ek_sec);
    MEMSET_ZERO(p_channel->my_ek_pub);
    MEMSET_ZERO(p_channel->ek_common);
    MEMSET_ZERO(p_channel->peer_sk_pub);
    MEMSET_ZERO(p_channel->peer_ek_pub);
    MEMSET_ZERO(p_channel->write_nonce);
    MEMSET_ZERO(p_channel->read_nonce);

    /* Initiate write and read nonce */
    if (p_channel->mode == SALT_SERVER)
    {
        p_channel->write_nonce[0]  = SALT_WRITE_NONCE_INIT_SERVER;
        p_channel->read_nonce[0] = SALT_READ_NONCE_INIT_SERVER;
        p_channel->write_nonce_incr = SALT_WRITE_NONCE_INCR_SERVER;
        p_channel->read_nonce_incr = SALT_READ_NONCE_INCR_SERVER;
    }
    else
    {
        p_channel->write_nonce[0]  = SALT_WRITE_NONCE_INIT_CLIENT;
        p_channel->read_nonce[0] = SALT_READ_NONCE_INIT_CLIENT;
        p_channel->write_nonce_incr = SALT_WRITE_NONCE_INCR_CLIENT;
        p_channel->read_nonce_incr = SALT_READ_NONCE_INCR_CLIENT;
    }

    /* Create ephemeral keypair used for only this session. */
    crypto_box_keypair(p_channel->my_ek_pub, p_channel->my_ek_sec);

    p_channel->state = SALT_SESSION_INITIATED;

    return SALT_SUCCESS;

}

salt_ret_t salt_handshake(salt_channel_t *p_channel)
{
    SALT_ASSERT_VALID_CHANNEL(p_channel);

    if (p_channel->mode == SALT_SERVER)
    {
        return salti_handshake_server(p_channel);
    }
    else
    {
        return salti_handshake_client(p_channel);
    }
}

/*======= Local function implementations ======================================*/
static salt_ret_t salti_handshake_server(salt_channel_t *p_channel)
{

    uint8_t proceed = 1;
    salt_ret_t ret_code = SALT_ERROR;

    while (proceed)
    {
        proceed = 0;
        switch (p_channel->state)
        {
            case SALT_SESSION_INITIATED:
                SALT_ASSERT(p_channel->state == SALT_SESSION_INITIATED,
                    p_channel->err_code,
                    SALT_ERR_SESSION_NOT_INITIATED);
                proceed = 1;
                p_channel->state = SALT_M1_INIT;
            case SALT_M1_INIT:
                p_channel->read_channel.p_data = p_channel->hdshk_buffer;
                p_channel->read_channel.max_size = SALT_HNDSHK_BUFFER_SIZE;
                proceed = 1;
                p_channel->state = SALT_M1_IO;
                break;
            case SALT_M1_IO:
                ret_code = p_channel->read_impl(&p_channel->read_channel);              
                if (ret_code == SALT_SUCCESS)
                {
                    proceed = 1;
                    p_channel->state = SALT_M1_VERIFY;
                }
                break;
            case SALT_M1_VERIFY:
                /*
                 * salti_parse_m1 will parse the M1 message and set the next
                 * state depending on the content of m1.
                 */  
                ret_code = salti_parse_m1(p_channel,
                    p_channel->read_channel.p_data,
                    p_channel->read_channel.size);
                proceed = (ret_code == SALT_SUCCESS);
                break;
            case SALT_M2_INIT:
                ret_code = salti_create_m2(p_channel,
                    p_channel->hdshk_buffer,
                    &p_channel->write_channel.size);
                if (ret_code == SALT_SUCCESS)
                {
                    p_channel->write_channel.p_data = p_channel->hdshk_buffer;
                    proceed = 1;
                    p_channel->state = SALT_M2_IO;
                }
                break;
            case SALT_M2_IO:
                ret_code = p_channel->write_impl(&p_channel->write_channel);              
                if (ret_code == SALT_SUCCESS)
                {
                    proceed = 1;
                    p_channel->state = SALT_M3_INIT;
                }
                break;
            case SALT_M3_INIT:
                ret_code = salti_create_m3(p_channel,
                    &p_channel->hdshk_buffer[38],
                    &p_channel->write_channel.size);
                {
                    p_channel->write_channel.p_data = &p_channel->hdshk_buffer[38];
                    proceed = 1;
                    p_channel->state = SALT_M3_IO;
                }
                break;
            case SALT_M3_IO:
                ret_code = p_channel->write_impl(&p_channel->write_channel);              
                if (ret_code == SALT_SUCCESS)
                {
                    proceed = 1;
                    p_channel->state = SALT_M4_INIT;
                }
                break;
            case SALT_M4_INIT:
                p_channel->read_channel.p_data = &p_channel->hdshk_buffer[crypto_secretbox_BOXZEROBYTES];
                p_channel->read_channel.max_size = (SALT_HNDSHK_BUFFER_SIZE-crypto_secretbox_BOXZEROBYTES);
                proceed = 1;
                p_channel->state = SALT_M4_IO;
                break;
            case SALT_M4_IO:
                ret_code = p_channel->read_impl(&p_channel->read_channel);              
                if (ret_code == SALT_SUCCESS)
                {
                    proceed = 1;
                    p_channel->state = SALT_M4_VERIFY;
                }
                break;
            case SALT_M4_VERIFY:
                ret_code = salti_parse_m4(p_channel,
                    p_channel->hdshk_buffer,
                    p_channel->read_channel.size + crypto_secretbox_BOXZEROBYTES);
                proceed = (ret_code == SALT_SUCCESS);
                break;
            default:
                p_channel->err_code = SALT_ERR_INVALID_STATE;
                ret_code = SALT_ERROR;
                break;
        }
    }

    return ret_code;
}

static salt_ret_t salti_handshake_client(salt_channel_t *p_channel)
{
    uint8_t proceed = 1;
    salt_ret_t ret_code = SALT_ERROR;

    while (proceed)
    {
        proceed = 0;
        switch (p_channel->state)
        {
            case SALT_SESSION_INITIATED:
                SALT_ASSERT(p_channel->state == SALT_SESSION_INITIATED,
                    p_channel->err_code,
                    SALT_ERR_SESSION_NOT_INITIATED);
                proceed = 1;
                p_channel->state = SALT_M1_INIT;
            case SALT_M1_INIT:
                ret_code = salti_create_m1(p_channel,
                    p_channel->hdshk_buffer,
                    &p_channel->write_channel.size);
                if (ret_code == SALT_SUCCESS)
                {
                    p_channel->write_channel.p_data = p_channel->hdshk_buffer;
                    proceed = 1;
                    p_channel->state = SALT_M1_IO;
                }
                break;
            case SALT_M1_IO:
                ret_code = p_channel->write_impl(&p_channel->write_channel);              
                if (ret_code == SALT_SUCCESS)
                {
                    proceed = 1;
                    p_channel->state = SALT_M2_INIT;
                }
                break;
            case SALT_M2_INIT:
                p_channel->read_channel.p_data = p_channel->hdshk_buffer;
                p_channel->read_channel.max_size = SALT_HNDSHK_BUFFER_SIZE;
                proceed = 1;
                p_channel->state = SALT_M2_IO;
                break;
            case SALT_M2_IO:
                ret_code = p_channel->read_impl(&p_channel->read_channel);              
                if (ret_code == SALT_SUCCESS)
                {
                    proceed = 1;
                    p_channel->state = SALT_M2_VERIFY;
                }
                break;
            case SALT_M2_VERIFY: 
                ret_code = salti_parse_m2(p_channel,
                    p_channel->read_channel.p_data,
                    p_channel->read_channel.size);
                /*
                 * We could start calculate M4 here.
                 */
                proceed = (ret_code == SALT_SUCCESS);
                break;
            case SALT_M3_INIT:
                p_channel->read_channel.p_data = &p_channel->hdshk_buffer[crypto_secretbox_BOXZEROBYTES];
                p_channel->read_channel.max_size = SALT_HNDSHK_BUFFER_SIZE-crypto_secretbox_BOXZEROBYTES;
                proceed = 1;
                p_channel->state = SALT_M3_IO;
                break;
            case SALT_M3_IO:
                ret_code = p_channel->read_impl(&p_channel->read_channel);              
                if (ret_code == SALT_SUCCESS)
                {
                    proceed = 1;
                    p_channel->state = SALT_M3_VERIFY;
                }
                break;
            case SALT_M3_VERIFY: 
                ret_code = salti_parse_m3(p_channel,
                    p_channel->hdshk_buffer,
                    p_channel->read_channel.size + crypto_secretbox_BOXZEROBYTES);
                proceed = (ret_code == SALT_SUCCESS);
                break;
            default:
                p_channel->err_code = SALT_ERR_INVALID_STATE;
                ret_code = SALT_ERROR;
                break;
        }
    }

    return ret_code;
}

static salt_ret_t salti_create_m1(salt_channel_t *p_channel, uint8_t *p_data, uint32_t *size)
{
    uint8_t offset = 0;
    uint8_t *p_msg;

    if (p_channel->mode == SALT_CLIENT_STREAM)
    {
        /* TODO: Make little/big endian indepentent. */
        *((uint32_t*)p_data) = crypto_box_PUBLICKEYBYTES + 2U;
        offset = 4;
    }

    p_msg = p_data + offset;

    p_msg[0] = 'S';
    p_msg[1] = '2';

    /* Header1 */
    p_msg[2] = 0x00;
    p_msg[3] = 0x00;

    memcpy(&p_msg[4], p_channel->my_ek_pub, crypto_box_PUBLICKEYBYTES);

    *size = 36 + offset;

    return SALT_SUCCESS;

}

static salt_ret_t salti_parse_m1(salt_channel_t *p_channel, uint8_t *p_data, uint8_t size)
{
    SALT_ASSERT(size >= 36,
        p_channel->err_code,
        SALT_ERR_M1_TOO_SMALL);

    SALT_ASSERT(p_data[0] == 'S' && p_data[1] == '2',
        p_channel->err_code,
        SALT_ERR_BAD_PROTOCOL);

    /*
     * p_data[2] and p_data[3] contains the Header1 bytes.
     *
     * If bit 0 in p_data[3] is set, the client is sending
     * a resume ticket.
     */

    if ((p_data[3] & 0x01U) > 0U)
    {
        /* Resume request */
        p_channel->err_code = SALT_ERR_NOT_SUPPORTED;
        return SALT_ERROR;
    }
    else {
        /*
         * Normal handshake
         *
         * The client public encryption key is located in
         * p_data[4:36]. We can now calculate the shared
         * symmetric encryption key.
         *
         */
        memcpy(p_channel->peer_ek_pub, &p_data[4], crypto_box_PUBLICKEYBYTES);
        /* Calculate shared key. */
        int ret = crypto_box_beforenm(p_channel->ek_common,
            p_channel->peer_ek_pub,
            p_channel->my_ek_sec);
        SALT_ASSERT(ret == 0, p_channel->err_code, SALT_ERR_COMMON_KEY);

        /* Go to M2 state */
        p_channel->state = SALT_M2_INIT;
    }

    if (size > 36U && memcmp(&p_data[36], p_channel->my_sk_pub, crypto_sign_PUBLICKEYBYTES) != 0)
    {
        /* Virtual host and ServerSigKey does not match our sig key, not supported! */
        p_channel->err_code = SALT_ERR_NOT_SUPPORTED;
        return SALT_ERROR;
    }

    return SALT_SUCCESS;

}

/**
 * @brief Create M2 message.
 *
 * Structure:
 *      { m2header[0] , m2header[1] , serverEncKey[32] }
 */
static salt_ret_t salti_create_m2(salt_channel_t *p_channel, uint8_t *p_data, uint32_t *size)
{
    /* Header2 is 0x0000 */
    uint8_t offset = 0;
    if (p_channel->mode == SALT_SERVER_STREAM)
    {
        /* TODO: Make little/big endian indepentent. */
        *((uint32_t*)p_data) = crypto_box_PUBLICKEYBYTES + 2U;
        offset = 4;
    }

    p_data[0+offset] = 0x00U;
    p_data[1+offset] = 0x00U;
    memcpy(&p_data[2+offset], p_channel->my_ek_pub, crypto_box_PUBLICKEYBYTES);
    *size = crypto_box_PUBLICKEYBYTES + 2U + offset;

    return SALT_SUCCESS;
}

static salt_ret_t salti_parse_m2(salt_channel_t *p_channel, uint8_t *p_data, uint8_t size)
{
    int ret;

    SALT_ASSERT(size >= 34,
        p_channel->err_code,
        SALT_ERR_M2_TOO_SMALL);

    /* Header2 in p_data[0], p_data[1] */

    memcpy(p_channel->peer_ek_pub, &p_data[2], crypto_box_PUBLICKEYBYTES);
    p_channel->state = SALT_M3_INIT;

   ret = crypto_box_beforenm(p_channel->ek_common, p_channel->peer_ek_pub, p_channel->my_ek_sec);

    SALT_ASSERT(ret == 0,
        p_channel->err_code,
        SALT_ERR_COMMON_KEY);

    return SALT_SUCCESS;
}

/**
 * @brief Create M2 message.
 *
 * Structure:
 *      { m3header[0] , m3header[1] , authTag[16] , Encrypted1[96] }
 *
 * Step 1: 
 *      sign({ ServerEncKeyPub[32] , ClientEncKeyPub[32] })
 *  -->      { signature[64] , ServerEncKeyPub[32] , ClientEncKeyPub[32] }
 * Step 2:
 *           { reserved[64] , signature[64] }
 *  -->      { 0x00[32] , ServerSigKeyPub[32] , signature[64] }
 * Step 3:
 *   encrypt({ 0x00[32] , ServerSigKeyPub[32] , signature[64] })
 *  -->      { 0x00[16] , AuthTag[16] , Encrypted1[96] }
 *  -->      { m3header[0] , m3header[1] , authTag[16] , Encrypted1[96] }
 *
 * M3 size = 2 + 16 + 96 = 114
 *
 */
static salt_ret_t salti_create_m3(salt_channel_t *p_channel, uint8_t *p_data, uint32_t *size)
{

    int ret;
    unsigned long long sign_msg_size;
    uint8_t offset = 0;
    uint8_t *p_msg;

    if (p_channel->mode == SALT_SERVER_STREAM)
    {
        /* TODO: Make little/big endian indepentent. */
        *((uint32_t*)p_data) = 114;
        offset = 4;
    }

    p_msg = p_data + offset;

    memcpy(p_msg, p_channel->my_ek_pub, crypto_box_PUBLICKEYBYTES);
    memcpy(&p_msg[crypto_box_PUBLICKEYBYTES], p_channel->peer_ek_pub, crypto_box_PUBLICKEYBYTES);

    ret = crypto_sign(
        p_msg,
        &sign_msg_size,
        p_msg,
        crypto_box_PUBLICKEYBYTES*2,
        p_channel->my_sk_sec);

    SALT_ASSERT(ret == 0,
        p_channel->err_code,
        SALT_ERR_SIGNING);

    PRINT_BYTES(p_msg, 128);

    memmove(&p_msg[crypto_sign_BYTES], p_msg, crypto_sign_BYTES);
    memcpy(&p_msg[crypto_secretbox_ZEROBYTES], p_channel->my_sk_pub, crypto_sign_PUBLICKEYBYTES);
    memset(p_msg, 0x00U, crypto_secretbox_ZEROBYTES);

    PRINT_BYTES(p_msg, 128);
    
    SALT_ASSERT(salti_encrypt(p_channel, p_msg, 128) == SALT_SUCCESS,
        p_channel->err_code,
        SALT_ERR_ENCRYPTION);

    PRINT_BYTES(p_msg, 128);

    memmove(&p_msg[2], &p_msg[crypto_secretbox_BOXZEROBYTES], 112);

    *size = 114 + offset;

    PRINT_BYTES(p_data, *size);

    return SALT_SUCCESS;

}

static salt_ret_t salti_parse_m3(salt_channel_t *p_channel, uint8_t *p_data, uint8_t size)
{

    int ret;
    unsigned long long sign_msg_size;
    uint8_t tmp[128];

    SALT_ASSERT(size == 130,
        p_channel->err_code,
        SALT_ERR_M2_TOO_SMALL);

    /* TODO: What to do with Header2 p_data[17], p_data[18]? */
    memset(&p_data[2], 0, crypto_secretbox_BOXZEROBYTES);

    SALT_ASSERT(salti_decrypt(p_channel, &p_data[2], size - 2) == SALT_SUCCESS,
        p_channel->err_code,
        SALT_ERR_DECRYPTION);

    memcpy(p_channel->peer_sk_pub, &p_data[2 + crypto_secretbox_ZEROBYTES], crypto_sign_PUBLICKEYBYTES);

    memmove(p_data,
        &p_data[2 + crypto_secretbox_ZEROBYTES + crypto_sign_PUBLICKEYBYTES],
        crypto_sign_BYTES);

    memcpy(&p_data[crypto_sign_BYTES],
        p_channel->peer_ek_pub,
        crypto_box_PUBLICKEYBYTES);

    memcpy(&p_data[crypto_sign_BYTES+crypto_box_PUBLICKEYBYTES],
        p_channel->my_ek_pub,
        crypto_box_PUBLICKEYBYTES);

    PRINT_BYTES(p_data, 128);
    PRINT_BYTES(p_channel->peer_sk_pub, 32);

    
    ret = crypto_sign_open(
        tmp,
        &sign_msg_size,
        p_data,
        crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES*2,
        p_channel->peer_sk_pub);

    SALT_ASSERT(ret == 0,
        p_channel->err_code,
        SALT_ERR_BAD_SIGNATURE);

    p_channel->state = SALT_M4_INIT;

    return SALT_SUCCESS;

}

static salt_ret_t salti_parse_m4(salt_channel_t *p_channel, uint8_t *p_data, uint8_t size)
{
    SALT_ASSERT(salti_decrypt(p_channel, p_data, size) == SALT_SUCCESS,
        p_channel->err_code,
        SALT_ERR_ENCRYPTION);

    memcpy(p_channel->peer_sk_pub, &p_data[crypto_secretbox_ZEROBYTES], crypto_sign_PUBLICKEYBYTES);
   // memmove(p_data, &p_data[])

    return SALT_ERROR;
}

static salt_ret_t salti_encrypt(salt_channel_t *p_channel, uint8_t *p_data, uint32_t size)
{
    int ret = crypto_box_afternm(
        p_data,
        p_data,
        size,
        p_channel->write_nonce,
        p_channel->ek_common);

    if (ret == 0)
    {
        salti_increase_nonce(p_channel->write_nonce, p_channel->write_nonce_incr);
        return SALT_SUCCESS;
    }

    return SALT_ERROR;

}

static salt_ret_t salti_decrypt(salt_channel_t *p_channel, uint8_t *p_data, uint32_t size)
{

    int ret = crypto_box_open_afternm(
        p_data,
        p_data,
        size,
        p_channel->read_nonce,
        p_channel->ek_common);


    if (ret == 0)
    {
        salti_increase_nonce(p_channel->read_nonce, p_channel->read_nonce_incr);
        return SALT_SUCCESS;
    }

    return SALT_ERROR;

}

static void salti_increase_nonce(uint8_t *p_nonce, uint8_t increment)
{
   uint_fast16_t c = increment;
   uint8_t i;

   for (i = 0; i < crypto_box_NONCEBYTES; i++) {
      c += (uint_fast16_t) p_nonce[i];
      p_nonce[i] = (uint8_t) c;
      c >>= 8U;
   }

}
