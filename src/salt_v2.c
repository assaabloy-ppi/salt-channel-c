/**
 * @file salt_v2.c
 *
 * Salt channel version 2 implementation.
 *
 */

/*======= Includes ============================================================*/
#include "salt_v2.h"

/* C Library includes */
#include <string.h> /* memcpy, memset */

/*======= Local Macro Definitions =============================================*/
#ifdef SALT_DEBUG
    #include <stdio.h>
    #define SALT_ASSERT(x, error_code)                                          \
    do {                                                                        \
        if (!(x)) {                                                             \
            p_channel->err_code = error_code;                                   \
            printf(                                                             \
                "Runtime error (%s): %s at %s:%d, %s.\r\n",                     \
                #error_code, #x, __FILE__, __LINE__, __func__);                 \
            return SALT_ERROR;                                                  \
        }                                                                       \
    } while (0)

#else
    #define SALT_ASSERT(x, error_code)                                          \
    do {                                                                        \
        if (!(x)) {                                                             \
            p_channel->err_code = error_code;                                   \
            return SALT_ERROR;                                                  \
        }                                                                       \
    } while (0)
#endif

#define NULL_PTR ( (void *) 0)
#define SALT_ASSERT_NOT_NULL(x)                                                 \
    SALT_ASSERT(((x) != NULL_PTR), SALT_ERR_NULL_PTR)

#define SALT_ASSERT_VALID_CHANNEL(x) if ((x) == NULL_PTR) return SALT_ERROR
#define SALT_TRIGGER_ERROR                      (0x00U)
#define SALT_ERROR(err_code) SALT_ASSERT(SALT_TRIGGER_ERROR, err_code)
#define MEMSET_ZERO(x) memset((x), 0, sizeof((x)))

/* Nonce initial values and increments */
#define SALT_WRITE_NONCE_INCR_SERVER            (2U)
#define SALT_WRITE_NONCE_INCR_CLIENT            (2U)
#define SALT_WRITE_NONCE_INIT_SERVER            (2U)
#define SALT_WRITE_NONCE_INIT_CLIENT            (1U)
#define SALT_READ_NONCE_INCR_SERVER             (2U)
#define SALT_READ_NONCE_INCR_CLIENT             (2U)
#define SALT_READ_NONCE_INIT_SERVER             (1U)
#define SALT_READ_NONCE_INIT_CLIENT             (2U)

/* Various defines */
#define SALT_CLEAR                              (0U)
#define SALT_ENCRYPTED                          (1U)
#define SALT_LENGTH_SIZE                        (4U)
#define SALT_HEADER_SIZE                        (0x01U)
#define SALT_HEADER_TYPE_FLAG                   (0x0FU)

/* M1 Message defines */
#define SALT_M1_HEADER_VALUE                    (0x01U)
#define SALT_M1_SIG_KEY_INCLUDED_FLAG           (0x10U)
#define SALT_M1_TICKED_INCLUDED_FLAG            (0x20U)
#define SALT_M1_TICKED_REQUEST_FLAG             (0x40U)

/* M2 Message defines */
#define SALT_M2_HEADER_VALUE                    (0x02U)
#define SALT_M2_ENC_KEY_INCLUDED_FLAG           (0x10U)
#define SALT_M2_RESUME_SUPPORTED_FLAG           (0x20U)
#define SALT_M2_NO_SUCH_SERVER_FLAG             (0x40U)
#define SALT_M2_BAD_TICKET_FLAG                 (0x80U)

/* M3 Message defines */
#define SALT_M3_MAX_SIZE                        (131U)
#define SALT_M3_HEADER_VALUE                    (0x03U)
#define SALT_M3_SIG_KEY_INCLUDED_FLAG           (0x10U)

/* M4 Message defines */
#define SALT_M4_HEADER_VALUE                    (0x04U)

/*======= Type Definitions ====================================================*/

/*======= Local variable declarations =========================================*/

/*======= Local function prototypes ===========================================*/
static salt_ret_t salti_read(salt_channel_t *p_channel,uint8_t *p_data, uint32_t *size, uint8_t encrypted);
static salt_ret_t salti_write(salt_channel_t *p_channel, uint8_t *p_data, uint32_t size, uint8_t encrypted);
static salt_ret_t salti_handshake_server(salt_channel_t *p_channel);
static salt_ret_t salti_handshake_client(salt_channel_t *p_channel);
static salt_ret_t salti_create_m1(salt_channel_t *p_channel, uint8_t *p_data, uint32_t *size);
static salt_ret_t salti_handle_m1(salt_channel_t *p_channel, uint8_t *p_data, uint32_t size);
static salt_ret_t salti_create_m2(salt_channel_t *p_channel, uint8_t *p_data, uint32_t *size);
static salt_ret_t salti_handle_m2(salt_channel_t *p_channel, uint8_t *p_data, uint32_t size);
static salt_ret_t salti_create_m3m4(salt_channel_t *p_channel, uint8_t *p_buffer, uint32_t *size, uint8_t header);
static salt_ret_t salti_handle_m3m4(salt_channel_t *p_channel, uint8_t *p_data, uint32_t size, uint8_t header);
static salt_ret_t salti_encrypt(salt_channel_t *p_channel, uint8_t *p_data, uint32_t size);
static salt_ret_t salti_decrypt(salt_channel_t *p_channel, uint8_t *p_data, uint32_t size);
static void salti_increase_nonce(uint8_t *p_nonce, uint8_t increment);
static void salti_size_to_bytes(uint8_t *dest, uint32_t size);
static uint32_t salti_bytes_to_size(uint8_t *src);

/*======= Global function implementations =====================================*/
salt_ret_t salt_create(
   salt_channel_t *p_channel,
   salt_mode_t mode,
   salt_io_impl write_impl,
   salt_io_impl read_impl)
{

    SALT_ASSERT_VALID_CHANNEL(p_channel);

    SALT_ASSERT(
        mode <= SALT_CLIENT,
        SALT_ERR_NOT_SUPPORTED);

    SALT_ASSERT_NOT_NULL(write_impl);
    SALT_ASSERT_NOT_NULL(read_impl);

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
    SALT_ASSERT_NOT_NULL(p_signature);

    memcpy(p_channel->my_sk_sec, p_signature, crypto_sign_SECRETKEYBYTES);

    p_channel->state = SALT_SIGNATURE_SET;

    return SALT_SUCCESS;

}


salt_ret_t salt_create_signature(salt_channel_t *p_channel)
{
    SALT_ASSERT_VALID_CHANNEL(p_channel);
    crypto_sign_keypair(p_channel->my_sk_pub, p_channel->my_sk_sec);
    p_channel->state = SALT_SIGNATURE_SET;
    return SALT_SUCCESS;
}

salt_ret_t salt_init_session(salt_channel_t *p_channel, uint8_t *hdshk_buffer, uint32_t hdshk_buffer_size)
{
    SALT_ASSERT_VALID_CHANNEL(p_channel);
    SALT_ASSERT(p_channel->state >= SALT_SIGNATURE_SET,
        SALT_ERR_NO_SIGNATURE);

    SALT_ASSERT_NOT_NULL(hdshk_buffer);
    SALT_ASSERT(hdshk_buffer_size >= SALT_HNDSHK_BUFFER_SIZE,
        SALT_ERR_BUFF_TO_SMALL);

    /* Save handshake buffer */
    p_channel->hdshk_buffer = hdshk_buffer;
    p_channel->hdshk_buffer_size = hdshk_buffer_size;

    /* Clear precious history */
    MEMSET_ZERO(p_channel->my_ek_sec);
    MEMSET_ZERO(p_channel->my_ek_pub);
    MEMSET_ZERO(p_channel->ek_common);
    MEMSET_ZERO(p_channel->peer_sk_pub);
    MEMSET_ZERO(p_channel->peer_ek_pub);
    MEMSET_ZERO(p_channel->write_nonce);
    MEMSET_ZERO(p_channel->read_nonce);
    memset(hdshk_buffer, 0, 32);

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

    p_channel->write_channel.state = SALT_IO_READY;
    p_channel->read_channel.state = SALT_IO_READY;

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

salt_ret_t salt_request_ticket(salt_channel_t *p_channel, uint8_t *p_ticket, uint32_t *p_ticket_size, uint32_t max_size)
{
    SALT_ASSERT_VALID_CHANNEL(p_channel);
    (void) p_ticket;
    (void) p_ticket_size;
    (void) max_size;
    p_channel->err_code = SALT_ERR_NOT_SUPPORTED;
    return SALT_ERROR;
}

salt_ret_t salt_resume(salt_channel_t *p_channel, uint8_t *p_host, uint8_t *p_ticket, uint32_t ticket_size, uint8_t *session_key)
{
    SALT_ASSERT_VALID_CHANNEL(p_channel);
    (void) p_host;
    (void) p_ticket;
    (void) ticket_size;
    (void) session_key;
    p_channel->err_code = SALT_ERR_NOT_SUPPORTED;
    return SALT_ERROR; 
}

salt_ret_t salt_read(salt_channel_t *p_channel, uint8_t *p_buffer, uint32_t *p_recv_size, uint32_t max_size)
{
    SALT_ASSERT_VALID_CHANNEL(p_channel);
    SALT_ASSERT(SALT_SESSION_ESTABLISHED == p_channel->state, SALT_ERR_INVALID_STATE);
    *p_recv_size = max_size;
    return salti_read(p_channel, p_buffer, p_recv_size, SALT_ENCRYPTED);
}

salt_ret_t salt_write(salt_channel_t *p_channel, uint8_t *p_buffer, uint32_t size)
{
    SALT_ASSERT_VALID_CHANNEL(p_channel);
    SALT_ASSERT(SALT_SESSION_ESTABLISHED == p_channel->state, SALT_ERR_INVALID_STATE);
    return salti_write(p_channel, p_buffer, size, SALT_ENCRYPTED);
}

/*======= Local function implementations ======================================*/
static salt_ret_t salti_read(salt_channel_t *p_channel, uint8_t *p_data, uint32_t *size, uint8_t encrypted)
{
    /* Maximum size is stored in *size */
    salt_ret_t ret_code = SALT_ERROR;

    switch (p_channel->read_channel.state)
    {
        case SALT_IO_READY:
            p_channel->read_channel.p_data = p_data;
            p_channel->read_channel.max_size = *size;
            p_channel->read_channel.size_expected = SALT_LENGTH_SIZE;
            p_channel->read_channel.size = 0;
            p_channel->read_channel.state = SALT_IO_SIZE;
        case SALT_IO_SIZE:
            ret_code = p_channel->read_impl(&p_channel->read_channel);

            if (SALT_SUCCESS != ret_code)
            {
                break;
            }

            p_channel->read_channel.size_expected = salti_bytes_to_size(p_data);

            if (p_channel->read_channel.size_expected > p_channel->read_channel.max_size)
            {
                p_channel->err_code = SALT_ERR_BUFF_TO_SMALL;
                ret_code = SALT_ERROR;
                break;
            }
            p_channel->read_channel.p_data = p_data;
            if (encrypted)
            {
                p_channel->read_channel.p_data += crypto_secretbox_BOXZEROBYTES;
            }
            p_channel->read_channel.state = SALT_IO_PENDING;
            p_channel->read_channel.size = 0;
        case SALT_IO_PENDING:
            ret_code = p_channel->read_impl(&p_channel->read_channel);
            if (SALT_SUCCESS == ret_code)
            {
                *size = p_channel->read_channel.size;
                if (encrypted)
                {
                    memset(p_data, 0x00U, crypto_secretbox_BOXZEROBYTES);
                    ret_code = salti_decrypt(p_channel,
                        p_channel->read_channel.p_data - crypto_secretbox_BOXZEROBYTES,
                        p_channel->read_channel.size + crypto_secretbox_BOXZEROBYTES);

                    if (SALT_ERROR == ret_code)
                    {
                        p_channel->err_code = SALT_ERR_DECRYPTION;
                    }
                    (*size) -= crypto_secretbox_BOXZEROBYTES;
                }
                p_channel->read_channel.state = SALT_IO_READY;
            }
            break;
        default:
            SALT_ERROR(SALT_ERR_INVALID_STATE);
    }

    if (SALT_ERROR == ret_code)
    {
        p_channel->read_channel.state = SALT_IO_READY;
    }

    return ret_code;
}

static salt_ret_t salti_write(salt_channel_t *p_channel, uint8_t *p_data, uint32_t size, uint8_t encrypted)
{

    salt_ret_t ret_code = SALT_ERROR;

    switch (p_channel->write_channel.state)
    {
        case SALT_IO_READY:
            p_channel->write_channel.p_data = p_data;
            p_channel->write_channel.size = 0;
            p_channel->write_channel.size_expected = size;
            
            if (encrypted)
            {
                memset(p_data, 0x00U, crypto_secretbox_ZEROBYTES);

                ret_code = salti_encrypt(p_channel, p_data, size);
                if (SALT_SUCCESS != ret_code)
                {
                    p_channel->err_code = SALT_ERR_ENCRYPTION;
                    return ret_code;
                }

                p_channel->write_channel.size_expected -= crypto_secretbox_BOXZEROBYTES;
                p_channel->write_channel.p_data += crypto_secretbox_BOXZEROBYTES;

                salti_size_to_bytes(&p_data[crypto_secretbox_BOXZEROBYTES-SALT_LENGTH_SIZE], p_channel->write_channel.size_expected);
                p_channel->write_channel.size_expected += SALT_LENGTH_SIZE;
                p_channel->write_channel.p_data -= SALT_LENGTH_SIZE;

            }
            p_channel->write_channel.state = SALT_IO_PENDING;
        case SALT_IO_PENDING:
            ret_code = p_channel->write_impl(&p_channel->write_channel);  
            if (SALT_SUCCESS == ret_code)
            {
                p_channel->write_channel.state = SALT_IO_READY;
            }            
            break;
        default:
            SALT_ERROR(SALT_ERR_INVALID_STATE); 
    }

    if (SALT_ERROR == ret_code)
    {
        p_channel->read_channel.state = SALT_IO_READY;
    }

    return ret_code;

}

static salt_ret_t salti_handshake_server(salt_channel_t *p_channel)
{

    uint32_t size;
    salt_ret_t ret_code = SALT_ERROR;

    switch (p_channel->state)
    {
        case SALT_SESSION_INITIATED:
            size = p_channel->hdshk_buffer_size; /* Max size */
            p_channel->state = SALT_M1_IO;
        case SALT_M1_IO:
            ret_code = salti_read(p_channel,
                p_channel->hdshk_buffer,
                &size, SALT_CLEAR);
            if (SALT_SUCCESS != ret_code)
            {
                /* Error or pending */
                break;
            }
            p_channel->state = SALT_M1_HANDLE;
        case SALT_M1_HANDLE:
            ret_code = salti_handle_m1(p_channel,p_channel->hdshk_buffer, size);
            SALT_ASSERT(SALT_SUCCESS == ret_code, p_channel->err_code);
            ret_code = salti_create_m2(p_channel, &p_channel->hdshk_buffer[129], &size);
            SALT_ASSERT(SALT_SUCCESS == ret_code, p_channel->err_code);

            /*
             * If the client included an invalid public signature key, the
             * SALT_ERR_NO_SUCH_SERVER error code will be set in p_channel->err_code.
             * If this is the case, we will stop imidiately after sending M2 and do not want
             * to calculate the symmetric ephemeral encryption key.
             */

            p_channel->state = SALT_M2_INIT;
        case SALT_M2_INIT:
            ret_code = salti_write(p_channel,
                &p_channel->hdshk_buffer[129],
                size, SALT_CLEAR);

            SALT_ASSERT(SALT_ERROR != ret_code, SALT_ERR_IO_WRITE);

            /*
             * Not error => Pending or success, calculate session key.
             * while I/O is in progress.
             */
            if (SALT_ERR_NONE == p_channel->err_code)
            {
                SALT_ASSERT(crypto_box_beforenm(p_channel->ek_common,
                    p_channel->peer_ek_pub,
                    p_channel->my_ek_sec) == 0, SALT_ERR_COMMON_KEY);
            }

            if (SALT_SUCCESS != ret_code)
            {
                /* I/O is still Pending */
                p_channel->state = SALT_M2_IO;
                break;
            }
        case SALT_M2_IO:
            /* Only continue I/O if the previous I/O call did not finish. */
            if (SALT_SUCCESS != ret_code)
            {
                ret_code = salti_write(p_channel,
                                &p_channel->hdshk_buffer[129],
                                size, SALT_CLEAR);
                if (SALT_SUCCESS != ret_code) {
                    /* Error or pending */
                    break;
                }
            }
            SALT_ASSERT(SALT_ERR_NONE == p_channel->err_code, p_channel->err_code);
            p_channel->state = SALT_M3_INIT;
        case SALT_M3_INIT:
            ret_code = salti_create_m3m4(p_channel,
                p_channel->hdshk_buffer,
                &size,
                (SALT_M3_HEADER_VALUE | SALT_M3_SIG_KEY_INCLUDED_FLAG));
            SALT_ASSERT(SALT_SUCCESS == ret_code, p_channel->err_code);
            p_channel->state = SALT_M3_IO;
        case SALT_M3_IO:
            ret_code = salti_write(p_channel,
                p_channel->hdshk_buffer,
                size, SALT_ENCRYPTED);
            if (SALT_SUCCESS != ret_code)
            {
                break;
            }
            p_channel->state = SALT_M4_IO;
            size = p_channel->hdshk_buffer_size;
        case SALT_M4_IO:
            ret_code = salti_read(p_channel,
                p_channel->hdshk_buffer,
                &size, SALT_ENCRYPTED);
            if (ret_code != SALT_SUCCESS)
            {
                break;
            }
            p_channel->state = SALT_M4_HANDLE;
        case SALT_M4_HANDLE:
            ret_code = salti_handle_m3m4(p_channel,
                &p_channel->hdshk_buffer[crypto_secretbox_ZEROBYTES],
                size, SALT_M4_HEADER_VALUE);
            SALT_ASSERT(SALT_SUCCESS == ret_code, p_channel->err_code);
            memset(p_channel->hdshk_buffer, 0x00, p_channel->hdshk_buffer_size);
            p_channel->state = SALT_SESSION_ESTABLISHED;
        case SALT_SESSION_ESTABLISHED:
            ret_code = SALT_SUCCESS;
            break;
        default:
            SALT_ERROR(SALT_ERR_INVALID_STATE);  
    }

    return ret_code;
}

static salt_ret_t salti_handshake_client(salt_channel_t *p_channel)
{
    uint32_t size;
    salt_ret_t ret_code = SALT_ERROR;

    switch (p_channel->state)
    {
        case SALT_SESSION_INITIATED:
            ret_code = salti_create_m1(p_channel, &p_channel->hdshk_buffer[crypto_secretbox_ZEROBYTES], &size);
            SALT_ASSERT(SALT_SUCCESS == ret_code, p_channel->err_code);
            p_channel->state = SALT_M1_IO;
        case SALT_M1_IO:
            ret_code = salti_write(p_channel,
                &p_channel->hdshk_buffer[crypto_secretbox_ZEROBYTES],
                size, SALT_CLEAR);
            if (SALT_SUCCESS != ret_code)
            {
                break;
            }
            size = 33U;
            p_channel->state = SALT_M2_IO;
        case SALT_M2_IO:
            ret_code = salti_read(p_channel,
                &p_channel->hdshk_buffer[crypto_secretbox_ZEROBYTES],
                &size, SALT_CLEAR);
            if (SALT_SUCCESS != ret_code)
            {
                break;
            }
            p_channel->state = SALT_M2_HANDLE;
        case SALT_M2_HANDLE:
            ret_code = salti_handle_m2(p_channel, &p_channel->hdshk_buffer[crypto_secretbox_ZEROBYTES], size);
            SALT_ASSERT(SALT_SUCCESS == ret_code, p_channel->err_code);
            /* calculate session key. */
            SALT_ASSERT(crypto_box_beforenm(p_channel->ek_common,
                p_channel->peer_ek_pub,
                p_channel->my_ek_sec) == 0, SALT_ERR_COMMON_KEY);
            ret_code = salti_create_m3m4(p_channel,
                &p_channel->hdshk_buffer[193],
                &size,
                SALT_M4_HEADER_VALUE);
            p_channel->write_channel.size = size;
            SALT_ASSERT(SALT_SUCCESS == ret_code, p_channel->err_code);
            p_channel->state = SALT_M3_IO;
            size = 129; /* Maximum size, the other "side" of p_channel->hdshk_buffer hold M4 */
        case SALT_M3_IO:
            ret_code = salti_read(p_channel,
                p_channel->hdshk_buffer,
                &size, SALT_ENCRYPTED);
            if (SALT_SUCCESS != ret_code)
            {
                break;
            }
            p_channel->state = SALT_M3_HANDLE;
        case SALT_M3_HANDLE:
            ret_code = salti_handle_m3m4(p_channel,
                &p_channel->hdshk_buffer[crypto_secretbox_ZEROBYTES],
                size, (SALT_M3_HEADER_VALUE | SALT_M3_SIG_KEY_INCLUDED_FLAG));
            SALT_ASSERT(SALT_SUCCESS == ret_code, p_channel->err_code);
            p_channel->state = SALT_M4_IO;
        case SALT_M4_IO:
            ret_code = salti_write(p_channel,
                &p_channel->hdshk_buffer[193],
                p_channel->write_channel.size, SALT_ENCRYPTED);
            if (SALT_SUCCESS != ret_code)
            {
                break;
            }
            memset(p_channel->hdshk_buffer, 0x00, p_channel->hdshk_buffer_size);
            p_channel->state = SALT_SESSION_ESTABLISHED;
        case SALT_SESSION_ESTABLISHED:
            ret_code = SALT_SUCCESS;
            break;
        default:
            SALT_ERROR(SALT_ERR_INVALID_STATE);
            break;
    }

    return ret_code;
}

/*
 ** @brief Creates the M1 message to initiate a salt channel.
 *
 * Resume feature and virtual host mode is not supported at this time.
 */
static salt_ret_t salti_create_m1(salt_channel_t *p_channel, uint8_t *p_data, uint32_t *size)
{

    /* First 4 bytes is reserved for size. */
    p_data[SALT_LENGTH_SIZE + 0] = SALT_M1_HEADER_VALUE;
    p_data[SALT_LENGTH_SIZE + 1] = 'S';
    p_data[SALT_LENGTH_SIZE + 2] = '2';

    memcpy(&p_data[SALT_LENGTH_SIZE + 3], p_channel->my_ek_pub, crypto_box_PUBLICKEYBYTES);
    (*size) = 35U;

    salti_size_to_bytes(&p_data[0], (*size));
    (*size) += SALT_LENGTH_SIZE;

    return SALT_SUCCESS;

}

static salt_ret_t salti_handle_m1(salt_channel_t *p_channel, uint8_t *p_data, uint32_t size)
{
    SALT_ASSERT(size >= 35,
        SALT_ERR_M1_TOO_SMALL);

    SALT_ASSERT((p_data[0] & SALT_HEADER_TYPE_FLAG) == SALT_M1_HEADER_VALUE,
        SALT_ERR_M1_BAD_HEADER);

    SALT_ASSERT(p_data[1] == 'S' && p_data[2] == '2',
        SALT_ERR_M1_BAD_PROTOCOL);

    if ((p_data[0] & SALT_M1_SIG_KEY_INCLUDED_FLAG) > 0U)
    {
        /*
         * The client included a public signature key. I.e., the client
         * expects the host to have that signature. Could be if we are
         * hosting several signatures, however, this is not supported at
         * this time. This means that the included signature key MUST match
         * our one and only public signature key.
         *
         * If the key does not match, we MUST close the session after M2 is sent.
         * Due to this, we does not need to store the client ephemeral public encryption
         * key.
         */
        if (!(size >= 67U && memcmp(&p_data[35], p_channel->my_sk_pub, crypto_sign_PUBLICKEYBYTES)) == 0)
        {
            p_channel->err_code = SALT_ERR_NO_SUCH_SERVER;
        }
        /*
         * TODO: How to handle multiple hosts?
         */
    }


    /* Check if client is requesting a resume. */
    if ((p_data[0] & SALT_M1_TICKED_INCLUDED_FLAG) > 0U)
    {
        /*
         * At this point, we do not support the resume feature. I.e., if the
         * client includes a resume ticket we must make sure to respond to this.
         */
        p_channel->err_code = SALT_ERR_NOT_SUPPORTED;
    }

    /* Copy the clients public ephemeral encryption key. */
    memcpy(p_channel->peer_ek_pub, &p_data[3], crypto_box_PUBLICKEYBYTES);

    return SALT_SUCCESS;

}

static salt_ret_t salti_create_m2(salt_channel_t *p_channel, uint8_t *p_data, uint32_t *size)
{
    /*
     * Depending on how M1 was handeled, we will have the error code in
     * p_channel->err_code.
     */
    switch(p_channel->err_code)
    {
        case SALT_ERR_NONE:
            /* First four bytes are reserved for size */
            p_data[SALT_LENGTH_SIZE + 0] = SALT_M2_HEADER_VALUE | SALT_M2_ENC_KEY_INCLUDED_FLAG;
            memcpy(&p_data[SALT_LENGTH_SIZE + 1], p_channel->my_ek_pub, crypto_box_PUBLICKEYBYTES);
            (*size) = 33U;
            /* Write 4 byte size */
            salti_size_to_bytes(&p_data[0], (*size));
            (*size) += SALT_LENGTH_SIZE;
            break;
        case SALT_ERR_NO_SUCH_SERVER:
            p_data[SALT_LENGTH_SIZE + 0] = SALT_M2_HEADER_VALUE | SALT_M2_NO_SUCH_SERVER_FLAG;
            (*size) = 1U;
            salti_size_to_bytes(&p_data[0], (*size));
            (*size) += SALT_LENGTH_SIZE;
            break;
        default:
            return SALT_ERROR;
    }

    return SALT_SUCCESS;
}

static salt_ret_t salti_handle_m2(salt_channel_t *p_channel, uint8_t *p_data, uint32_t size)
{
    SALT_ASSERT(size >= 33U,
        SALT_ERR_M2_TOO_SMALL);

    SALT_ASSERT((p_data[0] & SALT_HEADER_TYPE_FLAG) == SALT_M2_HEADER_VALUE,
        SALT_ERR_M2_BAD_HEADER);

    SALT_ASSERT((p_data[0] & SALT_M2_NO_SUCH_SERVER_FLAG) == 0U,
        SALT_ERR_NO_SUCH_SERVER);

    /*
     * If this fails, the server this not include an public ephemeral encryption
     * key. This should only occur if we requested a resume. This is however not
     * supported at this time.
     */
    SALT_ASSERT((p_data[0] & SALT_M2_ENC_KEY_INCLUDED_FLAG) > 0U,
        SALT_ERR_NOT_SUPPORTED);

    memcpy(p_channel->peer_ek_pub, &p_data[1], crypto_box_PUBLICKEYBYTES);

    return SALT_SUCCESS;
}

static salt_ret_t salti_create_m3m4(salt_channel_t *p_channel, uint8_t *p_buffer, uint32_t *size, uint8_t header)
{
    unsigned long long sign_msg_size;
    uint8_t *p_msg = &p_buffer[32];
    uint8_t *p_sig = &p_msg[SALT_HEADER_SIZE + crypto_sign_PUBLICKEYBYTES];

    p_msg[0] = header;
    memcpy(&p_msg[SALT_HEADER_SIZE], p_channel->my_sk_pub, 32);

    memcpy(p_sig, p_channel->my_ek_pub, crypto_box_PUBLICKEYBYTES);
    memcpy(&p_sig[crypto_box_PUBLICKEYBYTES], p_channel->peer_ek_pub, crypto_box_PUBLICKEYBYTES);

    SALT_ASSERT(crypto_sign(
            p_sig,
            &sign_msg_size,
            p_sig,
            crypto_box_PUBLICKEYBYTES*2,
            p_channel->my_sk_sec) == 0, SALT_ERR_SIGNING);

    (*size) = crypto_secretbox_ZEROBYTES + 97U;

    return SALT_SUCCESS;
}

static salt_ret_t salti_handle_m3m4(salt_channel_t *p_channel, uint8_t *p_data, uint32_t size, uint8_t header)
{
    unsigned long long sign_msg_size;
    uint8_t tmp_signature[128];

    SALT_ASSERT(97U == size, SALT_ERR_M3M4_WRONG_SIZE);

    SALT_ASSERT(p_data[0] == header,
        SALT_ERR_NOT_SUPPORTED);

    memcpy(&p_data[97], p_channel->peer_ek_pub, 32);
    memcpy(&p_data[97+32], p_channel->my_ek_pub, 32);

    SALT_ASSERT(crypto_sign_open(
        tmp_signature,
        &sign_msg_size,
        &p_data[33],
        crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES*2,
        &p_data[1]) == 0, SALT_ERR_BAD_SIGNATURE);

    memcpy(p_channel->peer_sk_pub, &p_data[1], crypto_sign_PUBLICKEYBYTES);

    return SALT_SUCCESS;
}

static salt_ret_t salti_encrypt(salt_channel_t *p_channel, uint8_t *p_data, uint32_t size)
{
    int ret = crypto_box_afternm(
        p_data,
        p_data,
        size,
        p_channel->write_nonce,
        p_channel->ek_common);

    if (0 == ret)
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


    if (0 == ret)
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

   for (i = 0U; i < crypto_box_NONCEBYTES; i++) {
      c += (uint_fast16_t) p_nonce[i];
      p_nonce[i] = (uint8_t) c;
      c >>= 8U;
   }

}

static void salti_size_to_bytes(uint8_t *dest, uint32_t size)
{
    memcpy(dest, &size, SALT_LENGTH_SIZE);
}

static uint32_t salti_bytes_to_size(uint8_t *src)
{
    return *((uint32_t*) src);
}
