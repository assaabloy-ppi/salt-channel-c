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
            return salt_error;                                                  \
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
#define SALT_LENGTH_SIZE                        (4U)

#define SALT_HEADER_SIZE                        (0x01U)
#define SALT_HEADER_TYPE_FLAG                   (0x0FU)
#define SALT_HANDSHAKE_MAX_MSG_SIZE             (200U)

#define SALT_M1_HEADER_VALUE                    (0x01U)
#define SALT_M1_SIG_KEY_INCLUDED_FLAG           (0x10U)
#define SALT_M1_TICKED_INCLUDED_FLAG            (0x20U)
#define SALT_M1_TICKED_REQUEST_FLAG             (0x40U)

#define SALT_M2_HEADER_VALUE                    (0x02U)
#define SALT_M2_ENC_KEY_INCLUDED_FLAG           (0x10U)
#define SALT_M2_RESUME_SUPPORTED_FLAG           (0x20U)
#define SALT_M2_NO_SUCH_SERVER_FLAG             (0x40U)
#define SALT_M2_BAD_TICKET_FLAG                 (0x80U)

#define SALT_M3_MAX_SIZE                        (131U)
#define SALT_M3_HEADER_VALUE                    (0x03U)
#define SALT_M3_SIG_KEY_INCLUDED_FLAG           (0x10U)

#define SALT_M4_HEADER_VALUE                    (0x04U)

/*======= Local function prototypes ===========================================*/
static salt_ret_t salti_handshake_server(salt_channel_t *p_channel);
static salt_ret_t salti_handshake_client(salt_channel_t *p_channel);

static salt_ret_t salti_create_m1(salt_channel_t *p_channel);
static salt_ret_t salti_handle_m1(salt_channel_t *p_channel, uint8_t *p_data, uint8_t size);
static salt_ret_t salti_create_m2(salt_channel_t *p_channel);
static salt_ret_t salti_handle_m2(salt_channel_t *p_channel, uint8_t *p_data, uint8_t size);
static salt_ret_t salti_create_m3m4_signature(salt_channel_t *p_channel, uint8_t *p_buf);
static salt_ret_t salti_create_m3(salt_channel_t *p_channel);
static salt_ret_t salti_handle_m3(salt_channel_t *p_channel, uint8_t *p_data, uint8_t size);
static salt_ret_t salti_create_m4(salt_channel_t *p_channel);
static salt_ret_t salti_handle_m4(salt_channel_t *p_channel, uint8_t *p_data, uint8_t size);
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
    p_channel->err_code = SALT_ERR_NOT_SUPPORTED;
    return SALT_ERROR;
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
                    SALT_ERR_SESSION_NOT_INITIATED);
                proceed = 1;
                p_channel->state = SALT_WAIT_FOR_INCOMING_MSG_INIT;
                p_channel->next_state = SALT_M1_HANDLE;
            case SALT_WAIT_FOR_INCOMING_MSG_INIT:
                p_channel->read_channel.p_data = &p_channel->hdshk_buffer[129];
                p_channel->read_channel.max_size = p_channel->hdshk_buffer_size - 129;
                p_channel->state = SALT_WAIT_FOR_INCOMING_MSG_IO;
                proceed = 1;
            case SALT_WAIT_FOR_INCOMING_MSG_IO:
                ret_code = p_channel->read_impl(&p_channel->read_channel);              
                if (ret_code == SALT_SUCCESS)
                {
                    proceed = 1;
                    p_channel->state = p_channel->next_state;
                }
                break;
            case SALT_WAIT_FOR_OUTGOING_MSG_INIT:
                ret_code = p_channel->write_impl(&p_channel->write_channel);              
                if (ret_code == SALT_SUCCESS)
                {
                    proceed = 1;
                    p_channel->state = p_channel->next_state;
                }
                break;
            case SALT_M1_HANDLE:
                /*
                 * If M1 is valid, salti_handle_m1 will set the new state.
                 */
                proceed = (salti_handle_m1(p_channel,
                    p_channel->read_channel.p_data,
                    p_channel->read_channel.size) == SALT_SUCCESS);
                break;
            case SALT_M2_INIT:
                /*
                 * salti_create_m2 will point the write channel outgoing buffer to appropiate place
                 * in the handshake buffer. If the M2 message was successfully created the state will
                 * be set to SALT_M2_IO.
                 */
                proceed = (salti_create_m2(p_channel) == SALT_SUCCESS);
                break;
            case SALT_CALCULATE_ENC_KEY:
                /* Calculate shared key. */
                SALT_ASSERT(crypto_box_beforenm(p_channel->ek_common,
                    p_channel->peer_ek_pub,
                    p_channel->my_ek_sec) == 0, SALT_ERR_COMMON_KEY);
                proceed = 1;
                p_channel->state = SALT_M3_INIT;
                break;
            case SALT_M3_INIT:
                /*
                 * salti_create_m3 will point the write channel outgoing buffer to appropiate place
                 * in the handshake buffer. If the M2 message was successfully created the state will
                 * be set to SALT_M3_IO.
                 */
                proceed = (salti_create_m3(p_channel) == SALT_SUCCESS);
                break;
            case SALT_M4_INIT:
                proceed = 1;
                p_channel->read_channel.p_data = &p_channel->hdshk_buffer[145];
                memset(&p_channel->hdshk_buffer[129], 0, 16);
                p_channel->read_channel.max_size = p_channel->hdshk_buffer_size - 145;
                p_channel->state = SALT_WAIT_FOR_INCOMING_MSG_IO;
                p_channel->next_state = SALT_M4_HANDLE;
                break;
            case SALT_M4_HANDLE:
                /*
                 * If M1 is valid, salti_handle_m1 will set the new state.
                 */
                proceed = (salti_handle_m4(p_channel,
                    &p_channel->hdshk_buffer[129],
                    p_channel->read_channel.size + 16) == SALT_SUCCESS);
                break;
            case SALT_SESSION_ESTABLISHED:
                proceed = 0;
                ret_code = SALT_SUCCESS;
                break;
            default:
                SALT_ERROR(SALT_ERR_INVALID_STATE);
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
                    SALT_ERR_SESSION_NOT_INITIATED);
                proceed = 1;
                p_channel->state = SALT_M1_INIT;
                break;
            case SALT_M1_INIT:
                proceed = (salti_create_m1(p_channel) == SALT_SUCCESS);
                break;
            case SALT_WAIT_FOR_OUTGOING_MSG_INIT:
                ret_code = p_channel->write_impl(&p_channel->write_channel);              
                if (ret_code == SALT_SUCCESS)
                {
                    proceed = 1;
                    p_channel->state = p_channel->next_state;
                }
                break;
            case SALT_M2_INIT:
                proceed = 1;
                p_channel->state = SALT_WAIT_FOR_INCOMING_MSG_IO;
                p_channel->next_state = SALT_M2_HANDLE;
                break;
            case SALT_WAIT_FOR_INCOMING_MSG_IO:
                ret_code = p_channel->read_impl(&p_channel->read_channel);              
                if (ret_code == SALT_SUCCESS)
                {
                    proceed = 1;
                    p_channel->state = p_channel->next_state;
                }
                break;
            case SALT_M2_HANDLE:
                /*
                 * If M2 is valid, salti_handle_m2 will set the new state.
                 */
                proceed = (salti_handle_m2(p_channel,
                    p_channel->read_channel.p_data,
                    p_channel->read_channel.size) == SALT_SUCCESS);
                break;
            case SALT_CALCULATE_ENC_KEY:
                /* Calculate shared key. */
                SALT_ASSERT(crypto_box_beforenm(p_channel->ek_common,
                    p_channel->peer_ek_pub,
                    p_channel->my_ek_sec) == 0, SALT_ERR_COMMON_KEY);
                p_channel->state = SALT_M4_INIT;
                proceed = 1;
                break;
            case SALT_M4_INIT:
                /* Calculate M4 signature while M3 is beeing received. */
                p_channel->state = SALT_WAIT_FOR_INCOMING_MSG_IO;
                p_channel->next_state = SALT_M3_HANDLE;
                proceed = (salti_create_m3m4_signature(p_channel, &p_channel->hdshk_buffer[129+32+32+1]) == SALT_SUCCESS);
                break;   
            case SALT_M3_HANDLE:
                proceed = (salti_handle_m3(p_channel,
                    p_channel->read_channel.p_data,
                    p_channel->read_channel.size) == SALT_SUCCESS);
                break;
            case SALT_SESSION_ESTABLISHED:
                proceed = 0;
                ret_code = SALT_SUCCESS;
                break;
            default:
                SALT_ERROR(SALT_ERR_INVALID_STATE);
                break;
        }
    }

    return ret_code;
}

/*
 ** @brief Creates the M1 message to initiate a salt channel.
 *
 * Resume feature and virtual host mode is not supported at this time.
 */
static salt_ret_t salti_create_m1(salt_channel_t *p_channel)
{

    uint8_t offset = (p_channel->mode == SALT_SERVER_STREAM) ? SALT_LENGTH_SIZE : 0U;
    uint8_t *p_data = &p_channel->hdshk_buffer[32];

    p_data[0 + offset] = SALT_M1_HEADER_VALUE;
    p_data[1 + offset] = 'S';
    p_data[2 + offset] = '2';

    memcpy(&p_data[3 + offset], p_channel->my_ek_pub, crypto_box_PUBLICKEYBYTES);
    p_channel->write_channel.size = 35;

    memcpy(p_data, &p_channel->write_channel.size, offset);
    p_channel->write_channel.size += offset;

    p_channel->write_channel.p_data = p_data;
    p_channel->state = SALT_WAIT_FOR_OUTGOING_MSG_INIT;
    p_channel->next_state = SALT_M2_INIT;

    p_channel->read_channel.p_data = &p_channel->hdshk_buffer[129];
    p_channel->read_channel.max_size = p_channel->hdshk_buffer_size - 129;

    return SALT_SUCCESS;

}

static salt_ret_t salti_handle_m1(salt_channel_t *p_channel, uint8_t *p_data, uint8_t size)
{
    SALT_ASSERT(size >= 35,
        SALT_ERR_M1_TOO_SMALL);

    SALT_ASSERT(p_data[1] == 'S' && p_data[2] == '2',
        SALT_ERR_BAD_PROTOCOL);

    /*
     * p_data[2] and p_data[3] contains the Header1 bytes.
     *
     * If bit 0 in p_data[3] is set, the client is sending
     * a resume ticket.
     */

    if ((p_data[3] & SALT_M1_TICKED_INCLUDED_FLAG) > 0U)
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
        memcpy(p_channel->peer_ek_pub, &p_data[3], crypto_box_PUBLICKEYBYTES);

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

/*
#define SALT_M2_HEADER_VALUE                    (0x02U)
#define SALT_M2_ENC_KEY_INCLUDED_FLAG           (0x10U)
#define SALT_M2_RESUME_SUPPORTED_FLAG           (0x20U)
#define SALT_M2_NO_SUCH_SERVER_FLAG             (0x40U)
#define SALT_M2_BAD_TICKET_FLAG                 (0x80U)
*/
static salt_ret_t salti_create_m2(salt_channel_t *p_channel)
{
    /* Reserve 4 bytes for size if using stream mode */

    uint8_t *p_data = &p_channel->hdshk_buffer[129];

    uint8_t offset = (p_channel->mode == SALT_SERVER_STREAM) ? SALT_LENGTH_SIZE : 0U;
    p_data[0 + offset] = SALT_M2_HEADER_VALUE | SALT_M2_ENC_KEY_INCLUDED_FLAG;
    memcpy(&p_data[1 + offset], p_channel->my_ek_pub, crypto_box_PUBLICKEYBYTES);

    p_channel->write_channel.size = 33U;

    /* Write 4 byte size */
    memcpy(p_data, &p_channel->write_channel.size, offset);
    p_channel->write_channel.size += offset;
    

    p_channel->write_channel.p_data = p_data;
    p_channel->state = SALT_WAIT_FOR_OUTGOING_MSG_INIT;
    p_channel->next_state = SALT_CALCULATE_ENC_KEY;

    return SALT_SUCCESS;
}

static salt_ret_t salti_handle_m2(salt_channel_t *p_channel, uint8_t *p_data, uint8_t size)
{
    SALT_ASSERT(size >= 33,
        SALT_ERR_M2_TOO_SMALL);

    SALT_ASSERT(p_data[0] == (SALT_M2_HEADER_VALUE | SALT_M2_ENC_KEY_INCLUDED_FLAG),
        SALT_ERR_NOT_SUPPORTED);

    memcpy(p_channel->peer_ek_pub, &p_data[1], crypto_box_PUBLICKEYBYTES);
    
    p_channel->state = SALT_CALCULATE_ENC_KEY;
    p_channel->read_channel.p_data = &p_channel->hdshk_buffer[16];
    p_channel->read_channel.max_size = p_channel->hdshk_buffer_size - 16;

    return SALT_SUCCESS;
}

static salt_ret_t salti_create_m3m4_signature(salt_channel_t *p_channel, uint8_t *p_buf)
{
    unsigned long long sign_msg_size;
    memcpy(p_buf, p_channel->my_ek_pub, crypto_box_PUBLICKEYBYTES);
    memcpy(&p_buf[crypto_box_PUBLICKEYBYTES], p_channel->peer_ek_pub, crypto_box_PUBLICKEYBYTES);

    SALT_ASSERT(crypto_sign(
            p_buf,
            &sign_msg_size,
            p_buf,
            crypto_box_PUBLICKEYBYTES*2,
            p_channel->my_sk_sec) == 0, SALT_ERR_SIGNING);

    return SALT_SUCCESS;
}
/*
 * The M3 message in ecnrypted, therefore we need crypto_secretbox_ZEROBYTES bytes of
 * zero padded data in the beggining of the message before encryption.
 */
static salt_ret_t salti_create_m3(salt_channel_t *p_channel)
{

    uint8_t *p_data = &p_channel->hdshk_buffer[32];
    uint8_t *p_msg = &p_data[SALT_HEADER_SIZE+crypto_sign_PUBLICKEYBYTES];
    uint8_t offset = (p_channel->mode == SALT_SERVER_STREAM) ? SALT_LENGTH_SIZE : 0U;

    p_data[0] = SALT_M3_HEADER_VALUE | SALT_M3_SIG_KEY_INCLUDED_FLAG;
    memcpy(&p_data[SALT_HEADER_SIZE], p_channel->my_sk_pub, 32);

    SALT_ASSERT(salti_create_m3m4_signature(p_channel, p_msg) == SALT_SUCCESS, SALT_ERR_SIGNING);

    SALT_ASSERT(salti_encrypt(p_channel,
        p_channel->hdshk_buffer, 128U + SALT_HEADER_SIZE) == SALT_SUCCESS,
        SALT_ERR_ENCRYPTION);


    p_channel->write_channel.size = 128U + SALT_HEADER_SIZE - crypto_secretbox_BOXZEROBYTES;

    if (offset)
    {
        memcpy(&p_channel->hdshk_buffer[16 - offset], &p_channel->write_channel.size, offset);
        p_channel->write_channel.size += offset;
    }

    p_channel->write_channel.p_data = &p_channel->hdshk_buffer[16 - offset];

    p_channel->state = SALT_WAIT_FOR_OUTGOING_MSG_INIT;

    /* We expect next state to be SALT_M4_HANDLE */
    p_channel->next_state = SALT_M4_INIT;

    return SALT_SUCCESS;

}

static salt_ret_t salti_handle_m3m4(salt_channel_t *p_channel, uint8_t *p_data, uint8_t size)
{
    
}

static salt_ret_t salti_handle_m3(salt_channel_t *p_channel, uint8_t *p_data, uint8_t size)
{
    unsigned long long sign_msg_size;

    SALT_ASSERT(salti_decrypt(p_channel,
        p_channel->hdshk_buffer,
        size+crypto_secretbox_BOXZEROBYTES) == SALT_SUCCESS, SALT_ERR_DECRYPTION);

    p_data = &p_data[16];

    SALT_ASSERT(p_data[0] == (SALT_M3_HEADER_VALUE | SALT_M3_SIG_KEY_INCLUDED_FLAG),
        SALT_ERR_NOT_SUPPORTED);

    memcpy(&p_data[97], p_channel->peer_ek_pub, 32);
    memcpy(&p_data[97+32], p_channel->my_ek_pub, 32);

    uint8_t tmp_signature[128];

    SALT_ASSERT(crypto_sign_open(
      tmp_signature,
      &sign_msg_size,
      &p_data[33],
      crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES*2,
      &p_data[1]) == 0, SALT_ERR_BAD_SIGNATURE);

    memcpy(p_channel->peer_sk_pub, &p_data[1], crypto_sign_PUBLICKEYBYTES);

    return salti_create_m4(p_channel);
}

static salt_ret_t salti_create_m4(salt_channel_t *p_channel)
{

    uint8_t *p_data = &p_channel->hdshk_buffer[129+32];
    uint8_t offset = (p_channel->mode == SALT_SERVER_STREAM) ? SALT_LENGTH_SIZE : 0U;

    p_data[0] = SALT_M4_HEADER_VALUE;

    /* Signature is already calculated in &p_channel->hdshk_buffer[129+32] */
    memcpy(&p_data[SALT_HEADER_SIZE], p_channel->my_sk_pub, 32);
    memset(&p_channel->hdshk_buffer[129], 0, 32);

    SALT_ASSERT(salti_encrypt(p_channel,
        &p_channel->hdshk_buffer[129], 128U + SALT_HEADER_SIZE) == SALT_SUCCESS,
        SALT_ERR_ENCRYPTION);


    p_channel->write_channel.size = 128U + SALT_HEADER_SIZE - crypto_secretbox_BOXZEROBYTES;

    if (offset)
    {
        memcpy(&p_channel->hdshk_buffer[129+12], &p_channel->write_channel.size, SALT_LENGTH_SIZE);
        p_channel->write_channel.size += offset;
    }

    p_channel->write_channel.p_data = &p_channel->hdshk_buffer[129 + 16 - offset];

    /* We expect next state to be SALT_M4_HANDLE */
    p_channel->state = SALT_WAIT_FOR_OUTGOING_MSG_INIT;
    p_channel->next_state = SALT_SESSION_ESTABLISHED;

    return SALT_SUCCESS;

}

static salt_ret_t salti_handle_m4(salt_channel_t *p_channel, uint8_t *p_data, uint8_t size)
{
    unsigned long long sign_msg_size;
    SALT_ASSERT(salti_decrypt(p_channel, p_data, size) == SALT_SUCCESS,
        SALT_ERR_ENCRYPTION);

    p_data += 32;

    memcpy(&p_data[97], p_channel->peer_ek_pub, 32);
    memcpy(&p_data[97+32], p_channel->my_ek_pub, 32);

    uint8_t tmp_signature[128];

    SALT_ASSERT(crypto_sign_open(
      tmp_signature,
      &sign_msg_size,
      &p_data[33],
      crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES*2,
      &p_data[1]) == 0, SALT_ERR_BAD_SIGNATURE);

    memcpy(p_channel->peer_sk_pub, &p_data[1], 32);

    p_channel->state = SALT_SESSION_ESTABLISHED;

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
