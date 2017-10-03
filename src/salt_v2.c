/**
 * @file salt_v2.c
 *
 * Salt channel version 2 implementation.
 *
 * See v2notes.txt for implementation details.
 *
 * TODO: Refer to v2notes.txt for tricks when placing messages in hanshake buffer.
 *
 */

/*======= Includes ============================================================*/
#include "salt_v2.h"

/* C Library includes */
#include <string.h> /* memcpy, memset */

/*======= Local Macro Definitions =============================================*/
#ifdef SALT_DEBUG
#include <stdio.h>
#include "salt_util.h"
#define SALT_VERIFY(x, error_code)                                              \
        do {                                                                    \
            if (!(x)) {                                                         \
                p_channel->err_code = error_code;                               \
                printf(                                                         \
                    "Runtime error (%s, %s): %s at %s:%d, %s.\r\n",             \
                    #error_code, salt_mode2str(p_channel->mode), #x,                 \
                    __FILE__, __LINE__, __func__);                              \
                return SALT_ERROR;                                              \
            }                                                                   \
        } while (0)
#else
#define SALT_VERIFY(x, error_code)                                              \
        do {                                                                    \
            if (!(x)) {                                                         \
                p_channel->err_code = error_code;                               \
                return SALT_ERROR;                                              \
            }                                                                   \
        } while (0)
#endif

#define SALT_VERIFY_NOT_NULL(x)                                                 \
    SALT_VERIFY(((x) != NULL), SALT_ERR_NULL_PTR)

#define SALT_VERIFY_VALID_CHANNEL(x) if ((x) == NULL) return SALT_ERROR
#define SALT_TRIGGER_ERROR                      (0x00U)
#define SALT_ERROR(err_code) SALT_VERIFY(SALT_TRIGGER_ERROR, err_code)
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
#define SALT_APP_MSG                            (3U)
#define SALT_APP_MULTI_MSG                      (7U)
#define SALT_LENGTH_SIZE                        (4U)
#define SALT_HEADER_SIZE                        (2U)
#define SALT_TIME_SIZE                          (4U)
#define SALT_TICKET_LENGTH_SIZE                 (1U)
#define SALT_MAX_TICKET_SIZE                    (127U) /* Not supported yet */
#define SALT_A1_HEADER                          (8U + 16U)

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

/* Encrypted message header */
#define SALT_ENCRYPTED_MSG_HEADER_VALUE         (0x06U)

/* Application package message header */
#define SALT_APP_PKG_MSG_HEADER_VALUE           (0x05U)
#define SALT_MULTI_APP_PKG_MSG_HEADER_VALUE     (0x0BU)

#define SALT_PUB_ENC_OFFSET                     (0U)
#define SALT_SEC_ENC_OFFSET                     (32U)
#define SALT_SIG_PREFIX_OFFSET                  (64U)
#define SALT_SIG_PREFIX_SIZE                    (8U)
#define SALT_M1_HASH_OFFSET                     (72U)
#define SALT_M2_HASH_OFFSET                     (136U)


/*======= Type Definitions ====================================================*/

/*======= Local variable declarations =========================================*/

/* Signature 1 prefix, ASCII "SC-SIG01" */
static uint8_t sig1prefix[8] = { 0x53, 0x43, 0x2d, 0x53, 0x49, 0x47, 0x30, 0x31 };
/* Signature 2 prefix, ASCII "SC-SIG02" */
static uint8_t sig2prefix[8] = { 0x53, 0x43, 0x2d, 0x53, 0x49, 0x47, 0x30, 0x32 };

/*======= Local function prototypes ===========================================*/
static salt_ret_t salti_read(salt_channel_t *p_channel,
                             uint8_t *p_data,
                             uint32_t *size,
                             uint8_t msg_type);

static salt_ret_t salti_write(salt_channel_t *p_channel,
                              uint8_t *p_data,
                              uint32_t size,
                              uint8_t encrypted);

static salt_ret_t salti_handshake_server(salt_channel_t *p_channel);

static salt_ret_t salti_handshake_client(salt_channel_t *p_channel);

static void salti_create_m1(salt_channel_t *p_channel,
                            uint8_t *p_data,
                            uint32_t *size,
                            uint8_t *p_hash);

static salt_ret_t salti_handle_a1_or_m1(salt_channel_t *p_channel,
                                        uint8_t *p_data,
                                        uint32_t size);

static salt_ret_t salti_create_a2(salt_channel_t *p_channel,
                                  uint8_t *p_data,
                                  uint32_t *size);

static salt_ret_t salti_handle_m1(salt_channel_t *p_channel,
                                  uint8_t *p_data,
                                  uint32_t size,
                                  uint8_t *p_hash);

static salt_ret_t salti_create_m2(salt_channel_t *p_channel,
                                  uint8_t *p_data,
                                  uint32_t *size,
                                  uint8_t *p_hash);

static salt_ret_t salti_handle_m2(salt_channel_t *p_channel,
                                  uint8_t *p_data,
                                  uint32_t size,
                                  uint8_t *p_hash);

static salt_ret_t salti_create_m3m4(salt_channel_t *p_channel,
                                    uint8_t *p_data,
                                    uint32_t *size);

static salt_ret_t salti_handle_m3m4(salt_channel_t *p_channel,
                                    uint8_t *p_data,
                                    uint32_t size,
                                    uint8_t header);

static salt_ret_t salti_encrypt(salt_channel_t *p_channel,
                                uint8_t *p_data,
                                uint32_t size);

static salt_ret_t salti_decrypt(salt_channel_t *p_channel,
                                uint8_t *p_data,
                                uint32_t size);

static void salti_increase_nonce(uint8_t *p_nonce, uint8_t increment);

static void salti_u16_to_bytes(uint8_t *dest, uint16_t size); // TODO: Consider renaming to u32_to_bytes
static uint32_t salti_bytes_to_u16(uint8_t *src); // TODO: Consider renaming to bytes_to_u32
static void salti_u32_to_bytes(uint8_t *dest, uint32_t size); // TODO: Consider renaming to u32_to_bytes
static uint32_t salti_bytes_to_u32(uint8_t *src); // TODO: Consider renaming to bytes_to_u32

static void salti_get_time(salt_channel_t *p_channel, uint32_t *p_time);

/*======= Global function implementations =====================================*/

salt_ret_t salt_create(
    salt_channel_t *p_channel,
    salt_mode_t mode,
    salt_io_impl write_impl,
    salt_io_impl read_impl,
    salt_time_impl time_impl)
{

    SALT_VERIFY_VALID_CHANNEL(p_channel);

    SALT_VERIFY(mode <= SALT_CLIENT,
        SALT_ERR_NOT_SUPPORTED);

    SALT_VERIFY_NOT_NULL(write_impl);
    SALT_VERIFY_NOT_NULL(read_impl);

    p_channel->write_impl = write_impl;
    p_channel->read_impl = read_impl;
    p_channel->time_impl = time_impl;
    p_channel->mode = mode;
    p_channel->state = SALT_CREATED;
    p_channel->err_code = SALT_ERR_NONE;
    p_channel->my_sk_pub = &p_channel->my_sk_sec[32];
    p_channel->p_protocols = NULL;

    return SALT_SUCCESS;
}

salt_ret_t salt_set_context(
    salt_channel_t *p_channel,
    void *p_write_context,
    void *p_read_context)
{
    SALT_VERIFY_VALID_CHANNEL(p_channel);
    p_channel->write_channel.p_context = p_write_context;
    p_channel->read_channel.p_context = p_read_context;

    return SALT_SUCCESS;
}

salt_ret_t salt_a1a2(salt_channel_t *p_channel,
                     uint8_t *p_buffer,
                     uint32_t size,
                     salt_protocols_t *p_protocols)
{

    salt_ret_t ret_code = SALT_PENDING;
    uint8_t proceed = 1;

    SALT_VERIFY_VALID_CHANNEL(p_channel);
    SALT_VERIFY_NOT_NULL(p_buffer);

    SALT_VERIFY(p_channel->state >= SALT_CREATED && p_channel->state < SALT_M1_IO,
                SALT_ERR_INVALID_STATE);

    while (proceed) {
        proceed = 0;
        switch (p_channel->state) {
            case SALT_CREATED:
            case SALT_SIGNATURE_SET:
            case SALT_SESSION_INITIATED:
                p_buffer[SALT_LENGTH_SIZE] = SALT_A1_HEADER;
                p_buffer[SALT_LENGTH_SIZE + 1] = 0;
                salti_u32_to_bytes(p_buffer, 2);
                p_channel->state = SALT_A1_IO;
                proceed = 1;
                break;
            case SALT_A1_IO:
                ret_code = salti_write(p_channel, p_buffer, 6, SALT_CLEAR);
                if (SALT_SUCCESS == ret_code) {
                    proceed = 1;
                    p_channel->state = SALT_A2_IO;
                }
                break;
            case SALT_A2_IO:
                ret_code = salti_read(p_channel, p_buffer, &size, SALT_CLEAR);
                if (SALT_SUCCESS == ret_code) {
                    p_channel->state = SALT_SESSION_INITIATED;
                    /*
                     * Each protocol supported should have a size of 10 bytes. The format is
                     *  { SC2------- , Protocol1- , SC3 , Protocol2- , ... }
                     *  Hence, the size must be n * 20 since the salt channel version is always
                     *  followed by another protocol.
                     */
                    SALT_VERIFY(size % (sizeof(salt_protocol_t)*2) == 0, SALT_ERR_BAD_PROTOCOL);
                    p_protocols->count = size / sizeof(salt_protocol_t);
                    p_protocols->p_protocols = (salt_protocol_t *) p_buffer;
                }
                break;
            default:
                return SALT_ERROR;
        } 
    }

    return ret_code;
}

salt_ret_t salt_set_signature(salt_channel_t *p_channel,
                              const uint8_t *p_signature)
{

    SALT_VERIFY_VALID_CHANNEL(p_channel);
    SALT_VERIFY_NOT_NULL(p_signature);

    memcpy(p_channel->my_sk_sec, p_signature, crypto_sign_SECRETKEYBYTES);
    p_channel->state = SALT_SIGNATURE_SET;

    return SALT_SUCCESS;

}


salt_ret_t salt_create_signature(salt_channel_t *p_channel)
{
    SALT_VERIFY_VALID_CHANNEL(p_channel);
    crypto_sign_keypair(p_channel->my_sk_pub, p_channel->my_sk_sec);
    p_channel->state = SALT_SIGNATURE_SET;
    return SALT_SUCCESS;
}

salt_ret_t salt_init_session(salt_channel_t *p_channel,
                             uint8_t *hdshk_buffer,
                             uint32_t hdshk_buffer_size)
{
    SALT_VERIFY_VALID_CHANNEL(p_channel);
    SALT_VERIFY(p_channel->state >= SALT_SIGNATURE_SET,
                SALT_ERR_NO_SIGNATURE);

    SALT_VERIFY_NOT_NULL(hdshk_buffer);
    SALT_VERIFY(hdshk_buffer_size >= SALT_HNDSHK_BUFFER_SIZE,
                SALT_ERR_BUFF_TO_SMALL);

    /* Save handshake buffer */
    p_channel->hdshk_buffer = hdshk_buffer;
    p_channel->hdshk_buffer_size = hdshk_buffer_size;

    /* Clear previous history */
    MEMSET_ZERO(p_channel->ek_common);
    MEMSET_ZERO(p_channel->peer_sk_pub);
    MEMSET_ZERO(p_channel->write_nonce);
    MEMSET_ZERO(p_channel->read_nonce);

    /* Initiate write and read nonce */
    if (p_channel->mode == SALT_SERVER) {
        p_channel->write_nonce[0]  = SALT_WRITE_NONCE_INIT_SERVER;
        p_channel->read_nonce[0] = SALT_READ_NONCE_INIT_SERVER;
        p_channel->write_nonce_incr = SALT_WRITE_NONCE_INCR_SERVER;
        p_channel->read_nonce_incr = SALT_READ_NONCE_INCR_SERVER;
    }
    else {
        p_channel->write_nonce[0]  = SALT_WRITE_NONCE_INIT_CLIENT;
        p_channel->read_nonce[0] = SALT_READ_NONCE_INIT_CLIENT;
        p_channel->write_nonce_incr = SALT_WRITE_NONCE_INCR_CLIENT;
        p_channel->read_nonce_incr = SALT_READ_NONCE_INCR_CLIENT;
    }

    p_channel->write_channel.state = SALT_IO_READY;
    p_channel->read_channel.state = SALT_IO_READY;

    /* 
     * Create ephemeral keypair used for only this session.
     * hdshk_buffer[0:31]:  Public key
     * hdshk_buffer[32:63]: Private key
     * The ephemeral keypair is kept where the signature later will be
     * until the common key is calculated.
     */
    crypto_box_keypair(hdshk_buffer, &hdshk_buffer[32]);

    p_channel->err_code = SALT_ERR_NONE;
    p_channel->state = SALT_SESSION_INITIATED;

    return SALT_SUCCESS;

}

salt_ret_t salt_handshake(salt_channel_t *p_channel)
{
    SALT_VERIFY_VALID_CHANNEL(p_channel);

    if (p_channel->mode == SALT_SERVER) {
        return salti_handshake_server(p_channel);
    }
    else {
        return salti_handshake_client(p_channel);
    }
}

salt_ret_t salt_request_ticket(salt_channel_t *p_channel,
                               uint8_t *p_ticket,
                               uint32_t *p_ticket_size,
                               uint32_t max_size)
{
    SALT_VERIFY_VALID_CHANNEL(p_channel);
    (void) p_ticket;
    (void) p_ticket_size;
    (void) max_size;
    p_channel->err_code = SALT_ERR_NOT_SUPPORTED;
    return SALT_ERROR;
}

salt_ret_t salt_resume(salt_channel_t *p_channel,
                       uint8_t *p_host,
                       uint8_t *p_ticket,
                       uint32_t ticket_size,
                       uint8_t *session_key)
{
    SALT_VERIFY_VALID_CHANNEL(p_channel);
    (void) p_host;
    (void) p_ticket;
    (void) ticket_size;
    (void) session_key;
    p_channel->err_code = SALT_ERR_NOT_SUPPORTED;
    return SALT_ERROR;
}

salt_ret_t salt_read_begin(salt_channel_t *p_channel,
                           uint8_t *p_buffer,
                           uint32_t buffer_size,
                           salt_msg_t *p_msg)
{
    salt_ret_t ret;

    SALT_VERIFY_VALID_CHANNEL(p_channel);
    SALT_VERIFY(SALT_SESSION_ESTABLISHED == p_channel->state,
                SALT_ERR_INVALID_STATE);
    SALT_VERIFY(buffer_size >= SALT_OVERHEAD_SIZE, SALT_ERR_BUFF_TO_SMALL);

    p_msg->p_buffer = p_buffer;
    p_msg->buffer_used = buffer_size;
    p_msg->buffer_size = buffer_size;

    ret = salti_read(p_channel, p_msg->p_buffer, &p_msg->buffer_used, SALT_ENCRYPTED);



    if (ret == SALT_SUCCESS) {

        if (p_msg->p_buffer[32] == SALT_APP_PKG_MSG_HEADER_VALUE) {

            SALT_VERIFY(p_msg->buffer_used >= 6U, SALT_ERR_BAD_PROTOCOL);

            /*
             * Single message:
             * p_msg->p_buffer[0:31] = 0x00
             * p_msg->p_buffer[32] = header
             * p_msg->p_buffer[33] = 0x00
             * p_msg->p_buffer[34:37] = time[4]
             * p_msg->p_buffer[38:p_msg->buffer_used - 6U] = message[p_msg->buffer_used - 6U]
             * 
             * { zeroPadding[32] , header[2] , time[4] , msg[n] }
             *                   |<---  p_msg->buffer_used  --->|
             * 
             */
            p_msg->messages_left = 0;
            p_msg->p_message = &p_msg->p_buffer[SALT_OVERHEAD_SIZE];
            p_msg->message_size = p_msg->buffer_used - 6U;

        } else if (p_msg->p_buffer[32] == SALT_MULTI_APP_PKG_MSG_HEADER_VALUE) {

            SALT_VERIFY(p_msg->buffer_used >= 8U, SALT_ERR_BAD_PROTOCOL);

            /*
             * Single message:
             * p_msg->p_buffer[0:31] = 0x00
             * p_msg->p_buffer[32] = header
             * p_msg->p_buffer[33] = 0x00
             * p_msg->p_buffer[34:37] = time[4]
             * p_msg->p_buffer[38:39] = count[2]
             * p_msg->p_buffer[40:41] = size1[2]
             * p_msg->p_buffer[42:42+size1] = msg1[size1]
             * 
             * { zeroPadding[32] , header[2] , time[4] , count[2] , size1[2] , msg1[n] , ... }
             *                   |<---                p_msg->buffer_used                 --->|
             *                                                    |<-- p_msg->buffer_size -->|
             */

            p_msg->messages_left = salti_bytes_to_u16(&p_msg->p_buffer[38]);
            p_msg->buffer_size = p_msg->buffer_used - 6U;
            p_msg->buffer_used = 0;
            p_msg->p_message = &p_msg->p_buffer[40];

            uint32_t total_size = p_msg->buffer_size;
            uint16_t messages_left = p_msg->messages_left;
            uint32_t buffer_used = 0;

            while (messages_left > 0) {
                uint16_t message_size = salti_bytes_to_u16(p_msg->p_message);
                p_msg->p_message += 2 + message_size;
                buffer_used += 2 + message_size;
                if (buffer_used < total_size) {
                    messages_left--;
                } else {
                    SALT_ERROR(SALT_ERR_BAD_PROTOCOL);
                }
            }

            p_msg->message_size = salti_bytes_to_u16(&p_msg->p_buffer[40]);
            p_msg->p_message = &p_msg->p_buffer[42];
            p_msg->messages_left--;
            p_msg->buffer_used = 2 + p_msg->message_size;

        } else {
            SALT_ERROR(SALT_ERR_BAD_PROTOCOL);
        }

    }

    return ret;
}

salt_ret_t salt_read_next(salt_msg_t *p_msg)
{

    if (p_msg->messages_left == 0) {
        return SALT_ERROR;
    }

    p_msg->p_message += p_msg->message_size;
    p_msg->message_size = salti_bytes_to_u16(p_msg->p_message);
    p_msg->p_message += 2;
    p_msg->buffer_used = 2 + p_msg->message_size;

    if (p_msg->buffer_used + 2 + p_msg->message_size > p_msg->buffer_size) {
        return SALT_ERROR;
    }

    p_msg->buffer_used += 2 + p_msg->message_size;

    p_msg->messages_left--;


    return SALT_SUCCESS;
}

salt_ret_t salt_write_begin(uint8_t *p_buffer,
                            uint32_t size,
                            salt_msg_t *p_msg)
{
    if (size < SALT_OVERHEAD_SIZE + 4U) {
        return SALT_ERROR;
    }

    /* First SALT_OVERHEAD_SIZE is overhead for encryption. The message
     * follows as:
     * { count[2] , size_1[2] , msg_1[n] , ... }
     * I.e.:
     * { overHead[SALT_OVERHEAD_SIZE] , count[2] , size_1[2] , msg_1[n] , ... }
     * 
     * Therefore the first message will be put in SALT_OVERHEAD_SIZE + 2.
     * 
     */

    p_msg->p_buffer = p_buffer;
    p_msg->buffer_size = size;
    p_msg->p_message = &p_buffer[SALT_OVERHEAD_SIZE] + 2U;
    p_msg->buffer_used = SALT_OVERHEAD_SIZE + 2U;
    p_msg->messages_left = 0;

    return SALT_SUCCESS;
}

salt_ret_t salt_write_next(salt_msg_t *p_msg, uint8_t *p_buffer, uint16_t size)
{

    /* We need size + 2 bytes available. */
    if ((p_msg->buffer_size - p_msg->buffer_used) < (size + 2)) {
        return SALT_ERROR;
    }

    salti_u16_to_bytes(p_msg->p_message, size);
    p_msg->p_message += 2;
    p_msg->buffer_used += 2;

    memcpy(p_msg->p_message, p_buffer, size);
    p_msg->p_message += size;
    p_msg->buffer_used += size;
    p_msg->messages_left++;

    return SALT_SUCCESS;
}

salt_ret_t salt_write_execute(salt_channel_t *p_channel, salt_msg_t *p_msg)
{
    SALT_VERIFY_VALID_CHANNEL(p_channel);
    SALT_VERIFY(SALT_SESSION_ESTABLISHED == p_channel->state,
                SALT_ERR_INVALID_STATE);
    SALT_VERIFY_NOT_NULL(p_msg);

    /*
     * If there is only one message, we send it as a one package message.
     * The buffer now looks like:
     * { overHead[SALT_OVERHEAD_SIZE] , count[2], size1[2], msg1[n] }
     * 
     * When sending a one application message we use the count[2] and size1[2]
     * as parts of the overhead bytes.
     * 
     */
    if (p_msg->messages_left == 1) {
        return salti_write(p_channel,
                           &p_msg->p_buffer[4],
                           p_msg->buffer_used - 4,
                           SALT_APP_PKG_MSG_HEADER_VALUE);
    }

    salti_u16_to_bytes(&p_msg->p_buffer[SALT_OVERHEAD_SIZE], p_msg->messages_left);

    return salti_write(p_channel,
                       p_msg->p_buffer,
                       p_msg->buffer_used,
                       SALT_MULTI_APP_PKG_MSG_HEADER_VALUE);
}


/*======= Local function implementations ======================================*/

/*
 * Internal read process state machine.
 *      1. Read the four bytes size.
 *      2. Read the message with the specific size that was read.
 *      3. Decrypt if necessary.
 *
 * If reading encrypted data, the first crypto_secretbox_BOXZEROBYTES of the
 * clear text data will be 0x00.
 * The maximum length of the message to be read is put in *size.
 * The actual length of the read message is returned in *size.
 *
 */
static salt_ret_t salti_read(salt_channel_t *p_channel,
                             uint8_t *p_data,
                             uint32_t *size,
                             uint8_t msg_type)
{
    /* Maximum size is stored in *size */
    salt_ret_t ret_code = SALT_ERROR;
    salt_io_channel_t *channel = &p_channel->read_channel;

    switch (channel->state) {
    case SALT_IO_READY:

        channel->p_data = p_data;
        channel->max_size = *size;
        channel->size_expected = SALT_LENGTH_SIZE;
        channel->size = 0;
        channel->state = SALT_IO_SIZE;
    /* Intentional fall-through */
    case SALT_IO_SIZE:
        ret_code = p_channel->read_impl(&p_channel->read_channel);

        if (SALT_SUCCESS != ret_code) {
            /* Pending or error. */
            break;
        }

        channel->size_expected = salti_bytes_to_u32(p_data);

        if (msg_type > SALT_CLEAR) {
            /*
             * If we read encrypted, we must ensure that the first crypto_secretbox_BOXZEROBYTES is 0x00.
             * These bytes are not sent by the other side.
             */
            channel->p_data += crypto_secretbox_BOXZEROBYTES - 0x02U;
            channel->max_size -= (crypto_secretbox_BOXZEROBYTES - 0x02U);
        }

        if (channel->size_expected > channel->max_size) {
            p_channel->err_code = SALT_ERR_BUFF_TO_SMALL;
            ret_code = SALT_ERROR;
            *size = 0;
            break;
        }

        channel->state = SALT_IO_PENDING;
        channel->size = 0;
    /* Intentional fall-through */
    case SALT_IO_PENDING:

        ret_code = p_channel->read_impl(&p_channel->read_channel);

        if (SALT_SUCCESS == ret_code) {
            /* The actual size received is put in channel->size. */
            if (msg_type > SALT_CLEAR) {

                /*
                 * Msg structure:
                 *      2   Header
                 *          { 0x06, 0x00 }
                 *
                 *      N   Encrypted data
                 *
                 *      Decrypt from channel->p_data
                 */

                SALT_VERIFY(SALT_ENCRYPTED_MSG_HEADER_VALUE == (channel->p_data[0] & 0x0FU),
                            SALT_ERR_BAD_PROTOCOL);

                channel->p_data -= (crypto_secretbox_BOXZEROBYTES - 0x02U);
                channel->size += (crypto_secretbox_BOXZEROBYTES - 0x02U);
                memset(channel->p_data, 0x00U, crypto_secretbox_BOXZEROBYTES);

                ret_code = salti_decrypt(p_channel,
                                         channel->p_data,
                                         channel->size);

                channel->size -= crypto_secretbox_ZEROBYTES;

                SALT_VERIFY(SALT_SUCCESS == ret_code, p_channel->err_code);

            }

            (*size) = channel->size;

            channel->state = SALT_IO_READY;
        }
        break;
    default:
        SALT_ERROR(SALT_ERR_INVALID_STATE);
    }

    if (SALT_PENDING != ret_code) {
        /*
         * TODO: What do actually do when there is any error?
         * Can we continue if there was I/O error?
         * If decryption failed, have we lost any message and need to
         * reinitate the session?
         */
        channel->state = SALT_IO_READY;
    }

    return ret_code;
}

static salt_ret_t salti_write(salt_channel_t *p_channel,
                              uint8_t *p_data,
                              uint32_t size,
                              uint8_t msg_type)
{

    salt_ret_t ret_code = SALT_ERROR;
    salt_io_channel_t *channel = &p_channel->write_channel;

    switch (channel->state) {
    case SALT_IO_READY:
        channel->p_data = p_data;
        channel->size = 0;
        channel->size_expected = size;


        if (msg_type > SALT_CLEAR) {
            /*
             * Crypto library requires the first crypto_secretbox_ZEROBYTES to be
             * 0x00 before encryption.
             */
            memset(channel->p_data, 0x00U, crypto_secretbox_ZEROBYTES);

            p_data[32] = msg_type;
            p_data[33] = 0x00U;
            salti_get_time(p_channel, (uint32_t *) &p_data[34]);

            SALT_VERIFY(salti_encrypt(p_channel,
                                      channel->p_data,
                                      channel->size_expected) == SALT_SUCCESS, p_channel->err_code);
            /*
             * After encryption, the first crypto_secretbox_BOXZEROBYTES will be 0x00.
             * This is know by the other side, i.e, we dont need to send this.
             */

            channel->p_data += crypto_secretbox_BOXZEROBYTES - 0x02U;
            channel->p_data[0] = SALT_ENCRYPTED_MSG_HEADER_VALUE;

            channel->size_expected -= (crypto_secretbox_BOXZEROBYTES - 0x02U);
            channel->p_data -= SALT_LENGTH_SIZE;

            salti_u32_to_bytes(channel->p_data, channel->size_expected);
            channel->size_expected += SALT_LENGTH_SIZE;

        }
        channel->state = SALT_IO_PENDING;
    /* Intentional fall-through */
    case SALT_IO_PENDING:
        ret_code = p_channel->write_impl(&p_channel->write_channel);
        if (SALT_SUCCESS == ret_code) {
            channel->state = SALT_IO_READY;
        }
        break;
    default:
        SALT_ERROR(SALT_ERR_INVALID_STATE);
    }

    if (SALT_PENDING != ret_code) {
        p_channel->read_channel.state = SALT_IO_READY;
    }

    return ret_code;

}

static salt_ret_t salti_handshake_server(salt_channel_t *p_channel)
{

    uint32_t size = 0;
    salt_ret_t ret_code = SALT_ERROR;
    uint8_t proceed = 1;

    while (proceed) {
        proceed = 0;
        switch (p_channel->state) {
            case SALT_SESSION_INITIATED:
                p_channel->state = SALT_M1_IO;
                proceed = 1;
                break;
            case SALT_M1_IO:
                size = 204; /* Maximum size of M1 */
                ret_code = salti_read(p_channel,
                                      &p_channel->hdshk_buffer[SALT_M1_HASH_OFFSET],
                                      &size, SALT_CLEAR);
                if (SALT_SUCCESS == ret_code) {
                    ret_code = salti_handle_a1_or_m1(p_channel,
                                                     &p_channel->hdshk_buffer[SALT_M1_HASH_OFFSET],
                                                     size);
                    proceed = (SALT_SUCCESS == ret_code);
                }
                break;
            case SALT_A1_HANDLE:
                ret_code = salti_create_a2(p_channel, &p_channel->hdshk_buffer[64], &size);
                if (SALT_SUCCESS == ret_code) {
                    p_channel->state = SALT_A2_IO;
                    proceed = 1;
                }
                break;
            case SALT_A2_IO:
                ret_code = salti_write(p_channel,
                                       &p_channel->hdshk_buffer[64],
                                       size, SALT_CLEAR);
                if (SALT_SUCCESS == ret_code) {
                    ret_code = SALT_PENDING;
                    p_channel->state = SALT_SESSION_INITIATED;
                }
                break;
            case SALT_M1_HANDLE:
                ret_code = salti_handle_m1(p_channel,
                                           &p_channel->hdshk_buffer[SALT_M1_HASH_OFFSET],
                                           size,
                                           &p_channel->hdshk_buffer[SALT_M1_HASH_OFFSET]);

                SALT_VERIFY(SALT_SUCCESS == ret_code, p_channel->err_code);
                p_channel->state = SALT_M2_INIT;
                proceed = 1;
                break;
            case SALT_M2_INIT:
                ret_code = salti_create_m2(p_channel,
                                           &p_channel->hdshk_buffer[200],
                                           &size,
                                           &p_channel->hdshk_buffer[SALT_M2_HASH_OFFSET]);

                SALT_VERIFY(SALT_ERROR != ret_code, p_channel->err_code);

                ret_code = salti_write(p_channel,
                                       &p_channel->hdshk_buffer[200],
                                       size, SALT_CLEAR);

                SALT_VERIFY(SALT_ERROR != ret_code, SALT_ERR_IO_WRITE);

                if (SALT_ERROR != ret_code) {
                    (void) crypto_box_beforenm(p_channel->ek_common,
                                                  &p_channel->hdshk_buffer[242],
                                                  &p_channel->hdshk_buffer[SALT_SEC_ENC_OFFSET]);
                    p_channel->state = SALT_M2_IO;

                }

                if (ret_code == SALT_SUCCESS) {
                    proceed = 1;
                    p_channel->state = SALT_M3_INIT;
                }

                /*
                 * If the client included an invalid public signature key, the
                 * SALT_ERR_NO_SUCH_SERVER error code will be set in p_channel->err_code.
                 * If this is the case, we will stop imidiately after sending M2 and do not want
                 * to calculate the symmetric ephemeral encryption key.
                 */

                break;
            case SALT_M2_IO:
                ret_code = salti_write(p_channel,
                                       &p_channel->hdshk_buffer[200],
                                       size, SALT_CLEAR);
                if (SALT_SUCCESS == ret_code) {
                        p_channel->state = SALT_M3_INIT;
                        proceed = 1;
                }
                break;
            case SALT_M3_INIT:
                ret_code = salti_create_m3m4(p_channel,
                                             &p_channel->hdshk_buffer[200 + 32],
                                             &size);

                if (SALT_SUCCESS == ret_code) {
                    p_channel->state = SALT_M3_IO;
                    proceed = 1;   
                }
                break;
            case SALT_M3_IO:
                ret_code = salti_write(p_channel,
                                       &p_channel->hdshk_buffer[200],
                                       size + 32, SALT_M3_HEADER_VALUE);
                if (SALT_SUCCESS == ret_code) {
                    p_channel->state = SALT_M4_IO;
                    proceed = 1;
                }
                break;
            case SALT_M4_IO:
                size = 120 + SALT_OVERHEAD_SIZE; /* Maximum size of M4 */
                ret_code = salti_read(p_channel,
                                      &p_channel->hdshk_buffer[200],
                                      &size, SALT_ENCRYPTED);
                if (ret_code == SALT_SUCCESS) {
                    p_channel->state = SALT_M4_HANDLE;
                    proceed = 1;
                }
                break;
            case SALT_M4_HANDLE:
                ret_code = salti_handle_m3m4(p_channel,
                                             &p_channel->hdshk_buffer[200 + 32],
                                             size, SALT_M4_HEADER_VALUE);
                if (SALT_SUCCESS == ret_code) {
                    p_channel->state = SALT_SESSION_ESTABLISHED;
                }
                memset(p_channel->hdshk_buffer, 0x00, p_channel->hdshk_buffer_size);
                break;
            default:
                SALT_ERROR(SALT_ERR_INVALID_STATE);
            }
    }

    return ret_code;
}

static salt_ret_t salti_handshake_client(salt_channel_t *p_channel)
{
    uint32_t size = 0;
    salt_ret_t ret_code = SALT_ERROR;
    uint8_t proceed = 1;
    while (proceed) {
        proceed = 0;
        switch (p_channel->state) {
            case SALT_SESSION_INITIATED:
                /*
                 * Create the M1 message at hdshk_buffer[128] and save the hash at
                 * p_channel->hdshk_buffer[64] (64 bytes). We save the hash so we later
                 * can verify that the message M1 was not modified by a MITM. No
                 * support for virtual server yet, so the size of M1 is always 42
                 * bytes.
                 */
                salti_create_m1(p_channel,
                                 &p_channel->hdshk_buffer[SALT_M2_HASH_OFFSET],
                                 &size,
                                 &p_channel->hdshk_buffer[SALT_M1_HASH_OFFSET]);

                p_channel->state = SALT_M1_IO;
                proceed = 1;
                break;
            case SALT_M1_IO:

                ret_code = salti_write(p_channel,
                                       &p_channel->hdshk_buffer[SALT_M2_HASH_OFFSET],
                                       size, SALT_CLEAR);

                if (SALT_SUCCESS == ret_code) {
                    p_channel->state = SALT_M2_IO;
                    proceed = 1;
                }
                break;
            case SALT_M2_IO:
                /*
                 * Read the M2 message to hdshk_buffer[128]. If the message is OK the
                 * hash is saved to hdshk_buffer[64]. Now we have the hashes of M1
                 * and M2 in hdshk_buffer[0:127].
                 */
                size = 38U;

                ret_code = salti_read(p_channel,
                                      &p_channel->hdshk_buffer[SALT_M2_HASH_OFFSET],
                                      &size, SALT_CLEAR);

                if (SALT_SUCCESS == ret_code) {
                    p_channel->state = SALT_M2_HANDLE;
                    proceed = 1;
                }
                break;
            case SALT_M2_HANDLE:

                ret_code = salti_handle_m2(p_channel,
                                           &p_channel->hdshk_buffer[SALT_M2_HASH_OFFSET],
                                           size, &p_channel->hdshk_buffer[SALT_M2_HASH_OFFSET]);
                if (SALT_SUCCESS == ret_code) {
                    p_channel->state = SALT_M3_INIT;
                    proceed = 1;
                }
            case SALT_M3_INIT:

                /*
                 * While the server calculates / sends the M3 message we can create
                 * the M4 message. This is good if the I/O channel is slow. Much of
                 * the time will be waiting for I/O. The M4 message is encrypted and
                 * the crypto library API requires that the first 32 bytes of the
                 * clear text message is 0x00. Also 16 bytes HMAC are added for
                 * authentication of the message. The size of the clear text M4 msg
                 * is 102 bytes.
                 *
                 * Further, the API for signing a msg
                 * will take a message m[n] and create a signed message sm[n+64].
                 * Thus, we need a sligther larger buffer for creating the msg:
                 * 1. M4 = { header[2] , timestamp[4] , pubSigKey[32] }
                 * 2. Sign the hashes of M1 and M2 and put the signed message at
                 *    the end of M4:
                 *    M4[230] = { header[2] , timestamp[4] , pubSigKey[32] , signedMsg[192] }
                 *    where signedMsg[192] = { sig[64] , M1Hash[64] , M2Hash[64] }.
                 *    The peer however can will calculate these hashes so we
                 *    don't send them. I.e.:
                 *    M4[102] = { header[2] , timestamp[4] , pubSigKey[32] , sig[64] }
                 *
                 *
                 */
                ret_code = salti_create_m3m4(p_channel,
                                             &p_channel->hdshk_buffer[400],
                                             &p_channel->write_channel.size);
                if (SALT_SUCCESS == ret_code) {
                    p_channel->state = SALT_M3_IO;
                    proceed = 1;
                }
                break;
            case SALT_M3_IO:

                size = 120 + SALT_OVERHEAD_SIZE; /* Maximum size of M3 */

                ret_code = salti_read(p_channel,
                                      &p_channel->hdshk_buffer[200],
                                      &size, SALT_ENCRYPTED);
                if (SALT_SUCCESS == ret_code) {
                    p_channel->state = SALT_M3_HANDLE;
                    proceed = 1;
                }
                break;
            case SALT_M3_HANDLE:
                ret_code = salti_handle_m3m4(p_channel,
                                             &p_channel->hdshk_buffer[200 + 32],
                                             size, SALT_M3_HEADER_VALUE);
                if (SALT_SUCCESS == ret_code) {
                    p_channel->state = SALT_M4_IO;
                    proceed = 1;
                }
                break;
            case SALT_M4_IO:
                ret_code = salti_write(p_channel,
                                       &p_channel->hdshk_buffer[400
                                        - 32],
                                       p_channel->write_channel.size + 32, SALT_M4_HEADER_VALUE);

                if (SALT_SUCCESS == ret_code) {
                    p_channel->state = SALT_SESSION_ESTABLISHED;
                }
                memset(p_channel->hdshk_buffer, 0x00, p_channel->hdshk_buffer_size);
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
 *
 */
static void salti_create_m1(salt_channel_t *p_channel,
                                  uint8_t *p_data,
                                  uint32_t *size,
                                  uint8_t *p_hash)
{
    /* First 4 bytes is reserved for size. */

    /* Protocol indicator */
    p_data[SALT_LENGTH_SIZE + 0] = 'S';
    p_data[SALT_LENGTH_SIZE + 1] = 'C';
    p_data[SALT_LENGTH_SIZE + 2] = 'v';
    p_data[SALT_LENGTH_SIZE + 3] = '2';
    p_data[SALT_LENGTH_SIZE + 4] = SALT_M1_HEADER_VALUE;
    p_data[SALT_LENGTH_SIZE + 5] = 0x00U; /* No tickets */

    salti_get_time(p_channel, (uint32_t *) &p_data[SALT_LENGTH_SIZE + 6]);

    memcpy(&p_data[SALT_LENGTH_SIZE + 10],
           &p_channel->hdshk_buffer[SALT_PUB_ENC_OFFSET],
           crypto_box_PUBLICKEYBYTES);

    (*size) = 42U;

    crypto_hash(p_hash, &p_data[SALT_LENGTH_SIZE], (*size));
    salti_u32_to_bytes(&p_data[0], (*size));

    (*size) += SALT_LENGTH_SIZE;

}

static salt_ret_t salti_handle_a1_or_m1(salt_channel_t *p_channel,
                                        uint8_t *p_data,
                                        uint32_t size)
{
    SALT_VERIFY(size >= 2U, SALT_ERR_BAD_PROTOCOL);
    if (p_data[0] == SALT_A1_HEADER && p_data[1] == 0) {
        p_channel->state = SALT_A1_HANDLE;
    } else {
        p_channel->state = SALT_M1_HANDLE;
    }
    return SALT_SUCCESS;
}

static salt_ret_t salti_create_a2(salt_channel_t *p_channel,
                                  uint8_t *p_data,
                                  uint32_t *size)
{
    uint8_t i;
    salt_protocols_t *protocols = p_channel->p_protocols;

    *size = 0;

    if (protocols != NULL) {

        uint8_t n_protocols = protocols->count;

        if (((SALT_HNDSHK_BUFFER_SIZE-SALT_LENGTH_SIZE) / (2*sizeof(salt_protocol_t))) < n_protocols) {
            n_protocols = (SALT_HNDSHK_BUFFER_SIZE / (2*sizeof(salt_protocol_t)));
        }

        for (i = 0; i < n_protocols; i++) {
            memcpy(&p_data[SALT_LENGTH_SIZE + i*2*sizeof(salt_protocol_t)],
                "SC2-------",
                sizeof(salt_protocol_t));
            memcpy(&p_data[SALT_LENGTH_SIZE + i*2*sizeof(salt_protocol_t) + sizeof(salt_protocol_t)],
                protocols->p_protocols[i],
                sizeof(salt_protocol_t));
            *size += sizeof(salt_protocol_t)*2;
        }
    } else {
        memcpy(&p_data[SALT_LENGTH_SIZE], "SC2-------", sizeof(salt_protocol_t));
        memcpy(&p_data[SALT_LENGTH_SIZE + sizeof(salt_protocol_t)],
            "----------", sizeof(salt_protocol_t));
        *size += sizeof(salt_protocol_t)*2;
    }


    salti_u32_to_bytes(p_data, *size);

    (*size) += SALT_LENGTH_SIZE;

    return SALT_SUCCESS;
}

static salt_ret_t salti_handle_m1(salt_channel_t *p_channel,
                                  uint8_t *p_data,
                                  uint32_t size,
                                  uint8_t *p_hash)
{
    SALT_VERIFY(size >= 42,
                SALT_ERR_M1_TOO_SMALL);

    /* Protocol indicator should be "SCv2" */
    SALT_VERIFY(memcmp(p_data, "SCv2", 4) == 0,
                SALT_ERR_M1_BAD_PROTOCOL);

    SALT_VERIFY(p_data[4] == SALT_M1_HEADER_VALUE,
                SALT_ERR_M1_BAD_HEADER);

    /* Time is in p_data[6:10], TODO: Handle */

    if (((p_data[5] & SALT_M1_SIG_KEY_INCLUDED_FLAG) > 0U) && (size >= 74U)) {
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
        if (memcmp(&p_data[42], p_channel->my_sk_pub, crypto_sign_PUBLICKEYBYTES) != 0) {
            p_channel->err_code = SALT_ERR_NO_SUCH_SERVER;
        }
        /*
         * TODO: How to handle multiple hosts?
         */
    }


    /* Check if client is requesting a resume. */
    if ((p_data[5] & SALT_M1_TICKED_INCLUDED_FLAG) > 0U) {
        /*
         * At this point, we do not support the resume feature. I.e., if the
         * client includes a resume ticket we must make sure to respond to this.
         */
        p_channel->err_code = SALT_ERR_NOT_SUPPORTED;
    }

    /* Copy the clients public ephemeral encryption key. */
    memcpy(&p_channel->hdshk_buffer[242], &p_data[10], crypto_box_PUBLICKEYBYTES);

    /* Save the hash of M1 */
    crypto_hash(p_hash, p_data, size);

    return SALT_SUCCESS;

}

static salt_ret_t salti_create_m2(salt_channel_t *p_channel,
                                  uint8_t *p_data,
                                  uint32_t *size,
                                  uint8_t *p_hash)
{
    /*
     * Depending on how M1 was handeled, we will have the error code in
     * p_channel->err_code.
     */

    /* First four bytes are reserved for size */
    p_data[SALT_LENGTH_SIZE] = SALT_M2_HEADER_VALUE;
    p_data[SALT_LENGTH_SIZE + 1] = 0x00U; /* Flags */

    salti_get_time(p_channel, (uint32_t *) &p_data[SALT_LENGTH_SIZE + 2]);

    memcpy(&p_data[SALT_LENGTH_SIZE + 6],
           &p_channel->hdshk_buffer[SALT_PUB_ENC_OFFSET],
           crypto_box_PUBLICKEYBYTES);

    (*size) = 38U;

    switch (p_channel->err_code) {
    case SALT_ERR_NONE:
        break;
    case SALT_ERR_NO_SUCH_SERVER:
        p_data[SALT_LENGTH_SIZE + 1] = SALT_M2_NO_SUCH_SERVER_FLAG;
        break;
    case SALT_ERR_NOT_SUPPORTED:
        /* If ticket was requested, will cause handshake to stop. */
        return SALT_ERROR;
        break;
    default:
        return SALT_ERROR;
    }

    p_channel->err_code = SALT_ERR_NONE;
    crypto_hash(p_hash, &p_data[SALT_LENGTH_SIZE], (*size));

    salti_u32_to_bytes(&p_data[0], (*size));
    (*size) += SALT_LENGTH_SIZE;

    return SALT_SUCCESS;
}

static salt_ret_t salti_handle_m2(salt_channel_t *p_channel,
                                  uint8_t *p_data,
                                  uint32_t size,
                                  uint8_t *p_hash)
{

    SALT_VERIFY(size >= 38U,
                SALT_ERR_M2_TOO_SMALL);

    SALT_VERIFY(p_data[0] == SALT_M2_HEADER_VALUE,
                SALT_ERR_M2_BAD_HEADER);

    /*
     * If no such server condition occurs, the session is considered closed.
     * I.e., we return error here and the application will stop the handshake
     * procedure.
     */
    SALT_VERIFY((p_data[1] & SALT_M2_NO_SUCH_SERVER_FLAG) == 0U,
                SALT_ERR_NO_SUCH_SERVER);


    /* TODO: Handle time in p_data[2:6]. */

    SALT_VERIFY(crypto_box_beforenm(p_channel->ek_common,
                                    &p_data[6],
                                    &p_channel->hdshk_buffer[SALT_SEC_ENC_OFFSET]) == 0, SALT_ERR_COMMON_KEY);

    crypto_hash(p_hash, p_data, size);

    return SALT_SUCCESS;
}

static salt_ret_t salti_create_m3m4(salt_channel_t *p_channel,
                                    uint8_t *p_data,
                                    uint32_t *size)
{
    unsigned long long sign_msg_size;

    salti_get_time(p_channel, (uint32_t *) &p_data[2]);
    memcpy(&p_data[6], p_channel->my_sk_pub, 32);

    if (p_channel->mode == SALT_SERVER) {
        memcpy(&p_channel->hdshk_buffer[64], sig1prefix, 8);
    } else {
        memcpy(&p_channel->hdshk_buffer[64], sig2prefix, 8);
    }

    /*
     * crypto_sign will sign a message { m[n] } into a signed message
     * { sign[64] , m[n] }.
     *
     */
    SALT_VERIFY(crypto_sign(
                    p_channel->hdshk_buffer,
                    &sign_msg_size,
                    &p_channel->hdshk_buffer[64],
                    136,
                    p_channel->my_sk_sec) == 0, SALT_ERR_SIGNING);
    memcpy(&p_data[38], p_channel->hdshk_buffer, 64);

    (*size) = 102U;

    return SALT_SUCCESS;
}

static salt_ret_t salti_handle_m3m4(salt_channel_t *p_channel,
                                    uint8_t *p_data,
                                    uint32_t size,
                                    uint8_t header)
{
    unsigned long long sign_msg_size;

    SALT_VERIFY(102U == size, SALT_ERR_M3M4_WRONG_SIZE);

    SALT_VERIFY(p_data[0] == header,
                SALT_ERR_NOT_SUPPORTED);

    memcpy(p_channel->peer_sk_pub, &p_data[6], 32);
    memcpy(p_channel->hdshk_buffer, &p_data[38], 64);

    if (p_channel->mode == SALT_SERVER) {
        memcpy(&p_channel->hdshk_buffer[64], sig2prefix, 8);
    } else {
        memcpy(&p_channel->hdshk_buffer[64], sig1prefix, 8);
    }
    SALT_VERIFY(crypto_sign_open(
                    &p_channel->hdshk_buffer[200],
                    &sign_msg_size,
                    p_channel->hdshk_buffer,
                    200,
                    p_channel->peer_sk_pub) == 0, SALT_ERR_BAD_SIGNATURE);
    return SALT_SUCCESS;
}

static salt_ret_t salti_encrypt(salt_channel_t *p_channel,
                                uint8_t *p_data,
                                uint32_t size)
{
    int ret = crypto_box_afternm(
                  p_data,
                  p_data,
                  size,
                  p_channel->write_nonce,
                  p_channel->ek_common);
    SALT_VERIFY(0 == ret, SALT_ERR_ENCRYPTION);

    salti_increase_nonce(p_channel->write_nonce, p_channel->write_nonce_incr);

    return SALT_SUCCESS;

}

static salt_ret_t salti_decrypt(salt_channel_t *p_channel,
                                uint8_t *p_data,
                                uint32_t size)
{
    int ret = crypto_box_open_afternm(
                  p_data,
                  p_data,
                  size,
                  p_channel->read_nonce,
                  p_channel->ek_common);
    SALT_VERIFY(0 == ret, SALT_ERR_DECRYPTION);

    salti_increase_nonce(p_channel->read_nonce, p_channel->read_nonce_incr);

    return SALT_SUCCESS;

}

static void salti_increase_nonce(uint8_t *p_nonce, uint8_t increment)
{
    /* Thanks to Libsodium */
    uint_fast16_t c = increment;
    uint8_t i;

    for (i = 0U; i < crypto_box_NONCEBYTES; i++) {
        c += (uint_fast16_t) p_nonce[i];
        p_nonce[i] = (uint8_t) c;
        c >>= 8U;
    }

}

static void salti_u16_to_bytes(uint8_t *dest, uint16_t size)
{
    memcpy(dest, &size, sizeof(uint16_t));
}

static uint32_t salti_bytes_to_u16(uint8_t *src)
{
    return *((uint16_t*) src);
}


static void salti_u32_to_bytes(uint8_t *dest, uint32_t size)
{
    memcpy(dest, &size, sizeof(uint32_t));
}

static uint32_t salti_bytes_to_u32(uint8_t *src)
{
    return *((uint32_t*) src);
}

static void salti_get_time(salt_channel_t *p_channel, uint32_t *p_time)
{
    if (p_channel->time_impl != NULL) {
        p_channel->time_impl(p_time);
        return;
    }
    memset(p_time, 0x00, 4);
}
