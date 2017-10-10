/**
 * @file salt.c
 *
 * Salt channel version 2 implementation.
 *
 * See v2notes.txt for implementation details.
 *
 * TODO: Refer to v2notes.txt for tricks when placing messages in hanshake buffer.
 *
 */

/*======= Includes ============================================================*/

/* C Library includes */
#include <string.h> /* memcpy, memset */

/* Salt library includes */
#include "salt.h"
#include "salti_handshake.h"
#include "salti_util.h"

/*======= Local Macro Definitions =============================================*/

/* Nonce initial values and increments */
#define SALT_WRITE_NONCE_INCR_SERVER            (2U)
#define SALT_WRITE_NONCE_INCR_CLIENT            (2U)
#define SALT_WRITE_NONCE_INIT_SERVER            (2U)
#define SALT_WRITE_NONCE_INIT_CLIENT            (1U)
#define SALT_READ_NONCE_INCR_SERVER             (2U)
#define SALT_READ_NONCE_INCR_CLIENT             (2U)
#define SALT_READ_NONCE_INIT_SERVER             (1U)
#define SALT_READ_NONCE_INIT_CLIENT             (2U)



/*======= Type Definitions ====================================================*/

/*======= Local variable declarations =========================================*/

/* Salt-channel v2 protocol, ASCII "SC2-------" */
static uint8_t sc2protocol[10] = { 0x53, 0x43, 0x32, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d };

/*======= Local function prototypes ===========================================*/

/*======= Global function implementations =====================================*/

salt_ret_t salt_create(
    salt_channel_t *p_channel,
    salt_mode_t mode,
    salt_io_impl write_impl,
    salt_io_impl read_impl,
    salt_time_t *time_impl)
{

    SALT_VERIFY_VALID_CHANNEL(p_channel);

    SALT_VERIFY(mode <= SALT_CLIENT,
                SALT_ERR_NOT_SUPPORTED);

    p_channel->mode = mode;

    SALT_VERIFY_NOT_NULL(write_impl);
    SALT_VERIFY_NOT_NULL(read_impl);

    p_channel->write_impl = write_impl;
    p_channel->read_impl = read_impl;
    p_channel->time_impl = time_impl;
    p_channel->state = SALT_CREATED;
    p_channel->err_code = SALT_ERR_NONE;
    p_channel->my_sk_pub = &p_channel->my_sk_sec[32];
    p_channel->p_protocols = NULL;
    p_channel->delay_threshold = 0;

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

salt_ret_t salt_protocols_init(salt_channel_t *p_channel,
                               salt_protocols_t *p_protocols,
                               uint8_t *p_buffer,
                               uint32_t size)
{
    SALT_VERIFY_VALID_CHANNEL(p_channel);
    SALT_VERIFY_NOT_NULL(p_protocols);
    SALT_VERIFY_NOT_NULL(p_buffer);

    /*
     * At least one protocol must fit. Seralization of this will result in:
     * { size[4] , header[2] , count[1] , p1[10], p2[10] }
     *
     */
    SALT_VERIFY(size >= 7U + 2 * sizeof(salt_protocol_t), SALT_ERR_BUFF_TO_SMALL);

    p_channel->p_protocols = p_protocols;
    p_protocols->count = 0;
    p_protocols->p_buffer = p_buffer;
    p_protocols->buf_size = size;
    p_protocols->buf_used = 7; /* Size + header + count */

    p_buffer[SALT_LENGTH_SIZE] = SALT_A2_HEADER;
    p_buffer[SALT_LENGTH_SIZE + 1] = SALT_LAST_FLAG;
    p_buffer[SALT_LENGTH_SIZE + 2] = p_protocols->count;

    p_protocols->p_protocols = (salt_protocol_t *) &p_buffer[SALT_LENGTH_SIZE + 3];

    return SALT_SUCCESS;
}

salt_ret_t salt_protocols_append(salt_protocols_t *p_protocols,
                                 char *p_buffer,
                                 uint8_t size)
{

    if (p_protocols == NULL) {
        return SALT_ERROR;
    }

    /* 20 bytes required for next protocol */
    if (p_protocols->buf_size - p_protocols->buf_used < sizeof(salt_protocol_t) * 2) {
        return SALT_ERROR;
    }

    if (size > sizeof(salt_protocol_t)) {
        return SALT_ERROR;
    }

    /* Append "SC2-------" */
    memcpy(&p_protocols->p_buffer[p_protocols->buf_used], sc2protocol, sizeof(salt_protocol_t));
    p_protocols->buf_used += sizeof(salt_protocol_t);

    /* Append protocol */
    memcpy(&p_protocols->p_buffer[p_protocols->buf_used], p_buffer, size);
    p_protocols->buf_used += size;

    /* Pad with "-" */
    memset(&p_protocols->p_buffer[p_protocols->buf_used], 0x2DU, sizeof(salt_protocol_t) - size);
    p_protocols->buf_used += sizeof(salt_protocol_t) - size;

    p_protocols->count += 2;
    p_protocols->p_buffer[SALT_LENGTH_SIZE + 2] = p_protocols->count / 2;

    /* Remove size from buf used */
    salti_u32_to_bytes(p_protocols->p_buffer, p_protocols->buf_used - 4);


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
            ret_code = salti_io_write(p_channel, p_buffer, 6);
            if (SALT_SUCCESS == ret_code) {
                proceed = 1;
                p_channel->state = SALT_A2_IO;
            }
            break;
        case SALT_A2_IO:
            ret_code = salti_io_read(p_channel, p_buffer, &size);
            if (SALT_SUCCESS == ret_code) {

                /*
                 * Expected format of p_buffer:
                 *  { header[2] , count[1] , protocols[ count * 2 * sizeof(salt_protocol_t) ] }
                 */

                SALT_VERIFY(p_buffer[0] == SALT_A2_HEADER && p_buffer[1] == SALT_LAST_FLAG,
                            SALT_ERR_BAD_PROTOCOL);

                /* Remove header and count from read size */
                size -= 3;

                SALT_VERIFY(size == p_buffer[2] * 2 * sizeof(salt_protocol_t), SALT_ERR_BAD_PROTOCOL);
                p_protocols->count = p_buffer[2] * 2;
                p_protocols->p_protocols = (salt_protocol_t *) &p_buffer[3];

                p_channel->state = SALT_SESSION_INITIATED;
                ret_code = SALT_SUCCESS;
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
    p_channel->time_supported = (p_channel->time_impl == NULL) ? 0 : 1;

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

salt_ret_t salt_set_delay_threshold(salt_channel_t *p_channel, uint32_t delay_threshold)
{
    SALT_VERIFY_VALID_CHANNEL(p_channel);
    p_channel->delay_threshold = delay_threshold;

    return SALT_SUCCESS;
}

salt_ret_t salt_handshake(salt_channel_t *p_channel)
{
    salt_ret_t ret;
    SALT_VERIFY_VALID_CHANNEL(p_channel);

    if (p_channel->mode == SALT_SERVER) {
        ret = salti_handshake_server(p_channel);
    }
    else {
        ret = salti_handshake_client(p_channel);
    }

    return ret;

}

salt_ret_t salt_read_begin(salt_channel_t *p_channel,
                           uint8_t *p_buffer,
                           uint32_t buffer_size,
                           salt_msg_t *p_msg)
{
    salt_ret_t ret;
    uint32_t size = buffer_size - 14U;
    uint8_t *header;

    SALT_VERIFY_VALID_CHANNEL(p_channel);
    SALT_VERIFY(SALT_SESSION_ESTABLISHED == p_channel->state,
                SALT_ERR_INVALID_STATE);

    SALT_VERIFY(buffer_size >= SALT_OVERHEAD_SIZE, SALT_ERR_BUFF_TO_SMALL);

    ret = salti_io_read(p_channel, &p_buffer[14], &size);

    if (ret == SALT_SUCCESS) {

        ret = salti_unwrap(p_channel,
                           p_buffer,
                           size,
                           &header,
                           &p_buffer,
                           &size);

        SALT_VERIFY(SALT_SUCCESS == ret, p_channel->err_code);

        SALT_VERIFY((SALT_APP_PKG_MSG_HEADER_VALUE == header[0]) ||
                    (SALT_MULTI_APP_PKG_MSG_HEADER_VALUE == header[0]),
                    SALT_ERR_BAD_PROTOCOL);

        salt_err_t err_code = salt_read_init(header[0], p_buffer, size, p_msg);
        SALT_VERIFY(err_code == SALT_ERR_NONE, err_code);
    }

    return ret;
}

salt_ret_t salt_read_next(salt_msg_t *p_msg)
{

    if (p_msg->read.messages_left == 0) {
        return SALT_ERROR;
    }

    p_msg->read.p_payload += p_msg->read.message_size;
    p_msg->read.message_size = salti_bytes_to_u16(p_msg->read.p_payload);
    p_msg->read.p_payload += 2;
    p_msg->read.buffer_used = 2 + p_msg->read.message_size;

    if (p_msg->read.buffer_used + 2 + p_msg->read.message_size > p_msg->read.buffer_size) {
        return SALT_ERROR;
    }

    p_msg->read.buffer_used += 2 + p_msg->read.message_size;

    p_msg->read.messages_left--;


    return SALT_SUCCESS;
}

salt_ret_t salt_write_begin(uint8_t *p_buffer,
                            uint32_t size,
                            salt_msg_t *p_msg)
{

    if (p_buffer == NULL) {
        return SALT_ERROR;
    }

    if (p_msg == NULL) {
        return SALT_ERROR;
    }

    if (size < SALT_WRITE_OVERHEAD_SIZE) {
        return SALT_ERROR;
    }

    /* First SALT_WRITE_OVERHEAD_SIZE is overhead for encryption. The message
     * follows as:
     * { count[2] , size_1[2] , msg_1[n] , ... }
     * I.e.:
     * { overHead[SALT_WRITE_OVERHEAD_SIZE] , count[2] , size_1[2] , msg_1[n] , ... }
     *
     * Therefore the first message will be put in SALT_WRITE_OVERHEAD_SIZE + 2.
     *
     */

    p_msg->write.state = 0;
    p_msg->write.p_buffer = p_buffer;
    p_msg->write.buffer_size = size;
    p_msg->write.p_payload = &p_buffer[SALT_OVERHEAD_SIZE] + 4U;
    p_msg->write.buffer_available = size - SALT_OVERHEAD_SIZE - 2U;
    p_msg->write.message_count = 0;

    return SALT_SUCCESS;
}

salt_ret_t salt_write_next(salt_msg_t *p_msg, uint8_t *p_buffer, uint16_t size)
{

    /* We need size + 2 bytes available. */
    if (p_msg->write.buffer_available < (size + 2U)) {
        return SALT_ERROR;
    }

    salti_u16_to_bytes(p_msg->write.p_payload - 2U, size);

    memcpy(p_msg->write.p_payload, p_buffer, size);
    p_msg->write.p_payload += size + 2U;
    p_msg->write.buffer_available -= (size + 2U);
    p_msg->write.message_count++;

    return SALT_SUCCESS;
}

salt_ret_t salt_write_commit(salt_msg_t *p_msg, uint16_t size)
{
    /* We need size + 2 bytes available. */
    if (p_msg->write.buffer_available < (size + 2U)) {
        return SALT_ERROR;
    }

    salti_u16_to_bytes(p_msg->write.p_payload - 2U, size);
    p_msg->write.p_payload += size + 2U;
    p_msg->write.buffer_available -= (size + 2U);
    p_msg->write.message_count++;

    return SALT_SUCCESS;
}

salt_ret_t salt_write_execute(salt_channel_t *p_channel,
                              salt_msg_t *p_msg,
                              bool last_msg)
{
    uint8_t type;
    salt_ret_t ret = SALT_ERROR;
    SALT_VERIFY_VALID_CHANNEL(p_channel);
    SALT_VERIFY(SALT_SESSION_ESTABLISHED == p_channel->state,
                SALT_ERR_INVALID_STATE);
    SALT_VERIFY_NOT_NULL(p_msg);

    if (p_msg->write.state == 0) {
        type = salt_write_create(p_msg);

        ret = salti_wrap(p_channel,
                         p_msg->write.p_buffer,
                         p_msg->write.buffer_size,
                         type,
                         &p_msg->write.p_buffer,
                         &p_msg->write.buffer_size,
                         last_msg);
        SALT_VERIFY(SALT_SUCCESS == ret, p_channel->err_code);
    }

    ret = salti_io_write(p_channel,
                         p_msg->write.p_buffer,
                         p_msg->write.buffer_size);

    return ret;
}

/*======= Local function implementations ======================================*/