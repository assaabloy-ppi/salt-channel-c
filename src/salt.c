/**
 * @file salt.c
 *
 * Salt channel version 2 implementation.
 *
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
#define SALT_WRITE_NONCE_INIT_SERVER            (2U)
#define SALT_WRITE_NONCE_INIT_CLIENT            (1U)
#define SALT_READ_NONCE_INIT_SERVER             (1U)
#define SALT_READ_NONCE_INIT_CLIENT             (2U)

/*======= Type Definitions ====================================================*/

/*======= Local variable declarations =========================================*/

/* Salt-channel v2 protocol, ASCII "SCv2------" */
static uint8_t sc2protocol[10] = "SCv2------";

/*======= Local function prototypes ===========================================*/

/*======= Global function implementations =====================================*/

salt_ret_t salt_create(salt_channel_t *p_channel,
                       salt_mode_t mode,
                       salt_io_impl write_impl,
                       salt_io_impl read_impl,
                       salt_time_t *time_impl)
{

    if (NULL == p_channel) {
        return SALT_ERROR;
    }

    memset(p_channel, 0x00U, sizeof(salt_channel_t));

    SALT_VERIFY(((SALT_CLIENT == mode) || (SALT_SERVER == mode)),
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

salt_ret_t salt_set_context(salt_channel_t *p_channel,
                            void *p_write_context,
                            void *p_read_context)
{
    if (NULL == p_channel) {
        return SALT_ERROR;
    }

    p_channel->write_channel.p_context = p_write_context;
    p_channel->read_channel.p_context = p_read_context;

    return SALT_SUCCESS;
}

salt_ret_t salt_protocols_init(salt_channel_t *p_channel,
                               salt_protocols_t *p_protocols,
                               uint8_t *p_buffer,
                               uint32_t size)
{
    if (NULL == p_channel) {
        return SALT_ERROR;
    }

    SALT_VERIFY_NOT_NULL(p_protocols);
    SALT_VERIFY_NOT_NULL(p_buffer);

    SALT_VERIFY(salt_protocols_create(p_protocols,
                                      p_buffer, size) == SALT_SUCCESS,
                                      SALT_ERR_BUFF_TO_SMALL);

    p_channel->p_protocols = p_protocols;

    return SALT_SUCCESS;

}

salt_ret_t salt_protocols_create(salt_protocols_t *p_protocols,
                                 uint8_t *p_buffer,
                                 uint32_t size)
{

    if (NULL == p_protocols) {
        return SALT_ERROR;
    }
    /*
     * At least one protocol must fit. Seralization of this will result in:
     * { size[4] , header[2] , count[1] , p1[10], p2[10] }
     *
     */
    if(size < (7U + (2 * sizeof(salt_protocol_t)))) {
        return SALT_ERROR;
    }

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

    if ((NULL == p_protocols) || (NULL == p_buffer)) {
        return SALT_ERROR;
    }

    /* 20 bytes required for next protocol */
    if (p_protocols->buf_size < p_protocols->buf_used) {
        return SALT_ERROR;
    }

    uint32_t remains = p_protocols->buf_size - p_protocols->buf_used;
    if (remains < (sizeof(salt_protocol_t)*2)) {
        return SALT_ERROR;
    }

    if (size > sizeof(salt_protocol_t)) {
        return SALT_ERROR;
    }

    /* Append "SC2-------" */
    memcpy(&p_protocols->p_buffer[p_protocols->buf_used], sc2protocol, sizeof(salt_protocol_t));
    p_protocols->buf_used += sizeof(salt_protocol_t);

    /* Pad with "-" */
    memset(&p_protocols->p_buffer[p_protocols->buf_used], 0x2DU, sizeof(salt_protocol_t));

    /* Append protocol */
    memcpy(&p_protocols->p_buffer[p_protocols->buf_used], p_buffer, size);
    p_protocols->buf_used += sizeof(salt_protocol_t);

    p_protocols->count += 2;
    p_protocols->p_buffer[SALT_LENGTH_SIZE + 2] = p_protocols->count / 2;

    /* Remove size from buf used */
    salti_u32_to_bytes(p_protocols->p_buffer, p_protocols->buf_used - 4);


    return SALT_SUCCESS;
}

salt_ret_t salt_a1a2(salt_channel_t *p_channel,
                     uint8_t *p_buffer,
                     uint32_t size,
                     salt_protocols_t *p_protocols,
                     uint8_t *p_with)
{

    salt_ret_t ret_code = SALT_PENDING;
    uint8_t proceed = 1;
    uint32_t a1_size = 0;

    if (NULL == p_channel) return SALT_ERROR;
    SALT_VERIFY_NOT_NULL(p_buffer);

    SALT_VERIFY(((p_channel->state >= SALT_CREATED) && (p_channel->state < SALT_M1_IO)),
                SALT_ERR_INVALID_STATE);

    while (proceed) {
        proceed = 0;
        switch (p_channel->state) {
            case SALT_CREATED:
            case SALT_SIGNATURE_SET:
            case SALT_SESSION_INITIATED:
                p_buffer[SALT_LENGTH_SIZE] = SALT_A1_HEADER;
                p_buffer[SALT_LENGTH_SIZE + 1] = 0x00U;

                if (NULL != p_with) {
                    p_buffer[SALT_LENGTH_SIZE + 2] = 0x01;
                    salti_u16_to_bytes(&p_buffer[SALT_LENGTH_SIZE + 3], 32);
                    memcpy(&p_buffer[SALT_LENGTH_SIZE + 5], p_with, 32);
                    a1_size = 37;
                } else {
                    p_buffer[SALT_LENGTH_SIZE + 2] = 0x00;
                    p_buffer[SALT_LENGTH_SIZE + 3] = 0x00;
                    p_buffer[SALT_LENGTH_SIZE + 4] = 0x00;
                    a1_size = 5;
                }

                salti_u32_to_bytes(p_buffer, a1_size);
                a1_size += SALT_LENGTH_SIZE;
                p_channel->state = SALT_A1_IO;
                proceed = 1;
                break;
            case SALT_A1_IO:
                ret_code = salti_io_write(p_channel, p_buffer, a1_size);
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

                    SALT_VERIFY((p_buffer[0] == SALT_A2_HEADER),
                                SALT_ERR_BAD_PROTOCOL);

                    /*
                     * Allowed value in p_buffer[1] is SALT_LAST_FLAG and/or SALT_NO_SUCH_SERVER_FLAG
                     */
                    SALT_VERIFY((0x00 == (p_buffer[1] & ~(SALT_NO_SUCH_SERVER_FLAG | SALT_LAST_FLAG))),
                                SALT_ERR_BAD_PROTOCOL);

                    if ((p_buffer[1] & SALT_NO_SUCH_SERVER_FLAG) > 0) {
                        p_channel->err_code = SALT_ERR_NO_SUCH_SERVER;
                        return SALT_ERROR;
                    }

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

    if (NULL == p_channel) {
        return SALT_ERROR;
    }

    SALT_VERIFY_NOT_NULL(p_signature);

    memcpy(p_channel->my_sk_sec, p_signature, api_crypto_sign_SECRETKEYBYTES);
    p_channel->state = SALT_SIGNATURE_SET;

    return SALT_SUCCESS;

}


salt_ret_t salt_create_signature(salt_channel_t *p_channel)
{
    if (NULL == p_channel) {
        return SALT_ERROR;
    }

    int ret = api_crypto_sign_keypair(p_channel->my_sk_pub, p_channel->my_sk_sec);
    SALT_VERIFY(0 == ret, SALT_ERR_CRYPTO_API);

    p_channel->state = SALT_SIGNATURE_SET;
    return SALT_SUCCESS;
}

salt_ret_t salt_init_session(salt_channel_t *p_channel,
                             uint8_t *hdshk_buffer,
                             uint32_t hdshk_buffer_size)
{
    return salt_init_session_using_key(p_channel,
                                       hdshk_buffer,
                                       hdshk_buffer_size,
                                       NULL,
                                       NULL);
}

salt_ret_t salt_init_session_using_key(salt_channel_t *p_channel,
                                       uint8_t *hdshk_buffer,
                                       uint32_t hdshk_buffer_size,
                                       const uint8_t *ek_pub,
                                       const uint8_t *ek_sec)
{

    if (NULL == p_channel) {
        return SALT_ERROR;
    }

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
    memset(p_channel->ek_common, 0x00U, sizeof(p_channel->ek_common));
    memset(p_channel->peer_sk_pub, 0x00U, sizeof(p_channel->peer_sk_pub));
    memset(p_channel->write_nonce, 0x00U, sizeof(p_channel->write_nonce));
    memset(p_channel->read_nonce, 0x00U, sizeof(p_channel->read_nonce));

    /* Initiate write and read nonce */
    if (SALT_SERVER == p_channel->mode) {
        p_channel->write_nonce[0]  = SALT_WRITE_NONCE_INIT_SERVER;
        p_channel->read_nonce[0] = SALT_READ_NONCE_INIT_SERVER;
    }
    else {
        p_channel->write_nonce[0]  = SALT_WRITE_NONCE_INIT_CLIENT;
        p_channel->read_nonce[0] = SALT_READ_NONCE_INIT_CLIENT;
    }

    p_channel->write_channel.state = SALT_IO_READY;
    p_channel->read_channel.state = SALT_IO_READY;


    if ((ek_pub == NULL) || (ek_sec == NULL)) {
        /*
         * Create ephemeral keypair used for only this session.
         * hdshk_buffer[0:31]:  Public key
         * hdshk_buffer[32:63]: Private key
         * The ephemeral keypair is kept where the signature later will be
         * until the common key is calculated.
         */
        int ret = api_crypto_box_keypair(hdshk_buffer, &hdshk_buffer[32]);
        SALT_VERIFY(0 == ret, SALT_ERR_CRYPTO_API);
    }
    else {
        memcpy(hdshk_buffer, ek_pub, 32);
        memcpy(&hdshk_buffer[32], ek_sec, 32);
    }


    p_channel->err_code = SALT_ERR_NONE;
    p_channel->state = SALT_SESSION_INITIATED;

    return SALT_SUCCESS;

}

salt_ret_t salt_set_delay_threshold(salt_channel_t *p_channel, uint32_t delay_threshold)
{

    if (NULL == p_channel) {
        return SALT_ERROR;
    }

    p_channel->delay_threshold = delay_threshold;

    return SALT_SUCCESS;
}

salt_ret_t salt_handshake(salt_channel_t *p_channel, const uint8_t *p_with)
{
    salt_ret_t ret;

    if (NULL == p_channel) {
        return SALT_ERROR;
    }

    if (SALT_SERVER == p_channel->mode) {
        ret = salti_handshake_server(p_channel, p_with);
    }

    else if (SALT_CLIENT == p_channel->mode) {
        ret = salti_handshake_client(p_channel, p_with);
    }

    else {
        p_channel->err_code = SALT_ERR_INVALID_STATE;
        ret = SALT_ERROR;
    }

    if (SALT_PENDING != ret) {
        /* If handshake succeeded or failed, clear the handshake buffer. */
        memset(p_channel->hdshk_buffer, 0x00U, p_channel->hdshk_buffer_size);
    }

    return ret;

}

/**
 * @brief See \ref salt_handshake
 */
salt_ret_t salt_handshake_server(salt_channel_t *p_channel, const uint8_t *p_with)
{
    salt_ret_t ret;

    if (NULL == p_channel) {
        return SALT_ERROR;
    }

    SALT_VERIFY(SALT_SERVER == p_channel->mode, SALT_ERR_INVALID_STATE);

    ret = salti_handshake_server(p_channel, p_with);

    if (SALT_PENDING != ret) {
        /* If handshake succeeded or failed, clear the handshake buffer. */
        memset(p_channel->hdshk_buffer, 0x00U, p_channel->hdshk_buffer_size);
    }

    return ret;

}

/**
 * @brief See \ref salt_handshake
 */
salt_ret_t salt_handshake_client(salt_channel_t *p_channel, const uint8_t *p_with)
{
    salt_ret_t ret;

    if (NULL == p_channel) {
        return SALT_ERROR;
    }

    SALT_VERIFY(SALT_CLIENT == p_channel->mode, SALT_ERR_INVALID_STATE);

    ret = salti_handshake_client(p_channel, p_with);

    if (SALT_PENDING != ret) {
        /* If handshake succeeded or failed, clear the handshake buffer. */
        memset(p_channel->hdshk_buffer, 0x00U, p_channel->hdshk_buffer_size);
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

    if (NULL == p_channel) {
        return SALT_ERROR;
    }

    SALT_VERIFY(SALT_SESSION_ESTABLISHED == p_channel->state,
                SALT_ERR_INVALID_STATE);

    SALT_VERIFY(buffer_size >= SALT_OVERHEAD_SIZE, SALT_ERR_BUFF_TO_SMALL);
    SALT_VERIFY(NULL != p_msg, SALT_ERR_NULL_PTR);

    ret = salti_io_read(p_channel, &p_buffer[14], &size);

    if (SALT_SUCCESS == ret) {

        /*
         * salti_unwrap returns pointer to clear text message to
         * p_buffer and the length of the clear text message to
         * size.
         */
        ret = salti_unwrap(p_channel,
                           p_buffer,
                           size,
                           &header,
                           &p_buffer,
                           &size);

        SALT_VERIFY(SALT_SUCCESS == ret, p_channel->err_code);

        SALT_VERIFY(((SALT_APP_PKG_MSG_HEADER_VALUE == header[0]) ||
                     (SALT_MULTI_APP_PKG_MSG_HEADER_VALUE == header[0])) &&
                    (header[1] == 0x00U), SALT_ERR_BAD_PROTOCOL);

        salt_err_t err_code = salt_read_init(header[0], p_buffer, size, p_msg);
        SALT_VERIFY(err_code == SALT_ERR_NONE, err_code);
    }

    return ret;
}

salt_ret_t salt_read_next(salt_msg_t *p_msg)
{

    uint16_t payload_size;
    uint32_t buffer_left;

    if (NULL == p_msg) {
        return SALT_ERROR;
    }

    if (0 == p_msg->read.messages_left) {
        return SALT_ERROR;
    }

    /*
     * First message, p_msg->read.message_size will be 0. Otherwise it will be
     * the length of last message.
     * 
     * First:
     * p_buffer = { count[2] , length1[2], payload1[n1] , ... , lengthN[2], patloadN[nN] }
     * buffer_used ----------->
     * 
     * Otherwise:
     * p_buffer = { count[2] , length1[2], payload1[n1] , ... , lengthN[2], patloadN[nN] }
     * buffer_used ----------------------->
     *                           message_size = n1
     * 
     */
    p_msg->read.buffer_used += p_msg->read.message_size;
    buffer_left = p_msg->read.buffer_size - p_msg->read.buffer_used;

    /* Two bytes required for payload size */
    if (buffer_left < 2U) {
        return SALT_ERROR;
    }

    payload_size = salti_bytes_to_u16(&p_msg->read.p_buffer[p_msg->read.buffer_used]);

    /*
     * After size is read, two more bytes are used. Therefore, we have 2 bytes
     * left in buffer.
     */
    p_msg->read.buffer_used += 2U;
    buffer_left -= 2U;

    if (payload_size > buffer_left) {
        return SALT_ERROR;
    }

    /*
     * Point current payload to next message.
     */
    p_msg->read.p_payload = &p_msg->read.p_buffer[p_msg->read.buffer_used];
    p_msg->read.message_size = payload_size;
    p_msg->read.messages_left--;

    return SALT_SUCCESS;
}

salt_ret_t salt_write_begin(uint8_t *p_buffer,
                            uint32_t size,
                            salt_msg_t *p_msg)
{

    if (NULL == p_buffer) {
        return SALT_ERROR;
    }

    if (NULL == p_msg) {
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

salt_ret_t salt_write_next(salt_msg_t *p_msg, void *p_buffer, uint16_t size)
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
    salt_ret_t ret = SALT_ERROR;

    if (NULL == p_channel) {
        return SALT_ERROR;
    }
    
    SALT_VERIFY(SALT_SESSION_ESTABLISHED == p_channel->state,
                SALT_ERR_INVALID_STATE);
    SALT_VERIFY_NOT_NULL(p_msg);

    if (0 == p_msg->write.state) {
        uint8_t type = salt_write_create(p_msg);

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
