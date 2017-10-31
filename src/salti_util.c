/**
 * @file salti_util.c
 *
 * Description
 *
 */

/*======= Includes ==========================================================*/

/* C Library includes */
#include <string.h> /* memcpy, memset */

/* Salt library includes */
#include "salti_util.h"

/*======= Local Macro Definitions ===========================================*/
/*======= Type Definitions ==================================================*/
/*======= Local function prototypes =========================================*/
/*======= Local variable declarations =======================================*/
/*======= Global function implementations ===================================*/

/**
 * @brief Internal read process state machine.
 *
 * Internal read process state machine.
 *      1. Read the four bytes size.
 *      2. Read the message with the specific size that was read.
 *
 * The maximum length of the message to be read is put in *size.
 * The actual length of the read message is returned in *size.
 *
 * @return SALT_SUCCESS Read operation was successful.
 * @return SALT_PENDING Read operation is still pending.
 * @return SALT_ERROR   Some I/O error occured. For details
 *                      see p_channel->err_code and
 *                      p_channel->read_channel.err_code.
 */
salt_ret_t salti_io_read(salt_channel_t *p_channel,
                         uint8_t *p_data,
                         uint32_t *size)
{
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

        channel->size_expected = salti_bytes_to_u32(channel->p_data);

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
            (*size) = channel->size;
            channel->state = SALT_IO_READY;
        }

        break;
    default:
        SALT_ERROR(SALT_ERR_INVALID_STATE);

    }

    return ret_code;
}

/**
 * @brief Internal write process state machine.
 *
 * This write process assumes that the bytes to send is serialized
 * according to the serial channel specification. I.e. the format
 * of the data must follow this specification:
 *
 * { size[4] , data[n] }
 *
 * Where the size bytes must be the length of n described in little
 * endian byte order. I.e.:
 *
 * n = 4    =>  size[4] = { 0x04, 0x00, 0x00, 0x00 }
 * n = 389  =>  size[4] = { 0x01, 0x85, 0x00, 0x00 }
 *
 * @return SALT_SUCCESS Write operation was successful.
 * @return SALT_PENDING Write operation is still pending.
 * @return SALT_ERROR   Some I/O error occured. For details
 *                      see p_channel->err_code.
 */
salt_ret_t salti_io_write(salt_channel_t *p_channel,
                          uint8_t *p_data,
                          uint32_t size)
{
    salt_ret_t ret_code = SALT_ERROR;
    salt_io_channel_t *channel = &p_channel->write_channel;

    switch (channel->state) {
    case SALT_IO_READY:
        channel->p_data = p_data;
        channel->size = 0;
        channel->size_expected = size;
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

    return ret_code;
}


/**
 * @brief Encrypts and wraps clear text data.
 *
 * The message is clear text wrapped according to:
 *
 * wrappedClear = { header[0] , header[1] , time[4] , msg[n] }
 *
 * Where header[0] is the type of the message. The wrapped message is
 * then encrypted. The encryption procedure requires the following format
 * of the clear text data:
 *
 * toDecrypt = {
 *      zeroPadded[crypto_secretbox_ZEROBYTES] ,
 *      wrappedClear[n + 6]
 * }
 *
 * Which will give the output:
 *
 * encrypted = {
 *      zeroPadded[crypto_secretbox_BOXZEROBYTES] ,
 *      cipher[n + 6 + crypto_secretbox_BOXZEROBYTES]
 * }
 *
 * This requires the clear text data input to this function to start at index
 * crypto_secretbox_ZEROBYTES + 6U.
 *
 * After the encryption, the message is padded with the size bytes:
 *
 * wrappedAndEncrypted = {
 *      zeroPadded[crypto_secretbox_ZEROBYTES - 6U] ,
 *      sizeBytes[4] ,
 *      header[2] ,
 *      cipher[n + 6 + crypto_secretbox_BOXZEROBYTES]
 * }
 *
 * Hence, the actual message to send to the received after this procedure
 * begins at p_data[12] with the length of:
 *  toSend = n + 4 + 2 + 6 + crypto_secretbox_BOXZEROBYTES = n + 28
 *
 * I.e., the usage will be:
 *  uint8_t data[100];
 *  snprintf(&data[crypto_secretbox_ZEROBYTES + 6U], "hejsan", 6);
 *  uint8_t *data_to_send;
 *  uint32_t len_to_send;
 *  salti_wrap(&channel, data, 6, SALT_APP_PKG_MSG_HEADER_VALUE, &data_to_send, &len_to_send);
 *  salti_io_write(&channel, data_to_send, len_to_send);
 *
 * @param p_channel         Pointer to salt channel structure.
 * @param p_data            Pointer to clear text message.
 * @param size              Size of clear text message.
 * @param type              Type of message.
 * @param wrapped           Return pointer to where the raw message to send begins.
 * @param wrapped_length    Return length of raw wrapped message.
 *
 * @return SALT_SUCCESS Wrapping was successfull.
 * @return SALT_ERROR   Wrapping failed.
 */
salt_ret_t salti_wrap(salt_channel_t *p_channel,
                      uint8_t *p_data,
                      uint32_t size,
                      uint8_t header,
                      uint8_t **wrapped,
                      uint32_t *wrapped_length,
                      bool last_msg)
{

    int ret;
    memset(p_data, 0x00, crypto_secretbox_ZEROBYTES);

    p_data[32] = header;
    p_data[33] = 0x00;

    uint32_t time = 0;
    salti_get_time(p_channel, &time);
    time -= p_channel->my_epoch;
    salti_u32_to_bytes(&p_data[34], time);

    ret = crypto_box_afternm(
              p_data,
              p_data,
              size + 6U + crypto_secretbox_ZEROBYTES,
              p_channel->write_nonce,
              p_channel->ek_common);

    SALT_VERIFY(0 == ret, SALT_ERR_ENCRYPTION);

    salti_increase_nonce(p_channel->write_nonce, p_channel->write_nonce_incr);
    p_data[14] = SALT_ENCRYPTED_MSG_HEADER_VALUE;
    p_data[15] = (last_msg) ? SALT_LAST_FLAG : 0x00U;
    size += 24;
    salti_u32_to_bytes(&p_data[10], size);
    size += 4U;

    *wrapped = &p_data[10];
    *wrapped_length = size;

    return SALT_SUCCESS;

}

/**
 * @brief Unwraps and decrypts a salt channel package.
 *
 * The unwrap routine requires a buffer of the following format:
 *
 * wrappedAndEncrypted = { zero[16] , raw[n] } = { zero[16] , header[2] , data[n-2] }
 *
 * When this is decrypted the following format will be given:
 *
 * wrappedAndDecrypt = {
 *      zero[crypto_secretbox_ZEROBYTES] ,
 *      header[2] ,
 *      time[4] ,
 *      clear[n - 2 - 2 - 4 - crypto_secretbox_BOXZEROBYTES]
 * }
 *
 * The time is then evaluated and information about the message is return using the in
 * parameter pointers.
 *
 * @param p_channel         Pointer to salt channel structure.
 * @param p_data            Pointer to ciåher text message.
 * @param size              Size of cipher message, exluding overhead bytes,
 * @param type              Return type of message.
 * @param unwrapped         Return pointer to clear text message.
 * @param unwrapped_length  Return length of clear text message.
 * @return [description]
 */
salt_ret_t salti_unwrap(salt_channel_t *p_channel,
                        uint8_t *p_data,
                        uint32_t size,
                        uint8_t **header,
                        uint8_t **unwrapped,
                        uint32_t *unwrapped_length)
{
    /* Header in p_data[14:15] must be { 0x06 , 0x00 } */
    SALT_VERIFY(p_data[14] == 0x06U,
                SALT_ERR_BAD_PROTOCOL);

    if ((p_data[15] & SALT_LAST_FLAG) > 0U) {
        p_channel->state = SALT_SESSION_CLOSED;
    }

    SALT_VERIFY(size >= 24U, SALT_ERR_BAD_PROTOCOL);

    memset(p_data, 0x00U, crypto_secretbox_BOXZEROBYTES);
    size = size + crypto_secretbox_BOXZEROBYTES - 2U;

    int ret = crypto_box_open_afternm(
                  p_data,
                  p_data,
                  size,
                  p_channel->read_nonce,
                  p_channel->ek_common);
    SALT_VERIFY(0 == ret, SALT_ERR_DECRYPTION);

    salti_increase_nonce(p_channel->read_nonce, p_channel->read_nonce_incr);

    (*header) = &p_data[32];

    if (p_channel->time_supported && p_channel->delay_threshold > 0) {
        uint32_t t_package = salti_bytes_to_u32(&p_data[34]);
        uint32_t t_arrival = 0;
        salti_get_time(p_channel, &t_arrival);
        if (t_arrival - p_channel->peer_epoch > t_package + p_channel->delay_threshold) {
            /* Delay detected */
            SALT_ERROR(SALT_ERR_DELAY_DETECTED);
        }
    }


    (*unwrapped) = &p_data[38];
    (*unwrapped_length) = size - crypto_secretbox_ZEROBYTES - 2U - 4U;

    return SALT_SUCCESS;

}

void salti_increase_nonce(uint8_t *p_nonce, uint8_t increment)
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

void salti_u16_to_bytes(uint8_t *dest, uint16_t size)
{
    dest[0] = size & 0xFFU;
    dest[1] = (size >> 8U) & 0xFFU;
}

uint16_t salti_bytes_to_u16(uint8_t *src)
{
    return ((src[0] & 0x00FFU) | ((src[1] << 8U) & 0xFF00U));
}


void salti_u32_to_bytes(uint8_t *dest, uint32_t size)
{
    dest[0] = size & 0xFFU;
    dest[1] = (size >> 8U) & 0xFFU;
    dest[2] = (size >> 16U) & 0xFFU;
    dest[3] = (size >> 24U) & 0xFFU;
}

uint32_t salti_bytes_to_u32(uint8_t *src)
{
    return (
               (src[0] & 0x000000FFU) |
               ((src[1] << 8U) & 0x0000FF00U) |
               ((src[2] << 16U) & 0x00FF0000U) |
               ((src[3] << 24U) & 0xFFU)
           );
}

salt_ret_t salti_get_time(salt_channel_t *p_channel, uint32_t *p_time)
{
    salt_ret_t ret = SALT_ERROR;
    if (p_channel->time_impl != NULL && p_channel->time_impl->get_time != NULL) {
        ret = p_channel->time_impl->get_time(p_channel->time_impl, p_time);
    }

    if (ret == SALT_ERROR) {
        memset(p_time, 0x00, 4);
    }

    return ret;

}

/**
 * @brief Used internally by \ref salt_read_begin. Declared public for testability.
 *
 * Initialized a parsing of a application or multi application message. The input to
 * this function is clear text.
 *
 * @param p_msg         Pointer to message structure to use when reading the message.
 *
 * @return SALT_SUCCESS The message follows salt-channel specification.
 * @return SALT_ERROR   The message doesn't follow salt channel specification or the
 *                      receive buffer is to small.
 */
salt_err_t salt_read_init(uint8_t type,
                          uint8_t *p_buffer,
                          uint32_t buffer_size,
                          salt_msg_t *p_msg)
{

    p_msg->read.p_buffer = p_buffer;
    p_msg->read.buffer_size = buffer_size;

    switch (type) {
    case SALT_APP_PKG_MSG_HEADER_VALUE:

        /*
         * Single message:
         * p_msg->read.p_buffer[0:31] = 0x00
         * p_msg->read.p_buffer[32] = header
         * p_msg->read.p_buffer[33] = 0x00
         * p_msg->read.p_buffer[34:37] = time[4]
         * p_msg->read.p_buffer[38:p_msg->read.buffer_used - 6U] = message[p_msg->read.buffer_used - 6U]
         *
         * { zeroPadding[32] , header[2] , time[4] , msg[n] }
         *                   |<---  p_msg->read.buffer_used  --->|
         *
         */
        p_msg->read.messages_left = 0;
        p_msg->read.p_payload = p_buffer;
        p_msg->read.message_size = buffer_size;

        break;
    case SALT_MULTI_APP_PKG_MSG_HEADER_VALUE:

        if (buffer_size < 2U) {
            return SALT_ERR_BAD_PROTOCOL;
        }

        /*
         * Single message:
         * p_msg->read.p_buffer[0:31] = 0x00
         * p_msg->read.p_buffer[32] = header
         * p_msg->read.p_buffer[33] = 0x00
         * p_msg->read.p_buffer[34:37] = time[4]
         * p_msg->read.p_buffer[38:39] = count[2]
         * p_msg->read.p_buffer[40:41] = size1[2]
         * p_msg->read.p_buffer[42:42+size1] = msg1[size1]
         *
         * { zeroPadding[32] , header[2] , time[4] , count[2] , size1[2] , msg1[n] , ... }
         *                   |<---                p_msg->read.buffer_used                 --->|
         *                                                    |<-- p_msg->read.buffer_size -->|
         */

        p_msg->read.messages_left = salti_bytes_to_u16(p_msg->read.p_buffer);
        p_msg->read.buffer_used = 0;
        p_msg->read.p_payload = &p_msg->read.p_buffer[2];

        if (p_msg->read.messages_left == 0) {
            return SALT_ERR_BAD_PROTOCOL;
        }

        uint32_t total_size = p_msg->read.buffer_size;
        uint16_t messages_left = p_msg->read.messages_left;
        uint32_t buffer_used = 0;
        uint16_t message_size;

        while (messages_left > 0) {
            message_size = salti_bytes_to_u16(p_msg->read.p_payload);
            p_msg->read.p_payload += 2 + message_size;
            buffer_used += 2 + message_size;
            if (buffer_used < total_size) {
                messages_left--;
            }
            else {
                return SALT_ERR_BAD_PROTOCOL;
            }
        }

        p_msg->read.message_size = salti_bytes_to_u16(&p_msg->read.p_buffer[2]);
        p_msg->read.p_payload = &p_msg->read.p_buffer[4];
        p_msg->read.messages_left--;
        p_msg->read.buffer_used = 4 + p_msg->read.message_size;

        break;
    default:
        return SALT_ERR_BAD_PROTOCOL;
    }

    return SALT_ERR_NONE;

}

/**
 * @brief Used internally by \ref salt_write_execute. Declared public for testability.
 *
 * Creates the final serialized clear text data after \ref salt_write_begin and
 * \ref salt_write_next have been called.
 *
 * @param p_msg         Pointer to message structure.
 *
 * @return SALT_SUCCESS The message was successfully serialized.
 * @return SALT_ERROR   p_msg was NULL.
 */
uint8_t salt_write_create(salt_msg_t *p_msg)
{

    p_msg->write.state = 1;

    if (p_msg->write.message_count == 1) {
        p_msg->write.p_buffer = &p_msg->write.p_buffer[4];
        p_msg->write.buffer_size -= (p_msg->write.buffer_available + SALT_OVERHEAD_SIZE + 4);
        p_msg->write.p_payload = &p_msg->write.p_buffer[SALT_OVERHEAD_SIZE];
        return SALT_APP_PKG_MSG_HEADER_VALUE;
    }
    else {
        salti_u16_to_bytes(&p_msg->write.p_buffer[SALT_OVERHEAD_SIZE], p_msg->write.message_count);
        p_msg->write.buffer_size -= (p_msg->write.buffer_available + SALT_OVERHEAD_SIZE);
        p_msg->write.p_payload = &p_msg->write.p_buffer[SALT_OVERHEAD_SIZE];
        return SALT_MULTI_APP_PKG_MSG_HEADER_VALUE;
    }

}

char *salt_mode2str(salt_mode_t mode)
{
    switch (mode) {
    case SALT_SERVER:
        return "SALT_SERVER";
    case SALT_CLIENT:
        return "SALT_CLIENT";
    default:
        return "UNKNOWN MODE";
    }
}

/*======= Local function implementations ====================================*/
