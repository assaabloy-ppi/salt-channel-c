#ifndef _SALT_V2_H_
#define _SALT_V2_H_

/**
 * @file salt_v2.h
 *
 * Salt channel version 2 header file. The salt-channel-c follows the specification:
 * https://github.com/assaabloy-ppi/salt-channel/blob/master/files/spec/spec-salt-channel-v2-draft4.md
 *
 * Current state is:
 *      - The time field is supported, but is never checked when received.
 *      - Resume is not supported.
 *      - Virtual hosting is not supported.
 *
 */

/*======= Includes ============================================================*/

#include <stdint.h>
#include "salt_crypto_wrapper.h"

/*======= Public macro definitions ==========================================*/

#define SALT_READ_OVERHEAD_SIZE     (38U)       /**< Encryption buffer overhead size for read. */
#define SALT_WRITE_OVERHEAD_SIZE    (42U)       /**< Encryption buffer overhead size for write. */
#define SALT_HNDSHK_BUFFER_SIZE     (502)       /**< Buffer used for handshake. */

/* Application package message header */
#define SALT_APP_PKG_MSG_HEADER_VALUE           (0x05U)
#define SALT_MULTI_APP_PKG_MSG_HEADER_VALUE     (0x0BU)

/*======= Type Definitions and declarations ===================================*/

/* Forward type declarations */
typedef struct salt_io_channel_s salt_io_channel_t;

/**
 * @brief Salt channel return codes.
 *
 */
typedef enum salt_ret_e {
    SALT_SUCCESS,                   /**< Success. */
    SALT_PENDING,                   /**< Process is pending. */
    SALT_ERROR                      /**< Any error occurred. */
} salt_ret_t;

/**
 * @brief Salt channel error codes.
 *
 * Salt channel error codes set when any error occurs.
 */
typedef enum salt_err_e {
    SALT_ERR_NONE = 0,              /**< No error. */
    SALT_ERR_NULL_PTR,              /**< Null pointer error. */
    SALT_ERR_NOT_SUPPORTED,         /**< Not supported mode error. */
    SALT_ERR_NO_SIGNATURE,          /**< No signature set error. */
    SALT_ERR_SESSION_NOT_INITIATED, /**< Session not initiated when handshaking error. */
    SALT_ERR_INVALID_STATE,         /**< Invalid state error. */
    SALT_ERR_M1_TOO_SMALL,          /**< Size of M1 message to small. */
    SALT_ERR_M1_BAD_PROTOCOL,       /**< Bad protocol in M1 message. */
    SALT_ERR_M1_BAD_HEADER,         /**< Bad header in M1 message. */
    SALT_ERR_NO_SUCH_SERVER,        /**< Client included an invalid public signature key. */
    SALT_ERR_M2_TOO_SMALL,          /**< Size of M2 message to small. */
    SALT_ERR_M2_BAD_HEADER,         /**< Vad header in M2 message. */
    SALT_ERR_M3M4_WRONG_SIZE,       /**< Bad size of M3/M4 message. */
    SALT_ERR_COMMON_KEY,            /**< Common key calculation error. */
    SALT_ERR_SIGNING,               /**< Signing error. */
    SALT_ERR_ENCRYPTION,            /**< Encryption error. */
    SALT_ERR_DECRYPTION,            /**< Decryption error. */
    SALT_ERR_BAD_SIGNATURE,         /**< Signature verification failed. */
    SALT_ERR_BUFF_TO_SMALL,         /**< I/O Buffer to small. */
    SALT_ERR_BAD_PROTOCOL,          /**< Package doesn't follow specification. */
    SALT_ERR_IO_WRITE,              /**< Error occured during I/O. */
    SALT_ERR_TIMEOUT,
    SALT_ERR_CONNECTION_CLOSED,
} salt_err_t;


/**
 * @brief Salt channel modes.
 *
 * The salt channel can be used as either server (host) or client.
 *
 */
typedef enum salt_mode_e {
    SALT_SERVER = 0,                /**< Server/host mode. */
    SALT_CLIENT,                    /**< Client mode. */
} salt_mode_t;

/**
 * @brief Salt channel state.
 *
 * These states are used internally during the handshake procedure.
 * After the handshake, the state should always be SALT_SESSION_ESTABLISHED.
 */
typedef enum salt_state_e {
    SALT_CREATED = 0,
    SALT_SIGNATURE_SET,
    SALT_SESSION_INITIATED,
    SALT_A1_IO,
    SALT_A1_HANDLE,
    SALT_M1_HANDLE,
    SALT_A2_HANDLE,
    SALT_A2_IO,
    SALT_M1_IO,
    SALT_M2_INIT,
    SALT_M2_IO,
    SALT_M2_HANDLE,
    SALT_M3_INIT,
    SALT_M3_IO,
    SALT_M3_HANDLE,
    SALT_M4_IO,
    SALT_M4_HANDLE,
    SALT_SESSION_ESTABLISHED,
} salt_state_t;

/**
 * Internal states used for the read and write functionality.
 */
typedef enum salt_io_state_e {
    SALT_IO_READY,
    SALT_IO_SIZE,
    SALT_IO_PENDING
} salt_io_state_t;

/**
 * @brief Function for dependency injection to make the salt channel available for
 * Any I/O channel.
 *
 * The I/O channel may be blockable or non-blockable. If using a non-blockable
 * I/O channel the implementations of the channels must return SALT_PENDING
 * until all bytes are transfered. Then, the function must return SALT_SUCCESS.
 *
 * p_channel->size_expected     <- Number of bytes expected
 * p_channel->size              <- Number of bytes written/read
 *
 * If any error occurs the function must return SALT_ERROR and the error code
 * must be reported in p_channel->err_code. When implementing the read channel,
 * the function must only return SALT_SUCCESS when p_channel->size_expected == p_channel.size.
 *
 *
 * @param p_channel    Pointer to I/O channel structure.
 *
 * @return SALT_SUCCESS The data was successfully written.
 * @return SALT_PENDING The writing process is still pending.
 * @return SALT_ERROR   The data could not be written. Error code is reported
 *                      in p_wchannel->err_code.
 */
typedef salt_ret_t (*salt_io_impl)(salt_io_channel_t *p_channel);

struct salt_io_channel_s {
    void            *p_context;                         /**< Pointer to I/O channel context. */
    uint8_t         *p_data;                            /**< Pointer to data to read/write. */
    uint32_t        size;                               /**< Size of data written or size of data read. */
    uint32_t        size_expected;                      /**< Expected size to read or be written. TODO: Rename to "wanted/requested" */
    uint32_t        max_size;                           /**< Maximum size of data to read (used internally). */
    salt_err_t      err_code;                           /**< Error code. */
    salt_io_state_t state;                              /**< I/O channel state. */
};

/**
 * @brief Function to receive current time stamp implementation.
 *
 * If a clock is present, a get time implementation can be provided. The time returned must be in
 * milliseconds. The time may prevents "delay"-attacks. The range of the time is [0:2^32-1].
 *
 * @param p_time    Pointer where current time will be copied to.
 */
typedef void (*salt_time_impl)(uint32_t *p_time);

/**
 * Supported protocol of salt-channel. The user support what protocols is used by the
 * salt-channel. Usage (After creation of salt-channel):
 *
 *  salt_protocol_t supported_protocols[] = {
 *      "Echo------",
 *      "Temp------",
 *      "Sensor----"
 *  };
 *
 *  salt_protocols_t my_protocols = {
 *       3,
 *      supported_protocols
 *  };
 *
 *  channel.p_protocols = &my_protocols;
 *
 *  When the client sends an A1 request the following will be the response:
 *  Response = {
 *      "SC2-------",
 *      "Echo------",
 *      "SC2-------",
 *      "Temp------",
 *      "Sensor----"
 *  }
 *
 */
typedef char salt_protocol_t[10];

typedef struct salt_protocols_s {
    uint8_t count;
    salt_protocol_t *p_protocols;
} salt_protocols_t;

/**
 * @brief Salt channel structure.
 *
 */
typedef struct salt_channel_s {
    salt_mode_t     mode;                               /**< Salt channel mode CLIENT/HOST. */
    salt_state_t    state;                              /**< Salt channel state. */
    salt_state_t    next_state;                         // TODO: Check if used
    salt_err_t      err_code;                           /**< Latest error code. */

    /* Encryption and signature stuff */
    uint8_t     ek_common[crypto_box_BEFORENMBYTES];    /**< Symmetric session encryption key. */
    uint8_t     peer_sk_pub[crypto_sign_PUBLICKEYBYTES];/**< Peer public signature key. */
    uint8_t     my_sk_sec[crypto_sign_SECRETKEYBYTES];  /**< My secret signature key. */
    uint8_t     *my_sk_pub;                             /**< My public signature key, points to &my_sk_sec[32]. */
    uint8_t     write_nonce[crypto_box_NONCEBYTES];     /**< Write nonce. */
    uint8_t     read_nonce[crypto_box_NONCEBYTES];      /**< Read nonce. */
    uint8_t     write_nonce_incr;                       /**< Write nonce increment. */
    uint8_t     read_nonce_incr;                        /**< Read nonce increment. */

    /* Time checking stuff */
    uint32_t    my_epoch;
    uint32_t    peer_epoch;
    uint32_t    time_supported;
    uint32_t    timeout;

    salt_io_channel_t   write_channel;                  /**< Write channel structure. */
    salt_io_impl        write_impl;                     /**< Function pointer to write implementation. */
    salt_io_channel_t   read_channel;                   /**< Read channel structure. */
    salt_io_impl        read_impl;                      /**< Function pointer to read implementation. */

    salt_time_impl      time_impl;                      /**< Function pointer to get time implementation. */
    salt_protocols_t    *p_protocols;                   /**< Function pointer to get supported protocols. */

    uint8_t     *hdshk_buffer;                          /**< TODO: Consider making a struct for read- and maintainability. */
    uint32_t    hdshk_buffer_size;
} salt_channel_t;

/**
 * @brief Structure used for easier creating/reading messages.
 * Specially used when writing/reading multi app packets.
 *
 */

typedef union salt_msg_u {
    struct {
        uint8_t     *p_buffer;      /**< Message buffer. */
        uint8_t     *p_message;     /**< Pointer to current message. */
        uint32_t    buffer_size;    /**< Message buffer size. */
        uint32_t    buffer_used;
        uint16_t    messages_left;  /**< Number of messages left to read. */
        uint16_t    message_size;   /**< Current message size. */
    } read;
    struct {
        uint8_t     *p_buffer;      /**< Message buffer. */
        uint8_t     *p_message;     /**< Pointer to current message. */
        uint32_t    buffer_size;    /**< Message buffer size. */
        uint32_t    buffer_used;
        uint16_t    message_count;  /**< Number of messages left to read. */
        uint16_t    state;           /**< Current message type. */
    } write;
} salt_msg_t;

/*======= Public function declarations ========================================*/

/**
 * @brief Creates a new salt channel.
 *
 *
 * @param p_channel     Pointer to channel handle.
 * @param mode          Salt channel mode { SALT_SERVER, SALT_HOST }
 * @param read_impl     User injected read implementation.
 * @param write_impl    Used injected write implementation.
 * @param time_impl     User injected get time implementation, may be NULL.
 *
 * @return SALT_SUCCESS The salt channel was successfully initiated.
 * @return SALT_ERROR   Any input pointer was a NULL pointer or invalid salt mode.
 *
 */
salt_ret_t salt_create(
    salt_channel_t *p_channel,
    salt_mode_t mode,
    salt_io_impl write_impl,
    salt_io_impl read_impl,
    salt_time_impl time_impl);

/**
 * @brief Sets the context passed to the user injected read implementation.
 *
 * @param p_channel         Pointer to channel handle.
 * @param p_write_context   Pointer to write context.
 * @param p_read_context    Pointer to read context.
 *
 * @return SALT_SUCCESS The context was successfully set.
 * @return SALT_ERROR   Any input pointer was a NULL pointer.
 */
salt_ret_t salt_set_context(
    salt_channel_t *p_channel,
    void *p_write_context,
    void *p_read_context);

/**
 * @brief Request information about protocols supported by host.
 * @details The client may ask the host what protocols are supported by using
 *          salt_a1a1. The A1/A2 is considered as a small session that ends
 *          after the host has responded to the A1 request.
 *
 *          The salt channel must have been created before using this command and may
 *          only be used after a session have been initiated.
 *
 *
 * Usage:
 *      uint8_t protocols_supported[400];
 *      uint32_t protocols_size = sizeof(protocols_supported);
 *      salt_protocols_t protocols;
 *      salt_ret_t ret_code = salt_a1a2(&channel, protocols_supported, protocols_size, &protocols);
 *      if (ret_code == SALT_SUCCESS) {
 *          printf("Supported protocol:\r\n");
 *          for (uint8_t i = 0; i < host_protocols.count; i+= 2) {
 *              printf("Salt channel version: %*.*s\r\n", 0, 10, protocols.p_protocols[i]);
 *              printf("With protocol: %*.*s\r\n", 0, 10, protocols.p_protocols[i+1]);
 *          }
 *      } else {
 *          // Pending or error
 *      }
 *
 *
 * @param p_channel Pointer to channel handle.
 * @param p_buffer  Buffer where to put the supported protocols.
 * @param p_size    Maximum size of buffer.
 * @return p_size   Size of supported protocols responded from host.
 * @return [description]
 */
salt_ret_t salt_a1a2(salt_channel_t *p_channel,
                     uint8_t *p_buffer,
                     uint32_t size,
                     salt_protocols_t *p_protocols);

/**
 * @brief Sets the signature used for the salt channel.
 *
 * @param p_channel     Pointer to channel handle.
 * @param p_signature   Pointer to signature. Must be crypto_sign_SECRETKEYBYTES bytes long.
 *
 * @return SALT_SUCCESS The A1 was sent successfully and the A2 was received successfully.
 * @return SALT_PENDING The A1/A2 session is still pending.
 * @return SALT_ERROR   If any error occured.
 */
salt_ret_t salt_set_signature(salt_channel_t *p_channel,
                              const uint8_t *p_signature);

/**
 * @brief Creates and sets the signature used for the salt channel.
 *
 * @param p_channel Pointer to channel handle.
 *
 * @return SALT_SUCCESS The signature was successfully set.
 * @return SALT_ERROR   Any input pointer was a NULL pointer.
 */
salt_ret_t salt_create_signature(salt_channel_t *p_channel);

/**
 * @brief Initiates a new salt session.
 *
 * A new ephemeral key pair is generated and the read and write nonce
 * is reseted.
 *
 * @param p_channel         Pointer to channel handle.
 * @param hdshk_buffer      Pointer to buffer used for handsize. Must be at least
 *                          SALT_HNDSHK_BUFFER_SIZE bytes large.
 * @param hdshk_buffer_size Size of the handshake buffer.
 *
 * @return SALT_SUCCESS The session was successfully initiated.
 * @return SALT_ERROR   The channel handle was a NULL pointer.
 *
 */
salt_ret_t salt_init_session(salt_channel_t *p_channel,
                             uint8_t *hdshk_buffer,
                             uint32_t hdshk_buffer_size);

salt_ret_t salt_set_timeout(salt_channel_t *p_channel, uint32_t timeout);

/**
 * @brief Salt handshake process.
 *
 * A state matchine that excecutes the salt handshaking process. If the user injected
 * I/O methods (See @p salt_write_impl, @p read_impl) are blocking, the function will run
 * through the whole handshaking process in one call. Otherwise, the function must be polled.
 *
 * @param p_channel Pointer to salt channel handle.
 *
 * @return SALT_SUCCESS When the handshake process is completed.
 * @return SALT_PENDING When the handshake process is still pending.
 * @return SALT_ERROR   If any error occured during the handshake process. At this time the session should be ended.
 *
 */
salt_ret_t salt_handshake(salt_channel_t *p_channel);

/**
 * @brief Reads one or more encrypted messages.
 *
 *
 * Usage: See example at \ref salt_read_next
 *
 * @param p_channel     Pointer to salt channel handle.
 * @param p_buffer      Pointer where to store received (clear text) data.
 * @param buffer_size   Size of p_buffer, must be greater or equal to SALT_READ_OVERHEAD_SIZE.
 * @param p_msg         Pointer to message structure to use when reading the message.
 *
 *
 * @return SALT_SUCCESS A message was successfully received.
 * @return SALT_PENDING The receive process is still pending.
 * @return SALT_ERROR   If any error occured during the read.
 */
salt_ret_t salt_read_begin(salt_channel_t *p_channel,
                           uint8_t *p_buffer,
                           uint32_t buffer_size,
                           salt_msg_t *p_msg);

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
                          salt_msg_t *p_msg);


/**
 * @brief Used to read messages recevied.
 *
 * Used to read single and multiple application packages. Due to encryption overhead
 * the longest clear text message that can be received is SALT_READ_OVERHEAD_SIZE smaller
 * than the provided receive buffer.
 *
 * Example code:
 *
 *      uint8_t buffer[256];
 *      salt_msg_t msg;
 *      salt_ret_t ret;
 *      do {
 *          ret = salt_read_begin(&channel, buffer, sizeof(buffer), &msg);
 *      } while (ret == SALT_PENDING);
 *
 *      if (ret == SALT_SUCCESS) {
 *
 *          printf("Recevied %d messages:\r\n", msg.messages_left + 1);
 *
 *          do {
 *              printf("%*.*s\r\n", 0, msg.message_size, (char*) msg.p_message);
 *          } while (salt_read_next(&msg) == SALT_SUCCESS);
 *
 *      } else {
 *          printf("Error during reading:\r\n");
 *          printf("Salt error: 0x%02x\r\n", channel.err_code);
 *          printf("Salt error read: 0x%02x\r\n", channel.read_channel.err_code);
 *      }
 *
 * @param p_channel Pointer to salt channel handle.
 * @param p_msg     Pointer to message structure.
 *
 * @return SALT_SUCCESS The next message could be parsed and ready to be read.
 * @return SALT_ERROR   No more messages available.
 */
salt_ret_t salt_read_next(salt_msg_t *p_msg);

/**
 * @brief Write encrypted messages
 *
 * One or more messages can be sent using one encrypted message. Due to encryption
 * overhead the size of a single clear text message can not be larger than the
 * provided send buffer - SALT_WRITE_OVERHEAD_SIZE.
 *
 * The content of p_buffer will be modified during the authenticated encryption.
 *
 * Usage: See example at \ref salt_write_execute
 *
 * @param p_buffer  Pointer where to store received (clear text) data.
 * @param size      Size of clear text message to send.
 * @param p_msg     Pointer to message state structure.
 *
 * @return SALT_SUCCESS Message state structure was initialized.
 * @return SALT_ERROR   Bad buffer size or bad state of channel session.
 *
 */
salt_ret_t salt_write_begin(uint8_t *p_buffer,
                            uint32_t size,
                            salt_msg_t *p_msg);

salt_err_t salt_write_init(uint8_t *p_buffer,
                           uint32_t size,
                           salt_msg_t *p_msg);

/**
 * @brief Add a clear text message to next encrypted package.
 *
 * If this function is called more than once after \ref salt_write_begin all
 * following clear text packages will be sent as one encrypted package.
 *
 * @param p_msg     Pointer to message state structure.
 * @param p_buffer  Pointer to clear text message.
 * @param size      Size of clear text message.
 *
 * @return SALT_SUCCESS A message was successfully appended to the state structure.
 * @return SALT_ERROR   The message was to large to fit in the state structure.
 *
 */
salt_ret_t salt_write_next(salt_msg_t *p_msg,
                           uint8_t *p_buffer,
                           uint16_t size);

/**
 * @brief Encrypts and send the messages prepared in \ref salt_write_begin and \ref salt_write_next
 *
 * The prepared message state structure will be encrypted and send to the other peer.
 * This routine will modify the data in the buffer of p_msg->p_buffer.
 *
 * Usage:
 *
 *      uint8_t tx_buffer[256];
 *      salt_msg_t tx_msg;
 *      salt_ret_t ret;
 *
 *      ret = salt_write_begin(tx_buffer, sizeof(tx_buffer), &tx_msg);
 *      if (ret == SALT_ERROR) {
 *          // Invalid size of tx_buffer, must be at least SALT_WRITE_OVERHEAD_SIZE bytes large.
 *      }
 *
 *      ret = salt_write_next(&tx_msg, "My first message", 16);
 *      if (ret == SALT_ERROR) {
 *          // tx_buffer is full
 *      }
 *
 *      ret = salt_write_next(&tx_msg, "My second message", 17);
 *      if (ret == SALT_ERROR) {
 *          // tx_buffer is full
 *      }
 *
 *      do {
 *          ret = salt_write_execute(&channel, &msg);
 *      } while (ret == SALT_PENDING);
 *
 *      if (ret == SALT_ERROR) {
 *          printf("Error during writing:\r\n");
 *          printf("Salt error: 0x%02x\r\n", channel.err_code);
 *          printf("Salt error read: 0x%02x\r\n", channel.write_channel.err_code);
 *      }
 *
 * @param p_channel     Pointer to salt channel handle.
 * @param p_msg         Pointer to message structure.
 *
 * @return SALT_SUCCESS A message was successfully sent.
 * @return SALT_PENDING The sending process is still pending.
 * @return SALT_ERROR   If any error occured during the sending process.
 */
salt_ret_t salt_write_execute(salt_channel_t *p_channel,
                              salt_msg_t *p_msg);

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
uint8_t salt_write_create(salt_msg_t *p_msg);


#endif /* _SALT_V2_H_ */
