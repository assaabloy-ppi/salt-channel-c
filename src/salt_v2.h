#ifndef _SALT_V2_H_
#define _SALT_V2_H_

/**
 * @file salt_v2.h
 *
 * Salt channel version 2 header file.
 *
 */

/*======= Includes ============================================================*/
#include <stdint.h>
#include "salt_crypto_wrapper.h"

/*======= Public macro definitions ==========================================*/
#define SALT_OVERHEAD_SIZE          (32U)       /**< Encryption buffer overhead size. */
#define SALT_HNDSHK_BUFFER_SIZE     (200U)      /**< Buffer used for handshake. */


/*======= Type Definitions and declarations ===================================*/

/* Forward type declarations */
typedef struct salt_io_channel_s salt_io_channel_t;

/**
 * @brief Salt channel return codes.
 *
 */
typedef enum salt_ret_s {
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
    SALT_ERR_M2_TOO_SMALL,
    SALT_ERR_BAD_PROTOCOL,          /**< Bad protocol in M1 message. */
    SALT_ERR_BAD_M1_HEADER,         /**< Bad header in M1 message. */
    SALT_ERR_COMMON_KEY,            /**< Common key calculation error. */
    SALT_ERR_SIGNING,               /**< Signing error. */
    SALT_ERR_ENCRYPTION,            /**< Encryption error. */
    SALT_ERR_DECRYPTION,            /**< Decryption error. */
    SALT_ERR_BAD_SIGNATURE,         /**< Signature verification failed. */
    SALT_ERR_BUFF_TO_SMALL          /**< I/O Buffer to small. */
} salt_err_t;

/**
 * @brief Salt channel modes.
 *
 * The salt channel can be used as either server (host) or client.
 *
 * If stream mode is used, a four byte size array is serialized and
 * put into the array passed to the I/O implementations.
 *
 */
typedef enum salt_mode_e {
    SALT_SERVER = 0,                    /**< Server/host mode. */
    SALT_SERVER_STREAM,             /**< Server/host stream mode. */
    SALT_CLIENT,                    /**< Client mode. */
    SALT_CLIENT_STREAM              /**< Client stream mode. */
} salt_mode_t;

/**
 * @brief Salt channel state.
 */
typedef enum salt_state_e {
    SALT_CREATED = 0,
    SALT_SIGNATURE_SET,
    SALT_SESSION_INITIATED,
    SALT_WAIT_FOR_INCOMING_MSG_INIT,
    SALT_WAIT_FOR_INCOMING_MSG_IO,
    SALT_WAIT_FOR_OUTGOING_MSG_INIT,
    SALT_WAIT_FOR_OUTGOING_MSG_IO,
    SALT_M1_INIT,
    SALT_M1_IO,
    SALT_M1_HANDLE,
    SALT_M2_INIT,
    SALT_M2_IO,
    SALT_M2_VERIFY,
    SALT_M3_INIT,
    SALT_M3_IO,
    SALT_M3_VERIFY,
    SALT_M4_INIT,
    SALT_M4_IO,
    SALT_M4_VERIFY,
    SALT_SESSION_ESTABLISHED,
    SALT_ERROR_STATE
} salt_state_t;

/**
 * @brief Function for dependency injection to make the salt channel available for
 * Any I/O channel.
 *
 * The I/O channel may be blockable or non-blockable. If using a non-blockable
 * I/O channel the implementations of the channels must return SALT_PENDING
 * until all bytes are transfered. Then, the function must return SALT_SUCCESS.
 *
 * If any error occurs the function must return SALT_ERROR and the error code
 * must be reported in p_wchannel->err_code.
 *
 * @param p_wchannel    Pointer to I/O channel structure.
 *
 * @return SALT_SUCCESS The data was successfully written.
 * @return SALT_PENDING The writing process is still pending.
 * @return SALT_ERROR   The data could not be written. Error code is reported
 *                      in p_wchannel->err_code.
 */
typedef salt_ret_t (*salt_io_impl)(salt_io_channel_t *p_channel);

struct salt_io_channel_s {
    void        *p_context;                             /**< Pointer to I/O channel context. */
    uint8_t     state;                                  /**< I/O channel state. */    
    uint8_t     *p_data;                                /**< Pointer to data to read/write. */
    uint32_t    size;                                   /**< Size of data to write or size of data read. */
    uint32_t    max_size;                               /**< Maximum size of data to read. */
    salt_err_t  err_code;                               /**< Error code. */
};

/**
 * @brief Salt channel structure.
 *
 */
typedef struct salt_channel_s {
    salt_mode_t     mode;                               /**< Salt channel mode. */
    salt_state_t    state;                              /**< Salt channel state. */
    salt_err_t      err_code;                           /**< Latest error code. */

    /* Encryption and signature stuff */
    uint8_t     my_ek_sec[crypto_box_SECRETKEYBYTES];   /**< Ephemeral secret encryption key. */
    uint8_t     my_ek_pub[crypto_box_PUBLICKEYBYTES];   /**< Ephemeral public encrypion key. */
    uint8_t     peer_ek_pub[crypto_box_PUBLICKEYBYTES]; /**< Peer public encryption key. */
    uint8_t     ek_common[crypto_box_BEFORENMBYTES];    /**< Symmetric session encryption key. */
    uint8_t     peer_sk_pub[crypto_sign_PUBLICKEYBYTES];/**< Peer public signature key. */
    uint8_t     my_sk_sec[crypto_sign_SECRETKEYBYTES];  /**< My secret signature key. */
    uint8_t     *my_sk_pub;                             /**< My public signature key, points to &my_sk_sec[32]. */
    uint8_t     write_nonce[crypto_box_NONCEBYTES];     /**< Write nonce. */
    uint8_t     read_nonce[crypto_box_NONCEBYTES];      /**< Read nonce. */
    uint8_t     write_nonce_incr;                       /**< Write nonce increment. */
    uint8_t     read_nonce_incr;                        /**< Read nonce increment. */

    salt_io_channel_t   write_channel;                  /**< Write channel structure. */
    salt_io_impl        write_impl;                     /**< Function pointer to write implementation. */
    salt_io_channel_t   read_channel;                   /**< Read channel structure. */
    salt_io_impl        read_impl;                      /**< Function pointer to read implementation. */

    uint8_t     *hdshk_buffer;
    uint32_t    hdshk_buffer_size;
} salt_channel_t;

/*======= Public function declarations ========================================*/

/**
 * @brief Creates a new salt channel.
 *
 *
 * @param p_channel     Pointer to channel handle.
 * @param mode          Salt channel mode { SALT_SERVER, SALT_HOST }
 * @param read_impl     User injected read implementation.
 * @param write_impl    Used injected write implementation.
 *
 * @return SALT_SUCCESS The salt channel was successfully initiated.
 * @return SALT_ERROR   Any input pointer was a NULL pointer or invalid salt mode.
 *
 */
salt_ret_t salt_create(
   salt_channel_t *p_channel,
   salt_mode_t mode,
   salt_io_impl write_impl,
   salt_io_impl read_impl);

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
 * @brief Sets the signature used for the salt channel.
 *
 * @param p_channel     Pointer to channel handle.
 * @param p_signature   Pointer to signature. Must be crypto_sign_SECRETKEYBYTES bytes long.
 *
 * @return SALT_SUCCESS The signature was successfully set.
 * @return SALT_ERROR Any input pointer was a NULL pointer.
 */
salt_ret_t salt_set_signature(salt_channel_t *p_channel, const uint8_t *p_signature);

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
salt_ret_t salt_init_session(salt_channel_t *p_channel, uint8_t *hdshk_buffer, uint32_t hdshk_buffer_size);

/**
 * @brief Salt handshake process.
 *
 * See TODO: Address to specification
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
 * @brief Read an encrypted message.
 *
 * Reads and decrypts an encrypted message into the buffer p_buffer.
 * The maximum length of the clear text message will be max_size - SALT_OVERHEAD_SIZE.
 *
 * @param p_channel     Pointer to salt channel handle.
 * @param p_buffer      Pointer where to store received (clear text) data.
 * @param p_recv_size   Pointer where to store size of received message.
 * @param max_size      Maxiumum allowed size to read.
 *
 * @return SALT_SUCCESS A message was successfully received.
 * @return SALT_PENDING The receive process is still pending.
 * @return SALT_ERROR   If any error occured during the read.
 *
 */
salt_ret_t salt_read(salt_channel_t *p_channel, uint8_t *p_buffer, uint32_t *p_recv_size, uint32_t max_size);

/**
 * @brief Write an encrypten message.
 *
 * The encryption process requires the first SALT_OVERHEAD_SIZE bytes of the buffer p_buffer
 * to be 0 (zero) padded. I.e, the user MUST NOT put any of the clear text data into the first
 * SALT_OVERHEAD_SIZE bytes.
 *
 * The message must have the following format:
 *
 * p_buffer: |<- Reserved [SALT_OVERHEAD_SIZE] >|<- Clear text data [size] ->|
 *
 * I.e, the length of p_buffer must be size + SALT_OVERHEAD_SIZE bytes long.
 *
 * Example code:
 *
 *      char buffer[256];
 *      size_t size;
 *      size = sprintf(&buffer[SALT_OVERHEAD_SIZE], "This is an encrypted message!");
 *      salt_write(&channel, (uint8_t *) buffer, size);
 *
 * The user is however not required to memset the 32 bytes to 0, this
 * is done by the salt channel.
 *
 * @param p_channel Pointer to salt channel handle.
 * @param p_buffer  Pointer where to store received (clear text) data.
 * @param size      Size of clear text message to send.
 *
 * @return SALT_SUCCESS A message was successfully sent.
 * @return SALT_PENDING The sending process is still pending.
 * @return SALT_ERROR   If any error occured during the sending process.
 *
 */
salt_ret_t salt_write(salt_channel_t *p_channel, uint8_t *p_buffer, uint32_t size);

#endif /* _SALT_V2_H_ */
