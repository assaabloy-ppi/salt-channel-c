#ifndef _SALT_V2_H_
#define _SALT_V2_H_

/**
 * @file salt_v2.h
 *
 * Salt channel version 2 header file.
 *
 */

/*======= Includes ==========================================================*/
#include <stdint.h>
#include "salt_crypto_wrapper.h"

/*======= Public macro definitions ==========================================*/
#define SALT_OVERHEAD_SIZE (32U)    /**< Encryption buffer overhead size. */

/*======= Type Definitions and declarations =================================*/

/* Forward type declarations */
typedef struct salt_write_channel_s salt_write_channel_t;
typedef struct salt_read_channel_s salt_read_channel_t;

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
    SALT_ERR_NULL_PTR               /**< Null pointer error. */
} salt_err_t;

/**
 * @brief Salt channel modes.
 *
 * The salt channel can be used as either server (host) or client.
 */
typedef enum salt_mode_e {
    SALT_SERVER,                    /**< Server/host mode. */
    SALT_CLIENT                     /**< Client mode. */
} salt_mode_t;

/**
 * @brief Salt channel state.
 */
typedef enum salt_state_e {
    SALT_CREATED,
    SALT_INITIATED
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
typedef salt_ret_t (*salt_write_impl)(salt_write_channel_t *p_wchannel);

struct salt_write_channel_s {
    void                *p_context;                     /**< Pointer to write channel context. */
    uint8_t             state;                          /**< Write channel state. */    
    const void          *p_data;                        /**< Pointer to data to write. */
    uint32_t            size;                           /**< Size of data to write. */
    salt_err_t          err_code;                       /**< Error code. */
};

/**
 * @brief Function for dependency injection to make the salt channel available for
 * Any I/O channel.
 *
 * The I/O channel may be blockable or non-blockable. If using a non-blockable
 * I/O channel the implementations of the channels must return SALT_PENDING
 * until all bytes are transfered. Then, the function must return SALT_SUCCESS.
 *
 * If any error occurs the function must return SALT_ERROR and the error code
 * must be reported in p_rchannel->err_code.
 *
 * @param p_rchannel    Pointer to I/O channel structure.
 *
 * @return SALT_SUCCESS The data was successfully read.
 * @return SALT_PENDING The reading process is still pending.
 * @return SALT_ERROR   The data could not be read. Error code is reported
 *                      in p_rchannel->err_code.
 */
typedef salt_ret_t (*salt_read_impl)(salt_read_channel_t *p_rchannel);

struct salt_read_channel_s {
    void                *p_context;                     /**< Pointer to read channel context. */
    uint8_t             state;                          /**< read channel state. */    
    void                *p_data;                        /**< Pointer to where to put received data. */
    uint32_t            size;                           /**< Size of data to read. */
    salt_err_t          err_code;                       /**< Error code. */
    
};

/**
 * @brief Salt channel structure.
 *
 */
typedef struct salt_channel_s {
    salt_mode_t     mode;                               /**< Salt channel mode. */
    salt_state_t    state;                              /**< Salt channel state. */

    /* Encryption and signature stuff */
    uint8_t     my_ek_sec[crypto_box_SECRETKEYBYTES];   /**< Ephemeral secret encryption key. */
    uint8_t     my_ek_pub[crypto_box_PUBLICKEYBYTES];   /**< Ephemeral public encrypion key. */
    uint8_t     ek_common[crypto_box_BEFORENMBYTES];    /**< Symmetric session encryption key. */
    uint8_t     peer_ek_pub[crypto_sign_PUBLICKEYBYTES];/**< Peer public signature key. */
    uint8_t     my_sk_sec[crypto_sign_SECRETKEYBYTES];  /**< My secret signature key. */
    uint8_t     *my_sk_pub;                             /**< My public signature key. */
    uint8_t     write_nonce[crypto_box_NONCEBYTES];     /**< Write nonce. */
    uint8_t     read_nonce[crypto_box_NONCEBYTES];      /**< Read nonce. */

    salt_write_channel_t    write_channel;               /**< Write channel structure. */
    salt_write_impl         impl;                        /**< Function pointer to write implementation. */
    salt_read_channel_t     read_channel;                /**< Read channel structure. */
    salt_read_impl          read_impl;                   /**< Function pointer to read implementation. */
} salt_channel_t;

/*======= Public function declarations ======================================*/

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
   salt_write_impl write_impl,
   salt_read_impl read_impl);

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
 * @param p_channel Pointer to channel handle.
 *
 * @return SALT_SUCCESS The session was successfully initiated.
 * @return SALT_ERROR   The channel handle was a NULL pointer.
 *
 */
salt_ret_t salt_init_session(salt_channel_t *p_channel);

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
 * p_buffer: |<- Reserved [32] >|<- Clear text data [size] ->|
 *
 * I.e, the length of p_buffer must be size + SALT_OVERHEAD_SIZE bytes long.
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
