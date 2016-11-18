#ifndef _SALT_H
#define _SALT_H

#include <stdint.h>

#include "salt_crypto_wrapper.h"

//=====================================================================
// Public macro definitions
//=====================================================================
#define SALT_OVERHEAD      (24U)

//=====================================================================
// Type Definitions and declarations
//=====================================================================

/**
 * @brief Return codes from salt functions.
 *
 */
typedef enum {
   SALT_SUCCESS = 0,
   SALT_PENDING,
   SALT_ERROR,
   SALT_ERROR_BUFFER_TO_SMALL,
   SALT_ERROR_NULL_PTR,
   SALT_ERROR_NO_SIGNATURE,
   SALT_ERROR_SESSION_NOT_INITIATED,
   SALT_ERROR_MSG_TO_LONG,
   SALT_ERROR_MAX_SIZE_TO_LARGE,
   SALT_ERROR_ENCRYPTION_FAILED,
   SALT_ERROR_DECRYPTION_FAILED,
   SALT_ERROR_FORMAT,
   SALT_ERROR_BAD_SIGNATURE,
   SALT_ERROR_PROT_VERSION,
   SALT_ERROR_SESSION_NOT_ESTABLISHED
} salt_ret_t;

typedef enum {
   SALT_SERVER,
   SALT_CLIENT
} salt_mode_t;

/**
 * @brief Function for dependency injection to make the salt channel available for
 * Any I/O channel.
 *
 * The I/O channel may be blockable or non-blockable. If using a non-blockable
 * I/O channel the implementations of the channels must return SALT_PENDING
 * until all bytes are transfered. Then, the function must return SALT_SUCCESS.
 *
 * If any error occurs the function must return SALT_ERROR.
 *
 */
typedef salt_ret_t (*salt_io_implementation)(void *p_context, uint8_t *p_data, uint32_t length);

typedef struct {
   void                    *p_context;
   uint8_t                 state;
   uint8_t                 nonce_increment;
   uint8_t                 nonce[crypto_box_NONCEBYTES];
   uint8_t                 *p_data;
   uint32_t                size;
   salt_io_implementation  io;
} salt_io_channel_t;


/**
 * @brief Salt channel data structure.
 *
 */
typedef struct {
   uint8_t           state;
   salt_mode_t       mode;

   /* Temporary buffer used for crypto methods. */
   uint8_t           buffer_locked;
   uint8_t           *p_buffer;
   uint32_t          buffer_size;

   /* Keys used for authenticated cryptography */
   uint8_t           my_ek_sec[crypto_box_SECRETKEYBYTES];
   uint8_t           my_ek_pub[crypto_box_PUBLICKEYBYTES];
   uint8_t           peer_ek_pub[crypto_box_PUBLICKEYBYTES];
   uint8_t           ek_common[crypto_box_BEFORENMBYTES];

   /* Keys used for signatures. */
   uint8_t           my_sk_sec[crypto_sign_SECRETKEYBYTES];
   uint8_t           *my_sk_pub;
   uint8_t           peer_sk_pub[crypto_sign_PUBLICKEYBYTES];

   /* User injected I/O functions. */
   salt_io_channel_t read_channel;
   salt_io_channel_t write_channel;
} salt_channel_t;


//=====================================================================
// Public function declarations
//=====================================================================

/**
 * @brief Initiate a salt channel.
 *
 * When encrypting a message there will be a fixed overhead of
 * SALT_OVERHEAD bytes. I.e, the user must provide a temporary buffer
 * that is SALT_OVERHEAD greater than the longest message that is to be
 * sent/received.
 *
 * @param p_channel Pointer to channel handle.
 * @param p_buffer Pointer to temporary buffer used for crypto operations.
 * @param buffer_size Size of temporary buffer used for crypto operations.
 * @param read_impl User injected read implementation.
 * @param write_impl Used injected write implementation.
 *
 * @return SALT_SUCCESS The salt channel was successfully initiated.
 * @return SALT_ERROR_NULL_PTR Any input pointer was a NULL pointer.
 *
 */
salt_ret_t salt_init(
   salt_channel_t *p_channel,
   uint8_t *p_buffer,
   uint32_t buffer_size,
   salt_io_implementation read_impl,
   salt_io_implementation write_impl);

/**
 * @brief Sets the context passed to the user injected read implementation.
 *
 * @param p_channel Pointer to channel handle.
 * @return SALT_SUCCESS The context was successfully set.
 * @return SALT_ERROR_NULL_PTR Any input pointer was a NULL pointer.
 */
salt_ret_t salt_set_read_context(salt_channel_t *p_channel, void *p_context);

/**
 * @brief Sets the context passed to the user injected write implementation.
 *
 * @param p_channel Pointer to channel handle.
 *
 * @return SALT_SUCCESS The context was successfully set.
 * @return SALT_ERROR_NULL_PTR Any input pointer was a NULL pointer.
 */
salt_ret_t salt_set_write_context(salt_channel_t *p_channel, void *p_context);

/**
 * @brief Sets the signature used for the salt channel.
 * @param p_channel Pointer to channel handle.
 * @param p_signature Pointer to signature. Must be crypto_sign_SECRETKEYBYTES bytes long.
 *
 * @return SALT_SUCCESS The signature was successfully set.
 * @return SALT_ERROR_NULL_PTR Any input pointer was a NULL pointer.
 */
salt_ret_t salt_set_signature(salt_channel_t *p_channel, const uint8_t *p_signature);

/**
 * @brief Creates and sets the signature used for the salt channel.
 * @param p_channel Pointer to channel handle.
 *
 * @return SALT_SUCCESS The signature was successfully set.
 * @return SALT_ERROR_NULL_PTR Any input pointer was a NULL pointer.
 */
salt_ret_t salt_create_signature(salt_channel_t *p_channel);

/**
 * @brief Initiates a new salt session.
 *
 * A new ephemeral key pair is generated and all previous history is cleared.
 *
 * @param p_channel Pointer to channel handle.
 *
 * @return SALT_SUCCESS The session was successfully initiated.
 * @return SALT_ERROR_NULL_PTR The channel handle was a NULL pointer.
 *
 */
salt_ret_t salt_init_session(salt_channel_t *p_channel, salt_mode_t mode);

/**
 * @brief Salt handshake process.
 *
 * See https://github.com/assaabloy-ppi/pot/blob/master/src/pot/channel/package.html for 
 * description of the handshake process.
 *
 * A state matchine that excecutes the salt handshaking process. If the user injected
 * I/O methods (See @p salt_io_implementation) are blocking, the function will run
 * through the whole handshaking process in one call. Otherwise, the function must be polled.
 * The temporary buffer provided in  @p salt_init will be used for sending/receiving messages.
 *
 * @param p_channel Pointer to salt channel handle.
 *
 * @return SALT_SUCCESS When the handshake process is completed.
 * @return SALT_PENDING When the handshake process is still pending.
 * @return SALT_ERROR If any error occured during the handshake process. At this time the session should be ended.
 *
 */
salt_ret_t salt_handshake(salt_channel_t *p_channel);

/**
 * @brief Read an encrypten message.
 *
 * The maximum size of the read message is defined either by @p max_size or by the size
 * of the temporary buffer provided in @p salt_init.
 *
 * @param p_channel Pointer to salt channel handle.
 * @param p_buffer Pointer where to store received (clear text) data.
 * @param p_recv_size Pointer where to store size of received message.
 * @param max_size Maxiumum allowed size to read.
 *
 * @return SALT_SUCCESS A message was successfully received.
 * @return SALT_PENDING The receive process is still pending.
 * @return SALT_ERROR If any error occured during the read.
 *
 */
salt_ret_t salt_read(salt_channel_t *p_channel, uint8_t *p_buffer, uint32_t *p_recv_size, uint32_t max_size);

/**
 * @brief Write an encrypten message.
 *
 * The maximum size of the read message is defined by the temporary buffer provided in @p salt_init.
 *
 * @param p_channel Pointer to salt channel handle.
 * @param p_buffer Pointer where to store received (clear text) data.
 * @param size Size of message to send.
 *
 * @return SALT_SUCCESS A message was successfully sent.
 * @return SALT_PENDING The sending process is still pending.
 * @return SALT_ERROR If any error occured during the sending process.
 *
 */
salt_ret_t salt_write(salt_channel_t *p_channel, uint8_t *p_buffer, uint32_t size);


#endif
