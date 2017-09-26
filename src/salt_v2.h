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

#define SALT_OVERHEAD_SIZE          (38U)       /**< Encryption buffer overhead size. */
#define SALT_HNDSHK_BUFFER_SIZE     (502)      /**< Buffer used for handshake. */

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

    salt_io_channel_t   write_channel;                  /**< Write channel structure. */
    salt_io_impl        write_impl;                     /**< Function pointer to write implementation. */
    salt_io_channel_t   read_channel;                   /**< Read channel structure. */
    salt_io_impl        read_impl;                      /**< Function pointer to read implementation. */

    salt_time_impl      time_impl;                      /**< Function pointer to get time implementation. */
    salt_protocols_t    *p_protocols;         /**< Function pointer to get supported protocols. */

    uint8_t     *hdshk_buffer;                          /**< TODO: Consider making a struct for read- and maintainability. */
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
 * @brief Salt request resume ticket.
 *
 * If the client at some later point want to resume the session, a resume ticket could be requested.
 * The client must store the resume ticket along with the session key and with knowledge of the host.
 *
 * NOTE: Not supported yet.
 * TODO: Maxiumum tickes size is limited by 1 byte, see specification.
 *
 * Example code: Request a ticket and store it along with the session key and identity of the host.
 *
 *      uint8_t ticket[200];
 *      uint32_t ticket_size;
 *      salt_ret_t ret_code = salt_request_ticket(&channel, ticket, &ticket_size, sizeof(sicket));
 *      if (ret_code == SALT_SUCCESS) {
 *          // Application specific storage of ticket
 *          store_ticket(ticket, ticket_size, channel.peer_sk_pub, channel.ek_common):
 *      }
 *      else {
 *          // The server does not support resume feature or any other error. See channel.err_code.
 *      }
 *
 * Later when the ticket is to be reused on the host with a specific identity (public sign key):
 *
 *      See salt_resume.
 *
 * @param p_channel     Pointer to salt channel handle.
 * @param p_ticket      Pointer where to store the received ticket.
 * @param p_ticket_size Pointer where to store size of received ticket.
 * @param max_size      Maxiumum allowed size of ticket.
 *
 * @return SALT_SUCCESS A resume ticket was successfully received.
 * @return SALT_PENDING The receive process is still pending.
 * @return SALT_ERROR   If any error occured.
 *
 */
salt_ret_t salt_request_ticket(salt_channel_t *p_channel,
                               uint8_t *p_ticket,
                               uint32_t *p_ticket_size,
                               uint32_t max_size);

/**
 * @brief Salt resume process using a ticket.
 *
 * If the client at a previous point has requested a resume ticket, we could try to
 * resume the session using this. The resume ticket must be stored along with the
 * symmetric session encryption key.. The client does not need to know anything specific
 * about the ticket (except whom it belongs to). This is only supported in SALT_CLIENT mode.
 *
 * NOTE: Not supported yet.
 * 
 * Example code:
 *
 *      uint8_t host_identity[32];
 *      uint8_t *p_ticket;
 *      uint32_t ticket_size;
 *      uint8_t *session_key;
 *      load_ticket(host_identity, &p_ticket, &ticket_size, &session_key);
 *      salt_ret_t = salt_resume(&channel, host_identity, p_ticket, ticket_size, session_key);
 *      if (salt_ret_t == SALT_ERROR)
 *      {
 *          // Wrong host, bad ticket or any other error. See channel.err_code.
 *      }
 *      // Do read and write stuff
 *
 * @param p_channel     Pointer to salt channel handle.
 * @param p_host        Pointer to host public sign key (identity).
 * @param p_ticket      Pointer to ticket to use.
 * @param ticket_size   Size of ticket.
 * @param session_key   Pointer to symmetric session key.
 *
 * @return SALT_SUCCESS A resume ticket was successfully received.
 * @return SALT_PENDING The receive process is still pending.
 * @return SALT_ERROR   If any error occured.
 *
 */
salt_ret_t salt_resume(salt_channel_t *p_channel,
                       uint8_t *p_host,
                       uint8_t *p_ticket,
                       uint32_t ticket_size,
                       uint8_t *session_key);

/**
 * @brief Read an encrypted message.
 *
 * Reads and decrypts an encrypted message into the buffer p_buffer.
 * The maximum length of the clear text message will be max_size - SALT_OVERHEAD_SIZE.
 * The returned size in p_recv_size will be the size of the clear text data.
 *
 * Depending on implementation of the used injected I/O function, the salt_read function
 * is blocking or non-blocking. If the reading is in process the return code will be SALT_PENDING.
 *
 * Example code:
 *
 *      char buffer[256];
 *      uint32_t clear_text_size;
 *      salt_ret_t ret_code = salt_read(&channel, buffer, &clear_text_size, 256);
 *      if (ret_code == SALT_SUCCESS)
 *      {
 *          printf("%*.*s\r\n", 0, clear_text_size, &buffer[SALT_OVERHEAD_SIZE]);
 *      }
 *      else {
 *          prtinf("Salt read error: 0x%x\r\n", channel.err_code);
 *      }
 *
 * @param p_channel     Pointer to salt channel handle.
 * @param p_buffer      Pointer where to store received (clear text) data.
 * @param p_recv_size   Pointer where to store size of received message.
 * @param max_size      Size of p_buffer.
 *
 * @return SALT_SUCCESS A message was successfully received.
 * @return SALT_PENDING The receive process is still pending.
 * @return SALT_ERROR   If any error occured during the read.
 *
 */
salt_ret_t salt_read(salt_channel_t *p_channel,
                     uint8_t *p_buffer,
                     uint32_t *p_recv_size,
                     uint32_t max_size);

/**
 * @brief Write an encrypten message.
 *
 * The encryption process requires the first SALT_OVERHEAD_SIZE bytes of the buffer p_buffer
 * to be 0 (zero) padded. I.e, the user MUST NOT put any of the clear text data into the first
 * SALT_OVERHEAD_SIZE bytes.
 *
 * Depending on implementation of the used injected I/O function, the salt_write function
 * is blocking or non-blocking. If the writing is in process the return code will be SALT_PENDING.
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
 *      salt_ret_t ret_code = salt_write(&channel, (uint8_t *) buffer, size + SALT_OVERHEAD_SIZE);
 *      if (ret_code != SALT_SUCCESS) {
 *          prtinf("Salt write error: 0x%x\r\n", channel.err_code);
 *      }
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
salt_ret_t salt_write(salt_channel_t *p_channel,
                      uint8_t *p_buffer,
                      uint32_t size);

#endif /* _SALT_V2_H_ */
