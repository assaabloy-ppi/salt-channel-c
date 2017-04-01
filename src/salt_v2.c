/**
 * @file salt_v2.c
 *
 * Salt channel version 2 implementation.
 *
 * Server:
 *     1. Received M1.
 *     
 *      M1 is received at the begining of the handshake buffer. The size of
 *      M1 is 42 <= M1 <= 74 + (optional 1 + ticket size). If the M1 message
 *      had correct format the hash of the message (later used for auth) is
 *      saved in the beginning of handshake buffer.
 *          
 *      - Read M1 to hdshk_buffer[0]
 *      - Verify M1
 *      - Put hash of M1 in hdshk_buffer[0:63]
 *          
 *      The maximum size of M1 can here be 74 + 1 + 255 = 330. The maximum size of the
 *      resume ticket fits only in one byte.
 *          
 *     2. Creates M2.
 *     
 *      M2 is created in the handshake buffer at offset 128. This is due to
 *      that the hash of M2 is later saved in the handshake buffer[64:127].
 *          
 *      - Create M2 to hdshk_buffer[128]
 *      - Put hash of M2 to hdshk_buffer[64:127]
 *          
 *      The maximum size of M2 is 38 bytes. The first four bytes of M2 will
 *      be the size of M2, therefore 42 bytes are actually used.
 *          
 *      M2Msg[42] = { 0x26 , 0x00[3] , M2Msg[38] }
 *
 *     3. Start sending M2
 *     
 *      After M2 is creater, the server initiate sending of M2. The I/O
 *      might be slow, so while waiting for M2, the server calculates the
 *      shared secret and starts creating M3.
 *          
 *     4. Calculate the shared secret (symmetric encryption key)
 *          
 *     5. Create M3.
 *     
 *      The M3 message is encrypted and the crypto API requires the 32 first
 *      bytes of the clear text to be zero padded. Therefore, M3 is created
 *      at hdshk_buffer[128 + 42 + 32] = hdshk_buffer[202].
 *          
 *      When creating M3, the hashes of M1 and M2 are signed. The routine is
 *      this:
 *          
 *      - Create header and timestamp of M3 at hdshk_buffer[128 + 42 + 32].
 *        The size of the header and the timestamp is 6 bytes.
 *      - Sign the hash, put it after the header and timestamp. Now we have
 *        the following format in the buffer:
 *        M3Msg = hdshk_buffer[128 + 42 + 32] = hdshk_buffer[202]
 *        M3Msg[0:1]    = M3 header
 *        M3Msg[2:5]    = Timestamp
 *        M3Msg[6:38]   = hostSigKey
 *        M3Msg[38:166] = { sig({hash(M1),hash(M2)}) , hash(M1), hash(M2) }
 *            
 *        The hash(M1), hash(M2) is at this point known by the client and
 *        is therefor not sent. I.e., size(M3Msg) = 2 + 6 + 32 + 64 = 104.
 *        We now have the format
 *        hdshk_buffer[170:273] = { 0x00[32] , M3Msg[104] }
 *            
 *        This message is now encrypted:
 *        AuthEncryptedM3Msg = { 0x00[16] , HMAC[16] , EncryptedM3Msg[104] }
 *        After this the size of AuthEncryptedM3Msg is written before the
 *        HMAC bytes. I.e., we send to the client:
 *        AuthEncryptedM3Msg[124] = { 0x78 , 0x00[3] , AuthEncryptedM3Msg[120] }
 *        
 *        This message is placed in hdshk_buffer[182:306]
 *        
 *       6. M4 is received.
 *       
 *        This message will not be received before the client
 *        has recieved and verified the M3 message. We need the hashes of M1
 *        and M2 to verify the signature received in the M4 message. The M4
 *        message is encrypted and the crypto API requires the first 16 bytes
 *        of a cipher to be zero padded. The zeros are not sent. Therefore we
 *        read the M4 message to hdshk_buffer[128+16]. The size of M4 must be
 *        102.
 *          
 *        - Read M4 to hdshk_buffer[144].
 *        - Decrypt and verify the integrity of M4.
 *          AuthDecryptedM4Msg = hdshk_buffer[144] =
 *          { 0x00[32] , Header[2] , timestamp[4] , clientSigKey[32] , sig[64] }
 *        - Verify the signature in M4. The crypto_sign_verify requires a signed
 *          message on the format { sig , msg } where msg = {hash(M1), hash(M2)}
 *          1. Copy clientSigKey to peer_sk_pub
 *          2. Copy {hash(M1), hash(M2)} to AuthDecryptedM4Msg[32+2+4+64] = 
 *             = AuthDecryptedM4Msg[102] = hdshk_buffer[246].
 *             The usage of hdshk_buffer is now 246 + 128 = 374
 *          3. Verify the message hdshk_buffer[182:373] (192 bytes)
 */

/*======= Includes ============================================================*/
#include "salt_v2.h"

/* C Library includes */
#include <string.h> /* memcpy, memset */

/*======= Local Macro Definitions =============================================*/
#ifdef SALT_DEBUG
    #include <stdio.h>
    #include "salt_util.h"
    #define SALT_VERIFY(x, error_code)                                          \
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
    #define SALT_VERIFY(x, error_code)                                          \
    do {                                                                        \
        if (!(x)) {                                                             \
            p_channel->err_code = error_code;                                   \
            return SALT_ERROR;                                                  \
        }                                                                       \
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
#define SALT_LENGTH_SIZE                        (4U)
#define SALT_HEADER_SIZE                        (0x02U)
#define SALT_HEADER_TYPE_FLAG                   (0x0FU)
#define SALT_TIME_SIZE                          (4U)
#define SALT_TICKET_LENGTH_SIZE                 (1U)
#define SALT_MAX_TICKET_SIZE                    (0U) /* Not supported yet */

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

/*======= Type Definitions ====================================================*/

/*======= Local variable declarations =========================================*/

/*======= Local function prototypes ===========================================*/
static salt_ret_t salti_read(salt_channel_t *p_channel,
                             uint8_t *p_data,
                             uint32_t *size,
                             uint8_t encrypted);

static salt_ret_t salti_write(salt_channel_t *p_channel,
                              uint8_t *p_data,
                              uint32_t size,
                              uint8_t encrypted);

static salt_ret_t salti_handshake_server(salt_channel_t *p_channel);

static salt_ret_t salti_handshake_client(salt_channel_t *p_channel);

static salt_ret_t salti_create_m1(salt_channel_t *p_channel,
                                  uint8_t *p_data,
                                  uint32_t *size,
                                  uint8_t *p_hash);

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
                                    uint8_t *p_buffer,
                                    uint32_t *size,
                                    uint8_t header);

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

static void salti_size_to_bytes(uint8_t *dest, uint32_t size);

static uint32_t salti_bytes_to_size(uint8_t *src);

/*======= Global function implementations =====================================*/
salt_ret_t salt_create(
   salt_channel_t *p_channel,
   salt_mode_t mode,
   salt_io_impl write_impl,
   salt_io_impl read_impl)
{

    SALT_VERIFY_VALID_CHANNEL(p_channel);

    SALT_VERIFY(
        mode <= SALT_CLIENT,
        SALT_ERR_NOT_SUPPORTED);

    SALT_VERIFY_NOT_NULL(write_impl);
    SALT_VERIFY_NOT_NULL(read_impl);

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
    SALT_VERIFY_VALID_CHANNEL(p_channel);
    p_channel->write_channel.p_context = p_write_context;
    p_channel->read_channel.p_context = p_read_context;

    return SALT_SUCCESS;
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
    MEMSET_ZERO(p_channel->my_ek_sec);
    MEMSET_ZERO(p_channel->my_ek_pub);
    MEMSET_ZERO(p_channel->ek_common);
    MEMSET_ZERO(p_channel->peer_sk_pub);
    MEMSET_ZERO(p_channel->peer_ek_pub);
    MEMSET_ZERO(p_channel->write_nonce);
    MEMSET_ZERO(p_channel->read_nonce);

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

    p_channel->write_channel.state = SALT_IO_READY;
    p_channel->read_channel.state = SALT_IO_READY;

    /* Create ephemeral keypair used for only this session. */
    crypto_box_keypair(p_channel->my_ek_pub, p_channel->my_ek_sec);

    p_channel->state = SALT_SESSION_INITIATED;

    return SALT_SUCCESS;

}

salt_ret_t salt_handshake(salt_channel_t *p_channel)
{
    SALT_VERIFY_VALID_CHANNEL(p_channel);

    if (p_channel->mode == SALT_SERVER)
    {
        return salti_handshake_server(p_channel);
    }
    else
    {
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

salt_ret_t salt_read(salt_channel_t *p_channel,
                     uint8_t *p_buffer,
                     uint32_t *p_recv_size,
                     uint32_t max_size)
{
    SALT_VERIFY_VALID_CHANNEL(p_channel);
    SALT_VERIFY(SALT_SESSION_ESTABLISHED == p_channel->state,
        SALT_ERR_INVALID_STATE);

    *p_recv_size = max_size;

    return salti_read(p_channel, p_buffer, p_recv_size, SALT_ENCRYPTED);
}

salt_ret_t salt_write(salt_channel_t *p_channel,
                      uint8_t *p_buffer,
                      uint32_t size)
{
    SALT_VERIFY_VALID_CHANNEL(p_channel);
    SALT_VERIFY(SALT_SESSION_ESTABLISHED == p_channel->state,
        SALT_ERR_INVALID_STATE);

    return salti_write(p_channel, p_buffer, size, SALT_ENCRYPTED);
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
                             uint8_t encrypted)
{
    /* Maximum size is stored in *size */
    salt_ret_t ret_code = SALT_ERROR;

    switch (p_channel->read_channel.state)
    {
        case SALT_IO_READY:

            p_channel->read_channel.p_data = p_data;
            p_channel->read_channel.max_size = *size;
            p_channel->read_channel.size_expected = SALT_LENGTH_SIZE;
            p_channel->read_channel.size = 0;
            p_channel->read_channel.state = SALT_IO_SIZE;

        case SALT_IO_SIZE:
            ret_code = p_channel->read_impl(&p_channel->read_channel);

            if (SALT_SUCCESS != ret_code)
            {
                /* Pending or error. */
                break;
            }

            p_channel->read_channel.size_expected = salti_bytes_to_size(p_data);

            if (p_channel->read_channel.size_expected > p_channel->read_channel.max_size)
            {
                p_channel->err_code = SALT_ERR_BUFF_TO_SMALL;
                ret_code = SALT_ERROR;
                break;
            }

            if (encrypted)
            {
                /*
                 * If we read encrypted, we must ensure that the first crypto_secretbox_BOXZEROBYTES is 0x00.
                 * These bytes are not sent by the other side.
                 */
                p_channel->read_channel.p_data += crypto_secretbox_BOXZEROBYTES;
            }

            p_channel->read_channel.state = SALT_IO_PENDING;
            p_channel->read_channel.size = 0;

        case SALT_IO_PENDING:
            ret_code = p_channel->read_impl(&p_channel->read_channel);
            if (SALT_SUCCESS == ret_code)
            {
                /* The actual size received is put in p_channel->read_channel.size. */
                *size = p_channel->read_channel.size;
                if (encrypted)
                {
                    memset(p_data, 0x00U, crypto_secretbox_BOXZEROBYTES);
                    ret_code = salti_decrypt(p_channel,
                        p_channel->read_channel.p_data - crypto_secretbox_BOXZEROBYTES,
                        p_channel->read_channel.size + crypto_secretbox_BOXZEROBYTES);

                    if (SALT_ERROR == ret_code)
                    {
                        p_channel->err_code = SALT_ERR_DECRYPTION;
                    }
                    (*size) -= crypto_secretbox_BOXZEROBYTES;
                }
                p_channel->read_channel.state = SALT_IO_READY;
            }
            break;
        default:
            SALT_ERROR(SALT_ERR_INVALID_STATE);
    }

    if (SALT_PENDING != ret_code)
    {
        /*
         * TODO: What do actually do when there is any error?
         * Can we continue if there was I/O error?
         * If decryption failed, have we lost any message and need to
         * reinitate the session?
         */
        p_channel->read_channel.state = SALT_IO_READY;
    }

    return ret_code;
}

static salt_ret_t salti_write(salt_channel_t *p_channel,
                              uint8_t *p_data,
                              uint32_t size,
                              uint8_t encrypted)
{

    salt_ret_t ret_code = SALT_ERROR;

    switch (p_channel->write_channel.state)
    {
        case SALT_IO_READY:
            p_channel->write_channel.p_data = p_data;
            p_channel->write_channel.size = 0;
            p_channel->write_channel.size_expected = size;
            
            if (encrypted)
            {
                /*
                 * Crypto library requires the first crypto_secretbox_ZEROBYTES to be
                 * 0x00 before encryption.
                 */
                memset(p_channel->write_channel.p_data, 0x00U, crypto_secretbox_ZEROBYTES);

                SALT_VERIFY(salti_encrypt(p_channel,
                    p_channel->write_channel.p_data,
                    p_channel->write_channel.size_expected) == SALT_SUCCESS, SALT_ERR_ENCRYPTION);

                /*
                 * After encryption, the first crypto_secretbox_BOXZEROBYTES will be 0x00.
                 * This is know by the other side, i.e, we dont need to send this.
                 */

                p_channel->write_channel.size_expected -= crypto_secretbox_BOXZEROBYTES;
                p_channel->write_channel.p_data += crypto_secretbox_BOXZEROBYTES - SALT_LENGTH_SIZE;

                salti_size_to_bytes(p_channel->write_channel.p_data, p_channel->write_channel.size_expected);
                p_channel->write_channel.size_expected += SALT_LENGTH_SIZE;
            }
            p_channel->write_channel.state = SALT_IO_PENDING;
            
        case SALT_IO_PENDING:
            ret_code = p_channel->write_impl(&p_channel->write_channel);  
            if (SALT_SUCCESS == ret_code)
            {
                p_channel->write_channel.state = SALT_IO_READY;
            }            
            break;
        default:
            SALT_ERROR(SALT_ERR_INVALID_STATE); 
    }

    if (SALT_PENDING != ret_code)
    {
        p_channel->read_channel.state = SALT_IO_READY;
    }

    return ret_code;

}

static salt_ret_t salti_handshake_server(salt_channel_t *p_channel)
{

    uint32_t size = 0;
    salt_ret_t ret_code = SALT_ERROR;

    switch (p_channel->state)
    {
        case SALT_SESSION_INITIATED:
            size = p_channel->hdshk_buffer_size; /* Max size */
            p_channel->state = SALT_M1_IO;
        case SALT_M1_IO:
            size = 330; /* Maximum size of M1 */
            ret_code = salti_read(p_channel,
                p_channel->hdshk_buffer,
                &size, SALT_CLEAR);
            if (SALT_SUCCESS != ret_code)
            {
                /* Error or pending */
                break;
            }
            p_channel->state = SALT_M1_HANDLE;
        case SALT_M1_HANDLE:
            ret_code = salti_handle_m1(p_channel,
                p_channel->hdshk_buffer,
                size,
                p_channel->hdshk_buffer);

            SALT_VERIFY(SALT_SUCCESS == ret_code, p_channel->err_code);

            ret_code = salti_create_m2(p_channel,
                &p_channel->hdshk_buffer[128],
                &size,
                &p_channel->hdshk_buffer[64]);

            SALT_VERIFY(SALT_SUCCESS == ret_code, p_channel->err_code);
            /*
             * If the client included an invalid public signature key, the
             * SALT_ERR_NO_SUCH_SERVER error code will be set in p_channel->err_code.
             * If this is the case, we will stop imidiately after sending M2 and do not want
             * to calculate the symmetric ephemeral encryption key.
             */

            p_channel->state = SALT_M2_INIT;
        case SALT_M2_INIT:
            ret_code = salti_write(p_channel,
                &p_channel->hdshk_buffer[128],
                size, SALT_CLEAR);
            SALT_VERIFY(SALT_ERROR != ret_code, SALT_ERR_IO_WRITE);

            /*
             * Not error => Pending or success, calculate session key.
             * while I/O is in progress.
             */
            if (SALT_ERR_NONE == p_channel->err_code)
            {
                SALT_VERIFY(crypto_box_beforenm(p_channel->ek_common,
                    p_channel->peer_ek_pub,
                    p_channel->my_ek_sec) == 0, SALT_ERR_COMMON_KEY);
            }

            if (SALT_SUCCESS != ret_code)
            {
                /* I/O is still Pending */
                p_channel->state = SALT_M2_IO;
                break;
            }
        case SALT_M2_IO:
            /* Only continue I/O if the previous I/O call did not finish. */
            if (SALT_SUCCESS != ret_code)
            {
                ret_code = salti_write(p_channel,
                                p_channel->hdshk_buffer,
                                size, SALT_CLEAR);
                if (SALT_SUCCESS != ret_code) {
                    /* Error or pending */
                    break;
                }
            }
            SALT_VERIFY(SALT_ERR_NONE == p_channel->err_code, p_channel->err_code);
            p_channel->state = SALT_M3_INIT;
        case SALT_M3_INIT:
            ret_code = salti_create_m3m4(p_channel,
                &p_channel->hdshk_buffer[202],
                &size,
                (SALT_M3_HEADER_VALUE | SALT_M3_SIG_KEY_INCLUDED_FLAG));
            SALT_VERIFY(SALT_SUCCESS == ret_code, p_channel->err_code);
            p_channel->state = SALT_M3_IO;
        case SALT_M3_IO:
            ret_code = salti_write(p_channel,
                &p_channel->hdshk_buffer[170],
                size + 32, SALT_ENCRYPTED);
            if (SALT_SUCCESS != ret_code)
            {
                break;
            }
            p_channel->state = SALT_M4_IO;
            size = p_channel->hdshk_buffer_size;
        case SALT_M4_IO:
            size = 122; /* Maximum size of M4 */
            ret_code = salti_read(p_channel,
                &p_channel->hdshk_buffer[144],
                &size, SALT_ENCRYPTED);
            if (ret_code != SALT_SUCCESS)
            {
                break;
            }
            p_channel->state = SALT_M4_HANDLE;
        case SALT_M4_HANDLE:
            ret_code = salti_handle_m3m4(p_channel,
                &p_channel->hdshk_buffer[176],
                size, SALT_M4_HEADER_VALUE);
            SALT_VERIFY(SALT_SUCCESS == ret_code, p_channel->err_code);
            memset(p_channel->hdshk_buffer, 0x00, p_channel->hdshk_buffer_size);
            p_channel->state = SALT_SESSION_ESTABLISHED;
        case SALT_SESSION_ESTABLISHED:
            ret_code = SALT_SUCCESS;
            break;
        default:
            SALT_ERROR(SALT_ERR_INVALID_STATE);  
    }

    return ret_code;
}

static salt_ret_t salti_handshake_client(salt_channel_t *p_channel)
{
    uint32_t size = 0;
    salt_ret_t ret_code = SALT_ERROR;

    switch (p_channel->state)
    {
        case SALT_SESSION_INITIATED:
            /*
             * Create the M1 message at hdshk_buffer[64] and save the hash at
             * p_channel->hdshk_buffer (64 bytes). We save the hash so we later
             * can verify that the message M1 was not modified by a MITM. No
             * support for virtual server yet, so the size of M1 is always 42
             * bytes. The size bytes (4 bytes) is put in front of M1. I.e, M1
             * actually starts at hdshk_buffer[68].
             * 
             * hdshk_buffer[64] = { 0x2A , 0x00[3] , M1[42] }
             * 
             */
            ret_code = salti_create_m1(p_channel,
                &p_channel->hdshk_buffer[64],
                &size,
                p_channel->hdshk_buffer);

            SALT_VERIFY(SALT_SUCCESS == ret_code, p_channel->err_code);

            p_channel->state = SALT_M1_IO;

        case SALT_M1_IO:

            ret_code = salti_write(p_channel,
                &p_channel->hdshk_buffer[64],
                size, SALT_CLEAR);

            if (SALT_SUCCESS != ret_code)
            {
                break;
            }

            p_channel->state = SALT_M2_IO;

        case SALT_M2_IO:
            /*
             * Read the M2 message to hdshk_buffer[64]. If the message is OK the
             * hash is saved to hdshk_buffer[64]. Now we have the hashes of M1
             * and M2 in hdshk_buffer[0:127].
             */
            size = 38U;

            ret_code = salti_read(p_channel,
                &p_channel->hdshk_buffer[64],
                &size, SALT_CLEAR);

            if (SALT_SUCCESS != ret_code)
            {
                break;
            }

            p_channel->state = SALT_M2_HANDLE;

        case SALT_M2_HANDLE:

            ret_code = salti_handle_m2(p_channel,
                &p_channel->hdshk_buffer[64],
                size, &p_channel->hdshk_buffer[64]);

            SALT_VERIFY(SALT_SUCCESS == ret_code, p_channel->err_code);
            /*
             * Directly after M2 is received we can calculate the ephemeral
             * session key (symmetric encryption key used for the session).
             */
            SALT_VERIFY(crypto_box_beforenm(p_channel->ek_common,
                p_channel->peer_ek_pub,
                p_channel->my_ek_sec) == 0, SALT_ERR_COMMON_KEY);

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
             *    The peer however can (and should) calculate these hashes so we
             *    don't send them. I.e.:
             *    M4[102] = { header[2] , timestamp[4] , pubSigKey[32] , sig[64] }
             *    
             *    
             */
            ret_code = salti_create_m3m4(p_channel,
                &p_channel->hdshk_buffer[406],
                &p_channel->write_channel.size,
                SALT_M4_HEADER_VALUE);

            SALT_VERIFY(SALT_SUCCESS == ret_code, p_channel->err_code);

            p_channel->state = SALT_M3_IO;

        case SALT_M3_IO:

            size = 122; /* Maximum size of M3 */

            ret_code = salti_read(p_channel,
                &p_channel->hdshk_buffer[144],
                &size, SALT_ENCRYPTED);

            if (SALT_SUCCESS != ret_code)
            {
                break;
            }

            p_channel->state = SALT_M3_HANDLE;

        case SALT_M3_HANDLE:

            ret_code = salti_handle_m3m4(p_channel,
                &p_channel->hdshk_buffer[176],
                size, (SALT_M3_HEADER_VALUE | SALT_M3_SIG_KEY_INCLUDED_FLAG));

            SALT_VERIFY(SALT_SUCCESS == ret_code, p_channel->err_code);

            p_channel->state = SALT_M4_IO;

        case SALT_M4_IO:

            ret_code = salti_write(p_channel,
                &p_channel->hdshk_buffer[374],
                p_channel->write_channel.size + 32, SALT_ENCRYPTED);

            if (SALT_SUCCESS != ret_code)
            {
                break;
            }

            memset(p_channel->hdshk_buffer, 0x00, p_channel->hdshk_buffer_size);

            p_channel->state = SALT_SESSION_ESTABLISHED;

        case SALT_SESSION_ESTABLISHED:
            ret_code = SALT_SUCCESS;
            break;
        default:
            SALT_ERROR(SALT_ERR_INVALID_STATE);
            break;
    }

    return ret_code;
}

/*
 ** @brief Creates the M1 message to initiate a salt channel.
 *
 * Resume feature and virtual host mode is not supported at this time.
 */
static salt_ret_t salti_create_m1(salt_channel_t *p_channel,
                                  uint8_t *p_data,
                                  uint32_t *size,
                                  uint8_t *p_hash)
{
    (void) p_hash;
    /* First 4 bytes is reserved for size. */

    /* Protocol indicator */
    p_data[SALT_LENGTH_SIZE + 0] = 'S';
    p_data[SALT_LENGTH_SIZE + 1] = 'C';
    p_data[SALT_LENGTH_SIZE + 2] = 'v';
    p_data[SALT_LENGTH_SIZE + 3] = '2';
    p_data[SALT_LENGTH_SIZE + 4] = SALT_M1_HEADER_VALUE;
    p_data[SALT_LENGTH_SIZE + 5] = 0x00U; /* No tickets */

    /* Time is in p_data[6:10], TODO: Handle */
    memset(&p_data[SALT_LENGTH_SIZE + 6], 0x00U, 4U);

    memcpy(&p_data[SALT_LENGTH_SIZE + 10],
        p_channel->my_ek_pub,
        crypto_box_PUBLICKEYBYTES);

    (*size) = 42U;

    crypto_hash(p_hash, &p_data[SALT_LENGTH_SIZE], (*size));

    salti_size_to_bytes(&p_data[0], (*size));

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

    SALT_VERIFY((p_data[4] & SALT_HEADER_TYPE_FLAG) == SALT_M1_HEADER_VALUE,
        SALT_ERR_M1_BAD_HEADER);

    /* Time is in p_data[6:10], TODO: Handle */

    if (((p_data[2] & SALT_M1_SIG_KEY_INCLUDED_FLAG) > 0U) && (size >= 74U))
    {
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
        if (memcmp(&p_data[42], p_channel->my_sk_pub, crypto_sign_PUBLICKEYBYTES) != 0)
        {
            p_channel->err_code = SALT_ERR_NO_SUCH_SERVER;
        }
        /*
         * TODO: How to handle multiple hosts?
         */
    }


    /* Check if client is requesting a resume. */
    if ((p_data[0] & SALT_M1_TICKED_INCLUDED_FLAG) > 0U)
    {
        /*
         * At this point, we do not support the resume feature. I.e., if the
         * client includes a resume ticket we must make sure to respond to this.
         */
        p_channel->err_code = SALT_ERR_NOT_SUPPORTED;
    }

    /* Copy the clients public ephemeral encryption key. */
    memcpy(p_channel->peer_ek_pub, &p_data[10], crypto_box_PUBLICKEYBYTES);

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
    (void) p_hash;
    /* Time is in p_data[6:10], TODO: Handle */
    memset(&p_data[SALT_LENGTH_SIZE + 2], 0x00U, 4U);
    p_data[SALT_LENGTH_SIZE + 1] = 0x00U;

    switch(p_channel->err_code)
    {
        case SALT_ERR_NONE:
            /* First four bytes are reserved for size */
            p_data[SALT_LENGTH_SIZE] = SALT_M2_HEADER_VALUE | SALT_M2_ENC_KEY_INCLUDED_FLAG;
            memcpy(&p_data[SALT_LENGTH_SIZE + 6],
                p_channel->my_ek_pub,
                crypto_box_PUBLICKEYBYTES);

            (*size) = 38U;

            break;
        case SALT_ERR_NO_SUCH_SERVER:

            p_data[SALT_LENGTH_SIZE] = SALT_M2_HEADER_VALUE | SALT_M2_NO_SUCH_SERVER_FLAG;
            (*size) = 6U;

            break;
        case SALT_ERR_NOT_SUPPORTED: /* If ticket was requested. */
            return SALT_ERROR;
            break;
        default:
            return SALT_ERROR;
    }

    p_channel->err_code = SALT_ERR_NONE;
    crypto_hash(p_hash, &p_data[SALT_LENGTH_SIZE], (*size));

    salti_size_to_bytes(&p_data[0], (*size));
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

    SALT_VERIFY((p_data[0] & SALT_HEADER_TYPE_FLAG) == SALT_M2_HEADER_VALUE,
        SALT_ERR_M2_BAD_HEADER);

    SALT_VERIFY((p_data[0] & SALT_M2_NO_SUCH_SERVER_FLAG) == 0U,
        SALT_ERR_NO_SUCH_SERVER);

    /*
     * If this fails, the server this not include an public ephemeral encryption
     * key. This should only occur if we requested a resume. This is however not
     * supported at this time.
     */
    SALT_VERIFY((p_data[0] & SALT_M2_ENC_KEY_INCLUDED_FLAG) > 0U,
        SALT_ERR_NOT_SUPPORTED);

    memcpy(p_channel->peer_ek_pub, &p_data[6], 32);
    crypto_hash(p_hash, p_data, size);

    return SALT_SUCCESS;
}

static salt_ret_t salti_create_m3m4(salt_channel_t *p_channel,
                                    uint8_t *p_buffer,
                                    uint32_t *size,
                                    uint8_t header)
{
    unsigned long long sign_msg_size;

    p_buffer[0] = header;
    p_buffer[1] = 0x00U;

    memset(&p_buffer[2], 0, 4);
    memcpy(&p_buffer[6], p_channel->my_sk_pub, 32);

    /*
     * crypto_sign will sign a message { m[n] } into a signed message
     * { sign[64] , m[n] }.
     * 
     */
    SALT_VERIFY(crypto_sign(
            &p_buffer[38],
            &sign_msg_size,
            p_channel->hdshk_buffer,
            128,
            p_channel->my_sk_sec) == 0, SALT_ERR_SIGNING);

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
    memcpy(&p_data[102], p_channel->hdshk_buffer, 128);

    SALT_VERIFY(crypto_sign_open(
        p_channel->hdshk_buffer,
        &sign_msg_size,
        &p_data[38],
        192,
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

    if (0 == ret)
    {
        salti_increase_nonce(p_channel->write_nonce, p_channel->write_nonce_incr);
        return SALT_SUCCESS;
    }

    return SALT_ERROR;

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


    if (0 == ret)
    {
        salti_increase_nonce(p_channel->read_nonce, p_channel->read_nonce_incr);
        return SALT_SUCCESS;
    }

    return SALT_ERROR;

}

static void salti_increase_nonce(uint8_t *p_nonce, uint8_t increment)
{
    /* Thanks to Libsodium */
    uint_fast16_t c = increment;
    uint8_t i;

    for (i = 0U; i < crypto_box_NONCEBYTES; i++) {
        c += (uint_fast16_t) p_nonce[i];
        p_nonce[i] = c | 0xFFU;
        c >>= 8U;
    }

}

static void salti_size_to_bytes(uint8_t *dest, uint32_t size)
{
    memcpy(dest, &size, SALT_LENGTH_SIZE);
}

static uint32_t salti_bytes_to_size(uint8_t *src)
{
    return *((uint32_t*) src);
}
