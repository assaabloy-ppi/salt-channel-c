/**
 * @file salti_handshake.c
 *
 *
 * Description
 *
 */

/*======= Includes ==========================================================*/

/* C Library includes */
#include <string.h> /* memcpy, memset */

/* Salt library includes */
#include "salti_handshake.h"

/*======= Local Macro Definitions ===========================================*/

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
#define SALT_M3M4_SIZE                          (120U)
#define SALT_M3_HEADER_VALUE                    (0x03U)
#define SALT_M3_SIG_KEY_INCLUDED_FLAG           (0x10U)

/* M4 Message defines */
#define SALT_M4_HEADER_VALUE                    (0x04U)


#define SALT_PUB_ENC_OFFSET                     (0U)
#define SALT_SEC_ENC_OFFSET                     (32U)
#define SALT_SIG_PREFIX_OFFSET                  (64U)
#define SALT_SIG_PREFIX_SIZE                    (8U)
#define SALT_M1_HASH_OFFSET                     (72U)
#define SALT_M2_HASH_OFFSET                     (136U)

/*======= Type Definitions ==================================================*/
/*======= Local variable declarations =======================================*/

/* Signature 1 prefix, ASCII "SC-SIG01" */
static uint8_t sig1prefix[8] = { 0x53, 0x43, 0x2d, 0x53, 0x49, 0x47, 0x30, 0x31 };
/* Signature 2 prefix, ASCII "SC-SIG02" */
static uint8_t sig2prefix[8] = { 0x53, 0x43, 0x2d, 0x53, 0x49, 0x47, 0x30, 0x32 };

/*======= Local function prototypes =========================================*/
/*======= Global function implementations ===================================*/
/*======= Local function implementations ====================================*/

salt_ret_t salti_handshake_server(salt_channel_t *p_channel, uint8_t *p_with)
{

    uint32_t size = 0;
    salt_ret_t ret_code = SALT_ERROR;
    uint8_t proceed = 1;
    uint8_t *payload;

    while (proceed) {
        proceed = 0;
        switch (p_channel->state) {
        case SALT_SESSION_INITIATED:
            p_channel->state = SALT_M1_IO;
            proceed = 1;
            break;
        case SALT_M1_IO:
            size = 204; /* Maximum size of M1 */
            ret_code = salti_io_read(p_channel,
                                     &p_channel->hdshk_buffer[SALT_M1_HASH_OFFSET],
                                     &size);
            if (SALT_SUCCESS == ret_code) {

                payload = &p_channel->hdshk_buffer[SALT_M1_HASH_OFFSET];

                /* Check if this is an A2 request. */
                if (size == 2 && payload[0] == SALT_A1_HEADER && payload[1] == 0x00U) {
                    p_channel->state = SALT_A1_HANDLE;
                } else {
                    /* Otherwise try to handle M1 */
                    p_channel->state = SALT_M1_HANDLE;
                }

                proceed = 1;

            }
            break;
        case SALT_A1_HANDLE:
            /*
             * If no supported protocols is set we answer that we supporting
             * salt-channel v2 and reveals nothing about overlying protocol(s).
             * I.e., the answer will be:
             *
             * SupportedProtocols = "SC2-------","----------"
             *
             * This message is created in p_channel->hdshk_buffer[64] since
             * we have the ephemeral keypair in p_channel->hdshk_buffer[0:63]
             */
            if (p_channel->p_protocols == NULL || p_channel->p_protocols->count == 0) {
                salt_protocols_t protocols;
                salt_protocols_init(p_channel,
                                    &protocols,
                                    &p_channel->hdshk_buffer[64],
                                    p_channel->hdshk_buffer_size - 64);
                salt_protocols_append(&protocols, "----------", 10);
                p_channel->write_channel.p_data = p_channel->hdshk_buffer;
                p_channel->write_channel.size = p_channel->hdshk_buffer_size;
            } else {
                p_channel->write_channel.p_data = p_channel->p_protocols->p_buffer;
                p_channel->write_channel.size = p_channel->p_protocols->buf_used;
            }

            if (SALT_SUCCESS == ret_code) {
                p_channel->state = SALT_A2_IO;
                proceed = 1;
            }
            break;
        case SALT_A2_IO:
            ret_code = salti_io_write(p_channel,
                                      p_channel->write_channel.p_data,
                                      p_channel->write_channel.size);
            if (SALT_SUCCESS == ret_code) {
                ret_code = SALT_PENDING;
                /*
                 * We can restart handshake after this without a new
                 * initialization.
                 */
                p_channel->state = SALT_SESSION_INITIATED;
            }
            break;
        case SALT_M1_HANDLE:

            /*
             * If an invalid sig key was included in M1 salti_handle_m1
             * will set p_channel->err_code = SALT_ERR_NO_SUCH_SERVER.
             * Then we will create M2 with that flag and last flag.
             * After this the session is considered closed.
             */

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

            if (p_channel->err_code == SALT_ERR_NO_SUCH_SERVER) {
                proceed = 1;
                p_channel->state = SALT_M2_IO;
                break;
            }

            SALT_VERIFY(SALT_ERROR != ret_code, p_channel->err_code);

            salti_get_time(p_channel, &p_channel->my_epoch);

            ret_code = salti_io_write(p_channel,
                                      &p_channel->hdshk_buffer[200],
                                      size);

            SALT_VERIFY(SALT_ERROR != ret_code, SALT_ERR_IO_WRITE);

            if (SALT_ERROR != ret_code) {

                /* crypto_box_beforenm always returns 0 */
                int tmp = crypto_box_beforenm(p_channel->ek_common,
                                              &p_channel->hdshk_buffer[242],
                                              &p_channel->hdshk_buffer[SALT_SEC_ENC_OFFSET]);
                (void) tmp;
                p_channel->state = SALT_M2_IO;

            }

            if (ret_code == SALT_SUCCESS) {
                proceed = 1;
                p_channel->state = SALT_M3_INIT;
            }

            break;
        case SALT_M2_IO:
            ret_code = salti_io_write(p_channel,
                                      &p_channel->hdshk_buffer[200],
                                      size);

            if (SALT_SUCCESS == ret_code) {
                SALT_VERIFY(p_channel->err_code == SALT_ERR_NONE, p_channel->err_code);
                p_channel->state = SALT_M3_INIT;
                proceed = 1;
            }
            break;
        case SALT_M3_INIT:
            ret_code = salti_create_m3m4_sig(p_channel,
                                         &p_channel->hdshk_buffer[200 + 38],
                                         &size);

            SALT_VERIFY(SALT_SUCCESS == ret_code, p_channel->err_code);

            ret_code = salti_wrap(p_channel,
                                  &p_channel->hdshk_buffer[200],
                                  size,
                                  SALT_M3_HEADER_VALUE,
                                  &p_channel->write_channel.p_data,
                                  &p_channel->write_channel.size, false);

            SALT_VERIFY(SALT_SUCCESS == ret_code, p_channel->err_code);

            if (SALT_SUCCESS == ret_code) {
                p_channel->state = SALT_M3_IO;
                proceed = 1;
            }

            break;
        case SALT_M3_IO:
            ret_code = salti_io_write(p_channel,
                                      p_channel->write_channel.p_data,
                                      p_channel->write_channel.size);
            if (SALT_SUCCESS == ret_code) {
                p_channel->state = SALT_M4_IO;
                proceed = 1;
            }
            break;
        case SALT_M4_IO:
            size = SALT_M3M4_SIZE;

            ret_code = salti_io_read(p_channel,
                                     &p_channel->hdshk_buffer[200 + 14],
                                     &size);

            if (ret_code == SALT_SUCCESS) {
                p_channel->state = SALT_M4_HANDLE;
                proceed = 1;
            }
            break;
        case SALT_M4_HANDLE:

            SALT_VERIFY(SALT_M3M4_SIZE == size, SALT_ERR_BAD_PROTOCOL);

            uint8_t *header;

            ret_code = salti_unwrap(p_channel,
                                    &p_channel->hdshk_buffer[200],
                                    size,
                                    &header,
                                    &p_channel->write_channel.p_data,
                                    &p_channel->write_channel.size);

            SALT_VERIFY(SALT_SUCCESS == ret_code, p_channel->err_code);
            SALT_VERIFY(SALT_M4_HEADER_VALUE == header[0], SALT_ERR_BAD_PROTOCOL);

            ret_code = salti_verify_m3m4_sig(p_channel,
                                         p_channel->write_channel.p_data,
                                         p_channel->write_channel.size);

            if (SALT_SUCCESS == ret_code) {

                /*
                 * If an expected public key of the peer is procided, check
                 * that this matches the from the one authenticated in M4.
                 */
                if (p_with != NULL) {
                    SALT_VERIFY(memcmp(p_with, p_channel->peer_sk_pub, 32) == 0,
                        SALT_ERR_BAD_PEER);
                }

                p_channel->state = SALT_SESSION_ESTABLISHED;
            }
            memset(p_channel->hdshk_buffer, 0x00U, p_channel->hdshk_buffer_size);
            break;
        case SALT_ERROR_STATE:
        default:
            return SALT_ERROR;
        }
    }

    return ret_code;
}

salt_ret_t salti_handshake_client(salt_channel_t *p_channel, uint8_t *p_with)
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
                            &p_channel->hdshk_buffer[SALT_M1_HASH_OFFSET],
                            p_with);
            salti_get_time(p_channel, &p_channel->my_epoch);
            p_channel->state = SALT_M1_IO;
            proceed = 1;
            break;
        case SALT_M1_IO:


            ret_code = salti_io_write(p_channel,
                                      &p_channel->hdshk_buffer[SALT_M2_HASH_OFFSET],
                                      size);

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

            ret_code = salti_io_read(p_channel,
                                     &p_channel->hdshk_buffer[SALT_M2_HASH_OFFSET],
                                     &size);

            if (SALT_SUCCESS == ret_code) {
                p_channel->state = SALT_M2_HANDLE;
                proceed = 1;
            }
            break;
        case SALT_M2_HANDLE:

            ret_code = salti_handle_m2(p_channel,
                                       &p_channel->hdshk_buffer[SALT_M2_HASH_OFFSET],
                                       size, &p_channel->hdshk_buffer[SALT_M2_HASH_OFFSET]);
            
            SALT_VERIFY(SALT_ERROR != ret_code, p_channel->err_code);

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
            ret_code = salti_create_m3m4_sig(p_channel,
                                         &p_channel->hdshk_buffer[406],
                                         &p_channel->write_channel.size);

            if (SALT_SUCCESS == ret_code) {
                p_channel->state = SALT_M3_IO;
                proceed = 1;
            }
            break;

        case SALT_M3_IO:

            size = 120; /* Maximum size of M3 */

            ret_code = salti_io_read(p_channel,
                                     &p_channel->hdshk_buffer[200 + 14],
                                     &size);
            if (SALT_SUCCESS == ret_code) {
                p_channel->state = SALT_M3_HANDLE;
                proceed = 1;
            }
            break;
        case SALT_M3_HANDLE:

            /* Wrapped and encrypted M3 MUST be 120 bytes long. */
            SALT_VERIFY(size == 120, SALT_ERR_BAD_PROTOCOL);
            uint8_t *header;

            ret_code = salti_unwrap(p_channel,
                                    &p_channel->hdshk_buffer[200],
                                    size,
                                    &header,
                                    &p_channel->read_channel.p_data,
                                    &p_channel->read_channel.size);

            SALT_VERIFY(SALT_SUCCESS == ret_code, p_channel->err_code);
            SALT_VERIFY(SALT_M3_HEADER_VALUE == header[0], SALT_ERR_BAD_PROTOCOL);

            ret_code = salti_verify_m3m4_sig(p_channel,
                                         p_channel->read_channel.p_data,
                                         p_channel->read_channel.size);

            if (SALT_SUCCESS == ret_code) {
                if (p_with != NULL) {
                    SALT_VERIFY(memcmp(p_with, p_channel->peer_sk_pub, 32) == 0,
                        SALT_ERR_BAD_PEER);
                }
                p_channel->state = SALT_M4_IO;
                proceed = 1;
            }

            break;
        case SALT_M4_IO:

            ret_code = salti_wrap(p_channel,
                                  &p_channel->hdshk_buffer[406 - 38],
                                  p_channel->write_channel.size,
                                  SALT_M4_HEADER_VALUE,
                                  &p_channel->write_channel.p_data,
                                  &p_channel->write_channel.size, false);

            SALT_VERIFY(SALT_SUCCESS == ret_code, p_channel->err_code);

            ret_code = salti_io_write(p_channel,
                                      p_channel->write_channel.p_data,
                                      p_channel->write_channel.size);

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
void salti_create_m1(salt_channel_t *p_channel,
                     uint8_t *p_data,
                     uint32_t *size,
                     uint8_t *p_hash,
                     uint8_t *p_with)
{
    /* First 4 bytes is reserved for size. */

    (*size) = 42U;

    /* Protocol indicator */
    p_data[SALT_LENGTH_SIZE + 0] = 'S';
    p_data[SALT_LENGTH_SIZE + 1] = 'C';
    p_data[SALT_LENGTH_SIZE + 2] = 'v';
    p_data[SALT_LENGTH_SIZE + 3] = '2';
    p_data[SALT_LENGTH_SIZE + 4] = SALT_M1_HEADER_VALUE;

    if (p_with != NULL) {
        p_data[SALT_LENGTH_SIZE + 5] = SALT_M1_SIG_KEY_INCLUDED_FLAG;
        memcpy(&p_data[SALT_LENGTH_SIZE + 10 + 32], p_with, 32);
        (*size) += 32;
    } else {
        p_data[SALT_LENGTH_SIZE + 5] = 0x00U; /* No tickets */
    }

    memset(&p_data[SALT_LENGTH_SIZE + 6], 0x00U, 4);
    if (p_channel->time_impl != NULL) {
        p_data[SALT_LENGTH_SIZE + 6] = 0x01U;
    }

    memcpy(&p_data[SALT_LENGTH_SIZE + 10],
           &p_channel->hdshk_buffer[SALT_PUB_ENC_OFFSET],
           crypto_box_PUBLICKEYBYTES);

    crypto_hash(p_hash, &p_data[SALT_LENGTH_SIZE], (*size));
    salti_u32_to_bytes(&p_data[0], (*size));

    (*size) += SALT_LENGTH_SIZE;

}

salt_ret_t salti_handle_m1(salt_channel_t *p_channel,
                           uint8_t *p_data,
                           uint32_t size,
                           uint8_t *p_hash)
{
    SALT_VERIFY(size == 42U || size == 74U,
                SALT_ERR_BAD_PROTOCOL);

    /* Protocol indicator should be "SCv2" */
    SALT_VERIFY(memcmp(p_data, "SCv2", 4) == 0,
                SALT_ERR_BAD_PROTOCOL);

    SALT_VERIFY(p_data[4] == SALT_M1_HEADER_VALUE,
                SALT_ERR_BAD_PROTOCOL);

    if (salti_bytes_to_u32(&p_data[6]) == 1) {
        salti_get_time(p_channel, &p_channel->peer_epoch);
        p_channel->time_supported &= 1;
    }
    else {
        p_channel->time_supported = 0;
    }

    if (((p_data[5] & SALT_M1_SIG_KEY_INCLUDED_FLAG) > 0U) && (size == 74U)) {
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
            return SALT_SUCCESS;
        }
    }

    /* Copy the clients public ephemeral encryption key. */
    memcpy(&p_channel->hdshk_buffer[242], &p_data[10], crypto_box_PUBLICKEYBYTES);

    /* Save the hash of M1 */
    crypto_hash(p_hash, p_data, size);

    return SALT_SUCCESS;

}

salt_ret_t salti_create_m2(salt_channel_t *p_channel,
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

    memset(&p_data[SALT_LENGTH_SIZE + 2], 0x00U, 4);
    if (p_channel->time_impl != NULL) {
        p_data[SALT_LENGTH_SIZE + 2] = 0x01U;
    }

    (*size) = 38U;

    if (p_channel->err_code == SALT_ERR_NO_SUCH_SERVER) {
        p_data[SALT_LENGTH_SIZE + 1] = SALT_M2_NO_SUCH_SERVER_FLAG;
        p_data[SALT_LENGTH_SIZE + 1] |= SALT_LAST_FLAG;
        memset(&p_data[SALT_LENGTH_SIZE + 6], 0x00,
               crypto_box_PUBLICKEYBYTES);
    } else {
        /* Copy ephemeral public key to M2 */
       memcpy(&p_data[SALT_LENGTH_SIZE + 6],
              &p_channel->hdshk_buffer[SALT_PUB_ENC_OFFSET],
              crypto_box_PUBLICKEYBYTES);

       crypto_hash(p_hash, &p_data[SALT_LENGTH_SIZE], (*size));

    }

    salti_u32_to_bytes(&p_data[0], (*size));
    (*size) += SALT_LENGTH_SIZE;

    return SALT_SUCCESS;
}

salt_ret_t salti_handle_m2(salt_channel_t *p_channel,
                           uint8_t *p_data,
                           uint32_t size,
                           uint8_t *p_hash)
{

    SALT_VERIFY(size >= 38U,
                SALT_ERR_BAD_PROTOCOL);

    SALT_VERIFY(p_data[0] == SALT_M2_HEADER_VALUE,
                SALT_ERR_BAD_PROTOCOL);

    /*
     * If no such server condition occurs, the session is considered closed.
     * I.e., we return error here and the application will stop the handshake
     * procedure.
     */
    SALT_VERIFY((p_data[1] & SALT_M2_NO_SUCH_SERVER_FLAG) == 0U,
                SALT_ERR_NO_SUCH_SERVER);


    if (salti_bytes_to_u32(&p_data[2]) == 1) {
        salti_get_time(p_channel, &p_channel->peer_epoch);
        p_channel->time_supported &= 1;
    }
    else {
        p_channel->time_supported = 0;
    }

    SALT_VERIFY(crypto_box_beforenm(p_channel->ek_common,
                                    &p_data[6],
                                    &p_channel->hdshk_buffer[SALT_SEC_ENC_OFFSET]) == 0, SALT_ERR_COMMON_KEY);

    crypto_hash(p_hash, p_data, size);

    return SALT_SUCCESS;
}

salt_ret_t salti_create_m3m4_sig(salt_channel_t *p_channel,
                             uint8_t *p_data,
                             uint32_t *size)
{
    unsigned long long sign_msg_size;

    memcpy(p_data, p_channel->my_sk_pub, 32);

    if (p_channel->mode == SALT_SERVER) {
        memcpy(&p_channel->hdshk_buffer[64], sig1prefix, 8);
    }
    else {
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
    memcpy(&p_data[32], p_channel->hdshk_buffer, 64);

    (*size) = 96U;

    return SALT_SUCCESS;
}

salt_ret_t salti_verify_m3m4_sig(salt_channel_t *p_channel,
                             uint8_t *p_data,
                             uint32_t size)
{
    unsigned long long sign_msg_size;

    SALT_VERIFY(96U == size, SALT_ERR_BAD_PROTOCOL);

    memcpy(p_channel->peer_sk_pub, p_data, 32);
    memcpy(p_channel->hdshk_buffer, &p_data[32], 64);

    if (p_channel->mode == SALT_SERVER) {
        memcpy(&p_channel->hdshk_buffer[64], sig2prefix, 8);
    }
    else {
        memcpy(&p_channel->hdshk_buffer[64], sig1prefix, 8);
    }
    SALT_VERIFY(crypto_sign_open(
                    &p_channel->hdshk_buffer[200],
                    &sign_msg_size,
                    p_channel->hdshk_buffer,
                    200,
                    p_channel->peer_sk_pub) == 0, SALT_ERR_BAD_PEER);
    return SALT_SUCCESS;
}

