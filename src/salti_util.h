#ifndef _SALTI_UTIL_H_
#define _SALTI_UTIL_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file salti_util.h
 *
 * Internal routines used by salt-channel. Not intended to use directly.
 * Due to this, these routines does not check for NULL pointers etc.
 *
 */

/*======= Includes ==========================================================*/

/* Salt library includes */
#include "salt.h"

/*======= Public macro definitions ==========================================*/

/* Application package message header */
#define SALT_APP_PKG_MSG_HEADER_VALUE           (0x05U)
#define SALT_MULTI_APP_PKG_MSG_HEADER_VALUE     (0x0BU)
#define SALT_OVERHEAD_SIZE                      (38U)

/* Various defines */
#define SALT_CLEAR                              (0U)
#define SALT_ENCRYPTED                          (1U)
#define SALT_APP_MSG                            (3U)
#define SALT_APP_MULTI_MSG                      (7U)
#define SALT_LENGTH_SIZE                        (4U)
#define SALT_HEADER_SIZE                        (2U)
#define SALT_TIME_SIZE                          (4U)
#define SALT_A1_HEADER                          (8U)
#define SALT_A2_HEADER                          (9U)
#define SALT_LAST_FLAG                          (0x80U)

/* Encrypted message header */
#define SALT_ENCRYPTED_MSG_HEADER_VALUE         (0x06U)

/**
 * SALT_VERIFY is only and MUST only used internal by the implementation.
 * x is a condition, if it is not true SALT_ERROR will be returned
 * by the function using the macro. The pointer to the channel structure,
 * p_channel must have exactly the name p_channel.
 */
#ifdef SALT_DEBUG
#include <stdio.h>
#define SALT_VERIFY(x, error_code)                                          \
        do {                                                                \
            if (!(x)) {                                                     \
                p_channel->err_code = error_code;                           \
                printf(                                                     \
                    "Runtime error (%s, %s): %s at %s:%d, %s.\r\n",         \
                    #error_code, salt_mode2str(p_channel->mode), #x,        \
                    __FILE__, __LINE__, __func__);                          \
                p_channel->state = SALT_SESSION_CLOSED;                     \
                return SALT_ERROR;                                          \
            }                                                               \
        } while (0)
#else
#define SALT_VERIFY(x, error_code)                                          \
        do {                                                                \
            if (!(x)) {                                                     \
                p_channel->err_code = error_code;                           \
                p_channel->state = SALT_SESSION_CLOSED;                     \
                return SALT_ERROR;                                          \
            }                                                               \
        } while (0)
#endif

#define SALT_VERIFY_NOT_NULL(x)                                             \
    SALT_VERIFY(((x) != NULL), SALT_ERR_NULL_PTR)

#define SALT_VERIFY_VALID_CHANNEL(x) if ((x) == NULL) return SALT_ERROR
#define SALT_TRIGGER_ERROR                      (0x00U)
#define SALT_ERROR(err_code) SALT_VERIFY(SALT_TRIGGER_ERROR, err_code)
#define MEMSET_ZERO(x) memset((x), 0, sizeof((x)))


#ifdef SALT_DEBUG
#include <stdio.h>
#define SALT_HEXDUMP_DEBUG(ptr, size)                                       \
    do {                                                                    \
        uint32_t i;                                                         \
        uint8_t *iptr = (uint8_t *) ptr;                                    \
        printf("%s:%d: %s (%d):\r\n",                                       \
            __FILE__, __LINE__, #ptr, (size));                              \
        for (i = 0; i < (uint32_t) (size); i++) {                           \
            printf("%02x", iptr[i]);                                        \
        } printf("\r\n");                                                   \
    } while(0)
#else
#define SALT_HEXDUMP_DEBUG(ptr, size)
#endif

/*======= Type Definitions and declarations =================================*/
/*======= Public variable declarations ======================================*/
/*======= Public function declarations ======================================*/

salt_ret_t salti_io_read(salt_channel_t *p_channel,
                         uint8_t *p_data,
                         uint32_t *size);

salt_ret_t salti_io_write(salt_channel_t *p_channel,
                          uint8_t *p_data,
                          uint32_t size);

salt_ret_t salti_wrap(salt_channel_t *p_channel,
                      uint8_t *p_data,
                      uint32_t size,
                      uint8_t header,
                      uint8_t **wrapped,
                      uint32_t *wrapped_length,
                      bool last_msg);

salt_ret_t salti_unwrap(salt_channel_t *p_channel,
                        uint8_t *p_data,
                        uint32_t size,
                        uint8_t **header,
                        uint8_t **unwrapped,
                        uint32_t *unwrapped_length);

salt_ret_t salti_increase_nonce(uint8_t *p_nonce);

void salti_u16_to_bytes(uint8_t *dest, uint16_t size);

uint16_t salti_bytes_to_u16(uint8_t *src);

void salti_u32_to_bytes(uint8_t *dest, uint32_t size);

uint32_t salti_bytes_to_u32(uint8_t *src);

salt_ret_t salti_get_time(salt_channel_t *p_channel, uint32_t *p_time);

salt_err_t salt_read_init(uint8_t type,
                          uint8_t *p_buffer,
                          uint32_t buffer_size,
                          salt_msg_t *p_msg);

uint8_t salt_write_create(salt_msg_t *p_msg);

bool time_check(uint32_t first, uint32_t my_time, uint32_t peer_time, uint32_t thresh);

/**
 * @brief Return a pointer to salt mode string.
 *
 * @param mode Salt mode to print
 * @return Return a pointer to salt mode string
 */
char *salt_mode2str(salt_mode_t mode);

#ifdef __cplusplus
}
#endif

#endif /* _SALTI_UTIL_H_ */
