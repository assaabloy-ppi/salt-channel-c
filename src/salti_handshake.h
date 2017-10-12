#ifndef _SALTI_HANDSHAKE_H_
#define _SALTI_HANDSHAKE_H_

/**
 * @file salti_handshake.h
 *
 * Description
 *
 */

/*======= Includes ==========================================================*/

/* Salt library includes */
#include "salt.h"
#include "salti_util.h"

/*======= Public macro definitions ==========================================*/

#define SALT_NO_SUCH_SERVER_FLAG             (0x40U)

/*======= Type Definitions and declarations =================================*/
/*======= Public function declarations ======================================*/

salt_ret_t salti_handshake_server(salt_channel_t *p_channel, uint8_t *p_with);

salt_ret_t salti_handshake_client(salt_channel_t *p_channel, uint8_t *p_with);

void salti_create_m1(salt_channel_t *p_channel,
                     uint8_t *p_data,
                     uint32_t *size,
                     uint8_t *p_hash,
                     uint8_t *p_with);

salt_ret_t salti_handle_a1_create_a2(salt_channel_t *p_channel,
                                     uint8_t *p_data,
                                     uint32_t size);

salt_state_t salti_handle_m1(salt_channel_t *p_channel,
                             uint8_t *p_data,
                             uint32_t size,
                             uint8_t *p_hash);

salt_state_t salti_create_m2(salt_channel_t *p_channel,
                             uint8_t *p_data,
                             uint32_t *size,
                             uint8_t *p_hash);

salt_ret_t salti_handle_m2(salt_channel_t *p_channel,
                           uint8_t *p_data,
                           uint32_t size,
                           uint8_t *p_hash);

void salti_create_m3m4_sig(salt_channel_t *p_channel,
                           uint8_t *p_data,
                           uint32_t *size);

salt_state_t salti_verify_m3m4_sig(salt_channel_t *p_channel,
                                   uint8_t *p_data,
                                   uint32_t size);

#endif /* _SALTI_HANDSHAKE_H_ */

