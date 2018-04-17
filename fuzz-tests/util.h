#ifndef _util_H_
#define _util_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file util.h.h
 *
 * Description
 *
 */

/*======= Includes ==========================================================*/
    
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "salt.h"

/*======= Public macro definitions ==========================================*/
/*======= Type Definitions and declarations =================================*/
/*======= Public variable declarations ======================================*/

extern salt_time_t mock_time;

/*======= Public function declarations ======================================*/

void randombytes(unsigned char *p_bytes, unsigned long long length);
void hexprint(const uint8_t *ptr, uint32_t size);
salt_ret_t fuzz_write(salt_io_channel_t *p_wchannel);
salt_ret_t fuzz_read(salt_io_channel_t *p_rchannel);

#ifdef __cplusplus
}
#endif

#endif /* _util_H_ */
