#ifndef _SALT_UTIL_H_
#define _SALT_UTIL_H_
/**
 * @file salt_util.h
 *
 * Description
 *
 */

/*======= Includes ==========================================================*/

#include <stdio.h>
#include "salt_v2.h"

/*======= Public macro definitions ==========================================*/


#define SALT_HEXDUMP(ptr, size)                                             \
do {                                                                        \
    uint32_t i;                                                             \
    uint8_t *iptr = (uint8_t *) ptr;                                        \
    printf("%s:%d: %s (%d):\r\n",                                           \
        __FILE__, __LINE__, #ptr, (size));                                  \
    for (i = 0; i < (size); i++) {                                          \
        printf("%02x", iptr[i]);                                            \
    } printf("\r\n");                                                       \
} while(0)

/*======= Type Definitions and declarations =================================*/
/*======= Public variable declarations ======================================*/
/*======= Public function declarations ======================================*/


/**
 * @brief Return a pointer to salt mode string.
 * 
 * @param mode Salt mode to print
 * @return Return a pointer to salt mode string
 */
char *salt_mode2str(salt_mode_t mode);

#endif /* _SALT_UTIL_H_ */
