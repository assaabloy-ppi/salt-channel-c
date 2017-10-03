/**
 * @file salt_util.c
 *
 * Description
 *
 */

/*======= Includes ==========================================================*/

#include "salt_util.h"

/*======= Local Macro Definitions ===========================================*/
/*======= Type Definitions ==================================================*/
/*======= Local function prototypes =========================================*/
/*======= Local variable declarations =======================================*/
/*======= Global function implementations ===================================*/

char *salt_mode2str(salt_mode_t mode)
{
    switch (mode) {
        case SALT_SERVER:
            return "SALT_SERVER";
        case SALT_CLIENT:
            return "SALT_CLIENT";
        default:
            return "UNKNOWN MODE";
    }
}

/*======= Local function implementations ====================================*/
