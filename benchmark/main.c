/**
 * @file time_stamp.c
 *
 * Description
 *
 */

/*======= Includes ==========================================================*/

#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "time_stamp.h"
#include "salt.h"
#include "crypto_benchmark.h"
#include "client_handshake_benchmark.h"
#include "host_handshake_benchmark.h"

/*======= Local Macro Definitions ===========================================*/
/*======= Type Definitions ==================================================*/
/*======= Local function prototypes =========================================*/
/*======= Local variable declarations =======================================*/
/*======= Global function implementations ===================================*/

int main(void) {

    time_stamps_t stamps;
    time_stamps_init(&stamps, "Benchmark");

    assert(run_crypto_benchmark(&stamps));
    assert(run_client_handshake_benchmark(&stamps));
    assert(run_host_handshake_benchmark(&stamps));


    time_stamps_result(&stamps);
    
    return 0;
}

/*======= Local function implementations ====================================*/

