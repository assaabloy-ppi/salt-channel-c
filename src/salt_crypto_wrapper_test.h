#ifndef _salt_crypto_wrapper_test_H_
#define _salt_crypto_wrapper_test_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file salt_crypto_wrapper_test.h
 *
 * Test suite for salt crypto wrapper.
 * 
 * TODO:
 *  - Add tests for all functions.
 *  - Add performance tests (target specific measurements must be provided)
 */

/*======= Includes ==========================================================*/

#include "salt_crypto_wrapper.h"

/*======= Public macro definitions ==========================================*/
/*======= Type Definitions and declarations =================================*/
/*======= Public variable declarations ======================================*/
/*======= Public function declarations ======================================*/

/**
 * @brief Tests all crypto API functions.
 *
 * Runs all test cases as defined below.
 *
 * @return 0    Tests passed
 * @return != 0 Tests failed
 */
int salt_crypto_wrapper_test(void);

/**
 * @brief Tests key agreement functionality.
 * 
 * Tests the functionality based on predefined key pairs and
 * also by generating key kairs for two peers and verifying that
 * the common calculated key does not differ.
 * 
 * @return 0    Test passed
 * @return != 0 Test failed
 */
int test_api_crypto_box_beforenm(void);
int test_api_crypto_box_afternm(void);
int test_api_crypto_sign(void);
int test_api_crypto_hash(void);

#ifdef __cplusplus
}
#endif

#endif /* _salt_crypto_wrapper_test_H_ */
