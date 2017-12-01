#ifndef _SALT_TASTE_H_
#define _SALT_TASTE_H_

#ifdef __cplusplus
extern "C" {
#endif

/*
opt:
use_printf
use_hal_rng
use_output / silent mode

event_callback crypto_api

calls:


test_rng
*/

int salt_taste_entry_point(salt_taste_hal_api_t *hal, int argc, char *argv[]);

//bool test_platform(salt_taste_hal_api_t *hal);
//bool test_sanity(salt_crypto_api_t *crypto_api, struct crypto_test_hal *test_hal);
//bool test_performance(salt_crypto_api_t *crypto_api, struct crypto_test_hal *test_hal);
//uint32_t ms_for_handshake((salt_crypto_api_t *crypto_api, struct crypto_test_hal *test_hal); 


#ifdef __cplusplus
}
#endif

#endif /* _SALT_TASTE_H_ */