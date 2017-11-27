
opt:
use_printf
use_hal_rng
use_output / silent mode

event_callback crypto_api

calls:


test_rng


bool test_platform(struct crypto_test_hal *test_hal);
bool test_sanity(salt_crypto_api_t *crypto_api, struct crypto_test_hal *test_hal);
bool test_performance(salt_crypto_api_t *crypto_api, struct crypto_test_hal *test_hal);
uint32_t ms_for_handshake((salt_crypto_api_t *crypto_api, struct crypto_test_hal *test_hal); 
