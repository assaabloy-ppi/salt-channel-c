#ifndef _SALT_TASTE_EVENT_H_
#define _SALT_TASTE_EVENT_H_

#ifdef __cplusplus
extern "C" {
#endif

enum salt_taste_status_e {
    SALT_TASTE_STATUS_UNKNOWN = 0,

    SALT_TASTE_STATUS_INIT,
    SALT_TASTE_STATUS_SUCCESS,
    SALT_TASTE_STATUS_FAILURE,

    SALT_TASTE_STATUS_COUNT  /* used for array declaration */
};



enum salt_taste_event_e {
    SALT_TASTE_EVENT_UNKNOWN = 0,
    SALT_TASTE_EVENT_READY,                  /**< salt_taste suite started */

    SALT_TASTE_EVENT_RNG_TEST_STATUS,        /**< */
    SALT_TASTE_EVENT_TIMER_TEST_STATUS,      /**< */
    SALT_TASTE_EVENT_HAL_TEST_STATUS,        /**< Summary of above: check if the HAL implemented in consistent way. */
    SALT_TASTE_EVENT_CRYPTO_SANITY_STATUS,   /**< Success. */
    SALT_TASTE_EVENT_CRYPTO_PERFMETER_STARTED,
    SALT_TASTE_EVENT_CRYPTO_PERFMETER_STOPPED,
    SALT_TASTE_EVENT_SC_HANDSHAKE_BEGIN,
    SALT_TASTE_EVENT_SC_HANDSHAKE_END,

    SALT_TASTE_EVENT_SHUTDOWN,                /**< no more tests, shutting down */

    SALT_TASTE_EVENT_COUNT                    /* used for array declaration */
};
typedef enum salt_taste_event_e salt_taste_event_t;


const char* salt_taste_status_tostr(enum salt_taste_status_e status);
const char* salt_taste_event_tostr(enum salt_taste_event_e event);


#ifdef __cplusplus
}
#endif

#endif /* _SALT_TASTE_EVENT_H_ */