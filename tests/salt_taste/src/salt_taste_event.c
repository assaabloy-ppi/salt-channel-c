#include "salt_taste_event.h"

const char* const _st_status_str[] = { 
	"???",  	/* SALT_TASTE_STATUS_UNKNOWN */
	"init",		/* SALT_TASTE_STATUS_INIT */	
	"done/ok",	/* SALT_TASTE_STATUS_SUCCESS */
	"fail"		/* SALT_TASTE_STATUS_FAILURE */
};

const char* const _st_event_str[] = { 
	"???",  			/* SALT_TASTE_EVENT_UNKNOWN */
	"ready",			/* SALT_TASTE_EVENT_READY */
	"rng",				/* SALT_TASTE_EVENT_RNG_TEST_STATUS */
	"timer",			/* SALT_TASTE_EVENT_TIMER_TEST_STATUS */
	"HAL",				/* SALT_TASTE_EVENT_HAL_TEST_STATUS */
	"crypto_sanity",	/* SALT_TASTE_EVENT_CRYPTO_SANITY_STATUS */
	"perf_start",		/* SALT_TASTE_EVENT_CRYPTO_PERFMETER_STARTED */
	"perf_stop",		/* SALT_TASTE_EVENT_CRYPTO_PERFMETER_STOPPED */
	"handshake",		/* SALT_TASTE_EVENT_SC_HANDSHAKE */
	"shutdown",				/* SALT_TASTE_EVENT_SHUTDOWN */		
};


const char* salt_taste_status_tostr(enum salt_taste_status_e status)
{
	return _st_status_str[status];
}

const char* salt_taste_event_tostr(enum salt_taste_event_e event)
{
	return _st_event_str[event];
}
