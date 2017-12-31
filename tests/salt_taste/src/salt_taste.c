#include <stdlib.h>

#include "salt_taste_hal.h"
#include "salt_taste_event.h"
#include "salt_taste.h"

#ifndef HAL_TEST_TIMER
#define HAL_TEST_TIMER ON
#endif

#ifndef HAL_TEST_RNG
#define HAL_TEST_RNG ON
#endif

static bool test_platform(salt_taste_hal_api_t *hal);
static bool test_elapsed_timer(salt_taste_hal_api_t *hal);
static bool test_rng(salt_taste_hal_api_t *hal);


/* HAL entry point should pass control here */
int salt_taste_entry_point(salt_taste_hal_api_t *hal, int argc, char *argv[])
{
	bool success = false;
	
	hal->notify(SALT_TASTE_EVENT_READY, SALT_TASTE_STATUS_SUCCESS);

	/* testing platform HAL */
	success = test_platform(hal);

	hal->notify(SALT_TASTE_EVENT_SHUTDOWN, SALT_TASTE_STATUS_INIT);
	return 0;
}



static bool test_platform(salt_taste_hal_api_t *hal)
{
	bool success = true;

	hal->notify(SALT_TASTE_EVENT_HAL_TEST_STATUS, SALT_TASTE_STATUS_INIT);
	
#if (HAL_TEST_TIMER == ON)
	success = test_elapsed_timer(hal);
#endif

#if (HAL_TEST_RNG == ON)
	if (success)
		success = test_rng(hal);
#endif

	if (success) {
		hal->notify(SALT_TASTE_EVENT_HAL_TEST_STATUS, SALT_TASTE_STATUS_SUCCESS);
		return true;
	}
	else {
		hal->notify(SALT_TASTE_EVENT_HAL_TEST_STATUS, SALT_TASTE_STATUS_FAILURE);
		hal->write_str(1, "Platform (HAL) test failed!\r\n");
		return false;
	}
}

static bool test_elapsed_timer(salt_taste_hal_api_t *hal)
{
	bool success = false;
	uint64_t  ms;
	volatile  unsigned short  counter = 1;

	hal->notify(SALT_TASTE_EVENT_TIMER_TEST_STATUS, SALT_TASTE_STATUS_INIT);

	/* do the checks */
	hal->trigger_elapsed_counter(0, true);

	hal->sleep(1500);

	ms = hal->trigger_elapsed_counter(0, false);
	success = (ms > 1480 && ms < 1520)? true : false; 
	/* checks done */


	hal->notify(SALT_TASTE_EVENT_TIMER_TEST_STATUS, 
				success? SALT_TASTE_STATUS_SUCCESS : SALT_TASTE_STATUS_FAILURE);
	return success;
}

static bool test_rng(salt_taste_hal_api_t *hal)
{	
	bool success = false;
	/*const uint8_t sample_len = 128;*/
	enum { sample_len = 10 };
	const uint8_t low_ci_point = 128-25;
	const uint8_t high_ci_point = 128+25;

	uint8_t i, buf[sample_len];
	uint64_t val_acc = 0;
	uint8_t val_avg;

	hal->notify(SALT_TASTE_EVENT_RNG_TEST_STATUS, SALT_TASTE_STATUS_INIT);

	/* do the checks */
	hal->rng(buf, sample_len);

	/* quick and dirty test without full uniform distribution validation */
	for (i=0; i<sample_len; i++)
		val_acc += buf[i];

	val_avg = val_acc / sample_len;
	success = (val_avg > low_ci_point && val_avg < high_ci_point)? true : false;

	/* checks done */

	hal->notify(SALT_TASTE_EVENT_RNG_TEST_STATUS, 
				success? SALT_TASTE_STATUS_SUCCESS : SALT_TASTE_STATUS_FAILURE);
	return success;
}

