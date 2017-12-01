#include "salt_taste_hal.h"
#include "salt_taste_event.h"
#include "salt_taste.h"


static bool test_platform(salt_taste_hal_api_t *hal);
static bool test_elapsed_timer(salt_taste_hal_api_t *hal);
static bool test_rng(salt_taste_hal_api_t *hal);


/* HAL entry point should pass control here */
int salt_taste_entry_point(salt_taste_hal_api_t *hal, int argc, char *argv[])
{
	bool success = false;
	
	hal->notify(SALT_TASTE_EVENT_READY, SALT_TASTE_STATUS_SUCCESS);

	success = test_platform(hal);
	if (!success) {
		hal->notify(SALT_TASTE_EVENT_HAL_TEST_STATUS, SALT_TASTE_STATUS_FAILURE);
		hal->write_str(1, "platform test failed!");
		hal->notify(SALT_TASTE_EVENT_SHUTDOWN, SALT_TASTE_STATUS_FAILURE);
		return -1;
	}



	hal->notify(SALT_TASTE_EVENT_SHUTDOWN, SALT_TASTE_STATUS_SUCCESS);
	
	//log shutdown
}



static bool test_platform(salt_taste_hal_api_t *hal)
{

}

static bool test_elapsed_timer(salt_taste_hal_api_t *hal)
{

}

static bool test_rng(salt_taste_hal_api_t *hal)
{

}
