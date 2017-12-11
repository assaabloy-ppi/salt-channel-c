#include "io430.h"
#include <intrinsics.h>  /* delays */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>  
#include <time.h>  

#include "salt_taste_hal.h"

#define ST_HAL_ELAPSED_COUNTERS    3

#ifndef SIMULATE
void initUART()
{ 
}
#endif

uint32_t get_info()
{
	return ST_HAL_HAS_CONSOLE | ST_HAL_HAS_PRINTF | ST_HAL_HAS_RNG;
}

int init()
{
	time_t t;

	srand((unsigned) time(&t));

#ifndef SIMULATE
  initUART();
#endif

	return 0;
}


int my_write(int fd, const char *buf, int count)
{
	/* do it via printf() for now, since DLIB configs (Normal, Full) seems missing in my (ppmag's) inst. */
	return printf("%.*s", count, buf);	
	//return write(fd, buf, count);
}

int my_write_str(int fd, const char *msg)
{
	return printf("%s", msg);	
}

int my_shutdown()
{
	/* flush buffers, etc*/
	return 0;
}

int my_dprintf(int fd, const char *format, ...)
{
    va_list args;
    int res;

    va_start(args, format);
    res = vprintf(format, args);  /* for now just ignore fd and write to stdout */
    va_end(args);
    return res;
}


/* platform dependant assert() implementation */
void my_assert(int expr, const char *msg)
{
	if (!expr)
		{
			my_write_str(0, msg);
			abort();
		}
}

void rng(uint8_t *buf, uint64_t count)
{
  for (int i=0; i<count; i++)
  	buf[i] = rand() % 0xff;
}

void my_sleep(uint32_t ms)
{
	for(int i = 0; i < ms; i++)
	  __delay_cycles(CLOCKS_PER_SEC / 1000);
}

/* return number of elapsed counters supported by HAL */    
int get_elapsed_counters_num()
{
    return ST_HAL_ELAPSED_COUNTERS;
}

uint64_t trigger_elapsed_counter(int counter_idx, bool start_it)
{
	clock_t ts[ST_HAL_ELAPSED_COUNTERS];
	clock_t end, diff;
 
	if (start_it)
	{
		/* see https://www.iar.com/support/resources/articles/using-c-standard-library-time-and-clock-functions/ */
		ts[counter_idx] = clock();  
		return 0ULL;
	}
	else {
		end = clock();
		diff = end - ts[counter_idx];
	}

	return diff * 1000 / CLOCKS_PER_SEC;
}


void notify(enum salt_taste_event_e event, enum salt_taste_status_e status)
{
	/* just debug output */
	my_dprintf(0, "EVENT: id=%-10s status=%-10s\n", salt_taste_event_tostr(event), 
		 													salt_taste_status_tostr(status));
}


int main(int argc, char *argv[])
{
	int ret;
	salt_taste_hal_api_t hal;

 	// Stop watchdog timer to prevent time out reset
  	WDTCTL = WDTPW + WDTHOLD;

	salt_test_hal_init(&hal);
	ret = hal.entry_point(&hal, argc, argv);
	salt_test_hal_shutdown(&hal);
	return ret;
}


int salt_test_hal_init(salt_taste_hal_api_t *hal)
{
	salt_taste_hal_api_t tmp =  {
		.get_info = get_info,
		.entry_point = salt_taste_entry_point,  /* should NOT be changed in new HAL templete instances*/
		.init = init,
		.shutdown = my_shutdown,
		.write = my_write,
		.write_str = my_write_str,
		.dprintf = my_dprintf,
		.assert = my_assert,
		.rng = rng,
		.sleep = my_sleep,
		.get_elapsed_counters_num = get_elapsed_counters_num,
		.trigger_elapsed_counter = trigger_elapsed_counter, 
		.notify = notify
	};	

	*hal = tmp;
	hal->cfg = hal->get_info();  /* set ON all platform features by default */

	hal->init();
	return 0;
}

int salt_test_hal_shutdown(salt_taste_hal_api_t *hal)
{
	hal->shutdown();  /* TODO: checks for NULL */
	return 0;
}
