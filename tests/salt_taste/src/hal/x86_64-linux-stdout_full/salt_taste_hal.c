#include <stdlib.h>
#include <stdio.h>
#include <time.h>  
#include <varargs.h>

#include "salt_taste_hal.h"

#define ST_HAL_ELAPSED_COUNTERS    3


int salt_test_hal_init(salt_taste_hal_api_t *hal)
{
	salt_taste_hal_api_t tmp =  {
		.get_info = get_info,
		.entry_point = salt_taste_entry_point,  /* should NOT be changed in new HAL templete instances*/
		.init = init,
		.write = my_write,
		.write_str = my_write_str,
		.printf = my_printf,
		.assert = my_assert,
		.rng = rng,
		.get_elapsed_counters_num = get_elapsed_counters_num,
		.trigger_elapsed_counter = trigger_elapsed_counter, 
		.notify = notify
	};	

	*hal = tmp;
	hal->cfg = hal->get_info();  /* set ON all platform features by default */

	hal->init();
}

uint32_t get_info()
{
	return ST_HAL_HAS_CONSOLE | ST_HAL_HAS_PRINTF | ST_HAL_HAS_RNG;
}

int init()
{
	// nothing to do on Linux
}

int my_write_str(int fd, const char *msg)
{
	return my_write(fd, msg, strlen(msg)+1); /* to simplify things */
}

int my_write(int fd, const char *buf, int count)
{
	return write(fd, buf, count);
}

int my_printf(const char *format, ...)
{
    va_list args;
    int res;

    va_start(args, fmt);
    res = printf(fmt, args);
    va_end(args);
    return res;
}

/* platform dependant assert() implementation */
void my_assert(int expr, const char *msg)
{
	if (!expr)
		{
			my_write_str(stderr, msg);
			flush(stderr);
			abort();
		}
}

void rng(uint8_t *buf, uint64_t count)
{
   FILE* fr = fopen("/dev/urandom", "r");
   my_assert(fr, "can't open /dev/urandom.");

   size_t tmp = fread(buf, sizeof(unsigned char), count, fr);
   my_assert(tmp == count, "can't read requested number of random bytes");
   assert_true(tmp == count);
   fclose(fr);
}


/* return number of elapsed counters supported by HAL */    
int get_elapsed_counters_num()
{
    return ST_HAL_ELAPSED_COUNTERS;
}

uint64_t trigger_elapsed_counter(int counter_idx, bool start_it)
{
	static struct timespec ts[ST_HAL_ELAPSED_COUNTERS];
	struct timespec end, diff;

	if (start_it)
	{
		clock_gettime(CLOCK_MONOTONIC, &ts[counter_idx]);
		return 0ULL;
	}
	else
	{
		clock_gettime(CLOCK_MONOTONIC, &end);

	    if ((end.tv_nsec - ts[counter_idx].tv_nsec) < 0)
	    {
		  diff.tv_sec = end.tv_sec-ts[counter_idx].tv_sec-1;
		  diff.tv_nsec = 1000000000 + end.tv_nsec - ts[counter_idx].tv_nsec;
	    } else {
		  diff.tv_sec = end.tv_sec - ts[counter_idx].tv_sec;
		  diff.tv_nsec = end.tv_nsec - ts[counter_idx].tv_nsec;
	    }
		return diff.tv_sec * 1000ULL + diff.tv_nsec / 1000000ULL;
	}

}


void notify(enum salt_taste_event_e event, enum salt_taste_status_e status)
{
	// just debug output
	my_printf("EVENT: id=%d, status=%d \n", event, status);


}


int main(int argc, char *argv[])
{
	salt_taste_hal_api_t hal;

	salt_test_hal_init(&hal);
	return hal.entry_point(&hal, argc, argv);	
}
