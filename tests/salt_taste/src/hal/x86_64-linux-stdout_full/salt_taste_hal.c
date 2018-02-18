#define _BSD_SOURCE
#define _POSIX_C_SOURCE 199309L
#include <time.h>  

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include "salt_taste_hal.h"

#define ST_HAL_ELAPSED_COUNTERS    3


uint32_t get_info()
{
	return ST_HAL_HAS_CONSOLE | ST_HAL_HAS_PRINTF | ST_HAL_HAS_RNG;
}

int init()
{
	/*nothing to do on Linux */
	return 0;
}


int my_write(int fd, const char *buf, int count)
{
	return write(fd, buf, count);
}

int my_write_str(int fd, const char *msg)
{
	return my_write(fd, msg, strlen(msg)+1);  /* strlen() overhead, but let's simplify things for now */
}

int my_shutdown()
{
	/* flush buffers, etc*/
	fsync(STDOUT_FILENO);
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
			my_write_str(STDOUT_FILENO, msg);
			fsync(STDOUT_FILENO);
			abort();
		}
}

void rng(uint8_t *buf, uint64_t count)
{
   FILE* fr = fopen("/dev/urandom", "r");
   my_assert(fr != NULL, "can't open /dev/urandom.");

   size_t tmp = fread(buf, sizeof(unsigned char), count, fr);
   my_assert(tmp == count, "can't read requested number of random bytes");
   fclose(fr);
}

void my_sleep(uint32_t ms)
{
	usleep(ms * 1000);
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
		return diff.tv_sec * 1000ULL + diff.tv_nsec / 1000ULL; //1000000ULL;
	}

}


void notify(enum salt_taste_event_e event, enum salt_taste_status_e status)
{
	/* just debug output */
	my_dprintf(STDOUT_FILENO, "EVENT: id=%-18s status=%-18s\n", salt_taste_event_tostr(event), 
		 													salt_taste_status_tostr(status));
}


int main(int argc, char *argv[])
{
	int ret;
	salt_taste_hal_api_t hal;

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