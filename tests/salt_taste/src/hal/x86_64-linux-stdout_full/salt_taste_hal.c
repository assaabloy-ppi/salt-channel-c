#include <stdio.h>  
#include <time.h>  
#include <varargs.h>

#include "salt_taste_hal.h"

int salt_test_hal_init(salt_taste_hal_api_t *hal)
{
	salt_taste_hal_api_t tmp =  {
		.get_info = get_info,
		.entry_point = main,
		.init = init,
		.write = my_write,
		.printf = my_printf,
		.rng = rng,
		.ticks = ticks,
		.ticks_to_ms_ratio = ticks_to_ms_ratio,
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
}

int my_write(int fd, const char *buf, int count)
{
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

void rng(uint8_t *buf, uint64_t count)
{
   /*FILE* fr = fopen("/dev/urandom", "r");
   if (!fr) 
   size_t tmp = fread(p_bytes, sizeof(unsigned char), length, fr);
   fclose(fr);*/
}

uint64_t get_ticks()
{
	struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);

}
    
float ticks_to_ms_ratio()
{

}

void notify(enum salt_taste_event_e event, enum salt_taste_status_e status)
{
	// just debug output
}


int main(int argc, char *argv[])
{
	salt_taste_hal_api_t hal;

	salt_test_hal_init(&hal);
	return hal.entry_point();	
}
