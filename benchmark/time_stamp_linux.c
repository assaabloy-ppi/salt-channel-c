#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "time_stamp.h"

void randombytes(unsigned char *p_bytes, unsigned long long length)
{
    FILE* fr = fopen("/dev/urandom", "r");
    if (!fr) { perror("urandom"); exit(EXIT_FAILURE); }
    size_t tmp = fread(p_bytes, sizeof(unsigned char), length, fr);
    fclose(fr);
    if (tmp != length)
    {
        assert(0);
    }

}


double time_stamps_get_millis(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    double curr_time = (((double)tv.tv_sec) * 1000.0f) + (((double)(tv.tv_usec)) / 1000.0f);
    return curr_time;
}

int time_stamps_printf(const char *format, va_list arg)
{
    return vprintf(format, arg);
}
