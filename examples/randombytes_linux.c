#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

void my_randombytes(unsigned char *p_bytes, unsigned long long length)
{
    FILE* fr = fopen("/dev/urandom", "r");
    if (fr == NULL) { perror("urandom"); exit(EXIT_FAILURE); }
    size_t tmp = fread(p_bytes, sizeof(unsigned char), length, fr);
    fclose(fr);
    if (tmp != length)
    {
        assert(0);
    }
    
}
