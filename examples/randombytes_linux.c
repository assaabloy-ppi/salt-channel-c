#include <stdlib.h>
#include <stdio.h>

void randombytes(unsigned char *p_bytes, unsigned long long length)
{
   FILE* fr = fopen("/dev/urandom", "r");
   if (!fr) perror("urandom"), exit(EXIT_FAILURE);
   size_t tmp = fread(p_bytes, sizeof(unsigned char), length, fr);
   (void) tmp;
   fclose(fr);
}
