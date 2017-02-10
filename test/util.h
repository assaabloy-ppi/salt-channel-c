#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdint.h>
#include <stdio.h>

void print_bytes(char *name, uint8_t *buffer, uint32_t size);
void print_bytes_c_style(char *name, uint8_t *buffer, uint32_t size);

#define PRINT_BYTES(buffer, size) print_bytes(#buffer, buffer, size)
#define PRINT_BYTES_C(buffer, size) print_bytes_c_style(#buffer, buffer, size)


#endif
