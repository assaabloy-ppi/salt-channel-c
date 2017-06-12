#include "util.h"

void print_bytes(char *name, uint8_t *buffer, uint32_t size)
{
    printf("%s (%d): ", name, size);
    for (uint32_t i = 0; i < size; i++)
    {
        printf("%02x", buffer[i]);
    } printf("\r\n");
}

void print_bytes_c_style(char *name, uint8_t *buffer, uint32_t size)
{
    printf("%s[%d] = {\r\n    ", name, size);
    for (uint32_t i = 0; i < size; i++)
    {
        printf("0x%02x, ", buffer[i]);
        if ((i+1) % 8 == 0 && i < (size-1))
        {
            printf("\r\n    ");
        }
    } printf("\b\b \r\n};\r\n");
}
