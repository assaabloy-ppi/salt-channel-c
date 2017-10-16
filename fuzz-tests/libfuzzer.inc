#ifdef AFL
#include <unistd.h>
#else
#include <stdint.h>
#include <stddef.h>

const uint8_t *gdata = NULL;
size_t gsize = 0;

/* redefine <unistd.h> read() function */
uint32_t read(int fd, void *buf, size_t count)
{    
    size_t sz = count < gsize? count : gsize;
    if (buf && gdata && sz)
        memcpy(buf, gdata, sz);
    return sz;
}

/* forward declaration */
int _main(void);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

    gdata = data;
    gsize = size;

    _main();

    gdata = NULL;
    gsize = 0;

    return 0;
}
#define main(...) _main(__VA_ARGS__)
#endif /* AFL */
