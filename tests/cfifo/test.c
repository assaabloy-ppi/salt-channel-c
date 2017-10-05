#include <stdio.h>
#include <assert.h>

#include "cfifo.h"

struct test {
    uint8_t a;
    uint16_t b;
    uint32_t c;
    uint8_t *d;
};

int struct_test(void)
{

    cfifo_t *fifo;
    uint8_t b = 4;
    struct test s;
    struct test h;

    CFIFO_CREATE(fifo, sizeof(struct test), 15);
    
    s.a = 1;
    s.b = 2;
    s.c = 3;
    s.d = &b;

    assert(cfifo_put(fifo, &s) == CFIFO_SUCCESS);
    assert(cfifo_size(fifo) == 1);
    assert(cfifo_get(fifo, &h) == CFIFO_SUCCESS);
    assert(h.a == 1);
    assert(h.b == 2);
    assert(h.c == 3);
    assert(s.d == &b);

    return 0;

}

int main(void)
{

    cfifo_t *fifo;
    uint8_t a;
    uint8_t b;
    uint32_t size;
    uint32_t i;

    uint8_t rdata[15];
    uint8_t data[15];

    assert(struct_test() == 0);

    CFIFO_CREATE(fifo, 1, 15);

    /* Empty queue from stat */
    assert(cfifo_size(fifo) == 0);
    assert(cfifo_get(fifo, &b) == CFIFO_ERR_EMPTY);

    /* One queue item */
    a = 1;
    assert(cfifo_put(fifo, &a) == CFIFO_SUCCESS);
    assert(cfifo_size(fifo) == 1);
    assert(cfifo_get(fifo, &b) == CFIFO_SUCCESS);
    assert(b == a);
    assert(cfifo_size(fifo) == 0);

    /* Fill and empty queue */
    for (i = 0; i < 15; i++)
    {
        a = (uint8_t) i;
        assert(cfifo_put(fifo, &a) == CFIFO_SUCCESS);
        assert(cfifo_size(fifo) == (i+1));
    }

    assert(cfifo_put(fifo, &a) == CFIFO_ERR_FULL);

    for (i = 0; i < 15; i++)
    {
        assert(cfifo_get(fifo, &a) == CFIFO_SUCCESS);
        assert(a == i);
        assert(cfifo_size(fifo) == 14 - i);
    }

    assert(cfifo_get(fifo, &b) == CFIFO_ERR_EMPTY);

    for (i = 0; i < 15; i++)
    {
        data[i] = i+1;
    }

    size = 15;

    assert(cfifo_write(fifo, data, &size) == CFIFO_SUCCESS);
    assert(size == 15);
    assert(cfifo_size(fifo) == 15);

    
    size = 15;
    assert(cfifo_read(fifo, rdata, &size) == CFIFO_SUCCESS);
    for (i = 0; i < 15; i++)
    {
        assert(rdata[i] == data[i]);
    }
    assert(size == 15);
    assert(cfifo_size(fifo) == 0);

    size = 13;

    assert(cfifo_write(fifo, data, &size) == CFIFO_SUCCESS);
    assert(size == 13);
    assert(cfifo_size(fifo) == 13);

    assert(cfifo_get(fifo, &a) == CFIFO_SUCCESS);
    assert(a == data[0]);
    assert(cfifo_get(fifo, &a) == CFIFO_SUCCESS);
    assert(a == data[1]);
    assert(cfifo_size(fifo) == 11);

    size = 7;
    assert(cfifo_read(fifo, rdata, &size) == CFIFO_SUCCESS);
    assert(size == 7);
    for (i = 0; i < 7; i++)
    {
        assert(rdata[i] == data[2+i]);
    }
    assert(cfifo_size(fifo) == 4);

    /* Simulate fifo counter overflow */
    fifo->write_pos = UINT32_MAX;
    fifo->read_pos = UINT32_MAX;
    assert(cfifo_size(fifo) == 0);

    /* One queue item */
    a = 67;
    assert(cfifo_put(fifo, &a) == CFIFO_SUCCESS);
    assert(cfifo_size(fifo) == 1);
    assert(cfifo_peek(fifo, &b) == CFIFO_SUCCESS);
    assert(b == a);
    assert(cfifo_size(fifo) == 1);
    assert(cfifo_get(fifo, &b) == CFIFO_SUCCESS);
    assert(b == a);
    assert(cfifo_size(fifo) == 0);

    for (i = 0; i < 15; i++)
    {
        data[i] = i+1;
    }

    size = 17;

    assert(cfifo_write(fifo, data, &size) == CFIFO_SUCCESS);
    assert(size == 15);
    assert(cfifo_size(fifo) == 15);
    assert(cfifo_flush(fifo) == CFIFO_SUCCESS);
    assert(cfifo_size(fifo) == 0);

    assert(cfifo_put(NULL, &a) == CFIFO_ERR_NULL);
    assert(cfifo_put(NULL, NULL) == CFIFO_ERR_NULL);
    assert(cfifo_put(fifo, NULL) == CFIFO_ERR_NULL);

    assert(cfifo_write(NULL, &a, &size) == CFIFO_ERR_NULL);
    assert(cfifo_write(NULL, NULL, &size) == CFIFO_ERR_NULL);
    assert(cfifo_write(NULL, NULL, NULL) == CFIFO_ERR_NULL);
    assert(cfifo_write(NULL, &a, NULL) == CFIFO_ERR_NULL);
    assert(cfifo_write(fifo, &a, NULL) == CFIFO_ERR_NULL);
    assert(cfifo_write(NULL, &a, NULL) == CFIFO_ERR_NULL);
    assert(cfifo_write(fifo, NULL, NULL) == CFIFO_ERR_NULL);
    assert(cfifo_write(fifo, NULL, &size) == CFIFO_ERR_NULL);


    assert(cfifo_read(NULL, &a, &size) == CFIFO_ERR_NULL);
    assert(cfifo_read(NULL, NULL, &size) == CFIFO_ERR_NULL);
    assert(cfifo_read(NULL, NULL, NULL) == CFIFO_ERR_NULL);
    assert(cfifo_read(NULL, &a, NULL) == CFIFO_ERR_NULL);
    assert(cfifo_read(fifo, &a, NULL) == CFIFO_ERR_NULL);
    assert(cfifo_read(NULL, &a, NULL) == CFIFO_ERR_NULL);
    assert(cfifo_read(fifo, NULL, NULL) == CFIFO_ERR_NULL);
    assert(cfifo_read(fifo, NULL, &size) == CFIFO_ERR_NULL);


    assert(cfifo_get(NULL, &a) == CFIFO_ERR_NULL);
    assert(cfifo_get(NULL, NULL) == CFIFO_ERR_NULL);
    assert(cfifo_get(fifo, NULL) == CFIFO_ERR_NULL);

    assert(cfifo_peek(NULL, &a) == CFIFO_ERR_NULL);
    assert(cfifo_peek(NULL, NULL) == CFIFO_ERR_NULL);
    assert(cfifo_peek(fifo, NULL) == CFIFO_ERR_NULL);

    assert(cfifo_flush(NULL) == CFIFO_ERR_NULL);

    assert(cfifo_init(NULL, NULL, 0, 0) == CFIFO_ERR_NULL);

    printf("cfifo test passed!\r\n");

    return 0;

}
