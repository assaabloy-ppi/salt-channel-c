/**
 * @file cfifo.c
 *
 * Description
 *
 */

/*======= Includes ==========================================================*/

/* Local includes */
#include "cfifo.h"

/* C-Library includes */
#include <string.h> /* For memcpy */

/*======= Local Macro Definitions ===========================================*/

#ifndef MIN
#define MIN(a,b) ((a) < (b)) ? (a) : (b)
#endif

#define CFIFO_SIZE      (p_cfifo->write_pos - p_cfifo->read_pos)
#define CFIFO_WRITE_POS (p_cfifo->write_pos % p_cfifo->buf_size)
#define CFIFO_READ_POS  (p_cfifo->read_pos % p_cfifo->buf_size)
#define CFIFO_WRITE_OFFSET  (CFIFO_WRITE_POS * p_cfifo->item_size)
#define CFIFO_READ_OFFSET   (CFIFO_READ_POS * p_cfifo->item_size)

/*======= Local function prototypes =========================================*/

static void cfifoi_put(cfifo_t *p_cfifo, const void *p_item);
static void cfifoi_get(cfifo_t *p_cfifo, void *p_item);

/*======= Global function implementations ===================================*/

cfifo_ret_t cfifo_init(cfifo_t *p_cfifo,
                       uint8_t *p_buf,
                       uint32_t buf_size,
                       uint32_t item_size)
{
    if (p_cfifo == NULL || p_buf == NULL) {
        /* Error, null pointers. */
        return CFIFO_ERR_NULL;
    }

    p_cfifo->p_buf = p_buf;
    p_cfifo->buf_size = buf_size;
    p_cfifo->item_size = item_size;
    p_cfifo->read_pos = 0;
    p_cfifo->write_pos = 0;

    return CFIFO_SUCCESS;
}

cfifo_ret_t cfifo_put(cfifo_t *p_cfifo,
                      const void *p_item)
{
    if (p_cfifo == 0 || p_item == 0) {
        /* Error, null pointers. */
        return CFIFO_ERR_NULL;
    }

    if (CFIFO_SIZE < p_cfifo->buf_size) {
        cfifoi_put(p_cfifo, p_item);
        return CFIFO_SUCCESS;
    }
    return CFIFO_ERR_FULL;
}

cfifo_ret_t cfifo_write(cfifo_t *p_cfifo,
                        const void *p_items,
                        uint32_t *p_num_items)
{
    uint32_t i;
    uint8_t *p_src = (uint8_t *) p_items;

    if (p_cfifo == 0 || p_items == 0 || p_num_items == 0) {
        /* Error, null pointers. */
        return CFIFO_ERR_NULL;
    }

    (*p_num_items) = MIN((*p_num_items), p_cfifo->buf_size - CFIFO_SIZE);

    for (i = 0; i < (*p_num_items); i++)
    {
        cfifoi_put(p_cfifo, &p_src[i * p_cfifo->item_size]);
    }

    return CFIFO_SUCCESS;

}

cfifo_ret_t cfifo_get(cfifo_t *p_cfifo,
                      void *p_item)
{
    if (p_cfifo == NULL || p_item == NULL) {
        /* Error, null pointers. */
        return CFIFO_ERR_NULL;
    }

    if (CFIFO_SIZE > 0)
    {
        cfifoi_get(p_cfifo, p_item);
        return CFIFO_SUCCESS;
    }
    return CFIFO_ERR_EMPTY;
}

cfifo_ret_t cfifo_read(cfifo_t *p_cfifo,
                       void *p_items,
                       uint32_t *p_num_items)
{

    uint32_t i;
    uint8_t *p_dest = (uint8_t *) p_items;

    if (p_cfifo == NULL || p_items == NULL || p_num_items == NULL) {
        /* Error, null pointers. */
        return CFIFO_ERR_NULL;
    }

    (*p_num_items) = MIN((*p_num_items), CFIFO_SIZE);

    for (i = 0; i < (*p_num_items); i++) {
        cfifoi_get(p_cfifo, &p_dest[i * p_cfifo->item_size]);
    }

    return CFIFO_SUCCESS;

}

cfifo_ret_t cfifo_peek(cfifo_t *p_cfifo,
                       void *p_item)
{
    if (p_cfifo == NULL || p_item == NULL) {
        /* Error, null pointers. */
        return CFIFO_ERR_NULL;
    }

    memcpy(p_item,
           &p_cfifo->p_buf[CFIFO_READ_OFFSET],
           p_cfifo->item_size);

    return CFIFO_SUCCESS;

}

uint32_t cfifo_size(cfifo_t *p_cfifo)
{
    return (p_cfifo) ? (p_cfifo->write_pos - p_cfifo->read_pos) : 0;
}

cfifo_ret_t cfifo_flush(cfifo_t *p_cfifo)
{
    if (p_cfifo == NULL) {
        /* Error, null pointers. */
        return CFIFO_ERR_NULL;
    }

    p_cfifo->write_pos = 0;
    p_cfifo->read_pos = 0;

    return CFIFO_SUCCESS;
}

/*======= Local function implementations ====================================*/

static void cfifoi_put(cfifo_t *p_cfifo, const void *p_item)
{
    memcpy(&p_cfifo->p_buf[CFIFO_WRITE_OFFSET],
           p_item,
           p_cfifo->item_size);
    p_cfifo->write_pos++;
}

static void cfifoi_get(cfifo_t *p_cfifo, void *p_item)
{
    memcpy(p_item,
           &p_cfifo->p_buf[CFIFO_READ_OFFSET],
           p_cfifo->item_size);
    p_cfifo->read_pos++;
}
