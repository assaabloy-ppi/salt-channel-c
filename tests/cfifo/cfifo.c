/**
 * @file cfifo.c
 *
 * Description
 *
 */

/*======= Includes ==========================================================*/

/* C-Library includes */
#include <string.h> /* For memcpy */

/* Local includes */
#include "cfifo.h"

/*======= Local Macro Definitions ===========================================*/

#ifndef MIN
#define MIN(a,b) ((a) < (b)) ? (a) : (b)
#endif

#define CFIFO_IS_POW_2(x)   (((x) > 0) && (((x) & (((x) - 1))) == 0))
#define CFIFO_WRITE_POS     (p_cfifo->write_pos & p_cfifo->num_items_mask)
#define CFIFO_READ_POS      (p_cfifo->read_pos & p_cfifo->num_items_mask)
#define CFIFO_WRITE_OFFSET  (CFIFO_WRITE_POS * p_cfifo->item_size)
#define CFIFO_READ_OFFSET   (CFIFO_READ_POS * p_cfifo->item_size)
#define CFIFO_SIZE          cfifoi_size(p_cfifo)
#define CFIFO_AVAILABLE     cfifoi_available(p_cfifo)

/*======= Local function prototypes =========================================*/

static size_t cfifoi_available(cfifo_t *p_cfifo);
static size_t cfifoi_size(cfifo_t *p_cfifo);
static void cfifoi_put(cfifo_t *p_cfifo, const void * const p_item);
static void cfifoi_get(cfifo_t *p_cfifo, void *p_item);

/*======= Global function implementations ===================================*/

cfifo_ret_t cfifo_init(cfifo_t *p_cfifo,
                       uint8_t *p_buf,
                       size_t num_items,
                       size_t item_size,
                       size_t buf_size)
{
    if (p_cfifo == NULL || p_buf == NULL) {
        /* Error, null pointers. */
        return CFIFO_ERR_NULL;
    }

    memset(p_cfifo, 0x00, sizeof(cfifo_t));

    if (!CFIFO_IS_POW_2(num_items)) {
        return CFIFO_ERR_BAD_SIZE;
    }

    if (!((item_size > 0) && (buf_size/item_size == num_items))) {
        return CFIFO_ERR_BAD_SIZE;
    }

    p_cfifo->p_buf = p_buf;
    p_cfifo->num_items_mask = num_items - 1;
    p_cfifo->item_size = item_size;
    p_cfifo->read_pos = 0;
    p_cfifo->write_pos = 0;

    return CFIFO_SUCCESS;
}

cfifo_ret_t cfifo_put(cfifo_t *p_cfifo,
                      const void * const p_item)
{
    if (p_cfifo == NULL || p_item == NULL) {
        /* Error, null pointers. */
        return CFIFO_ERR_NULL;
    }

    if (p_cfifo->p_buf == NULL) {
        return CFIFO_ERR_INVALID_STATE;
    }

    if (CFIFO_AVAILABLE > 0) {
        cfifoi_put(p_cfifo, p_item);
        return CFIFO_SUCCESS;
    }
    return CFIFO_ERR_FULL;
}

cfifo_ret_t cfifo_write(cfifo_t *p_cfifo,
                        const void * const p_items,
                        size_t *p_num_items)
{
    size_t i;
    uint8_t *p_src = (uint8_t *) p_items;

    if (p_cfifo == 0 || p_items == 0 || p_num_items == 0) {
        /* Error, null pointers. */
        return CFIFO_ERR_NULL;
    }

    if (p_cfifo->p_buf == NULL) {
        return CFIFO_ERR_INVALID_STATE;
    }

    (*p_num_items) = MIN((*p_num_items), CFIFO_AVAILABLE);

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

    if (p_cfifo->p_buf == NULL) {
        return CFIFO_ERR_INVALID_STATE;
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
                       size_t *p_num_items)
{

    size_t i;
    uint8_t *p_dest = (uint8_t *) p_items;

    if (p_cfifo == NULL || p_items == NULL || p_num_items == NULL) {
        /* Error, null pointers. */
        return CFIFO_ERR_NULL;
    }

    if (p_cfifo->p_buf == NULL) {
        return CFIFO_ERR_INVALID_STATE;
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

    if (p_cfifo->p_buf == NULL) {
        return CFIFO_ERR_INVALID_STATE;
    }

    if (CFIFO_SIZE > 0)
    {
        memcpy(p_item,
               &p_cfifo->p_buf[CFIFO_READ_OFFSET],
               p_cfifo->item_size);
        return CFIFO_SUCCESS;
    }
    return CFIFO_ERR_EMPTY;

}

size_t cfifo_contains(cfifo_t *p_cfifo,
                        void *p_item)
{

    /* Store original read pos. */
    size_t i;
    size_t size;
    size_t read_pos;
    size_t items_found = 0;

    if (p_cfifo == NULL || p_item == NULL || p_cfifo->p_buf == NULL) {
        /* Error, null pointers. */
        return 0;
    }

    read_pos = p_cfifo->read_pos;
    size = CFIFO_SIZE;

    for (i = 0; i < size; i++) {
        if (memcmp(p_item,
                   &p_cfifo->p_buf[CFIFO_READ_OFFSET],
                   p_cfifo->item_size) == 0) {
            items_found++;
        }
        p_cfifo->read_pos++;
    }

    p_cfifo->read_pos = read_pos;

    return items_found;
}

size_t cfifo_size(cfifo_t *p_cfifo)
{
    return (p_cfifo && p_cfifo->p_buf != NULL) ? CFIFO_SIZE : 0;
}

size_t cfifo_available(cfifo_t *p_cfifo)
{
    return (p_cfifo && p_cfifo->p_buf != NULL) ? CFIFO_AVAILABLE : 0;
}

cfifo_ret_t cfifo_flush(cfifo_t *p_cfifo)
{
    if (p_cfifo == NULL) {
        /* Error, null pointers. */
        return CFIFO_ERR_NULL;
    }

    if (p_cfifo->p_buf == NULL) {
        return CFIFO_ERR_INVALID_STATE;
    }

    p_cfifo->write_pos = 0;
    p_cfifo->read_pos = 0;

    return CFIFO_SUCCESS;
}

/*======= Local function implementations ====================================*/

static size_t cfifoi_available(cfifo_t *p_cfifo)
{
    return p_cfifo->num_items_mask + 1 - cfifoi_size(p_cfifo);
}
static size_t cfifoi_size(cfifo_t *p_cfifo)
{
    size_t tmp = p_cfifo->read_pos;
    return p_cfifo->write_pos - tmp;
}

static void cfifoi_put(cfifo_t *p_cfifo, const void * const p_item)
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
