#ifndef CFIFO_H_
#define CFIFO_H_

/**
 * @file cfifo.h
 *
 * Description
 *
 */

/*======= Includes ==========================================================*/

/* C-Library includes */
#include <stdint.h>

/*======= Public macro definitions ==========================================*/

#define CFIFO_CREATE(p_cfifo, item_size, num_items)                         \
    do {                                                                    \
        static cfifo_t cfifo;                                               \
        static uint8_t cfifo_buf[(item_size)*(num_items)];                  \
        cfifo_init(&cfifo, cfifo_buf, (num_items), (item_size));            \
        p_cfifo = &cfifo;                                                   \
    } while(0)

/*======= Type Definitions and declarations =================================*/

typedef struct cfifo_s {
    uint8_t             *p_buf;
    uint32_t            buf_size;
    uint32_t            item_size;
    volatile uint32_t   read_pos;
    volatile uint32_t   write_pos;
} cfifo_t;

typedef enum cfifo_ret_e {
    CFIFO_SUCCESS,
    CFIFO_ERR_NULL,
    CFIFO_ERR_EMPTY,
    CFIFO_ERR_FULL
} cfifo_ret_t;

/*======= Public function declarations ======================================*/

/**
 * @brief TODO: Brief description.
 *
 * TODO: Write description.
 *
 * @param   p_cfifo
 * @param   p_buf
 * @param   buf_size
 * @param   item_size
 *
 * @return  CFIFO_SUCCESS
 *
 */
cfifo_ret_t cfifo_init(cfifo_t *p_cfifo,
                       uint8_t *p_buf,
                       uint32_t buf_size,
                       uint32_t item_size);

/**
 * @brief TODO: Brief description.
 *
 * TODO: Write description.
 *
 * @param   p_cfifo
 * @param   p_item
 *
 * @return  CFIFO_SUCCESS
 *
 */
cfifo_ret_t cfifo_put(cfifo_t *p_cfifo,
                      const void *p_item);

/**
 * @brief TODO: Brief description.
 *
 * TODO: Write description.
 *
 * @param   p_cfifo
 * @param   p_items
 * @param   p_num_items
 *
 * @return  CFIFO_SUCCESS
 *
 */
cfifo_ret_t cfifo_write(cfifo_t *p_cfifo,
                        const void *p_items,
                        uint32_t *p_num_items);

/**
 * @brief TODO: Brief description.
 *
 * TODO: Write description.
 *
 * @param   p_cfifo
 * @param   p_item
 *
 * @return  CFIFO_SUCCESS
 *
 */
cfifo_ret_t cfifo_get(cfifo_t *p_cfifo,
                      void *p_item);

/**
 * @brief TODO: Brief description.
 *
 * TODO: Write description.
 *
 * @param   p_cfifo
 * @param   p_items
 * @param   p_num_items
 *
 * @return  CFIFO_SUCCESS
 *
 */
cfifo_ret_t cfifo_read(cfifo_t *p_cfifo,
                       void *p_items,
                       uint32_t *p_num_items);

/**
 * @brief TODO: Brief description.
 *
 * TODO: Write description.
 *
 * @param   p_cfifo
 * @param   p_item
 *
 * @return  CFIFO_SUCCESS
 *
 */
cfifo_ret_t cfifo_peek(cfifo_t *p_cfifo,
                       void *p_item);

/**
 * @brief TODO: Brief description.
 *
 * TODO: Write description.
 *
 * @param   p_cfifo
 * @param   p_num_items
 *
 * @return  CFIFO_SUCCESS
 *
 */
uint32_t cfifo_size(cfifo_t *p_cfifo);

/**
 * @brief TODO: Brief description.
 *
 * TODO: Write description.
 *
 * @param   p_cfifo
 *
 * @return  CFIFO_SUCCESS
 *
 */
cfifo_ret_t cfifo_flush(cfifo_t *p_cfifo);

#endif /* CFIFO_H_ */
