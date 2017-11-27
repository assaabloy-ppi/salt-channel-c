#ifndef _SALT_TASTE_HAL_H_
#define _SALT_TASTE_HAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>


typedef enum salt_taste_hal_flags_e {
    ST_HAL_HAS_CONSOLE   = 0x01,
    ST_HAL_HAS_PRINTF   = 0x02,
    ST_HAL_HAS_RNG      = 0x04,    

} salt_taste_hal_flags_t;


struct salt_taste_hal_api_s {
    uint32_t cfg; 

    uint32_t (*get_info)();       /* request platform-dependant functionality implemeted in ???_hal.c */
    int (*entry_point)();         /* usually just a pointer to main() */
    int (*init)();                /* hal initialization: retarget printf(), etc */

    int (*write)(int fd, const char *buf, int count);  /* */
    int (*printf)(const char *format, ...);

    void (*rng)(uint8_t *buf, uint64_t count);
    uint64_t (*get_ticks)();          /* returns highest available resolution timer value */
    float    (*ticks_to_ms_ratio)();  /* ticks() * ticks_to_ms_ratio() = ms */
    void (*notify)(enum salt_taste_event_e event, enum salt_taste_status_e status);
};
typedef struct salt_taste_hal_api_s salt_taste_hal_api_t;


int salt_test_hal_init(salt_taste_hal_api_t *hal);
int salt_test_hal_set_cfg(salt_taste_hal_api_t *hal, uint32_t flags);


#ifdef __cplusplus
}
#endif

#endif /* _SALT_TASTE_HAL_H_ */