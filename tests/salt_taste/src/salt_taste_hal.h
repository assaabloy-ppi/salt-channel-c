#ifndef _SALT_TASTE_HAL_H_
#define _SALT_TASTE_HAL_H_

#ifdef __cplusplus
extern "C" {
#endif

/* include platform-dependant type definitions */
#include "salt_taste_hal_def.h"
#include "salt_taste_event.h"

struct salt_taste_hal_api_s;

/* HAL entry point should invode this portable entry_point */
extern int salt_taste_entry_point(struct salt_taste_hal_api_s *hal, int argc, char *argv[]);

typedef enum salt_taste_hal_flags_e {
    ST_HAL_HAS_CONSOLE   = 0x01,
    ST_HAL_HAS_PRINTF   = 0x02,
    ST_HAL_HAS_RNG      = 0x04,    

} salt_taste_hal_flags_t;

typedef enum salt_taste_hal_counter_action_e {
    ST_HAL_CNT_START    = 1,
    ST_HAL_CNT_STOP,
    ST_HAL_CNT_TOGGLE,    

} salt_taste_hal_counter_action_t;

struct salt_taste_hal_api_s {
    uint32_t cfg; 

    uint32_t (*get_info)();       /* request platform-dependant functionality implemeted in ???_hal.c */
    int (*entry_point)(struct salt_taste_hal_api_s *hal, int argc, char *argv[]);
    int (*init)();                /* hal initialization: retarget printf(), etc */
    int (*shutdown)();            /* hal shutdown: flush buffers, etc */

    int (*write)(int fd, const char *buf, int count);  /* */
    int (*write_str)(int fd, const char *msg);
    int (*dprintf)(int fd, const char *format, ...);
    void (*assert)(int expr, const char *msg);

    void (*rng)(uint8_t *buf, uint64_t count);

    void (*enter_rt)();  /* enter realtime mode */
    void (*leave_rt)();  /* leave realtime mode */    
    void (*sleep)(uint32_t ms);

    int  (*get_elapsed_counters_num)();  /* return number of elapsed counters supported by HAL */    
    uint64_t (*trigger_elapsed_counter)(int counter_idx, bool start_it);

    void (*notify)(enum salt_taste_event_e event, enum salt_taste_status_e status);
};
typedef struct salt_taste_hal_api_s salt_taste_hal_api_t;


int salt_test_hal_init(salt_taste_hal_api_t *hal);
int salt_test_hal_shutdown(salt_taste_hal_api_t *hal);
int salt_test_hal_set_cfg(salt_taste_hal_api_t *hal, uint32_t flags);


#ifdef __cplusplus
}
#endif

#endif /* _SALT_TASTE_HAL_H_ */
