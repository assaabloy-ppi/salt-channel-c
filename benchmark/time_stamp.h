#ifndef _TIME_STAMP_H
#define _TIME_STAMP_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file time_stamp.h.h
 *
 * Description
 *
 */

/*======= Includes ==========================================================*/

#include <stdarg.h>
#include <stddef.h>
#include <inttypes.h>

/*======= Public macro definitions ==========================================*/

#define VAR_NAME time_stamp_data##___FUNCTION__##__LINE__

#define STAMP_BEGIN(stamp_ptr, message)                                 \
    do {                                                                \
        static time_stamp_t VAR_NAME;                                   \
        time_stamps_begin_entry(&VAR_NAME, message);                    \
        time_stamps_attach_entry(stamp_ptr, &VAR_NAME);                 \
    } while(0)

#define STAMP_END(stamp_ptr, runs)                                      \
    do {                                                                \
        time_stamps_end_entry((stamp_ptr)->last, runs);                 \
    } while(0)

/*======= Type Definitions and declarations =================================*/

typedef struct time_stamps_s    time_stamps_t;
typedef struct time_stamp_s     time_stamp_t;
typedef uint32_t (*get_millis_t)(void);

struct time_stamps_s {
    const char      *name;
    time_stamp_t    *first;
    time_stamp_t    *last;
    double          start;
    double          end;
};

struct time_stamp_s {
    const char      *msg;
    double          start;
    double          end;
    double          diff;
    double          average;
    uint32_t        runs;
    time_stamp_t    *next;
};

/*======= Public variable declarations ======================================*/
/*======= Public function declarations ======================================*/

/* To be linked in by user. */
double time_stamps_get_millis(void);
int time_stamps_printf(const char *format, va_list arg);

void time_stamps_init(time_stamps_t *ts,
                      const char *name);

void time_stamps_begin_entry(time_stamp_t *entry,
                             const char *msg);

void time_stamps_attach_entry(time_stamps_t *ts, time_stamp_t *entry);

void time_stamps_end_entry(time_stamp_t *entry, uint32_t runs);

void time_stamps_result(const time_stamps_t *ts);

#ifdef __cplusplus
}
#endif

#endif /* _TIME_STAMP_H */
