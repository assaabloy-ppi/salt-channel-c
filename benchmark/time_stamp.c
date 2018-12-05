/**
 * @file time_stamp.c
 *
 * Description
 *
 */

/*======= Includes ==========================================================*/

#include <string.h>

#include "time_stamp.h"

/*======= Local Macro Definitions ===========================================*/
/*======= Type Definitions ==================================================*/
/*======= Local function prototypes =========================================*/
/*======= Local variable declarations =======================================*/

static int m_time_stamps_printf(const char *format, ...);

/*======= Global function implementations ===================================*/

void time_stamps_init(time_stamps_t *ts,
                      const char *name)
{
    memset(ts, 0x00, sizeof(time_stamps_t));
    ts->name = name;
    ts->start = time_stamps_get_millis();
}

void time_stamps_begin_entry(time_stamp_t *entry,
                             const char *msg)
{

    memset(entry, 0x00, sizeof(time_stamp_t));
    entry->msg = msg;
    entry->runs = 1;
    entry->start = time_stamps_get_millis();

}

void time_stamps_attach_entry(time_stamps_t *ts, time_stamp_t *entry)
{
    if (NULL == ts->first) {
        ts->first = entry;
        ts->last = entry;
    } else {
        ts->last->next = entry;
        ts->last = entry;
    }
}

void time_stamps_end_entry(time_stamp_t *entry, uint32_t runs)
{
    entry->end = time_stamps_get_millis();
    entry->diff = entry->end - entry->start;
    entry->runs = runs;
    entry->average = entry->diff;
    if (runs > 1) {
        entry->average = (double) ((double) (entry->diff)) / (double) runs;
    }
}

void time_stamps_result(const time_stamps_t *ts)
{
    m_time_stamps_printf("-------------------------------------------------------------\r\n");
    m_time_stamps_printf("| %-57.56s |\r\n", ts->name);
    m_time_stamps_printf("-------------------------------------------------------------\r\n");
    m_time_stamps_printf("| Stamp # | Execution time [ms] | Executions | Average [ms] |\r\n");
    m_time_stamps_printf("-------------------------------------------------------------\r\n");
    //m_time_stamps_printf("Results for meassure \"%s\":\r\n", ts->name);
    time_stamp_t *stamp = ts->first;
    uint32_t i = 0;
    double total = 0.0f;
    while (NULL != stamp) {
        if (stamp->runs < 2) {
            m_time_stamps_printf(
                "| %-7"PRIu32" | %-20.3f| %-11"PRIu32"| N/A          | %s\r\n",
                i, stamp->diff, stamp->runs, stamp->msg
            );
        } else {
            m_time_stamps_printf(
                "| %-7"PRIu32" | %-20.3f| %-11"PRIu32"| %-13.3f| %s\r\n",
                i, stamp->diff, stamp->runs, stamp->average, stamp->msg
            );
        }
        total += stamp->diff;
        stamp = stamp->next;
        i++;
    }
    m_time_stamps_printf("-------------------------------------------------------------\r\n");
    m_time_stamps_printf("| Total run time: %-42.3f|\r\n",
        total);
    m_time_stamps_printf("-------------------------------------------------------------\r\n");
}

/*======= Local function implementations ====================================*/

static int m_time_stamps_printf(const char *format, ...)
{
    va_list argptr;
    va_start(argptr, format);
    int ret = time_stamps_printf(format, argptr);
    va_end(argptr);
    return ret;
}
