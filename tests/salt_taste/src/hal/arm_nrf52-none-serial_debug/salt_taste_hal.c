
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "boards.h"
//#include "bsp.h"
#include "app_uart.h"
#include "app_error.h"
#include "nrf_delay.h"
#include "nrf.h"


#include "salt_taste_hal.h"

#define MAX_TEST_DATA_BYTES     (15U)                /**< max number of test bytes to be used for tx and rx. */
#define UART_TX_BUF_SIZE 256                         /**< UART TX buffer size. */
#define UART_RX_BUF_SIZE 1                           /**< UART RX buffer size. */
#define PIN_LED 19 // LED1 

#define ST_HAL_ELAPSED_COUNTERS    3

int _write(int file, char *ptr, int len)
{

    int i=0;
    uint8_t cr;
    for(i=0 ; i<len ; i++) {
        cr = *ptr++;
        while(app_uart_put(cr) != NRF_SUCCESS);
    }
    return len;
}

void uart_error_handle(app_uart_evt_t * p_event)
{
    if (p_event->evt_type == APP_UART_COMMUNICATION_ERROR)
    {
        APP_ERROR_HANDLER(p_event->data.error_communication);
    }
    else if (p_event->evt_type == APP_UART_FIFO_ERROR)
    {
        APP_ERROR_HANDLER(p_event->data.error_code);
    }
}


uint32_t get_info()
{
	return ST_HAL_HAS_CONSOLE | ST_HAL_HAS_PRINTF | ST_HAL_HAS_RNG;
}

int init()
{
    nrf_gpio_cfg_output(PIN_LED);
    nrf_gpio_pin_set(PIN_LED); // LED is off
    
    uint32_t err_code;
    const app_uart_comm_params_t comm_params =
      {
          RX_PIN_NUMBER,
          TX_PIN_NUMBER,
          RTS_PIN_NUMBER,
          CTS_PIN_NUMBER,
          APP_UART_FLOW_CONTROL_ENABLED,
          false,
          UART_BAUDRATE_BAUDRATE_Baud115200
      };

    APP_UART_FIFO_INIT(&comm_params,
                         UART_RX_BUF_SIZE,
                         UART_TX_BUF_SIZE,
                         uart_error_handle,
                         APP_IRQ_PRIORITY_LOW,
                         err_code);

    APP_ERROR_CHECK(err_code);

    uint32_t i =0;
     while(1) {
         nrf_gpio_pin_toggle(PIN_LED); 
         printf("%08" PRId32 " Hello world ! (%s)\r\n",i++,__DATE__);
         nrf_delay_ms(1000);
         
    }

	return 0;
}


int my_write(int fd, const char *buf, int count)
{
	/* do it via printf() for now, since DLIB configs (Normal, Full) seems missing in my (ppmag's) inst. */
	return printf("%.*s", count, buf);	
	//return write(fd, buf, count);
}

int my_write_str(int fd, const char *msg)
{
	return printf("%s", msg);	
}

int my_shutdown()
{
	/* flush buffers, etc*/
	return 0;
}

int my_dprintf(int fd, const char *format, ...)
{
    va_list args;
    int res;

    va_start(args, format);
    res = vprintf(format, args);  /* for now just ignore fd and write to stdout */
    va_end(args);
    return res;
}


/* platform dependant assert() implementation */
void my_assert(int expr, const char *msg)
{
	if (!expr)
		{
			my_write_str(0, msg);
			abort();
		}
}

void rng(uint8_t *buf, uint64_t count)
{
  //for (int i=0; i<count; i++)
  //	buf[i] = rand() % 0xff;
}

void my_sleep(uint32_t ms)
{
//	for(int i = 0; i < ms; i++)
//	  __delay_cycles(CLOCKS_PER_SEC / 1000);
}

/* return number of elapsed counters supported by HAL */    
int get_elapsed_counters_num()
{
    return ST_HAL_ELAPSED_COUNTERS;
}

uint64_t trigger_elapsed_counter(int counter_idx, bool start_it)
{
	/*clock_t ts[ST_HAL_ELAPSED_COUNTERS];
	clock_t end, diff;
 
	if (start_it)
	{

		ts[counter_idx] = clock();  
		return 0ULL;
	}
	else {
		end = clock();
		diff = end - ts[counter_idx];
	}

	return diff * 1000 / CLOCKS_PER_SEC;*/
	return 0ULL;
}


void notify(enum salt_taste_event_e event, enum salt_taste_status_e status)
{
	/* just debug output */
	my_dprintf(0, "EVENT: id=%-10s status=%-10s\n", salt_taste_event_tostr(event), 
		 													salt_taste_status_tostr(status));
}


int main(int argc, char *argv[])
{
	int ret;
	salt_taste_hal_api_t hal;

	salt_test_hal_init(&hal);
	ret = hal.entry_point(&hal, argc, argv);
	salt_test_hal_shutdown(&hal);
	return ret;
}


int salt_test_hal_init(salt_taste_hal_api_t *hal)
{
	salt_taste_hal_api_t tmp =  {
		.get_info = get_info,
		.entry_point = salt_taste_entry_point,  /* should NOT be changed in new HAL templete instances*/
		.init = init,
		.shutdown = my_shutdown,
		.write = my_write,
		.write_str = my_write_str,
		.dprintf = my_dprintf,
		.assert = my_assert,
		.rng = rng,
		.sleep = my_sleep,
		.get_elapsed_counters_num = get_elapsed_counters_num,
		.trigger_elapsed_counter = trigger_elapsed_counter, 
		.notify = notify
	};	

	*hal = tmp;
	hal->cfg = hal->get_info();  /* set ON all platform features by default */

	hal->init();
	return 0;
}

int salt_test_hal_shutdown(salt_taste_hal_api_t *hal)
{
	hal->shutdown();  /* TODO: checks for NULL */
	return 0;
}
