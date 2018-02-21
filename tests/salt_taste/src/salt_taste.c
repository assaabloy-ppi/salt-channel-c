#include <stdio.h>
//#include <stdbool.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

#include "salt_taste_hal.h"
#include "salt_taste_event.h"
#include "salt_taste.h"

#include "salt_crypto.h"

#include "salt.h"
#include "salti_util.h"
//#include "salt_io.h"

#ifndef HAL_TEST_TIMER
#define HAL_TEST_TIMER ON
#endif

#ifndef HAL_TEST_RNG
#define HAL_TEST_RNG ON
#endif

static bool test_build(salt_crypto_api_t *crypto_api, salt_taste_hal_api_t *hal);
static bool test_platform(salt_taste_hal_api_t *hal);
static bool test_elapsed_timer(salt_taste_hal_api_t *hal);
static bool test_rng(salt_taste_hal_api_t *hal);
static uint64_t calc_handshake_perf(salt_crypto_api_t *crypto_api, salt_taste_hal_api_t *hal, uint16_t loops);
static bool test_crypto_sanity(salt_crypto_api_t *crypto_api, salt_taste_hal_api_t *hal);
static void util_dump(salt_taste_hal_api_t *hal, uint8_t *ptr, uint32_t size);

salt_crypto_api_t crypto; /* shoult be global, since referenced outside with 'extern' */


static uint8_t client_sk_sec[64] = {
    0x55, 0xf4, 0xd1, 0xd1, 0x98, 0x09, 0x3c, 0x84,
    0xde, 0x9e, 0xe9, 0xa6, 0x29, 0x9e, 0x0f, 0x68,
    0x91, 0xc2, 0xe1, 0xd0, 0xb3, 0x69, 0xef, 0xb5,
    0x92, 0xa9, 0xe3, 0xf1, 0x69, 0xfb, 0x0f, 0x79,
    0x55, 0x29, 0xce, 0x8c, 0xcf, 0x68, 0xc0, 0xb8,
    0xac, 0x19, 0xd4, 0x37, 0xab, 0x0f, 0x5b, 0x32,
    0x72, 0x37, 0x82, 0x60, 0x8e, 0x93, 0xc6, 0x26,
    0x4f, 0x18, 0x4b, 0xa1, 0x52, 0xc2, 0x35, 0x7b
};

static uint8_t client_ek_sec[32] = {
    0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
    0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
    0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
    0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
};
static uint8_t client_ek_pub[32] = {
    0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
    0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
    0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
    0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a
};
static uint8_t host_sk_sec[64] = {
    0x7a, 0x77, 0x2f, 0xa9, 0x01, 0x4b, 0x42, 0x33,
    0x00, 0x07, 0x6a, 0x2f, 0xf6, 0x46, 0x46, 0x39,
    0x52, 0xf1, 0x41, 0xe2, 0xaa, 0x8d, 0x98, 0x26,
    0x3c, 0x69, 0x0c, 0x0d, 0x72, 0xee, 0xd5, 0x2d,
    0x07, 0xe2, 0x8d, 0x4e, 0xe3, 0x2b, 0xfd, 0xc4,
    0xb0, 0x7d, 0x41, 0xc9, 0x21, 0x93, 0xc0, 0xc2,
    0x5e, 0xe6, 0xb3, 0x09, 0x4c, 0x62, 0x96, 0xf3,
    0x73, 0x41, 0x3b, 0x37, 0x3d, 0x36, 0x16, 0x8b 
};
static uint8_t host_ek_sec[32] = {
    0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
    0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
    0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
    0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb
};
static uint8_t host_ek_pub[32] = {
    0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
    0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
    0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
    0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f
};
static uint8_t m1[46] = {
    0x2a, 0x00, 0x00, 0x00, // 42
    0x53, 0x43, 0x76, 0x32, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x85, 0x20, 0xf0, 0x09, 0x89, 0x30,
    0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e,
    0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38,
    0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b,
    0x4e, 0x6a
};
static uint8_t m2[42] = {
    0x26, 0x00, 0x00, 0x00, // 38
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xde, 0x9e,
    0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b,
    0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37, 0x3f, 0x83,
    0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc,
    0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f
};
static uint8_t m3[124] = {
    0x78, 0x00, 0x00, 0x00, // 120
    0x06, 0x00, 0xe4, 0x7d, 0x66, 0xe9, 0x07, 0x02,
    0xaa, 0x81, 0xa7, 0xb4, 0x57, 0x10, 0x27, 0x8d,
    0x02, 0xa8, 0xc6, 0xcd, 0xdb, 0x69, 0xb8, 0x6e,
    0x29, 0x9a, 0x47, 0xa9, 0xb1, 0xf1, 0xc1, 0x86,
    0x66, 0xe5, 0xcf, 0x8b, 0x00, 0x07, 0x42, 0xba,
    0xd6, 0x09, 0xbf, 0xd9, 0xbf, 0x2e, 0xf2, 0x79,
    0x87, 0x43, 0xee, 0x09, 0x2b, 0x07, 0xeb, 0x32,
    0xa4, 0x5f, 0x27, 0xcd, 0xa2, 0x2c, 0xbb, 0xd0,
    0xf0, 0xbb, 0x7a, 0xd2, 0x64, 0xbe, 0x1c, 0x8f,
    0x6e, 0x08, 0x0d, 0x05, 0x3b, 0xe0, 0x16, 0xd5,
    0xb0, 0x4a, 0x4a, 0xeb, 0xff, 0xc1, 0x9b, 0x6f,
    0x81, 0x6f, 0x9a, 0x02, 0xe7, 0x1b, 0x49, 0x6f,
    0x46, 0x28, 0xae, 0x47, 0x1c, 0x8e, 0x40, 0xf9,
    0xaf, 0xc0, 0xde, 0x42, 0xc9, 0x02, 0x3c, 0xfc,
    0xd1, 0xb0, 0x78, 0x07, 0xf4, 0x3b, 0x4e, 0x25
};
static uint8_t m4[124] = {
    0x78, 0x00, 0x00, 0x00, // 120
    0x06, 0x00, 0xb4, 0xc3, 0xe5, 0xc6, 0xe4, 0xa4,
    0x05, 0xe9, 0x1e, 0x69, 0xa1, 0x13, 0xb3, 0x96,
    0xb9, 0x41, 0xb3, 0x2f, 0xfd, 0x05, 0x3d, 0x58,
    0xa5, 0x4b, 0xdc, 0xc8, 0xee, 0xf6, 0x0a, 0x47,
    0xd0, 0xbf, 0x53, 0x05, 0x74, 0x18, 0xb6, 0x05,
    0x4e, 0xb2, 0x60, 0xcc, 0xa4, 0xd8, 0x27, 0xc0,
    0x68, 0xed, 0xff, 0x9e, 0xfb, 0x48, 0xf0, 0xeb,
    0x84, 0x54, 0xee, 0x0b, 0x12, 0x15, 0xdf, 0xa0,
    0x8b, 0x3e, 0xbb, 0x3e, 0xcd, 0x29, 0x77, 0xd9,
    0xb6, 0xbd, 0xe0, 0x3d, 0x47, 0x26, 0x41, 0x10,
    0x82, 0xc9, 0xb7, 0x35, 0xe4, 0xba, 0x74, 0xe4,
    0xa2, 0x25, 0x78, 0xfa, 0xf6, 0xcf, 0x36, 0x97,
    0x36, 0x4e, 0xfe, 0x2b, 0xe6, 0x63, 0x5c, 0x4c,
    0x61, 0x7a, 0xd1, 0x2e, 0x6d, 0x18, 0xf7, 0x7a,
    0x23, 0xeb, 0x06, 0x9f, 0x8c, 0xb3, 0x81, 0x73
};
static uint8_t msg1[34] = {
    0x1e, 0x00, 0x00, 0x00, // 30[] => 0x010505050505
    0x06, 0x00, 0x50, 0x89, 0x76, 0x9d, 0xa0, 0xde,
    0xf9, 0xf3, 0x72, 0x89, 0xf9, 0xe5, 0xff, 0x6e,
    0x78, 0x71, 0x0b, 0x97, 0x47, 0xd8, 0xa0, 0x97,
    0x15, 0x91, 0xab, 0xf2, 0xe4, 0xfb
};
static uint8_t msg2[34] = {
    0x1e, 0x00, 0x00, 0x00, // 30 => 0x010505050505
    0x06, 0x00, 0x82, 0xeb, 0x9d, 0x36, 0x60, 0xb8,
    0x29, 0x84, 0xf3, 0xc1, 0xc1, 0x05, 0x1f, 0x87,
    0x51, 0xab, 0x55, 0x85, 0xb7, 0xd0, 0xad, 0x35,
    0x4d, 0x9b, 0x5c, 0x56, 0xf7, 0x55
};

static uint8_t sha512_abc[64] = {
    0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
    0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
    0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
    0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
    0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
    0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
    0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
    0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f
};

static salt_ret_t client_io_write(salt_io_channel_t *p_wchannel)
{
    uint8_t *expected;
    uint32_t expected_size;

    static uint8_t i = 0;

    switch (i) {
        case 0:
            expected = m1;
            expected_size = sizeof(m1);
            break;
        case 1:
            expected = m4;
            expected_size = sizeof(m4);
            break;
        case 2:
            expected = msg1;
            expected_size = sizeof(msg1);
            break;

    }

    i++;

    if (p_wchannel->size_expected == expected_size && memcmp(expected, p_wchannel->p_data, expected_size) == 0) {
        p_wchannel->size = p_wchannel->size_expected;
        return SALT_SUCCESS;
    }

    return SALT_ERROR;

}

static salt_ret_t client_io_read(salt_io_channel_t *p_rchannel)
{
    static uint8_t i = 0;

    switch (i) {
        case 0:
            memcpy(p_rchannel->p_data, m2, 4);
            p_rchannel->size = 4;
            break;
        case 1:
            memcpy(p_rchannel->p_data, &m2[4], 38);
            p_rchannel->size = 38;
            break;
        case 2:
            memcpy(p_rchannel->p_data, m3, 4);
            p_rchannel->size = 4;
            break;
        case 3:
            memcpy(p_rchannel->p_data, &m3[4], 120);
            p_rchannel->size = 120;
            break;
        case 4:
            memcpy(p_rchannel->p_data, msg2, 4);
            p_rchannel->size = 4;
            break;
        case 5:
            memcpy(p_rchannel->p_data, &msg2[4], 30);
            p_rchannel->size = 30;
            break;

    }

    i++;

    return SALT_SUCCESS;
}

bool test_client_handshake(void) {

    salt_channel_t channel;
    salt_ret_t ret;
    uint8_t hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE];

    ret = salt_create(&channel, SALT_CLIENT, client_io_write, client_io_read, NULL);
    ret = salt_set_signature(&channel, client_sk_sec);
    ret = salt_init_session_using_key(&channel,
                                      hndsk_buffer,
                                      SALT_HNDSHK_BUFFER_SIZE,
                                      client_ek_pub,
                                      client_ek_sec);

    ret = salt_handshake(&channel, NULL);

    if (ret != SALT_SUCCESS) {
        return false;
    }

    /* Write echo bytes 010505050505 */
    uint8_t echo_bytes[6] = {0x01, 0x05, 0x05, 0x05, 0x05, 0x05};
    salt_msg_t msg_out;
    ret = salt_write_begin(hndsk_buffer, sizeof(hndsk_buffer), &msg_out);
    ret = salt_write_next(&msg_out, echo_bytes, sizeof(echo_bytes));
    ret = salt_write_execute(&channel, &msg_out, false);
    if (ret != SALT_SUCCESS) {
        return false;
    }

    salt_msg_t msg_in;
    ret = salt_read_begin(&channel, hndsk_buffer, sizeof(hndsk_buffer), &msg_in);
    if (msg_in.read.message_size == sizeof(echo_bytes) && memcmp(echo_bytes, msg_in.read.p_payload, sizeof(echo_bytes)) == 0) {
        return true;
    }

    (void) host_sk_sec;
    (void) host_ek_pub;
    (void) host_ek_sec;

    return false;
}



/* HAL entry point should pass control here */
int salt_taste_entry_point(salt_taste_hal_api_t *hal, int argc, char *argv[])
{	
	bool success = false;
	uint64_t us;

	hal->write_str(1, "\r\n\r\n");
	success = test_build(&crypto, hal);

    hal->write_str(1, "Crypto init ... ");
    salt_crypto_api_init(&crypto, NULL);  /* deterministic mode */
    hal->write_str(1, "done \r\n");

	for (int i=0; i<42; i++)
		hal->write_str(1, "=");
	hal->write_str(1, "\r\n");

	hal->notify(SALT_TASTE_EVENT_READY, SALT_TASTE_STATUS_SUCCESS);

	/* testing platform HAL */
	success = test_platform(hal);

	if (success)
		success = test_crypto_sanity(&crypto, hal);

	if (success) {
		hal->write_str(1, "------ Handshake measurement (loops: 1)...\r\n");
		us = calc_handshake_perf(&crypto, hal, 1);
		hal->dprintf(1, "------ Spent in one loop: %ld ms (%ld%ld us).\r\n", 
                        (uint32_t)us/1000, (uint32_t)us/1000, (uint32_t)us%1000);
	}


	hal->notify(SALT_TASTE_EVENT_SHUTDOWN, SALT_TASTE_STATUS_INIT);
	return 0;
}


static bool test_build(salt_crypto_api_t *crypto_api, salt_taste_hal_api_t *hal)
{
	/* print system/build info */
	hal->write_str(1, "Crypto backend: ");
	hal->write_str(1, salt_crypto_get_name(crypto_api));
	hal->write_str(1, "\r\n");

	return true;
}

static bool test_platform(salt_taste_hal_api_t *hal)
{
	bool success = true;

	hal->notify(SALT_TASTE_EVENT_HAL_TEST_STATUS, SALT_TASTE_STATUS_INIT);
	
#if (HAL_TEST_TIMER == ON)
	success = test_elapsed_timer(hal);
#endif

#if (HAL_TEST_RNG == ON)
	if (success)
		success = test_rng(hal);
#endif

	if (success) {
		hal->notify(SALT_TASTE_EVENT_HAL_TEST_STATUS, SALT_TASTE_STATUS_SUCCESS);
		return true;
	}
	else {
		hal->notify(SALT_TASTE_EVENT_HAL_TEST_STATUS, SALT_TASTE_STATUS_FAILURE);
		hal->write_str(1, "Platform (HAL) test failed!\r\n");
		return false;
	}
}

static bool test_elapsed_timer(salt_taste_hal_api_t *hal)
{
	bool success = false;
	uint64_t  ms;
	volatile  unsigned short  counter = 1;

	hal->notify(SALT_TASTE_EVENT_TIMER_TEST_STATUS, SALT_TASTE_STATUS_INIT);

	/* do the checks - short interval */
	hal->enter_rt();	
	hal->trigger_elapsed_counter(0, true);
	hal->sleep(10);
	ms = hal->trigger_elapsed_counter(0, false);
	hal->leave_rt();
	success = success && (ms > 8 && ms < 12)? true : false; 
	/* checks done */

	/* do the checks - long interval */
	hal->enter_rt();
	hal->trigger_elapsed_counter(0, true);
	hal->sleep(1500);
	ms = hal->trigger_elapsed_counter(0, false);
	hal->leave_rt();
	success = (ms > 1470 && ms < 1530)? true : false; 
	/* checks done */

	hal->notify(SALT_TASTE_EVENT_TIMER_TEST_STATUS, 
				success? SALT_TASTE_STATUS_SUCCESS : SALT_TASTE_STATUS_FAILURE);
	return success;
}

static bool test_rng(salt_taste_hal_api_t *hal)
{	
	bool success = false;
	/*const uint8_t sample_len = 128;*/
	enum { sample_len = 10 };
	const uint8_t low_ci_point = 128-50;
	const uint8_t high_ci_point = 128+50;

	uint8_t i, buf[sample_len];
	uint64_t val_acc = 0;
	uint8_t val_avg;

	hal->notify(SALT_TASTE_EVENT_RNG_TEST_STATUS, SALT_TASTE_STATUS_INIT);

	/* do the checks */
	hal->rng(buf, sample_len);

	// [TODO] provide better alg: without false negatives 
	/* quick and dirty test without full uniform distribution validation */   
	for (i=0; i<sample_len; i++)
		val_acc += buf[i];

	val_avg = val_acc / sample_len;
	success = (val_avg > low_ci_point && val_avg < high_ci_point)? true : false;

	/* checks done */

	hal->notify(SALT_TASTE_EVENT_RNG_TEST_STATUS, 
				success? SALT_TASTE_STATUS_SUCCESS : SALT_TASTE_STATUS_FAILURE);
	return success;
}

static uint64_t calc_handshake_perf(salt_crypto_api_t *crypto_api, salt_taste_hal_api_t *hal, uint16_t loops)
{
	bool success = true;


	hal->notify(SALT_TASTE_EVENT_SC_HANDSHAKE, SALT_TASTE_STATUS_INIT);
	
	/* ----------- begin of measurement section*/
	hal->trigger_elapsed_counter(0, true);	

	for (uint16_t i=0; i<loops; i++)
		success = success && test_client_handshake();

	uint64_t ms = hal->trigger_elapsed_counter(0, false);
	/* ----------- end of measurement section*/

	if (success) {
		hal->notify(SALT_TASTE_EVENT_SC_HANDSHAKE, SALT_TASTE_STATUS_SUCCESS);
		return ms;
	}
	else {
		hal->notify(SALT_TASTE_EVENT_SC_HANDSHAKE, SALT_TASTE_STATUS_FAILURE);
		hal->write_str(1, "handshake test failed!\r\n");
		return 0;
	}
}

static bool test_crypto_sanity(salt_crypto_api_t *crypto_api, salt_taste_hal_api_t *hal)
{
	bool success = true;
	uint8_t pdst[crypto_sign_BYTES + 3];
	uint8_t pdst2[crypto_sign_BYTES + 3];

	hal->notify(SALT_TASTE_EVENT_CRYPTO_SANITY_STATUS, SALT_TASTE_STATUS_INIT);

    /* crypto_sign_keypair() */
    hal->write_str(1, "... crypto_sign_keypair()\r\n");
	crypto_api->crypto_sign_keypair(pdst, client_sk_sec);
	if (memcmp(pdst, client_sk_sec + crypto_sign_PUBLICKEYBYTES, crypto_sign_PUBLICKEYBYTES))
	{
		hal->notify(SALT_TASTE_EVENT_CRYPTO_SANITY_STATUS, SALT_TASTE_STATUS_FAILURE);
		util_dump(hal, pdst, crypto_sign_PUBLICKEYBYTES);
		return false;	
	}

    /* crypto_sign() + crypto_sign_open() */
	unsigned long long mlen, smlen;
	int sign_open_res = -1;
	const uint8_t msg[] = { 0x03, 0x03, 0x03 };
	
	hal->write_str(1, "... crypto_sign()\r\n");
    int sign_res = crypto_api->crypto_sign(pdst, &smlen, msg, sizeof(msg), client_sk_sec);
    if (!sign_res){
    	util_dump(hal, pdst, smlen);
    	hal->write_str(1, "... crypto_sign_open()\r\n");
		sign_open_res = crypto_api->crypto_sign_open(pdst2, &mlen, pdst, smlen, &(client_sk_sec[32]));
    }
    if (sign_open_res || memcmp(msg, pdst2, sizeof(msg)))
    {
		hal->notify(SALT_TASTE_EVENT_CRYPTO_SANITY_STATUS, SALT_TASTE_STATUS_FAILURE);
		return false;
    }

/*    hal->write_str(1, "... crypto_sign_verify_detached()\r\n");
    int signdet_res = crypto_api->crypto_sign_verify_detached(pdst, msg, sizeof(msg), &(client_sk_sec[32]));
    if (!signdet_res) {
        hal->notify(SALT_TASTE_EVENT_CRYPTO_SANITY_STATUS, SALT_TASTE_STATUS_FAILURE);
        return false;        
    }
*/
    /* crypto_box_keypair() */
    hal->write_str(1, "... crypto_box_keypair()\r\n");
    crypto_api->crypto_box_keypair(pdst, client_ek_sec);
    if (memcmp(pdst, client_ek_pub, crypto_box_PUBLICKEYBYTES))
    {
        hal->notify(SALT_TASTE_EVENT_CRYPTO_SANITY_STATUS, SALT_TASTE_STATUS_FAILURE);
        util_dump(hal, pdst, crypto_box_PUBLICKEYBYTES);
        return false;   
    }

    /* crypto_box_beforenm() */
    hal->write_str(1, "... crypto_box_beforenm()\r\n");
    crypto_api->crypto_box_beforenm(pdst, host_ek_pub, client_ek_sec);    
    crypto_api->crypto_box_beforenm(pdst2, client_ek_pub, host_ek_sec); 

    if (memcmp(pdst, pdst2, crypto_box_BEFORENMBYTES))
    {
        hal->notify(SALT_TASTE_EVENT_CRYPTO_SANITY_STATUS, SALT_TASTE_STATUS_FAILURE);
        util_dump(hal, pdst, crypto_box_BEFORENMBYTES);
        util_dump(hal, pdst2, crypto_box_BEFORENMBYTES);
        return false;   
    }

    uint8_t n[crypto_box_NONCEBYTES] = {0};
    uint8_t m[crypto_box_ZEROBYTES + sizeof(msg)] = {0};
    uint8_t c[sizeof(m)] = {0};
    //uint8_t m2[sizeof(m)] = {0};

    memcpy(m + crypto_box_ZEROBYTES, msg, sizeof(msg));
        
    crypto_api->crypto_box_afternm(c, m, sizeof(m), n, pdst);
    util_dump(hal, c, sizeof(c));
    crypto_api->crypto_box_open_afternm(c, c, sizeof(m), n, pdst);

    if (memcmp(msg, c + crypto_box_ZEROBYTES, sizeof(msg)))
    {
        hal->notify(SALT_TASTE_EVENT_CRYPTO_SANITY_STATUS, SALT_TASTE_STATUS_FAILURE);
        util_dump(hal, c, sizeof(c));
        return false;   
    }

    /* crypto_hash() */
    hal->write_str(1, "... crypto_hash()\r\n");
    crypto_api->crypto_hash(pdst, (const uint8_t*)"abc", 3);

    if (memcmp(pdst, sha512_abc, crypto_hash_BYTES))
    {
        hal->notify(SALT_TASTE_EVENT_CRYPTO_SANITY_STATUS, SALT_TASTE_STATUS_FAILURE);
        util_dump(hal, sha512_abc, crypto_hash_BYTES);
        return false;   
    }

    /* multipart crypto_hash_sha512 */
    hal->write_str(1, "... crypto_hash_sha512_*()\r\n");
    
    crypto_hash_sha512_state  hash_state;
    crypto_api->crypto_hash_sha512_init(&hash_state);
    crypto_api->crypto_hash_sha512_update(&hash_state, (const uint8_t*)"a", 1);
    crypto_api->crypto_hash_sha512_update(&hash_state, (const uint8_t*)"bc", 2);
    crypto_api->crypto_hash_sha512_final(&hash_state, pdst);

    if (memcmp(pdst, sha512_abc, crypto_hash_BYTES))
    {
        hal->notify(SALT_TASTE_EVENT_CRYPTO_SANITY_STATUS, SALT_TASTE_STATUS_FAILURE);
        util_dump(hal, sha512_abc, crypto_hash_BYTES);
        return false;   
    }


	hal->notify(SALT_TASTE_EVENT_CRYPTO_SANITY_STATUS, SALT_TASTE_STATUS_SUCCESS);
	return true;
}


static void util_dump(salt_taste_hal_api_t *hal, uint8_t *ptr, uint32_t size)
{
	hal->dprintf(1, "      srcline:%d, ptr: %p, size: %d -> ", __LINE__, ptr, size);
	for (int i = 0; i<size; i++)
      hal->dprintf(1, "%02x", ptr[i]);
    hal->dprintf(1, "\r\n");
}