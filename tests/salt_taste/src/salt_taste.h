#ifndef _SALT_TASTE_H_
#define _SALT_TASTE_H_

#ifdef __cplusplus
extern "C" {
#endif

/* define it to be cmake friendly when using options */
#ifndef ON
#define ON 1
#endif
#ifndef OFF
#define OFF 0
#endif

int salt_taste_entry_point(salt_taste_hal_api_t *hal, int argc, char *argv[]);


#ifdef __cplusplus
}
#endif

#endif /* _SALT_TASTE_H_ */
