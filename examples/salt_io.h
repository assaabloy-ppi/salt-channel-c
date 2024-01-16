#ifndef SALT_IO_H
#define SALT_IO_H

#include "salt.h"

salt_ret_t my_write(salt_io_channel_t *p_wchannel);
salt_ret_t my_read(salt_io_channel_t *p_rchannel);

extern salt_time_t my_time;

#endif /* SALT_IO_H */
