#ifndef SALT_IO_H
#define SALT_IO_H

#include "salt_v2.h"

salt_ret_t my_write(salt_io_channel_t *p_wchannel);
salt_ret_t my_read(salt_io_channel_t *p_rchannel);

#endif /* SALT_IO_H */