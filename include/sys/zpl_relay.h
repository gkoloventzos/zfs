#ifndef	_SYS_ZPL_RELAY_H
#define	_SYS_ZPL_RELAY_H

#include <linux/relay.h>

#define N_SUBBUFS 10
#define SUBBUF_SIZE 512000

struct rchan *relay_chan = NULL;

#endif
