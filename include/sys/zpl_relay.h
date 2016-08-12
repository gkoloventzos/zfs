#ifndef	_SYS_ZPL_RELAY_H
#define	_SYS_ZPL_RELAY_H

#include <linux/relay.h>

#define N_SUBBUFS 100
#define SUBBUF_SIZE 4096000

struct rchan *relay_chan = NULL;
unsigned long long dropped = 0;

#endif
