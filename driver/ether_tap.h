#ifndef __ETHER_TAP_H_
#define __ETHER_TAP_H_

#include "net.h"

extern struct net_device *ether_tap_init(const char *name, const char *addr);

#endif // __ETHER_TAP_H_
