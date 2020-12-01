#ifndef UDP_H
#define UDP_H

#include <stddef.h>
#include <stdint.h>

#include "ip.h"

extern ssize_t
udp_output(struct ip_iface *iface, uint16_t sport, uint8_t *buf, size_t len, ip_addr_t peer, uint16_t port);
extern int
udp_init(void);

#endif
