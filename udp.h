#ifndef UDP_H
#define UDP_H

#include <stddef.h>
#include <stdint.h>

#include "net.h"
#include "ip.h"

extern int
udp_open(void);
extern int
udp_close(int soc);
extern int
udp_bind(int soc, ip_addr_t addr, uint16_t port);
extern ssize_t
udp_recvfrom(int soc, uint8_t *buf, size_t size, ip_addr_t *peer, uint16_t *port);
extern ssize_t
udp_sendto(int soc, uint8_t *buf, size_t len, ip_addr_t peer, uint16_t port);

extern ssize_t
udp_output(struct ip_iface *iface, uint16_t sport, uint8_t *buf, size_t len, ip_addr_t peer, uint16_t port);
extern int
udp_init(void);

#endif
