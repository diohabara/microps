#ifndef UDP_H
#define UDP_H

#include <stddef.h>
#include <stdint.h>

#include "ip.h"

struct udp_pcb;

extern int
udp_open(void);
extern int
udp_bind(int index, struct socket *local);
extern ssize_t
udp_sendto(int id, uint8_t *buf, size_t len, struct socket *peer);
extern ssize_t
udp_recvfrom(int id, uint8_t *buf, size_t size, struct socket *peer);
extern int
udp_close(int id);

extern ssize_t
udp_output(ip_addr_t src, uint16_t sport, uint8_t *buf, size_t len, ip_addr_t peer, uint16_t port);
extern int
udp_init(void);

#endif
