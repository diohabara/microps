#ifndef TCP_H
#define TCP_H

#include <stdint.h>

#include "ip.h"

extern struct tcp_pcb * 
tcp_cmd_open(struct socket *local, struct socket *foreign, int active);
extern struct tcp_pcb *
tcp_cmd_accept(struct tcp_pcb *pcb, struct socket *peer);
extern ssize_t
tcp_cmd_send(struct tcp_pcb *pcb, uint8_t *data, size_t len);
extern ssize_t
tcp_cmd_receive(struct tcp_pcb *pcb, uint8_t *buf, size_t size);
extern int
tcp_cmd_close(struct tcp_pcb *pcb);

extern int
tcp_init(void);

#endif
