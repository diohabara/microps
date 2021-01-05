#ifndef TCP_H
#define TCP_H

#include <stdint.h>

#include "ip.h"

extern int
tcp_open_rfc793(struct socket *local, struct socket *foreign, int active);
extern int
tcp_open(void);
extern int
tcp_bind(int id, struct socket *local);
extern int
tcp_connect(int id, struct socket *foreign);
extern int
tcp_listen(int id, int backlog);
extern int
tcp_accept(int id, struct socket *foreign);
extern ssize_t
tcp_send(int id, uint8_t *data, size_t len);
extern ssize_t
tcp_receive(int id, uint8_t *buf, size_t size);
extern int
tcp_close(int id);

extern int
tcp_init(void);

#endif
