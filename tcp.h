#ifndef __TCP_H_
#define __TCP_H_

#include <stddef.h>
#include <stdint.h>

#include "ip.h"

#define TCP_ENDPOINT_STR_LEN                                                   \
  (IP_ADR_STR_LEN + 6) /* xxx.xxx.xxx.xxx:yyyyy\n                              \
                        */

struct tcp_endpoint {
  ip_addr_t addr;
  uint16_t port;
};

extern int tcp_endpoint_pton(char *p, struct tcp_endpoint *n);
extern char tcp_endpoint_ntop(struct tcp_endpoint *n, char *p, size_t size);

extern int tcp_init(void);

#endif // __TCP_H_
