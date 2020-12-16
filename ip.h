#ifndef IP_H
#define IP_H

#include <stddef.h>
#include <stdint.h>

#include <net.h>

#define IP_HDR_SIZE_MIN 20
#define IP_HDR_SIZE_MAX 60

#define IP_PAYLOAD_SIZE_MAX (65535 - IP_HDR_SIZE_MIN)

#define IP_ADDR_LEN 4
#define IP_ADDR_STR_LEN 16 /* "ddd.ddd.ddd.ddd\0" */

#define IP_VERSION_IPV4 4

#define NET_IFACE_FAMILY_IPV4 1

typedef uint32_t ip_addr_t;

extern const ip_addr_t IP_ADDR_ANY;
extern const ip_addr_t IP_ADDR_BROADCAST;

struct ip_hdr {
    uint8_t vhl;
    uint8_t tos;
    uint16_t len;
    uint16_t id;
    uint16_t offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t sum;
    ip_addr_t src;
    ip_addr_t dst;
    uint8_t options[0];
};

struct ip_iface {
    struct net_iface iface;
    ip_addr_t unicast;
    ip_addr_t netmask;
    ip_addr_t broadcast;
};

struct socket {
    ip_addr_t addr;
    uint16_t port;
};

extern int
ip_addr_pton(const char *p, ip_addr_t *n);
extern char *
ip_addr_ntop(const ip_addr_t *n, char *p, size_t size);

extern struct ip_iface *
ip_iface_alloc(const char *addr, const char *netmask);
extern int
ip_iface_register(struct net_device *dev, struct ip_iface *iface);
extern struct ip_iface *
ip_iface_by_addr(ip_addr_t addr);
extern struct ip_iface *
ip_iface_by_peer(ip_addr_t peer);

extern int
ip_set_default_gateway(struct ip_iface *iface, const char *gateway);

extern ssize_t
ip_output(struct ip_iface *iface, uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t dst);
extern int
ip_protocol_register(const char *name, uint8_t type, void (*handler)(struct ip_iface *iface, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst));
extern int
ip_init(void);

#endif
