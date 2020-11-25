#ifndef NET_H
#define NET_H

#include <stdint.h>
#include <pthread.h>
#include <sys/types.h>

#include "util.h"

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

#define NET_DEVICE_FLAG_UP        0x0001
#define NET_DEVICE_FLAG_LOOPBACK  0x0010
#define NET_DEVICE_FLAG_BROADCAST 0x0020
#define NET_DEVICE_FLAG_P2P       0x0040
#define NET_DEVICE_FLAG_NOARP     0x0100

#define NET_DEVICE_ADDR_LEN 16

struct net_device;

struct net_device_ops {
    int (*open)(struct net_device *dev);
    int (*close)(struct net_device *dev);
    int (*transmit)(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst);
    int (*poll)(struct net_device *dev);
};

struct net_device {
    struct net_device *next;
    unsigned int index;
    char name[IFNAMSIZ];
    uint16_t type;
    uint16_t mtu;
    uint16_t flags;
    uint16_t hlen; /* header length */
    uint16_t alen; /* address length */
    uint8_t addr[NET_DEVICE_ADDR_LEN];
    union {
        uint8_t peer[NET_DEVICE_ADDR_LEN];
        uint8_t broadcast[NET_DEVICE_ADDR_LEN];
    };
    struct net_device_ops *ops;
    pthread_mutex_t mutex;
    struct queue_head queue; /* transmit queue */
    void *priv;
};

extern struct net_device *
net_device_alloc(void (*setup)(struct net_device *dev));
extern int
net_device_register(struct net_device *dev);
extern int
net_device_transmit(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst);
extern int
net_device_received(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len);

extern int
net_protocol_register(uint16_t type, void (*handler)(struct net_device *dev, const uint8_t *data, size_t len));

extern void
net_shutdown(void);
extern void
net_init(void);

#endif
