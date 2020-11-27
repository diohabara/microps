#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#include "util.h"
#include "net.h"

#define NET_DEVICE_TYPE_LOOPBACK 0x0001

static int
loopback_open(struct net_device *dev)
{
    dev->flags |= NET_DEVICE_FLAG_UP;

    debugf("<%s> up", dev->name);
    return 0;
};

static int
loopback_close(struct net_device *dev)
{
    dev->flags &= ~NET_DEVICE_FLAG_UP;

    debugf("<%s> down", dev->name);
    return 0;
}

static int
loopback_transmit(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst)
{
    debugf("<%s> type=0x%04x len=%zd", dev->name, type, len);
    debugdump(data, len);

    if (!(dev->flags & NET_DEVICE_FLAG_UP)) {
        errorf("<%s> is down", dev->name);
        return -1;
    }
    net_device_input(dev, type, data, len);
    return 0;
}

static struct net_device_ops loopback_ops = {
    .open = loopback_open,
    .close = loopback_close,
    .transmit = loopback_transmit,
};

void
loopback_setup(struct net_device *dev)
{
    dev->type = NET_DEVICE_TYPE_LOOPBACK;
    dev->mtu = 65535;
    dev->hlen = 0;
    dev->alen = 0;
    dev->flags |= (NET_DEVICE_FLAG_LOOPBACK | NET_DEVICE_FLAG_NOARP);
    dev->ops = &loopback_ops;
}

struct net_device *
loopback_init(void)
{
    struct net_device *dev;

    dev = net_device_alloc(loopback_setup);
    if (!dev) {
        errorf("net_device_alloc() failure");
        return NULL;
    }
    net_device_register(dev);

    infof("<%s> initialized", dev->name);
    return dev;
}
