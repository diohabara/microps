#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <net/ethernet.h>
#include <linux/if.h>
#include <linux/if_packet.h>

#include "net.h"
#include "ether.h"

struct ether {
    char name[IFNAMSIZ];
    int fd;
};

#define PRIV(x) ((struct ether *)x->priv)

static int
ether_addr(struct net_device *dev) {
    int soc;
    struct ifreq ifr;

    soc = socket(AF_INET, SOCK_DGRAM, 0);
    if (soc == -1) {
        errorf("socket: %s", strerror(errno));
        return -1;
    }
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, PRIV(dev)->name, sizeof(ifr.ifr_name) - 1);
    if (ioctl(soc, SIOCGIFHWADDR, &ifr) == -1) {
        errorf("ioctl [SIOCGIFHWADDR]: %s", strerror(errno));
        close(soc);
        return -1;
    }
    memcpy(dev->addr, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
    close(soc);
    return 0;
}

static int
ether_open(struct net_device *dev)
{
    struct ether *ether;
    struct ifreq ifr;
    struct sockaddr_ll addr;

    if (!(dev->flags & NET_DEVICE_FLAG_UP)) {
        ether = PRIV(dev);
        ether->fd = socket(PF_PACKET, SOCK_RAW, hton16(ETH_P_ALL));
        if (ether->fd == -1) {
            errorf("socket: %s", strerror(errno));
            return -1;
        }
        strncpy(ifr.ifr_name, ether->name, sizeof(ifr.ifr_name) - 1);
        if (ioctl(ether->fd, SIOCGIFINDEX, &ifr) == -1) {
            errorf("ioctl [SIOCGIFINDEX]: %s", strerror(errno));
            close(ether->fd);
            return -1;
        }
        memset(&addr, 0x00, sizeof(addr));
        addr.sll_family = AF_PACKET;
        addr.sll_protocol = hton16(ETH_P_ALL);
        addr.sll_ifindex = ifr.ifr_ifindex;
        if (bind(ether->fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
            errorf("bind: %s", strerror(errno));
            close(ether->fd);
            return -1;
        }
        if (ioctl(ether->fd, SIOCGIFFLAGS, &ifr) == -1) {
            errorf("ioctl [SIOCGIFFLAGS]: %s", strerror(errno));
            close(ether->fd);
            return -1;
        }
        ifr.ifr_flags = ifr.ifr_flags | IFF_PROMISC;
        if (ioctl(ether->fd, SIOCSIFFLAGS, &ifr) == -1) {
            errorf("ioctl [SIOCSIFFLAGS]: %s", strerror(errno));
            close(ether->fd);
            return -1;
        }
        if (memcmp(dev->addr, ETHER_ADDR_ANY, ETHER_ADDR_LEN) == 0) {
            if (ether_addr(dev) == -1) {
                errorf("ether_addr() failure");
                close(ether->fd);
                return -1;
            }
        }
        dev->flags |= NET_DEVICE_FLAG_UP;
    }
    debugf("<%s> up", dev->name);
    return 0;
};

static int
ether_close(struct net_device *dev)
{
    if (dev->flags & NET_DEVICE_FLAG_UP) {
        dev->flags &= ~NET_DEVICE_FLAG_UP;
        close(PRIV(dev)->fd);
    }
    debugf("<%s> down", dev->name);
    return 0;
}

static ssize_t
ether_write(struct net_device *dev, const uint8_t *frame, size_t flen)
{
    return write(PRIV(dev)->fd, frame, flen);
}

int
ether_transmit(struct net_device *dev, uint16_t type, const uint8_t *buf, size_t len, const void *dst)
{
    return ether_transmit_helper(dev, type, buf, len, dst, ether_write);
}

static ssize_t
ether_read(struct net_device *dev, uint8_t *buf, size_t size)
{
    ssize_t len;

    len = read(PRIV(dev)->fd, buf, size);
    if (len <= 0) {
        if (len == -1 && errno != EINTR) {
            errorf("read: %s", strerror(errno));
        }
        return -1;
    }
    return len;
}

static int
ether_poll(struct net_device *dev)
{
    struct pollfd pfd;
    int ret;

    pfd.fd = PRIV(dev)->fd;
    pfd.events = POLLIN;
    ret = poll(&pfd, 1, 0);
    switch (ret) {
    case -1:
        if (errno != EINTR) {
            errorf("poll: %s", strerror(errno));
        }
        /* fall through */
    case 0:
        return -1;
    }
    return ether_poll_helper(dev, ether_read);
}

static struct net_device_ops ops = {
    .open = ether_open,
    .close = ether_close,
    .transmit = ether_transmit,
    .poll = ether_poll,
};

struct net_device *
ether_init(const char *name)
{
    struct ether *tap;
    struct net_device *dev;

    tap = malloc(sizeof(struct ether));
    if (!tap) {
        errorf("malloc() failure");
        return NULL;
    }
    strncpy(tap->name, name, sizeof(tap->name) - 1);
    tap->fd = -1;
    dev = net_device_alloc(ether_setup_helper);
    if (!dev) {
        errorf("net_device_alloc() failure");
        close(tap->fd);
        free(tap);
        return NULL;
    }
    dev->ops = &ops;
    dev->priv = tap;
    net_device_register(dev);
    return dev;
}
