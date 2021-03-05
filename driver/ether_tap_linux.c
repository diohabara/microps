#include "ether_tap_linux.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "ether.h"
#include "net.h"
#include "util.h"

#define CLONE_DEVICE "/dev/net/tun"

struct ether_tap {
  char name[IFNAMSIZ];
  int fd;
};

#define PRIV(x) ((struct ether_tap *)x->priv)

static int ether_tap_addr(struct net_device *dev) {}

static int ether_tap_open(struct net_device *dev) {}

static int ether_tap_close(struct net_device *dev) {}

static ssize_t ether_tap_write(struct net_device *dev, const uint8_t *frame,
                               size_t flen) {}

int ether_tap_transmit(struct net_device *dev, uint16_t type,
                       const uint8_t *buf, size_t len, const void *dst) {}

static ssize_t ether_tap_read(struct net_device *dev, uint8_t *buf,
                              size_t size) {}

static int ether_tap_poll(struct net_device *dev) {}

static struct net_device_ops ether_tap_ops = {
    .open = ether_tap_open,
    .close = ether_tap_close,
    .transmit = ether_tap_transmit,
    .poll = ether_tap_poll,
};

struct net_device *ether_tap_init(const char *name, const char *addr) {}
