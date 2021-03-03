#include <stdint.h>
#include <stdio.h>

#include "loopback.h"
#include "util.h"

#define NULL_MUT UINT16_MAX /* maimum size of IP datagram */

static int null_trasmit(struct net_device *dev, uint16_t type,
                        const uint8_t *data, size_t len, const void *dst) {}
