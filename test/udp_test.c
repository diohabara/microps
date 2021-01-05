#include <stdio.h>
#include <unistd.h>
#include <signal.h>

#include "util.h"
#include "net.h"
#include "arp.h"
#include "ip.h"
#include "icmp.h"
#include "udp.h"

#include "loopback.h"

#include "test.h"

volatile sig_atomic_t terminate;

static uint8_t data[] = "1234567890";

static void
on_signal (int s)
{
    (void)s;
    terminate = 1;
}

static int
setup(void)
{
    struct net_device *dev;
    struct ip_iface *iface;

    signal(SIGINT, on_signal);
    if (net_init() == -1) {
        return -1;
    }
    if (arp_init() == -1) {
        return -1;
    }
    if (ip_init() == -1) {
        return -1;
    }
    if (icmp_init() == -1) {
        return -1;
    }
    if (udp_init() == -1) {
        return -1;
    }
    dev = loopback_init();
    if (!dev) {
        return -1;
    }
    if (dev->ops->open(dev) == -1) {
        return -1;
    }
    iface = ip_iface_alloc("127.0.0.1", "255.0.0.0");
    if (!iface) {
        return -1;
    }
    if (ip_iface_register(dev, iface) == -1) {
        return -1;
    }
    net_run();
    return 0;
}

int
main(void)
{
    ip_addr_t src, dst;

    if (setup() == -1) {
        return -1;
    }

    ip_addr_pton("127.0.0.1", &src);
    ip_addr_pton("127.0.0.1", &dst);
    while (!terminate) {
        udp_output(src, hton16(7), data, sizeof(data), dst, hton16(7));
        sleep(1);
    }
    net_shutdown();
    return 0;
}
