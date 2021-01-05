#include <stdio.h>
#include <unistd.h>
#include <signal.h>

#include "loopback.h"
#include "net.h"
#include "arp.h"
#include "ip.h"
#include "icmp.h"

#include "ether.h"

#include "util.h"
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
    dev = ether_init("wlp2s0");
    if (!dev) {
        return -1;
    }
    iface = ip_iface_alloc("192.168.11.113", "255.255.255.0");
    if (!iface) {
        return -1;
    }
    if (ip_iface_register(dev, iface) == -1) {
        return -1;
    }
    if (dev->ops->open(dev) == -1) {
        return -1;
    }
    net_run();
    return 0;
}

int
main(void)
{
    ip_addr_t dst;

    if (setup() == -1) {
        return -1;
    }
    ip_addr_pton("192.168.11.1", &dst);
    while (!terminate) {
        sleep(1);
    }
    net_shutdown();
    return 0;
}
