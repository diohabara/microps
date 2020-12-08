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

static void
setup(void)
{
    signal(SIGINT, on_signal);
    net_init();
    arp_init();
    ip_init();
    icmp_init();
}

int
main(void)
{
    struct net_device *dev;
    struct ip_iface *iface;
    ip_addr_t dst;

    setup();

    dev = ether_init("wlp2s0");
    if (!dev) {
        return -1;
    }
    if (dev->ops->open(dev) == -1) {
        return -1;
    }
    iface = ip_iface_alloc("192.168.11.113", "255.255.255.0");
    ip_iface_register(dev, iface);
    ip_addr_pton("192.168.11.1", &dst);
    while (!terminate) {
        sleep(1);
    }
    net_shutdown();
    return 0;
}
