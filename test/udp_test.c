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

static void
setup(void)
{
    signal(SIGINT, on_signal);
    net_init();
    arp_init();
    ip_init();
    icmp_init();
    udp_init();
}

int
main(void)
{
    struct net_device *dev;
    struct ip_iface *iface;
    ip_addr_t dst;

    setup();

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
    ip_addr_pton("127.0.0.1", &dst);
    while (!terminate) {
        udp_output(iface, hton16(7), data, sizeof(data), dst, hton16(7));
        sleep(1);
    }
    net_shutdown();
    return 0;
}
