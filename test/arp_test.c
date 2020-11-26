#include <stdio.h>
#include <unistd.h>
#include <signal.h>

#include "loopback.h"
#include "net.h"
#include "ip.h"
#include "icmp.h"
#include "ether_tap.h"
#include "arp.h"

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

static int
setup_loopback(void) {
    struct net_device *dev;
    struct ip_iface *iface;

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
    return ip_iface_register(dev, iface);
}

int
main(void)
{
    struct net_device *dev;
    struct ip_iface *iface;
    ip_addr_t dst;

    setup();
    setup_loopback();

    dev = ether_tap_init("tap0");
    if (!dev) {
        return -1;
    }
    if (dev->ops->open(dev) == -1) {
        return -1;
    }
    iface = ip_iface_alloc("172.16.10.2", "255.255.255.0");
    ip_iface_register(dev, iface);
    ip_addr_pton("172.16.10.1", &dst);
    while (!terminate) {
        icmp_output(iface, ICMP_TYPE_ECHO, 0, 0, data, sizeof(data), dst);
        sleep(1);
    }
    net_shutdown();
    return 0;
}
