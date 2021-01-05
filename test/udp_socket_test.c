#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>

#include "util.h"
#include "net.h"
#include "loopback.h"
#include "ether.h"
#include "ether_tap.h"
#include "arp.h"
#include "ip.h"
#include "icmp.h"
#include "udp.h"

volatile sig_atomic_t terminate;

static void
on_signal (int s) {
    (void)s;
    net_interrupt = 1;
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
    dev = ether_tap_init("tap0");
    if (!dev) {
        return -1;
    }
    iface = ip_iface_alloc("172.16.10.2", "255.255.255.0");
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
main(int argc, char *argv[])
{
    int handle;
    int ret;
    uint8_t buf[65535];
    struct socket local, peer;
    char addr[IP_ADDR_STR_LEN];

    if (setup() == -1) {
        return -1;
    }
    local.addr = IP_ADDR_ANY;
    local.port = hton16(7);
    handle = udp_open();
    if (handle == -1) {
        return -1;
    }
    if (udp_bind(handle, &local) == -1) {
        return -1;
    }
    fprintf(stderr, "running...\n");
    while (!terminate) {
        ret = udp_recvfrom(handle, buf, sizeof(buf), &peer);
        if (ret <= 0) {
            break;
        }
        debugf("receive %d bytes message from %s:%d",
            ret, ip_addr_ntop(&peer.addr, addr, sizeof(addr)), ntoh16(peer.port));
        debugdump(buf, ret);
        udp_sendto(handle, buf, ret, &peer);
    }
    udp_close(handle);
    net_shutdown();
    return 0;
}
