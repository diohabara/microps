#include <stdio.h>
#include <unistd.h>
#include <signal.h>

#include "util.h"
#include "net.h"
#include "arp.h"
#include "ip.h"
#include "icmp.h"
#include "tcp.h"

#include "ether_tap.h"

#include "test.h"

static void
on_signal (int s)
{
    (void)s;
    net_interrupt = 1;
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
    if (tcp_init() == -1) {
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
main(void)
{
    struct socket peer;
    int con;
    uint8_t buf[4096];
    ssize_t n;

    if (setup() == -1) {
        return -1;
    }
    ip_addr_pton("172.16.10.1", &peer.addr);
    peer.port = hton16(7);
    con = tcp_open();
    if (con == -1) {
        return -1;
    }
    tcp_connect(con, &peer);
    debugf("connection established");
    while (1) {
        n = tcp_receive(con, buf, sizeof(buf));
        if (n <= 0) {
            break;
        }
        debugf("redeive %u bytes data", n);
        debugdump(buf, n);
        tcp_send(con, buf, n);
    }
    tcp_close(con);
    net_shutdown();
    return 0;
}
