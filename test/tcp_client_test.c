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

volatile sig_atomic_t terminate;

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
    tcp_init();
}

int
main(void)
{
    struct net_device *dev;
    struct ip_iface *iface;
    struct socket self, peer;
    struct tcp_pcb *tcb;
    uint8_t buf[4096];
    ssize_t n;

    setup();

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
    ip_addr_pton("172.16.10.2", &self.addr);
    self.port = hton16(7);
    ip_addr_pton("172.16.10.1", &peer.addr);
    peer.port = hton16(7);
    tcb = tcp_cmd_open(&self, &peer, 1);
    if (!tcb) {
        return -1;
    }
    debugf("connection established");
    while (!terminate) {
        n = tcp_cmd_receive(tcb, buf, sizeof(buf));
        if (n <= 0) {
            break;
        }
        debugf("redeive %u bytes data", n);
        debugdump(buf, n);
        tcp_cmd_send(tcb, buf, n);
    }
    tcp_cmd_close(tcb);
    net_shutdown();
    return 0;
}
