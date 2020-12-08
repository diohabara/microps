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
    struct tcp_pcb *tcb, *acc;
    char addr[IP_ADDR_STR_LEN];
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
    self.addr = IP_ADDR_ANY;
    self.port = hton16(7);
    tcb = tcp_cmd_open(&self, NULL, 0);
    if (!tcb) {
        return -1;
    }
    acc = tcp_cmd_accept(tcb, &peer);
    if (!acc) {
        return -1;
    }
    debugf("connection established: peer=%s:%d",
        ip_addr_ntop(&peer.addr, addr, sizeof(addr)), ntoh16(peer.port));
    while (!terminate) {
        n = tcp_cmd_receive(acc, buf, sizeof(buf));
        if (n <= 0) {
            tcp_cmd_close(acc);
            break;
        }
        debugf("redeive %u bytes data", n);
        debugdump(buf, n);
        tcp_cmd_send(acc, buf, n);
    }
    tcp_cmd_close(tcb);
    net_shutdown();
    return 0;
}
