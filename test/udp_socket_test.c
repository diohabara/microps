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
    signal(SIGINT, on_signal);
    net_init();
    arp_init();
    ip_init();
    icmp_init();
    udp_init();
    return 0;
}

int
main(int argc, char *argv[])
{
    struct net_device *dev;
    struct ip_iface *iface;
    char *ifname, *hwaddr = NULL, *ipaddr, *netmask;
    int soc = -1, ret;
    uint8_t buf[65535];
    ip_addr_t peer_addr;
    uint16_t port, peer_port;
    char addr[IP_ADDR_STR_LEN];

    switch (argc) {
    case 6:
        hwaddr = argv[2];
        /* fall through */
    case 5:
        ifname = argv[1];
        ipaddr = argv[argc-3];
        netmask = argv[argc-2];
        port = hton16(strtol(argv[argc-1], NULL, 10));
        break;
    default:
        fprintf(stderr, "usage: %s interface [mac_address] ip_address netmask port\n", argv[0]);
        return -1;
    }
    setup();
    dev = ether_tap_init(ifname);
    if (hwaddr) {
        ether_addr_pton(hwaddr, dev->addr);
    }
    dev->ops->open(dev);
    iface = ip_iface_alloc(ipaddr, netmask);
    ip_iface_register(dev, iface);
    soc = udp_open();
    if (soc == -1) {
        return -1;
    }
    if (udp_bind(soc, IP_ADDR_ANY, port) == -1) {
        udp_close(soc);
        return -1;
    }
    fprintf(stderr, "running...\n");
    while (!terminate) {
        ret = udp_recvfrom(soc, buf, sizeof(buf), &peer_addr, &peer_port);
        if (ret <= 0) {
            break;
        }
        debugf("receive %d bytes message from %s:%d",
            ret, ip_addr_ntop(&peer_addr, addr, sizeof(addr)) ,ntoh16(peer_port));
        debugdump(buf, ret);
        udp_sendto(soc, buf, ret, peer_addr, peer_port);
    }
    udp_close(soc);
    net_shutdown();
    return 0;
}
