#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/time.h>

#include "util.h"
#include "net.h"
#include "ip.h"
#include "udp.h"

#define IP_PROTOCOL_UDP 17

struct pseudo_hdr {
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t protocol; 
    uint16_t len;
};

struct udp_hdr {
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t sum;
};

void
udp_dump(const uint8_t *data, size_t len)
{
    struct udp_hdr *hdr;

    hdr = (struct udp_hdr *)data;
    flockfile(stderr);
    fprintf(stderr, " sport: %u\n", ntoh16(hdr->sport));
    fprintf(stderr, " dport: %u\n", ntoh16(hdr->dport));
    fprintf(stderr, "   len: %u\n", ntoh16(hdr->len));
    fprintf(stderr, "   sum: 0x%04x\n", ntoh16(hdr->len));
    hexdump(stderr, data, len);
    funlockfile(stderr);
}

static void
udp_input(struct ip_iface *iface, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst) {
    struct pseudo_hdr pseudo;
    uint16_t psum = 0;
    struct udp_hdr *hdr;
    char addr1[IP_ADDR_STR_LEN], addr2[IP_ADDR_STR_LEN];

    if (len < sizeof(struct udp_hdr)) {
        errorf("too short");
        return;
    }
    pseudo.src = src;
    pseudo.dst = dst;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_UDP;
    pseudo.len = hton16(len);
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    hdr = (struct udp_hdr *)data;
    if (cksum16((uint16_t *)hdr, len, psum) != 0) {
        errorf("udp checksum error");
        return;
    }
    debugf("receive: <%s> %s => %s (%zu byte)",
        NET_IFACE(iface)->dev->name,
        ip_addr_ntop(&src, addr1, sizeof(addr1)),
        ip_addr_ntop(&dst, addr2, sizeof(addr2)),
        len);
    udp_dump(data, len);
}

ssize_t
udp_output(struct ip_iface *iface, uint16_t sport, uint8_t *data, size_t len, ip_addr_t peer, uint16_t port) {
    struct pseudo_hdr pseudo;
    uint16_t psum = 0;
    uint8_t buf[65536];
    char addr1[IP_ADDR_STR_LEN], addr2[IP_ADDR_STR_LEN];
    struct udp_hdr *hdr;

    pseudo.src = iface->unicast;
    pseudo.dst = peer;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_UDP;
    pseudo.len = hton16(sizeof(struct udp_hdr) + len);
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    hdr = (struct udp_hdr *)buf;
    hdr->sport = sport;
    hdr->dport = port;
    hdr->len = hton16(sizeof(struct udp_hdr) + len);
    hdr->sum = 0;
    memcpy(hdr + 1, data, len);
    hdr->sum = cksum16((uint16_t *)hdr, sizeof(struct udp_hdr) + len, psum);
    debugf("transmit: <%s> %s => %s (%zu byte)",
        NET_IFACE(iface)->dev->name,
        ip_addr_ntop(&iface->unicast, addr1, sizeof(addr1)),
        ip_addr_ntop(&peer, addr2, sizeof(addr2)),
        sizeof(struct udp_hdr) + len);
    udp_dump((uint8_t *)hdr, sizeof(struct udp_hdr) + len);
    return ip_output(iface, IP_PROTOCOL_UDP, (uint8_t *)hdr, sizeof(struct udp_hdr) + len, peer);
}

int
udp_init(void)
{
    ip_protocol_register("UDP", IP_PROTOCOL_UDP, udp_input);
    return 0;
}
