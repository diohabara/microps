#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "util.h"
#include "net.h"
#include "ip.h"

#define NET_PROTOCOL_TYPE_IP 0x0800

const ip_addr_t IP_ADDR_ANY = 0x00000000;
const ip_addr_t IP_ADDR_BROADCAST = 0xffffffff;

int
ip_addr_pton(const char *p, ip_addr_t *n) {
    char *sp, *ep;
    int idx;
    long ret;

    sp = (char *)p;
    for (idx = 0; idx < 4; idx++) {
        ret = strtol(sp, &ep, 10);
        if (ret < 0 || ret > 255) {
            return -1;
        }
        if (ep == sp) {
            return -1;
        }
        if ((idx == 3 && *ep != '\0') || (idx != 3 && *ep != '.')) {
            return -1;
        }
        ((uint8_t *)n)[idx] = ret;
        sp = ep + 1;
    }
    return 0;
}

char *
ip_addr_ntop(const ip_addr_t *n, char *p, size_t size) {
    uint8_t *u8;

    u8 = (uint8_t *)n;
    snprintf(p, size, "%d.%d.%d.%d", u8[0], u8[1], u8[2], u8[3]);
    return p;
}

void
ip_dump(const uint8_t *packet, size_t plen) {
    struct ip_hdr *hdr;
    uint8_t hl;
    uint16_t offset;
    char addr[IP_ADDR_STR_LEN];

    
    hdr = (struct ip_hdr *)packet;
    hl = hdr->vhl & 0x0f;
    flockfile(stderr);
    fprintf(stderr, "     vhl: 0x%02x [v: %u, hl: %u (%u)]\n", hdr->vhl, (hdr->vhl & 0xf0) >> 4, hl, hl << 2);
    fprintf(stderr, "     tos: 0x%02x\n", hdr->tos);
    fprintf(stderr, "     len: %u\n", ntoh16(hdr->len));
    fprintf(stderr, "      id: %u\n", ntoh16(hdr->id));
    offset = ntoh16(hdr->offset);
    fprintf(stderr, "  offset: 0x%04x [flags=%x, offset=%u]\n", offset, (offset & 0xe000) >> 13, offset & 0x1fff);
    fprintf(stderr, "     ttl: %u\n", hdr->ttl);
    fprintf(stderr, "protocol: %u\n", hdr->protocol);
    fprintf(stderr, "     sum: 0x%04x\n", ntoh16(hdr->sum));
    fprintf(stderr, "     src: %s\n", ip_addr_ntop(&hdr->src, addr, sizeof(addr)));
    fprintf(stderr, "     dst: %s\n", ip_addr_ntop(&hdr->dst, addr, sizeof(addr)));
    hexdump(stderr, packet, plen);
    funlockfile(stderr);
}

void
ip_input(struct net_device *dev, const uint8_t *data, size_t len)
{
    struct ip_hdr *hdr;
    uint16_t hlen;

    if (len < sizeof(struct ip_hdr)) {
        return;
    }
    hdr = (struct ip_hdr *)data;
    if ((hdr->vhl >> 4) != IP_VERSION_IPV4) {
        return;
    }
    hlen = (hdr->vhl & 0x0f) << 2;
    if (len < hlen || len < ntoh16(hdr->len)) {
        errorf("ip packet length error");
        return;
    }
    if (!hdr->ttl) {
        errorf("ip packet was dead (TTL=0)");
        return;
    }
    if (cksum16((uint16_t *)hdr, hlen, 0) != 0) {
        errorf("ip checksum error");
        return;
    }
    debugf("<%s> %zd bytes data", dev->name, len);
    ip_dump(data, len);
}

int
ip_init(void)
{
    net_protocol_register(NET_PROTOCOL_TYPE_IP, ip_input);
    return 0;
}
