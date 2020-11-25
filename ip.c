#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "util.h"
#include "net.h"
#include "ip.h"

#define NET_PROTOCOL_TYPE_IP 0x0800

#define NET_IFACE_FAMILY_IPV4 1

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

/*
 * IP INTERFACE
 */

struct ip_iface *
ip_iface_alloc(const char *addr, const char *netmask)
{
    struct ip_iface *iface;
    ip_addr_t network;

    if (!addr || !netmask) {
        return NULL;
    }
    iface = malloc(sizeof(struct ip_iface));
    if (!iface) {
        return NULL;
    }
    NET_IFACE(iface)->next = NULL;
    NET_IFACE(iface)->dev = NULL;
    NET_IFACE(iface)->family = NET_IFACE_FAMILY_IPV4;
    NET_IFACE(iface)->alen = IP_ADDR_LEN; 
    if (ip_addr_pton(addr, &iface->unicast) == -1) {
        free(iface);
        return NULL;
    }
    if (ip_addr_pton(netmask, &iface->netmask) == -1) {
        free(iface);
        return NULL;
    }
    network = iface->unicast & iface->netmask;
    iface->broadcast = network | ~iface->netmask;
    return iface;
}

int
ip_iface_register(struct net_device *dev, struct ip_iface *iface)
{
    if (net_device_add_iface(dev, NET_IFACE(iface)) == -1) {
        return -1;
    }
    return 0;
}

static void
ip_input(struct net_device *dev, const uint8_t *data, size_t len)
{
    struct ip_hdr *hdr;
    uint16_t hlen;
    struct ip_iface *iface;

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
    iface = (struct ip_iface *)net_device_get_iface(dev, NET_IFACE_FAMILY_IPV4);
    if (!iface) {
        errorf("<%s> ip interface does not registerd", dev->name);
        return;
    }
    if (hdr->dst != iface->unicast) {
        if (hdr->dst != iface->broadcast && hdr->dst != IP_ADDR_BROADCAST) {
            /* for other host */
            return;
        }
    }
    debugf("<%s> arrived %zd bytes data", dev->name, len);
    ip_dump(data, len);
}

static uint16_t
ip_generate_id(void)
{
    static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    static uint16_t id = 128;
    uint16_t ret;

    pthread_mutex_lock(&mutex);
    ret = id++;
    pthread_mutex_unlock(&mutex);
    return ret;
}

static int
ip_output_device(struct ip_iface *iface, uint8_t *data, size_t len, ip_addr_t dst)
{
    uint8_t ha[NET_DEVICE_ADDR_LEN];
    char addr[IP_ADDR_STR_LEN];
    ssize_t ret;

    do {
        if (NET_IFACE(iface)->dev->flags & NET_DEVICE_FLAG_NOARP) {
            memset(ha, 0, sizeof(ha));
            break;
        }
        if (dst == iface->broadcast || dst == IP_ADDR_BROADCAST) {
            memcpy(ha, NET_IFACE(iface)->dev->broadcast, NET_IFACE(iface)->dev->alen);
            break;
        }
        warnf("arp does not implement");
        return -1;
    } while (0);
    debugf("<%s> %zd bytes data to %s", NET_IFACE(iface)->dev->name, len, ip_addr_ntop(&dst, addr, sizeof(addr)));
    ip_dump((uint8_t *)data, len);
    ret = net_device_transmit(NET_IFACE(iface)->dev, NET_PROTOCOL_TYPE_IP, data, len, ha);
    if (ret != (ssize_t)len) {
        return -1;
    }
    return 0;
}

static ssize_t
ip_output_core(struct ip_iface *iface, uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, uint16_t id, uint16_t offset)
{
    uint8_t buf[4096];
    struct ip_hdr *hdr;
    uint16_t hlen;

    hdr = (struct ip_hdr *)buf;
    hlen = sizeof(struct ip_hdr);
    hdr->vhl = (IP_VERSION_IPV4 << 4) | (hlen >> 2);
    hdr->tos = 0;
    hdr->len = hton16(hlen + len);
    hdr->id = hton16(id);
    hdr->offset = hton16(offset);
    hdr->ttl = 0xff;
    hdr->protocol = protocol;
    hdr->sum = 0;
    hdr->src = src;
    hdr->dst = dst;
    hdr->sum = cksum16((uint16_t *)hdr, hlen, 0);
    memcpy(hdr + 1, data, len);
    return ip_output_device(iface, buf, hlen + len, dst);
}

ssize_t
ip_output(struct ip_iface *iface, uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t dst)
{
    uint16_t id;

    if (len > (size_t)(NET_IFACE(iface)->dev->mtu - IP_HDR_SIZE_MIN)) {
        /* flagmentation does not support */
        return -1;
    }
    id = ip_generate_id();
    if (ip_output_core(iface, protocol, data, len, iface->unicast, dst, id, 0) == -1) {
        return -1;
    }
    return len;
}

int
ip_init(void)
{
    net_protocol_register(NET_PROTOCOL_TYPE_IP, ip_input);
    return 0;
}
