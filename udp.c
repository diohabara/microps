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

#define UDP_CB_TABLE_SIZE 16

#define UDP_SOURCE_PORT_MIN 49152
#define UDP_SOURCE_PORT_MAX 65535

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

struct udp_queue_entry {
    struct queue_entry *next;
    ip_addr_t addr;
    uint16_t port;
    uint16_t len;
    uint8_t data[0];
};

struct udp_pcb {
    int used;
    ip_addr_t addr;
    uint16_t port;
    struct queue_head queue; /* receive queue */
    pthread_cond_t cond;
};

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static struct udp_pcb pcb_table[UDP_CB_TABLE_SIZE];

void
udp_dump(const uint8_t *data, size_t len)
{
    struct udp_hdr *hdr;

    hdr = (struct udp_hdr *)data;
    flockfile(stderr);
    fprintf(stderr, " sport: %u\n", ntoh16(hdr->sport));
    fprintf(stderr, " dport: %u\n", ntoh16(hdr->dport));
    fprintf(stderr, "   len: %u\n", ntoh16(hdr->len));
    fprintf(stderr, "   sum: 0x%04x\n", ntoh16(hdr->sum));
    hexdump(stderr, data, len);
    funlockfile(stderr);
}

static struct udp_pcb *
udp_pcb_select(ip_addr_t addr, uint16_t port)
{
    struct udp_pcb *pcb;

    for (pcb = pcb_table; pcb < array_tailof(pcb_table); pcb++) {
        if (pcb->used && (pcb->addr == IP_ADDR_ANY || pcb->addr == addr) && pcb->port == port) {
            return pcb;
        }
    }
    return NULL;
}

static void
udp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst) {
    struct pseudo_hdr pseudo;
    uint16_t psum = 0;
    struct udp_hdr *hdr;
    char addr1[IP_ADDR_STR_LEN], addr2[IP_ADDR_STR_LEN];
    struct udp_pcb *pcb;
    struct udp_queue_entry *entry;

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
    debugf("receive: %s => %s (%zu byte)",
        ip_addr_ntop(&src, addr1, sizeof(addr1)), ip_addr_ntop(&dst, addr2, sizeof(addr2)), len);
    udp_dump(data, len);
    pthread_mutex_lock(&mutex);
    pcb = udp_pcb_select(dst, hdr->dport);
    if (!pcb) {
        pthread_mutex_unlock(&mutex);
        /* TODO: ICMP Destination Unreachable (Port Unreachable) */
        return;
    }
    entry = malloc(sizeof(struct udp_queue_entry) + (len - sizeof(struct udp_hdr)));
    if (!entry) {
        pthread_mutex_unlock(&mutex);
        errorf("malloc() failure");
        return;
    }
    entry->addr = src;
    entry->port = hdr->sport;
    entry->len = len - sizeof(struct udp_hdr);
    memcpy(entry->data, hdr + 1, len - sizeof(struct udp_hdr));
    queue_push(&pcb->queue, (struct queue_entry *)entry);
    pthread_cond_broadcast(&pcb->cond);
    pthread_mutex_unlock(&mutex);
}

ssize_t
udp_output(ip_addr_t src, uint16_t sport, uint8_t *data, size_t len, ip_addr_t dst, uint16_t dport) {
    struct pseudo_hdr pseudo;
    uint16_t psum = 0;
    uint8_t buf[65536];
    char addr1[IP_ADDR_STR_LEN], addr2[IP_ADDR_STR_LEN];
    struct udp_hdr *hdr;

    pseudo.src = src;
    pseudo.dst = dst;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_UDP;
    pseudo.len = hton16(sizeof(struct udp_hdr) + len);
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    hdr = (struct udp_hdr *)buf;
    hdr->sport = sport;
    hdr->dport = dport;
    hdr->len = hton16(sizeof(struct udp_hdr) + len);
    hdr->sum = 0;
    memcpy(hdr + 1, data, len);
    hdr->sum = cksum16((uint16_t *)hdr, sizeof(struct udp_hdr) + len, psum);
    debugf("transmit: %s => %s (%zu byte)",
        ip_addr_ntop(&src, addr1, sizeof(addr1)), ip_addr_ntop(&dst, addr2, sizeof(addr2)), sizeof(struct udp_hdr) + len);
    udp_dump((uint8_t *)hdr, sizeof(struct udp_hdr) + len);
    return ip_output(IP_PROTOCOL_UDP, (uint8_t *)hdr, sizeof(struct udp_hdr) + len, src, dst);
}

int
udp_open(void)
{
    struct udp_pcb *pcb;

    pthread_mutex_lock(&mutex);
    for (pcb = pcb_table; pcb < array_tailof(pcb_table); pcb++) {
        if (!pcb->used) {
            pcb->used = 1;
            pthread_mutex_unlock(&mutex);
            return array_offset(pcb_table, pcb);
        }
    }
    pthread_mutex_unlock(&mutex);
    return -1;
}

int
udp_close(int soc)
{
    struct udp_pcb *pcb;
    struct queue_entry *entry;

    if (soc < 0 || soc >= UDP_CB_TABLE_SIZE) {
        return -1;
    }
    pthread_mutex_lock(&mutex);
    pcb = &pcb_table[soc];
    if (!pcb->used) {
        pthread_mutex_unlock(&mutex);
        return -1;
    }
    pcb->used = 0;
    pcb->addr = IP_ADDR_ANY;
    pcb->port = 0;
    while ((entry = queue_pop(&pcb->queue)) != NULL) {
        free(entry);
    }
    pcb->queue.next = pcb->queue.tail = NULL;
    pthread_mutex_unlock(&mutex);
    return 0;
}

int
udp_bind(int soc, ip_addr_t addr, uint16_t port)
{
    struct udp_pcb *pcb;

    if (soc < 0 || soc >= UDP_CB_TABLE_SIZE) {
        return -1;
    }
    pthread_mutex_lock(&mutex);
    pcb = &pcb_table[soc];
    if (!pcb->used) {
        pthread_mutex_unlock(&mutex);
        return -1;
    }
    if (addr) {
        // FIXME: check interface addr
        if (!ip_iface_by_addr(addr)) {
            pthread_mutex_unlock(&mutex);
            return -1;
        }
    }
    if (udp_pcb_select(addr, port) != NULL) {
        pthread_mutex_unlock(&mutex);
        return -1;
    }
    pcb->addr = addr;
    pcb->port = port;
    pthread_mutex_unlock(&mutex);
    return 0;
}

ssize_t
udp_sendto(int soc, uint8_t *data, size_t len, ip_addr_t peer, uint16_t port)
{
    struct udp_pcb *pcb;
    ip_addr_t src;
    struct ip_iface *iface;
    uint32_t p;
    uint16_t sport;

    if (soc < 0 || soc >= UDP_CB_TABLE_SIZE) {
        return -1;
    }
    pthread_mutex_lock(&mutex);
    pcb = &pcb_table[soc];
    if (!pcb->used) {
        pthread_mutex_unlock(&mutex);
        return -1;
    }
    src = pcb->addr;
    if (src == IP_ADDR_ANY) {
        iface = ip_iface_by_peer(peer);
        if (!iface) {
            pthread_mutex_unlock(&mutex);
            return -1;
        }
        src = iface->unicast;
    }
    if (!pcb->port) {
        for (p = UDP_SOURCE_PORT_MIN; p <= UDP_SOURCE_PORT_MAX; p++) {
            if (!udp_pcb_select(src, hton16(p))) {
                pcb->port = hton16(p);
                break;
            }
        }
        if (!pcb->port) {
            pthread_mutex_unlock(&mutex);
            return -1;
        }
    }
    sport = pcb->port;
    pthread_mutex_unlock(&mutex);
    return udp_output(src, sport, data, len, peer, port);
}

ssize_t
udp_recvfrom(int soc, uint8_t *buf, size_t size, ip_addr_t *peer, uint16_t *port)
{
    struct udp_pcb *pcb;
    struct timespec timeout;
    struct udp_queue_entry *entry;
    ssize_t len;

    if (soc < 0 || soc >= UDP_CB_TABLE_SIZE) {
        return -1;
    }
    pthread_mutex_lock(&mutex);
    pcb = &pcb_table[soc];
    if (!pcb->used) {
        pthread_mutex_unlock(&mutex);
        return -1;
    }
    while ((entry = (struct udp_queue_entry *)queue_pop(&pcb->queue)) == NULL && !net_interrupt) {
        clock_gettime(CLOCK_REALTIME, &timeout);
        timeout.tv_sec += 1;
        pthread_cond_timedwait(&pcb->cond, &mutex, &timeout);
    }
    pthread_mutex_unlock(&mutex);
    if (!entry) {
        errno = EINTR;
        return -1;
    }
    if (peer) {
        *peer = entry->addr;
    }
    if (port) {
        *port = entry->port;
    }
    len = MIN(size, entry->len);
    memcpy(buf, entry->data, len);
    free(entry);
    return len;
}

int
udp_init(void)
{
    struct udp_pcb *pcb;

    for (pcb = pcb_table; pcb < array_tailof(pcb_table); pcb++) {
        pthread_cond_init(&pcb->cond, NULL);
    }
    ip_protocol_register("UDP", IP_PROTOCOL_UDP, udp_input);
    return 0;
}
