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

#define UDP_PCB_ARRAY_SIZE 16 

#define UDP_PCB_STATE_FREE 0
#define UDP_PCB_STATE_OPEN 1
#define UDP_PCB_STATE_CLOSING 2

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
    int state;
    ip_addr_t addr;
    uint16_t port;
    struct queue_head queue; /* receive queue */
    int wait;
    pthread_cond_t cond;
};

static pthread_mutex_t m_pcbs = PTHREAD_MUTEX_INITIALIZER;
static struct udp_pcb pcbs[UDP_PCB_ARRAY_SIZE];

static void
udp_dump(const uint8_t *data, size_t len)
{
    struct udp_hdr *hdr;

    hdr = (struct udp_hdr *)data;
    flockfile(stderr);
    fprintf(stderr, "  sport: %u\n", ntoh16(hdr->sport));
    fprintf(stderr, "  dport: %u\n", ntoh16(hdr->dport));
    fprintf(stderr, "    len: %u\n", ntoh16(hdr->len));
    fprintf(stderr, "    sum: 0x%04x\n", ntoh16(hdr->sum));
#ifdef ENABLE_DUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

/*
 * UDP PROTOCOL CONTROL BLOCK
 */

static struct udp_pcb *
udp_pcb_new(void)
{
    struct udp_pcb *pcb;

    for (pcb = pcbs; pcb < array_tailof(pcbs); pcb++) {
        if (pcb->state == UDP_PCB_STATE_FREE) {
            pcb->state = UDP_PCB_STATE_OPEN;
            pthread_cond_init(&pcb->cond, NULL);
            return pcb;
        }
    }
    return NULL;
}

static void
udp_pcb_release(struct udp_pcb *pcb)
{
    struct queue_entry *entry;

    if (pcb->state == UDP_PCB_STATE_OPEN) {
        pcb->state = UDP_PCB_STATE_CLOSING;
    }
    if (pcb->wait) {
        pthread_cond_broadcast(&pcb->cond);
        return;
    }
    pcb->state = UDP_PCB_STATE_FREE;
    pcb->addr = IP_ADDR_ANY;
    pcb->port = 0;
    while ((entry = queue_pop(&pcb->queue)) != NULL) {
        free(entry);
    }
    pthread_cond_destroy(&pcb->cond);
}

static struct udp_pcb *
udp_pcb_select(ip_addr_t addr, uint16_t port)
{
    struct udp_pcb *pcb;

    for (pcb = pcbs; pcb < array_tailof(pcbs); pcb++) {
        if (pcb->state == UDP_PCB_STATE_OPEN) {
            if ((pcb->addr == IP_ADDR_ANY || pcb->addr == addr) && pcb->port == port) {
                return pcb;
            }
        }
    }
    return NULL;
}

static struct udp_pcb *
udp_pcb_get(int id)
{
    struct udp_pcb *pcb;

    if (!array_index_isvalid(pcbs, id)) {
        return NULL;
    }
    pcb = &pcbs[id];
    if (pcb->state != UDP_PCB_STATE_OPEN) {
        return NULL;
    }
    return pcb;
}

static int
udp_pcb_id(struct udp_pcb *pcb)
{
    return array_offset(pcbs, pcb);
}

/*
 * UDP CORE
 */

static void
udp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst) {
    struct pseudo_hdr pseudo;
    uint16_t psum = 0;
    struct udp_hdr *hdr;
    char addr1[IP_ADDR_STR_LEN], addr2[IP_ADDR_STR_LEN];
    struct udp_pcb *pcb;
    struct udp_queue_entry *entry;

    if (len < sizeof(struct udp_hdr)) {
        errorf("input data is too short");
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
    debugf("%s:%d > %s:%d (%zu byte)",
        ip_addr_ntop(&src, addr1, sizeof(addr1)), ntoh16(hdr->sport),
        ip_addr_ntop(&dst, addr2, sizeof(addr2)), ntoh16(hdr->dport),
        len - sizeof(struct udp_hdr));
    udp_dump(data, len);
    pthread_mutex_lock(&m_pcbs);
    pcb = udp_pcb_select(dst, hdr->dport);
    if (!pcb) {
        pthread_mutex_unlock(&m_pcbs);
        /* TODO: ICMP Destination Unreachable (Port Unreachable) */
        return;
    }
    entry = malloc(sizeof(struct udp_queue_entry) + (len - sizeof(struct udp_hdr)));
    if (!entry) {
        pthread_mutex_unlock(&m_pcbs);
        errorf("malloc() failure");
        return;
    }
    entry->addr = src;
    entry->port = hdr->sport;
    entry->len = len - sizeof(struct udp_hdr);
    memcpy(entry->data, hdr + 1, len - sizeof(struct udp_hdr));
    queue_push(&pcb->queue, (struct queue_entry *)entry);
    pthread_cond_broadcast(&pcb->cond);
    pthread_mutex_unlock(&m_pcbs);
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
    debugf("%s:%d > %s:%d (%zu bytes)",
        ip_addr_ntop(&src, addr1, sizeof(addr1)), ntoh16(sport),
        ip_addr_ntop(&dst, addr2, sizeof(addr2)), ntoh16(dport),
        len);
    udp_dump((uint8_t *)hdr, sizeof(struct udp_hdr) + len);
    return ip_output(IP_PROTOCOL_UDP, (uint8_t *)hdr, sizeof(struct udp_hdr) + len, src, dst);
}

/*
 * UDP USER COMMAND
 */

int
udp_open(void)
{
    struct udp_pcb *pcb;
    int id; 

    pthread_mutex_lock(&m_pcbs);
    pcb = udp_pcb_new();
    if (!pcb) {
        errorf("");
        pthread_mutex_unlock(&m_pcbs);
        return -1;
    }
    id = udp_pcb_id(pcb);
    pthread_mutex_unlock(&m_pcbs);
    return id;
}

int
udp_close(int index)
{
    struct udp_pcb *pcb;

    pthread_mutex_lock(&m_pcbs);
    pcb = udp_pcb_get(index);
    if (!pcb) {
        errorf("not found");
        pthread_mutex_unlock(&m_pcbs);
        return -1;
    }
    udp_pcb_release(pcb);
    pthread_mutex_unlock(&m_pcbs);
    return 0;
}

int
udp_bind(int id, struct socket *local)
{
    struct udp_pcb *pcb;

    pthread_mutex_lock(&m_pcbs);
    pcb = udp_pcb_get(id);
    if (!pcb) {
        errorf("not found");
        pthread_mutex_unlock(&m_pcbs);
        return -1;
    }
    if (udp_pcb_select(local->addr, local->port)) {
        errorf("exists");
        pthread_mutex_unlock(&m_pcbs);
        return -1;
    }
    pcb->addr = local->addr;
    pcb->port = local->port;
    debugf("success");
    pthread_mutex_unlock(&m_pcbs);
    return 0;
}

ssize_t
udp_sendto(int id, uint8_t *data, size_t len, struct socket *peer)
{
    struct udp_pcb *pcb;
    ip_addr_t src;
    struct ip_iface *iface;
    char addr[IP_ADDR_STR_LEN];
    uint32_t p;
    uint16_t sport;

    pthread_mutex_lock(&m_pcbs);
    pcb = udp_pcb_get(id);
    if (!pcb) {
        errorf("not found");
        pthread_mutex_unlock(&m_pcbs);
        return -1;
    }
    src = pcb->addr;
    if (src == IP_ADDR_ANY) {
        iface = ip_iface_by_peer(peer->addr);
        if (!iface) {
            pthread_mutex_unlock(&m_pcbs);
            return -1;
        }
        debugf("select source address: %s", ip_addr_ntop(&iface->unicast, addr, sizeof(addr)));
        src = iface->unicast;
    }
    if (!pcb->port) {
        for (p = UDP_SOURCE_PORT_MIN; p <= UDP_SOURCE_PORT_MAX; p++) {
            if (!udp_pcb_select(src, hton16(p))) {
                debugf("dinamic assign srouce port: %d", p);
                pcb->port = hton16(p);
                break;
            }
        }
        if (!pcb->port) {
            debugf("failed to dinamic assign srouce port");
            pthread_mutex_unlock(&m_pcbs);
            return -1;
        }
    }
    sport = pcb->port;
    pthread_mutex_unlock(&m_pcbs);
    return udp_output(src, sport, data, len, peer->addr, peer->port);
}

ssize_t
udp_recvfrom(int id, uint8_t *buf, size_t size, struct socket *peer)
{
    struct udp_pcb *pcb;
    struct timespec timeout;
    struct udp_queue_entry *entry;
    ssize_t len;

    pthread_mutex_lock(&m_pcbs);
    pcb = udp_pcb_get(id);
    if (!pcb) {
        errorf("not found");
        pthread_mutex_unlock(&m_pcbs);
        return -1;
    }
    while ((entry = (struct udp_queue_entry *)queue_pop(&pcb->queue)) == NULL && !net_interrupt) {
        clock_gettime(CLOCK_REALTIME, &timeout);
        timespec_add_nsec(&timeout, 10000000); /* 100ms */
        pcb->wait++;
        pthread_cond_timedwait(&pcb->cond, &m_pcbs, &timeout);
        pcb->wait--;
    }
    if (pcb->state == UDP_PCB_STATE_CLOSING) {
        udp_pcb_release(pcb);
        free(entry);
        pthread_mutex_unlock(&m_pcbs);
        return 0;
    }
    if (!entry) {
        if (net_interrupt) {
            /* interrupt */
            errno = EINTR;
        }
        pthread_mutex_unlock(&m_pcbs);
        return -1;
    }
    if (peer) {
        peer->addr = entry->addr;
        peer->port = entry->port;
    }
    len = MIN(size, entry->len); /* truncate */
    memcpy(buf, entry->data, len);
    free(entry);
    pthread_mutex_unlock(&m_pcbs);
    return len;
}

int
udp_init(void)
{
    ip_protocol_register("UDP", IP_PROTOCOL_UDP, udp_input);
    return 0;
}
