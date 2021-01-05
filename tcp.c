#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <pthread.h>

#include "net.h"
#include "ip.h"
#include "tcp.h"
#include "util.h"

#define IP_PROTOCOL_TCP 6

#define TCP_FLG_FIN 0x01
#define TCP_FLG_SYN 0x02
#define TCP_FLG_RST 0x04
#define TCP_FLG_PSH 0x08
#define TCP_FLG_ACK 0x10
#define TCP_FLG_URG 0x20

#define TCP_FLG_IS(x, y) ((x & 0x3f) == (y))
#define TCP_FLG_ISSET(x, y) ((x & 0x3f) & (y))

#define TCP_PCB_ARRAY_SIZE 16

#define TCP_PCB_STATE_NONE         0
#define TCP_PCB_STATE_CLOSED       1
#define TCP_PCB_STATE_LISTEN       2
#define TCP_PCB_STATE_SYN_SENT     3
#define TCP_PCB_STATE_SYN_RECEIVED 4
#define TCP_PCB_STATE_ESTABLISHED  5
#define TCP_PCB_STATE_FIN_WAIT1    6
#define TCP_PCB_STATE_FIN_WAIT2    7
#define TCP_PCB_STATE_CLOSING      8
#define TCP_PCB_STATE_TIME_WAIT    9
#define TCP_PCB_STATE_CLOSE_WAIT  10
#define TCP_PCB_STATE_LAST_ACK    11

#define TCP_SOURCE_PORT_MIN 49152
#define TCP_SOURCE_PORT_MAX 65535

#define TCP_DEFAULT_MSS 536 /* rfc879 */

struct tcp_hdr {
    uint16_t src;
    uint16_t dst;
    uint32_t seq;
    uint32_t ack;
    uint8_t  off;
    uint8_t  flg;
    uint16_t win;
    uint16_t sum;
    uint16_t urg;
};

struct tcp_queue_entry {
    struct queue_entry *next;
    struct tcp_hdr *segment;
    uint16_t len;
    struct timeval timestamp;
};

struct tcp_backlog_entry {
    struct queue_entry *next;
    struct tcp_pcb *pcb;
};

struct tcp_pcb {
    int state;
    struct socket self;
    struct socket peer;
    struct {
        uint32_t nxt;
        uint32_t una;
        uint16_t wnd;
        uint16_t up;
        uint32_t wl1;
        uint32_t wl2;
    } snd;
    uint32_t iss;
    struct {
        uint32_t nxt;
        uint16_t wnd;
        uint16_t up;
    } rcv;
    uint32_t irs;
    uint16_t mtu;
    uint16_t mss;
    struct queue_head snd_queue;
    uint8_t rcv_buf[65535];
    struct tcp_pcb *parent;
    struct queue_head backlog;
    pthread_cond_t cond;
    int wait;
};

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
struct tcp_pcb pcbs[TCP_PCB_ARRAY_SIZE];

void
tcp_dump(const uint8_t *data, size_t len)
{
    struct tcp_hdr *hdr;

    hdr = (struct tcp_hdr *)data;
    flockfile(stderr);
    fprintf(stderr, "  src: %u\n", ntoh16(hdr->src));
    fprintf(stderr, "  dst: %u\n", ntoh16(hdr->dst));
    fprintf(stderr, "  seq: %u\n", ntoh32(hdr->seq));
    fprintf(stderr, "  ack: %u\n", ntoh32(hdr->ack));
    fprintf(stderr, "  off: 0x%02x (%d)\n", hdr->off, (hdr->off >> 4) << 2);
    fprintf(stderr, "  flg: 0x%02x (--%c%c%c%c%c%c)\n", hdr->flg,
        TCP_FLG_ISSET(hdr->flg, TCP_FLG_URG) ? 'U' : '-',
        TCP_FLG_ISSET(hdr->flg, TCP_FLG_ACK) ? 'A' : '-',
        TCP_FLG_ISSET(hdr->flg, TCP_FLG_PSH) ? 'P' : '-',
        TCP_FLG_ISSET(hdr->flg, TCP_FLG_RST) ? 'R' : '-',
        TCP_FLG_ISSET(hdr->flg, TCP_FLG_SYN) ? 'S' : '-',
        TCP_FLG_ISSET(hdr->flg, TCP_FLG_FIN) ? 'F' : '-');
    fprintf(stderr, "  win: %u\n", ntoh16(hdr->win));
    fprintf(stderr, "  sum: 0x%04x (%u)\n", ntoh16(hdr->sum), ntoh16(hdr->sum));
    fprintf(stderr, "  urg: %u\n", ntoh16(hdr->urg));
#ifdef ENABLE_DUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

/*
 * TCP PROTOCOL CONTROL BLOCK
 */

static struct tcp_pcb *
tcp_pcb_new(void)
{
    struct tcp_pcb *pcb;

    for (pcb = pcbs; pcb < array_tailof(pcbs); pcb++) {
        if (pcb->state == TCP_PCB_STATE_NONE) {
            pcb->state = TCP_PCB_STATE_CLOSED;
            pthread_cond_init(&pcb->cond, NULL);
            return pcb;
        }
    }
    return NULL;
}

static void
tcp_pcb_release(struct tcp_pcb *pcb)
{
    struct queue_entry *entry;

    if (pcb->wait) {
        pthread_cond_broadcast(&pcb->cond);
        return;
    }
    while ((entry = queue_pop(&pcb->snd_queue)) != NULL) {
        free(entry);
    }
    while ((entry = queue_pop(&pcb->backlog)) != NULL) {
        free(entry);
    }
    pthread_cond_destroy(&pcb->cond);
    memset(pcb, 0, sizeof(struct tcp_pcb));
}

static struct tcp_pcb *
tcp_pcb_select(struct socket *local, struct socket *foreign)
{
    struct tcp_pcb *pcb, *candidate = NULL;

    for (pcb = pcbs; pcb < array_tailof(pcbs); pcb++) {
        if ((pcb->self.addr == IP_ADDR_ANY || pcb->self.addr == local->addr) && pcb->self.port == local->port) {
            if (!foreign) {
                candidate = pcb;
                break;
            }
            if (pcb->peer.addr == foreign->addr && pcb->peer.port == foreign->port) {
                candidate = pcb;
                break;
            }
            if (!candidate && pcb->state == TCP_PCB_STATE_LISTEN) {
                candidate = pcb;
            }
        }
    }
    return candidate;
}

static struct tcp_pcb *
tcp_pcb_get(int index)
{
    struct tcp_pcb *pcb;

    if (!array_index_isvalid(pcbs, index)) {
        return NULL;
    }
    pcb = &pcbs[index];
    return pcb;
}

static int
tcp_pcb_id(struct tcp_pcb *pcb)
{
    return array_offset(pcbs, pcb);
}

/*
 * TCP CORE
 */

static int
tcp_queue_add(struct tcp_pcb *pcb, struct tcp_hdr *hdr, size_t len)
{
    struct tcp_queue_entry *entry;

    entry = malloc(sizeof(struct tcp_queue_entry));
    if (!entry) {
        return -1;
    }
    entry->segment = malloc(len);
    if (!entry->segment) {
        free(entry);
        return -1;
    }
    memcpy(entry->segment, hdr, len);
    entry->len = len;
    gettimeofday(&entry->timestamp, NULL);
    if (!queue_push(&pcb->snd_queue, (struct queue_entry *)entry)) {
        free(entry->segment);
        free(entry);
        return -1;
    }
    return 0;
}

#define tcplog(hdr,_src,_dst,_len) \
    do { \
        char _a1[IP_ADDR_STR_LEN], _a2[IP_ADDR_STR_LEN]; \
        debugf("%s:%u => %s:%u [--%c%c%c%c%c%c] %zu bytes", \
            ip_addr_ntop(&_src,_a1,sizeof(_a1)), ntoh16(hdr->src), ip_addr_ntop(&_dst,_a2,sizeof(_a2)), ntoh16(hdr->dst), \
            TCP_FLG_ISSET(hdr->flg, TCP_FLG_URG) ? 'U' : '-', \
            TCP_FLG_ISSET(hdr->flg, TCP_FLG_ACK) ? 'A' : '-', \
            TCP_FLG_ISSET(hdr->flg, TCP_FLG_PSH) ? 'P' : '-', \
            TCP_FLG_ISSET(hdr->flg, TCP_FLG_RST) ? 'R' : '-', \
            TCP_FLG_ISSET(hdr->flg, TCP_FLG_SYN) ? 'S' : '-', \
            TCP_FLG_ISSET(hdr->flg, TCP_FLG_FIN) ? 'F' : '-', \
            _len - ((hdr->off >> 4) << 2)); \
    } while(0);

static ssize_t
tcp_output(struct tcp_pcb *pcb, uint32_t seq, uint32_t ack, uint8_t flg, uint8_t *data, size_t len)
{
    uint8_t buf[1500];
    struct tcp_hdr *hdr;
    uint32_t pseudo = 0;

    memset(&buf, 0, sizeof(buf));
    hdr = (struct tcp_hdr *)buf;
    hdr->src = pcb->self.port;
    hdr->dst = pcb->peer.port;
    hdr->seq = hton32(seq);
    hdr->ack = hton32(ack);
    hdr->off = (sizeof(struct tcp_hdr) >> 2) << 4;
    hdr->flg = flg;
    hdr->win = hton16(pcb->rcv.wnd);
    hdr->sum = 0;
    hdr->urg = 0;
    memcpy(hdr + 1, data, len);
    pseudo += (pcb->self.addr >> 16) & 0xffff;
    pseudo += pcb->self.addr & 0xffff;
    pseudo += (pcb->peer.addr >> 16) & 0xffff;
    pseudo += pcb->peer.addr & 0xffff;
    pseudo += hton16((uint16_t)IP_PROTOCOL_TCP);
    pseudo += hton16(sizeof(struct tcp_hdr) + len);
    hdr->sum = cksum16((uint16_t *)hdr, sizeof(struct tcp_hdr) + len, pseudo);
    tcplog(hdr, pcb->self.addr, pcb->peer.addr, sizeof(struct tcp_hdr) + len);
    tcp_dump((uint8_t *)hdr, sizeof(struct tcp_hdr) + len);
    ip_output(IP_PROTOCOL_TCP, (uint8_t *)hdr, sizeof(struct tcp_hdr) + len, pcb->self.addr, pcb->peer.addr);
    if (len || TCP_FLG_ISSET(flg, TCP_FLG_SYN | TCP_FLG_FIN)) {
        tcp_queue_add(pcb, hdr, sizeof(struct tcp_hdr) + len);
    }
    return len;
}

// rfc793 - section 3.9 [Event Processing > SEGMENT ARRIVES]
static void
tcp_segment_arrives(struct tcp_hdr *hdr, size_t len, ip_addr_t src, ip_addr_t dst)
{
    struct socket local, foreign;
    struct tcp_pcb *pcb, *new_pcb;
    size_t hlen, slen;
    int acceptable = 0;

    local.addr = dst;
    local.port = hdr->dst;
    foreign.addr = src;
    foreign.port = hdr->src;
    pcb = tcp_pcb_select(&local, &foreign);
    if (!pcb) {
        return;
    }
    hlen = ((hdr->off >> 4) << 2);
    slen = len - hlen;
    switch(pcb->state) {
    case TCP_PCB_STATE_CLOSED:
        if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_RST)) {
            return;
        }
        if (!TCP_FLG_ISSET(hdr->flg, TCP_FLG_ACK)) {
            tcp_output(pcb, 0, ntoh32(hdr->seq) + slen, TCP_FLG_RST | TCP_FLG_ACK, NULL, 0);
        } else {
            tcp_output(pcb, ntoh32(hdr->ack), 0, TCP_FLG_RST, NULL, 0);
        }
        return;
    case TCP_PCB_STATE_LISTEN:
        // 1. check for an RST
        if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_RST)) {
            return;
        }
        // 2. check for an ACK
        if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_ACK)) {
            struct tcp_pcb tmp = {};
            tmp.self.addr = dst;
            tmp.self.port = hdr->dst;
            tmp.peer.addr = src;
            tmp.peer.port = hdr->src;
            tcp_output(&tmp, ntoh32(hdr->ack), 0, TCP_FLG_RST, NULL, 0);
            return;
        }
        // 3. check for an SYN
        if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_SYN)) {
            // TODO: security/compartment check
            // TODO: precedence check
            new_pcb = tcp_pcb_new();
            if (!new_pcb) {
                errorf("");
                return;
            }
            new_pcb->parent = pcb;
            pcb = new_pcb;
            pcb->self.addr = dst;
            pcb->self.port = hdr->dst;
            pcb->peer.addr = src;
            pcb->peer.port = hdr->src;
            pcb->rcv.wnd = sizeof(pcb->rcv_buf);
            pcb->rcv.nxt = ntoh32(hdr->seq) + 1;
            pcb->irs = ntoh32(hdr->seq);
            pcb->iss = random();
            tcp_output(pcb, pcb->iss, pcb->rcv.nxt, TCP_FLG_SYN | TCP_FLG_ACK, NULL, 0);
            pcb->snd.nxt = pcb->iss + 1;
            pcb->snd.una = pcb->iss;
            pcb->state = TCP_PCB_STATE_SYN_RECEIVED;
            // TODO: Note that any other incoming control or data (combined with SYN) will be processed in the SYN-RECEIVED state, but processing of SYN and ACK  should not be repeated
            return;
        }
        // 4. other text or control
        return;
    case TCP_PCB_STATE_SYN_SENT:
        // 1. check the ACK bit
        if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_ACK)) {
            if (ntoh32(hdr->ack) <= pcb->iss || ntoh32(hdr->ack) > pcb->snd.nxt) {
                tcp_output(pcb, ntoh32(hdr->ack), 0, TCP_FLG_RST, NULL, 0);
                return;
            }
            if (pcb->snd.una <= ntoh32(hdr->ack) && ntoh32(hdr->ack) <= pcb->snd.nxt) {
                acceptable = 1;
            }
        }
        // 2. check the RST bit
        if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_RST)) {
            if (acceptable) {
                errorf("connection reset");
                pcb->state = TCP_PCB_STATE_CLOSED;
                tcp_pcb_release(pcb);
            }
            return;
        }

        // TODO: 3. check security and precedence

        // 4. check the SYN bit
        if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_SYN)) {
            pcb->rcv.nxt = ntoh32(hdr->seq) + 1;
            pcb->irs = ntoh32(hdr->seq);
            if (acceptable) {
                pcb->snd.una = ntoh32(hdr->ack);
                // TODO: any segments on the retransmission queue which are thereby acknowledged should be removed
            }
            if (pcb->snd.una > pcb->iss) {
                pcb->state = TCP_PCB_STATE_ESTABLISHED;
                tcp_output(pcb, pcb->snd.nxt, pcb->rcv.nxt, TCP_FLG_ACK, NULL, 0);
                // XXX: not specified in the RFC793, but send window initialization required
                pcb->snd.wnd = ntoh16(hdr->win);
                pcb->snd.wl1 = ntoh32(hdr->seq);
                pcb->snd.wl2 = ntoh32(hdr->ack);
                // TODO: continue processing at the sixth step below where the URG bit is checked
                pthread_cond_broadcast(&pcb->cond);
                return;
            } else {
                pcb->state = TCP_PCB_STATE_SYN_RECEIVED;
                tcp_output(pcb, pcb->iss, pcb->rcv.nxt, TCP_FLG_SYN | TCP_FLG_ACK, NULL, 0);
                // TODO: If there are other controls or text in the segment, queue them for processing after the ESTABLISHED state has been reached
                return;
            }
        }
        // 5. if neither of the SYN or RST bits is set then drop the segment and return
        return;
    }
    // Otherwise
    // 1. check sequence number
    switch (pcb->state) {
    case TCP_PCB_STATE_SYN_RECEIVED:
    case TCP_PCB_STATE_ESTABLISHED:
    case TCP_PCB_STATE_FIN_WAIT1:
    case TCP_PCB_STATE_FIN_WAIT2:
    case TCP_PCB_STATE_CLOSE_WAIT:
    case TCP_PCB_STATE_CLOSING:
    case TCP_PCB_STATE_LAST_ACK:
    case TCP_PCB_STATE_TIME_WAIT:
        if (!slen) {
            if (!pcb->rcv.wnd) {
                if (ntoh32(hdr->seq) == pcb->rcv.nxt) {
                    acceptable = 1;
                }
            } else {
                if (pcb->rcv.nxt <= ntoh32(hdr->seq) && ntoh32(hdr->seq) < pcb->rcv.nxt + pcb->rcv.wnd) {
                    acceptable = 1;
                }
            }
        } else {
            if (!pcb->rcv.wnd) {
                // not acceptable
            } else {
                if ((pcb->rcv.nxt <= ntoh32(hdr->seq) && ntoh32(hdr->seq) < pcb->rcv.nxt + pcb->rcv.wnd) ||
                    (pcb->rcv.nxt <= ntoh32(hdr->seq) + slen - 1 && ntoh32(hdr->seq) + slen - 1 < pcb->rcv.nxt + pcb->rcv.wnd)) {
                    acceptable = 1;
                }
            }
        }
        if (!acceptable) {
            if (!TCP_FLG_ISSET(hdr->flg, TCP_FLG_RST)) {
                tcp_output(pcb, pcb->snd.nxt, pcb->rcv.nxt, TCP_FLG_ACK, NULL, 0);
            }
            return;
        }
        // TODO: In the following it is assumed that the segment is the idealized
        //       segment that begins at RCV.NXT and does not exceed the window.
        //       One could tailor actual segments to fit this assumption by
        //       trimming off any portions that lie outside the window (including
        //       SYN and FIN), and only processing further if the segment then
        //       begins at RCV.NXT.  Segments with higher begining sequence
        //       numbers may be held for later processing.
    }
    // 2. check the RST bit
    switch (pcb->state) {
    case TCP_PCB_STATE_SYN_RECEIVED:
        if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_RST)) {
            pcb->state = TCP_PCB_STATE_CLOSED;
            tcp_pcb_release(pcb);
            return;
        }
        break;
    case TCP_PCB_STATE_ESTABLISHED:
    case TCP_PCB_STATE_FIN_WAIT1:
    case TCP_PCB_STATE_FIN_WAIT2:
    case TCP_PCB_STATE_CLOSE_WAIT:
        if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_RST)) {
            errorf("connection reset");
            pcb->state = TCP_PCB_STATE_CLOSED;
            tcp_pcb_release(pcb);
            return;
        }
        break;
    case TCP_PCB_STATE_CLOSING:
    case TCP_PCB_STATE_LAST_ACK:
    case TCP_PCB_STATE_TIME_WAIT:
        if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_RST)) {
            pcb->state = TCP_PCB_STATE_CLOSED;
            tcp_pcb_release(pcb);
            return;
        }
        break;
    }

    // TODO: 3. check security and precedence

    // 4. check the SYN bit
    switch (pcb->state) {
    case TCP_PCB_STATE_SYN_RECEIVED:
    case TCP_PCB_STATE_ESTABLISHED:
    case TCP_PCB_STATE_FIN_WAIT1:
    case TCP_PCB_STATE_FIN_WAIT2:
    case TCP_PCB_STATE_CLOSE_WAIT:
    case TCP_PCB_STATE_CLOSING:
    case TCP_PCB_STATE_LAST_ACK:
    case TCP_PCB_STATE_TIME_WAIT:
        if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_SYN)) {
            tcp_output(pcb, pcb->snd.nxt, pcb->rcv.nxt, TCP_FLG_RST, NULL, 0);
            errorf("connection reset");
            pcb->state = TCP_PCB_STATE_CLOSED;
            tcp_pcb_release(pcb);
            return;
        }
    }
    // 5. check the ACK field
    if (!TCP_FLG_ISSET(hdr->flg, TCP_FLG_ACK)) {
        // drop
        return;
    }
    switch (pcb->state) {
    case TCP_PCB_STATE_SYN_RECEIVED:
        if (pcb->snd.una <= ntoh32(hdr->ack) && ntoh32(hdr->ack) <= pcb->snd.nxt) {
            pcb->state = TCP_PCB_STATE_ESTABLISHED;
            if (pcb->parent) {
                struct tcp_backlog_entry *entry = malloc(sizeof(struct tcp_backlog_entry));
                if (!entry) {
                    errorf("malloc() failure");
                    return;
                }
                entry->pcb = pcb;
                queue_push(&pcb->parent->backlog, (struct queue_entry *)entry);
                pthread_cond_broadcast(&pcb->parent->cond);
            }
        } else {
            tcp_output(pcb, ntoh32(hdr->ack), 0, TCP_FLG_RST, NULL, 0);
            return;
        }
        // fall through
    case TCP_PCB_STATE_ESTABLISHED:
    case TCP_PCB_STATE_FIN_WAIT1:
    case TCP_PCB_STATE_FIN_WAIT2:
    case TCP_PCB_STATE_CLOSE_WAIT:
    case TCP_PCB_STATE_CLOSING:
        if (pcb->snd.una < ntoh32(hdr->ack) && ntoh32(hdr->ack) <= pcb->snd.nxt) {
            pcb->snd.una = ntoh32(hdr->ack);
            // TODO: Any segments on the retransmission queue which are thereby entirely acknowledged are removed
            // TODO: Users should receive positive acknowledgments for buffers which have been SENT and fully acknowledged (i.e., SEND buffer should be returned with "ok" response)
            if (pcb->snd.wl1 < ntoh32(hdr->seq) || (pcb->snd.wl1 == ntoh32(hdr->seq) && pcb->snd.wl2 <= ntoh32(hdr->ack))) {
                pcb->snd.wnd = ntoh16(hdr->win);
                pcb->snd.wl1 = ntoh32(hdr->seq);
                pcb->snd.wl2 = ntoh32(hdr->ack);
            }
        } else if (ntoh32(hdr->ack) < pcb->snd.una) {
            // ignore
        } else if (ntoh32(hdr->ack) > pcb->snd.nxt) {
            tcp_output(pcb, pcb->snd.nxt, pcb->rcv.nxt, TCP_FLG_ACK, NULL, 0);
            return;
        }
        switch (pcb->state) {
        case TCP_PCB_STATE_FIN_WAIT1:
            if (ntoh32(hdr->ack) == pcb->snd.nxt) {
                pcb->state = TCP_PCB_STATE_FIN_WAIT2;
            }
            break;
        case TCP_PCB_STATE_FIN_WAIT2:
            // if the retransmission queue is empty, the user's CLOSE can be acknowledged ("ok") but do not delete the TCB.
            break;
        case TCP_PCB_STATE_CLOSE_WAIT:
            // do nothing
            break;
        case TCP_PCB_STATE_CLOSING:
            if (ntoh32(hdr->ack) == pcb->snd.nxt) {
                pcb->state = TCP_PCB_STATE_TIME_WAIT;
                pthread_cond_broadcast(&pcb->cond);
            }
            break;
        }
        break;
    case TCP_PCB_STATE_LAST_ACK:
        if (ntoh32(hdr->ack) == pcb->snd.nxt) {
            pcb->state = TCP_PCB_STATE_CLOSED;
            tcp_pcb_release(pcb);
        }
        return;
    case TCP_PCB_STATE_TIME_WAIT:
        if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_FIN)) {
            // TODO: restart the 2 MSL timeout
        }
        break;
    }

    // 6. check the URG bit

    // 7. process the segment text
    switch (pcb->state) {
    case TCP_PCB_STATE_ESTABLISHED:
    case TCP_PCB_STATE_FIN_WAIT1:
    case TCP_PCB_STATE_FIN_WAIT2:
        memcpy(pcb->rcv_buf + (sizeof(pcb->rcv_buf) - pcb->rcv.wnd), (uint8_t *)hdr + hlen, slen);
        pcb->rcv.nxt = ntoh32(hdr->seq) + slen;
        pcb->rcv.wnd -= slen;
        tcp_output(pcb, pcb->snd.nxt, pcb->rcv.nxt, TCP_FLG_ACK, NULL, 0);
        pthread_cond_broadcast(&pcb->cond);
        break;
    case TCP_PCB_STATE_CLOSE_WAIT:
    case TCP_PCB_STATE_CLOSING:
    case TCP_PCB_STATE_LAST_ACK:
    case TCP_PCB_STATE_TIME_WAIT:
        // ignore
        break;
    }

    // 8. check the FIN bit
    if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_FIN)) {
        switch (pcb->state) {
        case TCP_PCB_STATE_CLOSED:
        case TCP_PCB_STATE_LISTEN:
        case TCP_PCB_STATE_SYN_SENT:
            // drop
            return;
        }
        pcb->rcv.nxt = ntoh32(hdr->seq) + 1;
        tcp_output(pcb, pcb->snd.nxt, pcb->rcv.nxt, TCP_FLG_ACK, NULL, 0);
        switch (pcb->state) {
        case TCP_PCB_STATE_SYN_RECEIVED:
        case TCP_PCB_STATE_ESTABLISHED:
            pcb->state = TCP_PCB_STATE_CLOSE_WAIT;
            pthread_cond_broadcast(&pcb->cond);
            break;
        case TCP_PCB_STATE_FIN_WAIT1:
            if (ntoh32(hdr->ack) == pcb->snd.nxt) {
                pcb->state = TCP_PCB_STATE_TIME_WAIT;
                // TODO: Start the time-wait timer, turn off the other timers
            } else {
                pcb->state = TCP_PCB_STATE_CLOSING;
            }
            break;
        case TCP_PCB_STATE_FIN_WAIT2:
            pcb->state = TCP_PCB_STATE_TIME_WAIT;
            // TODO: Start the time-wait timer, turn off the other timers
            break;
        case TCP_PCB_STATE_CLOSE_WAIT:
            // Remain in the CLOSE-WAIT state
            break;
        case TCP_PCB_STATE_CLOSING:
            // Remain in the CLOSING state
            break;
        case TCP_PCB_STATE_LAST_ACK:
            // Remain in the LAST-ACK state
            break;
        case TCP_PCB_STATE_TIME_WAIT:
            // Remain in the TIME-WAIT state
            // TODO: Restart the 2 MSL time-wait timeout
            break;
        }
    }

    return;
}

static void
tcp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst) {
    struct tcp_hdr *hdr;
    uint32_t pseudo = 0;

    if (len < sizeof(struct tcp_hdr)) {
        errorf("input data is too short");
        return;
    }
    hdr = (struct tcp_hdr *)data;
    pseudo += src >> 16;
    pseudo += src & 0xffff;
    pseudo += dst >> 16;
    pseudo += dst & 0xffff;
    pseudo += hton16((uint16_t)IP_PROTOCOL_TCP);
    pseudo += hton16(len);
    if (cksum16((uint16_t *)hdr, len, pseudo) != 0) {
        errorf("tcp checksum error");
        return;
    }
    tcplog(hdr, src, dst, len);
    tcp_dump(data, len);
    pthread_mutex_lock(&mutex);
    tcp_segment_arrives(hdr, len, src, dst);
    pthread_mutex_unlock(&mutex);
    return;
}

/*
 * USER COMMAND (RFC793)
 */

int
tcp_open_rfc793(struct socket *local, struct socket *foreign, int active)
{
    struct tcp_pcb *pcb;
    int state, id;

    pthread_mutex_lock(&mutex);
    pcb = tcp_pcb_new();
    if (!pcb) {
        errorf("");
        pthread_mutex_unlock(&mutex);
        return -1;
    }
    if (!active) {
        pcb->self.addr = local->addr;
        pcb->self.port = local->port;
        if (foreign) {
            pcb->peer.addr = foreign->addr;
            pcb->peer.port = foreign->port;
        }
        pcb->state = TCP_PCB_STATE_LISTEN;
    } else {
        pcb->self.addr = local->addr;
        pcb->self.port = local->port;
        pcb->peer.addr = foreign->addr;
        pcb->peer.port = foreign->port;
        pcb->rcv.wnd = sizeof(pcb->rcv_buf);
        pcb->iss = random();
        tcp_output(pcb, pcb->iss, 0, TCP_FLG_SYN, NULL, 0);
        pcb->snd.una = pcb->iss;
        pcb->snd.nxt = pcb->iss + 1;
        pcb->state = TCP_PCB_STATE_SYN_SENT;
    }
AGAIN:
    state = pcb->state;
    // waiting for state changed
    while ((pcb->state == state) && !net_interrupt) {
        pcb->wait++;
        pthread_cond_wait(&pcb->cond, &mutex);
        pcb->wait--;
    }
    if (pcb->state != TCP_PCB_STATE_ESTABLISHED) {
        if (pcb->state == TCP_PCB_STATE_SYN_RECEIVED) {
            goto AGAIN;
        }
        errorf("open error: %d", pcb->state);
        pcb->state = TCP_PCB_STATE_CLOSED;
        tcp_pcb_release(pcb);
        pthread_mutex_unlock(&mutex);
        return -1;
    }
    id = tcp_pcb_id(pcb);
    pthread_mutex_unlock(&mutex);
    return id;
}

int
tcp_open(void)
{
    struct tcp_pcb *pcb;
    int id; 

    pthread_mutex_lock(&mutex);
    pcb = tcp_pcb_new();
    if (!pcb) {
        errorf("");
        pthread_mutex_unlock(&mutex);
        return -1;
    }
    id = tcp_pcb_id(pcb);
    pthread_mutex_unlock(&mutex);
    return id;
}

int
tcp_connect(int id, struct socket *foreign)
{
    struct tcp_pcb *pcb;
    struct socket local;
    struct ip_iface *iface;
    char addr[IP_ADDR_STR_LEN];
    int p;
    int state;

    pthread_mutex_lock(&mutex);
    pcb = tcp_pcb_get(id);
    if (!pcb) {
        errorf("");
        pthread_mutex_unlock(&mutex);
        return -1;
    }
    local.addr = pcb->self.addr;
    local.port = pcb->self.port;
    if (local.addr == IP_ADDR_ANY) {
        iface = ip_iface_by_peer(foreign->addr);
        if (!iface) {
            errorf("");
            pthread_mutex_unlock(&mutex);
            return -1;
        }
        debugf("select source address: %s", ip_addr_ntop(&iface->unicast, addr, sizeof(addr)));
        local.addr = iface->unicast;
    }
    if (!local.port) {
        for (p = TCP_SOURCE_PORT_MIN; p <= TCP_SOURCE_PORT_MAX; p++) {
            local.port = p;
            if (!tcp_pcb_select(&local, foreign)) {
                debugf("dinamic assign srouce port: %d", ntoh16(local.port));
                pcb->self.port = local.port;
                break;
            }
        }
        if (!local.port) {
            debugf("failed to dinamic assign srouce port");
            pthread_mutex_unlock(&mutex);
            return -1;
        }
    }
    pcb->self.addr = local.addr;
    pcb->self.port = local.port;
    pcb->peer.addr = foreign->addr;
    pcb->peer.port = foreign->port;
    pcb->rcv.wnd = sizeof(pcb->rcv_buf);
    pcb->iss = random();
    tcp_output(pcb, pcb->iss, 0, TCP_FLG_SYN, NULL, 0);
    pcb->snd.una = pcb->iss;
    pcb->snd.nxt = pcb->iss + 1;
    pcb->state = TCP_PCB_STATE_SYN_SENT;
AGAIN:
    state = pcb->state;
    // waiting for state changed
    while ((pcb->state == state) && !net_interrupt) {
        pcb->wait++;
        pthread_cond_wait(&pcb->cond, &mutex);
        pcb->wait--;
    }
    if (pcb->state != TCP_PCB_STATE_ESTABLISHED) {
        if (pcb->state == TCP_PCB_STATE_SYN_RECEIVED) {
            goto AGAIN;
        }
        errorf("open error: %d", pcb->state);
        pcb->state = TCP_PCB_STATE_CLOSED;
        tcp_pcb_release(pcb);
        pthread_mutex_unlock(&mutex);
        return -1;
    }
    id = tcp_pcb_id(pcb);
    pthread_mutex_unlock(&mutex);
    return id;
}

int
tcp_bind(int id, struct socket *local)
{
    struct tcp_pcb *pcb, *exists;

    pthread_mutex_lock(&mutex);
    pcb = tcp_pcb_get(id);
    if (!pcb) {
        errorf("");
        pthread_mutex_unlock(&mutex);
        return -1;
    }
    exists = tcp_pcb_select(local, NULL);
    if (exists) {
        errorf("exists");
        pthread_mutex_unlock(&mutex);
        return -1;
    }
    pcb->self.addr = local->addr;
    pcb->self.port = local->port;
    debugf("success");
    pthread_mutex_unlock(&mutex);
    return 0;
}

int
tcp_listen(int id, int backlog)
{
    struct tcp_pcb *pcb;

    pthread_mutex_lock(&mutex);
    pcb = tcp_pcb_get(id);
    if (!pcb) {
        errorf("");
        pthread_mutex_unlock(&mutex);
        return -1;
    }
    pcb->state = TCP_PCB_STATE_LISTEN;
    (void)backlog; // TODO: set backlog
    pthread_mutex_unlock(&mutex);
    return 0;
}

int
tcp_accept(int id, struct socket *peer)
{
    struct tcp_backlog_entry *entry;
    struct tcp_pcb *pcb, *new_pcb;
    int new_id;

    pthread_mutex_lock(&mutex);
    pcb = tcp_pcb_get(id);
    if (!pcb) {
        errorf("");
        pthread_mutex_unlock(&mutex);
        return -1;
    }
    if (pcb->state != TCP_PCB_STATE_LISTEN) {
        errorf("");
        pthread_mutex_unlock(&mutex);
        return -1;
    }
    while (!(entry = (struct tcp_backlog_entry *)queue_pop(&pcb->backlog)) && !net_interrupt) {
        pcb->wait++;
        pthread_cond_wait(&pcb->cond, &mutex);
        pcb->wait--;
    }
    if (!entry) {
        /* EINTR */
        pthread_mutex_unlock(&mutex);
        return -1;
    }
    new_pcb = entry->pcb;
    if (peer) {
        peer->addr = new_pcb->peer.addr;
        peer->port = new_pcb->peer.port;
    }
    free(entry);
    new_id = tcp_pcb_id(new_pcb);
    pthread_mutex_unlock(&mutex);
    return new_id;
}

ssize_t
tcp_send(int id, uint8_t *data, size_t len)
{
    struct tcp_pcb *pcb;
    ssize_t sent = 0;
    struct ip_iface *iface;
    size_t mss, cap, slen;

    pthread_mutex_lock(&mutex);
    pcb = tcp_pcb_get(id);
    if (!pcb) {
        errorf("");
        pthread_mutex_unlock(&mutex);
        return -1;
    }
RETRY:
    switch (pcb->state) {
    case TCP_PCB_STATE_CLOSED:
        errorf("connection does not exist");
        pthread_mutex_unlock(&mutex);
        return -1;
    case TCP_PCB_STATE_LISTEN:
        // TODO: change the connection from passive to active
        errorf("this connection is passive");
        pthread_mutex_unlock(&mutex);
        return -1;
    case TCP_PCB_STATE_SYN_SENT:
    case TCP_PCB_STATE_SYN_RECEIVED:
        // TODO: Queue the data for transmission after entering ESTABLISHED state
        errorf("insufficient resources");
        pthread_mutex_unlock(&mutex);
        return -1;
    case TCP_PCB_STATE_ESTABLISHED:
    case TCP_PCB_STATE_CLOSE_WAIT:
        iface = ip_iface_by_addr(pcb->self.addr);
        if (!iface) {
            errorf("iface not found");
            pthread_mutex_unlock(&mutex);
            return -1;
        }
        mss = NET_IFACE(iface)->dev->mtu - (IP_HDR_SIZE_MIN + sizeof(struct tcp_hdr));
        while (sent < (ssize_t)len) {
            cap = pcb->snd.wnd - (pcb->snd.nxt - pcb->snd.una);
            if (!cap) {
                pcb->wait++;
                pthread_cond_wait(&pcb->cond, &mutex);
                pcb->wait--;
                if (net_interrupt) {
                    break;
                }
                goto RETRY;
            }
            slen = MIN(MIN(mss, len - sent), cap);
            tcp_output(pcb, pcb->snd.nxt, pcb->rcv.nxt, TCP_FLG_ACK | TCP_FLG_PSH, data + sent, slen);
            pcb->snd.nxt += slen;
            sent += slen;
        }
        break;
    case TCP_PCB_STATE_FIN_WAIT1:
    case TCP_PCB_STATE_FIN_WAIT2:
    case TCP_PCB_STATE_CLOSING:
    case TCP_PCB_STATE_LAST_ACK:
    case TCP_PCB_STATE_TIME_WAIT:
        errorf("connection closing");
        pthread_mutex_unlock(&mutex);
        return -1;
    default:
        errorf("unknown state '%u'", pcb->state);
        pthread_mutex_unlock(&mutex);
        return -1;
    }
    pthread_mutex_unlock(&mutex);
    return sent;
}

ssize_t
tcp_receive(int id, uint8_t *buf, size_t size)
{
    struct tcp_pcb *pcb;
    size_t remain, len;

    pthread_mutex_lock(&mutex);
    pcb = tcp_pcb_get(id);
    if (!pcb) {
        errorf("not found");
        pthread_mutex_unlock(&mutex);
        return -1;
    }
RETRY:
    switch (pcb->state) {
    case TCP_PCB_STATE_CLOSED:
        errorf("connection does not exist");
        pthread_mutex_unlock(&mutex);
        return -1;
    case TCP_PCB_STATE_LISTEN:
    case TCP_PCB_STATE_SYN_SENT:
    case TCP_PCB_STATE_SYN_RECEIVED:
        // TODO: Queue for processing after entering ESTABLISHED state
        errorf("insufficient resources");
        pthread_mutex_unlock(&mutex);
        return -1;
    case TCP_PCB_STATE_ESTABLISHED:
    case TCP_PCB_STATE_FIN_WAIT1:
    case TCP_PCB_STATE_FIN_WAIT2:
        remain = sizeof(pcb->rcv_buf) - pcb->rcv.wnd;
        if (!remain) {
            pcb->wait++;
            pthread_cond_wait(&pcb->cond, &mutex);
            pcb->wait--;
            if (net_interrupt) {
                errorf("interrupt");
                pthread_mutex_unlock(&mutex);
                return -1;
            }
            goto RETRY;
        }
        break;
    case TCP_PCB_STATE_CLOSE_WAIT:
        remain = sizeof(pcb->rcv_buf) - pcb->rcv.wnd;
        if (remain) {
            break;
        }
        // fall through
    case TCP_PCB_STATE_CLOSING:
    case TCP_PCB_STATE_LAST_ACK:
    case TCP_PCB_STATE_TIME_WAIT:
        errorf("connection closing");
        pthread_mutex_unlock(&mutex);
        return 0;
    default:
        errorf("unknown state '%u'", pcb->state);
        pthread_mutex_unlock(&mutex);
        return -1;
    }
    len = MIN(size, remain);
    memcpy(buf, pcb->rcv_buf, len);
    memmove(pcb->rcv_buf, pcb->rcv_buf + len, remain - len);
    pcb->rcv.wnd += len;
    pthread_mutex_unlock(&mutex);
    return len;
}

int
tcp_close(int id)
{
    struct tcp_pcb *pcb;

    pthread_mutex_lock(&mutex);
    pcb = tcp_pcb_get(id);
    if (!pcb) {
        errorf("not found");
        pthread_mutex_unlock(&mutex);
        return -1;
    }
    switch (pcb->state) {
    case TCP_PCB_STATE_CLOSED:
        errorf("connection does not exist");
        pthread_mutex_unlock(&mutex);
        return -1;
    case TCP_PCB_STATE_LISTEN:
        pcb->state = TCP_PCB_STATE_CLOSED;
        break;
    case TCP_PCB_STATE_SYN_SENT:
        pcb->state = TCP_PCB_STATE_CLOSED;
        break;
    case TCP_PCB_STATE_SYN_RECEIVED:
        pcb->state = TCP_PCB_STATE_FIN_WAIT1;
        break;
    case TCP_PCB_STATE_ESTABLISHED:
        pcb->state = TCP_PCB_STATE_FIN_WAIT1;
        break;
    case TCP_PCB_STATE_FIN_WAIT1:
    case TCP_PCB_STATE_FIN_WAIT2:
        errorf("connection closing");
        pthread_mutex_unlock(&mutex);
        return -1;
    case TCP_PCB_STATE_CLOSE_WAIT:
        pcb->state = TCP_PCB_STATE_CLOSING;
        break;
    case TCP_PCB_STATE_CLOSING:
    case TCP_PCB_STATE_LAST_ACK:
    case TCP_PCB_STATE_TIME_WAIT:
        errorf("connection closing");
        pthread_mutex_unlock(&mutex);
        return -1;
    default:
        errorf("unknown state '%u'", pcb->state);
        pthread_mutex_unlock(&mutex);
        return -1;
    }
    if (pcb->state == TCP_PCB_STATE_CLOSED) {
        tcp_pcb_release(pcb);
    } else {
        pthread_cond_broadcast(&pcb->cond);
    }
    pthread_mutex_unlock(&mutex);
    return 0;
}

static void
tcp_timer(void)
{
    struct tcp_pcb *pcb;
    struct tcp_queue_entry *entry;
    struct timeval timestamp, diff;

    pthread_mutex_lock(&mutex);
    gettimeofday(&timestamp, NULL);
    for (pcb = pcbs; pcb < array_tailof(pcbs); pcb++) {
        if (pcb->state == TCP_PCB_STATE_NONE) {
            continue;
        }
        if (net_interrupt) {    
            pthread_cond_broadcast(&pcb->cond);
            continue;
        }
        while (pcb->snd_queue.next) {
            entry = (struct tcp_queue_entry *)pcb->snd_queue.next;
            if (ntoh32(entry->segment->seq) >= pcb->snd.una) {
                break;
            }
            entry = (struct tcp_queue_entry *)queue_pop(&pcb->snd_queue);
            free(entry->segment);
            free(entry);
        }
        for (entry = (struct tcp_queue_entry *)pcb->snd_queue.next; entry; entry = (struct tcp_queue_entry *)entry->next) {
            timersub(&timestamp, &entry->timestamp, &diff);
            if (diff.tv_sec > 3) {
                ip_output(IP_PROTOCOL_TCP, (uint8_t *)entry->segment, entry->len, pcb->self.addr, pcb->peer.addr);
                entry->timestamp = timestamp;
            }
        }
    }
    pthread_mutex_unlock(&mutex);
}

int
tcp_init(void)
{
    struct timeval interval = {0,100000};

    ip_protocol_register("TCP", IP_PROTOCOL_TCP, tcp_input);
    net_timer_register("TCP Timer", interval, tcp_timer);
    return 0;
}
