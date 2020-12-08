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

#define TCP_STATE_CLOSED       0
#define TCP_STATE_LISTEN       1
#define TCP_STATE_SYN_SENT     2
#define TCP_STATE_SYN_RECEIVED 3
#define TCP_STATE_ESTABLISHED  4
#define TCP_STATE_FIN_WAIT1    5
#define TCP_STATE_FIN_WAIT2    6
#define TCP_STATE_CLOSING      7
#define TCP_STATE_TIME_WAIT    8
#define TCP_STATE_CLOSE_WAIT   9
#define TCP_STATE_LAST_ACK    10

#define TCP_FLG_FIN 0x01
#define TCP_FLG_SYN 0x02
#define TCP_FLG_RST 0x04
#define TCP_FLG_PSH 0x08
#define TCP_FLG_ACK 0x10
#define TCP_FLG_URG 0x20

#define TCP_FLG_IS(x, y) ((x & 0x3f) == (y))
#define TCP_FLG_ISSET(x, y) ((x & 0x3f) & (y))

#define TCP_CB_TABLE_SIZE 128

#define TCP_SOURCE_PORT_MIN 49152
#define TCP_SOURCE_PORT_MAX 65535

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

struct tcp_txq_entry {
    struct tcp_hdr *segment;
    uint16_t len;
    struct timeval timestamp;
    struct tcp_txq_entry *next;
};

struct tcp_txq_head {
    struct tcp_txq_entry *head;
    struct tcp_txq_entry *tail;
};

struct tcp_pcb {
    uint8_t state;
    struct socket self;
    struct socket peer;
    struct {
        uint32_t nxt;
        uint32_t una;
        uint16_t up;
        uint32_t wl1;
        uint32_t wl2;
        uint16_t wnd;
    } snd;
    uint32_t iss;
    struct {
        uint32_t nxt;
        uint16_t up;
        uint16_t wnd;
    } rcv;
    uint32_t irs;
    struct tcp_txq_head txq;
    uint8_t window[65535];
    struct tcp_pcb *parent;
    struct queue_head backlog;
    pthread_cond_t cond;
    struct tcp_pcb *next;
};

struct tcp_backlog_entry {
    struct queue_entry *next;
    struct tcp_pcb *pcb;
};

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
struct tcp_pcb *pcbs;

void
tcp_dump(const uint8_t *data, size_t len)
{
    struct tcp_hdr *hdr;

    hdr = (struct tcp_hdr *)data;
    flockfile(stderr);
    fprintf(stderr, " src: %u\n", ntoh16(hdr->src));
    fprintf(stderr, " dst: %u\n", ntoh16(hdr->dst));
    fprintf(stderr, " seq: %u\n", ntoh32(hdr->seq));
    fprintf(stderr, " ack: %u\n", ntoh32(hdr->ack));
    fprintf(stderr, " off: 0x%02x (%d)\n", hdr->off, (hdr->off >> 4) << 2);
    fprintf(stderr, " flg: 0x%02x (--%c%c%c%c%c%c)\n", hdr->flg,
        TCP_FLG_ISSET(hdr->flg, TCP_FLG_URG) ? 'U' : '-',
        TCP_FLG_ISSET(hdr->flg, TCP_FLG_ACK) ? 'A' : '-',
        TCP_FLG_ISSET(hdr->flg, TCP_FLG_PSH) ? 'P' : '-',
        TCP_FLG_ISSET(hdr->flg, TCP_FLG_RST) ? 'R' : '-',
        TCP_FLG_ISSET(hdr->flg, TCP_FLG_SYN) ? 'S' : '-',
        TCP_FLG_ISSET(hdr->flg, TCP_FLG_FIN) ? 'F' : '-');
    fprintf(stderr, " win: %u\n", ntoh16(hdr->win));
    fprintf(stderr, " sum: 0x%04x (%u)\n", ntoh16(hdr->sum), ntoh16(hdr->sum));
    fprintf(stderr, " urg: %u\n", ntoh16(hdr->urg));
    hexdump(stderr, data, len);
    funlockfile(stderr);
}

static struct tcp_pcb *
tcp_pcb_select(ip_addr_t src_addr, uint16_t src_port, ip_addr_t dst_addr, uint16_t dst_port)
{
    struct tcp_pcb *pcb;

    for (pcb = pcbs; pcb; pcb = pcb->next) {
        if ((pcb->self.addr == IP_ADDR_ANY || pcb->self.addr == dst_addr) && pcb->self.port == dst_port) {
            if (pcb->peer.addr == src_addr && pcb->peer.port == src_port) {
                break;
            }
            if (pcb->state == TCP_STATE_LISTEN) {
                break;
            }
        }
    }
    return pcb;
}

static void
delete_pcb(struct tcp_pcb *pcb)
{
    struct tcp_pcb *cur;

    if (pcbs == pcb) {
        pcbs = pcb->next;
        return;
    }
    for (cur = pcbs; cur; cur = cur->next) {
        if (cur->next == pcb) {
            cur->next = pcb->next;
            return;
        }
    }
}

static int
tcp_txq_add(struct tcp_pcb *pcb, struct tcp_hdr *hdr, size_t len)
{
    struct tcp_txq_entry *txq;

    txq = malloc(sizeof(struct tcp_txq_entry));
    if (!txq) {
        return -1;
    }
    txq->segment = malloc(len);
    if (!txq->segment) {
        free(txq);
        return -1;
    }
    memcpy(txq->segment, hdr, len);
    txq->len = len;
    gettimeofday(&txq->timestamp, NULL);
    txq->next = NULL;

    // set txq to next of tail entry
    if (pcb->txq.head == NULL) {
        pcb->txq.head = txq;
    } else {
        pcb->txq.tail->next = txq;
    }
    // update tail entry
    pcb->txq.tail = txq;
    return 0;
}

static ssize_t
tcp_output(struct tcp_pcb *pcb, uint32_t seq, uint32_t ack, uint8_t flg, uint8_t *data, size_t len)
{
    uint8_t buf[1500];
    struct tcp_hdr *hdr;
    uint32_t pseudo = 0;
    struct ip_iface *iface;

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
    iface = ip_iface_by_addr(pcb->self.addr);
    if (!iface) {
        errorf("iface not found");
        return -1;
    }
    debugf("output");
    tcp_dump((uint8_t *)hdr, sizeof(struct tcp_hdr) + len);
    ip_output(iface, IP_PROTOCOL_TCP, (uint8_t *)hdr, sizeof(struct tcp_hdr) + len, pcb->peer.addr);
    if (len || TCP_FLG_ISSET(flg, TCP_FLG_SYN | TCP_FLG_FIN)) {
        tcp_txq_add(pcb, hdr, sizeof(struct tcp_hdr) + len);
    }
    return len;
}

// rfc793 - section 3.9 [Event Processing > SEGMENT ARRIVES]
static void
tcp_segment_arrives(struct tcp_hdr *hdr, size_t len, ip_addr_t src, ip_addr_t dst)
{
    struct tcp_pcb *pcb, *new_pcb;
    size_t hlen, slen;
    int acceptable = 0;

    pcb = tcp_pcb_select(src, hdr->src, dst, hdr->dst);
    if (!pcb) {
        return;
    }
    hlen = ((hdr->off >> 4) << 2);
    slen = len - hlen;
    switch(pcb->state) {
    case TCP_STATE_CLOSED:
        if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_RST)) {
            return;
        }
        if (!TCP_FLG_ISSET(hdr->flg, TCP_FLG_ACK)) {
            tcp_output(pcb, 0, ntoh32(hdr->seq) + slen, TCP_FLG_RST | TCP_FLG_ACK, NULL, 0);
        } else {
            tcp_output(pcb, ntoh32(hdr->ack), 0, TCP_FLG_RST, NULL, 0);
        }
        return;
    case TCP_STATE_LISTEN:
        // 1. check for an RST
        if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_RST)) {
            return;
        }
        // 2. check for an ACK
        if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_ACK)) {
            tcp_output(pcb, ntoh32(hdr->ack), 0, TCP_FLG_RST, NULL, 0);
            return;
        }
        // 3. check for an SYN
        if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_SYN)) {
            // TODO: security/compartment check
            // TODO: precedence check
            new_pcb = malloc(sizeof(struct tcp_pcb));
            if (!new_pcb) {
                errorf("malloc() failure");
                return;
            }
            memset(new_pcb, 0, sizeof(struct tcp_pcb));
            new_pcb->self.addr = dst;
            new_pcb->self.port = hdr->dst;
            new_pcb->peer.addr = src;
            new_pcb->peer.port = hdr->src;
            new_pcb->rcv.wnd = sizeof(new_pcb->window);
            new_pcb->parent = pcb;
            new_pcb->next = pcbs;
            pcbs = new_pcb;
            new_pcb->rcv.nxt = ntoh32(hdr->seq) + 1;
            new_pcb->irs = ntoh32(hdr->seq);
            new_pcb->iss = random();
            tcp_output(new_pcb, new_pcb->iss, new_pcb->rcv.nxt, TCP_FLG_SYN | TCP_FLG_ACK, NULL, 0);
            new_pcb->snd.nxt = new_pcb->iss + 1;
            new_pcb->snd.una = new_pcb->iss;
            new_pcb->state = TCP_STATE_SYN_RECEIVED;
            // TODO: Note that any other incoming control or data (combined with SYN) will be processed in the SYN-RECEIVED state, but processing of SYN and ACK  should not be repeated
            return;
        }
        // 4. other text or control
        return;
    case TCP_STATE_SYN_SENT:
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
                pcb->state = TCP_STATE_CLOSED;
                // tcp_close_pcb(pcb);
                pthread_cond_broadcast(&pcb->cond);
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
                pcb->state = TCP_STATE_ESTABLISHED;
                tcp_output(pcb, pcb->snd.nxt, pcb->rcv.nxt, TCP_FLG_ACK, NULL, 0);
                // XXX: not specified in the RFC793, but send window initialization required
                pcb->snd.wnd = ntoh16(hdr->win);
                pcb->snd.wl1 = ntoh32(hdr->seq);
                pcb->snd.wl2 = ntoh32(hdr->ack);
                // TODO: continue processing at the sixth step below where the URG bit is checked
                pthread_cond_broadcast(&pcb->cond);
                return;
            } else {
                pcb->state = TCP_STATE_SYN_RECEIVED;
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
    case TCP_STATE_SYN_RECEIVED:
    case TCP_STATE_ESTABLISHED:
    case TCP_STATE_FIN_WAIT1:
    case TCP_STATE_FIN_WAIT2:
    case TCP_STATE_CLOSE_WAIT:
    case TCP_STATE_CLOSING:
    case TCP_STATE_LAST_ACK:
    case TCP_STATE_TIME_WAIT:
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
    case TCP_STATE_SYN_RECEIVED:
        if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_RST)) {
            pcb->state = TCP_STATE_CLOSED;
            // TODO: delete TCB
            pthread_cond_broadcast(&pcb->cond);
            return;
        }
        break;
    case TCP_STATE_ESTABLISHED:
    case TCP_STATE_FIN_WAIT1:
    case TCP_STATE_FIN_WAIT2:
    case TCP_STATE_CLOSE_WAIT:
        if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_RST)) {
            errorf("connection reset");
            pcb->state = TCP_STATE_CLOSED;
            // TODO: delete TCB
            pthread_cond_broadcast(&pcb->cond);
            return;
        }
        break;
    case TCP_STATE_CLOSING:
    case TCP_STATE_LAST_ACK:
    case TCP_STATE_TIME_WAIT:
        if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_RST)) {
            pcb->state = TCP_STATE_CLOSED;
            // TODO: delete TCB
            return;
        }
        break;
    }

    // TODO: 3. check security and precedence

    // 4. check the SYN bit
    switch (pcb->state) {
    case TCP_STATE_SYN_RECEIVED:
    case TCP_STATE_ESTABLISHED:
    case TCP_STATE_FIN_WAIT1:
    case TCP_STATE_FIN_WAIT2:
    case TCP_STATE_CLOSE_WAIT:
    case TCP_STATE_CLOSING:
    case TCP_STATE_LAST_ACK:
    case TCP_STATE_TIME_WAIT:
        if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_SYN)) {
            tcp_output(pcb, pcb->snd.nxt, pcb->rcv.nxt, TCP_FLG_RST, NULL, 0);
            errorf("connection reset");
            pcb->state = TCP_STATE_CLOSED;
            // TODO: delete TCB
            pthread_cond_broadcast(&pcb->cond);
            return;
        }
    }
    // 5. check the ACK field
    if (!TCP_FLG_ISSET(hdr->flg, TCP_FLG_ACK)) {
        // drop
        return;
    }
    switch (pcb->state) {
    case TCP_STATE_SYN_RECEIVED:
        if (pcb->snd.una <= ntoh32(hdr->ack) && ntoh32(hdr->ack) <= pcb->snd.nxt) {
            pcb->state = TCP_STATE_ESTABLISHED;
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
    case TCP_STATE_ESTABLISHED:
    case TCP_STATE_FIN_WAIT1:
    case TCP_STATE_FIN_WAIT2:
    case TCP_STATE_CLOSE_WAIT:
    case TCP_STATE_CLOSING:
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
        case TCP_STATE_FIN_WAIT1:
            if (ntoh32(hdr->ack) == pcb->snd.nxt) {
                pcb->state = TCP_STATE_FIN_WAIT2;
            }
            break;
        case TCP_STATE_FIN_WAIT2:
            // TODO: if the retransmission queue is empty, the user's CLOSE can be acknowledged ("ok") but do not delete the TCB.
            break;
        case TCP_STATE_CLOSE_WAIT:
            // do nothing
            break;
        case TCP_STATE_CLOSING:
            if (ntoh32(hdr->ack) == pcb->snd.nxt) {
                pcb->state = TCP_STATE_TIME_WAIT;
                pthread_cond_broadcast(&pcb->cond);
            }
            break;
        }
        break;
    case TCP_STATE_LAST_ACK:
        if (ntoh32(hdr->ack) == pcb->snd.nxt) {
            pcb->state = TCP_STATE_CLOSED;
            // tcp_close_pcb(pcb)
            pthread_cond_broadcast(&pcb->cond);
        }
        return;
    case TCP_STATE_TIME_WAIT:
        if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_FIN)) {
            // TODO: restart the 2 MSL timeout
        }
        break;
    }

    // 6. check the URG bit

    // 7. process the segment text
    switch (pcb->state) {
    case TCP_STATE_ESTABLISHED:
    case TCP_STATE_FIN_WAIT1:
    case TCP_STATE_FIN_WAIT2:
        memcpy(pcb->window + (sizeof(pcb->window) - pcb->rcv.wnd), (uint8_t *)hdr + hlen, slen);
        pcb->rcv.nxt = ntoh32(hdr->seq) + slen;
        pcb->rcv.wnd -= slen;
        tcp_output(pcb, pcb->snd.nxt, pcb->rcv.nxt, TCP_FLG_ACK, NULL, 0);
        pthread_cond_broadcast(&pcb->cond);
        break;
    case TCP_STATE_CLOSE_WAIT:
    case TCP_STATE_CLOSING:
    case TCP_STATE_LAST_ACK:
    case TCP_STATE_TIME_WAIT:
        // ignore
        break;
    }

    // 8. check the FIN bit
    if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_FIN)) {
        switch (pcb->state) {
        case TCP_STATE_CLOSED:
        case TCP_STATE_LISTEN:
        case TCP_STATE_SYN_SENT:
            // drop
            return;
        }
        pcb->rcv.nxt = ntoh32(hdr->seq) + 1;
        tcp_output(pcb, pcb->snd.nxt, pcb->rcv.nxt, TCP_FLG_ACK, NULL, 0);
        switch (pcb->state) {
        case TCP_STATE_SYN_RECEIVED:
        case TCP_STATE_ESTABLISHED:
            pcb->state = TCP_STATE_CLOSE_WAIT;
            pthread_cond_broadcast(&pcb->cond);
            break;
        case TCP_STATE_FIN_WAIT1:
            if (ntoh32(hdr->ack) == pcb->snd.nxt) {
                pcb->state = TCP_STATE_TIME_WAIT;
                // TODO: Start the time-wait timer, turn off the other timers
            } else {
                pcb->state = TCP_STATE_CLOSING;
            }
            break;
        case TCP_STATE_FIN_WAIT2:
            pcb->state = TCP_STATE_TIME_WAIT;
            // TODO: Start the time-wait timer, turn off the other timers
            break;
        case TCP_STATE_CLOSE_WAIT:
            // Remain in the CLOSE-WAIT state
            break;
        case TCP_STATE_CLOSING:
            // Remain in the CLOSING state
            break;
        case TCP_STATE_LAST_ACK:
            // Remain in the LAST-ACK state
            break;
        case TCP_STATE_TIME_WAIT:
            // Remain in the TIME-WAIT state
            // TODO: Restart the 2 MSL time-wait timeout
            break;
        }
    }

    return;
}

static void
tcp_input(struct ip_iface *iface, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst) {
    struct tcp_hdr *hdr;
    uint32_t pseudo = 0;

    if (len < sizeof(struct tcp_hdr)) {
        errorf("too short");
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
    debugf("input");
    tcp_dump(data, len);
    pthread_mutex_lock(&mutex);
    tcp_segment_arrives(hdr, len, src, dst);
    pthread_mutex_unlock(&mutex);
    return;
}

static struct tcp_pcb * 
tcp_open(struct socket *local, struct socket *foreign, int active)
{
    struct tcp_pcb *pcb;

    pcb = malloc(sizeof(struct tcp_pcb));
    if (!pcb) {
        errorf("malloc() failure");
        return NULL;
    }
    memset(pcb, 0, sizeof(struct tcp_pcb));
    pthread_cond_init(&pcb->cond, NULL);
    if (!active) {
        if (local->addr != IP_ADDR_ANY) {
            pcb->self.addr = local->addr;
        }
        pcb->self.port = local->port;
        pcb->state = TCP_STATE_LISTEN;
        pcb->next = pcbs;
        pcbs = pcb;
    } else {
        pcb->self.addr = local->addr;
        pcb->self.port = local->port;
        pcb->peer.addr = foreign->addr;
        pcb->peer.port = foreign->port;
        pcb->rcv.wnd = sizeof(pcb->window);
        pcb->iss = random();
        tcp_output(pcb, pcb->iss, 0, TCP_FLG_SYN, NULL, 0);
        pcb->snd.una = pcb->iss;
        pcb->snd.nxt = pcb->iss + 1;
        pcb->state = TCP_STATE_SYN_SENT;
        pcb->next = pcbs;
        pcbs = pcb;
        // waiting for state changed
        while (pcb->state == TCP_STATE_SYN_SENT && !net_interrupt) {
            pthread_cond_wait(&pcb->cond, &mutex);
        }
        if (pcb->state != TCP_STATE_ESTABLISHED) {
            errorf("open error: %d", pcb->state);
            delete_pcb(pcb);
            free(pcb);
            return NULL;
        }
    }
    return pcb;
}

static struct tcp_pcb *
tcp_accept(struct tcp_pcb *pcb)
{
    struct tcp_backlog_entry *entry;
    struct tcp_pcb *new_pcb;

    if (pcb->state != TCP_STATE_LISTEN) {
        return NULL;
    }
    while (!(entry = (struct tcp_backlog_entry *)queue_pop(&pcb->backlog)) && !net_interrupt) {
        pthread_cond_wait(&pcb->cond, &mutex);
    }
    if (!entry) {
        return NULL;
    }
    new_pcb = entry->pcb;
    free(entry);
    return new_pcb;
}

static ssize_t
tcp_send(struct tcp_pcb *pcb, uint8_t *data, size_t len)
{
    struct ip_iface *iface;
    size_t mss, cap, slen;
    ssize_t sent = 0;

RETRY:
    switch (pcb->state) {
    case TCP_STATE_CLOSED:
        errorf("connection does not exist");
        return -1;
    case TCP_STATE_LISTEN:
        // TODO: change the connection from passive to active
        errorf("this connection is passive");
        return -1;
    case TCP_STATE_SYN_SENT:
    case TCP_STATE_SYN_RECEIVED:
        // TODO: Queue the data for transmission after entering ESTABLISHED state
        errorf("insufficient resources");
        return -1;
    case TCP_STATE_ESTABLISHED:
    case TCP_STATE_CLOSE_WAIT:
        iface = ip_iface_by_addr(pcb->self.addr);
        if (!iface) {
            errorf("iface not found");
            return -1;
        }
        mss = NET_IFACE(iface)->dev->mtu - (IP_HDR_SIZE_MIN + sizeof(struct tcp_hdr));
        while (sent < (ssize_t)len) {
            cap = pcb->snd.wnd - (pcb->snd.nxt - pcb->snd.una);
            if (!cap) {
                pthread_cond_wait(&pcb->cond, &mutex);
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
        return sent;
    case TCP_STATE_FIN_WAIT1:
    case TCP_STATE_FIN_WAIT2:
    case TCP_STATE_CLOSING:
    case TCP_STATE_LAST_ACK:
    case TCP_STATE_TIME_WAIT:
        errorf("connection closing");
        return -1;
    default:
        errorf("unknown state '%u'", pcb->state);
        return -1;
    }
}

static ssize_t
tcp_receive(struct tcp_pcb *pcb, uint8_t *buf, size_t size)
{
    size_t remain, len;

RETRY:
    switch (pcb->state) {
    case TCP_STATE_CLOSED:
        errorf("connection does not exist");
        return -1;
    case TCP_STATE_LISTEN:
    case TCP_STATE_SYN_SENT:
    case TCP_STATE_SYN_RECEIVED:
        // TODO: Queue for processing after entering ESTABLISHED state
        errorf("insufficient resources");
        return -1;
    case TCP_STATE_ESTABLISHED:
    case TCP_STATE_FIN_WAIT1:
    case TCP_STATE_FIN_WAIT2:
        remain = sizeof(pcb->window) - pcb->rcv.wnd;
        if (!remain) {
            pthread_cond_wait(&pcb->cond, &mutex);
            if (net_interrupt) {
                errorf("interrupt");
                return -1;
            }
            goto RETRY;
        }
        break;
    case TCP_STATE_CLOSE_WAIT:
        remain = sizeof(pcb->window) - pcb->rcv.wnd;
        if (remain) {
            break;
        }
        // fall through
    case TCP_STATE_CLOSING:
    case TCP_STATE_LAST_ACK:
    case TCP_STATE_TIME_WAIT:
        errorf("connection closing");
        return 0;
    default:
        errorf("unknown state '%u'", pcb->state);
        return -1;
    }
    len = MIN(size, remain);
    memcpy(buf, pcb->window, len);
    memmove(pcb->window, pcb->window + len, remain - len);
    pcb->rcv.wnd += len;
    return len;
}

static int
tcp_close(struct tcp_pcb *pcb)
{
    switch (pcb->state) {
    case TCP_STATE_CLOSED:
        errorf("connection does not exist");
        return -1;
    case TCP_STATE_LISTEN:
        pcb->state = TCP_STATE_CLOSED;
        pthread_cond_broadcast(&pcb->cond);
        return 0;
    case TCP_STATE_SYN_SENT:
        pcb->state = TCP_STATE_CLOSED;
        pthread_cond_broadcast(&pcb->cond);
        return 0;
    case TCP_STATE_SYN_RECEIVED:
        pcb->state = TCP_STATE_FIN_WAIT1;
        pthread_cond_broadcast(&pcb->cond);
        return 0;
    case TCP_STATE_ESTABLISHED:
        pcb->state = TCP_STATE_FIN_WAIT1;
        pthread_cond_broadcast(&pcb->cond);
        return 0;
    case TCP_STATE_FIN_WAIT1:
    case TCP_STATE_FIN_WAIT2:
        errorf("connection closing");
        return -1;
    case TCP_STATE_CLOSE_WAIT:
        pcb->state = TCP_STATE_CLOSING;
        pthread_cond_broadcast(&pcb->cond);
        return 0;
    case TCP_STATE_CLOSING:
    case TCP_STATE_LAST_ACK:
    case TCP_STATE_TIME_WAIT:
        errorf("connection closing");
        return -1;
    default:
        errorf("unknown state '%u'", pcb->state);
        return -1;
    }
}

struct tcp_pcb *
tcp_cmd_open(struct socket *local, struct socket *foreign, int active)
{
    struct tcp_pcb *ret;

    pthread_mutex_lock(&mutex);
    ret = tcp_open(local, foreign, active);
    pthread_mutex_unlock(&mutex);
    return ret;
}

struct tcp_pcb *
tcp_cmd_accept(struct tcp_pcb *pcb, struct socket *peer)
{
    struct tcp_pcb *ret;

    pthread_mutex_lock(&mutex);
    ret = tcp_accept(pcb);
    if (ret && peer) {
        peer->addr = ret->peer.addr;
        peer->port = ret->peer.port;
    }
    pthread_mutex_unlock(&mutex);
    return ret;
}

ssize_t
tcp_cmd_send(struct tcp_pcb *pcb, uint8_t *data, size_t len)
{
    ssize_t ret;

    pthread_mutex_lock(&mutex);
    ret = tcp_send(pcb, data, len);
    pthread_mutex_unlock(&mutex);
    return ret;
}

ssize_t
tcp_cmd_receive(struct tcp_pcb *pcb, uint8_t *buf, size_t size)
{
    ssize_t ret;

    pthread_mutex_lock(&mutex);
    ret = tcp_receive(pcb, buf, size);
    pthread_mutex_unlock(&mutex);
    return ret;
}

int
tcp_cmd_close(struct tcp_pcb *pcb)
{
    int ret;

    pthread_mutex_lock(&mutex);
    ret = tcp_close(pcb);
    pthread_mutex_unlock(&mutex);
    return ret;
}

static void
tcp_timer(void)
{
    struct timeval timestamp, diff;
    struct tcp_pcb *pcb;
    struct tcp_txq_entry *entry;
    struct ip_iface *iface;

    pthread_mutex_lock(&mutex);
    gettimeofday(&timestamp, NULL);
    for (pcb = pcbs; pcb; pcb = pcb->next) {
        while (pcb->txq.head) {
            entry = pcb->txq.head;
            if (ntoh32(entry->segment->seq) >= pcb->snd.una) {
                break;
            }
            pcb->txq.head = entry->next;
            free(entry->segment);
            free(entry);
        }
        for (entry = pcb->txq.head; entry; entry = entry->next) {
            timersub(&timestamp, &entry->timestamp, &diff);
            if (diff.tv_sec > 3) {
                iface = ip_iface_by_addr(pcb->self.addr);
                ip_output(iface, IP_PROTOCOL_TCP, (uint8_t *)entry->segment, entry->len, pcb->peer.addr);
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
    net_timer_register(interval, tcp_timer);
    return 0;
}
