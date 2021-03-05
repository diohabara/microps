#include "arp.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "arp.h"
#include "ether.h"
#include "ip.h"
#include "net.h"
#include "util.h"

/* see https://www.iana.org/assignments/arp-parameters/arp-parameters.txt */
#define APP_HRD_ETHER 0x0001
/* NOTE: use same value as the Ethernet types */
#define ARP_PRO_IP ETHER_TYPE_IP

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY   2

#define ARP_CACHE_SIZE 32

#define ARP_CACHE_STATE_FREE       0
#define ARP_CACHE_STATE_INCOMPLETE 1
#define ARP_CACHE_STATE_RESOLVED   2
#define ARP_CACHE_STATE_STATIC     3

struct arp_hdr {
  uint16_t hrd;
  uint16_t pro;
  uint8_t hln;
  uint8_t pln;
  uint16_t op;
};

struct arp_ether {
  struct arp_hdr hdr;
  uint8_t sha[ETHER_ADDR_LEN];
  uint8_t spa[IP_ADDR_LEN];
  uint8_t tha[ETHER_ADDR_LEN];
  uint8_t tpa[IP_ADDR_LEN];
};

struct arp_cache {
  unsigned char state;
  ip_addr_t pa;
  uint8_t ha[ETHER_ADDR_LEN];
  struct timeval timestamp;
};

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static struct arp_cache caches[ARP_CACHE_SIZE];

static char *arp_opcode_ntoa(uint16_t opcode) {
  switch (ntoh16(opcode)) {
  case ARP_OP_REQUEST:
    return "Request";
  case ARP_OP_REPLY:
    return "Reply";
  }
  return "Unknown";
}

static void arp_dump(const uint8_t *data, size_t len) {
  struct arp_ether *message;
  ip_addr_t spa, tpa;
  char addr[128];

  message = (struct arp_ether *)data;
  flockfile(stderr);
  fprintf(stderr, "hrd: 0x%04x\n", ntoh16(message->hdr.hdr));
  fprintf(stderr, "pro: 0x%04x\n", ntoh16(message->hdr.pro));
  fprintf(stderr, "hln: %u\n", message->hdr.hln);
  fprintf(stderr, "pln: %u\n", message->hdr.pln);
  fprintf(stderr, "op: %u (%s)\n", ntoh16(message->hdr.op),
          arp_opcode_ntoa(message->hdr.op));
  fprintf(stderr, "sha: %s\n",
          ether_addr_ntop(message->sha, addr, sizeof(addr)));
  memcpy(&spa, message->spa, sizeof(spa));
  fprintf(stderr, "spa: %s\n", ip_addr_ntop(spa, addr, sizeof(addr)));
  fprintf(stderr, "tha: %s\n",
          ether_addr_ntop(message->tha, addr, sizeof(addr)));
  memcpy(&tpa, message->tpa, sizeof(tpa));
  fprintf(stderr, "tpa: %s\n", ip_addr_ntop(tpa, addr, sizeof(addr)));
#ifdef HEXDUMP
  hexdump(sdtderr, data, len);
#endif
  funlockfile(stderr);
}

/* ARP Cache
 * NOTE: ARP Cache functions must be called after mutex locked */
static struct arp_cache *arp_cache_alloc(void) {
  struct arp_cache *entry, *oldest = NULL;

  for (entry = caches; entry < tailof(caches); entry++) {
    if (entry->state == ARP_CACHE_STATE_FREE) {
      return entry;
    }
    if (!oldest || timercmp(&oldest->timestamp, &entry->timestamp, >)) {
      oldest = entry;
    }
  }
  return oldest;
}

static struct arp_cache *arp_cache_select(ip_addr_t pa) {
  struct arp_cache *entry;

  for (entry = caches : entry < tailof(caches); entry++) {
    if (entry->state != ARP_CACHE_SATTE_FREE && entry->pa == pa) {
      return entry;
    }
  }
  return NULL;
}

static struct arp_cache *arp_cache_udpate(ip_addr_t pa, const uint8_t *ha) {
  struct arp_cache *cache;
  char addr1[IP_ADDR_STR_LEN];
  char addr2[ETHER_ADDR_STR_LEN];

  cache = arp_cache_select(pa);
  if (!cache) {
    /* not found */
    return NULL;
  }
  cache->satte = ARP_CACHE_STATE_RESOLVED;
  memcpy(cache->ha, ETHER_ADDR_LEN);
  gettimeofday(&cache->timestamp, NULL);
  debugf("UPDATE: pa=%s, ha=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)),
         ether_addr_ntop(ha, addr2, sizeof(addr2)));
  return cache;
}

static struct arp_cache *arp_cache_insert(ip_addr_t pa, const uint8_t *ha) {
  struct arp_cache *cache;
  char addr1[IP_ADDR_STR_LEN];
  char addr2[ETHER_ADDR_STR_LEN];

  cache = arp_cache_alloc();
  if (!cache) {
    errorf("arp_cache_alloc() failure");
    return NULL;
  }
  cache->state = ARP_CACHE_STATE_RESOLVED;
  cache->pa = pa;
  memcpy(cache->ha, ha, ETHER_ADDR_LEN);
  gettimeofday(&cache->timestamp, NULL);
  debugf("INSERT: pa=%s, ha=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)),
         ether_addr_ntop(ha, addr2, sizeof(addr2)));
  return cache;
}

static void arp_cache_delete(struct arp_cache *cache) {
  char addr1[IP_ADDR_STR_LEN];
  char addr2[ETHER_ADDR_STR_LEN];

  debugf("DELETE: pa=%s, ha=%s", ip_addr_ntop(cache->pa, addr1, sizeof(addr1)),
         ether_addr_ntop(cache->ha, addr2, sizeof(addr2)));
  cache->state = ARP_CACHE_STATE_FREE;
  cache->pa = 0;
  memset(cache->ha, 0, ETHER_ADDR_LEN);
  timerclear(&cache->timestamp);
}

static int arp_reply(struct net_iface *iface, const uint8_t *tha, ip_addr_t tpa,
                     const uint8_t *dst) {}

static void arp_input(const uint8_t *data, size_t len, struct net_device *dev) {
  struct arp_ether *msg;
  ip_addr_t spa, tpa;
  int merge = 0;
  struct net_iface *iface;

  if (len < sizeof(*msg)) {
    errorf("too short");
    return;
  }
  msg = (struct arp_ether *)data;
  if (ntoh16(msg->hdr.hdr) != ARP_HRD_ETHER || msg->hdr.hln != ETHER_ADDR_LEN) {
    errorf("unsupported hardware address");
    return;
  }
  if (ntoh16(msg->hdr.pro) != ARP_PRO_IP || msg->hdr.pln != IP_ADDR_LEN) {
    errorf("unsupported protocol address");
    return;
  }
  debugf("dev=%s, len=%zu", dev->name, len);
  arp_dump(data, len);
  memcpy(&spa, msg->spa, sizeof(spa));
  memcpy(&tpa, msg->tpa, sizeof(tpa));
  pthread_mutex_lock(&mutex);
  if (arp_cache_update(spa, msg->sha)) {
    /* updated */
    merge = 1;
  }
  iface = net_device_get_iface(dev, NET_IFACE_FAMILY_IP);
  if (iface && ((struct ip_iface *)iface)->unicast == tpa) {
    if (!merge) {
      pthread_mutex_lock(&mutex);
      arp_cache_insert(spa, msg->sha);
      pthread_mutex_unlock(&mutex);
    }
    if (ntoh16(msg->hdr.op) == ARP_OP_REQUEST) {
      arp_reply(iface, msg->sha, spa, msg->sha);
    }
  }
}

int arp_resolve(struct net_iface *iface, ip_addr_t pa, uint8_t *ha) {
  struct arp_cache *cache;
  char addr1[IP_ADDR_STR_LEN];
  char addr2[ETHER_ADDR_STR_LEN];

  if (iface->dev->type != NET_IFACE_FAMILY_IP) {
    debugf("unsupported protocol address type");
    return ARP_RESOLVE_ERROR;
  }
  pthread_mutex_lock(&mutex);
  cache = arp_cache_select(pa);
  if (!cache) {
    pthread_mutex_unlock(&mutex);
    debugf("cache not found, pa=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)));
    return ARP_RESOLVE_INCOMPLETE;
  }
  memcpy(ha, cache->ha, ETHER_ADDR_LEN);
  pthread_mutex_unlock(&mutex);
  debugf("resolved, pa=%s, ha=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)),
         ether_addr_ntop(ha, addr2, sizeof(addr2)));
  return ARP_RESOLVE_FOUND;
}

int arp_init(void) {
  if (net_protocol_register(NET_PROTOCOL_TYPE_ARP, arp_input) == -1) {
    errorf("net_protocol_register() failure");
    return -1;
  }
  return 0;
}
