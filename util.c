#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include <time.h>
#include <sys/time.h>

#include "util.h"

int
lprintf(int level, const char *file, int line, const char *func, const char *fmt, ...) {
    struct timeval tv;
    struct tm tm;
    char timestamp[32];
    int n = 0;
    va_list ap;

    gettimeofday(&tv, NULL);
    strftime(timestamp, sizeof(timestamp), "%T", localtime_r(&tv.tv_sec, &tm));
    flockfile(stderr);
    n += fprintf(stderr, "%s.%03d [%c] %s: ", timestamp, (int)(tv.tv_usec / 1000), level, func);
    va_start(ap, fmt);
    n += vfprintf(stderr, fmt, ap);
    va_end(ap);
    n += fprintf(stderr, " (%s:%d)\n", file, line);
    funlockfile(stderr);
    return n;
}

void
hexdump(FILE *fp, const void *data, size_t size) {
    unsigned char *src;
    int offset, index;

    flockfile(fp);
    src = (unsigned char *)data;
    fprintf(fp, "+------+-------------------------------------------------+------------------+\n");
    for(offset = 0; offset < (int)size; offset += 16) {
        fprintf(fp, "| %04x | ", offset);
        for(index = 0; index < 16; index++) {
            if(offset + index < (int)size) {
                fprintf(fp, "%02x ", 0xff & src[offset + index]);
            } else {
                fprintf(fp, "   ");
            }
        }
        fprintf(fp, "| ");
        for(index = 0; index < 16; index++) {
            if(offset + index < (int)size) {
                if(isascii(src[offset + index]) && isprint(src[offset + index])) {
                    fprintf(fp, "%c", src[offset + index]);
                } else {
                    fprintf(fp, ".");
                }
            } else {
                fprintf(fp, " ");
            }
        }
        fprintf(fp, " |\n");
    }
    fprintf(fp, "+------+-------------------------------------------------+------------------+\n");
    funlockfile(fp);
}

#ifndef __BIG_ENDIAN
#define __BIG_ENDIAN 4321
#endif
#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN 1234
#endif

static int endian;

int
byteorder(void) {
    uint32_t x = 0x00000001;

    return *(uint8_t *)&x ? __LITTLE_ENDIAN : __BIG_ENDIAN;
}

uint16_t
byteswap16(uint16_t v) {
    return (v & 0x00ff) << 8 | (v & 0xff00 ) >> 8;
}

uint32_t
byteswap32(uint32_t v) {
    return (v & 0x000000ff) << 24 | (v & 0x0000ff00) << 8 | (v & 0x00ff0000) >> 8 | (v & 0xff000000) >> 24;
}

uint16_t
hton16(uint16_t h) {
    if (!endian) endian = byteorder();
    return endian == __LITTLE_ENDIAN ? byteswap16(h) : h;
}

uint16_t
ntoh16(uint16_t n) {
    if (!endian) endian = byteorder();
    return endian == __LITTLE_ENDIAN ? byteswap16(n) : n;
}

uint32_t
hton32(uint32_t h) {
    if (!endian) endian = byteorder();
    return endian == __LITTLE_ENDIAN ? byteswap32(h) : h;
}

uint32_t
ntoh32(uint32_t n) {
    if (!endian) endian = byteorder();
    return endian == __LITTLE_ENDIAN ? byteswap32(n) : n;
}

void
queue_init(struct queue_head *queue) {
    queue->next = NULL;
    queue->tail = NULL;
    queue->num = 0;
}

struct queue_entry *
queue_push(struct queue_head *queue, struct queue_entry *entry) {
    if (!queue || !entry) {
        return NULL;
    }
    entry->next = NULL;
    if (queue->tail) {
        queue->tail->next = entry;
    }
    queue->tail = entry;
    if (!queue->next) {
        queue->next = entry;
    }
    queue->num++;
    return entry;
}

struct queue_entry *
queue_pop(struct queue_head *queue) {
    struct queue_entry *entry;

    if (!queue || !queue->next) {
        return NULL;
    }
    entry = queue->next;
    queue->next = entry->next;
    if (!queue->next) {
        queue->tail = NULL;
    }
    queue->num--;
    return entry;
}

uint16_t
cksum16(uint16_t *addr, uint16_t count, uint32_t init) {
    uint32_t sum;

    sum = init;
    while (count > 1) {
        sum += *(addr++);
        count -= 2;
    }
    if (count > 0) {
        sum += *(uint8_t *)addr;
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return ~(uint16_t)sum;
}
