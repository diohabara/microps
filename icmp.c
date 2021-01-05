#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "util.h"
#include "net.h"
#include "ip.h"
#include "icmp.h"

#define IP_PROTOCOL_ICMP 1
#define ICMP_BUFSIZ IP_PAYLOAD_SIZE_MAX

struct icmp_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t sum;
    uint32_t values;
};

struct icmp_echo {
    uint8_t type;
    uint8_t code;
    uint16_t sum;
    uint16_t id;
    uint16_t seq;
};

static char *
icmp_type_ntoa(uint8_t type) {
    switch (type) {
    case ICMP_TYPE_ECHOREPLY:
        return "Echo Reply";
    case ICMP_TYPE_DEST_UNREACH:
        return "Destination Unreachable";
    case ICMP_TYPE_SOURCE_QUENCH:
        return "Source Quench";
    case ICMP_TYPE_REDIRECT:
        return "Redirect";
    case ICMP_TYPE_ECHO:
        return "Echo";
    case ICMP_TYPE_TIME_EXCEEDED:
        return "Time Exceeded";
    case ICMP_TYPE_PARAM_PROBLEM:
        return "Parameter Problem";
    case ICMP_TYPE_TIMESTAMP:
        return "Timestamp";
    case ICMP_TYPE_TIMESTAMPREPLY:
        return "Timestamp Reply";
    case ICMP_TYPE_INFO_REQUEST:
        return "Information Request";
    case ICMP_TYPE_INFO_REPLY:
        return "Information Reply";
    }
    return "Unknown";
}

static void
icmp_dump(const uint8_t *data, size_t len)
{
    struct icmp_hdr *hdr;
    struct icmp_echo *echo;

    hdr = (struct icmp_hdr *)data;
    flockfile(stderr);
    fprintf(stderr, "    type: %u (%s)\n", hdr->type, icmp_type_ntoa(hdr->type));
    fprintf(stderr, "    code: %u\n", hdr->code);
    fprintf(stderr, "     sum: 0x%04x\n", ntoh16(hdr->sum));
    switch (hdr->type) {
    case ICMP_TYPE_ECHOREPLY:
    case ICMP_TYPE_ECHO:
        echo = (struct icmp_echo *)hdr;
        fprintf(stderr, "      id: %u\n", ntoh16(echo->id));
        fprintf(stderr, "     seq: %u\n", ntoh16(echo->seq));
        break;
    default:
        fprintf(stderr, "  values: 0x%08x\n", ntoh32(hdr->values));
        break;
    }
#ifdef ENABLE_DUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

static void
icmp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst)
{
    char addr1[IP_ADDR_STR_LEN], addr2[IP_ADDR_STR_LEN];
    struct icmp_hdr *hdr;

    if (len < sizeof(struct icmp_hdr)) {
        errorf("input data is too short");
        return;
    }
    debugf("%s => %s (%zu byte)",
        ip_addr_ntop(&src, addr1, sizeof(addr1)), ip_addr_ntop(&dst, addr2, sizeof(addr2)), len);
    icmp_dump(data, len);
    hdr = (struct icmp_hdr *)data;
    switch (hdr->type) {
    case ICMP_TYPE_ECHO:
        icmp_output(ICMP_TYPE_ECHOREPLY, hdr->code, hdr->values, (uint8_t *)(hdr + 1), len - sizeof(struct icmp_hdr), dst, src);
        break;
    default:
        /* ignore */
        break;
    }
}

int
icmp_output(uint8_t type, uint8_t code, uint32_t values, uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst)
{
    uint8_t buf[ICMP_BUFSIZ];
    struct icmp_hdr *hdr;
    size_t msg_len;
    char addr1[IP_ADDR_STR_LEN], addr2[IP_ADDR_STR_LEN];

    hdr = (struct icmp_hdr *)buf;
    hdr->type = type;
    hdr->code = code;
    hdr->sum = 0;
    hdr->values = values;
    memcpy(hdr + 1, data, len);
    msg_len = sizeof(struct icmp_hdr) + len;
    hdr->sum = cksum16((uint16_t *)hdr, msg_len, 0);
    debugf("%s => %s (%zu byte)",
        ip_addr_ntop(&src, addr1, sizeof(addr1)), ip_addr_ntop(&dst, addr2, sizeof(addr2)), msg_len);
    icmp_dump((uint8_t *)hdr, msg_len);
    return ip_output(IP_PROTOCOL_ICMP, (uint8_t *)hdr, msg_len, src, dst);
}

int
icmp_init(void)
{
    ip_protocol_register("ICMP", IP_PROTOCOL_ICMP, icmp_input);
    return 0;
}
