#include <stdio.h>
#include <unistd.h>
#include <signal.h>

#include "loopback.h"
#include "net.h"
#include "ip.h"

#include "util.h"
#include "test.h"

volatile sig_atomic_t terminate;

static struct test ip_test = {17, sizeof(test_data2), test_data2};

static void
on_signal (int s)
{
    (void)s;
    terminate = 1;
}

static void
dummy_func(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst)
{
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];

    debugf("%s => %s (%zd bytes data)", ip_addr_ntop(&src, addr1, sizeof(addr1)), ip_addr_ntop(&src, addr2, sizeof(addr2)), len);
    debugdump(data, len);
}

static int
setup(void)
{
    struct net_device *dev;
    struct ip_iface *iface;

    signal(SIGINT, on_signal);
    if (net_init() == -1) {
        return -1;
    }
    if (ip_init() == -1) {
        return -1;
    }
    ip_protocol_register("UDP", 17, dummy_func);
    dev = loopback_init();
    if (!dev) {
        return -1;
    }
    iface = ip_iface_alloc("127.0.0.1", "255.0.0.0");
    if (!iface) {
        return -1;
    }
    if (ip_iface_register(dev, iface) == -1) {
        return -1;
    }
    if (dev->ops->open(dev) == -1) {
        return -1;
    }
    net_run();
    return 0;
}

int
main(void)
{
    ip_addr_t addr;

    if (setup() == -1) {
        return -1;
    }
    ip_addr_pton("127.0.0.1", &addr);
    while (!terminate) {
        ip_output(ip_test.type, ip_test.data, ip_test.len, addr, addr);
        sleep(1);
    }
    net_shutdown();
    return 0;
}
