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
dummy_func(struct ip_iface *iface, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst)
{
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];

    debugf("<%s> %s => %s (%zd bytes data)", NET_IFACE(iface)->dev->name, ip_addr_ntop(&src, addr1, sizeof(addr1)), ip_addr_ntop(&src, addr2, sizeof(addr2)), len);
    debugdump(data, len);
}

static void
setup(void)
{
    signal(SIGINT, on_signal);
    net_init();
    ip_init();
    ip_protocol_register("UDP", 17, dummy_func);
}

int
main(void)
{
    struct net_device *dev;
    struct ip_iface *iface;
    ip_addr_t dst;

    setup();
    dev = loopback_init();
    if (!dev) {
        return -1;
    }
    if (dev->ops->open(dev) == -1) {
        return -1;
    }
    iface = ip_iface_alloc("127.0.0.1", "255.0.0.0");
    if (!iface) {
        return -1;
    }
    ip_iface_register(dev, iface);
    ip_addr_pton("127.0.0.1", &dst);
    while (!terminate) {
        ip_output(iface, ip_test.type, ip_test.data, ip_test.len, dst);
        sleep(1);
    }
    net_shutdown();
    return 0;
}
