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
    ip_addr_t dst;

    if (setup() == -1) {
        return -1;
    }
    ip_addr_pton("127.0.0.1", &dst);
    while (!terminate) {
        ip_output(ip_test.type, ip_test.data, ip_test.len, IP_ADDR_ANY, dst);
        sleep(1);
    }
    net_shutdown();
    return 0;
}
