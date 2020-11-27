#include <stdio.h>
#include <unistd.h>
#include <signal.h>

#include "loopback.h"
#include "net.h"
#include "ip.h"

#include "util.h"
#include "test.h"

volatile sig_atomic_t terminate;

static struct test ip_test = {0x0800, sizeof(test_data1), test_data1};

static void
on_signal (int s)
{
    (void)s;
    terminate = 1;
}

static void
setup(void)
{
    signal(SIGINT, on_signal);
    net_init();
    ip_init();
}

int
main(void)
{
    struct net_device *dev;
    struct ip_iface *iface;

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
    while (!terminate) {
        net_device_output(dev, ip_test.type, ip_test.data, ip_test.len, NULL);
        sleep(1);
    }
    net_shutdown();
    return 0;
}
