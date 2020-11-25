#include <stdio.h>
#include <unistd.h>
#include <signal.h>

#include "loopback.h"
#include "net.h"
#include "ip.h"

#include "util.h"
#include "test.h"

volatile sig_atomic_t terminate;

static struct test ip_test = {0x0800, sizeof(test_data), test_data};

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

    setup();
    dev = loopback_init();
    if (!dev) {
        return -1;
    }
    if (dev->ops->open(dev) == -1) {
        return -1;
    }
    while (!terminate) {
        net_device_transmit(dev, ip_test.type, ip_test.data, ip_test.len, NULL);
        sleep(1);
    }
    net_shutdown();
    return 0;
}
