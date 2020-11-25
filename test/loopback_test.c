#include <stdio.h>
#include <unistd.h>
#include <signal.h>

#include "loopback.h"
#include "net.h"
#include "util.h"

#include "test.h"

volatile sig_atomic_t terminate;

static struct test loopback_test = {0x0800, sizeof(test_data), test_data};

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
        net_device_transmit(dev, loopback_test.type, loopback_test.data, loopback_test.len, NULL);
        sleep(1);
    }
    return 0;
}
