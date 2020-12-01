APPS = 

TEST = test/loopback_test \
       test/ip_test \
       test/ip_iface_test \
       test/ip_output_test \
       test/ip_route_test \
       test/ip_protocol_test \
       test/icmp_test \
       test/ether_test \
       test/arp_test \
       test/udp_test \
       test/udp_socket_test \

DRIVERS = loopback.o \
          ether.o \

OBJS = util.o \
       net.o \
       ip.o \
       icmp.o \
       arp.o \
       udp.o \

CFLAGS := $(CFLAGS) -g -W -Wall -Wno-unused-parameter -DDEBUG -I .

ifeq ($(shell uname),Linux)
       CFLAGS := $(CFLAGS) -pthread
       DRIVERS := $(DRIVERS) ether_tap_linux.o
endif

.SUFFIXES:
.SUFFIXES: .c .o

.PHONY: all clean

all: $(APPS) $(TEST)

$(APPS): % : %.o $(OBJS) $(DRIVERS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(TEST): % : %.o $(OBJS) $(DRIVERS) test/test.h
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(APPS) $(APPS:=.o) $(OBJS) $(DRIVERS) $(TEST) $(TEST:=.o)
