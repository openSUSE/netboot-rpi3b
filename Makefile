# SPDX-License: MIT
#
# Copyright (C) 2020 Petr Tesarik <ptesarik@suse.com>
#

CFLAGS=-O2 -Wall

LDFLAGS=
LIBS=-lpthread -lpcap

PROGRAMS=\
  netboot-rpi3b

OBJS=\
  netboot-rpi3b.o

%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<

all: $(PROGRAMS)

netboot-rpi3b: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(OBJS) $(PROGRAMS)
