CC     = gcc
CFLAGS = -Wall -Wextra -Wvla -O2 -D_GNU_SOURCE $(shell pkg-config --cflags libpipewire-0.3)

LDLIBS = -lsystemd $(shell pkg-config --libs libpipewire-0.3) -lxcb -lxcb-xinput

SOURCES = fake-systemd.c networkmanager.c login1.c pipewire-wake.c x11-wake.c

all: fake-systemd settz

fake-systemd: $(SOURCES) fake-systemd.h
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LDLIBS)

settz: settz.c
	$(CC) $(CFLAGS) -o $@ settz.c

clean:
	rm -f fake-systemd settz

.PHONY: all clean
