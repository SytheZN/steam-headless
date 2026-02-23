CC     = gcc
CFLAGS = -Wall -Wextra -Wvla -O2 -fPIC -D_GNU_SOURCE

# Preload-specific: hidden visibility (only EXPORT symbols in dynsym),
# LTO for cross-TU inlining, gc-sections for dead code, no unwind tables.
CFLAGS_LIB  = $(CFLAGS) -fvisibility=hidden -flto -ffunction-sections \
              -fdata-sections -fno-asynchronous-unwind-tables
LDFLAGS_LIB = -shared -ldl -flto -Wl,--gc-sections -Wl,-O1 \
              -Wl,--as-needed -Wl,--exclude-libs,ALL -s

LDFLAGS_DAEMON =

PRELOAD_SRCS = preload.c preload-helpers.c \
               preload-intercept-open.c preload-intercept-io.c \
               preload-intercept-dir.c preload-intercept-stat.c \
               preload-intercept-poll.c
PRELOAD_HDRS = preload.h protocol.h

DAEMON_SRCS  = daemon.c daemon-helpers.c daemon-ioctl.c
DAEMON_HDRS  = daemon.h protocol.h

INSTALL_SRCS = uinput-install.c

EXTRA_CFLAGS = -DUINPUT_EXTRA_INTERCEPTS

all: uinput-preload.so uinput-preload.i686.so \
     uinput-preload.extra.so uinput-preload.extra.i686.so \
     uinput-daemon uinput-install

uinput-preload.so: $(PRELOAD_SRCS) $(PRELOAD_HDRS)
	$(CC) $(CFLAGS_LIB) $(LDFLAGS_LIB) -o $@ $(PRELOAD_SRCS)

uinput-preload.i686.so: $(PRELOAD_SRCS) $(PRELOAD_HDRS)
	$(CC) $(CFLAGS_LIB) -m32 $(LDFLAGS_LIB) -o $@ $(PRELOAD_SRCS)

uinput-preload.extra.so: $(PRELOAD_SRCS) $(PRELOAD_HDRS)
	$(CC) $(CFLAGS_LIB) $(EXTRA_CFLAGS) $(LDFLAGS_LIB) -o $@ $(PRELOAD_SRCS)

uinput-preload.extra.i686.so: $(PRELOAD_SRCS) $(PRELOAD_HDRS)
	$(CC) $(CFLAGS_LIB) $(EXTRA_CFLAGS) -m32 $(LDFLAGS_LIB) -o $@ $(PRELOAD_SRCS)

uinput-daemon: $(DAEMON_SRCS) $(DAEMON_HDRS)
	$(CC) $(CFLAGS) -o $@ $(DAEMON_SRCS) $(LDFLAGS_DAEMON)

uinput-install: $(INSTALL_SRCS)
	$(CC) $(CFLAGS) -o $@ $(INSTALL_SRCS)

dist: all
	mkdir -p dist/uinput/lib64 dist/uinput/lib
	cp uinput-preload.so       dist/uinput/lib64/uinput.so
	cp uinput-preload.extra.so dist/uinput/lib64/uinput.extra.so
	cp uinput-preload.i686.so       dist/uinput/lib/uinput.so
	cp uinput-preload.extra.i686.so dist/uinput/lib/uinput.extra.so

clean:
	rm -f uinput-preload.so uinput-preload.i686.so \
	     uinput-preload.extra.so uinput-preload.extra.i686.so \
	     uinput-daemon uinput-install
	rm -rf dist

.PHONY: all dist clean
