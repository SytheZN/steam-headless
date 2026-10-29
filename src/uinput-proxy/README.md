# uinput-proxy

A userspace input device proxy for rootless containers.

## What it does

Lets unprivileged processes create and consume virtual input devices without access to `/dev/uinput` or real `/dev/input/event*` nodes. Steam and games see a normal Linux evdev/uinput API while the container has no elevated privileges or device pass-through.

## Components

### `uinput-daemon`

A privileged daemon (`daemon.c`, `daemon-helpers.c`, `daemon-ioctl.c`, `daemon-sysfs.c`) that:

- Listens on a Unix socket at `/tmp/uinput-proxy.sock`
- Manages up to 8 virtual device slots with full capability state (evbit, keybit, absbit, relbit, ffbit, mscbit, swbit, ledbit, sndbit, propbit)
- Creates real `mknod` device stubs at `/dev/input/eventN` so that directory enumeration works
- Owns a shared-memory ring buffer (memfd) per device for zero-copy event broadcast to readers, and a doorbell eventfd per reader that is readable while the reader has unread packets
- Timestamps each packet as the kernel does: the last valid writer timestamp in the packet, otherwise the time of the `SYN_REPORT`
- Tracks live device state (key/LED/switch positions, absinfo values) for `EVIOCGKEY`/`EVIOCGLED`/`EVIOCGSW` queries
- Writes synthetic udev database entries (`/run/udev/data/c13:*`) with auto-detected device type (gamepad, joystick, mouse, keyboard)
- Maintains a sysfs mirror of the virtual devices under `/tmp/uinput/sysfs`
- Optionally sends `AF_NETLINK` kobject uevents (add/remove) when `UINPUT_EXTRA` is set
- Applies a 2-second cooldown on device slots after destruction to prevent reuse races
- Handles graceful shutdown on SIGTERM/SIGINT, cleaning up all devices

### `uinput-preload.so`

An `LD_PRELOAD` library (`preload.c`, `preload-helpers.c`, `preload-sysfs.c`, `preload-intercept-*.c`) that intercepts syscalls to transparently redirect input device access through the daemon.

Built in two variants:
- **Standard** (`uinput-preload.so`) — intercepts `open`/`open64`/`openat`/`openat64` (and their fortified `__open_2`/`__open64_2`/`__openat_2`/`__openat64_2` forms), `close`, `read`, `write`, `ioctl`, `fcntl`, `dup`/`dup2`/`dup3`, `opendir`, `scandir`/`scandir64`, `fopen`/`fopen64`, `stat`/`lstat`/`stat64`/`lstat64`/`__xstat`/`__lxstat`/`__xstat64`/`__lxstat64`, `fstat`/`fstat64`/`__fxstat`/`__fxstat64`, `fstatat`/`fstatat64`/`__fxstatat`/`__fxstatat64`, `statx`, `fstatfs`/`fstatfs64`, `access`, `faccessat`, `readlink`/`readlinkat`/`__readlinkat_chk`, `realpath`/`__realpath_chk`, `poll`/`ppoll`, `select`/`pselect`, `epoll_ctl`/`epoll_wait`/`epoll_pwait`
- **Extra** (`uinput-preload.extra.so`, with `-DUINPUT_EXTRA_INTERCEPTS`) — additionally intercepts `inotify_init`/`inotify_init1`/`inotify_add_watch`/`inotify_rm_watch`, `writev`, `splice`, `sendfile`/`sendfile64`, `pwrite`/`pwrite64` for logging

Both variants are built for x86_64 and i686 (32-bit).

Self-disables when running inside the daemon process itself (detected via `prctl(PR_GET_NAME)`).

### `uinput-install`

A helper binary that appends the preload library to `/etc/ld.so.preload` using `$LIB` for automatic multilib resolution and prints the corresponding `LD_PRELOAD` and `UINPUT_PRELOAD` exports.

## How it works

### Writers (uinput)

A process opening `/dev/uinput` gets a Unix socket to the daemon. `ioctl()` and `write()` calls are serialized into messages (`MSG_IOCTL`, `MSG_WRITE`) and forwarded over the socket. The daemon maintains the full device state machine — capability setup via `UI_SET_*BIT`, device creation via `UI_DEV_SETUP`/`UI_DEV_CREATE` (or the legacy `uinput_user_dev` write path), and teardown via `UI_DEV_DESTROY`.

On creation, the daemon allocates a memfd-backed shared memory ring, writes a udev database entry, adds the device to the sysfs mirror, creates a real device node via `mknod`, and optionally emits netlink uevents.

### Readers (evdev)

A process opening `/dev/input/eventN` connects to the daemon, which sends back the device's shared-memory fd and the reader's doorbell eventfd via `SCM_RIGHTS`. The preload library mmaps the ring read-only. Opening a node that does not exist fails with `ENOENT` without contacting the daemon. Reader state is shared between `dup`ed fds.

**Reads** consume events from the ring buffer using `packet_head` (the position after the last `SYN_REPORT`) to ensure only complete packets are delivered. Error checks follow `evdev_read`'s order. Blocking reads use `futex(FUTEX_WAIT)` on the ring's `wake_seq` word with no timeout. Ring overflow is detected and reported as `SYN_DROPPED`. A reader whose daemon socket has hung up gets `ENODEV`.

**Poll/ppoll** and **select/pselect** become a single real `ppoll` in which each virtual evdev fd is replaced by its daemon socket (for hangup) and its doorbell (for readability).

**Epoll** registrations of virtual fds go into an inner epoll set, registered in the caller's epoll set, that watches each fd's doorbell, so `epoll_wait` sleeps in the kernel.

Clock conversion is supported: readers can request `CLOCK_MONOTONIC` via `EVIOCSCLOCKID`, and events are re-stamped from the ring's `CLOCK_REALTIME` timestamps on delivery.

### Sysfs / udev

The daemon maintains a real directory tree under `/tmp/uinput/sysfs` with kernel-format content for the virtual devices: `devices/virtual/input/inputN/` (with `eventN/`), `class/input/` links, `dev/char/13:N` links, and a `/proc/bus/input/devices` listing.

Path-based calls are redirected into the mirror for:

- `/sys/class/input/`
- `/sys/devices/virtual/input/`
- `/sys/dev/char/13:*`
- `/proc/bus/input/devices`

so host input devices are hidden. Relative lookups through directory fds are resolved via `/proc/self/fd/N`, `readlink`/`realpath` results are translated back to the system path, and `fstatfs` on a mirror fd reports `SYSFS_MAGIC` (or `PROC_SUPER_MAGIC`) so libudev accepts it.

Virtual fds are also intercepted for:

- `/dev/uinput` — stat as char device `10:223`
- `/dev/input/eventN` — fstat as char device `13:(64+N)`
- `/proc/self/fd/N` — readlink returns the device path for virtual fds

Inotify watches on input-related paths are passed through to real implementations, and tracked and logged in the extra variant.

### Force feedback

FF effect uploads (`EVIOCSFF`) and erases (`EVIOCRMFF`) from readers are proxied to the writer via `MSG_FF_REQUEST`. The daemon manages up to 16 FF effect slots per device, with effect IDs allocated in `int16_t` range to avoid collisions. The writer handles `UI_BEGIN_FF_UPLOAD`/`UI_END_FF_UPLOAD` and `UI_BEGIN_FF_ERASE`/`UI_END_FF_ERASE` as a real uinput driver would.

`EV_FF` trigger events from readers are forwarded to the writer via `MSG_EVDEV_WRITE`.

## Wire protocol

All messages use a 5-byte packed header (`type:u8`, `length:u32`) followed by a variable-length payload. Shared memory rings use 24-byte wire events (matching 64-bit `struct input_event`); 32-bit preload libraries convert between native 16-byte and wire 24-byte formats.

Message types:

| Type | Direction | Purpose |
|------|-----------|---------|
| `MSG_UINPUT_OPEN` | Client → Daemon | Register as uinput writer |
| `MSG_EVDEV_OPEN` | Client → Daemon | Register as evdev reader |
| `MSG_LIST_DEVICES` | Client → Daemon | Query device list |
| `MSG_IOCTL` | Client → Daemon | Forward ioctl |
| `MSG_WRITE` | Writer → Daemon | Forward input events |
| `MSG_FF_REQUEST` | Daemon → Writer | FF upload/erase from reader |
| `MSG_EVDEV_WRITE` | Reader → Daemon | EV_FF trigger events |
| `MSG_IOCTL_REPLY` | Daemon → Client | Ioctl response |
| `MSG_DEVICE_LIST_REPLY` | Daemon → Client | Device list response |
| `MSG_DEVICE_INFO` | Client → Daemon | Query device metadata (unused by the preload) |
| `MSG_DEVICE_INFO_REPLY` | Daemon → Client | Full device info |

## Environment variables

| Variable | Component | Description |
|----------|-----------|-------------|
| `UINPUT_DEBUG` | Daemon | `console` for stderr, or a file path for debug logging |
| `UINPUT_EXTRA` | Daemon | Set to any value to enable netlink uevent emission |
| `UINPUTLD_DEBUG` | Preload | `console` for stderr, or a file path for debug logging |

## Limits

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_DEVICES` | 8 | Maximum concurrent virtual devices |
| `MAX_READERS` | 16 | Maximum readers per device |
| `MAX_FF_EFFECTS` | 16 | Maximum FF effects per device |
| `EVDEV_RING_FRAMES` | 256 | Shared memory ring size (256 × 24 = 6144 bytes) |
| `VFD_MAX` | 4096 | Maximum tracked virtual file descriptors per process |
| `EPOLL_TRACK_MAX` | 64 | Maximum tracked epoll instances per process |
| `EPOLL_VFD_MAX` | 64 | Maximum virtual fds per epoll instance |
