# uinput-proxy

A userspace input device proxy for rootless containers.

## What it does

Lets unprivileged processes create and consume virtual input devices without access to `/dev/uinput` or real `/dev/input/event*` nodes. Steam and games see a normal Linux evdev/uinput API while the container has no elevated privileges or device pass-through.

## Components

### `uinput-daemon`

A privileged daemon (`daemon.c`, `daemon-helpers.c`) that:

- Listens on a Unix socket at `/tmp/uinput-proxy.sock`
- Manages up to 8 virtual device slots with full capability state (evbit, keybit, absbit, relbit, ffbit, mscbit, swbit, ledbit, sndbit, propbit)
- Creates real `mknod` device stubs at `/dev/input/eventN` so that directory enumeration works
- Owns a shared-memory ring buffer (memfd) per device for zero-copy event broadcast to readers
- Tracks live device state (key/LED/switch positions, absinfo values) for `EVIOCGKEY`/`EVIOCGLED`/`EVIOCGSW` queries
- Writes synthetic udev database entries (`/run/udev/data/c13:*`) with auto-detected device type (gamepad, joystick, mouse, keyboard)
- Optionally sends `AF_NETLINK` kobject uevents (add/remove) when `UINPUT_EXTRA` is set
- Implements a 1-second heartbeat timer per device for liveness detection
- Applies a 2-second cooldown on device slots after destruction to prevent reuse races
- Handles graceful shutdown on SIGTERM/SIGINT, cleaning up all devices

### `uinput-preload.so`

An `LD_PRELOAD` library (`preload.c`, `preload-helpers.c`, `preload-intercepts.c`) that intercepts syscalls to transparently redirect input device access through the daemon.

Built in two variants:
- **Standard** (`uinput-preload.so`) — intercepts `open`, `close`, `read`, `write`, `ioctl`, `fcntl`, `opendir`/`readdir`/`closedir`, `stat`, `access`, `poll`
- **Extra** (`uinput-preload.extra.so`, with `-DUINPUT_EXTRA_INTERCEPTS`) — additionally intercepts `openat`/`openat64`, `dup`/`dup2`/`dup3`, `lstat`, `fstat`/`fstat64`/`__fxstat`/`__fxstat64`, `stat64`/`lstat64`/`__xstat`/`__lxstat`/`__xstat64`/`__lxstat64`, `faccessat`, `readlink`, `ppoll`, `select`/`pselect`, `epoll_ctl`/`epoll_wait`/`epoll_pwait`, `inotify_init`/`inotify_init1`/`inotify_add_watch`/`inotify_rm_watch`, `writev`, `splice`, `sendfile`/`sendfile64`, `pwrite`/`pwrite64`

Both variants are built for x86_64 and i686 (32-bit).

Self-disables when running inside the daemon process itself (detected via `prctl(PR_GET_NAME)`).

### `uinput-install`

A helper binary that appends the preload library to `/etc/ld.so.preload` using `$LIB` for automatic multilib resolution and prints the corresponding `LD_PRELOAD` export.

## How it works

### Writers (uinput)

A process opening `/dev/uinput` gets a Unix socket to the daemon. `ioctl()` and `write()` calls are serialized into messages (`MSG_IOCTL`, `MSG_WRITE`) and forwarded over the socket. The daemon maintains the full device state machine — capability setup via `UI_SET_*BIT`, device creation via `UI_DEV_SETUP`/`UI_DEV_CREATE` (or the legacy `uinput_user_dev` write path), and teardown via `UI_DEV_DESTROY`.

On creation, the daemon allocates a memfd-backed shared memory ring, creates a real device node via `mknod`, writes a udev database entry, and optionally emits netlink uevents.

### Readers (evdev)

A process opening `/dev/input/eventN` connects to the daemon, which sends back the device's shared-memory fd via `SCM_RIGHTS`. The preload library mmaps the ring read-only.

**Reads** consume events from the ring buffer using `packet_head` (the position after the last `SYN_REPORT`) to ensure only complete packets are delivered. Blocking reads use `futex(FUTEX_WAIT)` on the ring's `wake_seq` word with a 3-second timeout, falling back to heartbeat liveness checks. Ring overflow is detected and reported as `SYN_DROPPED`.

**Poll/ppoll** splits file descriptors into evdev (futex-based) and non-evdev (real `poll`) groups. Evdev readiness is checked via `packet_head`; when mixed with real fds, the implementation uses `futex_waitv` with 1ms time slices to multiplex. Stack-allocated arrays are used for up to 256 fds, with heap fallback beyond that.

**Epoll** is supported via a tracking table that records virtual fd registrations per epoll instance. `epoll_wait` converts tracked entries into a `poll` call through `intercept_poll`.

**Select/pselect** pass through to real implementations with logging for virtual fds.

Clock conversion is supported: readers can request `CLOCK_MONOTONIC` via `EVIOCSCLOCKID`, and events are re-stamped from the ring's `CLOCK_REALTIME` timestamps on delivery.

### Sysfs / udev

`stat`, `lstat`, `fstat`, `access`, `faccessat`, `opendir`, `readdir`, `readlink`, and `open` are intercepted for:

- `/dev/uinput` — stat as char device `10:223`
- `/dev/input/eventN` — stat as char device `13:(64+N)`
- `/sys/class/input/` — fake directory listing of `eventN` symlinks
- `/sys/class/input/eventN` — symlink target to `../../devices/virtual/input/inputN/eventN`
- `/sys/devices/virtual/input/` — fake directory listing of `inputN` directories
- `/sys/devices/virtual/input/inputN/` — fake directory with `name`, `id/`, `capabilities/`, `uevent`, `eventN/`
- `/sys/devices/virtual/input/inputN/eventN/` — fake directory with `dev`, `uevent`
- Attribute files (`name`, `id/bustype`, `id/vendor`, `id/product`, `id/version`, `capabilities/*`, `dev`, `uevent`) — served as memfd-backed read-only fds with kernel-format content
- `/proc/self/fd/N` — readlink returns the fake device path for virtual fds

The device info cache queries the daemon once per device and caches results for the process lifetime, invalidated on `/dev/input` directory opens.

Inotify watches on input-related paths are tracked and logged but passed through to real implementations.

### Force feedback

FF effect uploads (`EVIOCSFF`) and erases (`EVIOCRMFF`) from readers are proxied to the writer via `MSG_FF_REQUEST`. The daemon manages up to 16 FF effect slots per device, with effect IDs allocated in `int16_t` range to avoid collisions. The writer handles `UI_BEGIN_FF_UPLOAD`/`UI_END_FF_UPLOAD` and `UI_BEGIN_FF_ERASE`/`UI_END_FF_ERASE` as a real uinput driver would.

`EV_FF` trigger events from readers are forwarded to the writer via `MSG_EVDEV_WRITE`.

### Joystick API

The daemon handles legacy joystick ioctls (`JSIOCGNAME`, `JSIOCGAXES`, `JSIOCGBUTTONS`) for reader connections, deriving axis/button counts from the device capability bits.

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
| `MSG_DEVICE_INFO` | Client → Daemon | Query device metadata |
| `MSG_DEVICE_INFO_REPLY` | Daemon → Client | Full device info (for sysfs) |

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
