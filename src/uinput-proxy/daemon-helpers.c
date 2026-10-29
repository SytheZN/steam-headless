#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <sys/eventfd.h>
#include <linux/netlink.h>
#include <linux/futex.h>
#include <limits.h>

#include "daemon.h"

/* ------------------------------------------------------------------ */
/* Wire I/O                                                           */
/* ------------------------------------------------------------------ */

int send_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return -1;
        }
        p   += n;
        len -= n;
    }
    return 0;
}

int recv_all(int fd, void *buf, size_t len) {
    uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return -1;
        }
        p   += n;
        len -= n;
    }
    return 0;
}

int send_msg(int fd, msg_type_t type, const void *payload, uint32_t plen) {
    struct msg_header hdr = { .type = (uint8_t)type, .length = plen };
    if (send_all(fd, &hdr, sizeof(hdr)) < 0) return -1;
    if (plen > 0 && send_all(fd, payload, plen) < 0) return -1;
    return 0;
}


int recv_msg(int fd, void *buf, size_t bufsz, uint32_t *payload_len) {
    struct msg_header hdr;
    if (recv_all(fd, &hdr, sizeof(hdr)) < 0) return -1;
    if (hdr.length > bufsz) {
        logmsg("recv_msg: payload too large (%u > %zu)", hdr.length, bufsz);
        return -1;
    }
    *payload_len = hdr.length;
    if (hdr.length > 0 && recv_all(fd, buf, hdr.length) < 0) return -1;
    return (int)hdr.type;
}

/* ------------------------------------------------------------------ */
/* Reply helpers                                                      */
/* ------------------------------------------------------------------ */

void send_ioctl_reply(int fd, int32_t ret, int32_t err,
                      const void *data, uint32_t dlen) {
    struct msg_ioctl_reply r = { .ret = ret, .err = err };
    size_t total = sizeof(r) + dlen;
    uint8_t *buf = malloc(total);
    if (!buf) return;
    memcpy(buf, &r, sizeof(r));
    if (dlen > 0 && data) memcpy(buf + sizeof(r), data, dlen);
    send_msg(fd, MSG_IOCTL_REPLY, buf, (uint32_t)total);
    free(buf);
}

/* ------------------------------------------------------------------ */
/* Device slot management                                             */
/* ------------------------------------------------------------------ */

static bool stub_exists(int device_num) {
    char path[64];
    snprintf(path, sizeof(path), "/dev/input/event%d", device_num);
    return access(path, F_OK) == 0;
}

/* Create the character device node for the device's allocated number. Returns 0 on success, -1 on failure. */
int device_create_stub(struct virtual_device *dev) {
    char path[64];
    snprintf(path, sizeof(path), "/dev/input/event%d", dev->device_num);
    dev_t rdev = makedev(INPUT_MAJOR, EVDEV_MINOR(dev->device_num));
    if (mknod(path, S_IFCHR | 0666, rdev) == 0) {
        if (chmod(path, 0666) < 0)
            dlog("chmod failed for %s: %s", path, strerror(errno));
        if (chown(path, CONTAINER_UID, CONTAINER_GID) < 0)
            dlog("chown failed for %s: %s", path, strerror(errno));
        return 0;
    }
    /* EEXIST means device already exists (real kernel device or our old stub) */
    return -1;
}

/* Create shared memory ring for device. Returns 0 on success, -1 on failure. */
int device_create_shmem(struct virtual_device *dev) {
    int sfd = memfd_create("evdev-shmem", MFD_CLOEXEC);
    if (sfd < 0) {
        logmsg("memfd_create: %s", strerror(errno));
        return -1;
    }
    if (ftruncate(sfd, sizeof(struct evdev_shmem)) < 0) {
        logmsg("ftruncate: %s", strerror(errno));
        close(sfd);
        return -1;
    }
    struct evdev_shmem *shm = mmap(NULL, sizeof(struct evdev_shmem),
                                   PROT_READ | PROT_WRITE, MAP_SHARED, sfd, 0);
    if (shm == MAP_FAILED) {
        logmsg("mmap: %s", strerror(errno));
        close(sfd);
        return -1;
    }
    atomic_store_explicit(&shm->write_pos,  0, memory_order_relaxed);
    atomic_store_explicit(&shm->packet_head, 0, memory_order_relaxed);
    atomic_store_explicit(&shm->wake_seq,   0, memory_order_relaxed);
    dev->shmem_fd = sfd;
    dev->shmem    = shm;
    return 0;
}

/* Find free device number and create device node. Returns 0 on success, -1 on failure. */
int device_allocate_number(struct virtual_device *dev) {
    for (int n = 0; n < MAX_DEVICE_NUM; n++) {
        if (!stub_exists(n) && find_slot_by_num(n) < 0) {
            dev->device_num = n;
            return 0;
        }
    }
    logmsg("no free device numbers available");
    return -1;
}

struct virtual_device *alloc_device(void) {
    time_t now = time(NULL);
    for (int i = 0; i < MAX_DEVICES; i++) {
        if (!devices[i].active && now >= devices[i].cooldown_until) {
            memset(&devices[i], 0, sizeof(devices[i]));
            devices[i].active     = true;
            devices[i].id         = i;
            devices[i].ff_next_id = 1;
            devices[i].writer_fd  = -1;
            devices[i].shmem_fd   = -1;
            devices[i].shmem      = NULL;
            for (int r = 0; r < MAX_READERS; r++) {
                devices[i].reader_fds[r]       = -1;
                devices[i].reader_doorbells[r] = -1;
            }

            /* Device number and shmem assigned later in UI_DEV_CREATE */
            devices[i].device_num = -1;

            return &devices[i];
        }
    }
    return NULL;
}

struct virtual_device *find_device_by_id(int id) {
    if (id >= 0 && id < MAX_DEVICES && devices[id].active)
        return &devices[id];
    return NULL;
}

int find_slot_by_num(int device_num) {
    for (int i = 0; i < MAX_DEVICES; i++) {
        if (devices[i].active && devices[i].device_num == device_num)
            return i;
    }
    return -1;
}

static void reader_slot_close(struct virtual_device *dev, int r) {
    if (dev->reader_fds[r] >= 0) {
        shutdown(dev->reader_fds[r], SHUT_RDWR);
        dev->reader_fds[r] = -1;
    }
    if (dev->reader_doorbells[r] >= 0) {
        close(dev->reader_doorbells[r]);
        dev->reader_doorbells[r] = -1;
    }
}

void device_ring_doorbells(struct virtual_device *dev) {
    for (int r = 0; r < MAX_READERS; r++) {
        if (dev->reader_doorbells[r] >= 0)
            eventfd_write(dev->reader_doorbells[r], 1);
    }
}

#define NSEC_PER_SEC  1000000000LL
#define NSEC_PER_USEC 1000LL

static int64_t clock_now_ns(clockid_t clock) {
    struct timespec ts;
    clock_gettime(clock, &ts);
    return (int64_t)ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
}

void device_note_event_time(struct virtual_device *dev, const struct input_event *ev) {
    int64_t t = (int64_t)ev->input_event_sec * NSEC_PER_SEC + (int64_t)ev->input_event_usec * NSEC_PER_USEC;
    if (t <= 0) return;
    int64_t now = clock_now_ns(CLOCK_MONOTONIC);
    if (t < now - UINPUT_TIMESTAMP_ALLOWED_OFFSET_SECS * NSEC_PER_SEC || t > now) return;
    dev->packet_time_mono_ns = t;
}

void device_seal_packet(struct virtual_device *dev, uint64_t end) {
    struct evdev_shmem *shm = dev->shmem;
    int64_t mono_now = clock_now_ns(CLOCK_MONOTONIC);
    int64_t real_now = clock_now_ns(CLOCK_REALTIME);
    int64_t mono = dev->packet_time_mono_ns ? dev->packet_time_mono_ns : mono_now;
    int64_t real = mono + (real_now - mono_now);
    dev->packet_time_mono_ns = 0;

    uint64_t start = atomic_load_explicit(&shm->packet_head, memory_order_relaxed);
    if (end - start > EVDEV_RING_FRAMES) start = end - EVDEV_RING_FRAMES;
    for (uint64_t pos = start; pos < end; pos++) {
        struct input_event ev;
        uint8_t *frame = shm->buf + FRAME_RING_BYTE(pos);
        memcpy(&ev, frame, sizeof(ev));
        ev.input_event_sec  = real / NSEC_PER_SEC;
        ev.input_event_usec = (real % NSEC_PER_SEC) / NSEC_PER_USEC;
        memcpy(frame, &ev, sizeof(ev));
    }

    atomic_store_explicit(&shm->write_pos, end, memory_order_release);
    atomic_store_explicit(&shm->packet_head, end, memory_order_release);
}

void device_destroy(struct virtual_device *dev) {
    if (!dev->active) return;
    logmsg("destroying device %d (%s)", dev->id, dev->name);

    /* Auto-complete any pending packet with SYN_REPORT */
    if (dev->shmem && dev->reader_count > 0) {
        uint64_t write_pos = atomic_load_explicit(&dev->shmem->write_pos, memory_order_relaxed);
        uint64_t packet_head = atomic_load_explicit(&dev->shmem->packet_head, memory_order_relaxed);

        if (write_pos != packet_head) {
            /* Incomplete packet - complete it with a SYN_REPORT */
            struct input_event sync_ev = {
                .type = EV_SYN,
                .code = SYN_REPORT,
                .value = 0
            };

            memcpy(dev->shmem->buf + FRAME_RING_BYTE(write_pos), &sync_ev, sizeof(sync_ev));
            device_seal_packet(dev, write_pos + 1);
            atomic_fetch_add_explicit(&dev->shmem->wake_seq, 1, memory_order_release);
            syscall(SYS_futex, &dev->shmem->wake_seq, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);

            dlog("device %d: auto-completed packet on destroy", dev->id);
        }
    }

    if (dev->created) {
        /* Kernel sends child eventN remove first, then parent inputN */
        send_uevent("remove", dev->device_num);
        send_uevent_input("remove", dev->device_num);
        device_remove_stub(dev);
        device_remove_udev_db(dev);
        sysfs_mirror_remove(dev);
    }
    for (int r = 0; r < MAX_READERS; r++)
        reader_slot_close(dev, r);
    dev->reader_count = 0;
    if (dev->shmem) {
        /* Wake blocked readers only after their sockets are shut down, so a woken
         * reader observes the hang-up and returns ENODEV instead of waiting again. */
        atomic_fetch_add_explicit(&dev->shmem->wake_seq, 1, memory_order_release);
        syscall(SYS_futex, &dev->shmem->wake_seq, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
        munmap(dev->shmem, sizeof(struct evdev_shmem));
        dev->shmem = NULL;
    }
    if (dev->shmem_fd >= 0) { close(dev->shmem_fd); dev->shmem_fd = -1; }
    dev->cooldown_until = time(NULL) + SLOT_COOLDOWN_SEC;
    dev->active = false;
}

/* ------------------------------------------------------------------ */
/* Stub / udev / uevent helpers                                       */
/* ------------------------------------------------------------------ */

void init_netlink(void) {
    netlink_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT);
    if (netlink_fd < 0)
        logmsg("warning: netlink socket: %s (uevents disabled)", strerror(errno));
    else
        dlog("netlink socket opened (fd=%d)", netlink_fd);
}

/* Null-terminated string append for uevent buffers. Each field is followed
 * by a NUL byte (uevent wire format). */
#define UEVENT_APPEND(buf, pos, bufsz, fmt, ...) do { \
    int _n = snprintf((buf) + (pos), (bufsz) - (pos), fmt, ##__VA_ARGS__); \
    if (_n > 0 && (pos) + (size_t)_n + 1 < (bufsz)) (pos) += (size_t)_n + 1; \
} while (0)

static void send_uevent_raw(const char *devpath, const char *action,
                             const char *extra_kvs[], int nextra,
                             const char *label) {
    if (netlink_fd < 0) return;

    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = 1;

    char buf[512];
    size_t pos = 0;

    UEVENT_APPEND(buf, pos, sizeof(buf), "%s@%s", action, devpath);
    UEVENT_APPEND(buf, pos, sizeof(buf), "ACTION=%s", action);
    UEVENT_APPEND(buf, pos, sizeof(buf), "DEVPATH=%s", devpath);
    UEVENT_APPEND(buf, pos, sizeof(buf), "SUBSYSTEM=input");
    for (int i = 0; i < nextra; i++)
        UEVENT_APPEND(buf, pos, sizeof(buf), "%s", extra_kvs[i]);

    struct iovec iov = { .iov_base = buf, .iov_len = pos };
    struct msghdr msg = {
        .msg_name    = &addr,
        .msg_namelen = sizeof(addr),
        .msg_iov     = &iov,
        .msg_iovlen  = 1,
    };

    if (sendmsg(netlink_fd, &msg, 0) < 0)
        dlog("%s: sendmsg: %s (Missing NET_ADMIN?)", label, strerror(errno));
    else
        dlog("%s: sent %s for %s", label, action, devpath);
}

#undef UEVENT_APPEND

void send_uevent(const char *action, int dev_id) {
    char devpath[128], major_kv[32], minor_kv[32], devname_kv[64];
    snprintf(devpath,    sizeof(devpath),    "/devices/virtual/input/input%d/event%d", dev_id, dev_id);
    snprintf(major_kv,   sizeof(major_kv),   "MAJOR=%d", INPUT_MAJOR);
    snprintf(minor_kv,   sizeof(minor_kv),   "MINOR=%d", EVDEV_MINOR(dev_id));
    snprintf(devname_kv, sizeof(devname_kv), "DEVNAME=input/event%d", dev_id);
    const char *kvs[] = { major_kv, minor_kv, devname_kv };
    send_uevent_raw(devpath, action, kvs, 3, "send_uevent");
}

void send_uevent_input(const char *action, int dev_id) {
    char devpath[128];
    snprintf(devpath, sizeof(devpath), "/devices/virtual/input/input%d", dev_id);
    const char *kvs[] = { "NAME=" };
    send_uevent_raw(devpath, action, kvs, 1, "send_uevent_input");
}

void device_remove_stub(struct virtual_device *dev) {
    char path[64];
    snprintf(path, sizeof(path), "/dev/input/event%d", dev->device_num);
    unlink(path);
}

void device_write_udev_db(struct virtual_device *dev) {
    if (mkdir("/run/udev", 0755) < 0 && errno != EEXIST)
        dlog("mkdir /run/udev: %s", strerror(errno));
    if (mkdir("/run/udev/data", 0755) < 0 && errno != EEXIST)
        dlog("mkdir /run/udev/data: %s", strerror(errno));

    char path[64];
    snprintf(path, sizeof(path), "/run/udev/data/c%d:%d", INPUT_MAJOR, EVDEV_MINOR(dev->device_num));

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        logmsg("warning: could not write udev db %s: %s", path, strerror(errno));
        return;
    }

    dprintf(fd, "E:ID_INPUT=1\n");

    /* Derive device type from capability bits rather than hardcoding gamepad. */
    bool has_ev_key = bit_test(dev->evbit, EV_KEY);
    bool has_ev_abs = bit_test(dev->evbit, EV_ABS);
    bool has_ev_rel = bit_test(dev->evbit, EV_REL);

    /* BTN_JOYSTICK = 0x120..0x12F, BTN_GAMEPAD = 0x130..0x13E */
    bool has_joystick_btn = false, has_gamepad_btn = false;
    for (int k = BTN_JOYSTICK; k < BTN_GAMEPAD; k++)
        if (bit_test(dev->keybit, k)) { has_joystick_btn = true; break; }
    for (int k = BTN_GAMEPAD; k < BTN_GAMEPAD + 0x10; k++)
        if (bit_test(dev->keybit, k)) { has_gamepad_btn = true; break; }

    if (has_ev_key && has_ev_abs && (has_joystick_btn || has_gamepad_btn)) {
        if (has_gamepad_btn) dprintf(fd, "E:ID_INPUT_GAMEPAD=1\n");
        dprintf(fd, "E:ID_INPUT_JOYSTICK=1\n");
    } else if (has_ev_key && has_ev_rel && bit_test(dev->keybit, BTN_MOUSE)) {
        dprintf(fd, "E:ID_INPUT_MOUSE=1\n");
    } else if (has_ev_key) {
        dprintf(fd, "E:ID_INPUT_KEY=1\n");
        dprintf(fd, "E:ID_INPUT_KEYBOARD=1\n");
    }

    dprintf(fd, "E:DEVNAME=input/event%d\n", dev->device_num);

    close(fd);
    logmsg("wrote udev db %s", path);
}

void device_remove_udev_db(struct virtual_device *dev) {
    char path[64];
    snprintf(path, sizeof(path), "/run/udev/data/c%d:%d", INPUT_MAJOR, EVDEV_MINOR(dev->device_num));
    unlink(path);
}

/* ------------------------------------------------------------------ */
/* Client management                                                  */
/* ------------------------------------------------------------------ */

struct client *alloc_client(int fd) {
    for (int i = 0; i < MAX_FDS; i++) {
        if (!clients[i].active) {
            clients[i].active    = true;
            clients[i].fd        = fd;
            clients[i].type      = CONN_UNKNOWN;
            clients[i].device_id = -1;
            return &clients[i];
        }
    }
    return NULL;
}

void remove_client(int fd) {
    for (int i = 0; i < MAX_FDS; i++) {
        if (clients[i].active && clients[i].fd == fd) {
            clients[i].active = false;
            return;
        }
    }
}

void remove_reader_from_device(struct virtual_device *dev, int fd) {
    for (int i = 0; i < MAX_READERS; i++) {
        if (dev->reader_fds[i] == fd) {
            reader_slot_close(dev, i);
            dev->reader_count--;
            return;
        }
    }
}

int add_reader_to_device(struct virtual_device *dev, int fd) {
    for (int i = 0; i < MAX_READERS; i++) {
        if (dev->reader_fds[i] == fd) return i;
    }
    for (int i = 0; i < MAX_READERS; i++) {
        if (dev->reader_fds[i] < 0) {
            int doorbell = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
            if (doorbell < 0) {
                logmsg("eventfd: %s", strerror(errno));
                return -1;
            }
            dev->reader_fds[i]       = fd;
            dev->reader_doorbells[i] = doorbell;
            dev->reader_count++;
            return i;
        }
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* SCM_RIGHTS helper                                                  */
/* ------------------------------------------------------------------ */

int send_fds(int sock, int *fds, int nfds) {
    assert(nfds >= 1 && nfds <= EVDEV_OPEN_FD_COUNT);
    char cmsgbuf[CMSG_SPACE(sizeof(int) * EVDEV_OPEN_FD_COUNT)];
    struct iovec  iov  = { .iov_base = "",  .iov_len = 1 };
    struct msghdr msg  = {
        .msg_iov        = &iov,
        .msg_iovlen     = 1,
        .msg_control    = cmsgbuf,
        .msg_controllen = CMSG_SPACE(sizeof(int) * nfds),
    };
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type  = SCM_RIGHTS;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(int) * nfds);
    memcpy(CMSG_DATA(cmsg), fds, sizeof(int) * nfds);
    return sendmsg(sock, &msg, MSG_NOSIGNAL) < 0 ? -1 : 0;
}

/* ------------------------------------------------------------------ */
/* Device list / info replies                                         */
/* ------------------------------------------------------------------ */

void send_device_list(int fd) {
    int count = 0;
    for (int i = 0; i < MAX_DEVICES; i++)
        if (devices[i].active && devices[i].created) count++;

    size_t sz = sizeof(struct msg_device_list_reply) + count * sizeof(struct device_entry);
    uint8_t *buf = calloc(1, sz);
    if (!buf) return;
    struct msg_device_list_reply *r = (struct msg_device_list_reply *)buf;
    r->count = (uint32_t)count;
    struct device_entry *e = (struct device_entry *)(buf + sizeof(*r));
    for (int i = 0; i < MAX_DEVICES; i++) {
        if (devices[i].active && devices[i].created) {
            e->id = (uint32_t)devices[i].device_num;
            strncpy(e->name, devices[i].name, UINPUT_MAX_NAME_SIZE - 1);
            e++;
        }
    }
    send_msg(fd, MSG_DEVICE_LIST_REPLY, buf, (uint32_t)sz);
    free(buf);
}

void send_device_info(int fd, uint32_t device_id) {
    struct device_info info;
    memset(&info, 0, sizeof(info));

    int slot = find_slot_by_num((int)device_id);
    struct virtual_device *dev = (slot >= 0) ? &devices[slot] : NULL;
    if (dev) {
        info.id      = (uint32_t)dev->device_num;
        info.created = dev->created;
        memcpy(info.name,    dev->name,    UINPUT_MAX_NAME_SIZE);
        info.input_id = dev->input_id;
        memcpy(info.evbit,   dev->evbit,   EVBIT_SIZE);
        memcpy(info.keybit,  dev->keybit,  KEYBIT_SIZE);
        memcpy(info.absbit,  dev->absbit,  ABSBIT_SIZE);
        memcpy(info.relbit,  dev->relbit,  RELBIT_SIZE);
        memcpy(info.ffbit,   dev->ffbit,   FFBIT_SIZE);
        memcpy(info.mscbit,  dev->mscbit,  MSCBIT_SIZE);
        memcpy(info.swbit,   dev->swbit,   SWBIT_SIZE);
        memcpy(info.ledbit,  dev->ledbit,  LEDBIT_SIZE);
        memcpy(info.sndbit,  dev->sndbit,  SNDBIT_SIZE);
        memcpy(info.propbit, dev->propbit, PROPBIT_SIZE);
    }
    send_msg(fd, MSG_DEVICE_INFO_REPLY, &info, sizeof(info));
}
