#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <linux/uinput.h>

#include "preload.h"

static const char *vfd_type_name(int fd) {
    switch (vfd_table[fd].type) {
        case VFD_UINPUT: return "uinput";
        case VFD_EVDEV:  return "evdev";
        case VFD_SYSFS:  return "sysfs";
        default:         return "?";
    }
}

/* ------------------------------------------------------------------ */
/* ioctl                                                              */
/* ------------------------------------------------------------------ */

bool should_intercept_ioctl(int fd) {
    return vfd_is_active(fd) && vfd_table[fd].type != VFD_SYSFS;
}

int intercept_ioctl(int fd, unsigned long cmd, void *arg) {
    dbg("ioctl: fd=%d cmd=0x%08lx type=%s dev=%d", fd, cmd,
        vfd_type_name(fd), vfd_table[fd].device_id);

    /* EVIOCSCLOCKID: per-reader clock selection, no daemon round-trip needed */
    if (cmd == EVIOCSCLOCKID && vfd_table[fd].type == VFD_EVDEV) {
        if (!arg) { errno = EFAULT; return -1; }
        uint32_t clkid = *(const uint32_t *)arg;
        if (clkid != CLOCK_REALTIME && clkid != CLOCK_MONOTONIC) {
            errno = EINVAL;
            return -1;
        }
        vfd_table[fd].clock_type = clkid;
        return 0;
    }

    size_t arg_size = _IOC_SIZE(cmd);
    void *data_ptr  = NULL;
    uint8_t scalar_buf[sizeof(uintptr_t)] = {0};
    uint8_t phys_buf[UINPUT_MAX_NAME_SIZE] = {0};

    if (arg_size > 0 && (_IOC_DIR(cmd) & (_IOC_WRITE | _IOC_READ))) {
        if (cmd == UI_SET_PHYS) {
            /* UI_SET_PHYS passes a const char* (pointer to string).
             * _IOC_SIZE is sizeof(char*), so we must dereference to get the
             * actual string content for the daemon. */
            if (arg) {
                const char *phys = (const char *)arg;
                size_t n = strnlen(phys, UINPUT_MAX_NAME_SIZE - 1);
                memcpy(phys_buf, phys, n);
            }
            arg_size = UINPUT_MAX_NAME_SIZE;
            data_ptr = phys_buf;
        } else if ((_IOC_DIR(cmd) & _IOC_WRITE) && arg_size <= sizeof(uintptr_t)) {
            /* Write-only ioctls like UI_SET_EVBIT pass the value directly
             * in the arg pointer rather than as a pointer-to-value. */
            uintptr_t val = (uintptr_t)arg;
            memcpy(scalar_buf, &val, arg_size);
            data_ptr = scalar_buf;
        } else {
            data_ptr = arg;
        }
    }

    size_t plen = sizeof(struct msg_ioctl) + arg_size;
    uint8_t *sendbuf = malloc(plen);
    if (!sendbuf) { errno = ENOMEM; return -1; }
    struct msg_ioctl *m = (struct msg_ioctl *)sendbuf;
    m->cmd = (uint32_t)cmd;
    if (arg_size > 0 && data_ptr)
        memcpy(sendbuf + sizeof(*m), data_ptr, arg_size);
    else
        memset(sendbuf + sizeof(*m), 0, arg_size);

    send_msg_r(fd, MSG_IOCTL, sendbuf, (uint32_t)plen);
    free(sendbuf);

    uint8_t replybuf[4096];
    uint32_t rplen = 0;
    int type = recv_msg_r(fd, replybuf, sizeof(replybuf), &rplen);
    if (type != MSG_IOCTL_REPLY || rplen < sizeof(struct msg_ioctl_reply)) {
        errno = EIO; return -1;
    }
    struct msg_ioctl_reply *r = (struct msg_ioctl_reply *)replybuf;
    if (r->ret < 0) {
        errno = r->err ? r->err : EIO;
        return -1;
    }

    size_t reply_data_len = rplen - sizeof(*r);
    if (reply_data_len > 0 && arg && (_IOC_DIR(cmd) & _IOC_READ)) {
        size_t copy = reply_data_len < _IOC_SIZE(cmd) ? reply_data_len : _IOC_SIZE(cmd);
        if (copy > 0) memcpy(arg, replybuf + sizeof(*r), copy);
    }

    if (cmd == UI_DEV_CREATE && vfd_table[fd].type == VFD_UINPUT)
        vfd_table[fd].created = true;
    if (cmd == UI_DEV_DESTROY && vfd_table[fd].type == VFD_UINPUT)
        vfd_table[fd].created = false;

    /* EVIOCGKEY/LED/SW: flush buffered events to keep state consistent.
     * The kernel does a per-type flush; we advance to packet_head as a
     * safe approximation. */
    if (vfd_is_active(fd) && vfd_table[fd].type == VFD_EVDEV &&
            vfd_table[fd].shmem && r->ret >= 0 &&
            _IOC_TYPE(cmd) == 'E' && (
                _IOC_NR(cmd) == _IOC_NR(EVIOCGKEY(0)) ||
                _IOC_NR(cmd) == _IOC_NR(EVIOCGLED(0)) ||
                _IOC_NR(cmd) == _IOC_NR(EVIOCGSW(0)))) {
        uint64_t ph = atomic_load_explicit(&vfd_table[fd].shmem->packet_head,
                                           memory_order_acquire);
        vfd_table[fd].read_pos = ph;
    }

    return (int)r->ret;
}

/* ------------------------------------------------------------------ */
/* read                                                               */
/* ------------------------------------------------------------------ */

bool should_intercept_read(int fd) {
    return vfd_is_active(fd) && vfd_table[fd].type != VFD_SYSFS;
}

ssize_t intercept_read(int fd, void *buf, size_t count) {
    dbg("read: fd=%d count=%zu type=%s dev=%d", fd, count,
        vfd_type_name(fd), vfd_table[fd].device_id);
    struct virtual_fd *vf = &vfd_table[fd];

    if (vf->type == VFD_EVDEV) {
        for (;;) {
            uint64_t write_pos = atomic_load_explicit(&vf->shmem->write_pos,
                                                       memory_order_acquire);
            if (write_pos - vf->read_pos > EVDEV_RING_FRAMES) {
                /* Overflow: daemon lapped us. Skip to newest packet. */
                uint64_t packet_head = atomic_load_explicit(&vf->shmem->packet_head,
                                                             memory_order_acquire);
                uint64_t oldest_valid = write_pos - EVDEV_RING_FRAMES;
                vf->read_pos = (packet_head > oldest_valid) ? packet_head : oldest_valid;

                if (count < sizeof(struct input_event)) { errno = EINVAL; return -1; }
                struct input_event ev;
                struct timespec ts;
                clock_gettime(CLOCK_REALTIME, &ts);
                ev.time.tv_sec  = ts.tv_sec;
                ev.time.tv_usec = ts.tv_nsec / 1000;
                ev.type  = EV_SYN;
                ev.code  = SYN_DROPPED;
                ev.value = 0;
                memcpy(buf, &ev, sizeof(ev));
                return sizeof(struct input_event);
            }

            uint64_t packet_head = atomic_load_explicit(&vf->shmem->packet_head,
                                                         memory_order_acquire);

            if (packet_head == vf->read_pos) {
                if (vf->flags & O_NONBLOCK) { errno = EAGAIN; return -1; }

                uint32_t seq = atomic_load_explicit(&vf->shmem->wake_seq,
                                                    memory_order_acquire);
                packet_head = atomic_load_explicit(&vf->shmem->packet_head,
                                                   memory_order_acquire);
                if (packet_head != vf->read_pos) continue;

                struct timespec ts = { .tv_sec = 3, .tv_nsec = 0 };
                long rc = syscall(SYS_futex, &vf->shmem->wake_seq, FUTEX_WAIT,
                                  seq, &ts, NULL, 0);
                if (rc < 0 && errno == EINTR) { return -1; }
                if (rc < 0 && errno == ETIMEDOUT) {
                    struct timespec now;
                    clock_gettime(CLOCK_MONOTONIC, &now);
                    uint64_t hb = atomic_load_explicit(&vf->shmem->heartbeat,
                                                       memory_order_relaxed);
                    if ((uint64_t)now.tv_sec - hb > HEARTBEAT_TIMEOUT_SEC) { errno = EIO; return -1; }
                }
                continue;
            }

            uint64_t avail_frames = packet_head - vf->read_pos;
            uint64_t want = count / sizeof(struct input_event);
            uint64_t nframes = avail_frames < want ? avail_frames : want;

            uint8_t *dst = buf;
            for (uint64_t i = 0; i < nframes; i++) {
                wire_to_native(vf->shmem->buf + FRAME_RING_BYTE(vf->read_pos),
                               (struct input_event *)dst);
                dst += sizeof(struct input_event);
                vf->read_pos++;
            }

            /* Re-stamp events if reader requested CLOCK_MONOTONIC.
             * The ring stores CLOCK_REALTIME timestamps. */
            if (vf->clock_type != CLOCK_REALTIME) {
                struct timespec rt, mono;
                clock_gettime(CLOCK_REALTIME,  &rt);
                clock_gettime(CLOCK_MONOTONIC, &mono);
                int64_t offset_us =
                    ((int64_t)mono.tv_sec  - (int64_t)rt.tv_sec)  * 1000000LL +
                    ((int64_t)mono.tv_nsec - (int64_t)rt.tv_nsec) / 1000LL;
                struct input_event *evs = (struct input_event *)buf;
                for (uint64_t i = 0; i < nframes; i++) {
                    int64_t t = (int64_t)evs[i].time.tv_sec * 1000000LL
                              + (int64_t)evs[i].time.tv_usec + offset_us;
                    if (t < 0) t = 0;
                    evs[i].time.tv_sec  = (long)(t / 1000000LL);
                    evs[i].time.tv_usec = (long)(t % 1000000LL);
                }
            }

            return (ssize_t)(nframes * sizeof(struct input_event));
        }
    }

    /* uinput read path: FF events from socket */
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int timeout = (vf->flags & O_NONBLOCK) ? 0 : -1;
    int ret = real_poll(&pfd, 1, timeout);
    if (ret == 0) { errno = EAGAIN; return -1; }
    if (ret < 0) return -1;

    struct msg_header hdr;
    if (recv_all_r(fd, &hdr, sizeof(hdr)) < 0) return -1;
    uint32_t plen = hdr.length;

    size_t nevents = plen / WIRE_EVENT_SIZE;
    if (nevents * sizeof(struct input_event) > count) { errno = EMSGSIZE; return -1; }
    if (plen > 0 && recv_all_r(fd, buf, plen) < 0) return -1;
    struct input_event *evs = (struct input_event *)buf;
    for (size_t i = 0; i < nevents; i++)
        wire_to_native((uint8_t *)buf + i * WIRE_EVENT_SIZE, &evs[i]);
    return (ssize_t)(nevents * sizeof(struct input_event));
}

/* ------------------------------------------------------------------ */
/* write                                                              */
/* ------------------------------------------------------------------ */

bool should_intercept_write(int fd) {
    return vfd_is_active(fd) && vfd_table[fd].type != VFD_SYSFS;
}

ssize_t intercept_write(int fd, const void *buf, size_t count) {
    dbg("write: fd=%d count=%zu type=%s dev=%d", fd, count,
        vfd_type_name(fd), vfd_table[fd].device_id);
    vfd_type_t type = vfd_table[fd].type;
    msg_type_t mtype = (type == VFD_UINPUT) ? MSG_WRITE : MSG_EVDEV_WRITE;

    /* Pre-creation uinput writes (legacy uinput_user_dev struct) are raw
     * bytes, not input_event arrays. Send without wire conversion. */
    if (type == VFD_UINPUT && !vfd_table[fd].created) {
        int rc = send_msg_r(fd, mtype, buf, (uint32_t)count);
        if (rc < 0) { errno = EIO; return -1; }
        return (ssize_t)count;
    }

    size_t nevents = count / sizeof(struct input_event);
    uint8_t wire_stack[WIRE_EVENT_SIZE * 32];
    uint8_t *wire_buf = wire_stack;
    size_t wire_len = nevents * WIRE_EVENT_SIZE;
    if (wire_len > sizeof(wire_stack)) {
        wire_buf = malloc(wire_len);
        if (!wire_buf) { errno = ENOMEM; return -1; }
    }
    const struct input_event *evs = (const struct input_event *)buf;
    for (size_t i = 0; i < nevents; i++)
        native_to_wire(&evs[i], wire_buf + i * WIRE_EVENT_SIZE);
    int rc = send_msg_r(fd, mtype, wire_buf, (uint32_t)wire_len);
    if (wire_buf != wire_stack) free(wire_buf);
    if (rc < 0) { errno = EIO; return -1; }
    return (ssize_t)count;
}
