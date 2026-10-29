#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/sysmacros.h>

#include "preload.h"

/* ------------------------------------------------------------------ */
/* Wire I/O                                                           */
/* ------------------------------------------------------------------ */

int send_all_r(int fd, const void *buf, size_t len) {
    const uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = real_write(fd, p, len);
        if (n <= 0) { if (n < 0 && errno == EINTR) continue; return -1; }
        p += n; len -= n;
    }
    return 0;
}

int recv_all_r(int fd, void *buf, size_t len) {
    uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = real_read(fd, p, len);
        if (n <= 0) { if (n < 0 && errno == EINTR) continue; return -1; }
        p += n; len -= n;
    }
    return 0;
}

int send_msg_r(int fd, msg_type_t type, const void *payload, uint32_t plen) {
    struct msg_header hdr = { .type = (uint8_t)type, .length = plen };
    if (send_all_r(fd, &hdr, sizeof(hdr)) < 0) return -1;
    if (plen > 0 && payload && send_all_r(fd, payload, plen) < 0) return -1;
    return 0;
}

int recv_msg_r(int fd, void *buf, size_t bufsz, uint32_t *plen_out) {
    struct msg_header hdr;
    if (recv_all_r(fd, &hdr, sizeof(hdr)) < 0) return -1;
    if (hdr.length > bufsz) { errno = EMSGSIZE; return -1; }
    *plen_out = hdr.length;
    if (hdr.length > 0 && recv_all_r(fd, buf, hdr.length) < 0) return -1;
    return (int)hdr.type;
}

/* ------------------------------------------------------------------ */
/* SCM_RIGHTS receive                                                 */
/* ------------------------------------------------------------------ */

int recv_fds(int sock, int *fds, int nfds) {
    assert(nfds >= 1 && nfds <= EVDEV_OPEN_FD_COUNT);
    char cmsgbuf[CMSG_SPACE(sizeof(int) * EVDEV_OPEN_FD_COUNT)];
    char dummy;
    struct iovec  iov = { .iov_base = &dummy, .iov_len = 1 };
    struct msghdr msg = {
        .msg_iov        = &iov,
        .msg_iovlen     = 1,
        .msg_control    = cmsgbuf,
        .msg_controllen = sizeof(cmsgbuf),
    };
    if (recvmsg(sock, &msg, 0) < 0) return -1;
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_type != SCM_RIGHTS) return -1;
    int n = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
    if (n < nfds) return -1;
    memcpy(fds, CMSG_DATA(cmsg), sizeof(int) * nfds);
    for (int i = nfds; i < n; i++)
        real_close(((int *)CMSG_DATA(cmsg))[i]);
    return 0;
}

struct evdev_reader *evdev_reader_new(const struct evdev_shmem *shmem, int doorbell) {
    struct evdev_reader *reader = calloc(1, sizeof(*reader));
    if (!reader) return NULL;
    atomic_init(&reader->refs, 1);
    reader->shmem      = shmem;
    reader->doorbell   = doorbell;
    reader->read_pos   = atomic_load_explicit(&shmem->packet_head, memory_order_acquire);
    reader->clock_type = CLOCK_REALTIME;
    return reader;
}

void evdev_reader_release(struct evdev_reader *reader) {
    if (atomic_fetch_sub_explicit(&reader->refs, 1, memory_order_acq_rel) != 1)
        return;
    munmap((void *)reader->shmem, sizeof(struct evdev_shmem));
    real_close(reader->doorbell);
    free(reader);
}

bool evdev_reader_has_packet(const struct evdev_reader *reader) {
    return atomic_load_explicit(&reader->shmem->packet_head, memory_order_acquire)
        != reader->read_pos;
}

void evdev_reader_sync_doorbell(struct evdev_reader *reader) {
    if (evdev_reader_has_packet(reader)) return;
    uint64_t pending;
    while (real_read(reader->doorbell, &pending, sizeof(pending)) == sizeof(pending))
        ;
    if (evdev_reader_has_packet(reader)) {
        uint64_t one = 1;
        real_write(reader->doorbell, &one, sizeof(one));
    }
}

bool evdev_socket_hung_up(int sock) {
    struct pollfd p = { .fd = sock, .events = POLLRDHUP };
    return real_poll(&p, 1, 0) > 0 &&
           (p.revents & (POLLRDHUP | POLLHUP | POLLERR | POLLNVAL));
}

/* ------------------------------------------------------------------ */
/* Daemon connection                                                  */
/* ------------------------------------------------------------------ */

int connect_to_daemon(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, UINPUT_PROXY_SOCK, sizeof(addr.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        real_close(fd);
        return -1;
    }
    return fd;
}

/* ------------------------------------------------------------------ */
/* Device list                                                        */
/* ------------------------------------------------------------------ */

int query_device_list(int *ids) {
    int sock = connect_to_daemon();
    if (sock < 0) return 0;

    send_msg_r(sock, MSG_LIST_DEVICES, NULL, 0);

    uint8_t replybuf[sizeof(struct msg_device_list_reply) + MAX_DEVICES * sizeof(struct device_entry)];
    uint32_t plen = 0;
    int type = recv_msg_r(sock, replybuf, sizeof(replybuf), &plen);
    real_close(sock);

    if (type != MSG_DEVICE_LIST_REPLY || plen < sizeof(struct msg_device_list_reply))
        return 0;

    struct msg_device_list_reply *r = (struct msg_device_list_reply *)replybuf;
    struct device_entry *e = (struct device_entry *)(replybuf + sizeof(*r));
    int count = (int)r->count;
    if (count > MAX_DEVICES) count = MAX_DEVICES;
    for (int i = 0; i < count; i++) ids[i] = (int)e[i].id;
    return count;
}

bool device_exists(int dev_id) {
    if (dev_id < 0 || dev_id >= MAX_DEVICES) return false;
    int ids[MAX_DEVICES];
    int count = query_device_list(ids);
    for (int i = 0; i < count; i++)
        if (ids[i] == dev_id) return true;
    return false;
}

/* ------------------------------------------------------------------ */
/* Path classification                                                */
/* ------------------------------------------------------------------ */

/* Fast inline integer parse — no locale overhead, no errno clobber.
 * Returns -1 on empty/invalid/overflow. */
static inline int parse_uint(const char *s, const char **end) {
    if (*s < '0' || *s > '9') return -1;
    int n = 0;
    while (*s >= '0' && *s <= '9') {
        n = n * 10 + (*s - '0');
        if (n >= MAX_DEVICES) return -1;
        s++;
    }
    *end = s;
    return n;
}

/* Advance past a literal prefix, or return NULL. Only compares the new
   segment — caller is responsible for feeding the already-advanced cursor. */
#define ADV(cursor, lit) \
    (memcmp(cursor, lit, sizeof(lit) - 1) == 0 ? (cursor) + (sizeof(lit) - 1) : NULL)

path_info_t classify_path(const char *path) {
    path_info_t none = { PATH_NONE, -1 };
    if (!path || path[0] != '/') return none;

    const char *p;

    switch (path[1]) {

    case 'd': /* /dev/... */
        if (!(p = ADV(path, "/dev/"))) return none;

        if (p[0] == 'u' && memcmp(p, "uinput", 7) == 0)
            return (path_info_t){ PATH_UINPUT, -1 };

        if (!(p = ADV(p, "input"))) return none;

        if (*p == '\0')
            return (path_info_t){ PATH_DEV_INPUT_DIR, -1 };

        if (!(p = ADV(p, "/event"))) return none;
        {
            const char *end;
            int n = parse_uint(p, &end);
            if (n < 0 || *end != '\0') return none;
            return (path_info_t){ PATH_EVDEV, n };
        }

    case 'p': /* /proc/self/fd/N */
        if (!(p = ADV(path, "/proc/self/fd/"))) return none;
        {
            const char *end;
            int fd_num = parse_uint(p, &end);
            if (fd_num < 0 || *end != '\0' || fd_num >= VFD_MAX) return none;
            if (!vfd_is_active(fd_num)) return none;
            return (path_info_t){ PATH_PROC_SELF_FD, fd_num };
        }

    default:
        return none;
    }
}

/* ------------------------------------------------------------------ */
/* Stat fill helpers                                                  */
/* ------------------------------------------------------------------ */

void fill_chr_stat(struct stat *st, dev_t rdev) {
    memset(st, 0, sizeof(*st));
    st->st_mode  = S_IFCHR | 0666;
    st->st_rdev  = rdev;
    st->st_nlink = 1;
}

void fill_chr_stat64(struct stat64 *st, dev_t rdev) {
    memset(st, 0, sizeof(*st));
    st->st_mode  = S_IFCHR | 0666;
    st->st_rdev  = rdev;
    st->st_nlink = 1;
}

void fill_chr_statx(struct statx *stx, dev_t rdev) {
    memset(stx, 0, sizeof(*stx));
    stx->stx_mask       = STATX_TYPE | STATX_MODE | STATX_NLINK;
    stx->stx_mode       = S_IFCHR | 0666;
    stx->stx_nlink      = 1;
    stx->stx_rdev_major = major(rdev);
    stx->stx_rdev_minor = minor(rdev);
}
