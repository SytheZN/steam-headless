#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "preload.h"

/* ------------------------------------------------------------------ */
/* open / openat                                                      */
/* ------------------------------------------------------------------ */

bool should_intercept_open(const char *path) {
    path_info_t pi = classify_path(path);
    return pi.cls == PATH_UINPUT || pi.cls == PATH_EVDEV;
}

int intercept_open(const char *path, int flags, mode_t mode) {
    (void)mode;
    dbg("open: %s flags=0x%x", path, flags);
    path_info_t pi = classify_path(path);

    if (pi.cls == PATH_UINPUT) {
        int sock = connect_to_daemon();
        if (sock < 0) { errno = ENODEV; return -1; }
        send_msg_r(sock, MSG_UINPUT_OPEN, NULL, 0);
        vfd_set(sock, VFD_UINPUT, -1);
        vfd_set_flags(sock, flags);
        return sock;
    }

    if (pi.cls == PATH_EVDEV) {
        if (real_access(path, F_OK) != 0) return -1;
        int dev_id = pi.dev_id;
        int sock = connect_to_daemon();
        if (sock < 0) { errno = ENODEV; return -1; }
        struct msg_evdev_open m = { .device_num = (uint32_t)dev_id };
        send_msg_r(sock, MSG_EVDEV_OPEN, &m, sizeof(m));

        int open_fds[EVDEV_OPEN_FD_COUNT];
        int recv_ret = recv_fds(sock, open_fds, EVDEV_OPEN_FD_COUNT);
        if (recv_ret < 0) {
            int saved_errno = errno;
            dbg("evdev open: recv_fds failed ret=%d errno=%d, fallback to real device", recv_ret, saved_errno);
            real_close(sock);
            int fd = real_open(path, flags, mode);
            dbg("evdev open: real_open returned fd=%d errno=%d", fd, errno);
            return fd;
        }
        int doorbell = open_fds[EVDEV_OPEN_FD_DOORBELL];
        const struct evdev_shmem *shm = mmap(NULL, sizeof(struct evdev_shmem),
                                              PROT_READ, MAP_SHARED,
                                              open_fds[EVDEV_OPEN_FD_SHMEM], 0);
        real_close(open_fds[EVDEV_OPEN_FD_SHMEM]);
        if (shm == MAP_FAILED) {
            dbg("evdev open: mmap failed: %s", strerror(errno));
            real_close(doorbell);
            real_close(sock); errno = ENODEV; return -1;
        }

        struct evdev_reader *reader = evdev_reader_new(shm, doorbell);
        if (!reader) {
            munmap((void *)shm, sizeof(struct evdev_shmem));
            real_close(doorbell);
            real_close(sock); errno = ENOMEM; return -1;
        }

        vfd_table[sock].type      = VFD_EVDEV;
        vfd_table[sock].device_id = dev_id;
        vfd_table[sock].flags     = flags;
        vfd_table[sock].created   = false;
        vfd_table[sock].reader    = reader;
        atomic_store_explicit(&vfd_table[sock].active, true, memory_order_release);
        return sock;
    }

    errno = ENOENT;
    return -1;
}

bool should_intercept_openat(int dfd, const char *path) {
    (void)dfd;
    return path && path[0] == '/' && should_intercept_open(path);
}

int intercept_openat(int dfd, const char *path, int flags, mode_t mode) {
    dbg("openat: dfd=%d path=%s", dfd, path);
    return intercept_open(path, flags, mode);
}
