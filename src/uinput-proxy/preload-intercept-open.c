#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "preload.h"

/* ------------------------------------------------------------------ */
/* open / openat                                                      */
/* ------------------------------------------------------------------ */

bool should_intercept_open(const char *path) {
    path_info_t pi = classify_path(path);
    switch (pi.cls) {
    case PATH_UINPUT:
    case PATH_EVDEV:
        return true;
    case PATH_SYSFS_EVENT:
    case PATH_SYSFS_INPUT:
    case PATH_SYSFS_CLASS:
        return pi.remainder[0] != '\0';
    default:
        return false;
    }
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
        int dev_id = pi.dev_id;
        int sock = connect_to_daemon();
        if (sock < 0) { errno = ENODEV; return -1; }
        struct msg_evdev_open m = { .device_num = (uint32_t)dev_id };
        send_msg_r(sock, MSG_EVDEV_OPEN, &m, sizeof(m));

        int shmem_fd;
        int recv_ret = recv_fds(sock, &shmem_fd, 1);
        if (recv_ret < 0) {
            int saved_errno = errno;
            dbg("evdev open: recv_fds failed ret=%d errno=%d, fallback to real device", recv_ret, saved_errno);
            real_close(sock);
            int fd = real_open(path, flags, mode);
            dbg("evdev open: real_open returned fd=%d errno=%d", fd, errno);
            return fd;
        }
        const struct evdev_shmem *shm = mmap(NULL, sizeof(struct evdev_shmem),
                                              PROT_READ, MAP_SHARED, shmem_fd, 0);
        real_close(shmem_fd);
        if (shm == MAP_FAILED) {
            dbg("evdev open: mmap failed: %s", strerror(errno));
            real_close(sock); errno = ENODEV; return -1;
        }

        vfd_table[sock].type      = VFD_EVDEV;
        vfd_table[sock].device_id = dev_id;
        vfd_table[sock].flags     = flags;
        vfd_table[sock].shmem     = shm;
        vfd_table[sock].read_pos  = atomic_load_explicit(&shm->write_pos, memory_order_acquire);
        atomic_store_explicit(&vfd_table[sock].active, true, memory_order_release);
        return sock;
    }

    if ((pi.cls == PATH_SYSFS_EVENT || pi.cls == PATH_SYSFS_INPUT ||
         pi.cls == PATH_SYSFS_CLASS) && pi.remainder[0]) {
        int fd = open_sysfs_content(pi.dev_id, pi.remainder);
        if (fd >= 0) vfd_set(fd, VFD_SYSFS, pi.dev_id);
        return fd;
    }

    errno = ENOENT;
    return -1;
}

bool should_intercept_openat(int dfd, const char *path) {
    if (!path) return false;
    if (dfd == FAKE_DIRFD_SENTINEL) return true;
    if (path[0] == '/') return should_intercept_open(path);
    return false;
}

int intercept_openat(int dfd, const char *path, int flags, mode_t mode) {
    dbg("openat: dfd=%d path=%s", dfd, path);
    if (dfd == FAKE_DIRFD_SENTINEL) {
        char full[256];
        snprintf(full, sizeof(full), "/dev/input/%s", path);
        return intercept_open(full, flags, mode);
    }
    return intercept_open(path, flags, mode);
}
