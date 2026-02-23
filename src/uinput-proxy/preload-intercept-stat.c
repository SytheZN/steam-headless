#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/sysmacros.h>

#include "preload.h"

/* ------------------------------------------------------------------ */
/* stat / lstat / access / readlink                                   */
/* ------------------------------------------------------------------ */

bool should_intercept_stat(const char *path) {
    path_info_t pi = classify_path(path);
    switch (pi.cls) {
    case PATH_UINPUT:
    case PATH_DEV_INPUT_DIR:
    case PATH_EVDEV:
    case PATH_SYSFS_CLASS_DIR:
    case PATH_SYSFS_VIRT_DIR:
    case PATH_SYSFS_CLASS:
    case PATH_SYSFS_EVENT:
    case PATH_SYSFS_INPUT:
        return true;
    default:
        return false;
    }
}

int intercept_stat(const char *path, struct stat *st) {
    dbg("intercept_stat: %s", path);
    path_info_t pi = classify_path(path);

    switch (pi.cls) {
    case PATH_UINPUT:
        fill_chr_stat(st, makedev(UINPUT_MAJOR, UINPUT_MINOR));
        return 0;
    case PATH_DEV_INPUT_DIR:
        fill_dir_stat(st);
        return 0;
    case PATH_EVDEV:
        if (!device_exists(pi.dev_id)) return real_stat(path, st);
        fill_chr_stat(st, makedev(INPUT_MAJOR, EVDEV_MINOR(pi.dev_id)));
        return 0;
    case PATH_SYSFS_CLASS_DIR:
    case PATH_SYSFS_VIRT_DIR:
        fill_dir_stat(st);
        return 0;
    case PATH_SYSFS_CLASS:
        if (!device_exists(pi.dev_id)) { errno = ENOENT; return -1; }
        if (pi.remainder[0] == '\0') { fill_lnk_stat(st); return 0; }
        /* fall through to sysfs attr */
    case PATH_SYSFS_EVENT:
    case PATH_SYSFS_INPUT:
        if (!device_exists(pi.dev_id)) { errno = ENOENT; return -1; }
        if (is_sysfs_dir_attr(pi.remainder)) fill_dir_stat(st);
        else fill_reg_stat(st);
        return 0;
    default:
        errno = ENOENT;
        return -1;
    }
}

int intercept_stat64(const char *path, struct stat64 *st) {
    dbg("intercept_stat64: %s", path);
    path_info_t pi = classify_path(path);

    switch (pi.cls) {
    case PATH_UINPUT:
        fill_chr_stat64(st, makedev(UINPUT_MAJOR, UINPUT_MINOR));
        return 0;
    case PATH_DEV_INPUT_DIR:
        fill_dir_stat64(st);
        return 0;
    case PATH_EVDEV:
        if (!device_exists(pi.dev_id)) return real_stat64(path, st);
        fill_chr_stat64(st, makedev(INPUT_MAJOR, EVDEV_MINOR(pi.dev_id)));
        return 0;
    case PATH_SYSFS_CLASS_DIR:
    case PATH_SYSFS_VIRT_DIR:
        fill_dir_stat64(st);
        return 0;
    case PATH_SYSFS_CLASS:
        if (!device_exists(pi.dev_id)) { errno = ENOENT; return -1; }
        if (pi.remainder[0] == '\0') { fill_lnk_stat64(st); return 0; }
    case PATH_SYSFS_EVENT:
    case PATH_SYSFS_INPUT:
        if (!device_exists(pi.dev_id)) { errno = ENOENT; return -1; }
        if (is_sysfs_dir_attr(pi.remainder)) fill_dir_stat64(st);
        else fill_reg_stat64(st);
        return 0;
    default:
        errno = ENOENT;
        return -1;
    }
}

/* ------------------------------------------------------------------ */
/* fstat                                                              */
/* ------------------------------------------------------------------ */

bool should_intercept_fstat(int fd) {
    return vfd_is_active(fd) &&
           (vfd_table[fd].type == VFD_EVDEV || vfd_table[fd].type == VFD_UINPUT);
}

int intercept_fstat(int fd, struct stat *st) {
    dbg("intercept_fstat: fd=%d", fd);
    struct virtual_fd *vf = &vfd_table[fd];
    if (vf->type == VFD_EVDEV)
        fill_chr_stat(st, makedev(INPUT_MAJOR, EVDEV_MINOR(vf->device_id)));
    else
        fill_chr_stat(st, makedev(UINPUT_MAJOR, UINPUT_MINOR));
    return 0;
}

int intercept_fstat64(int fd, struct stat64 *st) {
    dbg("intercept_fstat64: fd=%d", fd);
    struct virtual_fd *vf = &vfd_table[fd];
    if (vf->type == VFD_EVDEV)
        fill_chr_stat64(st, makedev(INPUT_MAJOR, EVDEV_MINOR(vf->device_id)));
    else
        fill_chr_stat64(st, makedev(UINPUT_MAJOR, UINPUT_MINOR));
    return 0;
}

/* ------------------------------------------------------------------ */
/* access                                                             */
/* ------------------------------------------------------------------ */

bool should_intercept_access(const char *path) {
    path_info_t pi = classify_path(path);
    switch (pi.cls) {
    case PATH_UINPUT:
    case PATH_DEV_INPUT_DIR:
    case PATH_EVDEV:
    case PATH_SYSFS_CLASS_DIR:
    case PATH_SYSFS_VIRT_DIR:
    case PATH_SYSFS_CLASS:
    case PATH_SYSFS_EVENT:
    case PATH_SYSFS_INPUT:
        return true;
    default:
        return false;
    }
}

int intercept_access(const char *path) {
    dbg("access: %s", path);
    path_info_t pi = classify_path(path);

    if (pi.cls == PATH_UINPUT || pi.cls == PATH_DEV_INPUT_DIR ||
        pi.cls == PATH_SYSFS_CLASS_DIR || pi.cls == PATH_SYSFS_VIRT_DIR)
        return 0;

    if (pi.cls == PATH_EVDEV) {
        if (!device_exists(pi.dev_id)) {
            dbg("access: device %d not ours, fallback", pi.dev_id);
            return real_access(path, R_OK | W_OK);
        }
        return 0;
    }

    if (pi.cls == PATH_SYSFS_CLASS || pi.cls == PATH_SYSFS_EVENT ||
        pi.cls == PATH_SYSFS_INPUT) {
        if (!device_exists(pi.dev_id)) { errno = ENOENT; return -1; }
        return 0;
    }

    errno = ENOENT;
    return -1;
}

/* ------------------------------------------------------------------ */
/* readlink                                                           */
/* ------------------------------------------------------------------ */

bool should_intercept_readlink(const char *path) {
    path_info_t pi = classify_path(path);
    if (pi.cls == PATH_SYSFS_CLASS && pi.remainder[0] == '\0') return true;
    if (pi.cls == PATH_PROC_SELF_FD) return true;
    return false;
}

ssize_t intercept_readlink(const char *path, char *buf, size_t bufsz) {
    dbg("readlink: %s", path);
    path_info_t pi = classify_path(path);

    if (pi.cls == PATH_PROC_SELF_FD) {
        int fd_num = pi.dev_id;
        const char *target = NULL;
        char target_buf[64];
        switch (vfd_table[fd_num].type) {
        case VFD_UINPUT:
            target = "/dev/uinput";
            break;
        case VFD_EVDEV:
            snprintf(target_buf, sizeof(target_buf),
                     "/dev/input/event%d", vfd_table[fd_num].device_id);
            target = target_buf;
            break;
        default:
            break;
        }
        if (target) {
            int n = snprintf(buf, bufsz, "%s", target);
            return (ssize_t)(n < (int)bufsz ? n : (int)bufsz);
        }
    }

    if (pi.cls == PATH_SYSFS_CLASS) {
        int dev_id = pi.dev_id;
        if (!device_exists(dev_id)) { errno = ENOENT; return -1; }
        int n = snprintf(buf, bufsz,
            "../../devices/virtual/input/input%d/event%d",
            dev_id, dev_id);
        return (ssize_t)(n < (int)bufsz ? n : (int)bufsz);
    }

    errno = ENOENT;
    return -1;
}
