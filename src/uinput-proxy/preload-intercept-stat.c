#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/sysmacros.h>

#include "preload.h"

static dev_t uinput_rdev(void) {
    return makedev(UINPUT_MAJOR, UINPUT_MINOR);
}

static dev_t vfd_rdev(int fd) {
    struct virtual_fd *vf = &vfd_table[fd];
    return vf->type == VFD_EVDEV ? makedev(INPUT_MAJOR, EVDEV_MINOR(vf->device_id))
                                 : uinput_rdev();
}

/* ------------------------------------------------------------------ */
/* stat / statx                                                       */
/* ------------------------------------------------------------------ */

bool should_intercept_stat(const char *path) {
    return classify_path(path).cls == PATH_UINPUT;
}

int intercept_stat(const char *path, struct stat *st) {
    dbg("intercept_stat: %s", path);
    fill_chr_stat(st, uinput_rdev());
    return 0;
}

int intercept_stat64(const char *path, struct stat64 *st) {
    dbg("intercept_stat64: %s", path);
    fill_chr_stat64(st, uinput_rdev());
    return 0;
}

int intercept_statx(const char *path, struct statx *stx) {
    dbg("intercept_statx: %s", path);
    fill_chr_statx(stx, uinput_rdev());
    return 0;
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
    fill_chr_stat(st, vfd_rdev(fd));
    return 0;
}

int intercept_fstat64(int fd, struct stat64 *st) {
    dbg("intercept_fstat64: fd=%d", fd);
    fill_chr_stat64(st, vfd_rdev(fd));
    return 0;
}

int intercept_fstatx(int fd, struct statx *stx) {
    dbg("intercept_fstatx: fd=%d", fd);
    fill_chr_statx(stx, vfd_rdev(fd));
    return 0;
}

/* ------------------------------------------------------------------ */
/* access                                                             */
/* ------------------------------------------------------------------ */

bool should_intercept_access(const char *path) {
    return classify_path(path).cls == PATH_UINPUT;
}

int intercept_access(const char *path) {
    dbg("access: %s", path);
    return 0;
}

/* ------------------------------------------------------------------ */
/* readlink                                                           */
/* ------------------------------------------------------------------ */

bool should_intercept_readlink(const char *path) {
    return classify_path(path).cls == PATH_PROC_SELF_FD;
}

ssize_t intercept_readlink(const char *path, char *buf, size_t bufsz) {
    dbg("readlink: %s", path);
    int fd = classify_path(path).dev_id;
    char target[64];
    if (vfd_table[fd].type == VFD_EVDEV)
        snprintf(target, sizeof(target), "/dev/input/event%d", vfd_table[fd].device_id);
    else
        snprintf(target, sizeof(target), "/dev/uinput");
    size_t len = strlen(target);
    if (len > bufsz) len = bufsz;
    memcpy(buf, target, len);
    return (ssize_t)len;
}
