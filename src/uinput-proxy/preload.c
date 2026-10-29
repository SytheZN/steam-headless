#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string.h>
#include <errno.h>
#include <stdatomic.h>
#include <sys/prctl.h>
#include <sys/poll.h>
#include <signal.h>

#include "preload.h"

/* ------------------------------------------------------------------ */
/* Global state                                                       */
/* ------------------------------------------------------------------ */

bool        enabled   = true;
FILE       *debug_log = NULL;
pid_t       log_pid   = 0;
const char *log_proc  = NULL;

struct virtual_fd vfd_table[VFD_MAX];
struct epoll_track_entry epoll_table[EPOLL_TRACK_MAX];

/* ------------------------------------------------------------------ */
/* Real function pointers                                             */
/* ------------------------------------------------------------------ */

int     (*real_open)(const char *, int, ...)              = NULL;
int     (*real_open64)(const char *, int, ...)            = NULL;
int     (*real_openat)(int, const char *, int, ...)       = NULL;
int     (*real_openat64)(int, const char *, int, ...)     = NULL;
int     (*real_close)(int)                                = NULL;
ssize_t (*real_read)(int, void *, size_t)                 = NULL;
ssize_t (*real_write)(int, const void *, size_t)          = NULL;
ssize_t (*real_writev)(int, const struct iovec *, int)    = NULL;
ssize_t (*real_splice)(int, loff_t *, int, loff_t *,
                       size_t, unsigned int)              = NULL;
ssize_t (*real_sendfile)(int, int, off_t *, size_t)      = NULL;
ssize_t (*real_sendfile64)(int, int, off64_t *, size_t)  = NULL;
ssize_t (*real_pwrite)(int, const void *, size_t, off_t) = NULL;
ssize_t (*real_pwrite64)(int, const void *, size_t, off64_t) = NULL;
int     (*real_ioctl)(int, unsigned long, ...)            = NULL;
int     (*real_dup)(int)                                  = NULL;
int     (*real_dup2)(int, int)                            = NULL;
int     (*real_dup3)(int, int, int)                       = NULL;
int     (*real_fcntl)(int, int, ...)                      = NULL;
DIR   * (*real_opendir)(const char *)                     = NULL;
int     (*real_stat)(const char *, struct stat *)         = NULL;
int     (*real_stat64)(const char *, struct stat64 *)     = NULL;
int     (*real_lstat)(const char *, struct stat *)        = NULL;
int     (*real_lstat64)(const char *, struct stat64 *)    = NULL;
int     (*real_fstat)(int, struct stat *)                 = NULL;
int     (*real_fstat64)(int, struct stat64 *)             = NULL;
int     (*real_fxstat)(int, int, struct stat *)           = NULL;
int     (*real_fxstat64)(int, int, struct stat64 *)       = NULL;
int     (*real_access)(const char *, int)                 = NULL;
int     (*real_faccessat)(int, const char *, int, int)    = NULL;
ssize_t (*real_readlink)(const char *, char *, size_t)    = NULL;
int     (*real_poll)(struct pollfd *, nfds_t, int)        = NULL;
int     (*real_ppoll)(struct pollfd *, nfds_t,
                      const struct timespec *,
                      const sigset_t *)                   = NULL;
int     (*real_select)(int, fd_set *, fd_set *, fd_set *,
                       struct timeval *)                  = NULL;
int     (*real_pselect)(int, fd_set *, fd_set *, fd_set *,
                        const struct timespec *,
                        const sigset_t *)                 = NULL;
int     (*real_epoll_ctl)(int, int, int, struct epoll_event *)  = NULL;
int     (*real_epoll_wait)(int, struct epoll_event *, int, int) = NULL;
int     (*real_epoll_pwait)(int, struct epoll_event *, int, int,
                            const sigset_t *)             = NULL;
int     (*real_inotify_init)(void)                        = NULL;
int     (*real_inotify_init1)(int)                        = NULL;
int     (*real_inotify_add_watch)(int, const char *, uint32_t) = NULL;
int     (*real_inotify_rm_watch)(int, int)                = NULL;
int     (*real_xstat)(int, const char *, struct stat *)   = NULL;
int     (*real_lxstat)(int, const char *, struct stat *)  = NULL;
int     (*real_xstat64)(int, const char *, struct stat64 *)  = NULL;
int     (*real_lxstat64)(int, const char *, struct stat64 *) = NULL;
int     (*real_fstatat)(int, const char *, struct stat *, int)          = NULL;
int     (*real_fstatat64)(int, const char *, struct stat64 *, int)      = NULL;
int     (*real_fxstatat)(int, int, const char *, struct stat *, int)    = NULL;
int     (*real_fxstatat64)(int, int, const char *, struct stat64 *, int) = NULL;
int     (*real_statx)(int, const char *, int, unsigned int, struct statx *) = NULL;
ssize_t (*real_readlinkat)(int, const char *, char *, size_t)           = NULL;
char  * (*real_realpath)(const char *, char *)                          = NULL;
char  * (*real___realpath_chk)(const char *, char *, size_t)            = NULL;
FILE  * (*real_fopen)(const char *, const char *)                       = NULL;
FILE  * (*real_fopen64)(const char *, const char *)                     = NULL;
int     (*real_scandir)(const char *, struct dirent ***,
                        int (*)(const struct dirent *),
                        int (*)(const struct dirent **, const struct dirent **)) = NULL;
int     (*real_scandir64)(const char *, struct dirent64 ***,
                          int (*)(const struct dirent64 *),
                          int (*)(const struct dirent64 **, const struct dirent64 **)) = NULL;
int     (*real___open_2)(const char *, int)                             = NULL;
int     (*real___open64_2)(const char *, int)                           = NULL;
int     (*real___openat_2)(int, const char *, int)                      = NULL;
int     (*real___openat64_2)(int, const char *, int)                    = NULL;
ssize_t (*real___readlinkat_chk)(int, const char *, char *, size_t, size_t) = NULL;
int     (*real_fstatfs)(int, struct statfs *)                           = NULL;
int     (*real_fstatfs64)(int, struct statfs64 *)                       = NULL;

#define RESOLVE(fn) do { real_##fn = dlsym(RTLD_NEXT, #fn); } while (0)
#define REAL(fn)    (real_##fn ? real_##fn : (resolve_real_functions(), real_##fn))

static void resolve_real_functions(void) {
    static _Atomic bool resolved = false;
    if (atomic_load_explicit(&resolved, memory_order_acquire)) return;

    RESOLVE(open);
    RESOLVE(open64);
    RESOLVE(close);
    RESOLVE(read);
    RESOLVE(write);
    RESOLVE(ioctl);
    RESOLVE(fcntl);
    RESOLVE(opendir);
    RESOLVE(stat);
    RESOLVE(access);
    RESOLVE(poll);
    RESOLVE(ppoll);
    RESOLVE(select);
    RESOLVE(pselect);
    RESOLVE(epoll_ctl);
    RESOLVE(epoll_wait);
    RESOLVE(epoll_pwait);
    RESOLVE(openat);
    RESOLVE(openat64);
    RESOLVE(dup);
    RESOLVE(dup2);
    RESOLVE(dup3);
    RESOLVE(lstat);
    RESOLVE(fstat);
    RESOLVE(fstat64);
    real_fxstat   = dlsym(RTLD_NEXT, "__fxstat");
    real_fxstat64 = dlsym(RTLD_NEXT, "__fxstat64");
    RESOLVE(faccessat);
    RESOLVE(readlink);
    real_xstat    = dlsym(RTLD_NEXT, "__xstat");
    real_lxstat   = dlsym(RTLD_NEXT, "__lxstat");
    RESOLVE(stat64);
    RESOLVE(lstat64);
    real_xstat64  = dlsym(RTLD_NEXT, "__xstat64");
    real_lxstat64 = dlsym(RTLD_NEXT, "__lxstat64");
    RESOLVE(fstatat);
    RESOLVE(fstatat64);
    real_fxstatat   = dlsym(RTLD_NEXT, "__fxstatat");
    real_fxstatat64 = dlsym(RTLD_NEXT, "__fxstatat64");
    RESOLVE(statx);
    RESOLVE(readlinkat);
    RESOLVE(realpath);
    RESOLVE(__realpath_chk);
    RESOLVE(fopen);
    RESOLVE(fopen64);
    RESOLVE(scandir);
    RESOLVE(scandir64);
    RESOLVE(__open_2);
    RESOLVE(__open64_2);
    RESOLVE(__openat_2);
    RESOLVE(__openat64_2);
    RESOLVE(__readlinkat_chk);
    RESOLVE(fstatfs);
    RESOLVE(fstatfs64);
#ifdef UINPUT_EXTRA_INTERCEPTS
    RESOLVE(writev);
    RESOLVE(splice);
    RESOLVE(sendfile);
    RESOLVE(sendfile64);
    RESOLVE(pwrite);
    RESOLVE(pwrite64);
    RESOLVE(inotify_init);
    RESOLVE(inotify_init1);
    RESOLVE(inotify_add_watch);
    RESOLVE(inotify_rm_watch);
#endif

    atomic_store_explicit(&resolved, true, memory_order_release);
}

__attribute__((constructor))
static void preload_init(void) {
    resolve_real_functions();

    static char proc_name_buf[17];
    log_pid  = getpid();
    prctl(PR_GET_NAME, proc_name_buf);
    log_proc = proc_name_buf;

    /* Disable the preload when running inside the daemon itself. */
    if (strcmp(log_proc, "uinput-daemon") == 0) {
        enabled = false;
    }

    const char *dbgval = getenv("UINPUTLD_DEBUG");
    if (dbgval && *dbgval) {
        if (strcmp(dbgval, "console") == 0) {
            debug_log = stderr;
        } else {
            debug_log = fopen(dbgval, "a");
            if (debug_log)
                setvbuf(debug_log, NULL, _IOLBF, 0);  /* flush on newline */
        }
    }

    if (!enabled)
      dbg("disabled");
}

/* ------------------------------------------------------------------ */
/* open / open64 / openat / openat64                                  */
/* __open_2 / __open64_2 / __openat_2 / __openat64_2                  */
/* ------------------------------------------------------------------ */

EXPORT int open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap); }
    if (!REAL(open)) { errno = ENOSYS; return -1; }
    char mirror[PATH_MAX];
    if (enabled && sysfs_redirect(path, mirror)) path = mirror;
    else if (enabled && should_intercept_open(path))
        return intercept_open(path, flags, mode);
    return real_open(path, flags, mode);
}

EXPORT int open64(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap); }
    if (!REAL(open64)) { errno = ENOSYS; return -1; }
    char mirror[PATH_MAX];
    if (enabled && sysfs_redirect(path, mirror)) path = mirror;
    else if (enabled && should_intercept_open(path))
        return intercept_open(path, flags, mode);
    return real_open64(path, flags, mode);
}

EXPORT int openat(int dfd, const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) { va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap); }
    if (!REAL(openat)) { errno = ENOSYS; return -1; }
    char mirror[PATH_MAX];
    if (enabled && sysfs_redirect_at(dfd, path, mirror)) { path = mirror; dfd = AT_FDCWD; }
    else if (enabled && should_intercept_openat(dfd, path))
        return intercept_openat(dfd, path, flags, mode);
    return real_openat(dfd, path, flags, mode);
}

EXPORT int openat64(int dfd, const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) { va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap); }
    if (!REAL(openat64)) { errno = ENOSYS; return -1; }
    char mirror[PATH_MAX];
    if (enabled && sysfs_redirect_at(dfd, path, mirror)) { path = mirror; dfd = AT_FDCWD; }
    else if (enabled && should_intercept_openat(dfd, path))
        return intercept_openat(dfd, path, flags, mode);
    return real_openat64(dfd, path, flags, mode);
}

EXPORT int __open_2(const char *path, int flags) {
    if (!REAL(__open_2)) { errno = ENOSYS; return -1; }
    char mirror[PATH_MAX];
    if (enabled && sysfs_redirect(path, mirror)) path = mirror;
    else if (enabled && should_intercept_open(path))
        return intercept_open(path, flags, 0);
    return real___open_2(path, flags);
}

EXPORT int __open64_2(const char *path, int flags) {
    if (!REAL(__open64_2)) { errno = ENOSYS; return -1; }
    char mirror[PATH_MAX];
    if (enabled && sysfs_redirect(path, mirror)) path = mirror;
    else if (enabled && should_intercept_open(path))
        return intercept_open(path, flags, 0);
    return real___open64_2(path, flags);
}

EXPORT int __openat_2(int dfd, const char *path, int flags) {
    if (!REAL(__openat_2)) { errno = ENOSYS; return -1; }
    char mirror[PATH_MAX];
    if (enabled && sysfs_redirect_at(dfd, path, mirror)) { path = mirror; dfd = AT_FDCWD; }
    else if (enabled && should_intercept_openat(dfd, path))
        return intercept_openat(dfd, path, flags, 0);
    return real___openat_2(dfd, path, flags);
}

EXPORT int __openat64_2(int dfd, const char *path, int flags) {
    if (!REAL(__openat64_2)) { errno = ENOSYS; return -1; }
    char mirror[PATH_MAX];
    if (enabled && sysfs_redirect_at(dfd, path, mirror)) { path = mirror; dfd = AT_FDCWD; }
    else if (enabled && should_intercept_openat(dfd, path))
        return intercept_openat(dfd, path, flags, 0);
    return real___openat64_2(dfd, path, flags);
}

/* ------------------------------------------------------------------ */
/* close                                                              */
/* ------------------------------------------------------------------ */

EXPORT int close(int fd) {
    if (!REAL(close)) { errno = ENOSYS; return -1; }
    if (enabled && should_intercept_close(fd))
        return intercept_close(fd);
    return real_close(fd);
}

/* ------------------------------------------------------------------ */
/* dup / dup2 / dup3 / fcntl                                          */
/* ------------------------------------------------------------------ */

EXPORT int dup(int oldfd) {
    if (!REAL(dup)) { errno = ENOSYS; return -1; }
    int newfd = real_dup(oldfd);
    if (enabled && newfd >= 0 && vfd_is_active(oldfd))
        vfd_dup(oldfd, newfd);
    return newfd;
}

EXPORT int dup2(int oldfd, int newfd) {
    if (!REAL(dup2)) { errno = ENOSYS; return -1; }
    if (enabled && oldfd != newfd && vfd_is_active(newfd)) release_vfd(newfd);
    int r = real_dup2(oldfd, newfd);
    if (enabled && r >= 0 && vfd_is_active(oldfd))
        vfd_dup(oldfd, r);
    return r;
}

EXPORT int dup3(int oldfd, int newfd, int fl) {
    if (!REAL(dup3)) { errno = ENOSYS; return -1; }
    if (enabled && oldfd != newfd && vfd_is_active(newfd)) release_vfd(newfd);
    int r = real_dup3(oldfd, newfd, fl);
    if (enabled && r >= 0 && vfd_is_active(oldfd))
        vfd_dup(oldfd, r);
    return r;
}

EXPORT int fcntl(int fd, int cmd, ...) {
    va_list ap; va_start(ap, cmd); long arg = va_arg(ap, long); va_end(ap);
    if (!REAL(fcntl)) { errno = ENOSYS; return -1; }
    if (enabled && should_intercept_fcntl(fd, cmd))
        return intercept_fcntl(fd, cmd, arg);
    int r = real_fcntl(fd, cmd, arg);
    if (enabled && r >= 0 && vfd_is_active(fd) &&
        (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC))
        vfd_dup(fd, r);
    return r;
}

/* ------------------------------------------------------------------ */
/* ioctl                                                              */
/* ------------------------------------------------------------------ */

EXPORT int ioctl(int fd, unsigned long cmd, ...) {
    va_list ap; va_start(ap, cmd); void *arg = va_arg(ap, void *); va_end(ap);
    if (!REAL(ioctl)) { errno = ENOSYS; return -1; }
    if (enabled && should_intercept_ioctl(fd))
        return intercept_ioctl(fd, cmd, arg);
    return real_ioctl(fd, cmd, arg);
}

/* ------------------------------------------------------------------ */
/* read                                                               */
/* ------------------------------------------------------------------ */

EXPORT ssize_t read(int fd, void *buf, size_t count) {
    if (!REAL(read)) { errno = ENOSYS; return -1; }
    if (enabled && should_intercept_read(fd))
        return intercept_read(fd, buf, count);
    return real_read(fd, buf, count);
}

/* ------------------------------------------------------------------ */
/* write                                                              */
/* ------------------------------------------------------------------ */

EXPORT ssize_t write(int fd, const void *buf, size_t count) {
    if (!REAL(write)) { errno = ENOSYS; return -1; }
    if (enabled && should_intercept_write(fd))
        return intercept_write(fd, buf, count);
    return real_write(fd, buf, count);
}

#ifdef UINPUT_EXTRA_INTERCEPTS
EXPORT ssize_t writev(int fd, const struct iovec *iov, int iovcnt) {
    if (!REAL(writev)) { errno = ENOSYS; return -1; }
    if (enabled && vfd_is_active(fd))
        dbg("writev: bypass fd=%d iovcnt=%d type=%s dev=%d",
            fd, iovcnt, vfd_table[fd].type == VFD_UINPUT ? "uinput" : "evdev",
            vfd_table[fd].device_id);
    return real_writev(fd, iov, iovcnt);
}

EXPORT ssize_t splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out,
               size_t len, unsigned int flags) {
    if (!REAL(splice)) { errno = ENOSYS; return -1; }
    if (enabled && (vfd_is_active(fd_in) || vfd_is_active(fd_out))) {
        const char *tin  = vfd_is_active(fd_in)  ? (vfd_table[fd_in].type  == VFD_UINPUT ? "uinput" : "evdev") : "other";
        const char *tout = vfd_is_active(fd_out) ? (vfd_table[fd_out].type == VFD_UINPUT ? "uinput" : "evdev") : "other";
        dbg("splice: bypass fd_in=%d/%s fd_out=%d/%s len=%zu",
            fd_in, tin, fd_out, tout, len);
    }
    return real_splice(fd_in, off_in, fd_out, off_out, len, flags);
}

EXPORT ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count) {
    if (!REAL(sendfile)) { errno = ENOSYS; return -1; }
    if (enabled && (vfd_is_active(out_fd) || vfd_is_active(in_fd))) {
        const char *tout = vfd_is_active(out_fd) ? (vfd_table[out_fd].type == VFD_UINPUT ? "uinput" : "evdev") : "other";
        const char *tin  = vfd_is_active(in_fd)  ? (vfd_table[in_fd].type  == VFD_UINPUT ? "uinput" : "evdev") : "other";
        dbg("sendfile: bypass out_fd=%d/%s in_fd=%d/%s count=%zu", out_fd, tout, in_fd, tin, count);
    }
    return real_sendfile(out_fd, in_fd, offset, count);
}

EXPORT ssize_t sendfile64(int out_fd, int in_fd, off64_t *offset, size_t count) {
    if (!REAL(sendfile64)) { errno = ENOSYS; return -1; }
    if (enabled && (vfd_is_active(out_fd) || vfd_is_active(in_fd))) {
        const char *tout = vfd_is_active(out_fd) ? (vfd_table[out_fd].type == VFD_UINPUT ? "uinput" : "evdev") : "other";
        const char *tin  = vfd_is_active(in_fd)  ? (vfd_table[in_fd].type  == VFD_UINPUT ? "uinput" : "evdev") : "other";
        dbg("sendfile64: bypass out_fd=%d/%s in_fd=%d/%s count=%zu", out_fd, tout, in_fd, tin, count);
    }
    return real_sendfile64(out_fd, in_fd, offset, count);
}

EXPORT ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset) {
    if (!REAL(pwrite)) { errno = ENOSYS; return -1; }
    if (enabled && vfd_is_active(fd))
        dbg("pwrite: bypass fd=%d count=%zu offset=%ld type=%s dev=%d",
            fd, count, (long)offset,
            vfd_table[fd].type == VFD_UINPUT ? "uinput" : "evdev",
            vfd_table[fd].device_id);
    return real_pwrite(fd, buf, count, offset);
}

EXPORT ssize_t pwrite64(int fd, const void *buf, size_t count, off64_t offset) {
    if (!REAL(pwrite64)) { errno = ENOSYS; return -1; }
    if (enabled && vfd_is_active(fd))
        dbg("pwrite64: bypass fd=%d count=%zu offset=%lld type=%s dev=%d",
            fd, count, (long long)offset,
            vfd_table[fd].type == VFD_UINPUT ? "uinput" : "evdev",
            vfd_table[fd].device_id);
    return real_pwrite64(fd, buf, count, offset);
}
#endif

/* ------------------------------------------------------------------ */
/* opendir / scandir / fopen                                          */
/* ------------------------------------------------------------------ */

EXPORT DIR *opendir(const char *path) {
    if (!REAL(opendir)) return NULL;
    char mirror[PATH_MAX];
    if (enabled && sysfs_redirect(path, mirror)) path = mirror;
    return real_opendir(path);
}

EXPORT int scandir(const char *path, struct dirent ***namelist,
                   int (*filter)(const struct dirent *),
                   int (*compar)(const struct dirent **, const struct dirent **)) {
    if (!REAL(scandir)) { errno = ENOSYS; return -1; }
    char mirror[PATH_MAX];
    if (enabled && sysfs_redirect(path, mirror)) path = mirror;
    return real_scandir(path, namelist, filter, compar);
}

EXPORT int scandir64(const char *path, struct dirent64 ***namelist,
                     int (*filter)(const struct dirent64 *),
                     int (*compar)(const struct dirent64 **, const struct dirent64 **)) {
    if (!REAL(scandir64)) { errno = ENOSYS; return -1; }
    char mirror[PATH_MAX];
    if (enabled && sysfs_redirect(path, mirror)) path = mirror;
    return real_scandir64(path, namelist, filter, compar);
}

EXPORT FILE *fopen(const char *path, const char *mode) {
    if (!REAL(fopen)) { errno = ENOSYS; return NULL; }
    char mirror[PATH_MAX];
    if (enabled && sysfs_redirect(path, mirror)) path = mirror;
    return real_fopen(path, mode);
}

EXPORT FILE *fopen64(const char *path, const char *mode) {
    if (!REAL(fopen64)) { errno = ENOSYS; return NULL; }
    char mirror[PATH_MAX];
    if (enabled && sysfs_redirect(path, mirror)) path = mirror;
    return real_fopen64(path, mode);
}

/* ------------------------------------------------------------------ */
/* stat / lstat / stat64 / lstat64 / __xstat* / __lxstat*             */
/* ------------------------------------------------------------------ */

EXPORT int stat(const char *path, struct stat *st) {
    char mirror[PATH_MAX];
    if (enabled && sysfs_redirect(path, mirror)) path = mirror;
    else if (enabled && should_intercept_stat(path))
        return intercept_stat(path, st);
    return REAL(stat) ? real_stat(path, st) : (errno = ENOSYS, -1);
}

EXPORT int lstat(const char *path, struct stat *st) {
    char mirror[PATH_MAX];
    if (enabled && sysfs_redirect(path, mirror)) path = mirror;
    else if (enabled && should_intercept_stat(path))
        return intercept_stat(path, st);
    return REAL(lstat) ? real_lstat(path, st) : (errno = ENOSYS, -1);
}

EXPORT int __xstat(int ver, const char *path, struct stat *st) {
    char mirror[PATH_MAX];
    if (enabled && sysfs_redirect(path, mirror)) path = mirror;
    else if (enabled && should_intercept_stat(path))
        return intercept_stat(path, st);
    return REAL(xstat) ? real_xstat(ver, path, st) : (errno = ENOSYS, -1);
}

EXPORT int __lxstat(int ver, const char *path, struct stat *st) {
    char mirror[PATH_MAX];
    if (enabled && sysfs_redirect(path, mirror)) path = mirror;
    else if (enabled && should_intercept_stat(path))
        return intercept_stat(path, st);
    return REAL(lxstat) ? real_lxstat(ver, path, st) : (errno = ENOSYS, -1);
}

EXPORT int stat64(const char *path, struct stat64 *st) {
    char mirror[PATH_MAX];
    if (enabled && sysfs_redirect(path, mirror)) path = mirror;
    else if (enabled && should_intercept_stat(path))
        return intercept_stat64(path, st);
    return REAL(stat64) ? real_stat64(path, st) : (errno = ENOSYS, -1);
}

EXPORT int lstat64(const char *path, struct stat64 *st) {
    char mirror[PATH_MAX];
    if (enabled && sysfs_redirect(path, mirror)) path = mirror;
    else if (enabled && should_intercept_stat(path))
        return intercept_stat64(path, st);
    return REAL(lstat64) ? real_lstat64(path, st) : (errno = ENOSYS, -1);
}

EXPORT int __xstat64(int ver, const char *path, struct stat64 *st) {
    char mirror[PATH_MAX];
    if (enabled && sysfs_redirect(path, mirror)) path = mirror;
    else if (enabled && should_intercept_stat(path))
        return intercept_stat64(path, st);
    return REAL(xstat64) ? real_xstat64(ver, path, st) : (errno = ENOSYS, -1);
}

EXPORT int __lxstat64(int ver, const char *path, struct stat64 *st) {
    char mirror[PATH_MAX];
    if (enabled && sysfs_redirect(path, mirror)) path = mirror;
    else if (enabled && should_intercept_stat(path))
        return intercept_stat64(path, st);
    return REAL(lxstat64) ? real_lxstat64(ver, path, st) : (errno = ENOSYS, -1);
}

/* ------------------------------------------------------------------ */
/* fstatat / fstatat64 / __fxstatat* / statx                          */
/* ------------------------------------------------------------------ */

static bool is_empty_path_on_vfd(int dfd, const char *path, int flags) {
    return path && path[0] == '\0' && (flags & AT_EMPTY_PATH) && should_intercept_fstat(dfd);
}

EXPORT int fstatat(int dfd, const char *path, struct stat *st, int flags) {
    if (enabled && is_empty_path_on_vfd(dfd, path, flags))
        return intercept_fstat(dfd, st);
    char mirror[PATH_MAX];
    if (enabled && sysfs_redirect_at(dfd, path, mirror)) { path = mirror; dfd = AT_FDCWD; }
    else if (enabled && path && path[0] == '/' && should_intercept_stat(path))
        return intercept_stat(path, st);
    return REAL(fstatat) ? real_fstatat(dfd, path, st, flags) : (errno = ENOSYS, -1);
}

EXPORT int fstatat64(int dfd, const char *path, struct stat64 *st, int flags) {
    if (enabled && is_empty_path_on_vfd(dfd, path, flags))
        return intercept_fstat64(dfd, st);
    char mirror[PATH_MAX];
    if (enabled && sysfs_redirect_at(dfd, path, mirror)) { path = mirror; dfd = AT_FDCWD; }
    else if (enabled && path && path[0] == '/' && should_intercept_stat(path))
        return intercept_stat64(path, st);
    return REAL(fstatat64) ? real_fstatat64(dfd, path, st, flags) : (errno = ENOSYS, -1);
}

EXPORT int __fxstatat(int ver, int dfd, const char *path, struct stat *st, int flags) {
    if (enabled && is_empty_path_on_vfd(dfd, path, flags))
        return intercept_fstat(dfd, st);
    char mirror[PATH_MAX];
    if (enabled && sysfs_redirect_at(dfd, path, mirror)) { path = mirror; dfd = AT_FDCWD; }
    else if (enabled && path && path[0] == '/' && should_intercept_stat(path))
        return intercept_stat(path, st);
    return REAL(fxstatat) ? real_fxstatat(ver, dfd, path, st, flags) : (errno = ENOSYS, -1);
}

EXPORT int __fxstatat64(int ver, int dfd, const char *path, struct stat64 *st, int flags) {
    if (enabled && is_empty_path_on_vfd(dfd, path, flags))
        return intercept_fstat64(dfd, st);
    char mirror[PATH_MAX];
    if (enabled && sysfs_redirect_at(dfd, path, mirror)) { path = mirror; dfd = AT_FDCWD; }
    else if (enabled && path && path[0] == '/' && should_intercept_stat(path))
        return intercept_stat64(path, st);
    return REAL(fxstatat64) ? real_fxstatat64(ver, dfd, path, st, flags) : (errno = ENOSYS, -1);
}

EXPORT int statx(int dfd, const char *path, int flags, unsigned int mask, struct statx *stx) {
    if (enabled && is_empty_path_on_vfd(dfd, path, flags))
        return intercept_fstatx(dfd, stx);
    char mirror[PATH_MAX];
    if (enabled && sysfs_redirect_at(dfd, path, mirror)) { path = mirror; dfd = AT_FDCWD; }
    else if (enabled && path && path[0] == '/' && should_intercept_stat(path))
        return intercept_statx(path, stx);
    return REAL(statx) ? real_statx(dfd, path, flags, mask, stx) : (errno = ENOSYS, -1);
}

/* ------------------------------------------------------------------ */
/* fstat / fstat64 / __fxstat / __fxstat64                            */
/* ------------------------------------------------------------------ */

EXPORT int fstat(int fd, struct stat *st) {
    if (enabled && should_intercept_fstat(fd))
        return intercept_fstat(fd, st);
    return REAL(fstat) ? real_fstat(fd, st) : (errno = ENOSYS, -1);
}

EXPORT int fstat64(int fd, struct stat64 *st) {
    if (enabled && should_intercept_fstat(fd))
        return intercept_fstat64(fd, st);
    return REAL(fstat64) ? real_fstat64(fd, st) : (errno = ENOSYS, -1);
}

EXPORT int __fxstat(int ver, int fd, struct stat *st) {
    if (enabled && should_intercept_fstat(fd))
        return intercept_fstat(fd, st);
    return REAL(fxstat) ? real_fxstat(ver, fd, st) : (errno = ENOSYS, -1);
}

EXPORT int __fxstat64(int ver, int fd, struct stat64 *st) {
    if (enabled && should_intercept_fstat(fd))
        return intercept_fstat64(fd, st);
    return REAL(fxstat64) ? real_fxstat64(ver, fd, st) : (errno = ENOSYS, -1);
}

/* ------------------------------------------------------------------ */
/* fstatfs / fstatfs64                                                */
/* ------------------------------------------------------------------ */

EXPORT int fstatfs(int fd, struct statfs *buf) {
    if (!REAL(fstatfs)) { errno = ENOSYS; return -1; }
    int r = real_fstatfs(fd, buf);
    long type;
    if (enabled && r == 0 && (type = sysfs_mirror_fs_type(fd)) != 0) buf->f_type = type;
    return r;
}

EXPORT int fstatfs64(int fd, struct statfs64 *buf) {
    if (!REAL(fstatfs64)) { errno = ENOSYS; return -1; }
    int r = real_fstatfs64(fd, buf);
    long type;
    if (enabled && r == 0 && (type = sysfs_mirror_fs_type(fd)) != 0) buf->f_type = type;
    return r;
}

/* ------------------------------------------------------------------ */
/* access / faccessat                                                 */
/* ------------------------------------------------------------------ */

EXPORT int access(const char *path, int mode) {
    char mirror[PATH_MAX];
    if (enabled && sysfs_redirect(path, mirror)) path = mirror;
    else if (enabled && should_intercept_access(path))
        return intercept_access(path);
    return REAL(access) ? real_access(path, mode) : (errno = ENOSYS, -1);
}

EXPORT int faccessat(int dfd, const char *path, int mode, int flags) {
    char mirror[PATH_MAX];
    if (enabled && sysfs_redirect_at(dfd, path, mirror)) { path = mirror; dfd = AT_FDCWD; }
    else if (enabled && path && path[0] == '/' && should_intercept_access(path))
        return intercept_access(path);
    return REAL(faccessat) ? real_faccessat(dfd, path, mode, flags) : (errno = ENOSYS, -1);
}

/* ------------------------------------------------------------------ */
/* readlink / readlinkat / __readlinkat_chk                           */
/* ------------------------------------------------------------------ */

EXPORT ssize_t readlink(const char *path, char *buf, size_t bufsz) {
    if (!REAL(readlink)) { errno = ENOSYS; return -1; }
    if (enabled && should_intercept_readlink(path))
        return intercept_readlink(path, buf, bufsz);
    char mirror[PATH_MAX];
    if (enabled && sysfs_redirect(path, mirror)) path = mirror;
    ssize_t n = real_readlink(path, buf, bufsz);
    return (enabled && n > 0) ? sysfs_unredirect(buf, n, bufsz) : n;
}

EXPORT ssize_t readlinkat(int dfd, const char *path, char *buf, size_t bufsz) {
    if (!REAL(readlinkat)) { errno = ENOSYS; return -1; }
    if (enabled && path && path[0] == '/' && should_intercept_readlink(path))
        return intercept_readlink(path, buf, bufsz);
    char mirror[PATH_MAX];
    if (enabled && sysfs_redirect_at(dfd, path, mirror)) { path = mirror; dfd = AT_FDCWD; }
    ssize_t n = real_readlinkat(dfd, path, buf, bufsz);
    return (enabled && n > 0) ? sysfs_unredirect(buf, n, bufsz) : n;
}

EXPORT ssize_t __readlinkat_chk(int dfd, const char *path, char *buf, size_t bufsz, size_t buflen) {
    if (!REAL(__readlinkat_chk)) { errno = ENOSYS; return -1; }
    if (enabled && path && path[0] == '/' && should_intercept_readlink(path))
        return intercept_readlink(path, buf, bufsz);
    char mirror[PATH_MAX];
    if (enabled && sysfs_redirect_at(dfd, path, mirror)) { path = mirror; dfd = AT_FDCWD; }
    ssize_t n = real___readlinkat_chk(dfd, path, buf, bufsz, buflen);
    return (enabled && n > 0) ? sysfs_unredirect(buf, n, bufsz) : n;
}

/* ------------------------------------------------------------------ */
/* realpath / __realpath_chk                                          */
/* ------------------------------------------------------------------ */

static char *unredirect_resolved(char *resolved) {
    if (enabled && resolved)
        sysfs_unredirect(resolved, (ssize_t)strlen(resolved), strlen(resolved) + 1);
    return resolved;
}

EXPORT char *realpath(const char *path, char *resolved) {
    if (!REAL(realpath)) { errno = ENOSYS; return NULL; }
    char mirror[PATH_MAX];
    if (enabled && sysfs_redirect(path, mirror)) path = mirror;
    return unredirect_resolved(real_realpath(path, resolved));
}

EXPORT char *__realpath_chk(const char *path, char *resolved, size_t resolvedlen) {
    if (!REAL(__realpath_chk)) { errno = ENOSYS; return NULL; }
    char mirror[PATH_MAX];
    if (enabled && sysfs_redirect(path, mirror)) path = mirror;
    return unredirect_resolved(real___realpath_chk(path, resolved, resolvedlen));
}

/* ------------------------------------------------------------------ */
/* poll / ppoll                                                       */
/* ------------------------------------------------------------------ */

EXPORT int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    if (!REAL(poll)) { errno = ENOSYS; return -1; }
    if (enabled && should_intercept_poll(fds, nfds))
        return intercept_poll(fds, nfds, timeout);

    /* Log if passing through with our fds */
    for (nfds_t i = 0; i < nfds; i++) {
        if (vfd_is_active(fds[i].fd)) {
            dbg("poll: passthrough nfds=%zu timeout=%d fd=%d type=%d",
                (size_t)nfds, timeout, fds[i].fd, vfd_table[fds[i].fd].type);
            break;
        }
    }

    return real_poll(fds, nfds, timeout);
}

EXPORT int ppoll(struct pollfd *fds, nfds_t nfds,
          const struct timespec *tmo, const sigset_t *sigmask) {
    if (!REAL(ppoll)) { errno = ENOSYS; return -1; }
    if (enabled && should_intercept_poll(fds, nfds))
        return intercept_ppoll(fds, nfds, tmo, sigmask);
    return real_ppoll(fds, nfds, tmo, sigmask);
}

EXPORT int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
           struct timeval *timeout) {
    if (!REAL(select)) { errno = ENOSYS; return -1; }
    if (enabled && should_intercept_select(nfds, readfds, writefds, exceptfds))
        return intercept_select(nfds, readfds, writefds, exceptfds, timeout);
    return real_select(nfds, readfds, writefds, exceptfds, timeout);
}

EXPORT int pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
            const struct timespec *timeout, const sigset_t *sigmask) {
    if (!REAL(pselect)) { errno = ENOSYS; return -1; }
    if (enabled && should_intercept_select(nfds, readfds, writefds, exceptfds))
        return intercept_pselect(nfds, readfds, writefds, exceptfds, timeout, sigmask);
    return real_pselect(nfds, readfds, writefds, exceptfds, timeout, sigmask);
}

EXPORT int epoll_ctl(int epfd, int op, int fd, struct epoll_event *ev) {
    if (!REAL(epoll_ctl)) { errno = ENOSYS; return -1; }
    if (enabled && should_intercept_epoll_ctl(epfd, op, fd))
        return intercept_epoll_ctl(epfd, op, fd, ev);
    return real_epoll_ctl(epfd, op, fd, ev);
}

EXPORT int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) {
    if (!REAL(epoll_wait)) { errno = ENOSYS; return -1; }
    if (enabled && should_intercept_epoll_wait(epfd))
        return intercept_epoll_wait(epfd, events, maxevents, timeout);
    return real_epoll_wait(epfd, events, maxevents, timeout);
}

EXPORT int epoll_pwait(int epfd, struct epoll_event *events, int maxevents, int timeout,
                const sigset_t *sigmask) {
    if (!REAL(epoll_pwait)) { errno = ENOSYS; return -1; }
    if (enabled && should_intercept_epoll_wait(epfd))
        return intercept_epoll_pwait(epfd, events, maxevents, timeout, sigmask);
    return real_epoll_pwait(epfd, events, maxevents, timeout, sigmask);
}

#ifdef UINPUT_EXTRA_INTERCEPTS
/* ------------------------------------------------------------------ */
/* inotify                                                            */
/* ------------------------------------------------------------------ */

/* Track which inotify fds have input-related watches */
#define INOTIFY_TRACK_MAX 32
static int inotify_input_fds[INOTIFY_TRACK_MAX];
static int inotify_input_count = 0;

static void inotify_track_add(int fd) {
    for (int i = 0; i < inotify_input_count; i++)
        if (inotify_input_fds[i] == fd) return;  /* already tracked */
    if (inotify_input_count < INOTIFY_TRACK_MAX)
        inotify_input_fds[inotify_input_count++] = fd;
}

static bool inotify_track_has(int fd) {
    for (int i = 0; i < inotify_input_count; i++)
        if (inotify_input_fds[i] == fd) return true;
    return false;
}

static bool is_input_watch_path(const char *path) {
    return classify_path(path).cls != PATH_NONE;
}

EXPORT int inotify_init(void) {
    if (!REAL(inotify_init)) { errno = ENOSYS; return -1; }
    return real_inotify_init();
}

EXPORT int inotify_init1(int flags) {
    if (!REAL(inotify_init1)) { errno = ENOSYS; return -1; }
    return real_inotify_init1(flags);
}

EXPORT int inotify_add_watch(int fd, const char *pathname, uint32_t mask) {
    if (!REAL(inotify_add_watch)) { errno = ENOSYS; return -1; }
    int wd = real_inotify_add_watch(fd, pathname, mask);
    if (enabled && is_input_watch_path(pathname)) {
        inotify_track_add(fd);
        dbg("inotify_add_watch: fd=%d wd=%d path=%s mask=0x%x",
            fd, wd, pathname, mask);
    }
    return wd;
}

EXPORT int inotify_rm_watch(int fd, int wd) {
    if (!REAL(inotify_rm_watch)) { errno = ENOSYS; return -1; }
    if (enabled && inotify_track_has(fd))
        dbg("inotify_rm_watch: fd=%d wd=%d", fd, wd);
    return real_inotify_rm_watch(fd, wd);
}
#endif
