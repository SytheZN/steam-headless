#pragma once
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <dirent.h>
#include <poll.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <sys/sendfile.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <string.h>
#include <limits.h>
#include <linux/futex.h>
#include <linux/input.h>

#include "protocol.h"

/* Mark libc interposition entry points visible; everything else is
   hidden via -fvisibility=hidden so it never hits the dynamic symbol table. */
#define EXPORT __attribute__((visibility("default")))

/* ------------------------------------------------------------------ */
/* Global flags (defined in preload.c)                                */
/* ------------------------------------------------------------------ */

extern bool        enabled;
extern FILE       *debug_log;
extern pid_t       log_pid;
extern const char *log_proc;

static inline void dbg_print(FILE *f, pid_t pid, const char *proc,
                             const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

static inline void dbg_print(FILE *f, pid_t pid, const char *proc,
                             const char *fmt, ...) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);
    fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d.%03ld] [uinput-preload] ",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec / 1000000);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fprintf(f, " pid=%d proc=%s\n", pid, proc);
    fflush(f);
}

#define dbg(fmt, ...) \
    do { if (debug_log) dbg_print(debug_log, log_pid, log_proc, fmt, ##__VA_ARGS__); } while (0)

/* ------------------------------------------------------------------ */
/* Real function pointers (defined in preload.c)                      */
/* ------------------------------------------------------------------ */

extern int      (*real_open)(const char *, int, ...);
extern int      (*real_open64)(const char *, int, ...);
extern int      (*real_openat)(int, const char *, int, ...);
extern int      (*real_openat64)(int, const char *, int, ...);
extern int      (*real_close)(int);
extern ssize_t  (*real_read)(int, void *, size_t);
extern ssize_t  (*real_write)(int, const void *, size_t);
extern int      (*real_ioctl)(int, unsigned long, ...);
extern int      (*real_dup)(int);
extern int      (*real_dup2)(int, int);
extern int      (*real_dup3)(int, int, int);
extern int      (*real_fcntl)(int, int, ...);
extern DIR    * (*real_opendir)(const char *);
extern int      (*real_stat)(const char *, struct stat *);
extern int      (*real_stat64)(const char *, struct stat64 *);
extern int      (*real_lstat)(const char *, struct stat *);
extern int      (*real_lstat64)(const char *, struct stat64 *);
extern int      (*real_fstat)(int, struct stat *);
extern int      (*real_fstat64)(int, struct stat64 *);
extern int      (*real_fxstat)(int, int, struct stat *);
extern int      (*real_fxstat64)(int, int, struct stat64 *);
extern int      (*real_access)(const char *, int);
extern int      (*real_faccessat)(int, const char *, int, int);
extern ssize_t  (*real_readlink)(const char *, char *, size_t);
extern int      (*real_poll)(struct pollfd *, nfds_t, int);
extern int      (*real_ppoll)(struct pollfd *, nfds_t,
                               const struct timespec *, const sigset_t *);
extern int      (*real_xstat)(int, const char *, struct stat *);
extern int      (*real_lxstat)(int, const char *, struct stat *);
extern int      (*real_xstat64)(int, const char *, struct stat64 *);
extern int      (*real_lxstat64)(int, const char *, struct stat64 *);
extern int      (*real_select)(int, fd_set *, fd_set *, fd_set *, struct timeval *);
extern int      (*real_pselect)(int, fd_set *, fd_set *, fd_set *,
                                 const struct timespec *, const sigset_t *);
extern int      (*real_epoll_ctl)(int, int, int, struct epoll_event *);
extern int      (*real_epoll_wait)(int, struct epoll_event *, int, int);
extern int      (*real_epoll_pwait)(int, struct epoll_event *, int, int, const sigset_t *);
extern int      (*real_inotify_init)(void);
extern int      (*real_inotify_init1)(int);
extern int      (*real_inotify_add_watch)(int, const char *, uint32_t);
extern int      (*real_inotify_rm_watch)(int, int);
extern int      (*real_fstatat)(int, const char *, struct stat *, int);
extern int      (*real_fstatat64)(int, const char *, struct stat64 *, int);
extern int      (*real_fxstatat)(int, int, const char *, struct stat *, int);
extern int      (*real_fxstatat64)(int, int, const char *, struct stat64 *, int);
extern int      (*real_statx)(int, const char *, int, unsigned int, struct statx *);
extern ssize_t  (*real_readlinkat)(int, const char *, char *, size_t);
extern char   * (*real_realpath)(const char *, char *);
extern char   * (*real___realpath_chk)(const char *, char *, size_t);
extern FILE   * (*real_fopen)(const char *, const char *);
extern FILE   * (*real_fopen64)(const char *, const char *);
extern int      (*real_scandir)(const char *, struct dirent ***,
                                int (*)(const struct dirent *),
                                int (*)(const struct dirent **, const struct dirent **));
extern int      (*real_scandir64)(const char *, struct dirent64 ***,
                                  int (*)(const struct dirent64 *),
                                  int (*)(const struct dirent64 **, const struct dirent64 **));
extern int      (*real___open_2)(const char *, int);
extern int      (*real___open64_2)(const char *, int);
extern int      (*real___openat_2)(int, const char *, int);
extern int      (*real___openat64_2)(int, const char *, int);
extern ssize_t  (*real___readlinkat_chk)(int, const char *, char *, size_t, size_t);
extern int      (*real_fstatfs)(int, struct statfs *);
extern int      (*real_fstatfs64)(int, struct statfs64 *);

bool    sysfs_redirect(const char *path, char *mirror);
bool    sysfs_redirect_at(int dirfd, const char *path, char *mirror);
ssize_t sysfs_unredirect(char *path, ssize_t len, size_t bufsz);
long    sysfs_mirror_fs_type(int fd);

/* ------------------------------------------------------------------ */
/* Path classification                                                */
/* ------------------------------------------------------------------ */

typedef enum {
    PATH_NONE = 0,
    PATH_UINPUT,
    PATH_DEV_INPUT_DIR,
    PATH_EVDEV,
    PATH_PROC_SELF_FD,
} path_class_t;

typedef struct {
    path_class_t cls;
    int          dev_id;
} path_info_t;

path_info_t classify_path(const char *path);

/* ------------------------------------------------------------------ */
/* Virtual FD table                                                   */
/* ------------------------------------------------------------------ */

#define VFD_MAX 4096

typedef enum { VFD_UINPUT = 0, VFD_EVDEV = 1, VFD_SYSFS = 2 } vfd_type_t;

struct evdev_reader {
    _Atomic int               refs;
    const struct evdev_shmem *shmem;
    int                       doorbell;
    uint64_t                  read_pos;
    uint32_t                  clock_type;
};

struct evdev_reader *evdev_reader_new(const struct evdev_shmem *shmem, int doorbell);
void                 evdev_reader_release(struct evdev_reader *reader);
bool                 evdev_reader_has_packet(const struct evdev_reader *reader);
void                 evdev_reader_sync_doorbell(struct evdev_reader *reader);
bool                 evdev_socket_hung_up(int sock);

struct virtual_fd {
    _Atomic bool         active;
    vfd_type_t           type;
    int                  device_id;
    int                  flags;
    bool                 created;
    struct evdev_reader *reader;
};

extern struct virtual_fd vfd_table[VFD_MAX];

/* Populate all fields, then publish active=true with release ordering.
 * Other threads that acquire-load active=true see all fields. */
static inline void vfd_set(int fd, vfd_type_t type, int device_id) {
    if (fd < 0 || fd >= VFD_MAX) return;
    vfd_table[fd].type       = type;
    vfd_table[fd].device_id  = device_id;
    vfd_table[fd].flags      = 0;
    vfd_table[fd].created    = false;
    vfd_table[fd].reader     = NULL;
    atomic_store_explicit(&vfd_table[fd].active, true, memory_order_release);
}

static inline void vfd_set_flags(int fd, int flags) {
    if (fd >= 0 && fd < VFD_MAX)
        vfd_table[fd].flags = flags;
}

static inline void vfd_dup(int oldfd, int newfd) {
    if (oldfd < 0 || oldfd >= VFD_MAX || newfd < 0 || newfd >= VFD_MAX) return;
    struct virtual_fd *src = &vfd_table[oldfd];
    struct virtual_fd *dst = &vfd_table[newfd];
    dst->type       = src->type;
    dst->device_id  = src->device_id;
    dst->flags      = src->flags;
    dst->created    = src->created;
    dst->reader     = src->reader;
    if (dst->reader)
        atomic_fetch_add_explicit(&dst->reader->refs, 1, memory_order_relaxed);
    atomic_store_explicit(&dst->active,
        atomic_load_explicit(&src->active, memory_order_relaxed),
        memory_order_release);
}

static inline void vfd_clear(int fd) {
    if (fd < 0 || fd >= VFD_MAX) return;
    atomic_store_explicit(&vfd_table[fd].active, false, memory_order_release);
    if (vfd_table[fd].reader) {
        evdev_reader_release(vfd_table[fd].reader);
        vfd_table[fd].reader = NULL;
    }
}

static inline bool vfd_is_active(int fd) {
    return fd >= 0 && fd < VFD_MAX &&
           atomic_load_explicit(&vfd_table[fd].active, memory_order_acquire);
}

/* ------------------------------------------------------------------ */
/* Wire event conversion (native <-> 24-byte wire format)             */
/* 64-bit: input_event is already 24 bytes. 32-bit: widen timeval.    */
/* ------------------------------------------------------------------ */

#if __SIZEOF_LONG__ == 4
static inline void native_to_wire(const struct input_event *ev, uint8_t *out) {
    int64_t sec  = (int64_t)ev->time.tv_sec;
    int64_t usec = (int64_t)ev->time.tv_usec;
    memcpy(out,      &sec,       8);
    memcpy(out + 8,  &usec,      8);
    memcpy(out + 16, &ev->type,  2);
    memcpy(out + 18, &ev->code,  2);
    memcpy(out + 20, &ev->value, 4);
}

static inline void wire_to_native(const uint8_t *in, struct input_event *ev) {
    int64_t sec, usec;
    memcpy(&sec,  in,     8);
    memcpy(&usec, in + 8, 8);
    ev->time.tv_sec  = (long)sec;
    ev->time.tv_usec = (long)usec;
    memcpy(&ev->type,  in + 16, 2);
    memcpy(&ev->code,  in + 18, 2);
    memcpy(&ev->value, in + 20, 4);
}
#else
static inline void native_to_wire(const struct input_event *ev, uint8_t *out) {
    memcpy(out, ev, WIRE_EVENT_SIZE);
}

static inline void wire_to_native(const uint8_t *in, struct input_event *ev) {
    memcpy(ev, in, WIRE_EVENT_SIZE);
}
#endif

/* ------------------------------------------------------------------ */
/* Wire I/O helpers (preload-helpers.c)                               */
/* ------------------------------------------------------------------ */

int send_all_r(int fd, const void *buf, size_t len);
int recv_all_r(int fd, void *buf, size_t len);
int send_msg_r(int fd, msg_type_t type, const void *payload, uint32_t plen);
int recv_msg_r(int fd, void *buf, size_t bufsz, uint32_t *plen_out);

/* ------------------------------------------------------------------ */
/* Daemon connection + device query (preload-helpers.c)               */
/* ------------------------------------------------------------------ */

int  connect_to_daemon(void);
int  recv_fds(int sock, int *fds, int nfds);
int  query_device_list(int *ids);
bool device_exists(int dev_id);

void fill_chr_stat(struct stat *st, dev_t rdev);
void fill_chr_stat64(struct stat64 *st, dev_t rdev);
void fill_chr_statx(struct statx *stx, dev_t rdev);

/* ------------------------------------------------------------------ */
/* Intercept predicates + handlers                                    */
/* ------------------------------------------------------------------ */

bool    should_intercept_open(const char *path);
int     intercept_open(const char *path, int flags, mode_t mode);

bool    should_intercept_openat(int dfd, const char *path);
int     intercept_openat(int dfd, const char *path, int flags, mode_t mode);

bool    should_intercept_ioctl(int fd);
int     intercept_ioctl(int fd, unsigned long cmd, void *arg);

bool    should_intercept_read(int fd);
ssize_t intercept_read(int fd, void *buf, size_t count);

bool    should_intercept_write(int fd);
ssize_t intercept_write(int fd, const void *buf, size_t count);

bool    should_intercept_stat(const char *path);
int     intercept_stat(const char *path, struct stat *st);
int     intercept_stat64(const char *path, struct stat64 *st);
int     intercept_statx(const char *path, struct statx *stx);

bool    should_intercept_fstat(int fd);
int     intercept_fstat(int fd, struct stat *st);
int     intercept_fstat64(int fd, struct stat64 *st);
int     intercept_fstatx(int fd, struct statx *stx);

bool    should_intercept_access(const char *path);
int     intercept_access(const char *path);

bool    should_intercept_readlink(const char *path);
ssize_t intercept_readlink(const char *path, char *buf, size_t bufsz);

bool should_intercept_poll(struct pollfd *fds, nfds_t nfds);
int  intercept_poll(struct pollfd *fds, nfds_t nfds, int timeout_ms);
int  intercept_ppoll(struct pollfd *fds, nfds_t nfds,
                     const struct timespec *tmo, const sigset_t *sigmask);

bool should_intercept_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds);
int  intercept_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
                      struct timeval *timeout);
int  intercept_pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
                       const struct timespec *timeout, const sigset_t *sigmask);

bool should_intercept_fcntl(int fd, int cmd);
int  intercept_fcntl(int fd, int cmd, long arg);

bool should_intercept_close(int fd);
int  intercept_close(int fd);
void release_vfd(int fd);

bool should_intercept_epoll_ctl(int epfd, int op, int fd);
int  intercept_epoll_ctl(int epfd, int op, int fd, struct epoll_event *ev);

bool should_intercept_epoll_wait(int epfd);
int  intercept_epoll_wait(int epfd, struct epoll_event *events,
                          int maxevents, int timeout);
int  intercept_epoll_pwait(int epfd, struct epoll_event *events,
                           int maxevents, int timeout, const sigset_t *sigmask);

/* ------------------------------------------------------------------ */
/* Epoll virtual-fd registration table                                */
/* ------------------------------------------------------------------ */

#define EPOLL_TRACK_MAX  64
#define EPOLL_VFD_MAX    64

struct epoll_vfd_entry {
    int            fd;
    int            doorbell;
    uint32_t       events;
    epoll_data_t   data;
    bool           disarmed;
    bool           pending;
};

struct epoll_track_entry {
    _Atomic bool         active;
    int                  epfd;
    int                  inner_epfd;
    int                  kick;
    struct epoll_vfd_entry vfds[EPOLL_VFD_MAX];
    int                  count;
};

bool should_intercept_epoll_close(int fd);
void intercept_epoll_close(int fd);
void epoll_forget_vfd(int fd);

extern struct epoll_track_entry epoll_table[EPOLL_TRACK_MAX];
