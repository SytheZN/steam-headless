#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>
#include <sys/eventfd.h>
#include <sys/resource.h>

#include "preload.h"

#define READ_EVENTS     (POLLIN | POLLRDNORM)
#define WRITE_EVENTS    (POLLOUT | POLLWRNORM)
#define HANGUP_EVENTS   (POLLHUP | POLLERR)
#define SOCKET_HANGUP   (POLLRDHUP | POLLHUP | POLLERR | POLLNVAL)
#define POLL_STACK_MAX  256
#define NSEC_PER_SEC    1000000000ULL
#define NSEC_PER_MSEC   1000000ULL
#define MAX_TIMEOUT_SEC (UINT64_MAX / NSEC_PER_SEC / 2)

static const struct timespec zero_timeout;

static bool is_vfd(int fd, vfd_type_t type) {
    return vfd_is_active(fd) && vfd_table[fd].type == type;
}

static bool is_waitable_vfd(int fd) {
    return is_vfd(fd, VFD_EVDEV) || is_vfd(fd, VFD_UINPUT);
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * NSEC_PER_SEC + (uint64_t)ts.tv_nsec;
}

static struct timespec ns_to_timespec(uint64_t ns) {
    return (struct timespec){ .tv_sec  = (time_t)(ns / NSEC_PER_SEC),
                              .tv_nsec = (long)  (ns % NSEC_PER_SEC) };
}

static bool timespec_valid(const struct timespec *ts) {
    return ts->tv_sec >= 0 && ts->tv_nsec >= 0 && (uint64_t)ts->tv_nsec < NSEC_PER_SEC;
}

static bool deadline_from_timeout(const struct timespec *timeout, uint64_t *deadline) {
    if (!timeout || (uint64_t)timeout->tv_sec > MAX_TIMEOUT_SEC) return false;
    *deadline = now_ns() + (uint64_t)timeout->tv_sec * NSEC_PER_SEC + (uint64_t)timeout->tv_nsec;
    return true;
}

static struct timespec remaining_until(uint64_t deadline) {
    uint64_t now = now_ns();
    return ns_to_timespec(deadline > now ? deadline - now : 0);
}

static const char *vfd_type_name_poll(int fd) {
    switch (vfd_table[fd].type) {
        case VFD_UINPUT: return "uinput";
        case VFD_EVDEV:  return "evdev";
        case VFD_SYSFS:  return "sysfs";
        default:         return "?";
    }
}

static void log_poll(const char *name, const struct pollfd *fds, nfds_t nfds) {
    if (!debug_log) return;
    char fdbuf[256];
    int pos = 0;
    for (nfds_t i = 0; i < nfds && pos < (int)sizeof(fdbuf) - 1; i++) {
        int fd = fds[i].fd;
        const char *type = vfd_is_active(fd) ? vfd_type_name_poll(fd) : "other";
        pos += snprintf(fdbuf + pos, sizeof(fdbuf) - (size_t)pos,
                        " fd=%d/%s/0x%x", fd, type, (unsigned)fds[i].events);
    }
    dbg("%s: nfds=%zu%s", name, (size_t)nfds, fdbuf);
}

/* ------------------------------------------------------------------ */
/* poll / ppoll                                                       */
/* ------------------------------------------------------------------ */

bool should_intercept_poll(struct pollfd *fds, nfds_t nfds) {
    for (nfds_t i = 0; i < nfds; i++)
        if (is_waitable_vfd(fds[i].fd)) return true;
    return false;
}

static short evdev_revents(int fd, short requested, bool hung_up) {
    short mask = hung_up ? HANGUP_EVENTS : WRITE_EVENTS;
    if (evdev_reader_has_packet(vfd_table[fd].reader))
        mask |= READ_EVENTS;
    return mask & (requested | HANGUP_EVENTS);
}

/* Kernel uinput_poll() unconditionally returns EPOLLOUT|EPOLLWRNORM */
static short uinput_revents(short socket_revents, short requested) {
    short mask = WRITE_EVENTS | (socket_revents & (READ_EVENTS | HANGUP_EVENTS));
    return mask & (requested | HANGUP_EVENTS);
}

static bool ready_without_waiting(const struct pollfd *fds, nfds_t nfds) {
    for (nfds_t i = 0; i < nfds; i++) {
        int fd = fds[i].fd;
        if (is_waitable_vfd(fd) && (fds[i].events & WRITE_EVENTS))
            return true;
        if (is_vfd(fd, VFD_EVDEV) && (fds[i].events & READ_EVENTS) &&
                evdev_reader_has_packet(vfd_table[fd].reader))
            return true;
    }
    return false;
}

/* A fake evdev fd is waited on as two kernel fds: its daemon socket with
 * POLLRDHUP, which the daemon's shutdown() raises when the device goes away,
 * and, when reads are requested, its doorbell eventfd, which is readable while
 * unread packets exist. Readiness itself is computed from the shared ring. */
static nfds_t build_kernel_fds(const struct pollfd *fds, nfds_t nfds,
                               struct pollfd *kfds, nfds_t *doorbell_owner) {
    nfds_t ndoorbells = 0;
    for (nfds_t i = 0; i < nfds; i++) {
        int fd = fds[i].fd;
        short events = fds[i].events;
        if (is_vfd(fd, VFD_EVDEV)) {
            kfds[i] = (struct pollfd){ .fd = fd, .events = POLLRDHUP };
            if (events & READ_EVENTS) {
                kfds[nfds + ndoorbells] = (struct pollfd){
                    .fd = vfd_table[fd].reader->doorbell, .events = POLLIN };
                doorbell_owner[ndoorbells++] = i;
            }
        } else if (is_vfd(fd, VFD_UINPUT)) {
            kfds[i] = (struct pollfd){ .fd = fd, .events = events & READ_EVENTS };
        } else {
            kfds[i] = (struct pollfd){ .fd = fd, .events = events };
        }
    }
    return nfds + ndoorbells;
}

static int collect_revents(struct pollfd *fds, nfds_t nfds, const struct pollfd *kfds) {
    int ready = 0;
    for (nfds_t i = 0; i < nfds; i++) {
        int fd = fds[i].fd;
        short kernel_revents = kfds[i].revents;
        if (is_vfd(fd, VFD_EVDEV))
            fds[i].revents = evdev_revents(fd, fds[i].events, kernel_revents & SOCKET_HANGUP);
        else if (is_vfd(fd, VFD_UINPUT))
            fds[i].revents = uinput_revents(kernel_revents, fds[i].events);
        else
            fds[i].revents = kernel_revents;
        if (fds[i].revents) ready++;
    }
    return ready;
}

static void clear_stale_doorbells(const struct pollfd *fds, nfds_t nfds,
                                  const struct pollfd *kfds, nfds_t nkfds,
                                  const nfds_t *doorbell_owner) {
    for (nfds_t k = nfds; k < nkfds; k++)
        if (kfds[k].revents & POLLIN)
            evdev_reader_sync_doorbell(vfd_table[fds[doorbell_owner[k - nfds]].fd].reader);
}

static int wait_for_events(struct pollfd *fds, nfds_t nfds,
                           const struct timespec *timeout, const sigset_t *sigmask) {
    struct rlimit nofile;
    if (getrlimit(RLIMIT_NOFILE, &nofile) == 0 && nfds > nofile.rlim_cur) {
        errno = EINVAL;
        return -1;
    }

    struct pollfd kfds_stack[2 * POLL_STACK_MAX];
    nfds_t        owner_stack[POLL_STACK_MAX];
    struct pollfd *kfds           = kfds_stack;
    nfds_t        *doorbell_owner = owner_stack;
    if (nfds > POLL_STACK_MAX) {
        kfds           = malloc(2 * nfds * sizeof(*kfds));
        doorbell_owner = malloc(nfds * sizeof(*doorbell_owner));
        if (!kfds || !doorbell_owner) {
            free(kfds); free(doorbell_owner);
            errno = ENOMEM;
            return -1;
        }
    }

    nfds_t nkfds = build_kernel_fds(fds, nfds, kfds, doorbell_owner);
    uint64_t deadline;
    bool has_deadline = deadline_from_timeout(timeout, &deadline);

    int ret;
    for (;;) {
        bool ready = ready_without_waiting(fds, nfds);
        struct timespec remaining;
        const struct timespec *wait_for = NULL;
        if (ready) {
            wait_for = &zero_timeout;
        } else if (has_deadline) {
            remaining = remaining_until(deadline);
            wait_for  = &remaining;
        }
        bool last_pass = !ready && wait_for &&
                         wait_for->tv_sec == 0 && wait_for->tv_nsec == 0;

        for (nfds_t k = 0; k < nkfds; k++) kfds[k].revents = 0;
        int rc = real_ppoll(kfds, nkfds, wait_for, ready ? NULL : sigmask);
        if (rc < 0 && errno != EINTR) { ret = -1; break; }

        ret = collect_revents(fds, nfds, kfds);
        if (ret > 0) break;
        if (rc < 0) { errno = EINTR; ret = -1; break; }
        if (last_pass) break;
        clear_stale_doorbells(fds, nfds, kfds, nkfds, doorbell_owner);
    }

    if (kfds != kfds_stack) {
        int saved_errno = errno;
        free(kfds); free(doorbell_owner);
        errno = saved_errno;
    }
    return ret;
}

int intercept_poll(struct pollfd *fds, nfds_t nfds, int timeout_ms) {
    log_poll("poll", fds, nfds);
    if (timeout_ms < 0)
        return wait_for_events(fds, nfds, NULL, NULL);
    struct timespec timeout = { .tv_sec  = timeout_ms / 1000,
                                .tv_nsec = (long)(timeout_ms % 1000) * (long)NSEC_PER_MSEC };
    return wait_for_events(fds, nfds, &timeout, NULL);
}

int intercept_ppoll(struct pollfd *fds, nfds_t nfds,
                    const struct timespec *tmo, const sigset_t *sigmask) {
    log_poll("ppoll", fds, nfds);
    if (tmo && !timespec_valid(tmo)) { errno = EINVAL; return -1; }
    return wait_for_events(fds, nfds, tmo, sigmask);
}

/* ------------------------------------------------------------------ */
/* select / pselect                                                   */
/* ------------------------------------------------------------------ */

#define SELECT_READ_EVENTS   (POLLIN | POLLRDNORM | POLLRDBAND)
#define SELECT_WRITE_EVENTS  (POLLOUT | POLLWRNORM | POLLWRBAND)
#define SELECT_EXCEPT_EVENTS (POLLPRI)
#define SELECT_READ_READY    (SELECT_READ_EVENTS | POLLHUP | POLLERR)
#define SELECT_WRITE_READY   (SELECT_WRITE_EVENTS | POLLERR)

static int select_limit(int nfds) {
    return nfds < FD_SETSIZE ? nfds : FD_SETSIZE;
}

bool should_intercept_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds) {
    for (int fd = 0; fd < select_limit(nfds); fd++) {
        if (!is_waitable_vfd(fd)) continue;
        if ((readfds && FD_ISSET(fd, readfds)) || (writefds && FD_ISSET(fd, writefds)) ||
            (exceptfds && FD_ISSET(fd, exceptfds)))
            return true;
    }
    return false;
}

static int select_via_poll(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
                           bool has_deadline, uint64_t deadline, const sigset_t *sigmask) {
    if (nfds < 0) { errno = EINVAL; return -1; }

    struct pollfd pfds[FD_SETSIZE];
    nfds_t n = 0;
    for (int fd = 0; fd < select_limit(nfds); fd++) {
        short events = 0;
        if (readfds   && FD_ISSET(fd, readfds))   events |= SELECT_READ_EVENTS;
        if (writefds  && FD_ISSET(fd, writefds))  events |= SELECT_WRITE_EVENTS;
        if (exceptfds && FD_ISSET(fd, exceptfds)) events |= SELECT_EXCEPT_EVENTS;
        if (!events) continue;
        if (real_fcntl(fd, F_GETFD) < 0) { errno = EBADF; return -1; }
        pfds[n++] = (struct pollfd){ .fd = fd, .events = events };
    }

    for (;;) {
        struct timespec remaining;
        const struct timespec *wait_for = NULL;
        if (has_deadline) {
            remaining = remaining_until(deadline);
            wait_for  = &remaining;
        }
        int rc = wait_for_events(pfds, n, wait_for, sigmask);
        if (rc < 0) return -1;

        int bits = 0;
        if (readfds)   FD_ZERO(readfds);
        if (writefds)  FD_ZERO(writefds);
        if (exceptfds) FD_ZERO(exceptfds);
        for (nfds_t i = 0; i < n; i++) {
            short requested = pfds[i].events;
            short revents   = pfds[i].revents;
            if ((requested & SELECT_READ_EVENTS) && (revents & SELECT_READ_READY)) {
                FD_SET(pfds[i].fd, readfds); bits++;
            }
            if ((requested & SELECT_WRITE_EVENTS) && (revents & SELECT_WRITE_READY)) {
                FD_SET(pfds[i].fd, writefds); bits++;
            }
            if ((requested & SELECT_EXCEPT_EVENTS) && (revents & SELECT_EXCEPT_EVENTS)) {
                FD_SET(pfds[i].fd, exceptfds); bits++;
            }
        }
        if (bits > 0 || rc == 0) return bits;

        for (nfds_t i = 0; i < n; i++) {
            if (pfds[i].events & SELECT_READ_EVENTS)   FD_SET(pfds[i].fd, readfds);
            if (pfds[i].events & SELECT_WRITE_EVENTS)  FD_SET(pfds[i].fd, writefds);
            if (pfds[i].events & SELECT_EXCEPT_EVENTS) FD_SET(pfds[i].fd, exceptfds);
        }
    }
}

int intercept_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
                     struct timeval *timeout) {
    dbg("select: nfds=%d", nfds);
    struct timespec ts;
    const struct timespec *tsp = NULL;
    if (timeout) {
        if (timeout->tv_sec < 0 || timeout->tv_usec < 0) { errno = EINVAL; return -1; }
        ts.tv_sec  = timeout->tv_sec + timeout->tv_usec / 1000000;
        ts.tv_nsec = (long)(timeout->tv_usec % 1000000) * 1000L;
        tsp = &ts;
    }

    uint64_t deadline = 0;
    bool has_deadline = deadline_from_timeout(tsp, &deadline);
    int ret = select_via_poll(nfds, readfds, writefds, exceptfds, has_deadline, deadline, NULL);

    if (has_deadline && (ts.tv_sec || ts.tv_nsec)) {
        int saved_errno = errno;
        struct timespec left = remaining_until(deadline);
        timeout->tv_sec  = left.tv_sec;
        timeout->tv_usec = left.tv_nsec / 1000;
        errno = saved_errno;
    }
    return ret;
}

int intercept_pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
                      const struct timespec *timeout, const sigset_t *sigmask) {
    dbg("pselect: nfds=%d", nfds);
    if (timeout && !timespec_valid(timeout)) { errno = EINVAL; return -1; }
    uint64_t deadline = 0;
    bool has_deadline = deadline_from_timeout(timeout, &deadline);
    return select_via_poll(nfds, readfds, writefds, exceptfds, has_deadline, deadline, sigmask);
}

/* ------------------------------------------------------------------ */
/* fcntl                                                              */
/* ------------------------------------------------------------------ */

bool should_intercept_fcntl(int fd, int cmd) {
    if (!vfd_is_active(fd)) return false;
    return (cmd == F_GETFL || cmd == F_SETFL);
}

int intercept_fcntl(int fd, int cmd, long arg) {
    dbg("fcntl: fd=%d cmd=%d arg=0x%lx", fd, cmd, arg);

    if (cmd == F_GETFL)
        return vfd_table[fd].flags & ~O_CLOEXEC;

    if (cmd == F_SETFL) {
        int preserve = vfd_table[fd].flags & (O_ACCMODE | O_CLOEXEC);
        int new_flags = preserve | ((int)arg & ~(O_ACCMODE | O_CLOEXEC));
        vfd_set_flags(fd, new_flags);
        return 0;
    }

    errno = EINVAL;
    return -1;
}

/* ------------------------------------------------------------------ */
/* close                                                              */
/* ------------------------------------------------------------------ */

void release_vfd(int fd) {
    if (is_vfd(fd, VFD_EVDEV))
        epoll_forget_vfd(fd);
    vfd_clear(fd);
}

bool should_intercept_close(int fd) {
    return vfd_is_active(fd) || should_intercept_epoll_close(fd);
}

int intercept_close(int fd) {
    if (!vfd_is_active(fd)) {
        intercept_epoll_close(fd);
        return real_close(fd);
    }
    dbg("close: fd=%d type=%d dev=%d", fd, vfd_table[fd].type, vfd_table[fd].device_id);
    release_vfd(fd);
    return real_close(fd);
}

/* ------------------------------------------------------------------ */
/* epoll_ctl / epoll_wait / epoll_pwait                               */
/* ------------------------------------------------------------------ */

#define KICK_TAG               UINT64_MAX
#define EPOLLEXCLUSIVE_OK_BITS (EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP | \
                                EPOLLWAKEUP | EPOLLET | EPOLLEXCLUSIVE)
#define EPOLL_READ_EVENTS      (EPOLLIN | EPOLLRDNORM)
#define EPOLL_WRITE_EVENTS     (EPOLLOUT | EPOLLWRNORM)
#define EPOLL_MODE_FLAGS       (EPOLLET | EPOLLONESHOT)

static uint64_t inner_tag(int slot, bool is_doorbell) {
    return ((uint64_t)slot << 1) | (is_doorbell ? 1 : 0);
}

static uint64_t outer_tag(const struct epoll_track_entry *te) {
    return (uint64_t)(uintptr_t)te;
}

static struct epoll_track_entry *epoll_track_find(int epfd) {
    for (int i = 0; i < EPOLL_TRACK_MAX; i++)
        if (atomic_load_explicit(&epoll_table[i].active, memory_order_acquire)
                && epoll_table[i].epfd == epfd)
            return &epoll_table[i];
    return NULL;
}

static int epoll_find_slot(const struct epoll_track_entry *te, int fd) {
    for (int j = 0; j < EPOLL_VFD_MAX; j++)
        if (te->vfds[j].fd == fd) return j;
    return -1;
}

static struct epoll_track_entry *epoll_track_alloc(int epfd) {
    for (int i = 0; i < EPOLL_TRACK_MAX; i++) {
        struct epoll_track_entry *te = &epoll_table[i];
        if (atomic_load_explicit(&te->active, memory_order_acquire)) continue;

        int inner = epoll_create1(EPOLL_CLOEXEC);
        if (inner < 0) return NULL;
        int kick = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        if (kick < 0) { real_close(inner); return NULL; }

        struct epoll_event kick_ev  = { .events = EPOLLIN, .data.u64 = KICK_TAG };
        struct epoll_event inner_ev = { .events = EPOLLIN, .data.u64 = outer_tag(te) };
        if (real_epoll_ctl(inner, EPOLL_CTL_ADD, kick, &kick_ev) < 0 ||
            real_epoll_ctl(epfd, EPOLL_CTL_ADD, inner, &inner_ev) < 0) {
            int saved_errno = errno;
            real_close(kick); real_close(inner);
            errno = saved_errno;
            return NULL;
        }

        te->epfd       = epfd;
        te->inner_epfd = inner;
        te->kick       = kick;
        te->count      = 0;
        for (int j = 0; j < EPOLL_VFD_MAX; j++) {
            te->vfds[j].fd       = -1;
            te->vfds[j].doorbell = -1;
        }
        atomic_store_explicit(&te->active, true, memory_order_release);
        return te;
    }
    errno = ENOMEM;
    return NULL;
}

static void epoll_track_free(struct epoll_track_entry *te) {
    atomic_store_explicit(&te->active, false, memory_order_release);
    for (int j = 0; j < EPOLL_VFD_MAX; j++) {
        if (te->vfds[j].doorbell >= 0) real_close(te->vfds[j].doorbell);
        te->vfds[j].fd       = -1;
        te->vfds[j].doorbell = -1;
    }
    real_close(te->kick);
    real_close(te->inner_epfd);
}

static uint32_t doorbell_interest(uint32_t events) {
    bool reads       = events & EPOLL_READ_EVENTS;
    bool edge_writes = (events & EPOLLET) && (events & EPOLL_WRITE_EVENTS);
    return (reads || edge_writes) ? (EPOLLIN | (events & EPOLL_MODE_FLAGS)) : 0;
}

static uint32_t socket_interest(uint32_t events) {
    uint32_t interest = EPOLLRDHUP | (events & EPOLL_MODE_FLAGS);
    if (!(events & EPOLLET) && (events & EPOLL_WRITE_EVENTS))
        interest |= EPOLLOUT;
    return interest;
}

static void entry_disarm(struct epoll_track_entry *te, struct epoll_vfd_entry *e) {
    real_epoll_ctl(te->inner_epfd, EPOLL_CTL_DEL, e->fd, NULL);
    real_epoll_ctl(te->inner_epfd, EPOLL_CTL_DEL, e->doorbell, NULL);
    e->pending = false;
}

static int entry_arm(struct epoll_track_entry *te, int slot) {
    struct epoll_vfd_entry *e = &te->vfds[slot];

    uint32_t doorbell_events = doorbell_interest(e->events);
    if (doorbell_events) {
        struct epoll_event ev = { .events = doorbell_events, .data.u64 = inner_tag(slot, true) };
        if (real_epoll_ctl(te->inner_epfd, EPOLL_CTL_ADD, e->doorbell, &ev) < 0)
            return -1;
    }
    struct epoll_event ev = { .events = socket_interest(e->events), .data.u64 = inner_tag(slot, false) };
    if (real_epoll_ctl(te->inner_epfd, EPOLL_CTL_ADD, e->fd, &ev) < 0) {
        int saved_errno = errno;
        entry_disarm(te, e);
        errno = saved_errno;
        return -1;
    }

    e->disarmed = false;
    if ((e->events & EPOLLET) && (e->events & EPOLL_WRITE_EVENTS)) {
        e->pending = true;
        eventfd_write(te->kick, 1);
    }
    return 0;
}

static void entry_release(struct epoll_track_entry *te, int slot) {
    struct epoll_vfd_entry *e = &te->vfds[slot];
    entry_disarm(te, e);
    real_close(e->doorbell);
    e->fd       = -1;
    e->doorbell = -1;
    if (--te->count == 0)
        epoll_track_free(te);
}

static uint32_t entry_ready_events(const struct epoll_vfd_entry *e) {
    uint32_t mask = evdev_socket_hung_up(e->fd) ? (EPOLLHUP | EPOLLERR) : EPOLL_WRITE_EVENTS;
    if (evdev_reader_has_packet(vfd_table[e->fd].reader))
        mask |= EPOLL_READ_EVENTS;
    return mask & (e->events | EPOLLERR | EPOLLHUP);
}

static int entry_deliver(struct epoll_track_entry *te, int slot, struct epoll_event *out) {
    struct epoll_vfd_entry *e = &te->vfds[slot];
    e->pending = false;

    uint32_t ready = entry_ready_events(e);
    if (!ready) {
        evdev_reader_sync_doorbell(vfd_table[e->fd].reader);
        return 0;
    }

    *out = (struct epoll_event){ .events = ready, .data = e->data };
    if (e->events & EPOLLONESHOT) {
        entry_disarm(te, e);
        e->disarmed = true;
    }
    return 1;
}

static int harvest_inner(struct epoll_track_entry *te, struct epoll_event *out, int space) {
    struct epoll_event raw[2 * EPOLL_VFD_MAX + 1];
    int max_raw = space < (int)(sizeof(raw) / sizeof(raw[0])) ? space : (int)(sizeof(raw) / sizeof(raw[0]));
    int n = real_epoll_wait(te->inner_epfd, raw, max_raw, 0);

    bool fired[EPOLL_VFD_MAX] = { false };
    for (int k = 0; k < n; k++) {
        if (raw[k].data.u64 == KICK_TAG) {
            eventfd_t drained;
            eventfd_read(te->kick, &drained);
        } else {
            fired[raw[k].data.u64 >> 1] = true;
        }
    }

    int produced = 0;
    for (int slot = 0; slot < EPOLL_VFD_MAX; slot++)
        if (fired[slot] && te->vfds[slot].fd >= 0)
            produced += entry_deliver(te, slot, &out[produced]);

    bool more_pending = false;
    for (int slot = 0; slot < EPOLL_VFD_MAX; slot++) {
        if (te->vfds[slot].fd < 0 || !te->vfds[slot].pending) continue;
        if (produced < space)
            produced += entry_deliver(te, slot, &out[produced]);
        else
            more_pending = true;
    }
    if (more_pending)
        eventfd_write(te->kick, 1);

    return produced;
}

bool should_intercept_epoll_ctl(int epfd, int op, int fd) {
    (void)epfd; (void)op;
    return is_vfd(fd, VFD_EVDEV);
}

int intercept_epoll_ctl(int epfd, int op, int fd, struct epoll_event *ev) {
    dbg("epoll_ctl: epfd=%d op=%d fd=%d", epfd, op, fd);

    struct epoll_track_entry *te = epoll_track_find(epfd);
    int slot = te ? epoll_find_slot(te, fd) : -1;

    if (op != EPOLL_CTL_ADD && slot < 0)
        return real_epoll_ctl(epfd, op, fd, ev);
    if (op != EPOLL_CTL_DEL && !ev) { errno = EFAULT; return -1; }

    switch (op) {
    case EPOLL_CTL_ADD: {
        if ((ev->events & EPOLLEXCLUSIVE) && (ev->events & ~EPOLLEXCLUSIVE_OK_BITS)) {
            errno = EINVAL; return -1;
        }
        if (slot >= 0) { errno = EEXIST; return -1; }
        if (!te && !(te = epoll_track_alloc(epfd))) return -1;

        slot = epoll_find_slot(te, -1);
        int doorbell = slot < 0 ? -1 :
            real_fcntl(vfd_table[fd].reader->doorbell, F_DUPFD_CLOEXEC, 0);
        if (doorbell < 0) {
            int saved_errno = slot < 0 ? ENOSPC : errno;
            if (te->count == 0) epoll_track_free(te);
            errno = saved_errno;
            return -1;
        }

        te->vfds[slot] = (struct epoll_vfd_entry){
            .fd = fd, .doorbell = doorbell, .events = ev->events, .data = ev->data,
        };
        te->count++;
        if (entry_arm(te, slot) < 0) {
            int saved_errno = errno;
            entry_release(te, slot);
            errno = saved_errno;
            return -1;
        }
        return 0;
    }
    case EPOLL_CTL_MOD: {
        struct epoll_vfd_entry *e = &te->vfds[slot];
        if ((ev->events | e->events) & EPOLLEXCLUSIVE) { errno = EINVAL; return -1; }
        entry_disarm(te, e);
        e->events = ev->events;
        e->data   = ev->data;
        return entry_arm(te, slot);
    }
    case EPOLL_CTL_DEL:
        entry_release(te, slot);
        return 0;
    default:
        errno = EINVAL;
        return -1;
    }
}

void epoll_forget_vfd(int fd) {
    for (int i = 0; i < EPOLL_TRACK_MAX; i++) {
        struct epoll_track_entry *te = &epoll_table[i];
        if (!atomic_load_explicit(&te->active, memory_order_acquire)) continue;
        int slot = epoll_find_slot(te, fd);
        if (slot >= 0) entry_release(te, slot);
    }
}

bool should_intercept_epoll_close(int fd) {
    return epoll_track_find(fd) != NULL;
}

void intercept_epoll_close(int fd) {
    struct epoll_track_entry *te = epoll_track_find(fd);
    if (te) epoll_track_free(te);
}

bool should_intercept_epoll_wait(int epfd) {
    return epoll_track_find(epfd) != NULL;
}

int intercept_epoll_pwait(int epfd, struct epoll_event *events,
                          int maxevents, int timeout, const sigset_t *sigmask) {
    dbg("epoll_wait: epfd=%d maxevents=%d timeout=%d", epfd, maxevents, timeout);

    struct epoll_track_entry *te = epoll_track_find(epfd);
    if (!te || maxevents <= 0)
        return real_epoll_pwait(epfd, events, maxevents, timeout, sigmask);

    uint64_t deadline = timeout > 0 ? now_ns() + (uint64_t)timeout * NSEC_PER_MSEC : 0;
    int wait_ms = timeout;
    for (;;) {
        int n = real_epoll_pwait(epfd, events, maxevents, wait_ms, sigmask);
        if (n <= 0) return n;

        int out = 0;
        bool inner_ready = false;
        for (int i = 0; i < n; i++) {
            if (events[i].data.u64 == outer_tag(te)) inner_ready = true;
            else events[out++] = events[i];
        }
        if (inner_ready)
            out += harvest_inner(te, events + out, maxevents - out);
        if (out > 0 || timeout == 0) return out;

        if (timeout > 0) {
            uint64_t now = now_ns();
            if (now >= deadline) return 0;
            wait_ms = (int)((deadline - now + NSEC_PER_MSEC - 1) / NSEC_PER_MSEC);
        }
    }
}

int intercept_epoll_wait(int epfd, struct epoll_event *events,
                         int maxevents, int timeout) {
    return intercept_epoll_pwait(epfd, events, maxevents, timeout, NULL);
}
