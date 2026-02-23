#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <time.h>

#include "preload.h"

/* ------------------------------------------------------------------ */
/* poll / ppoll                                                       */
/* ------------------------------------------------------------------ */

bool should_intercept_poll(struct pollfd *fds, nfds_t nfds) {
    for (nfds_t i = 0; i < nfds; i++) {
        int fd = fds[i].fd;
        if (vfd_is_active(fd) && (vfd_table[fd].type == VFD_EVDEV ||
                                   vfd_table[fd].type == VFD_UINPUT)) return true;
    }
    return false;
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static struct timespec ns_to_timespec(uint64_t ns) {
    return (struct timespec){ .tv_sec  = (time_t)(ns / 1000000000ULL),
                              .tv_nsec = (long)  (ns % 1000000000ULL) };
}

static const char *vfd_type_name_poll(int fd) {
    switch (vfd_table[fd].type) {
        case VFD_UINPUT: return "uinput";
        case VFD_EVDEV:  return "evdev";
        case VFD_SYSFS:  return "sysfs";
        default:         return "?";
    }
}

static int check_evdev(struct pollfd *fds, struct pollfd *evdev_fds,
                       nfds_t nevdev, int *evdev_orig) {
    int ready = 0;
    for (nfds_t i = 0; i < nevdev; i++) {
        struct virtual_fd *vf = &vfd_table[evdev_fds[i].fd];
        if (!vf->shmem) continue;

        __poll_t revents = 0;

        if (evdev_fds[i].events & (POLLOUT | POLLWRNORM))
            revents |= POLLOUT | POLLWRNORM;

        if (evdev_fds[i].events & (POLLIN | POLLRDNORM)) {
            uint64_t packet_head = atomic_load_explicit(&vf->shmem->packet_head,
                                                         memory_order_acquire);
            if (packet_head != vf->read_pos)
                revents |= POLLIN | POLLRDNORM;
        }

        if (revents) {
            fds[evdev_orig[i]].revents = revents;
            ready++;
        }
    }
    return ready;
}

static void merge_poll_results(struct pollfd *fds, struct pollfd *other_fds,
                        nfds_t nother, int *other_orig) {
    for (nfds_t i = 0; i < nother; i++)
        fds[other_orig[i]].revents |= other_fds[i].revents;
}

#ifndef POLL_STACK_MAX
#  define POLL_STACK_MAX 256
#endif

int intercept_poll(struct pollfd *fds, nfds_t nfds, int timeout_ms) {
    if (debug_log) {
        char _fdbuf[256]; int _pos = 0;
        for (nfds_t _i = 0; _i < nfds && _pos < (int)sizeof(_fdbuf) - 1; _i++) {
            int _fd = fds[_i].fd;
            const char *_t = vfd_is_active(_fd) ? vfd_type_name_poll(_fd) : "other";
            _pos += snprintf(_fdbuf + _pos, sizeof(_fdbuf) - (size_t)_pos,
                             " fd=%d/%s/0x%x", _fd, _t, (unsigned)fds[_i].events);
        }
        dbg("poll: nfds=%zu timeout=%d%s", (size_t)nfds, timeout_ms, _fdbuf);
    }

    struct pollfd      evdev_stack[POLL_STACK_MAX], other_stack[POLL_STACK_MAX];
    int                evdev_orig_stack[POLL_STACK_MAX], other_orig_stack[POLL_STACK_MAX];
    struct futex_waitv waitv_stack[POLL_STACK_MAX];

    struct pollfd      *evdev_fds, *other_fds;
    int                *evdev_orig, *other_orig;
    struct futex_waitv *waitv;
    bool                heap = (nfds > POLL_STACK_MAX);

    if (heap) {
        evdev_fds  = malloc(nfds * sizeof(*evdev_fds));
        other_fds  = malloc(nfds * sizeof(*other_fds));
        evdev_orig = malloc(nfds * sizeof(*evdev_orig));
        other_orig = malloc(nfds * sizeof(*other_orig));
        waitv      = malloc(nfds * sizeof(*waitv));
        if (!evdev_fds || !other_fds || !evdev_orig || !other_orig || !waitv) {
            free(evdev_fds); free(other_fds);
            free(evdev_orig); free(other_orig);
            free(waitv);
            errno = ENOMEM; return -1;
        }
    } else {
        evdev_fds  = evdev_stack;
        other_fds  = other_stack;
        evdev_orig = evdev_orig_stack;
        other_orig = other_orig_stack;
        waitv      = waitv_stack;
    }

    nfds_t nevdev = 0, nother = 0;

    for (nfds_t i = 0; i < nfds; i++) {
        fds[i].revents = 0;
        int fd = fds[i].fd;
        if (vfd_is_active(fd) && vfd_table[fd].type == VFD_EVDEV) {
            evdev_fds[nevdev]  = (struct pollfd){ .fd = fd, .events = fds[i].events };
            evdev_orig[nevdev] = (int)i;
            nevdev++;
        } else {
            other_fds[nother]  = (struct pollfd){ .fd = fds[i].fd, .events = fds[i].events };
            other_orig[nother] = (int)i;
            nother++;
        }
    }

    for (nfds_t i = 0; i < nevdev; i++) {
        struct virtual_fd *vf = &vfd_table[evdev_fds[i].fd];
        waitv[i] = (struct futex_waitv){
            .uaddr = (uint64_t)(uintptr_t)&vf->shmem->wake_seq,
            .val   = atomic_load_explicit(&vf->shmem->wake_seq, memory_order_acquire),
            .flags = FUTEX_32,
        };
    }

    uint64_t cap      = (nother > 0 && nevdev > 0) ? POLL_FUTEX_CAP_NS : POLL_FUTEX_CAP_ONLY_NS;
    bool     infinite = (timeout_ms < 0);
    uint64_t deadline = infinite ? 0 : now_ns() + (uint64_t)timeout_ms * 1000000ULL;

    int ret = 0;

    for (;;) {
        int ready = check_evdev(fds, evdev_fds, nevdev, evdev_orig);
        if (nother > 0) {
            int r = real_poll(other_fds, nother, 0);
            if (r > 0) { merge_poll_results(fds, other_fds, nother, other_orig); ready += r; }

            /* Kernel uinput_poll() unconditionally returns EPOLLOUT|EPOLLWRNORM */
            for (nfds_t i = 0; i < nother; i++) {
                int fd = other_fds[i].fd;
                if (vfd_is_active(fd) && vfd_table[fd].type == VFD_UINPUT) {
                    bool was_ready = (fds[other_orig[i]].revents != 0);
                    fds[other_orig[i]].revents |= POLLOUT | POLLWRNORM;
                    if (!was_ready) ready++;
                }
            }
        }
        if (ready > 0 || timeout_ms == 0) { ret = ready; goto done; }

        uint64_t now = now_ns();
        if (!infinite && now >= deadline) { ret = 0; goto done; }

        uint64_t slice_end = (!infinite && deadline - now < cap) ? deadline : now + cap;
        struct timespec abs_slice = ns_to_timespec(slice_end);

        if (nevdev == 0) {
            uint64_t now2 = now_ns();
            uint64_t rem  = slice_end > now2 ? slice_end - now2 : 0;
            int64_t  ms64 = (int64_t)(rem / 1000000ULL);
            int pr = real_poll(other_fds, nother, ms64 > INT_MAX ? INT_MAX : (int)ms64);
            if (pr < 0 && errno == EINTR) { ret = -1; goto done; }
            continue;
        }

        long rc = syscall(SYS_futex_waitv, waitv, (unsigned int)nevdev,
                          0, &abs_slice, CLOCK_MONOTONIC);

        if (rc < 0 && errno == EINTR) { ret = -1; goto done; }

        if (rc < 0 && errno == ETIMEDOUT) {
            struct timespec now_ts;
            clock_gettime(CLOCK_MONOTONIC, &now_ts);
            int dead = 0;
            for (nfds_t i = 0; i < nevdev; i++) {
                struct virtual_fd *vf = &vfd_table[evdev_fds[i].fd];
                uint64_t hb = atomic_load_explicit(&vf->shmem->heartbeat, memory_order_relaxed);
                if ((uint64_t)now_ts.tv_sec - hb > HEARTBEAT_TIMEOUT_SEC) { fds[evdev_orig[i]].revents |= POLLHUP; dead++; }
            }
            if (dead > 0) { ret = dead; goto done; }
        }
    }

done:
    if (heap) {
        free(evdev_fds); free(other_fds);
        free(evdev_orig); free(other_orig);
        free(waitv);
    }
    return ret;
}

int intercept_ppoll(struct pollfd *fds, nfds_t nfds,
                    const struct timespec *tmo, const sigset_t *sigmask) {
    dbg("ppoll: nfds=%zu", (size_t)nfds);
    (void)sigmask;
    int ms;
    if (!tmo) {
        ms = -1;
    } else {
        int64_t ms64 = (int64_t)tmo->tv_sec * 1000 + (int64_t)tmo->tv_nsec / 1000000;
        ms = ms64 > (int64_t)INT_MAX ? INT_MAX : (int)ms64;
    }
    return intercept_poll(fds, nfds, ms);
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

bool should_intercept_close(int fd) {
    return vfd_is_active(fd);
}

int intercept_close(int fd) {
    struct virtual_fd *vf = &vfd_table[fd];
    dbg("close: fd=%d type=%d dev=%d", fd, vf->type, vf->device_id);

    if (vf->type == VFD_EVDEV && vf->shmem)
        munmap((void *)vf->shmem, sizeof(struct evdev_shmem));

    if (vf->type == VFD_EVDEV) {
        for (int i = 0; i < EPOLL_TRACK_MAX; i++) {
            if (!atomic_load_explicit(&epoll_table[i].active, memory_order_acquire))
                continue;
            for (int j = 0; j < EPOLL_VFD_MAX; j++) {
                if (epoll_table[i].vfds[j].fd == fd) {
                    epoll_table[i].vfds[j].fd = -1;
                    epoll_table[i].count--;
                    if (epoll_table[i].count <= 0)
                        atomic_store_explicit(&epoll_table[i].active, false,
                                              memory_order_release);
                }
            }
        }
    }

    vfd_clear(fd);
    return real_close(fd);
}

/* ------------------------------------------------------------------ */
/* epoll_ctl / epoll_wait / epoll_pwait                               */
/* ------------------------------------------------------------------ */

static struct epoll_track_entry *epoll_track_find(int epfd) {
    for (int i = 0; i < EPOLL_TRACK_MAX; i++)
        if (atomic_load_explicit(&epoll_table[i].active, memory_order_acquire)
                && epoll_table[i].epfd == epfd)
            return &epoll_table[i];
    return NULL;
}

static struct epoll_track_entry *epoll_track_alloc(int epfd) {
    for (int i = 0; i < EPOLL_TRACK_MAX; i++) {
        if (!atomic_load_explicit(&epoll_table[i].active, memory_order_acquire)) {
            epoll_table[i].epfd  = epfd;
            epoll_table[i].count = 0;
            for (int j = 0; j < EPOLL_VFD_MAX; j++)
                epoll_table[i].vfds[j].fd = -1;
            atomic_store_explicit(&epoll_table[i].active, true, memory_order_release);
            return &epoll_table[i];
        }
    }
    return NULL;
}

bool should_intercept_epoll_ctl(int epfd, int op, int fd) {
    (void)epfd; (void)op;
    if (vfd_is_active(fd) && vfd_table[fd].type == VFD_EVDEV) return true;
    if ((op == EPOLL_CTL_DEL || op == EPOLL_CTL_MOD) && epoll_track_find(epfd))
        return true;
    return false;
}

int intercept_epoll_ctl(int epfd, int op, int fd, struct epoll_event *ev) {
    dbg("epoll_ctl: epfd=%d op=%d fd=%d", epfd, op, fd);

    struct epoll_track_entry *te = epoll_track_find(epfd);

    if (op == EPOLL_CTL_ADD) {
        if (!vfd_is_active(fd) || vfd_table[fd].type != VFD_EVDEV)
            return real_epoll_ctl(epfd, op, fd, ev);
        if (!te) te = epoll_track_alloc(epfd);
        if (!te) { errno = ENOMEM; return -1; }

        for (int j = 0; j < EPOLL_VFD_MAX; j++)
            if (te->vfds[j].fd == fd) { errno = EEXIST; return -1; }
        for (int j = 0; j < EPOLL_VFD_MAX; j++) {
            if (te->vfds[j].fd == -1) {
                te->vfds[j].fd     = fd;
                te->vfds[j].events = ev ? ev->events : (EPOLLIN | EPOLLOUT);
                te->vfds[j].data   = ev ? ev->data   : (epoll_data_t){ .fd = fd };
                te->count++;
                return 0;
            }
        }
        errno = ENOMEM;
        return -1;
    }

    if (op == EPOLL_CTL_MOD) {
        if (!te) return real_epoll_ctl(epfd, op, fd, ev);
        for (int j = 0; j < EPOLL_VFD_MAX; j++) {
            if (te->vfds[j].fd == fd) {
                if (ev) {
                    te->vfds[j].events = ev->events;
                    te->vfds[j].data   = ev->data;
                }
                return 0;
            }
        }
        return real_epoll_ctl(epfd, op, fd, ev);
    }

    if (op == EPOLL_CTL_DEL) {
        if (!te) return real_epoll_ctl(epfd, op, fd, ev);
        for (int j = 0; j < EPOLL_VFD_MAX; j++) {
            if (te->vfds[j].fd == fd) {
                te->vfds[j].fd = -1;
                te->count--;
                if (te->count <= 0)
                    atomic_store_explicit(&te->active, false, memory_order_release);
                return 0;
            }
        }
        return real_epoll_ctl(epfd, op, fd, ev);
    }

    return real_epoll_ctl(epfd, op, fd, ev);
}

bool should_intercept_epoll_wait(int epfd) {
    return epoll_track_find(epfd) != NULL;
}

int intercept_epoll_wait(int epfd, struct epoll_event *events,
                         int maxevents, int timeout) {
    dbg("epoll_wait: epfd=%d maxevents=%d timeout=%d", epfd, maxevents, timeout);

    struct epoll_track_entry *te = epoll_track_find(epfd);
    if (!te || maxevents <= 0)
        return real_epoll_wait(epfd, events, maxevents, timeout);

    struct pollfd virt_pfds[EPOLL_VFD_MAX];
    int virt_orig[EPOLL_VFD_MAX];
    int nvirt = 0;

    for (int j = 0; j < EPOLL_VFD_MAX; j++) {
        int vfd = te->vfds[j].fd;
        if (vfd < 0 || !vfd_is_active(vfd)) continue;
        virt_pfds[nvirt].fd      = vfd;
        virt_pfds[nvirt].events  = (short)te->vfds[j].events;
        virt_pfds[nvirt].revents = 0;
        virt_orig[nvirt]         = j;
        nvirt++;
    }

    if (nvirt == 0)
        return real_epoll_wait(epfd, events, maxevents, timeout);

    int ret = intercept_poll(virt_pfds, (nfds_t)nvirt, timeout);
    if (ret < 0) return ret;

    int nready = 0;
    for (int i = 0; i < nvirt && nready < maxevents; i++) {
        if (!virt_pfds[i].revents) continue;
        events[nready].events = (uint32_t)virt_pfds[i].revents;
        events[nready].data   = te->vfds[virt_orig[i]].data;
        nready++;
    }

    return nready;
}

int intercept_epoll_pwait(int epfd, struct epoll_event *events,
                          int maxevents, int timeout, const sigset_t *sigmask) {
    (void)sigmask;
    return intercept_epoll_wait(epfd, events, maxevents, timeout);
}
