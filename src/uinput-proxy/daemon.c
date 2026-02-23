#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/poll.h>
#include <limits.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <time.h>
#include <linux/futex.h>

#include "daemon.h"

/* ------------------------------------------------------------------ */
/* Configuration                                                      */
/* ------------------------------------------------------------------ */

static const char *SOCK_PATH   = UINPUT_PROXY_SOCK;
static const char *DEVDIR      = "/dev/input";
static const char *UINPUT_STUB = "/dev/uinput";

#define CLIENT_MSG_BUF   4096

/* ------------------------------------------------------------------ */
/* Global state                                                       */
/* ------------------------------------------------------------------ */

bool                 debug_mode      = false;
bool                 uevent_enabled  = false;
FILE                *debug_log       = NULL;
struct virtual_device devices[MAX_DEVICES];
struct client         clients[MAX_FDS];
int                   server_fd       = -1;
int                   netlink_fd      = -1;

/* ------------------------------------------------------------------ */
/* Logging                                                            */
/* ------------------------------------------------------------------ */

void logmsg(const char *fmt, ...) {
    FILE *out = debug_log ? debug_log : stderr;

    if (debug_log) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        struct tm tm;
        localtime_r(&ts.tv_sec, &tm);
        fprintf(out, "[%04d-%02d-%02d %02d:%02d:%02d.%03ld] [uinput-daemon] ",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec / 1000000);
    } else {
        fprintf(out, "[uinput-daemon] ");
    }

    va_list ap;
    va_start(ap, fmt);
    vfprintf(out, fmt, ap);
    va_end(ap);

    fputc('\n', out);
    fflush(out);
}

static void disconnect_client(int fd);

/* ------------------------------------------------------------------ */
/* Graceful shutdown                                                  */
/* ------------------------------------------------------------------ */

static volatile sig_atomic_t shutdown_requested = 0;

static void handle_signal(int sig) {
    (void)sig;
    shutdown_requested = 1;
}

static void cleanup_and_exit(void) {
    logmsg("shutting down, cleaning up devices");
    for (int i = 0; i < MAX_DEVICES; i++) {
        if (devices[i].active)
            device_destroy(&devices[i]);
    }
    if (server_fd >= 0) { close(server_fd); server_fd = -1; }
    unlink(SOCK_PATH);
}

/* ------------------------------------------------------------------ */
/* Message dispatch                                                   */
/* ------------------------------------------------------------------ */

static bool handle_client_message(struct client *c) {
    uint8_t buf[CLIENT_MSG_BUF];
    uint32_t plen = 0;
    int type = recv_msg(c->fd, buf, sizeof(buf), &plen);
    if (type < 0) return false;

    if (c->type == CONN_UNKNOWN) {
        if (type == MSG_UINPUT_OPEN) {
            struct virtual_device *dev = alloc_device();
            if (!dev) { logmsg("no free device slots"); return false; }
            dev->writer_fd = c->fd;
            c->type        = CONN_WRITER;
            c->device_id   = dev->id;
            logmsg("writer connected, device slot %d", dev->id);
            return true;
        }
        if (type == MSG_EVDEV_OPEN && plen >= sizeof(struct msg_evdev_open)) {
            struct msg_evdev_open *m = (struct msg_evdev_open *)buf;
            int slot = find_slot_by_num((int)m->device_num);
            if (slot < 0) {
                logmsg("evdev open: device %u not found/created", m->device_num);
                return false;
            }
            struct virtual_device *dev = &devices[slot];
            if (!dev->created) {
                logmsg("evdev open: device %u not created yet", m->device_num);
                return false;
            }
            if (add_reader_to_device(dev, c->fd) < 0) {
                logmsg("evdev open: add_reader failed for device %d", dev->id);
                return false;
            }
            if (send_fds(c->fd, &dev->shmem_fd, 1) < 0) {
                logmsg("evdev open: send_fds failed: %s", strerror(errno));
                remove_reader_from_device(dev, c->fd);
                return false;
            }
            c->type      = CONN_READER;
            c->device_id = dev->id;
            dlog("reader fd=%d connected to device %d, shmem_fd sent", c->fd, dev->id);
            return true;
        }
        if (type == MSG_LIST_DEVICES) {
            send_device_list(c->fd);
            return false;
        }
        if (type == MSG_DEVICE_INFO && plen >= sizeof(struct msg_evdev_open)) {
            struct msg_evdev_open *m = (struct msg_evdev_open *)buf;
            send_device_info(c->fd, m->device_num);
            return false;
        }
        logmsg("unknown first message type %d", type);
        return false;
    }

    struct virtual_device *dev = find_device_by_id(c->device_id);

    if (c->type == CONN_WRITER) {
        if (!dev) return false;

        if (type == MSG_IOCTL && plen >= sizeof(struct msg_ioctl)) {
            struct msg_ioctl *m = (struct msg_ioctl *)buf;
            uint8_t *data = buf + sizeof(*m);
            uint32_t dlen = plen - sizeof(*m);
            handle_writer_ioctl(c->fd, dev, m->cmd, data, dlen);
            return true;
        }

        if (type == MSG_WRITE) {
            if (!dev->created && plen >= sizeof(struct uinput_user_dev)) {
                struct uinput_user_dev *u = (struct uinput_user_dev *)buf;
                memcpy(dev->name, u->name, UINPUT_MAX_NAME_SIZE);
                dev->name[UINPUT_MAX_NAME_SIZE - 1] = '\0';
                dev->input_id       = u->id;
                dev->ff_effects_max = u->ff_effects_max;
                for (int i = 0; i < ABS_CNT; i++) {
                    dev->absinfo[i].maximum = u->absmax[i];
                    dev->absinfo[i].minimum = u->absmin[i];
                    dev->absinfo[i].fuzz    = u->absfuzz[i];
                    dev->absinfo[i].flat    = u->absflat[i];
                }
                dlog("old-style uinput_user_dev: name='%s' vendor=%04x product=%04x",
                     dev->name, dev->input_id.vendor, dev->input_id.product);
            } else {
                struct evdev_shmem *shm = dev->shmem;
                if (shm && dev->reader_count > 0) {
                    uint64_t nframes = BYTES_TO_FRAMES(plen);
                    dlog("writing %zu frames to device %d (%d readers)",
                         (size_t)nframes, dev->id, dev->reader_count);

                    uint64_t w = atomic_load_explicit(&shm->write_pos, memory_order_relaxed);
                    const uint8_t *src = buf;
                    bool has_syn_report = false;

                    for (uint64_t f = 0; f < nframes; f++) {
                        const struct input_event *ev = (const struct input_event *)src;
                        memcpy(shm->buf + FRAME_RING_BYTE(w), src, WIRE_EVENT_SIZE);
                        src += WIRE_EVENT_SIZE;
                        w++;

                        if (ev->type == EV_KEY && ev->code < KEY_CNT) {
                            if (ev->value == 0)
                                dev->key_state[ev->code / 8] &= ~(1 << (ev->code % 8));
                            else if (ev->value == 1)
                                dev->key_state[ev->code / 8] |= (1 << (ev->code % 8));
                        } else if (ev->type == EV_LED && ev->code < LED_CNT) {
                            if (ev->value == 0)
                                dev->led_state[ev->code / 8] &= ~(1 << (ev->code % 8));
                            else
                                dev->led_state[ev->code / 8] |= (1 << (ev->code % 8));
                        } else if (ev->type == EV_SW && ev->code < SW_CNT) {
                            if (ev->value == 0)
                                dev->sw_state[ev->code / 8] &= ~(1 << (ev->code % 8));
                            else
                                dev->sw_state[ev->code / 8] |= (1 << (ev->code % 8));
                        } else if (ev->type == EV_ABS && ev->code < ABS_CNT) {
                            dev->absinfo[ev->code].value = ev->value;
                        }

                        if (ev->type == EV_SYN && ev->code == SYN_REPORT) {
                            has_syn_report = true;
                            atomic_store_explicit(&shm->packet_head, w, memory_order_release);
                        }
                    }

                    atomic_store_explicit(&shm->write_pos, w, memory_order_release);

                    if (has_syn_report) {
                        atomic_fetch_add_explicit(&shm->wake_seq, 1, memory_order_release);
                        syscall(SYS_futex, &shm->wake_seq, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
                    }
                }
            }
            return true;
        }

        logmsg("writer: unexpected message type %d", type);
        return true;
    }

    if (c->type == CONN_READER) {
        if (!dev) return false;

        if (type == MSG_IOCTL && plen >= sizeof(struct msg_ioctl)) {
            struct msg_ioctl *m = (struct msg_ioctl *)buf;
            uint8_t *data = buf + sizeof(*m);
            uint32_t dlen = plen - sizeof(*m);
            handle_reader_ioctl(c->fd, dev, m->cmd, data, dlen);
            return true;
        }

        if (type == MSG_EVDEV_WRITE) {
            dlog("evdev write: %u bytes from reader on device %d", plen, dev->id);
            if (dev->writer_fd >= 0)
                send_msg(dev->writer_fd, MSG_FF_REQUEST, buf, plen);
            return true;
        }

        logmsg("reader: unexpected message type %d", type);
        return true;
    }

    return false;
}

/* ------------------------------------------------------------------ */
/* Main event loop                                                    */
/* ------------------------------------------------------------------ */

static void disconnect_client(int fd) {
    for (int i = 0; i < MAX_FDS; i++) {
        if (!clients[i].active || clients[i].fd != fd) continue;
        struct client *c = &clients[i];

        dlog("disconnect fd=%d type=%d device=%d", fd, c->type, c->device_id);

        if (c->type == CONN_WRITER) {
            struct virtual_device *dev = find_device_by_id(c->device_id);
            if (dev) device_destroy(dev);
        } else if (c->type == CONN_READER) {
            struct virtual_device *dev = find_device_by_id(c->device_id);
            if (dev) remove_reader_from_device(dev, fd);
        }

        clients[i].active = false;
        break;
    }
    close(fd);
}

int main(void) {
    if (access("/.container", F_OK) != 0) {
        fprintf(stderr, "uinput-daemon: refusing to run outside a container (/.container not found)\n");
        return 1;
    }
    if (access("/dev/uinput", F_OK) == 0) {
        fprintf(stderr, "uinput-daemon: refusing to run with real /dev/uinput present\n");
        return 1;
    }

    const char *dbgval = getenv("UINPUT_DEBUG");
    if (dbgval && *dbgval) {
        debug_mode = true;
        if (strcmp(dbgval, "console") == 0) {
            debug_log = stderr;
        } else {
            debug_log = fopen(dbgval, "a");
            if (debug_log)
                setvbuf(debug_log, NULL, _IOLBF, 0);
        }
    }

    struct sigaction sa = { .sa_handler = handle_signal, .sa_flags = SA_RESTART };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);

    const char *extraval = getenv("UINPUT_EXTRA");
    uevent_enabled = (extraval && *extraval);

    logmsg("starting (euid=%d, uid=%d, debug=%s, uevent=%s)",
           (int)geteuid(), (int)getuid(),
           debug_mode ? "on" : "off",
           uevent_enabled ? "on" : "off");

    if (uevent_enabled)
        init_netlink();

    if (mkdir(DEVDIR, 0755) < 0 && errno != EEXIST)
        logmsg("warning: mkdir %s: %s", DEVDIR, strerror(errno));
    else
        dlog("mkdir %s: ok", DEVDIR);

    {
        int fd = open(UINPUT_STUB, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (fd < 0)
            logmsg("warning: create %s: %s", UINPUT_STUB, strerror(errno));
        else {
            dlog("created %s", UINPUT_STUB);
            close(fd);
        }
    }

    memset(devices, 0, sizeof(devices));
    memset(clients, 0, sizeof(clients));

    unlink(SOCK_PATH);
    server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) { logmsg("socket: %s", strerror(errno)); return 1; }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path) - 1);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        logmsg("bind %s: %s", SOCK_PATH, strerror(errno)); return 1;
    }
    /* 0777: socket must be reachable by all UIDs inside the container.
     * The container boundary is the trust boundary. */
    if (chmod(SOCK_PATH, 0777) < 0)
        logmsg("warning: chmod %s: %s", SOCK_PATH, strerror(errno));
    if (listen(server_fd, 16) < 0) {
        logmsg("listen: %s", strerror(errno)); return 1;
    }

    logmsg("listening on %s", SOCK_PATH);

    int timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    if (timer_fd < 0) {
        logmsg("timerfd_create: %s", strerror(errno)); return 1;
    }
    {
        struct itimerspec ts = {
            .it_interval = { .tv_sec = 1, .tv_nsec = 0 },
            .it_value    = { .tv_sec = 1, .tv_nsec = 0 },
        };
        timerfd_settime(timer_fd, 0, &ts, NULL);
    }

    for (;;) {
        struct pollfd pfds[MAX_FDS + 2];
        int nfds = 0;

        pfds[nfds].fd      = server_fd;
        pfds[nfds].events  = POLLIN;
        pfds[nfds].revents = 0;
        nfds++;

        pfds[nfds].fd      = timer_fd;
        pfds[nfds].events  = POLLIN;
        pfds[nfds].revents = 0;
        nfds++;

        for (int i = 0; i < MAX_FDS; i++) {
            if (!clients[i].active) continue;
            pfds[nfds].fd      = clients[i].fd;
            pfds[nfds].events  = POLLIN;
            pfds[nfds].revents = 0;
            nfds++;
        }

        if (shutdown_requested) {
            cleanup_and_exit();
            return 0;
        }

        int ret = poll(pfds, nfds, -1);
        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            break;
        }

        if (pfds[1].revents & POLLIN) {
            uint64_t expirations;
            if (read(timer_fd, &expirations, sizeof(expirations)) <= 0) expirations = 1;
            (void)expirations;
            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            uint64_t now = (uint64_t)ts.tv_sec;
            for (int i = 0; i < MAX_DEVICES; i++) {
                if (devices[i].active && devices[i].shmem)
                    atomic_store_explicit(&devices[i].shmem->heartbeat,
                                         now, memory_order_relaxed);
            }
        }

        if (pfds[0].revents & POLLIN) {
            int cfd = accept(server_fd, NULL, NULL);
            if (cfd >= 0) {
                {
                    struct ucred cr = {0};
                    socklen_t crlen = sizeof(cr);
                    if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cr, &crlen) == 0)
                        dlog("accepted connection fd=%d pid=%d uid=%d", cfd, cr.pid, cr.uid);
                    else
                        dlog("accepted connection fd=%d", cfd);
                }
                if (!alloc_client(cfd)) {
                    logmsg("too many clients, dropping fd=%d", cfd);
                    close(cfd);
                }
            }
        }

        for (int i = 2; i < nfds; i++) {
            if (!pfds[i].revents) continue;
            int fd = pfds[i].fd;

            struct client *c = NULL;
            for (int j = 0; j < MAX_FDS; j++)
                if (clients[j].active && clients[j].fd == fd) { c = &clients[j]; break; }
            if (!c) continue;

            if (pfds[i].revents & POLLIN) {
                if (!handle_client_message(c))
                    disconnect_client(fd);
                continue;
            }

            if (pfds[i].revents & (POLLHUP | POLLERR | POLLNVAL))
                disconnect_client(fd);
        }
    }

    return 0;
}
