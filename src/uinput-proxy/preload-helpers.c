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
    assert(nfds == 1);
    char cmsgbuf[CMSG_SPACE(sizeof(int))];
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
/* Device info cache                                                  */
/* ------------------------------------------------------------------ */

struct cached_device_info {
    bool             valid;
    struct device_info info;
};

static struct cached_device_info sysfs_cache[MAX_DEVICES];

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
    if (sysfs_cache[dev_id].valid)
        return sysfs_cache[dev_id].info.created;
    int ids[MAX_DEVICES];
    int count = query_device_list(ids);
    for (int i = 0; i < count; i++)
        if (ids[i] == dev_id) return true;
    return false;
}

const struct device_info *get_device_info(int dev_id) {
    if (dev_id < 0 || dev_id >= MAX_DEVICES) return NULL;

    if (sysfs_cache[dev_id].valid)
        return &sysfs_cache[dev_id].info;

    int sock = connect_to_daemon();
    if (sock < 0) return NULL;

    struct msg_evdev_open m = { .device_num = (uint32_t)dev_id };
    if (send_msg_r(sock, MSG_DEVICE_INFO, &m, sizeof(m)) < 0) {
        real_close(sock);
        return NULL;
    }

    uint8_t replybuf[sizeof(struct device_info)];
    uint32_t plen = 0;
    int type = recv_msg_r(sock, replybuf, sizeof(replybuf), &plen);
    real_close(sock);

    if (type != MSG_DEVICE_INFO_REPLY || plen < sizeof(struct device_info))
        return NULL;

    memcpy(&sysfs_cache[dev_id].info, replybuf, sizeof(struct device_info));
    sysfs_cache[dev_id].valid = true;
    return &sysfs_cache[dev_id].info;
}

void sysfs_cache_invalidate(void) {
    memset(sysfs_cache, 0, sizeof(sysfs_cache));
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
    path_info_t none = { PATH_NONE, -1, "" };
    if (!path || path[0] != '/') return none;

    const char *p;

    switch (path[1]) {

    case 'd': /* /dev/... */
        if (!(p = ADV(path, "/dev/"))) return none;

        if (p[0] == 'u' && memcmp(p, "uinput", 7) == 0)
            return (path_info_t){ PATH_UINPUT, -1, "" };

        if (!(p = ADV(p, "input"))) return none;

        if (*p == '\0')
            return (path_info_t){ PATH_DEV_INPUT_DIR, -1, "" };

        if (!(p = ADV(p, "/event"))) return none;
        {
            const char *end;
            int n = parse_uint(p, &end);
            if (n < 0 || *end != '\0') return none;
            return (path_info_t){ PATH_EVDEV, n, "" };
        }

    case 's': /* /sys/... */
        if (!(p = ADV(path, "/sys/"))) return none;

        /* /sys/class/input... */
        if ((p = ADV(p, "class/input"))) {
            if (*p == '\0' || (*p == '/' && *(p+1) == '\0'))
                return (path_info_t){ PATH_SYSFS_CLASS_DIR, -1, "" };
            if (!(p = ADV(p, "/event"))) return none;
            const char *end;
            int n = parse_uint(p, &end);
            if (n < 0) return none;
            const char *rem = (*end == '/') ? end + 1 : end;
            return (path_info_t){ PATH_SYSFS_CLASS, n, rem };
        }

        /* /sys/devices/virtual/input... (re-read from path[5] since class/ failed) */
        p = path + 5;
        if (!(p = ADV(p, "devices/virtual/input"))) return none;

        if (*p == '\0' || (*p == '/' && *(p+1) == '\0'))
            return (path_info_t){ PATH_SYSFS_VIRT_DIR, -1, "" };

        if (!(p = ADV(p, "/input"))) return none;
        {
            const char *end;
            int input_n = parse_uint(p, &end);
            if (input_n < 0) return none;
            p = end;

            if (*p == '/') {
                const char *sub;
                if ((sub = ADV(p, "/event"))) {
                    const char *end2;
                    int ev_n = parse_uint(sub, &end2);
                    if (ev_n == input_n) {
                        const char *rem = (*end2 == '/') ? end2 + 1 : end2;
                        return (path_info_t){ PATH_SYSFS_EVENT, input_n, rem };
                    }
                }
                return (path_info_t){ PATH_SYSFS_INPUT, input_n, p + 1 };
            }

            return (path_info_t){ PATH_SYSFS_INPUT, input_n, "" };
        }

    case 'p': /* /proc/self/fd/N */
        if (!(p = ADV(path, "/proc/self/fd/"))) return none;
        {
            const char *end;
            int fd_num = parse_uint(p, &end);
            if (fd_num < 0 || *end != '\0' || fd_num >= VFD_MAX) return none;
            if (!vfd_is_active(fd_num)) return none;
            return (path_info_t){ PATH_PROC_SELF_FD, fd_num, "" };
        }

    default:
        return none;
    }
}

/* ------------------------------------------------------------------ */
/* Sysfs content helpers                                              */
/* ------------------------------------------------------------------ */

/* Kernel format: space-separated 32-bit hex groups, MSB chunk first */
void format_capability_hex(const uint8_t *bits, int bit_count,
                            char *out, size_t outsz) {
    int byte_count = (bit_count + 7) / 8;
    int chunks = (byte_count + 3) / 4;
    char tmp[256];
    int pos = 0;
    bool leading = true;
    for (int c = chunks - 1; c >= 0; c--) {
        uint32_t val = 0;
        for (int b = 0; b < 4; b++) {
            int idx = c * 4 + b;
            if (idx < byte_count)
                val |= (uint32_t)bits[idx] << (b * 8);
        }
        if (leading && val == 0 && c > 0) continue;
        if (!leading) tmp[pos++] = ' ';
        pos += snprintf(tmp + pos, sizeof(tmp) - pos, "%x", val);
        leading = false;
    }
    if (leading) { tmp[pos++] = '0'; tmp[pos] = '\0'; }
    else tmp[pos] = '\0';
    snprintf(out, outsz, "%s\n", tmp);
}

int make_sysfs_fd(const char *content) {
    int fd = memfd_create("sysfs", MFD_CLOEXEC);
    if (fd < 0) return -1;
    size_t len = strlen(content);
    if (real_write(fd, content, len) != (ssize_t)len) {
        real_close(fd);
        return -1;
    }
    lseek(fd, 0, SEEK_SET);
    return fd;
}

static int open_sysfs_cap(const struct device_info *di, const uint8_t *bits,
                          int bit_count) {
    char buf[1024];
    format_capability_hex(bits, bit_count, buf, sizeof(buf));
    return make_sysfs_fd(buf);
}

int open_sysfs_content(int dev_id, const char *attr) {
    const struct device_info *di = get_device_info(dev_id);
    if (!di || !di->created) { errno = ENOENT; return -1; }

    char buf[1024];

    switch (attr[0]) {
    case 'n':
        if (attr[1] == 'a' && memcmp(attr, "name", 5) == 0) {
            snprintf(buf, sizeof(buf), "%s\n", di->name);
            return make_sysfs_fd(buf);
        }
        break;

    case 'i':
        if (attr[1] == 'd' && attr[2] == '/') {
            const char *id = attr + 3;
            uint16_t val;
            switch (id[0]) {
            case 'b': val = di->input_id.bustype; break;
            case 'v':
                val = (id[1] == 'e') ? di->input_id.vendor
                                     : di->input_id.version;
                break;
            case 'p': val = di->input_id.product;  break;
            default:  goto miss;
            }
            snprintf(buf, sizeof(buf), "%04x\n", val);
            return make_sysfs_fd(buf);
        }
        break;

    case 'd':
        if (attr[1] == 'e' && attr[2] == 'v' && attr[3] == '\0') {
            snprintf(buf, sizeof(buf), "%d:%d\n", INPUT_MAJOR, EVDEV_MINOR(dev_id));
            return make_sysfs_fd(buf);
        }
        break;

    case 'u':
        if (memcmp(attr, "uevent", 7) == 0) {
            snprintf(buf, sizeof(buf),
                "MAJOR=%d\nMINOR=%d\nDEVNAME=input/event%d\n",
                INPUT_MAJOR, EVDEV_MINOR(dev_id), dev_id);
            return make_sysfs_fd(buf);
        }
        break;

    case 'c':
        if (memcmp(attr, "capabilities/", 13) != 0)
            break;
        switch (attr[13]) {
        case 'e': return open_sysfs_cap(di, di->evbit,  EV_CNT);
        case 'k': return open_sysfs_cap(di, di->keybit, KEY_CNT);
        case 'a': return open_sysfs_cap(di, di->absbit, ABS_CNT);
        case 'r': return open_sysfs_cap(di, di->relbit, REL_CNT);
        case 'f': return open_sysfs_cap(di, di->ffbit,  FF_CNT);
        case 'm': return open_sysfs_cap(di, di->mscbit, MSC_CNT);
        case 'l': return open_sysfs_cap(di, di->ledbit, LED_CNT);
        case 's':
            if (attr[14] == 'w') return open_sysfs_cap(di, di->swbit,  SW_CNT);
            if (attr[14] == 'n') return open_sysfs_cap(di, di->sndbit, SND_CNT);
            break;
        }
        break;

    case 'p':
        if (memcmp(attr, "properties", 11) == 0)
            return open_sysfs_cap(di, di->propbit, INPUT_PROP_CNT);
        break;
    }

miss:
    errno = ENOENT;
    return -1;
}

/* ------------------------------------------------------------------ */
/* Fake DIR helpers                                                   */
/* ------------------------------------------------------------------ */

bool is_fake_dir(DIR *d) {
    return d && ((struct fake_dir *)d)->magic == FAKE_DIR_MAGIC;
}

struct fake_dir *make_fake_dir(const char *path) {
    struct fake_dir *d = calloc(1, sizeof(*d));
    if (!d) return NULL;
    d->magic = FAKE_DIR_MAGIC;
    snprintf(d->path, sizeof(d->path), "%s", path ? path : "?");
    d->entries[0].d_ino = 1; d->entries[0].d_type = DT_DIR;
    strncpy(d->entries[0].d_name, ".",  sizeof(d->entries[0].d_name));
    d->entries[1].d_ino = 2; d->entries[1].d_type = DT_DIR;
    strncpy(d->entries[1].d_name, "..", sizeof(d->entries[1].d_name));
    d->entries64[0].d_ino = 1; d->entries64[0].d_type = DT_DIR;
    strncpy(d->entries64[0].d_name, ".",  sizeof(d->entries64[0].d_name));
    d->entries64[1].d_ino = 2; d->entries64[1].d_type = DT_DIR;
    strncpy(d->entries64[1].d_name, "..", sizeof(d->entries64[1].d_name));
    d->count = 2;
    return d;
}

void fake_dir_add(struct fake_dir *d, const char *name,
                  unsigned char type, ino_t ino) {
    if (d->count >= FAKE_DIR_MAX_ENTRIES) return;
    struct dirent *e = &d->entries[d->count];
    e->d_ino  = ino;
    e->d_type = type;
    snprintf(e->d_name, sizeof(e->d_name), "%s", name);
    struct dirent64 *e64 = &d->entries64[d->count];
    e64->d_ino  = ino;
    e64->d_type = type;
    snprintf(e64->d_name, sizeof(e64->d_name), "%s", name);
    d->count++;
}

/* ------------------------------------------------------------------ */
/* Stat fill helpers                                                  */
/* ------------------------------------------------------------------ */

void fill_reg_stat(struct stat *st) {
    memset(st, 0, sizeof(*st));
    st->st_mode  = S_IFREG | 0444;
    st->st_nlink = 1;
    st->st_size  = 128;
}

void fill_lnk_stat(struct stat *st) {
    memset(st, 0, sizeof(*st));
    st->st_mode  = S_IFLNK | 0777;
    st->st_nlink = 1;
}

void fill_chr_stat(struct stat *st, dev_t rdev) {
    memset(st, 0, sizeof(*st));
    st->st_mode  = S_IFCHR | 0666;
    st->st_rdev  = rdev;
    st->st_nlink = 1;
}

void fill_dir_stat(struct stat *st) {
    memset(st, 0, sizeof(*st));
    st->st_mode  = S_IFDIR | 0755;
    st->st_nlink = 2;
}

void fill_reg_stat64(struct stat64 *st) {
    memset(st, 0, sizeof(*st));
    st->st_mode  = S_IFREG | 0444;
    st->st_nlink = 1;
    st->st_size  = 128;
}

void fill_lnk_stat64(struct stat64 *st) {
    memset(st, 0, sizeof(*st));
    st->st_mode  = S_IFLNK | 0777;
    st->st_nlink = 1;
}

void fill_chr_stat64(struct stat64 *st, dev_t rdev) {
    memset(st, 0, sizeof(*st));
    st->st_mode  = S_IFCHR | 0666;
    st->st_rdev  = rdev;
    st->st_nlink = 1;
}

void fill_dir_stat64(struct stat64 *st) {
    memset(st, 0, sizeof(*st));
    st->st_mode  = S_IFDIR | 0755;
    st->st_nlink = 2;
}

bool is_sysfs_dir_attr(const char *rem) {
    return rem[0] == '\0'
        || strcmp(rem, "id") == 0
        || strcmp(rem, "capabilities") == 0;
}
