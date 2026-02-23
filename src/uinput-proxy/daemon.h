#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <linux/input.h>
#include <linux/uinput.h>
#include "protocol.h"

/* ------------------------------------------------------------------ */
/* Configuration                                                      */
/* ------------------------------------------------------------------ */

#define MAX_CLIENTS  (MAX_DEVICES * (1 + MAX_READERS) + 4)
#define MAX_FDS      (MAX_CLIENTS + 4)

/* ------------------------------------------------------------------ */
/* Logging                                                            */
/* ------------------------------------------------------------------ */

extern bool  debug_mode;
extern FILE *debug_log;

void logmsg(const char *fmt, ...);
#define dlog(...) do { if (debug_mode) logmsg(__VA_ARGS__); } while (0)

/* ------------------------------------------------------------------ */
/* Force-feedback                                                     */
/* ------------------------------------------------------------------ */

typedef enum {
    FF_PENDING_NONE = 0,
    FF_PENDING_UPLOAD,
    FF_PENDING_ERASE,
} ff_pending_type_t;

struct ff_pending {
    ff_pending_type_t type;
    int               reader_fd;
    int               effect_slot;
    struct ff_effect  effect;
    int               effect_id;
    bool              writer_done;
    int32_t           writer_ret;
};

struct ff_slot {
    bool             used;
    int              id;
    struct ff_effect effect;
};

/* ------------------------------------------------------------------ */
/* Virtual device                                                     */
/* ------------------------------------------------------------------ */

struct virtual_device {
    bool    active;
    int     id;          /* slot index in devices[] array */
    int     device_num;  /* actual /dev/input/eventN number */
    int     writer_fd;
    time_t  cooldown_until;  /* slot cannot be reused until this time */

    char    name[UINPUT_MAX_NAME_SIZE];
    char    phys[256];
    char    uniq[256];
    struct  input_id input_id;

    uint8_t evbit [EVBIT_SIZE];
    uint8_t keybit[KEYBIT_SIZE];
    uint8_t absbit[ABSBIT_SIZE];
    uint8_t relbit[RELBIT_SIZE];
    uint8_t ffbit [FFBIT_SIZE];
    uint8_t mscbit[MSCBIT_SIZE];
    uint8_t swbit [SWBIT_SIZE];
    uint8_t ledbit[LEDBIT_SIZE];
    uint8_t sndbit[SNDBIT_SIZE];
    uint8_t propbit[PROPBIT_SIZE];

    /* Current device state (for EVIOCGKEY/LED/SW) */
    uint8_t key_state[KEYBIT_SIZE];   /* Currently pressed keys */
    uint8_t led_state[LEDBIT_SIZE];   /* Currently active LEDs */
    uint8_t sw_state[SWBIT_SIZE];     /* Current switch positions */

    struct input_absinfo absinfo[ABS_CNT];

    struct ff_slot    ff_effects[MAX_FF_EFFECTS];
    int               ff_effects_max;
    struct ff_pending ff_pending;
    int               ff_next_id;

    bool created;

    /* Shared memory ring (one per device, broadcast to all readers) */
    int                shmem_fd;                      /* memfd fd             */
    struct evdev_shmem *shmem;                        /* mmap'd ring pointer  */

    /* Per-reader slots (indexed 0..MAX_READERS-1) */
    int                reader_fds[MAX_READERS];       /* control socket fds   */
    int                reader_count;
};

/* ------------------------------------------------------------------ */
/* Client connection state                                            */
/* ------------------------------------------------------------------ */

typedef enum {
    CONN_UNKNOWN = 0,
    CONN_WRITER,
    CONN_READER,
    CONN_LIST,
} conn_type_t;

struct client {
    bool        active;
    int         fd;
    conn_type_t type;
    int         device_id;
};

/* ------------------------------------------------------------------ */
/* Global state (defined in uinput-daemon.c)                          */
/* ------------------------------------------------------------------ */

extern struct virtual_device devices[MAX_DEVICES];
extern struct client         clients[MAX_FDS];
extern int                   server_fd;
extern int                   netlink_fd;   /* persistent AF_NETLINK socket for uevents */

void init_netlink(void);

/* ------------------------------------------------------------------ */
/* Wire I/O (daemon-helpers.c)                                        */
/* ------------------------------------------------------------------ */

int send_all(int fd, const void *buf, size_t len);
int recv_all(int fd, void *buf, size_t len);
int send_msg(int fd, msg_type_t type, const void *payload, uint32_t plen);
int recv_msg(int fd, void *buf, size_t bufsz, uint32_t *payload_len);

/* ------------------------------------------------------------------ */
/* Reply helpers (daemon-helpers.c)                                   */
/* ------------------------------------------------------------------ */

void send_ioctl_reply(int fd, int32_t ret, int32_t err,
                      const void *data, uint32_t dlen);

/* ------------------------------------------------------------------ */
/* Device slot management (daemon-helpers.c)                           */
/* ------------------------------------------------------------------ */

struct virtual_device *alloc_device(void);
struct virtual_device *find_device_by_id(int id);
int                    find_slot_by_num(int device_num);
void                   device_destroy(struct virtual_device *dev);
int                    device_create_shmem(struct virtual_device *dev);
int                    device_allocate_number(struct virtual_device *dev);

/* ------------------------------------------------------------------ */
/* Stub / udev / uevent helpers (daemon-helpers.c)                    */
/* ------------------------------------------------------------------ */

void send_uevent(const char *action, int dev_id);
void send_uevent_input(const char *action, int dev_id);
void device_remove_stub(struct virtual_device *dev);
void device_write_udev_db(struct virtual_device *dev);
void device_remove_udev_db(struct virtual_device *dev);

/* ------------------------------------------------------------------ */
/* Ioctl handlers (daemon-ioctl.c)                                    */
/* ------------------------------------------------------------------ */

void handle_writer_ioctl(int fd, struct virtual_device *dev,
                         uint32_t cmd, uint8_t *data, uint32_t dlen);
void handle_reader_ioctl(int fd, struct virtual_device *dev,
                         uint32_t cmd, uint8_t *data, uint32_t dlen);

/* ------------------------------------------------------------------ */
/* Client management (daemon-helpers.c)                               */
/* ------------------------------------------------------------------ */

struct client *alloc_client(int fd);
void           remove_client(int fd);
void           remove_reader_from_device(struct virtual_device *dev, int fd);
int            add_reader_to_device(struct virtual_device *dev, int fd);

/* SCM_RIGHTS helper (daemon-helpers.c) */
int            send_fds(int sock, int *fds, int nfds);

/* ------------------------------------------------------------------ */
/* Device list / info helpers (daemon-helpers.c)                      */
/* ------------------------------------------------------------------ */

void   send_device_list(int fd);
void   send_device_info(int fd, uint32_t device_id);
