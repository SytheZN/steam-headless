#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <linux/input.h>
#include <linux/uinput.h>

#define UINPUT_PROXY_SOCK "/tmp/uinput-proxy.sock"

/* Shared limits (used by both daemon and preload library) */
#define MAX_DEVICES    8
#define MAX_READERS    16
#define MAX_FF_EFFECTS 16

/* Input subsystem constants (from linux kernel) */
#define INPUT_MAJOR        13
#define EVDEV_MINOR_BASE   64
#define EVDEV_MINOR(n)     (EVDEV_MINOR_BASE + (n))
#define UINPUT_MAJOR       10   /* misc device major */
#define UINPUT_MINOR       223
#define MAX_DEVICE_NUM     256   /* scan range for /dev/input/eventN allocation */

/* Evdev input protocol version (EV_VERSION from linux/input.h) */
#define EVDEV_VERSION      0x010001

/* Timing constants */
#define HEARTBEAT_TIMEOUT_SEC   5    /* daemon heartbeat considered dead after this */
#define SLOT_COOLDOWN_SEC       2    /* seconds before a destroyed slot can be reused */

/* Poll timing (nanoseconds) */
#define POLL_FUTEX_CAP_NS       1000000ULL    /* 1ms — futex cap when mixing evdev + other fds */
#define POLL_FUTEX_CAP_ONLY_NS  3000000000ULL /* 3s  — futex cap when only evdev fds */

/* Container user identity (daemon creates nodes owned by this uid/gid) */
#define CONTAINER_UID  1000
#define CONTAINER_GID  1000

/* Message types */
typedef enum {
    /* Client → Daemon (connection setup) */
    MSG_UINPUT_OPEN       = 1,   /* Register as uinput writer. No payload. */
    MSG_EVDEV_OPEN        = 2,   /* Register as evdev reader. Payload: msg_evdev_open */
    MSG_LIST_DEVICES      = 3,   /* Query device list. No payload. */

    /* Writer → Daemon */
    MSG_IOCTL             = 4,   /* Forward ioctl. Payload: msg_ioctl + data */
    MSG_WRITE             = 5,   /* Forward input events. Payload: raw struct input_event[] */

    /* Daemon → Writer */
    MSG_FF_REQUEST        = 6,   /* FF upload/erase queued by reader. Payload: struct input_event (EV_UINPUT) */

    /* Reader → Daemon */
    MSG_EVDEV_WRITE       = 7,   /* EV_FF trigger events. Payload: struct input_event */

    /* 8 reserved */

    /* Shared responses */
    MSG_IOCTL_REPLY       = 9,   /* Payload: msg_ioctl_reply + data */
    MSG_DEVICE_LIST_REPLY = 10,  /* Payload: msg_device_list_reply */

    /* Device info query (for sysfs faking) */
    MSG_DEVICE_INFO       = 11,  /* Query full device info. Payload: msg_evdev_open (device_id) */
    MSG_DEVICE_INFO_REPLY = 12,  /* Full device metadata. Payload: struct device_info */
} msg_type_t;

/* Wire header — prepended to every message */
struct msg_header {
    uint8_t  type;
    uint32_t length;   /* payload length in bytes (NOT including this header) */
} __attribute__((packed));

/* MSG_EVDEV_OPEN payload */
struct msg_evdev_open {
    uint32_t device_num;  /* /dev/input/eventN number, not slot index */
} __attribute__((packed));

/* MSG_IOCTL payload (header + variable data follows) */
struct msg_ioctl {
    uint32_t cmd;
    /* Variable-length data follows: the ioctl argument (size from _IOC_SIZE(cmd) or fixed per cmd) */
} __attribute__((packed));

/* MSG_IOCTL_REPLY payload */
struct msg_ioctl_reply {
    int32_t  ret;
    int32_t  err;      /* errno on failure */
    /* Variable-length data follows: updated ioctl argument (for read-type ioctls) */
} __attribute__((packed));

/* One entry in MSG_DEVICE_LIST_REPLY */
struct device_entry {
    uint32_t id;
    char     name[UINPUT_MAX_NAME_SIZE];
};

/* MSG_DEVICE_LIST_REPLY payload */
struct msg_device_list_reply {
    uint32_t count;
    /* struct device_entry entries[] follows */
};

/* Capability bitfield sizes (kernel-matching) */
#define BITS_TO_BYTES(n) (((n) + 7) / 8)

#define EVBIT_SIZE   BITS_TO_BYTES(EV_CNT)
#define KEYBIT_SIZE  BITS_TO_BYTES(KEY_CNT)
#define ABSBIT_SIZE  BITS_TO_BYTES(ABS_CNT)
#define RELBIT_SIZE  BITS_TO_BYTES(REL_CNT)
#define FFBIT_SIZE   BITS_TO_BYTES(FF_CNT)
#define MSCBIT_SIZE  BITS_TO_BYTES(MSC_CNT)
#define SWBIT_SIZE   BITS_TO_BYTES(SW_CNT)
#define LEDBIT_SIZE  BITS_TO_BYTES(LED_CNT)
#define SNDBIT_SIZE  BITS_TO_BYTES(SND_CNT)
#define PROPBIT_SIZE BITS_TO_BYTES(INPUT_PROP_CNT)

/* MSG_DEVICE_INFO_REPLY payload */
struct device_info {
    uint32_t        id;
    bool            created;
    char            name[UINPUT_MAX_NAME_SIZE];
    struct input_id input_id;
    uint8_t         evbit [EVBIT_SIZE];
    uint8_t         keybit[KEYBIT_SIZE];
    uint8_t         absbit[ABSBIT_SIZE];
    uint8_t         relbit[RELBIT_SIZE];
    uint8_t         ffbit [FFBIT_SIZE];
    uint8_t         mscbit[MSCBIT_SIZE];
    uint8_t         swbit [SWBIT_SIZE];
    uint8_t         ledbit[LEDBIT_SIZE];
    uint8_t         sndbit[SNDBIT_SIZE];
    uint8_t         propbit[PROPBIT_SIZE];
};

/* ------------------------------------------------------------------ */
/* Shared memory event ring                                           */
/* ------------------------------------------------------------------ */

/* Wire event size — always 24 bytes (matching 64-bit struct input_event).
 * On 64-bit this equals sizeof(struct input_event); on 32-bit the preload
 * converts between native 16-byte events and 24-byte wire format.         */
#define WIRE_EVENT_SIZE 24

/* Ring size in frames (wire event units).                             */
#define EVDEV_RING_FRAMES  256

/* Frame <-> byte conversion.  All ring positions are frame numbers;   */
/* these macros produce the byte quantities needed for memcpy/mmap.    */
#define FRAMES_TO_BYTES(n)   ((n)  * WIRE_EVENT_SIZE)
#define BYTES_TO_FRAMES(n)   ((n)  / WIRE_EVENT_SIZE)
#define EVDEV_RING_BYTES     FRAMES_TO_BYTES(EVDEV_RING_FRAMES)

/* Byte offset into the ring buffer for a given frame position.        */
/* pos is a monotonically increasing frame count; the macro wraps it   */
/* into the ring and converts to bytes in one step.                    */
#define FRAME_RING_BYTE(pos) (((pos) % EVDEV_RING_FRAMES) * WIRE_EVENT_SIZE)

/* Shared memory layout — one region per reader connection.            */
/* write_pos is owned by the daemon; read_pos is private to preload.   */
struct evdev_shmem {
    _Atomic uint64_t write_pos;           /* frame count, release-stored by daemon */
    _Atomic uint64_t packet_head;         /* position after last SYN_REPORT (complete packet boundary) */
    _Atomic uint32_t wake_seq;            /* futex word: incremented per write batch */
    _Atomic uint64_t heartbeat;           /* CLOCK_MONOTONIC seconds, updated ~1/s by daemon */
    uint8_t          buf[EVDEV_RING_BYTES];
};

/* ------------------------------------------------------------------ */
/* Helpers for set/test bits */
static inline void bit_set(uint8_t *bits, int bit) {
    bits[bit / 8] |= (1 << (bit % 8));
}
static inline bool bit_test(const uint8_t *bits, int bit) {
    return (bits[bit / 8] >> (bit % 8)) & 1;
}
