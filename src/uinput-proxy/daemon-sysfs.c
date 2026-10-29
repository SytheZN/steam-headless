#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <limits.h>
#include <ftw.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/stat.h>

#include "daemon.h"

#define BITS_PER_WORD   64
#define TEXT_MAX        8192

/* ------------------------------------------------------------------ */
/* Kernel-format attribute text                                       */
/* ------------------------------------------------------------------ */

static bool bitmap_test(const uint8_t *bits, size_t nbytes, int bit) {
    size_t byte = (size_t)bit / 8;
    return byte < nbytes && (bits[byte] >> (bit % 8)) & 1;
}

static uint64_t bitmap_word(const uint8_t *bits, size_t nbytes, int word) {
    uint64_t value = 0;
    for (int b = 0; b < 8; b++) {
        size_t byte = (size_t)word * 8 + (size_t)b;
        if (byte < nbytes)
            value |= (uint64_t)bits[byte] << (8 * b);
    }
    return value;
}

/* Matches input_print_bitmap() for 64-bit unsigned long words. On real sysfs a
 * 32-bit (compat) reader gets each word split into 32-bit halves instead
 * (input_bits_to_string() in input-compat.c); a static file has one format. */
static size_t format_bitmap(char *out, size_t outsz, const uint8_t *bits, size_t nbytes, int max) {
    size_t len = 0;
    bool skip_empty = true;
    for (int word = (max + BITS_PER_WORD - 1) / BITS_PER_WORD - 1; word >= 0; word--) {
        uint64_t value = bitmap_word(bits, nbytes, word);
        if (!value && skip_empty) continue;
        skip_empty = false;
        len += (size_t)snprintf(out + len, outsz - len, "%" PRIx64 "%s", value, word > 0 ? " " : "");
    }
    if (len == 0)
        len = (size_t)snprintf(out, outsz, "0");
    return len;
}

static size_t format_modalias_bits(char *out, size_t outsz, char name,
                                   const uint8_t *bits, size_t nbytes, int min_bit, int max_bit) {
    size_t len = (size_t)snprintf(out, outsz, "%c", name);
    for (int bit = min_bit; bit < max_bit; bit++)
        if (bitmap_test(bits, nbytes, bit))
            len += (size_t)snprintf(out + len, outsz - len, "%X,", bit);
    return len;
}

static void format_modalias(char *out, size_t outsz, const struct virtual_device *dev) {
    size_t len = (size_t)snprintf(out, outsz, "input:b%04Xv%04Xp%04Xe%04X-",
                                  dev->input_id.bustype, dev->input_id.vendor,
                                  dev->input_id.product, dev->input_id.version);
    len += format_modalias_bits(out + len, outsz - len, 'e', dev->evbit,  sizeof(dev->evbit),  0, EV_MAX);
    len += format_modalias_bits(out + len, outsz - len, 'k', dev->keybit, sizeof(dev->keybit), KEY_MIN_INTERESTING, KEY_MAX);
    len += format_modalias_bits(out + len, outsz - len, 'r', dev->relbit, sizeof(dev->relbit), 0, REL_MAX);
    len += format_modalias_bits(out + len, outsz - len, 'a', dev->absbit, sizeof(dev->absbit), 0, ABS_MAX);
    len += format_modalias_bits(out + len, outsz - len, 'm', dev->mscbit, sizeof(dev->mscbit), 0, MSC_MAX);
    len += format_modalias_bits(out + len, outsz - len, 'l', dev->ledbit, sizeof(dev->ledbit), 0, LED_MAX);
    len += format_modalias_bits(out + len, outsz - len, 's', dev->sndbit, sizeof(dev->sndbit), 0, SND_MAX);
    len += format_modalias_bits(out + len, outsz - len, 'f', dev->ffbit,  sizeof(dev->ffbit),  0, FF_MAX);
    format_modalias_bits(out + len, outsz - len, 'w', dev->swbit,  sizeof(dev->swbit),  0, SW_MAX);
}

struct capability {
    const char    *attr;
    const char    *uevent_key;
    int            ev_type;
    const uint8_t *bits;
    size_t         nbytes;
    int            max;
};

static size_t device_capabilities(const struct virtual_device *dev, struct capability *caps) {
    const struct capability all[] = {
        { "ev",  "EV",  -1,     dev->evbit,  sizeof(dev->evbit),  EV_MAX  },
        { "key", "KEY", EV_KEY, dev->keybit, sizeof(dev->keybit), KEY_MAX },
        { "rel", "REL", EV_REL, dev->relbit, sizeof(dev->relbit), REL_MAX },
        { "abs", "ABS", EV_ABS, dev->absbit, sizeof(dev->absbit), ABS_MAX },
        { "msc", "MSC", EV_MSC, dev->mscbit, sizeof(dev->mscbit), MSC_MAX },
        { "led", "LED", EV_LED, dev->ledbit, sizeof(dev->ledbit), LED_MAX },
        { "snd", "SND", EV_SND, dev->sndbit, sizeof(dev->sndbit), SND_MAX },
        { "ff",  "FF",  EV_FF,  dev->ffbit,  sizeof(dev->ffbit),  FF_MAX  },
        { "sw",  "SW",  EV_SW,  dev->swbit,  sizeof(dev->swbit),  SW_MAX  },
    };
    memcpy(caps, all, sizeof(all));
    return sizeof(all) / sizeof(all[0]);
}

static bool capability_reported(const struct virtual_device *dev, const struct capability *cap) {
    return cap->ev_type < 0 || bitmap_test(dev->evbit, sizeof(dev->evbit), cap->ev_type);
}

/* ------------------------------------------------------------------ */
/* Mirror filesystem helpers                                          */
/* ------------------------------------------------------------------ */

static void mirror_path(char *out, size_t outsz, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static void mirror_path(char *out, size_t outsz, const char *fmt, ...) {
    size_t len = (size_t)snprintf(out, outsz, "%s/", SYSFS_MIRROR_ROOT);
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(out + len, outsz - len, fmt, ap);
    va_end(ap);
}

static void make_dir(const char *path) {
    if (mkdir(path, 0755) < 0 && errno != EEXIST)
        logmsg("sysfs mirror: mkdir %s: %s", path, strerror(errno));
}

static void write_text(const char *path, const char *text) {
    FILE *f = fopen(path, "w");
    if (!f) {
        logmsg("sysfs mirror: write %s: %s", path, strerror(errno));
        return;
    }
    fputs(text, f);
    fclose(f);
    chmod(path, 0444);
}

static void make_link(const char *target, const char *path) {
    unlink(path);
    if (symlink(target, path) < 0)
        logmsg("sysfs mirror: symlink %s -> %s: %s", path, target, strerror(errno));
}

static int remove_entry(const char *path, const struct stat *st, int type, struct FTW *ftw) {
    (void)st; (void)type; (void)ftw;
    remove(path);
    return 0;
}

static void remove_tree(const char *path) {
    nftw(path, remove_entry, 16, FTW_DEPTH | FTW_PHYS);
}

/* ------------------------------------------------------------------ */
/* /proc/bus/input/devices                                            */
/* ------------------------------------------------------------------ */

static void write_proc_devices(const struct virtual_device *removed) {
    char text[TEXT_MAX * 2];
    size_t len = 0;
    for (int i = 0; i < MAX_DEVICES; i++) {
        const struct virtual_device *dev = &devices[i];
        if (!dev->active || !dev->created || dev == removed) continue;

        len += (size_t)snprintf(text + len, sizeof(text) - len,
            "I: Bus=%04x Vendor=%04x Product=%04x Version=%04x\n"
            "N: Name=\"%s\"\n"
            "P: Phys=%s\n"
            "S: Sysfs=/devices/virtual/input/input%d\n"
            "U: Uniq=%s\n"
            "H: Handlers=event%d \n",
            dev->input_id.bustype, dev->input_id.vendor, dev->input_id.product, dev->input_id.version,
            dev->name, dev->phys, dev->device_num, dev->uniq, dev->device_num);

        char bitmap[TEXT_MAX];
        format_bitmap(bitmap, sizeof(bitmap), dev->propbit, sizeof(dev->propbit), INPUT_PROP_MAX);
        len += (size_t)snprintf(text + len, sizeof(text) - len, "B: PROP=%s\n", bitmap);

        struct capability caps[16];
        size_t ncaps = device_capabilities(dev, caps);
        for (size_t c = 0; c < ncaps; c++) {
            if (!capability_reported(dev, &caps[c])) continue;
            format_bitmap(bitmap, sizeof(bitmap), caps[c].bits, caps[c].nbytes, caps[c].max);
            len += (size_t)snprintf(text + len, sizeof(text) - len, "B: %s=%s\n", caps[c].uevent_key, bitmap);
        }
        len += (size_t)snprintf(text + len, sizeof(text) - len, "\n");
    }
    text[len < sizeof(text) ? len : sizeof(text) - 1] = '\0';

    char path[PATH_MAX];
    mirror_path(path, sizeof(path), "%s", PROC_INPUT_DEVICES_MIRROR);
    write_text(path, text);
}

/* ------------------------------------------------------------------ */
/* Mirror lifecycle                                                   */
/* ------------------------------------------------------------------ */

void sysfs_mirror_init(void) {
    remove_tree(SYSFS_MIRROR_ROOT);
    make_dir(SYSFS_MIRROR_ROOT);

    const char *dirs[] = {
        "class", "class/input",
        "devices", "devices/virtual", "devices/virtual/input",
        "dev", "dev/char",
    };
    char path[PATH_MAX];
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        mirror_path(path, sizeof(path), "%s", dirs[i]);
        make_dir(path);
    }
    write_proc_devices(NULL);
}

void sysfs_mirror_add(const struct virtual_device *dev) {
    int n = dev->device_num;
    char path[PATH_MAX];
    char text[TEXT_MAX];

    mirror_path(path, sizeof(path), "devices/virtual/input/input%d", n);
    make_dir(path);
    mirror_path(path, sizeof(path), "devices/virtual/input/input%d/id", n);
    make_dir(path);
    mirror_path(path, sizeof(path), "devices/virtual/input/input%d/capabilities", n);
    make_dir(path);
    mirror_path(path, sizeof(path), "devices/virtual/input/input%d/event%d", n, n);
    make_dir(path);

    const struct { const char *attr; const char *value; } strings[] = {
        { "name", dev->name }, { "phys", dev->phys }, { "uniq", dev->uniq },
    };
    for (size_t i = 0; i < sizeof(strings) / sizeof(strings[0]); i++) {
        snprintf(text, sizeof(text), "%s\n", strings[i].value);
        mirror_path(path, sizeof(path), "devices/virtual/input/input%d/%s", n, strings[i].attr);
        write_text(path, text);
    }

    const struct { const char *attr; unsigned value; } ids[] = {
        { "bustype", dev->input_id.bustype }, { "vendor",  dev->input_id.vendor },
        { "product", dev->input_id.product }, { "version", dev->input_id.version },
    };
    for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
        snprintf(text, sizeof(text), "%04x\n", ids[i].value);
        mirror_path(path, sizeof(path), "devices/virtual/input/input%d/id/%s", n, ids[i].attr);
        write_text(path, text);
    }

    struct capability caps[16];
    size_t ncaps = device_capabilities(dev, caps);
    for (size_t c = 0; c < ncaps; c++) {
        size_t len = format_bitmap(text, sizeof(text), caps[c].bits, caps[c].nbytes, caps[c].max);
        snprintf(text + len, sizeof(text) - len, "\n");
        mirror_path(path, sizeof(path), "devices/virtual/input/input%d/capabilities/%s", n, caps[c].attr);
        write_text(path, text);
    }

    size_t len = format_bitmap(text, sizeof(text), dev->propbit, sizeof(dev->propbit), INPUT_PROP_MAX);
    snprintf(text + len, sizeof(text) - len, "\n");
    mirror_path(path, sizeof(path), "devices/virtual/input/input%d/properties", n);
    write_text(path, text);

    char modalias[TEXT_MAX];
    format_modalias(modalias, sizeof(modalias), dev);
    snprintf(text, sizeof(text), "%s\n", modalias);
    mirror_path(path, sizeof(path), "devices/virtual/input/input%d/modalias", n);
    write_text(path, text);

    mirror_path(path, sizeof(path), "devices/virtual/input/input%d/inhibited", n);
    write_text(path, "0\n");

    len = (size_t)snprintf(text, sizeof(text), "PRODUCT=%x/%x/%x/%x\nNAME=\"%s\"\n",
                           dev->input_id.bustype, dev->input_id.vendor,
                           dev->input_id.product, dev->input_id.version, dev->name);
    if (dev->phys[0]) len += (size_t)snprintf(text + len, sizeof(text) - len, "PHYS=\"%s\"\n", dev->phys);
    if (dev->uniq[0]) len += (size_t)snprintf(text + len, sizeof(text) - len, "UNIQ=\"%s\"\n", dev->uniq);
    len += (size_t)snprintf(text + len, sizeof(text) - len, "PROP=");
    len += format_bitmap(text + len, sizeof(text) - len, dev->propbit, sizeof(dev->propbit), INPUT_PROP_MAX);
    len += (size_t)snprintf(text + len, sizeof(text) - len, "\n");
    for (size_t c = 0; c < ncaps; c++) {
        if (!capability_reported(dev, &caps[c])) continue;
        len += (size_t)snprintf(text + len, sizeof(text) - len, "%s=", caps[c].uevent_key);
        len += format_bitmap(text + len, sizeof(text) - len, caps[c].bits, caps[c].nbytes, caps[c].max);
        len += (size_t)snprintf(text + len, sizeof(text) - len, "\n");
    }
    snprintf(text + len, sizeof(text) - len, "MODALIAS=%s\n", modalias);
    mirror_path(path, sizeof(path), "devices/virtual/input/input%d/uevent", n);
    write_text(path, text);

    snprintf(text, sizeof(text), "%d:%d\n", INPUT_MAJOR, EVDEV_MINOR(n));
    mirror_path(path, sizeof(path), "devices/virtual/input/input%d/event%d/dev", n, n);
    write_text(path, text);

    snprintf(text, sizeof(text), "MAJOR=%d\nMINOR=%d\nDEVNAME=input/event%d\n",
             INPUT_MAJOR, EVDEV_MINOR(n), n);
    mirror_path(path, sizeof(path), "devices/virtual/input/input%d/event%d/uevent", n, n);
    write_text(path, text);

    mirror_path(path, sizeof(path), "devices/virtual/input/input%d/subsystem", n);
    make_link("../../../../class/input", path);
    mirror_path(path, sizeof(path), "devices/virtual/input/input%d/event%d/subsystem", n, n);
    make_link("../../../../../class/input", path);
    snprintf(text, sizeof(text), "../../input%d", n);
    mirror_path(path, sizeof(path), "devices/virtual/input/input%d/event%d/device", n, n);
    make_link(text, path);

    snprintf(text, sizeof(text), "../../devices/virtual/input/input%d", n);
    mirror_path(path, sizeof(path), "class/input/input%d", n);
    make_link(text, path);
    snprintf(text, sizeof(text), "../../devices/virtual/input/input%d/event%d", n, n);
    mirror_path(path, sizeof(path), "class/input/event%d", n);
    make_link(text, path);
    mirror_path(path, sizeof(path), "dev/char/%d:%d", INPUT_MAJOR, EVDEV_MINOR(n));
    make_link(text, path);

    write_proc_devices(NULL);
}

void sysfs_mirror_remove(const struct virtual_device *dev) {
    int n = dev->device_num;
    char path[PATH_MAX];

    mirror_path(path, sizeof(path), "dev/char/%d:%d", INPUT_MAJOR, EVDEV_MINOR(n));
    unlink(path);
    mirror_path(path, sizeof(path), "class/input/event%d", n);
    unlink(path);
    mirror_path(path, sizeof(path), "class/input/input%d", n);
    unlink(path);
    mirror_path(path, sizeof(path), "devices/virtual/input/input%d", n);
    remove_tree(path);

    write_proc_devices(dev);
}
