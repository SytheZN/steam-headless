#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <linux/uinput.h>

#include "daemon.h"

/* Joystick API ioctl NR fields (linux/joystick.h) */
#define JSIOCGAXES_NR    0x11
#define JSIOCGBUTTONS_NR 0x12
#define JSIOCGNAME_NR    0x13

/* Kernel bits_to_user() return value */
#define BITS_PER_LONG (sizeof(long) * 8)
#define BITS_TO_LONGS(n) (((n) + BITS_PER_LONG - 1) / BITS_PER_LONG)
#define BITS_RET(maxbit, sz) \
    ((int32_t)((sz) < BITS_TO_LONGS(maxbit) * sizeof(long) \
        ? (sz) : BITS_TO_LONGS(maxbit) * sizeof(long)))

/* ------------------------------------------------------------------ */
/* Writer ioctl handler                                               */
/* ------------------------------------------------------------------ */

void handle_writer_ioctl(int fd, struct virtual_device *dev,
                         uint32_t cmd, uint8_t *data, uint32_t dlen) {
    if (cmd == UI_GET_VERSION) {
        uint32_t ver = UINPUT_VERSION;
        send_ioctl_reply(fd, 0, 0, &ver, sizeof(ver));
        return;
    }

    if (cmd == UI_DEV_SETUP) {
        if (dlen >= sizeof(struct uinput_setup)) {
            struct uinput_setup *s = (struct uinput_setup *)data;
            memcpy(dev->name, s->name, UINPUT_MAX_NAME_SIZE);
            dev->name[UINPUT_MAX_NAME_SIZE - 1] = '\0';
            dev->input_id       = s->id;
            dev->ff_effects_max = s->ff_effects_max;
            dlog("UI_DEV_SETUP device=%d name='%s' vendor=%04x product=%04x",
                 dev->id, dev->name, s->id.vendor, s->id.product);
        }
        send_ioctl_reply(fd, 0, 0, NULL, 0);
        return;
    }

    if (cmd == UI_ABS_SETUP) {
        if (dlen >= sizeof(struct uinput_abs_setup)) {
            struct uinput_abs_setup *s = (struct uinput_abs_setup *)data;
            if (s->code < ABS_CNT)
                dev->absinfo[s->code] = s->absinfo;
        }
        send_ioctl_reply(fd, 0, 0, NULL, 0);
        return;
    }

    if (cmd == UI_SET_PHYS) {
        size_t n = strnlen((char *)data, dlen);
        if (n < sizeof(dev->phys)) {
            memcpy(dev->phys, data, n);
            dev->phys[n] = '\0';
        }
        send_ioctl_reply(fd, 0, 0, NULL, 0);
        return;
    }

    if (cmd == UI_DEV_CREATE) {
        /* Kernel always forces EV_SYN on input_register_device() */
        bit_set(dev->evbit, EV_SYN);

        if (device_create_shmem(dev) < 0) {
            send_ioctl_reply(fd, -1, errno, NULL, 0);
            return;
        }

        if (device_allocate_number(dev) < 0) {
            send_ioctl_reply(fd, -1, ENOSPC, NULL, 0);
            return;
        }

        dev->created = true;
        device_write_udev_db(dev);
        send_uevent_input("add", dev->device_num);
        send_uevent("add", dev->device_num);
        logmsg("device slot %d created as /dev/input/event%d: %s", dev->id, dev->device_num, dev->name);
        send_ioctl_reply(fd, 0, 0, NULL, 0);
        return;
    }

    if (cmd == UI_DEV_DESTROY) {
        device_destroy(dev);
        send_ioctl_reply(fd, 0, 0, NULL, 0);
        return;
    }

#define HANDLE_SETBIT(uicmd, arr, cnt) \
    if (cmd == (uicmd)) { \
        if (dlen >= 4) { int b = *(int32_t *)data; if (b >= 0 && b < (cnt)) bit_set(dev->arr, b); } \
        send_ioctl_reply(fd, 0, 0, NULL, 0); return; \
    }
    HANDLE_SETBIT(UI_SET_EVBIT,   evbit,   EV_CNT)
    HANDLE_SETBIT(UI_SET_KEYBIT,  keybit,  KEY_CNT)
    HANDLE_SETBIT(UI_SET_ABSBIT,  absbit,  ABS_CNT)
    HANDLE_SETBIT(UI_SET_RELBIT,  relbit,  REL_CNT)
    HANDLE_SETBIT(UI_SET_FFBIT,   ffbit,   FF_CNT)
    HANDLE_SETBIT(UI_SET_MSCBIT,  mscbit,  MSC_CNT)
    HANDLE_SETBIT(UI_SET_SWBIT,   swbit,   SW_CNT)
    HANDLE_SETBIT(UI_SET_LEDBIT,  ledbit,  LED_CNT)
    HANDLE_SETBIT(UI_SET_SNDBIT,  sndbit,  SND_CNT)
    HANDLE_SETBIT(UI_SET_PROPBIT, propbit, INPUT_PROP_CNT)
#undef HANDLE_SETBIT

    if (cmd == UI_BEGIN_FF_UPLOAD) {
        struct ff_pending *p = &dev->ff_pending;
        if (p->type == FF_PENDING_UPLOAD) {
            struct uinput_ff_upload up;
            memset(&up, 0, sizeof(up));
            up.request_id = (uint32_t)p->effect_slot;
            up.retval     = 0;
            up.effect     = p->effect;
            send_ioctl_reply(fd, 0, 0, &up, sizeof(up));
        } else {
            send_ioctl_reply(fd, -1, EINVAL, NULL, 0);
        }
        return;
    }

    if (cmd == UI_END_FF_UPLOAD) {
        struct ff_pending *p = &dev->ff_pending;
        if (p->type == FF_PENDING_UPLOAD && dlen >= sizeof(struct uinput_ff_upload)) {
            struct uinput_ff_upload *up = (struct uinput_ff_upload *)data;
            p->writer_ret  = up->retval;
            p->writer_done = true;
            if (p->reader_fd >= 0) {
                if (up->retval == 0)
                    send_ioctl_reply(p->reader_fd, 0, 0, &p->effect,
                                     sizeof(struct ff_effect));
                else
                    send_ioctl_reply(p->reader_fd, -1, EIO, NULL, 0);
            }
            p->type = FF_PENDING_NONE;
        }
        send_ioctl_reply(fd, 0, 0, NULL, 0);
        return;
    }

    if (cmd == UI_BEGIN_FF_ERASE) {
        struct ff_pending *p = &dev->ff_pending;
        if (p->type == FF_PENDING_ERASE) {
            struct uinput_ff_erase er;
            memset(&er, 0, sizeof(er));
            er.request_id = (uint32_t)p->effect_id;
            er.retval     = 0;
            send_ioctl_reply(fd, 0, 0, &er, sizeof(er));
        } else {
            send_ioctl_reply(fd, -1, EINVAL, NULL, 0);
        }
        return;
    }

    if (cmd == UI_END_FF_ERASE) {
        struct ff_pending *p = &dev->ff_pending;
        if (p->type == FF_PENDING_ERASE) {
            p->writer_done = true;
            if (p->reader_fd >= 0)
                send_ioctl_reply(p->reader_fd, 0, 0, NULL, 0);
            p->type = FF_PENDING_NONE;
        }
        send_ioctl_reply(fd, 0, 0, NULL, 0);
        return;
    }

    logmsg("writer ioctl: unknown cmd 0x%08x", cmd);
    send_ioctl_reply(fd, -1, EINVAL, NULL, 0);
}

/* ------------------------------------------------------------------ */
/* Reader ioctl handler                                               */
/* ------------------------------------------------------------------ */

void handle_reader_ioctl(int fd, struct virtual_device *dev,
                         uint32_t cmd, uint8_t *data, uint32_t dlen) {
    if (cmd == EVIOCGVERSION) {
        int32_t ver = EVDEV_VERSION;
        send_ioctl_reply(fd, 0, 0, &ver, sizeof(ver));
        return;
    }

    if (cmd == EVIOCGID) {
        send_ioctl_reply(fd, 0, 0, &dev->input_id, sizeof(dev->input_id));
        return;
    }

    if (_IOC_TYPE(cmd) == 'E' && _IOC_NR(cmd) == _IOC_NR(EVIOCGNAME(0))) {
        size_t sz = _IOC_SIZE(cmd);
        char buf[256] = {0};
        size_t n = strnlen(dev->name, UINPUT_MAX_NAME_SIZE);
        if (n >= sizeof(buf)) n = sizeof(buf) - 1;
        memcpy(buf, dev->name, n);
        size_t reply_sz = sz < sizeof(buf) ? sz : sizeof(buf);
        send_ioctl_reply(fd, (int32_t)n + 1, 0, buf, (uint32_t)reply_sz);
        return;
    }

    if (_IOC_TYPE(cmd) == 'E' && _IOC_NR(cmd) == _IOC_NR(EVIOCGPHYS(0))) {
        size_t sz = _IOC_SIZE(cmd);
        char buf[256] = {0};
        strncpy(buf, dev->phys, sizeof(buf) - 1);
        size_t reply_sz = sz < sizeof(buf) ? sz : sizeof(buf);
        send_ioctl_reply(fd, (int32_t)strlen(buf) + 1, 0, buf, (uint32_t)reply_sz);
        return;
    }

    if (_IOC_TYPE(cmd) == 'E' && _IOC_NR(cmd) == _IOC_NR(EVIOCGUNIQ(0))) {
        size_t sz = _IOC_SIZE(cmd);
        char buf[256] = {0};
        strncpy(buf, dev->uniq, sizeof(buf) - 1);
        size_t reply_sz = sz < sizeof(buf) ? sz : sizeof(buf);
        send_ioctl_reply(fd, (int32_t)strlen(buf) + 1, 0, buf, (uint32_t)reply_sz);
        return;
    }

    if (_IOC_TYPE(cmd) == 'E' && _IOC_NR(cmd) == _IOC_NR(EVIOCGPROP(0))) {
        size_t sz = _IOC_SIZE(cmd);
        uint8_t buf[PROPBIT_SIZE] = {0};
        size_t  copy = sz < PROPBIT_SIZE ? sz : PROPBIT_SIZE;
        memcpy(buf, dev->propbit, copy);
        send_ioctl_reply(fd, BITS_RET(INPUT_PROP_MAX, sz), 0, buf, sz);
        return;
    }

    if (_IOC_TYPE(cmd) == 'E' && _IOC_NR(cmd) >= _IOC_NR(EVIOCGBIT(0,0))
            && _IOC_NR(cmd) <= _IOC_NR(EVIOCGBIT(EV_MAX,0))) {
        int    ev_type = _IOC_NR(cmd) - _IOC_NR(EVIOCGBIT(0,0));
        size_t sz      = _IOC_SIZE(cmd);
        uint8_t zeros[KEY_CNT/8+1] = {0};
        const uint8_t *bits = zeros;
        size_t         bsz  = sizeof(zeros);
        int            maxbit = 0;

        switch (ev_type) {
            case 0:       bits = dev->evbit;   bsz = EVBIT_SIZE;  maxbit = EV_MAX;  break;
            case EV_KEY:  bits = dev->keybit;  bsz = KEYBIT_SIZE; maxbit = KEY_MAX; break;
            case EV_ABS:  bits = dev->absbit;  bsz = ABSBIT_SIZE; maxbit = ABS_MAX; break;
            case EV_REL:  bits = dev->relbit;  bsz = RELBIT_SIZE; maxbit = REL_MAX; break;
            case EV_FF:   bits = dev->ffbit;   bsz = FFBIT_SIZE;  maxbit = FF_MAX;  break;
            case EV_MSC:  bits = dev->mscbit;  bsz = MSCBIT_SIZE; maxbit = MSC_MAX; break;
            case EV_SW:   bits = dev->swbit;   bsz = SWBIT_SIZE;  maxbit = SW_MAX;  break;
            case EV_LED:  bits = dev->ledbit;  bsz = LEDBIT_SIZE; maxbit = LED_MAX; break;
            case EV_SND:  bits = dev->sndbit;  bsz = SNDBIT_SIZE; maxbit = SND_MAX; break;
            default: break;
        }
        uint8_t buf[KEY_CNT/8+1];
        memset(buf, 0, sizeof(buf));
        size_t copy = sz < bsz ? sz : bsz;
        memcpy(buf, bits, copy);
        send_ioctl_reply(fd, BITS_RET(maxbit, sz), 0, buf, sz);
        return;
    }

    if (_IOC_TYPE(cmd) == 'E' &&
            _IOC_NR(cmd) >= _IOC_NR(EVIOCGABS(0)) &&
            _IOC_NR(cmd) <  _IOC_NR(EVIOCGABS(0)) + ABS_CNT) {
        int axis = _IOC_NR(cmd) - _IOC_NR(EVIOCGABS(0));
        send_ioctl_reply(fd, 0, 0, &dev->absinfo[axis], sizeof(struct input_absinfo));
        return;
    }

    if (cmd == EVIOCGEFFECTS) {
        int32_t n = dev->ff_effects_max;
        send_ioctl_reply(fd, 0, 0, &n, sizeof(n));
        return;
    }

    if (_IOC_TYPE(cmd) == 'E' && (
            _IOC_NR(cmd) == _IOC_NR(EVIOCGKEY(0)) ||
            _IOC_NR(cmd) == _IOC_NR(EVIOCGLED(0)) ||
            _IOC_NR(cmd) == _IOC_NR(EVIOCGSW(0)))) {
        size_t sz = _IOC_SIZE(cmd);
        uint8_t buf[KEY_CNT / 8 + 1];
        memset(buf, 0, sizeof(buf));

        const uint8_t *state;
        size_t state_size;
        int maxbit;

        if (_IOC_NR(cmd) == _IOC_NR(EVIOCGKEY(0))) {
            state = dev->key_state;
            state_size = KEYBIT_SIZE;
            maxbit = KEY_MAX;
        } else if (_IOC_NR(cmd) == _IOC_NR(EVIOCGLED(0))) {
            state = dev->led_state;
            state_size = LEDBIT_SIZE;
            maxbit = LED_MAX;
        } else {
            state = dev->sw_state;
            state_size = SWBIT_SIZE;
            maxbit = SW_MAX;
        }

        size_t copy_size = sz < state_size ? sz : state_size;
        memcpy(buf, state, copy_size);

        send_ioctl_reply(fd, BITS_RET(maxbit, sz), 0, buf, sz);
        return;
    }

    if (_IOC_TYPE(cmd) == 'j') {
        if (_IOC_NR(cmd) == JSIOCGNAME_NR) {
            size_t sz = _IOC_SIZE(cmd);
            char buf[256] = {0};
            strncpy(buf, dev->name, sizeof(buf) - 1);
            size_t reply_sz = sz < sizeof(buf) ? sz : sizeof(buf);
            send_ioctl_reply(fd, (int32_t)strlen(buf) + 1, 0, buf, (uint32_t)reply_sz);
            return;
        }
        if (_IOC_NR(cmd) == JSIOCGAXES_NR) {
            uint8_t count = 0;
            for (int i = 0; i < ABS_CNT; i++)
                if (dev->absbit[i / 8] & (1 << (i % 8))) count++;
            send_ioctl_reply(fd, 0, 0, &count, sizeof(count));
            return;
        }
        if (_IOC_NR(cmd) == JSIOCGBUTTONS_NR) {
            uint8_t count = 0;
            for (int i = 0; i < KEY_CNT; i++)
                if (dev->keybit[i / 8] & (1 << (i % 8))) count++;
            send_ioctl_reply(fd, 0, 0, &count, sizeof(count));
            return;
        }
    }

    if (cmd == EVIOCSFF && dlen >= sizeof(struct ff_effect)) {
        struct ff_effect *eff = (struct ff_effect *)data;

        int slot = -1;
        if (eff->id >= 0) {
            for (int i = 0; i < MAX_FF_EFFECTS; i++)
                if (dev->ff_effects[i].used && dev->ff_effects[i].id == eff->id) {
                    slot = i; break;
                }
        }
        if (slot < 0) {
            for (int i = 0; i < MAX_FF_EFFECTS; i++)
                if (!dev->ff_effects[i].used) { slot = i; break; }
        }
        if (slot < 0) { send_ioctl_reply(fd, -1, ENOSPC, NULL, 0); return; }

        int effect_id;
        if (eff->id >= 0 && dev->ff_effects[slot].used) {
            effect_id = dev->ff_effects[slot].id;
        } else {
            /* Wrap within int16_t range, skip collisions */
            do {
                if (dev->ff_next_id > INT16_MAX || dev->ff_next_id < 1)
                    dev->ff_next_id = 1;
                effect_id = dev->ff_next_id++;
                bool collision = false;
                for (int ci = 0; ci < MAX_FF_EFFECTS; ci++)
                    if (dev->ff_effects[ci].used && dev->ff_effects[ci].id == effect_id)
                        { collision = true; break; }
                if (!collision) break;
            } while (1);
        }
        dev->ff_effects[slot].used      = true;
        dev->ff_effects[slot].id        = effect_id;
        dev->ff_effects[slot].effect    = *eff;
        dev->ff_effects[slot].effect.id = effect_id;

        if (dev->writer_fd >= 0) {
            if (dev->ff_pending.type != FF_PENDING_NONE) {
                send_ioctl_reply(fd, -1, EBUSY, NULL, 0);
                return;
            }
            dev->ff_pending.type        = FF_PENDING_UPLOAD;
            dev->ff_pending.reader_fd   = fd;
            dev->ff_pending.effect_slot = slot;
            dev->ff_pending.effect      = dev->ff_effects[slot].effect;
            dev->ff_pending.effect_id   = effect_id;
            dev->ff_pending.writer_done = false;

            struct input_event ev = {
                .type  = EV_UINPUT,
                .code  = UI_FF_UPLOAD,
                .value = (int32_t)slot,
            };
            send_msg(dev->writer_fd, MSG_FF_REQUEST, &ev, sizeof(ev));
        } else {
            send_ioctl_reply(fd, 0, 0, &dev->ff_effects[slot].effect,
                             sizeof(struct ff_effect));
        }
        return;
    }

    if (cmd == EVIOCRMFF) {
        if (dlen < sizeof(int32_t)) { send_ioctl_reply(fd, -1, EINVAL, NULL, 0); return; }
        int32_t effect_id = *(int32_t *)data;
        int slot = -1;
        for (int i = 0; i < MAX_FF_EFFECTS; i++)
            if (dev->ff_effects[i].used && dev->ff_effects[i].id == effect_id) {
                slot = i; break;
            }
        if (slot < 0) { send_ioctl_reply(fd, -1, EINVAL, NULL, 0); return; }
        dev->ff_effects[slot].used = false;

        if (dev->writer_fd >= 0) {
            if (dev->ff_pending.type != FF_PENDING_NONE) {
                send_ioctl_reply(fd, -1, EBUSY, NULL, 0);
                return;
            }
            dev->ff_pending.type        = FF_PENDING_ERASE;
            dev->ff_pending.reader_fd   = fd;
            dev->ff_pending.effect_id   = effect_id;
            dev->ff_pending.writer_done = false;

            struct input_event ev = {
                .type  = EV_UINPUT,
                .code  = UI_FF_ERASE,
                .value = effect_id,
            };
            send_msg(dev->writer_fd, MSG_FF_REQUEST, &ev, sizeof(ev));
        } else {
            send_ioctl_reply(fd, 0, 0, NULL, 0);
        }
        return;
    }

    /* No competing readers outside the container; accept as no-op */
    if (cmd == EVIOCGRAB || cmd == EVIOCREVOKE) {
        send_ioctl_reply(fd, 0, 0, NULL, 0);
        return;
    }

    /* Clock type is handled per-reader in the preload library */
    if (cmd == EVIOCSCLOCKID) {
        send_ioctl_reply(fd, 0, 0, NULL, 0);
        return;
    }

    logmsg("reader ioctl: unknown cmd 0x%08x", cmd);
    send_ioctl_reply(fd, -1, EINVAL, NULL, 0);
}
