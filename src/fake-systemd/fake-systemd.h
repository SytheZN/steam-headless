#ifndef FAKE_SYSTEMD_H
#define FAKE_SYSTEMD_H

#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>

typedef void (*wake_callback)(void);

void logmsg(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void require_success(int result, const char *action);

void networkmanager_register(sd_bus *bus);
void login1_register(sd_bus *bus, sd_event *event);

int pipewire_wake_start(sd_event *event, wake_callback callback);
void pipewire_wake_stop(void);

int x11_wake_start(sd_event *event, wake_callback callback);
void x11_wake_stop(void);

#endif
