#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <sys/signalfd.h>

#include "fake-systemd.h"

#define PATH_OBJECT_MANAGER     "/org/freedesktop"

#define NETWORK_MANAGER_BUS_NAME "org.freedesktop.NetworkManager"
#define LOGIN1_BUS_NAME          "org.freedesktop.login1"

void logmsg(const char *fmt, ...) {
    fprintf(stderr, "[fake-systemd] ");

    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fputc('\n', stderr);
    fflush(stderr);
}

void require_success(int result, const char *action) {
    if (result >= 0)
        return;
    logmsg("%s failed: %s", action, strerror(-result));
    exit(EXIT_FAILURE);
}

static int handle_termination_signal(sd_event_source *source,
                                     const struct signalfd_siginfo *info __attribute__((unused)),
                                     void *userdata __attribute__((unused))) {
    logmsg("termination requested");
    return sd_event_exit(sd_event_source_get_event(source), 0);
}

static void install_termination_handlers(sd_event *event) {
    sigset_t termination_signals;
    sigemptyset(&termination_signals);
    sigaddset(&termination_signals, SIGTERM);
    sigaddset(&termination_signals, SIGINT);

    if (sigprocmask(SIG_BLOCK, &termination_signals, NULL) != 0) {
        logmsg("sigprocmask failed");
        exit(EXIT_FAILURE);
    }

    require_success(sd_event_add_signal(event, NULL, SIGTERM, handle_termination_signal, NULL),
                    "sd_event_add_signal(SIGTERM)");
    require_success(sd_event_add_signal(event, NULL, SIGINT, handle_termination_signal, NULL),
                    "sd_event_add_signal(SIGINT)");
}

int main(void) {
    if (access("/.container", F_OK) != 0) {
        fprintf(stderr, "fake-systemd: refusing to run outside a container (/.container not found)\n");
        return 1;
    }

    sd_event *event = NULL;
    require_success(sd_event_default(&event), "sd_event_default");
    install_termination_handlers(event);

    sd_bus *bus = NULL;
    require_success(sd_bus_open_system(&bus), "sd_bus_open_system");
    require_success(sd_bus_add_object_manager(bus, NULL, PATH_OBJECT_MANAGER), "sd_bus_add_object_manager");
    networkmanager_register(bus);
    login1_register(bus, event);
    require_success(sd_bus_request_name(bus, NETWORK_MANAGER_BUS_NAME, 0), "sd_bus_request_name(NetworkManager)");
    require_success(sd_bus_request_name(bus, LOGIN1_BUS_NAME, 0), "sd_bus_request_name(login1)");
    require_success(sd_bus_attach_event(bus, event, SD_EVENT_PRIORITY_NORMAL), "sd_bus_attach_event");

    logmsg("serving %s and %s", NETWORK_MANAGER_BUS_NAME, LOGIN1_BUS_NAME);

    int result = sd_event_loop(event);

    pipewire_wake_stop();
    x11_wake_stop();
    sd_bus_flush_close_unref(bus);
    sd_event_unref(event);

    if (result < 0) {
        logmsg("event loop failed: %s", strerror(-result));
        return 1;
    }
    return 0;
}
