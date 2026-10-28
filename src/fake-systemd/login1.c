#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "fake-systemd.h"

#define PATH_LOGIN1             "/org/freedesktop/login1"
#define INTERFACE_MANAGER       "org.freedesktop.login1.Manager"

#define CONST_PROPERTY          SD_BUS_VTABLE_PROPERTY_CONST
#define EMITS_CHANGE_PROPERTY   SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE

#define INHIBIT_DELAY_MAX_USEC  5000000ull

#define GETTER_PARAMS \
    sd_bus *bus __attribute__((unused)), \
    const char *path __attribute__((unused)), \
    const char *interface __attribute__((unused)), \
    const char *property __attribute__((unused)), \
    sd_bus_message *reply, \
    void *userdata __attribute__((unused)), \
    sd_bus_error *error __attribute__((unused))

#define METHOD_PARAMS \
    sd_bus_message *message, \
    void *userdata __attribute__((unused)), \
    sd_bus_error *error __attribute__((unused))

static bool preparing_for_sleep;
static sd_bus *login1_bus;
static sd_event *login1_event;

#define DEFINE_BOOL_GETTER(function, value) \
    static int function(GETTER_PARAMS) { \
        int flag = (value); \
        return sd_bus_message_append_basic(reply, SD_BUS_TYPE_BOOLEAN, &flag); \
    }

#define DEFINE_U32_GETTER(function, value) \
    static int function(GETTER_PARAMS) { \
        uint32_t number = (value); \
        return sd_bus_message_append_basic(reply, SD_BUS_TYPE_UINT32, &number); \
    }

#define DEFINE_U64_GETTER(function, value) \
    static int function(GETTER_PARAMS) { \
        uint64_t number = (value); \
        return sd_bus_message_append_basic(reply, SD_BUS_TYPE_UINT64, &number); \
    }

#define DEFINE_STRING_GETTER(function, value) \
    static int function(GETTER_PARAMS) { \
        const char *text = (value); \
        return sd_bus_message_append_basic(reply, SD_BUS_TYPE_STRING, text); \
    }

#define DEFINE_STRING_REPLY(function, value) \
    static int function(METHOD_PARAMS) { \
        return sd_bus_reply_method_return(message, "s", (value)); \
    }

DEFINE_BOOL_GETTER(get_preparing_for_sleep, preparing_for_sleep)
DEFINE_BOOL_GETTER(get_true, 1)
DEFINE_BOOL_GETTER(get_false, 0)

DEFINE_U32_GETTER(get_u32_0, 0)

DEFINE_U64_GETTER(get_u64_0, 0)
DEFINE_U64_GETTER(get_inhibit_delay_max_usec, INHIBIT_DELAY_MAX_USEC)

DEFINE_STRING_GETTER(get_empty_string, "")
DEFINE_STRING_GETTER(get_ignore_string, "ignore")

DEFINE_STRING_REPLY(reply_with_yes, "yes")
DEFINE_STRING_REPLY(reply_with_na, "na")

static void emit_preparing_for_sleep_property_changed(void) {
    require_success(sd_bus_emit_properties_changed(login1_bus, PATH_LOGIN1, INTERFACE_MANAGER,
                                                   "PreparingForSleep", NULL),
                    "sd_bus_emit_properties_changed(PreparingForSleep)");
}

static void emit_prepare_for_sleep_signal(void) {
    int flag = preparing_for_sleep;
    require_success(sd_bus_emit_signal(login1_bus, PATH_LOGIN1, INTERFACE_MANAGER,
                                       "PrepareForSleep", "b", flag),
                    "sd_bus_emit_signal(PrepareForSleep)");
}

static void wake_from_sleep(const char *reason) {
    if (!preparing_for_sleep)
        return;

    pipewire_wake_stop();
    x11_wake_stop();
    preparing_for_sleep = false;
    emit_prepare_for_sleep_signal();
    emit_preparing_for_sleep_property_changed();
    logmsg("waking: %s", reason);
}

static void wake_on_stream_consumer(void) {
    wake_from_sleep("stream consumer connected");
}

static void wake_on_input(void) {
    wake_from_sleep("input detected");
}

static void enter_sleep(void) {
    preparing_for_sleep = true;
    emit_preparing_for_sleep_property_changed();
    emit_prepare_for_sleep_signal();
    logmsg("entering fake sleep");

    if (pipewire_wake_start(login1_event, wake_on_stream_consumer) < 0) {
        logmsg("cannot watch pipewire, waking immediately");
        wake_from_sleep("pipewire unavailable");
    }

    if (preparing_for_sleep && x11_wake_start(login1_event, wake_on_input) < 0)
        logmsg("cannot watch x11 input, relying on stream wake");
}

static int reply_and_enter_sleep(METHOD_PARAMS) {
    int result = sd_bus_reply_method_return(message, NULL);
    if (result < 0)
        return result;

    if (!preparing_for_sleep)
        enter_sleep();
    return result;
}

static int reply_with_inhibitor_fd(METHOD_PARAMS) {
    int pipe_ends[2];
    if (pipe2(pipe_ends, O_CLOEXEC) != 0)
        return -errno;

    int result = sd_bus_reply_method_return(message, "h", pipe_ends[1]);

    close(pipe_ends[0]);
    close(pipe_ends[1]);
    return result;
}

static int reply_with_empty_inhibitors(METHOD_PARAMS) {
    return sd_bus_reply_method_return(message, "a(ssssuu)", 0);
}

static const sd_bus_vtable manager_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_PROPERTY("PreparingForSleep", "b", get_preparing_for_sleep, 0, EMITS_CHANGE_PROPERTY),
    SD_BUS_PROPERTY("PreparingForShutdown", "b", get_false, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("BlockInhibited", "s", get_empty_string, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("DelayInhibited", "s", get_empty_string, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("InhibitDelayMaxUSec", "t", get_inhibit_delay_max_usec, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("IdleHint", "b", get_false, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("IdleSinceHint", "t", get_u64_0, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("IdleSinceHintMonotonic", "t", get_u64_0, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Docked", "b", get_false, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("LidClosed", "b", get_false, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("OnExternalPower", "b", get_true, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("NAutoVTs", "u", get_u32_0, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("KillUserProcesses", "b", get_false, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("HandleLidSwitch", "s", get_ignore_string, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("HandlePowerKey", "s", get_ignore_string, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("HandleSuspendKey", "s", get_ignore_string, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("IdleAction", "s", get_ignore_string, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("IdleActionUSec", "t", get_u64_0, 0, CONST_PROPERTY),
    SD_BUS_METHOD("Suspend", "b", "", reply_and_enter_sleep, 0),
    SD_BUS_METHOD("SuspendWithFlags", "t", "", reply_and_enter_sleep, 0),
    SD_BUS_METHOD("CanSuspend", "", "s", reply_with_yes, 0),
    SD_BUS_METHOD("CanPowerOff", "", "s", reply_with_na, 0),
    SD_BUS_METHOD("CanReboot", "", "s", reply_with_na, 0),
    SD_BUS_METHOD("CanHalt", "", "s", reply_with_na, 0),
    SD_BUS_METHOD("CanHibernate", "", "s", reply_with_na, 0),
    SD_BUS_METHOD("CanHybridSleep", "", "s", reply_with_na, 0),
    SD_BUS_METHOD("CanSuspendThenHibernate", "", "s", reply_with_na, 0),
    SD_BUS_METHOD("CanRebootParameter", "", "s", reply_with_na, 0),
    SD_BUS_METHOD("CanRebootToFirmwareSetup", "", "s", reply_with_na, 0),
    SD_BUS_METHOD("CanRebootToBootLoaderMenu", "", "s", reply_with_na, 0),
    SD_BUS_METHOD("CanRebootToBootLoaderEntry", "", "s", reply_with_na, 0),
    SD_BUS_METHOD("Inhibit", "ssss", "h", reply_with_inhibitor_fd, 0),
    SD_BUS_METHOD("ListInhibitors", "", "a(ssssuu)", reply_with_empty_inhibitors, 0),
    SD_BUS_SIGNAL("PrepareForSleep", "b", 0),
    SD_BUS_SIGNAL("PrepareForShutdown", "b", 0),
    SD_BUS_SIGNAL("SessionNew", "so", 0),
    SD_BUS_SIGNAL("SessionRemoved", "so", 0),
    SD_BUS_SIGNAL("UserNew", "uo", 0),
    SD_BUS_SIGNAL("UserRemoved", "uo", 0),
    SD_BUS_SIGNAL("SeatNew", "so", 0),
    SD_BUS_SIGNAL("SeatRemoved", "so", 0),
    SD_BUS_VTABLE_END
};

void login1_register(sd_bus *bus, sd_event *event) {
    login1_bus = bus;
    login1_event = event;

    require_success(sd_bus_add_object_vtable(bus, NULL, PATH_LOGIN1, INTERFACE_MANAGER, manager_vtable, NULL),
                    "sd_bus_add_object_vtable(login1.Manager)");
}
