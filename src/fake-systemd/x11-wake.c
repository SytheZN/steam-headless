#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <sys/epoll.h>

#include <xcb/xcb.h>
#include <xcb/xinput.h>

#include "fake-systemd.h"

#define X11_SOCKET_DIRECTORY    "/tmp/.X11-unix"
#define X11_SOCKET_PREFIX       'X'
#define DISPLAY_NAME_SIZE       32
#define XINPUT_MAJOR_VERSION    2
#define XINPUT_MINOR_VERSION    2

#define RAW_INPUT_MASK \
    (XCB_INPUT_XI_EVENT_MASK_RAW_KEY_PRESS | \
     XCB_INPUT_XI_EVENT_MASK_RAW_BUTTON_PRESS | \
     XCB_INPUT_XI_EVENT_MASK_RAW_MOTION)

struct wake_watch {
    sd_event *event;
    wake_callback callback;
    xcb_connection_t *connection;
    uint8_t input_opcode;
    sd_event_source *io_source;
    sd_event_source *teardown_source;
    bool fired;
};

struct raw_input_selection {
    xcb_input_event_mask_t header;
    uint32_t mask_word;
};

static struct wake_watch watch;

static void teardown_watch(void) {
    if (!watch.connection)
        return;

    watch.io_source = sd_event_source_unref(watch.io_source);
    watch.teardown_source = sd_event_source_unref(watch.teardown_source);

    xcb_disconnect(watch.connection);

    memset(&watch, 0, sizeof(watch));
    logmsg("stopped watching x11");
}

static int fail_start(const char *action, int result) {
    logmsg("%s failed: %s", action, strerror(-result));
    teardown_watch();
    return result;
}

static void fire_callback(void) {
    if (watch.fired)
        return;
    watch.fired = true;
    logmsg("raw input detected");
    watch.callback();
}

static int handle_teardown(sd_event_source *source __attribute__((unused)),
                           void *userdata __attribute__((unused))) {
    teardown_watch();
    return 0;
}

static bool parse_display_number(const char *socket_name, unsigned long *display_number) {
    if (socket_name[0] != X11_SOCKET_PREFIX)
        return false;

    const char *digits = socket_name + 1;
    if (*digits == '\0' || strspn(digits, "0123456789") != strlen(digits))
        return false;

    char *end = NULL;
    errno = 0;
    unsigned long parsed = strtoul(digits, &end, 10);
    if (errno != 0 || *end != '\0' || parsed > INT_MAX)
        return false;

    *display_number = parsed;
    return true;
}

static int find_display(char *display, size_t display_size) {
    DIR *directory = opendir(X11_SOCKET_DIRECTORY);
    if (!directory)
        return -errno;

    bool found = false;
    unsigned long lowest_number = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        unsigned long display_number = 0;
        if (!parse_display_number(entry->d_name, &display_number))
            continue;
        if (!found || display_number < lowest_number) {
            lowest_number = display_number;
            found = true;
        }
    }
    closedir(directory);

    if (!found)
        return -ENOENT;

    int written = snprintf(display, display_size, ":%lu", lowest_number);
    if (written < 0 || (size_t)written >= display_size)
        return -ENAMETOOLONG;
    return 0;
}

static int check_xinput_version(void) {
    xcb_input_xi_query_version_cookie_t cookie =
        xcb_input_xi_query_version(watch.connection, XINPUT_MAJOR_VERSION, XINPUT_MINOR_VERSION);
    xcb_input_xi_query_version_reply_t *reply =
        xcb_input_xi_query_version_reply(watch.connection, cookie, NULL);
    if (!reply)
        return -EPROTO;

    bool supported = reply->major_version >= XINPUT_MAJOR_VERSION;
    free(reply);
    return supported ? 0 : -ENOTSUP;
}

static int select_raw_input(void) {
    const xcb_setup_t *setup = xcb_get_setup(watch.connection);
    xcb_window_t root = xcb_setup_roots_iterator(setup).data->root;

    struct raw_input_selection selection = {
        .header = {
            .deviceid = XCB_INPUT_DEVICE_ALL_MASTER,
            .mask_len = 1,
        },
        .mask_word = RAW_INPUT_MASK,
    };

    xcb_void_cookie_t cookie = xcb_input_xi_select_events_checked(watch.connection, root, 1, &selection.header);
    xcb_generic_error_t *error = xcb_request_check(watch.connection, cookie);
    if (error) {
        free(error);
        return -EPROTO;
    }
    return 0;
}

static bool is_raw_input_event(const xcb_generic_event_t *event) {
    if ((event->response_type & 0x7f) != XCB_GE_GENERIC)
        return false;
    return ((const xcb_ge_generic_event_t *)event)->extension == watch.input_opcode;
}

static int handle_x11_readable(sd_event_source *source __attribute__((unused)),
                               int fd __attribute__((unused)),
                               uint32_t revents __attribute__((unused)),
                               void *userdata __attribute__((unused))) {
    xcb_generic_event_t *event;
    while ((event = xcb_poll_for_event(watch.connection)) != NULL) {
        if (is_raw_input_event(event))
            fire_callback();
        free(event);
    }

    if (xcb_connection_has_error(watch.connection)) {
        logmsg("x11 connection lost");
        x11_wake_stop();
    }
    return 0;
}

int x11_wake_start(sd_event *event, wake_callback callback) {
    teardown_watch();

    watch.event = event;
    watch.callback = callback;

    char display[DISPLAY_NAME_SIZE];
    int result = find_display(display, sizeof(display));
    if (result < 0)
        return fail_start("find_display", result);

    watch.connection = xcb_connect(display, NULL);
    if (!watch.connection || xcb_connection_has_error(watch.connection))
        return fail_start("xcb_connect", -ECONNREFUSED);

    const xcb_query_extension_reply_t *extension = xcb_get_extension_data(watch.connection, &xcb_input_id);
    if (!extension || !extension->present)
        return fail_start("xcb_get_extension_data(XInputExtension)", -ENOTSUP);
    watch.input_opcode = extension->major_opcode;

    result = check_xinput_version();
    if (result < 0)
        return fail_start("xcb_input_xi_query_version", result);

    result = select_raw_input();
    if (result < 0)
        return fail_start("xcb_input_xi_select_events", result);

    if (xcb_flush(watch.connection) <= 0)
        return fail_start("xcb_flush", -EIO);

    result = sd_event_add_io(event, &watch.io_source, xcb_get_file_descriptor(watch.connection), EPOLLIN,
                             handle_x11_readable, NULL);
    if (result < 0)
        return fail_start("sd_event_add_io", result);

    logmsg("watching x11 display %s for input", display);
    return 0;
}

void x11_wake_stop(void) {
    if (!watch.connection || watch.teardown_source)
        return;

    int result = sd_event_add_defer(watch.event, &watch.teardown_source, handle_teardown, NULL);
    if (result < 0) {
        logmsg("sd_event_add_defer failed: %s", strerror(-result));
        teardown_watch();
    }
}
