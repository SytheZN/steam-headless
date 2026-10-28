#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/epoll.h>

#include <pipewire/pipewire.h>

#include "fake-systemd.h"

#define GAMESCOPE_NODE_NAME "gamescope"

struct wake_watch {
    sd_event *event;
    wake_callback callback;
    struct pw_loop *loop;
    struct pw_context *context;
    struct pw_core *core;
    struct pw_registry *registry;
    struct spa_hook core_listener;
    struct spa_hook registry_listener;
    sd_event_source *io_source;
    sd_event_source *teardown_source;
    int sync_sequence;
    bool initial_sync_done;
    bool gamescope_node_known;
    uint32_t gamescope_node_id;
    bool fired;
};

static struct wake_watch watch;
static bool pipewire_initialized;

static void teardown_watch(void) {
    if (!watch.loop)
        return;

    watch.io_source = sd_event_source_unref(watch.io_source);
    watch.teardown_source = sd_event_source_unref(watch.teardown_source);

    spa_hook_remove(&watch.registry_listener);
    spa_hook_remove(&watch.core_listener);

    if (watch.registry)
        pw_proxy_destroy((struct pw_proxy *)watch.registry);
    if (watch.core)
        pw_core_disconnect(watch.core);
    if (watch.context)
        pw_context_destroy(watch.context);

    pw_loop_leave(watch.loop);
    pw_loop_destroy(watch.loop);

    memset(&watch, 0, sizeof(watch));
    logmsg("stopped watching pipewire");
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
    watch.callback();
}

static int handle_teardown(sd_event_source *source __attribute__((unused)),
                           void *userdata __attribute__((unused))) {
    teardown_watch();
    return 0;
}

static void on_core_done(void *data __attribute__((unused)), uint32_t id, int sequence) {
    if (id == PW_ID_CORE && sequence == watch.sync_sequence)
        watch.initial_sync_done = true;
}

static void on_core_error(void *data __attribute__((unused)), uint32_t id, int sequence __attribute__((unused)),
                          int result, const char *message) {
    if (id != PW_ID_CORE || result != -EPIPE)
        return;
    logmsg("pipewire connection lost: %s", message);
    fire_callback();
}

static bool parse_node_id(const char *text, uint32_t *node_id) {
    char *end = NULL;
    errno = 0;
    unsigned long parsed = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed > UINT32_MAX)
        return false;
    *node_id = (uint32_t)parsed;
    return true;
}

static void track_gamescope_node(uint32_t id, const struct spa_dict *props) {
    const char *node_name = spa_dict_lookup(props, PW_KEY_NODE_NAME);
    if (!node_name || strcmp(node_name, GAMESCOPE_NODE_NAME) != 0)
        return;

    watch.gamescope_node_id = id;
    watch.gamescope_node_known = true;
    logmsg("gamescope node id=%u", id);
}

static void detect_gamescope_link(uint32_t id, const struct spa_dict *props) {
    if (!watch.initial_sync_done || !watch.gamescope_node_known)
        return;

    const char *output_node = spa_dict_lookup(props, PW_KEY_LINK_OUTPUT_NODE);
    uint32_t output_node_id = 0;
    if (!output_node || !parse_node_id(output_node, &output_node_id))
        return;
    if (output_node_id != watch.gamescope_node_id)
        return;

    logmsg("link id=%u from gamescope node id=%u detected", id, output_node_id);
    fire_callback();
}

static void on_registry_global(void *data __attribute__((unused)), uint32_t id,
                               uint32_t permissions __attribute__((unused)), const char *type,
                               uint32_t version __attribute__((unused)), const struct spa_dict *props) {
    if (!props)
        return;

    if (strcmp(type, PW_TYPE_INTERFACE_Node) == 0)
        track_gamescope_node(id, props);
    else if (strcmp(type, PW_TYPE_INTERFACE_Link) == 0)
        detect_gamescope_link(id, props);
}

static const struct pw_core_events core_events = {
    PW_VERSION_CORE_EVENTS,
    .done = on_core_done,
    .error = on_core_error,
};

static const struct pw_registry_events registry_events = {
    PW_VERSION_REGISTRY_EVENTS,
    .global = on_registry_global,
};

static int handle_pipewire_readable(sd_event_source *source __attribute__((unused)),
                                    int fd __attribute__((unused)),
                                    uint32_t revents __attribute__((unused)),
                                    void *userdata __attribute__((unused))) {
    int result = pw_loop_iterate(watch.loop, 0);
    if (result < 0) {
        logmsg("pw_loop_iterate failed: %s", strerror(-result));
        fire_callback();
    }
    return 0;
}

int pipewire_wake_start(sd_event *event, wake_callback callback) {
    if (!pipewire_initialized) {
        pw_init(NULL, NULL);
        pipewire_initialized = true;
    }

    teardown_watch();

    watch.event = event;
    watch.callback = callback;

    watch.loop = pw_loop_new(NULL);
    if (!watch.loop)
        return fail_start("pw_loop_new", -errno);
    pw_loop_enter(watch.loop);

    watch.context = pw_context_new(watch.loop, NULL, 0);
    if (!watch.context)
        return fail_start("pw_context_new", -errno);

    watch.core = pw_context_connect(watch.context, NULL, 0);
    if (!watch.core)
        return fail_start("pw_context_connect", -errno);
    pw_core_add_listener(watch.core, &watch.core_listener, &core_events, NULL);

    watch.registry = pw_core_get_registry(watch.core, PW_VERSION_REGISTRY, 0);
    if (!watch.registry)
        return fail_start("pw_core_get_registry", -errno);
    pw_registry_add_listener(watch.registry, &watch.registry_listener, &registry_events, NULL);

    watch.sync_sequence = pw_core_sync(watch.core, PW_ID_CORE, 0);
    if (watch.sync_sequence < 0)
        return fail_start("pw_core_sync", watch.sync_sequence);

    int result = sd_event_add_io(event, &watch.io_source, pw_loop_get_fd(watch.loop), EPOLLIN,
                                 handle_pipewire_readable, NULL);
    if (result < 0)
        return fail_start("sd_event_add_io", result);

    logmsg("watching pipewire for gamescope stream consumer");
    return 0;
}

void pipewire_wake_stop(void) {
    if (!watch.loop || watch.teardown_source)
        return;

    int result = sd_event_add_defer(watch.event, &watch.teardown_source, handle_teardown, NULL);
    if (result < 0) {
        logmsg("sd_event_add_defer failed: %s", strerror(-result));
        teardown_watch();
    }
}
