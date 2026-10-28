#!/bin/bash
set -e

# Create named pipe for logging; tee output to both stdout and a persistent log file
mkdir -p "/home/steam/.local/share/Steam/logs"
mkfifo "/tmp/headless.log"
tail -f "/tmp/headless.log" &

log "start" "Logging initialized"

eval "$(setup-uinput)"
/usr/local/bin/uinput-daemon &

until [ -S /tmp/uinput-proxy.sock ]; do sleep 0.1; done

export $(dbus-launch)

saved_zone=$(cat /home/steam/.steam/timezone 2>/dev/null || true)
if settz "${saved_zone:-UTC}"; then
    log "start" "Time zone: ${saved_zone:-UTC}"
else
    settz UTC
    log "start" "Time zone '${saved_zone}' invalid, using UTC"
fi

rm -f /run/dbus/system_bus_socket
dbus-daemon --config-file=/etc/dbus-1/headless-system.conf --fork --nopidfile
fake-systemd &

# In headless mode, don't connect to host audio
if [ "${GAMESCOPE_BACKEND:-headless}" = "headless" ]; then
    unset PULSE_SERVER
fi

pipewire &
pipewire-pulse &
wireplumber &

sleep 3

log "start" "System init complete"

# Resolve resolution name to width/height
case "${GAMESCOPE_RESOLUTION:-1080p}" in
    360p)  GS_WIDTH=640;  GS_HEIGHT=360  ;;
    480p)  GS_WIDTH=853;  GS_HEIGHT=480  ;;
    720p)  GS_WIDTH=1280; GS_HEIGHT=720  ;;
    1080p) GS_WIDTH=1920; GS_HEIGHT=1080 ;;
    1440p) GS_WIDTH=2560; GS_HEIGHT=1440 ;;
    4k)    GS_WIDTH=3840; GS_HEIGHT=2160 ;;
    *)
        log "start" "Unknown resolution '${GAMESCOPE_RESOLUTION}', defaulting to 1080p"
        GS_WIDTH=1920; GS_HEIGHT=1080
        ;;
esac
log "start" "Resolution: ${GAMESCOPE_RESOLUTION:-1080p} (${GS_WIDTH}x${GS_HEIGHT})"

# Build gamescope debug flags
GAMESCOPE_DEBUG_FLAGS=""
if csvhas focus "$HEADLESS_DEBUG"; then
    log "start" "Enabling focus debugging"
    GAMESCOPE_DEBUG_FLAGS="--debug-focus"
fi

# Start Gamescope with configurable backend
# Use GAMESCOPE_BACKEND env var (defaults to headless)
# For setup: GAMESCOPE_BACKEND=sdl docker compose up
if [ "${GAMESCOPE_BACKEND:-headless}" != "headless" ]; then
    export WAYLAND_DISPLAY=host-wayland-0
fi

exec gamescope \
    --steam \
    --backend ${GAMESCOPE_BACKEND:-headless} \
    --xwayland-count 1 \
    --mangoapp \
    --prefer-vk-device /dev/dri/renderD128 \
    -W $GS_WIDTH -H $GS_HEIGHT \
    -r 60 \
    $GAMESCOPE_DEBUG_FLAGS \
    -- session-manager
