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

# In headless mode, don't connect to host audio
if [ "${GAMESCOPE_BACKEND:-headless}" = "headless" ]; then
    unset PULSE_SERVER
fi

pipewire &
pipewire-pulse &
wireplumber &

sleep 3

log "start" "System init complete"

# Build gamescope debug flags
GAMESCOPE_DEBUG_FLAGS=""
if csvhas focus "$HEADLESS_DEBUG"; then
    log "start" "Enabling focus debugging"
    GAMESCOPE_DEBUG_FLAGS="--debug-focus"
fi

# Start Gamescope with configurable backend
# Use GAMESCOPE_BACKEND env var (defaults to headless)
# For setup: GAMESCOPE_BACKEND=sdl docker compose up
WAYLAND_DISPLAY=host-wayland-0 exec gamescope \
    --steam \
    --backend ${GAMESCOPE_BACKEND:-headless} \
    --xwayland-count 1 \
    --prefer-vk-device /dev/dri/renderD128 \
    -W 1920 -H 1080 \
    -r 60 \
    $GAMESCOPE_DEBUG_FLAGS \
    -- session-manager
