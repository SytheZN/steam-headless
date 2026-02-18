#!/bin/bash
set -e

# Create named pipe for logging
mkfifo "/tmp/headless.log"
tail -f "/tmp/headless.log" &

log "start" "Logging initialized"

# Start D-Bus session bus
export $(dbus-launch)

# In headless mode, don't connect to host audio
if [ "${GAMESCOPE_BACKEND:-headless}" = "headless" ]; then
    unset PULSE_SERVER
fi

# Start PipeWire for audio
pipewire &
pipewire-pulse &
wireplumber &

sleep 3

log "start" "System init complete"

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
    -- session-manager
