#!/bin/sh
# Launch the Futura desktop shell with proper environment
# This script should be run after the Wayland compositor has started

# Set environment variables needed for Wayland client
export WAYLAND_DISPLAY=wayland-0
export XDG_RUNTIME_DIR=/tmp

# Give the compositor time to initialize
echo "[SHELL-LAUNCHER] Waiting for Wayland display..."
sleep 2

# Check if Wayland socket exists
if [ ! -S "${XDG_RUNTIME_DIR}/${WAYLAND_DISPLAY}" ]; then
    echo "[SHELL-LAUNCHER] Wayland display not found at ${XDG_RUNTIME_DIR}/${WAYLAND_DISPLAY}"
    echo "[SHELL-LAUNCHER] Available sockets:"
    ls -la ${XDG_RUNTIME_DIR}/wayland* 2>/dev/null || echo "  (none found)"
    exit 1
fi

echo "[SHELL-LAUNCHER] Launching futura-shell..."
exec /sbin/futura-shell
