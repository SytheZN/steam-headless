# Include overlays in the PipeWire stream

## Problems

1. **MangoHud didn't show on the stream.** The PipeWire capture (used by Steam Remote Play) never painted the external overlay window that `--mangoapp` uses.
2. **Overlays froze when the game stopped rendering.** The capture only pushed a new frame when the game (or its related windows) committed one. If the game stops presenting, e.g. a Unity game pausing when it loses focus while the Steam menu is open, the Steam overlay and MangoHud stopped updating on the stream too.

## Fix

- The external overlay is painted into the capture on top of everything else, when it's visible and there's a free layer.
- Commits from the Steam overlay and the external overlay now count as changes, so the stream keeps updating while either is active even if the game has stopped presenting.
