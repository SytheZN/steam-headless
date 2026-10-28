# Fix slow PipeWire capture on discrete GPUs

## Problem

While streaming, each PipeWire capture took ~18ms of GPU time on an RTX 5090. That's longer than a 60Hz frame, so gamescope missed every other vblank and vsynced games and the Steam UI dropped to 30fps.

Every step of the capture was writing somewhere slow:

- The RGB intermediate texture was allocated in system RAM (`bMappable`), so the GPU wrote and read it over PCIe.
- The NV12 conversion wrote straight into the exported PipeWire buffer, a linear multi-planar image. NVIDIA is very slow at writing those, whether from a shader or with an image copy.

## Fix

- The RGB intermediate and DMA-BUF PipeWire buffers are no longer mappable, so they live in VRAM. Screenshot and memfd buffers stay mappable because the CPU reads them.
- The NV12 conversion writes into a VRAM scratch image instead of the PipeWire buffer.
- The PipeWire buffer's DMA-BUF is re-imported as a `VkBuffer`, and the scratch image is copied into it with `vkCmdCopyImageToBuffer`. Copying into a buffer avoids NVIDIA's slow linear-image path. Same memory, same layout, so consumers see no difference.
- Exported (non-scanout) images prefer a device-local memory type that isn't host-visible.
- The RGB10 format check now looks at optimal tiling, since the intermediate is no longer linear.

## Result

| Pass | Before | After (1440p) |
| ---- | ------ | ------------- |
| Blit | 5.2ms | 0.08ms |
| NV12 | 12.9ms | 0.02ms |
| Copy | — | 0.01ms |

Stream holds 60fps.
