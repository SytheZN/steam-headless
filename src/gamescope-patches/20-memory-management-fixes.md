# Fix Vulkan resource management and spec compliance

## Summary

- Fix leaked VkImages for textures that reuse another texture's memory (partial overlay path)
- Fix destruction order so child textures are destroyed before their parent's memory is freed
- Fix two stale result checks in reshade effect manager where `vkBindBufferMemory` return values were silently ignored
- Fix missing `VkExternalMemoryImageCreateInfo` for non-flippable exported images (PipeWire capture textures)
- Fix missing queue family ownership acquire for external destination images

## Details

### VkImage leak in CVulkanTexture destructor (src/rendervulkan.cpp)

When a texture reuses another texture's `VkDeviceMemory` (partial overlay images), `m_vkImageMemory` is set to `VK_NULL_HANDLE` to indicate it doesn't own the memory. However, the destructor only called `vkDestroyImage` inside a `m_vkImageMemory != VK_NULL_HANDLE` guard, so these textures' `VkImage` handles were never destroyed. Each leaked VkImage holds a GEM buffer object in the kernel driver. The fix unconditionally destroys the VkImage.

### Use-after-free from destruction order (src/rendervulkan.cpp)

In `vulkan_make_output_images`, parent output images were destroyed before their partial overlay children. Since children are bound to the parent's `VkDeviceMemory`, this frees the memory while the child's VkImage (and exported dmabuf FDs) still reference it. The fix reverses the destruction order: children first, then parents.

### Stale result check in reshade (src/reshade_effect_manager.cpp)

Two `vkBindBufferMemory` calls didn't capture their return value — the subsequent `if (result != VK_SUCCESS)` check was testing the result of the prior `vkAllocateMemory` call instead. The fix assigns the `vkBindBufferMemory` return to `result`.

### Missing VkExternalMemoryImageCreateInfo for non-flippable exported images (`src/rendervulkan.cpp`)

When a texture is created with `bExportable=true`, its memory is allocated with `VkExportMemoryAllocateInfo` declaring `VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT`, and later exported via `vkGetMemoryFdKHR`. However, `VkExternalMemoryImageCreateInfo` was only chained into the `VkImageCreateInfo` pNext in two specific code paths: the DRM format modifier export path (requires `bFlippable`) and the dmabuf import path (requires `pDMA != nullptr`). PipeWire capture textures (`bExportable=true, bMappable=true, bLinear=true, bFlippable=false`) missed both paths entirely — the VkImage was created without telling the driver it would be used for external memory, but the memory was exported as a dmabuf FD anyway. Per the Vulkan spec, `VkExternalMemoryImageCreateInfo` must be included in the pNext chain when the bound memory will be exported with that handle type. Without it, the driver is not required to make the resulting FD importable by another process. The fix broadens the condition to chain `VkExternalMemoryImageCreateInfo` whenever `bExportable` is true (not just when `bFlippable` triggers the modifier path), while skipping the case where the modifier export path already added it.

### Missing queue family ownership acquire for external destination images (src/rendervulkan.cpp)

`prepareDestImage` set `needsExport=true` for external images but not `needsImport=true`. After the first frame exports an image to the external queue family (`VK_QUEUE_FAMILY_FOREIGN_EXT` / `VK_QUEUE_FAMILY_EXTERNAL_KHR`), subsequent frames used the image without re-acquiring ownership — the non-flush barrier had `srcQueueFamilyIndex == dstQueueFamilyIndex` (both gamescope's queue), but the image was actually owned by the external queue family from the previous frame's export. Additionally, `image->queueFamily` was never updated after export, so the tracked owner diverged from reality. Per the Vulkan spec, both halves of a queue family ownership transfer are required. The fix adds `needsImport=true` in `prepareDestImage` for external images, and updates `image->queueFamily` in `insertBarrier` after both import and export barriers so ownership tracking stays correct across frames.
