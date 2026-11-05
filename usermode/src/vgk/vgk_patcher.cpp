#include "vgk_patcher.hpp"
#include "../hypercall/hypercall.hpp"
#include "../util/log.hpp"

#include <Windows.h>
#include <unordered_map>
#include <cstring>

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

// ============================================================================
// Hypercall Wrappers (adapt local API to V2 hc:: API)
// ============================================================================
namespace
{
    std::uint64_t current_cr3()
    {
        return hc::curr_cr3();
    }

    std::uint64_t translate_va(std::uint64_t va, std::uint64_t cr3)
    {
        return hc::translate_va(cr3, va);
    }

    std::uint64_t read_guest_virtual_memory(void* dest, std::uint64_t src_va, std::uint64_t src_cr3, std::uint64_t size)
    {
        std::uint64_t dest_pa = hc::translate_va(hc::curr_cr3(), reinterpret_cast<std::uint64_t>(dest));
        if (dest_pa == 0) return 0;

        if (hc::virt_copy(src_cr3, src_va, hc::curr_cr3(), reinterpret_cast<std::uint64_t>(dest), size))
            return size;
        return 0;
    }

    std::uint64_t read_guest_physical_memory(void* dest, std::uint64_t src_pa, std::uint64_t size)
    {
        std::uint64_t dest_pa = hc::translate_va(hc::curr_cr3(), reinterpret_cast<std::uint64_t>(dest));
        if (dest_pa == 0) return 0;

        if (hc::phys_copy(src_pa, dest_pa, size))
            return size;
        return 0;
    }

    std::uint64_t write_guest_virtual_memory(const void* src, std::uint64_t dest_va, std::uint64_t dest_cr3, std::uint64_t size)
    {
        if (hc::virt_copy(hc::curr_cr3(), reinterpret_cast<std::uint64_t>(src), dest_cr3, dest_va, size))
            return size;
        return 0;
    }

    bool add_slat_code_hook(std::uint64_t target_pa, std::uint64_t shadow_pa)
    {
        return hc::hook_add(target_pa, shadow_pa);
    }

    std::uint64_t remove_slat_code_hook(std::uint64_t target_pa)
    {
        return hc::hook_remove(target_pa) ? 1 : 0;
    }

    void* allocate_locked_memory(std::size_t size, DWORD protect)
    {
        void* ptr = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, protect);
        if (ptr)
        {
            VirtualLock(ptr, size);
        }
        return ptr;
    }

    void free_locked_memory(void* ptr)
    {
        if (ptr)
        {
            VirtualFree(ptr, 0, MEM_RELEASE);
        }
    }
}

// ============================================================================
// VGK Patcher Implementation
// ============================================================================
namespace
{
    constexpr std::uint64_t vgk_page_size = 0x1000;

    std::uint64_t vgk_base_address = 0;
    bool initialized = false;
    std::uint32_t vgk_time_date_stamp = 0;

    std::vector<vgk_patcher::callback_patch_t> vgk_callbacks = {
        {"ObCallback",       0x1031C, {0}, false, 0, 0},
        {"ProcessNotify #2", 0x10B6C, {0}, false, 0, 0},
        {"ThreadNotify",     0x12038, {0}, false, 0, 0},
        {"Registry",         0x102E8, {0}, false, 0, 0},
    };

    constexpr std::uint64_t REGISTRY_ALT_OFFSET = 0xB63DF;
    constexpr std::uint8_t registry_alt_patch = 0xFF;
    constexpr std::uint64_t registry_alt_patch_offset_in_insn = 2;

    struct shadow_info_t
    {
        void* shadow_page_mapped;
        std::uint64_t shadow_page_physical;
        std::uint64_t target_page_physical;
        int ref_count;
    };

    std::unordered_map<std::uint64_t, shadow_info_t> shadow_pages;
    std::unordered_map<std::uint64_t, std::uint64_t> callback_to_page;

    constexpr std::uint8_t patch_byte = 0xC3;

    // Pattern patches tracking
    std::vector<std::uint8_t> module_cache;
    std::uint64_t cached_module_base = 0;
    std::uint64_t cached_module_size = 0;

    struct pattern_patch_info_t
    {
        std::string name;
        std::uint64_t vgk_offset;
        std::uint64_t page_pa;
        std::uint64_t patch_write_offset;
        std::vector<std::uint8_t> original_bytes;
        std::vector<std::uint8_t> patch_bytes;
    };
    std::vector<pattern_patch_info_t> pattern_patches;

    struct direct_patch_info_t
    {
        std::string name;
        std::uint64_t vgk_offset;
        std::vector<std::uint8_t> original_bytes;
        std::vector<std::uint8_t> patch_bytes;
    };
    std::vector<direct_patch_info_t> direct_patches;

    bool pattern_match(const std::uint8_t* data, const std::uint8_t* pattern,
                       const std::uint8_t* mask, std::size_t len)
    {
        for (std::size_t i = 0; i < len; i++)
        {
            if (mask[i] == 0xFF) continue;
            if (data[i] != pattern[i]) return false;
        }
        return true;
    }
}

bool vgk_patcher::initialize()
{
    if (initialized)
        return true;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll)
    {
        LOG_ERR("[VGK] Failed to get ntdll handle");
        return false;
    }

    using NtQuerySystemInformation_t = NTSTATUS(WINAPI*)(
        ULONG SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength
    );

    auto NtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformation_t>(
        GetProcAddress(ntdll, "NtQuerySystemInformation")
    );

    if (!NtQuerySystemInformation)
    {
        LOG_ERR("[VGK] Failed to get NtQuerySystemInformation");
        return false;
    }

    ULONG size = 0;
    NtQuerySystemInformation(11, nullptr, 0, &size);

    if (size == 0)
    {
        LOG_ERR("[VGK] Failed to get module info size");
        return false;
    }

    std::vector<std::uint8_t> buffer(size + 0x1000);
    NTSTATUS status = NtQuerySystemInformation(11, buffer.data(), static_cast<ULONG>(buffer.size()), &size);

    if (status != 0)
    {
        LOG_ERR("[VGK] NtQuerySystemInformation failed: 0x{:X}", static_cast<unsigned>(status));
        return false;
    }

    struct RTL_PROCESS_MODULE_INFORMATION
    {
        HANDLE Section;
        PVOID MappedBase;
        PVOID ImageBase;
        ULONG ImageSize;
        ULONG Flags;
        USHORT LoadOrderIndex;
        USHORT InitOrderIndex;
        USHORT LoadCount;
        USHORT OffsetToFileName;
        UCHAR FullPathName[256];
    };

    struct RTL_PROCESS_MODULES
    {
        ULONG NumberOfModules;
        RTL_PROCESS_MODULE_INFORMATION Modules[1];
    };

    auto modules = reinterpret_cast<RTL_PROCESS_MODULES*>(buffer.data());

    for (ULONG i = 0; i < modules->NumberOfModules; i++)
    {
        const char* name = reinterpret_cast<const char*>(
            modules->Modules[i].FullPathName + modules->Modules[i].OffsetToFileName
        );

        if (_stricmp(name, "vgk.sys") == 0)
        {
            vgk_base_address = reinterpret_cast<std::uint64_t>(modules->Modules[i].ImageBase);
            LOG_INFO("[VGK] Found vgk.sys at 0x{:X}, size 0x{:X}",
                     vgk_base_address, modules->Modules[i].ImageSize);
            break;
        }
    }

    if (vgk_base_address == 0)
    {
        LOG_ERR("[VGK] vgk.sys not found in loaded modules");
        return false;
    }

    // Read PE headers to get TimeDateStamp
    IMAGE_DOS_HEADER dos_header = {};
    if (read_guest_virtual_memory(&dos_header, vgk_base_address, current_cr3(),
                                  sizeof(dos_header)) == 0 ||
        dos_header.e_magic != IMAGE_DOS_SIGNATURE)
    {
        LOG_ERR("[VGK] Failed to read DOS header");
        return false;
    }

    IMAGE_NT_HEADERS64 nt_headers = {};
    if (read_guest_virtual_memory(&nt_headers,
                                  vgk_base_address + dos_header.e_lfanew,
                                  current_cr3(), sizeof(nt_headers)) == 0 ||
        nt_headers.Signature != IMAGE_NT_SIGNATURE)
    {
        LOG_ERR("[VGK] Failed to read NT headers");
        return false;
    }

    vgk_time_date_stamp = nt_headers.FileHeader.TimeDateStamp;
    LOG_INFO("[VGK] vgk.sys TimeDateStamp: 0x{:X}", vgk_time_date_stamp);

    // Read original bytes for each callback
    for (auto& cb : vgk_callbacks)
    {
        std::uint64_t callback_va = vgk_base_address + cb.offset;

        if (read_guest_virtual_memory(cb.original_bytes, callback_va, current_cr3(), 8) == 0)
        {
            LOG_ERR("[VGK] Failed to read original bytes for {} at 0x{:X}",
                    cb.name, callback_va);
            return false;
        }

        LOG_INFO("[VGK] {} @ vgk+0x{:X} (0x{:X}): {:02X} {:02X} {:02X} {:02X} {:02X}",
                 cb.name, cb.offset, callback_va,
                 cb.original_bytes[0], cb.original_bytes[1], cb.original_bytes[2],
                 cb.original_bytes[3], cb.original_bytes[4]);
    }

    initialized = true;
    return true;
}

std::uint32_t vgk_patcher::get_vgk_timedatestamp()
{
    return vgk_time_date_stamp;
}

std::uint64_t vgk_patcher::get_vgk_base()
{
    return vgk_base_address;
}

std::uint64_t vgk_patcher::get_vgk_size()
{
    return cached_module_size;
}

bool vgk_patcher::is_vgk_loaded()
{
    return vgk_base_address != 0;
}

std::vector<vgk_patcher::callback_patch_t>& vgk_patcher::get_callbacks()
{
    return vgk_callbacks;
}

bool vgk_patcher::patch_callback(std::uint64_t vgk_offset)
{
    if (!initialized && !initialize())
        return false;

    callback_patch_t* target_cb = nullptr;
    for (auto& cb : vgk_callbacks)
    {
        if (cb.offset == vgk_offset)
        {
            target_cb = &cb;
            break;
        }
    }

    if (!target_cb)
    {
        LOG_ERR("[VGK] Unknown callback offset 0x{:X}", vgk_offset);
        return false;
    }

    if (target_cb->is_patched)
    {
        LOG_INFO("[VGK] {} already patched", target_cb->name);
        return true;
    }

    std::uint64_t callback_va = vgk_base_address + vgk_offset;
    std::uint64_t callback_pa = translate_va(callback_va, current_cr3());

    if (callback_pa == 0)
    {
        LOG_ERR("[VGK] Failed to translate VA 0x{:X} to physical", callback_va);
        return false;
    }

    std::uint64_t page_pa = callback_pa & ~0xFFFULL;
    std::uint64_t page_offset = callback_pa & 0xFFF;

    LOG_INFO("[VGK] Patching {}: VA=0x{:X} PA=0x{:X} PageOffset=0x{:X}",
             target_cb->name, callback_va, callback_pa, page_offset);

    const std::uint64_t patch_write_offset = (vgk_offset == REGISTRY_ALT_OFFSET)
        ? (page_offset + registry_alt_patch_offset_in_insn)
        : page_offset;

    auto it = shadow_pages.find(page_pa);
    if (it != shadow_pages.end())
    {
        LOG_INFO("[VGK] Page 0x{:X} already hooked, patching existing shadow", page_pa);

        std::uint8_t* const shadow_mapped = static_cast<std::uint8_t*>(it->second.shadow_page_mapped);
        std::uint8_t* const patch_location = shadow_mapped + patch_write_offset;
        const std::uint8_t original_byte_at_write = *patch_location;

        if (vgk_offset == REGISTRY_ALT_OFFSET)
            *patch_location = registry_alt_patch;
        else
            *patch_location = patch_byte;

        it->second.ref_count++;
        callback_to_page[vgk_offset] = page_pa;
        target_cb->patch_write_offset = patch_write_offset;
        target_cb->original_byte = original_byte_at_write;
        target_cb->is_patched = true;

        LOG_INFO("[VGK] {} PATCHED (reused shadow)", target_cb->name);
        return true;
    }

    void* shadow_page = allocate_locked_memory(vgk_page_size, PAGE_READWRITE);
    if (!shadow_page)
    {
        LOG_ERR("[VGK] Failed to allocate shadow page");
        return false;
    }

    std::uint64_t shadow_pa = translate_va(reinterpret_cast<std::uint64_t>(shadow_page), current_cr3());
    if (shadow_pa == 0)
    {
        LOG_ERR("[VGK] Failed to translate shadow page to physical");
        free_locked_memory(shadow_page);
        return false;
    }

    std::uint64_t bytes_copied = read_guest_physical_memory(shadow_page, page_pa, vgk_page_size);
    if (bytes_copied != vgk_page_size)
    {
        LOG_ERR("[VGK] Partial read of original page: {} / {} bytes", bytes_copied, vgk_page_size);
        free_locked_memory(shadow_page);
        return false;
    }

    std::uint8_t* shadow_bytes = static_cast<std::uint8_t*>(shadow_page);
    std::uint8_t* const patch_location = shadow_bytes + patch_write_offset;
    const std::uint8_t original_byte_at_write = *patch_location;

    if (vgk_offset == REGISTRY_ALT_OFFSET)
        *patch_location = registry_alt_patch;
    else
        *patch_location = patch_byte;

    LOG_INFO("[VGK] Shadow @ 0x{:X} (post-patch): {:02X}",
             patch_write_offset, *patch_location);

    if (!add_slat_code_hook(page_pa, shadow_pa))
    {
        LOG_ERR("[VGK] Failed to add EPT hook");
        free_locked_memory(shadow_page);
        return false;
    }

    shadow_pages[page_pa] = {shadow_page, shadow_pa, page_pa, 1};
    callback_to_page[vgk_offset] = page_pa;
    target_cb->patch_write_offset = patch_write_offset;
    target_cb->original_byte = original_byte_at_write;
    target_cb->is_patched = true;

    LOG_INFO("[VGK] {} PATCHED successfully (EPT split-view active)", target_cb->name);
    return true;
}

bool vgk_patcher::restore_callback(std::uint64_t vgk_offset)
{
    callback_patch_t* target_cb = nullptr;
    for (auto& cb : vgk_callbacks)
    {
        if (cb.offset == vgk_offset)
        {
            target_cb = &cb;
            break;
        }
    }

    if (!target_cb || !target_cb->is_patched)
        return true;

    auto page_it = callback_to_page.find(vgk_offset);
    if (page_it == callback_to_page.end())
        return false;

    std::uint64_t page_pa = page_it->second;
    auto shadow_it = shadow_pages.find(page_pa);
    if (shadow_it == shadow_pages.end())
        return false;

    std::uint8_t* const shadow_mapped = static_cast<std::uint8_t*>(shadow_it->second.shadow_page_mapped);
    shadow_mapped[target_cb->patch_write_offset] = target_cb->original_byte;

    const int new_ref_count = shadow_it->second.ref_count - 1;

    if (new_ref_count <= 0)
    {
        if (remove_slat_code_hook(shadow_it->second.target_page_physical) != 1)
        {
            LOG_ERR("[VGK] Failed to remove EPT hook for page 0x{:X}", page_pa);
            return false;
        }

        free_locked_memory(shadow_it->second.shadow_page_mapped);
        shadow_pages.erase(shadow_it);
        callback_to_page.erase(page_it);
        target_cb->is_patched = false;

        LOG_INFO("[VGK] {} RESTORED (EPT hook removed)", target_cb->name);
    }
    else
    {
        shadow_it->second.ref_count = new_ref_count;
        callback_to_page.erase(page_it);
        target_cb->is_patched = false;

        LOG_INFO("[VGK] {} RESTORED (shadow page still in use)", target_cb->name);
    }

    return true;
}

vgk_patcher::patch_status_t vgk_patcher::patch_all_callbacks()
{
    if (!initialized && !initialize())
        return patch_status_t::partial_undefined;

    LOG_INFO("[VGK] ========== PATCHING ALL CALLBACKS ==========");

    std::vector<std::uint64_t> patched_offsets;

    for (const auto& cb : vgk_callbacks)
    {
        if (!patch_callback(cb.offset))
        {
            LOG_ERR("[VGK] Failed to patch {} - rolling back", cb.name);

            for (auto it = patched_offsets.rbegin(); it != patched_offsets.rend(); ++it)
                restore_callback(*it);

            return patch_status_t::rolled_back;
        }

        patched_offsets.push_back(cb.offset);
    }

    LOG_INFO("[VGK] ========== PATCH COMPLETE ==========");
    return patch_status_t::all_patched;
}

bool vgk_patcher::restore_all_callbacks()
{
    bool all_success = true;

    LOG_INFO("[VGK] ========== RESTORING ALL CALLBACKS ==========");

    for (const auto& cb : vgk_callbacks)
    {
        if (cb.is_patched && !restore_callback(cb.offset))
            all_success = false;
    }

    LOG_INFO("[VGK] ========== RESTORE COMPLETE ==========");
    return all_success;
}

bool vgk_patcher::cleanup()
{
    if (restore_all_callbacks())
    {
        vgk_base_address = 0;
        initialized = false;
        return true;
    }
    return false;
}

// ============================================================================
// Pattern Scanning
// ============================================================================

bool vgk_patcher::cache_module()
{
    if (!initialized && !initialize())
        return false;

    IMAGE_DOS_HEADER dos_header = {};
    if (read_guest_virtual_memory(&dos_header, vgk_base_address, current_cr3(), sizeof(dos_header)) == 0)
        return false;

    IMAGE_NT_HEADERS64 nt_headers = {};
    if (read_guest_virtual_memory(&nt_headers, vgk_base_address + dos_header.e_lfanew, current_cr3(), sizeof(nt_headers)) == 0)
        return false;

    cached_module_size = nt_headers.OptionalHeader.SizeOfImage;
    cached_module_base = vgk_base_address;

    LOG_INFO("[VGK] Caching module: base=0x{:X} size=0x{:X}", cached_module_base, cached_module_size);

    module_cache.resize(cached_module_size);

    constexpr std::uint64_t chunk_size = 0x1000;
    for (std::uint64_t offset = 0; offset < cached_module_size; offset += chunk_size)
    {
        std::uint64_t read_size = (std::min)(chunk_size, cached_module_size - offset);
        std::uint64_t bytes_read = read_guest_virtual_memory(
            &module_cache[offset], cached_module_base + offset, current_cr3(), read_size);

        if (bytes_read != read_size)
            std::memset(&module_cache[offset], 0xCC, read_size);
    }

    LOG_INFO("[VGK] Module cached successfully ({} bytes)", cached_module_size);
    return true;
}

std::vector<std::uint64_t> vgk_patcher::scan_pattern(const std::uint8_t* pattern,
                                                      const std::uint8_t* mask,
                                                      std::size_t len,
                                                      std::uint64_t start_offset,
                                                      std::uint64_t end_offset)
{
    std::vector<std::uint64_t> results;

    if (module_cache.empty() && !cache_module())
        return results;

    if (end_offset == 0) end_offset = module_cache.size();
    if (end_offset > module_cache.size()) end_offset = module_cache.size();

    for (std::uint64_t i = start_offset; i < end_offset - len; i++)
    {
        if (pattern_match(&module_cache[i], pattern, mask, len))
            results.push_back(i);
    }

    return results;
}

// ============================================================================
// Pattern Definitions
// ============================================================================

std::vector<vgk_patcher::pattern_def_t> vgk_patcher::get_bts_patterns()
{
    return {
        // CPUID FMA mismatch - bit 12
        {"BTS Bit12_FMA", {0x0F, 0xBA, 0x2D, 0x00, 0x00, 0x00, 0x00, 0x0C},
                         {0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00},
                         {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90}, 1, 0},
        // CPUID CMPXCHG16B - bit 13
        {"BTS Bit13_CX16", {0x0F, 0xBA, 0x2D, 0x00, 0x00, 0x00, 0x00, 0x0D},
                          {0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00},
                          {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90}, 1, 0},
        // CPUID xTPR - bit 14
        {"BTS Bit14_xTPR", {0x0F, 0xBA, 0x2D, 0x00, 0x00, 0x00, 0x00, 0x0E},
                          {0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00},
                          {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90}, 1, 0},
        // BYOVD driver blocked - bit 17
        {"BTS Bit17_BYOVD", {0x0F, 0xBA, 0x2D, 0x00, 0x00, 0x00, 0x00, 0x11},
                           {0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00},
                           {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90}, 1, 0},
        // CPUID SSE4.2 - bit 20
        {"BTS Bit20_SSE42", {0x0F, 0xBA, 0x2D, 0x00, 0x00, 0x00, 0x00, 0x14},
                           {0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00},
                           {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90}, 1, 0},
        // Hypervisor detected - bit 26 (2 locations expected)
        {"BTS Bit26_HV", {0x0F, 0xBA, 0x2D, 0x00, 0x00, 0x00, 0x00, 0x1A},
                         {0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00},
                         {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90}, 2, 0}
    };
}

std::vector<vgk_patcher::pattern_def_t> vgk_patcher::get_jump_patterns()
{
    return {
        {"JNZ Bypass", {0x0F, 0x84, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x84, 0xC0, 0x0F, 0x85, 0x00, 0x00, 0x00, 0x00},
                       {0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00},
                       {0x90, 0xE9}, 1, 13},
        {"JZ #2 NOP", {0x48, 0x85, 0xC9, 0x0F, 0x84, 0xF0, 0x01, 0x00, 0x00},
                      {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                      {0x90, 0x90, 0x90, 0x90, 0x90, 0x90}, 1, 3}
    };
}

std::vector<vgk_patcher::pattern_def_t> vgk_patcher::get_callback_patterns()
{
    return {
        {"vgk_handle_post_operation",
            {0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xF9, 0x48, 0x8B, 0xDA, 0x48, 0x8D, 0x0D},
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
            {0xC3}, 1, 4},
        {"B1 RET #2 (Wrapper)",
            {0xC3, 0xCC, 0xCC, 0xCC, 0x48, 0x83, 0xEC, 0x28, 0x48, 0x8D, 0x0D},
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
            {0xC3}, 1, 4},
        {"B1 RET #3 (.grfn1)",
            {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x8B, 0xD8, 0x8B, 0xF2},
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
            {0xC3}, 1, 0},
        // Thread/Image Notify callback in .grfn1
        {"vgk_thread_image_notify",
            {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x57, 0x48, 0x83, 0xEC, 0x20,
             0x49, 0x8B, 0xD8, 0x48, 0x8B, 0xFA, 0x48, 0x8B, 0xF1, 0x90, 0xEB, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00,
             0xFF, 0xE0, 0x48, 0x83, 0xC4, 0x20, 0xEB, 0x00, 0x5F, 0xEB, 0x00, 0xC3, 0x00, 0x00, 0x00, 0x00},
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
            {0xC3}, 1, 0}
    };
}

// ============================================================================
// Pattern Patching (EPT)
// ============================================================================

namespace
{
    bool apply_ept_patch(const std::string& name, std::uint64_t vgk_offset,
                         const std::uint8_t* patch_bytes, std::size_t patch_size)
    {
        std::uint64_t patch_va = vgk_base_address + vgk_offset;
        std::uint64_t patch_pa = translate_va(patch_va, current_cr3());

        if (patch_pa == 0)
        {
            LOG_ERR("[VGK] {} failed to translate VA 0x{:X}", name, patch_va);
            return false;
        }

        std::uint64_t page_pa = patch_pa & ~0xFFFULL;
        std::uint64_t page_offset = patch_pa & 0xFFF;

        auto it = shadow_pages.find(page_pa);
        if (it != shadow_pages.end())
        {
            std::uint8_t* shadow_mapped = static_cast<std::uint8_t*>(it->second.shadow_page_mapped);

            std::vector<std::uint8_t> original(patch_size);
            std::memcpy(original.data(), shadow_mapped + page_offset, patch_size);

            if (std::memcmp(shadow_mapped + page_offset, patch_bytes, patch_size) == 0)
            {
                LOG_INFO("[VGK] {} already patched", name);
                return true;
            }

            std::memcpy(shadow_mapped + page_offset, patch_bytes, patch_size);
            it->second.ref_count++;

            pattern_patches.push_back({name, vgk_offset, page_pa, page_offset, original,
                std::vector<std::uint8_t>(patch_bytes, patch_bytes + patch_size)});

            LOG_INFO("[VGK] {} PATCHED at vgk+0x{:X} (reused shadow)", name, vgk_offset);
            return true;
        }

        void* shadow_page = allocate_locked_memory(vgk_page_size, PAGE_READWRITE);
        if (!shadow_page)
            return false;

        std::uint64_t shadow_pa = translate_va(reinterpret_cast<std::uint64_t>(shadow_page), current_cr3());
        if (shadow_pa == 0)
        {
            free_locked_memory(shadow_page);
            return false;
        }

        if (read_guest_physical_memory(shadow_page, page_pa, vgk_page_size) != vgk_page_size)
        {
            free_locked_memory(shadow_page);
            return false;
        }

        std::uint8_t* shadow_bytes = static_cast<std::uint8_t*>(shadow_page);

        std::vector<std::uint8_t> original(patch_size);
        std::memcpy(original.data(), shadow_bytes + page_offset, patch_size);

        std::memcpy(shadow_bytes + page_offset, patch_bytes, patch_size);

        if (!add_slat_code_hook(page_pa, shadow_pa))
        {
            free_locked_memory(shadow_page);
            return false;
        }

        shadow_pages[page_pa] = {shadow_page, shadow_pa, page_pa, 1};
        pattern_patches.push_back({name, vgk_offset, page_pa, page_offset, original,
            std::vector<std::uint8_t>(patch_bytes, patch_bytes + patch_size)});

        LOG_INFO("[VGK] {} PATCHED at vgk+0x{:X} (EPT split-view)", name, vgk_offset);
        return true;
    }
}

bool vgk_patcher::patch_bts_patterns(patch_stats_t* stats)
{
    if (!initialized && !initialize()) return false;
    if (module_cache.empty() && !cache_module()) return false;

    auto bts_patterns = get_bts_patterns();
    int total = 0;

    for (const auto& pat : bts_patterns)
    {
        auto matches = scan_pattern(pat.pattern.data(), pat.mask.data(), pat.pattern.size());
        total += static_cast<int>(matches.size());

        LOG_INFO("[VGK] {} found {} match(es)", pat.name, matches.size());

        for (auto offset : matches)
        {
            if (apply_ept_patch(pat.name, offset + pat.patch_offset, pat.patch.data(), pat.patch.size()))
            {
                if (stats) stats->total_patched++;
            }
            else
            {
                if (stats) stats->total_failed++;
            }
        }
    }

    if (stats) stats->bts_patterns = total;
    return true;
}

bool vgk_patcher::patch_jump_patterns(patch_stats_t* stats)
{
    if (!initialized && !initialize()) return false;
    if (module_cache.empty() && !cache_module()) return false;

    auto jump_patterns = get_jump_patterns();
    int total = 0;

    for (const auto& pat : jump_patterns)
    {
        auto matches = scan_pattern(pat.pattern.data(), pat.mask.data(), pat.pattern.size());
        total += static_cast<int>(matches.size());

        LOG_INFO("[VGK] {} found {} match(es)", pat.name, matches.size());

        for (auto offset : matches)
        {
            if (apply_ept_patch(pat.name, offset + pat.patch_offset, pat.patch.data(), pat.patch.size()))
            {
                if (stats) stats->total_patched++;
            }
            else
            {
                if (stats) stats->total_failed++;
            }
        }
    }

    if (stats) stats->jump_patterns = total;
    return true;
}

bool vgk_patcher::patch_callback_patterns(patch_stats_t* stats)
{
    if (!initialized && !initialize()) return false;
    if (module_cache.empty() && !cache_module()) return false;

    auto callback_patterns = get_callback_patterns();
    int total = 0;

    for (const auto& pat : callback_patterns)
    {
        if (pat.patch.empty()) continue;

        auto matches = scan_pattern(pat.pattern.data(), pat.mask.data(), pat.pattern.size());
        total += static_cast<int>(matches.size());

        LOG_INFO("[VGK] {} found {} match(es)", pat.name, matches.size());

        for (auto offset : matches)
        {
            if (apply_ept_patch(pat.name, offset + pat.patch_offset, pat.patch.data(), pat.patch.size()))
            {
                if (stats) stats->total_patched++;
            }
            else
            {
                if (stats) stats->total_failed++;
            }
        }
    }

    if (stats) stats->callback_patterns = total;
    return true;
}

bool vgk_patcher::patch_cpuid_patterns(patch_stats_t* stats)
{
    if (stats) stats->cpuid_patterns = 0;
    return true;
}

bool vgk_patcher::apply_pattern_patches(patch_stats_t* stats)
{
    if (!initialized && !initialize()) return false;

    LOG_INFO("[VGK] ========== APPLYING PATTERN PATCHES (EPT) ==========");

    pattern_patches.clear();

    if (stats)
    {
        std::memset(stats, 0, sizeof(patch_stats_t));
        stats->vgk_base = vgk_base_address;
        stats->vgk_size = cached_module_size;
    }

    bool bts = patch_bts_patterns(stats);
    bool jumps = patch_jump_patterns(stats);
    bool callbacks = patch_callback_patterns(stats);

    LOG_INFO("[VGK] Shadow pages active: {}", shadow_pages.size());
    LOG_INFO("[VGK] ========== PATTERN PATCHES COMPLETE ==========");

    return bts && jumps && callbacks;
}

bool vgk_patcher::restore_pattern_patches()
{
    LOG_INFO("[VGK] ========== RESTORING PATTERN PATCHES (EPT) ==========");

    bool all_success = true;

    // Restore original bytes in shadow pages
    for (const auto& patch : pattern_patches)
    {
        auto it = shadow_pages.find(patch.page_pa);
        if (it == shadow_pages.end())
        {
            LOG_ERR("[VGK] Shadow page not found for {}", patch.name);
            all_success = false;
            continue;
        }

        std::uint8_t* shadow_mapped = static_cast<std::uint8_t*>(it->second.shadow_page_mapped);
        std::memcpy(shadow_mapped + patch.patch_write_offset, patch.original_bytes.data(), patch.original_bytes.size());

        it->second.ref_count--;

        LOG_INFO("[VGK] {} restored (ref_count={})", patch.name, it->second.ref_count);
    }

    // Remove EPT hooks for pages with ref_count <= 0
    std::vector<std::uint64_t> pages_to_remove;
    for (const auto& [page_pa, info] : shadow_pages)
    {
        if (info.ref_count <= 0)
        {
            pages_to_remove.push_back(page_pa);
        }
    }

    for (auto page_pa : pages_to_remove)
    {
        auto it = shadow_pages.find(page_pa);
        if (it == shadow_pages.end()) continue;

        if (remove_slat_code_hook(it->second.target_page_physical) != 1)
        {
            LOG_ERR("[VGK] Failed to remove EPT hook for page 0x{:X}", page_pa);
            all_success = false;
            continue;
        }

        free_locked_memory(it->second.shadow_page_mapped);
        shadow_pages.erase(it);
        LOG_INFO("[VGK] EPT hook removed for page 0x{:X}", page_pa);
    }

    pattern_patches.clear();

    LOG_INFO("[VGK] Shadow pages remaining: {}", shadow_pages.size());
    LOG_INFO("[VGK] ========== PATTERN RESTORE COMPLETE ==========");

    return all_success;
}

// ============================================================================
// Direct Write Patches
// ============================================================================

namespace
{
    bool apply_direct_patch(const std::string& name, std::uint64_t vgk_offset,
                            const std::uint8_t* patch_bytes, std::size_t patch_size)
    {
        std::uint64_t patch_va = vgk_base_address + vgk_offset;

        std::vector<std::uint8_t> original(patch_size);
        if (read_guest_virtual_memory(original.data(), patch_va, current_cr3(), patch_size) != patch_size)
        {
            LOG_ERR("[VGK] {} failed to read original bytes", name);
            return false;
        }

        if (std::memcmp(original.data(), patch_bytes, patch_size) == 0)
        {
            LOG_INFO("[VGK] {} already patched", name);
            return true;
        }

        if (write_guest_virtual_memory(patch_bytes, patch_va, current_cr3(), patch_size) != patch_size)
        {
            LOG_ERR("[VGK] {} failed to write patch", name);
            return false;
        }

        direct_patches.push_back({name, vgk_offset, original,
            std::vector<std::uint8_t>(patch_bytes, patch_bytes + patch_size)});

        LOG_INFO("[VGK] {} PATCHED (direct write) at vgk+0x{:X}", name, vgk_offset);
        return true;
    }
}

bool vgk_patcher::apply_pattern_patches_direct(patch_stats_t* stats)
{
    if (!initialized && !initialize()) return false;

    LOG_INFO("[VGK] ========== APPLYING PATTERN PATCHES (DIRECT) ==========");
    LOG_INFO("[VGK] WARNING: Direct writes are visible to CRC checks!");

    direct_patches.clear();

    if (module_cache.empty() && !cache_module()) return false;

    if (stats)
    {
        std::memset(stats, 0, sizeof(patch_stats_t));
        stats->vgk_base = vgk_base_address;
        stats->vgk_size = cached_module_size;
    }

    auto bts_patterns = get_bts_patterns();
    for (const auto& pat : bts_patterns)
    {
        auto matches = scan_pattern(pat.pattern.data(), pat.mask.data(), pat.pattern.size());
        if (stats) stats->bts_patterns += static_cast<int>(matches.size());

        for (auto offset : matches)
        {
            if (apply_direct_patch(pat.name, offset + pat.patch_offset, pat.patch.data(), pat.patch.size()))
            {
                if (stats) stats->total_patched++;
            }
            else
            {
                if (stats) stats->total_failed++;
            }
        }
    }

    auto jump_patterns = get_jump_patterns();
    for (const auto& pat : jump_patterns)
    {
        auto matches = scan_pattern(pat.pattern.data(), pat.mask.data(), pat.pattern.size());
        if (stats) stats->jump_patterns += static_cast<int>(matches.size());

        for (auto offset : matches)
        {
            if (apply_direct_patch(pat.name, offset + pat.patch_offset, pat.patch.data(), pat.patch.size()))
            {
                if (stats) stats->total_patched++;
            }
            else
            {
                if (stats) stats->total_failed++;
            }
        }
    }

    LOG_INFO("[VGK] ========== DIRECT PATCHES COMPLETE ==========");
    return true;
}

bool vgk_patcher::restore_pattern_patches_direct()
{
    bool all_success = true;

    for (const auto& patch : direct_patches)
    {
        std::uint64_t patch_va = vgk_base_address + patch.vgk_offset;

        if (write_guest_virtual_memory(patch.original_bytes.data(), patch_va, current_cr3(),
                                       patch.original_bytes.size()) != patch.original_bytes.size())
        {
            LOG_ERR("[VGK] Failed to restore {}", patch.name);
            all_success = false;
        }
        else
        {
            LOG_INFO("[VGK] {} RESTORED", patch.name);
        }
    }

    direct_patches.clear();
    return all_success;
}

std::size_t vgk_patcher::get_direct_patch_count()
{
    return direct_patches.size();
}
