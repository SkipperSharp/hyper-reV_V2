#pragma once
#include <cstdint>
#include <vector>
#include <string>

namespace vgk_patcher
{
    // ============================================================================
    // EPT Split-View Callback Patches
    // ============================================================================

    struct callback_patch_t
    {
        std::string name;
        std::uint64_t offset;
        std::uint8_t original_bytes[8];
        bool is_patched;
        std::uint64_t patch_write_offset;
        std::uint8_t original_byte;
    };

    enum class patch_status_t : std::uint32_t
    {
        all_patched         = 0,
        rolled_back         = 1,
        partial_undefined   = 2,
    };

    // ============================================================================
    // Pattern-Based Patches
    // ============================================================================

    struct pattern_def_t
    {
        std::string name;
        std::vector<std::uint8_t> pattern;
        std::vector<std::uint8_t> mask;      // 0x00 = must match, 0xFF = wildcard
        std::vector<std::uint8_t> patch;
        int expected_count;                   // 0 = any, >0 = exact count required
        int patch_offset;                     // offset within pattern to apply patch
    };

    struct patch_stats_t
    {
        std::uint64_t vgk_base;
        std::uint64_t vgk_size;
        int cpuid_patterns;
        int bts_patterns;
        int callback_patterns;
        int jump_patterns;
        int total_patched;
        int total_skipped;
        int total_failed;
    };

    // ============================================================================
    // Core Functions
    // ============================================================================

    bool initialize();
    std::uint64_t get_vgk_base();
    std::uint64_t get_vgk_size();
    std::uint32_t get_vgk_timedatestamp();
    bool is_vgk_loaded();
    bool cleanup();

    // ============================================================================
    // EPT Split-View Patches (for callbacks that need invisible patching)
    // ============================================================================

    patch_status_t patch_all_callbacks();
    bool patch_callback(std::uint64_t vgk_offset);
    bool restore_all_callbacks();
    bool restore_callback(std::uint64_t vgk_offset);
    std::vector<callback_patch_t>& get_callbacks();

    // ============================================================================
    // Pattern-Based Patches (EPT split-view - invisible to CRC)
    // ============================================================================

    bool cache_module();

    std::vector<std::uint64_t> scan_pattern(const std::uint8_t* pattern,
                                             const std::uint8_t* mask,
                                             std::size_t len,
                                             std::uint64_t start_offset = 0,
                                             std::uint64_t end_offset = 0);

    // Apply all pattern-based patches with EPT split-view
    bool apply_pattern_patches(patch_stats_t* stats = nullptr);

    // Restore all EPT pattern patches
    bool restore_pattern_patches();

    // Individual patch categories (EPT)
    bool patch_bts_patterns(patch_stats_t* stats = nullptr);
    bool patch_jump_patterns(patch_stats_t* stats = nullptr);
    bool patch_cpuid_patterns(patch_stats_t* stats = nullptr);
    bool patch_callback_patterns(patch_stats_t* stats = nullptr);

    // Get pattern definitions
    std::vector<pattern_def_t> get_bts_patterns();
    std::vector<pattern_def_t> get_jump_patterns();
    std::vector<pattern_def_t> get_callback_patterns();

    // ============================================================================
    // Direct Write Patches (no EPT - visible to CRC, but simpler)
    // ============================================================================

    bool apply_pattern_patches_direct(patch_stats_t* stats = nullptr);
    bool restore_pattern_patches_direct();
    std::size_t get_direct_patch_count();
}
