#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>

#include <optional>
#include <string>
#include <vector>

#include "inspector/memory_view.hpp"
#include "inspector/types.hpp"

namespace inspector::detail {

struct MemoryRegion {
    u64 base{};
    u64 size{};
    DWORD protect{};
    DWORD state{};
    DWORD type{};
};

[[nodiscard]] inline std::vector<MemoryRegion> EnumerateRegions(
    u64 low = 0x10000ULL,
    u64 high = 0x00007FFF'00000000ULL,
    bool only_readable = true,
    bool only_writable = false,
    bool only_executable = false) {

    std::vector<MemoryRegion> out;
    u64 cursor = low;
    while (cursor < high) {
        MEMORY_BASIC_INFORMATION mbi{};
        const auto ok = ::VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &mbi, sizeof(mbi));
        if (ok != sizeof(mbi)) break;
        const u64 base = reinterpret_cast<u64>(mbi.BaseAddress);
        const u64 size = static_cast<u64>(mbi.RegionSize);
        if (size == 0) break;
        const u64 end = base + size;
        if (mbi.State == MEM_COMMIT) {
            bool keep = true;
            if (only_readable   && !MemoryView::IsReadable(mbi.Protect))   keep = false;
            if (only_writable   && !MemoryView::IsWritable(mbi.Protect))   keep = false;
            if (only_executable && !MemoryView::IsExecutable(mbi.Protect)) keep = false;
            if (keep) {
                out.push_back(MemoryRegion{
                    .base = base, .size = size,
                    .protect = mbi.Protect, .state = mbi.State, .type = mbi.Type,
                });
            }
        }
        if (end <= cursor) break;
        cursor = end;
    }
    return out;
}

// ---------------------------------------------------------------------------
// PE image info for a given module base. Parses enough of the PE header to
// enumerate sections with name/characteristics.
// ---------------------------------------------------------------------------

struct RemoteSectionInfo {
    std::string name;
    u64 address{};
    u32 size{};
    u32 characteristics{};
};

struct RemoteImageInfo {
    u64 base{};
    u32 size_of_image{};
    std::vector<RemoteSectionInfo> sections;
};

[[nodiscard]] inline std::optional<RemoteImageInfo> ReadImageInfo(const MemoryView& mem, u64 base) {
    const auto mz = mem.TryRead<u16>(base);
    if (!mz || *mz != 0x5A4D) return std::nullopt;

    const auto lfanew = mem.TryRead<u32>(base + 0x3C);
    if (!lfanew) return std::nullopt;

    const auto pe = mem.TryRead<u32>(base + *lfanew);
    if (!pe || *pe != 0x00004550) return std::nullopt;

    const auto number_of_sections = mem.TryRead<u16>(base + *lfanew + 6);
    const auto size_of_optional   = mem.TryRead<u16>(base + *lfanew + 20);
    const auto size_of_image      = mem.TryRead<u32>(base + *lfanew + 24 + 56);
    if (!number_of_sections || !size_of_optional || !size_of_image) return std::nullopt;

    RemoteImageInfo out{};
    out.base = base;
    out.size_of_image = *size_of_image;
    out.sections.reserve(*number_of_sections);

    const u64 table = base + *lfanew + 24 + *size_of_optional;
    for (u16 i = 0; i < *number_of_sections; ++i) {
        const u64 entry = table + (static_cast<u64>(i) * 40ULL);
        char name_raw[9] = {0};
        if (!mem.ReadRaw(entry, name_raw, 8)) return std::nullopt;
        const auto vsize = mem.TryRead<u32>(entry + 8);
        const auto vaddr = mem.TryRead<u32>(entry + 12);
        const auto rsize = mem.TryRead<u32>(entry + 16);
        const auto chars = mem.TryRead<u32>(entry + 36);
        if (!vsize || !vaddr || !rsize || !chars) return std::nullopt;
        const u32 section_size = std::max(*vsize, *rsize);
        if (section_size == 0) continue;
        out.sections.push_back(RemoteSectionInfo{
            .name = name_raw,
            .address = base + *vaddr,
            .size = section_size,
            .characteristics = *chars,
        });
    }
    return out;
}

} // namespace inspector::detail
