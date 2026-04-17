#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <optional>

#include "inspector/types.hpp"

namespace inspector {

// Read-only memory view over the inspector-hosting process. All reads use a
// SEH __try (MSVC) / plain memcpy (MinGW) guarded by a preceding VirtualQuery,
// so we never fault when probing untrusted pointer chains.
class MemoryView {
public:
    [[nodiscard]] bool ReadRaw(u64 address, void* out, std::size_t size) const {
        if (address == 0 || out == nullptr || size == 0) {
            return false;
        }
        auto* dst = static_cast<std::byte*>(out);
        std::size_t copied = 0;
        while (copied < size) {
            const auto current = static_cast<std::uintptr_t>(address + copied);
            MEMORY_BASIC_INFORMATION mbi{};
            if (::VirtualQuery(reinterpret_cast<LPCVOID>(current), &mbi, sizeof(mbi)) != sizeof(mbi)) {
                return false;
            }
            if (mbi.State != MEM_COMMIT || !IsReadable(mbi.Protect)) {
                return false;
            }
            const auto begin = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const auto end = begin + mbi.RegionSize;
            if (current < begin || current >= end) return false;
            const auto avail = static_cast<std::size_t>(end - current);
            const auto chunk = std::min(avail, size - copied);
#if defined(_MSC_VER)
            __try {
                std::memcpy(dst + copied, reinterpret_cast<const void*>(current), chunk);
            } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
#else
            std::memcpy(dst + copied, reinterpret_cast<const void*>(current), chunk);
#endif
            copied += chunk;
        }
        return true;
    }

    template <typename T>
    [[nodiscard]] std::optional<T> TryRead(u64 address) const {
        T value{};
        if (!ReadRaw(address, &value, sizeof(T))) return std::nullopt;
        return value;
    }

    [[nodiscard]] static bool IsReadable(DWORD protect) noexcept {
        if ((protect & PAGE_GUARD) != 0 || (protect & PAGE_NOACCESS) != 0) return false;
        switch (protect & 0xFFu) {
        case PAGE_READONLY: case PAGE_READWRITE: case PAGE_WRITECOPY:
        case PAGE_EXECUTE_READ: case PAGE_EXECUTE_READWRITE: case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
        }
    }

    [[nodiscard]] static bool IsWritable(DWORD protect) noexcept {
        if ((protect & PAGE_GUARD) != 0 || (protect & PAGE_NOACCESS) != 0) return false;
        switch (protect & 0xFFu) {
        case PAGE_READWRITE: case PAGE_EXECUTE_READWRITE:
        case PAGE_WRITECOPY: case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
        }
    }

    [[nodiscard]] static bool IsExecutable(DWORD protect) noexcept {
        if ((protect & PAGE_GUARD) != 0 || (protect & PAGE_NOACCESS) != 0) return false;
        switch (protect & 0xFFu) {
        case PAGE_EXECUTE: case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE: case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
        }
    }
};

} // namespace inspector
