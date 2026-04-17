#pragma once

#include <cstddef>
#include <cstdint>

namespace inspector {

using u8  = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
using i8  = std::int8_t;
using i16 = std::int16_t;
using i32 = std::int32_t;
using i64 = std::int64_t;
using f32 = float;
using f64 = double;

struct PointerRange {
    u64 low  = 0x10000ULL;
    u64 high = 0x000F000000000000ULL;
};

inline bool IsLikelyPointer(u64 value, PointerRange range = {}) noexcept {
    return value >= range.low && value < range.high;
}

} // namespace inspector
