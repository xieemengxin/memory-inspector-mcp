#include "inspector/service.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstring>
#include <sstream>

#include "inspector/formatting.hpp"
#include "inspector/service_util.hpp"

namespace inspector {

namespace {

[[nodiscard]] std::optional<ScanValueKind> ParseScanKind(const std::string& text) {
    const auto t = Trim(text);
    if (t == "u8")  return ScanValueKind::U8;
    if (t == "u16") return ScanValueKind::U16;
    if (t == "u32") return ScanValueKind::U32;
    if (t == "u64") return ScanValueKind::U64;
    if (t == "i8")  return ScanValueKind::I8;
    if (t == "i16") return ScanValueKind::I16;
    if (t == "i32") return ScanValueKind::I32;
    if (t == "i64") return ScanValueKind::I64;
    if (t == "f32") return ScanValueKind::F32;
    if (t == "f64") return ScanValueKind::F64;
    return std::nullopt;
}

[[nodiscard]] std::optional<u64> ReadScanValueAt(const MemoryView& memory, u64 address, ScanValueKind kind) {
    switch (kind) {
    case ScanValueKind::U8:  { auto v = memory.TryRead<u8>(address);  return v ? std::optional<u64>(*v) : std::nullopt; }
    case ScanValueKind::U16: { auto v = memory.TryRead<u16>(address); return v ? std::optional<u64>(*v) : std::nullopt; }
    case ScanValueKind::U32: { auto v = memory.TryRead<u32>(address); return v ? std::optional<u64>(*v) : std::nullopt; }
    case ScanValueKind::U64: { auto v = memory.TryRead<u64>(address); return v ? std::optional<u64>(*v) : std::nullopt; }
    case ScanValueKind::I8:  { auto v = memory.TryRead<i8>(address);  return v ? std::optional<u64>(static_cast<u64>(static_cast<i64>(*v))) : std::nullopt; }
    case ScanValueKind::I16: { auto v = memory.TryRead<i16>(address); return v ? std::optional<u64>(static_cast<u64>(static_cast<i64>(*v))) : std::nullopt; }
    case ScanValueKind::I32: { auto v = memory.TryRead<i32>(address); return v ? std::optional<u64>(static_cast<u64>(static_cast<i64>(*v))) : std::nullopt; }
    case ScanValueKind::I64: { auto v = memory.TryRead<i64>(address); return v ? std::optional<u64>(static_cast<u64>(*v)) : std::nullopt; }
    case ScanValueKind::F32: { auto v = memory.TryRead<u32>(address); return v ? std::optional<u64>(*v) : std::nullopt; }
    case ScanValueKind::F64: { auto v = memory.TryRead<u64>(address); return v ? std::optional<u64>(*v) : std::nullopt; }
    }
    return std::nullopt;
}

[[nodiscard]] f64 ScanBitsToDouble(u64 bits, ScanValueKind kind) {
    switch (kind) {
    case ScanValueKind::U8:  return static_cast<f64>(static_cast<u8>(bits));
    case ScanValueKind::U16: return static_cast<f64>(static_cast<u16>(bits));
    case ScanValueKind::U32: return static_cast<f64>(static_cast<u32>(bits));
    case ScanValueKind::U64: return static_cast<f64>(bits);
    case ScanValueKind::I8:  return static_cast<f64>(static_cast<i8>(static_cast<u8>(bits)));
    case ScanValueKind::I16: return static_cast<f64>(static_cast<i16>(static_cast<u16>(bits)));
    case ScanValueKind::I32: return static_cast<f64>(static_cast<i32>(static_cast<u32>(bits)));
    case ScanValueKind::I64: return static_cast<f64>(static_cast<i64>(bits));
    case ScanValueKind::F32: { f32 v; std::memcpy(&v, &bits, 4); return static_cast<f64>(v); }
    case ScanValueKind::F64: { f64 v; std::memcpy(&v, &bits, 8); return v; }
    }
    return 0.0;
}

[[nodiscard]] std::string ScanBitsToText(u64 bits, ScanValueKind kind) {
    std::ostringstream oss;
    switch (kind) {
    case ScanValueKind::F32: { f32 v; std::memcpy(&v, &bits, 4); oss << v; return oss.str(); }
    case ScanValueKind::F64: { f64 v; std::memcpy(&v, &bits, 8); oss << v; return oss.str(); }
    case ScanValueKind::I8: case ScanValueKind::I16:
    case ScanValueKind::I32: case ScanValueKind::I64:
        oss << static_cast<long long>(ScanBitsToDouble(bits, kind));
        return oss.str();
    default:
        oss << static_cast<unsigned long long>(bits);
        return oss.str();
    }
}

[[nodiscard]] std::optional<u64> ParseScanValue(const std::string& text, ScanValueKind kind) {
    switch (kind) {
    case ScanValueKind::U8: case ScanValueKind::U16:
    case ScanValueKind::U32: case ScanValueKind::U64: {
        const auto v = ParseU64(text); return v ? std::optional<u64>(*v) : std::nullopt;
    }
    case ScanValueKind::I8: case ScanValueKind::I16:
    case ScanValueKind::I32: case ScanValueKind::I64: {
        const auto v = ParseI64(text); return v ? std::optional<u64>(static_cast<u64>(*v)) : std::nullopt;
    }
    case ScanValueKind::F32: {
        const auto v = ParseF64(text); if (!v) return std::nullopt;
        const f32 f = static_cast<f32>(*v);
        u32 bits; std::memcpy(&bits, &f, 4);
        return static_cast<u64>(bits);
    }
    case ScanValueKind::F64: {
        const auto v = ParseF64(text); if (!v) return std::nullopt;
        u64 bits; std::memcpy(&bits, &*v, 8); return bits;
    }
    }
    return std::nullopt;
}

enum class ScanOp {
    Unknown, Equal, NotEqual, Gt, Lt, Ge, Le, Between,
    Changed, Unchanged, Increased, Decreased,
};

[[nodiscard]] std::optional<ScanOp> ParseScanOp(const std::string& text) {
    const auto t = Trim(text);
    if (t == "unknown" || t == "any" || t == "*") return ScanOp::Unknown;
    if (t == "==" || t == "eq")   return ScanOp::Equal;
    if (t == "!=" || t == "ne")   return ScanOp::NotEqual;
    if (t == ">"  || t == "gt")   return ScanOp::Gt;
    if (t == "<"  || t == "lt")   return ScanOp::Lt;
    if (t == ">=" || t == "ge")   return ScanOp::Ge;
    if (t == "<=" || t == "le")   return ScanOp::Le;
    if (t == "between" || t == "in") return ScanOp::Between;
    if (t == "changed"   || t == "chg")   return ScanOp::Changed;
    if (t == "unchanged" || t == "same")  return ScanOp::Unchanged;
    if (t == "increased" || t == "inc")   return ScanOp::Increased;
    if (t == "decreased" || t == "dec")   return ScanOp::Decreased;
    return std::nullopt;
}

[[nodiscard]] bool EvaluateOp(ScanOp op, ScanValueKind kind, u64 current_bits,
                                std::optional<u64> last_bits,
                                std::optional<u64> v1, std::optional<u64> v2) {
    switch (op) {
    case ScanOp::Unknown:    return true;
    case ScanOp::Equal:      return v1 && current_bits == *v1;
    case ScanOp::NotEqual:   return v1 && current_bits != *v1;
    case ScanOp::Gt: case ScanOp::Lt: case ScanOp::Ge: case ScanOp::Le:
    case ScanOp::Between: {
        if (!v1) return false;
        const auto a = ScanBitsToDouble(current_bits, kind);
        const auto b = ScanBitsToDouble(*v1, kind);
        switch (op) {
        case ScanOp::Gt: return a >  b;
        case ScanOp::Lt: return a <  b;
        case ScanOp::Ge: return a >= b;
        case ScanOp::Le: return a <= b;
        case ScanOp::Between: {
            if (!v2) return false;
            const auto c = ScanBitsToDouble(*v2, kind);
            const auto lo = std::min(b, c);
            const auto hi = std::max(b, c);
            return a >= lo && a <= hi;
        }
        default: return false;
        }
    }
    case ScanOp::Changed:   return last_bits && current_bits != *last_bits;
    case ScanOp::Unchanged: return last_bits && current_bits == *last_bits;
    case ScanOp::Increased:
        return last_bits && ScanBitsToDouble(current_bits, kind) > ScanBitsToDouble(*last_bits, kind);
    case ScanOp::Decreased:
        return last_bits && ScanBitsToDouble(current_bits, kind) < ScanBitsToDouble(*last_bits, kind);
    }
    return false;
}

} // namespace

// ---------------------------------------------------------------------------
// First-scan (CE)
// ---------------------------------------------------------------------------

std::string Service::ScanValue(const std::string& type, const std::string& op,
                                 const std::string& value1, const std::string& value2,
                                 u32 max_matches) {
    const auto kind_opt = ParseScanKind(type);
    if (!kind_opt) return "bad type\n";
    const auto op_opt = ParseScanOp(op);
    if (!op_opt) return "bad op\n";
    const auto kind = *kind_opt;
    const auto width = ScanKindWidth(kind);

    std::optional<u64> v1;
    std::optional<u64> v2;
    if (!value1.empty()) v1 = ParseScanValue(value1, kind);
    if (!value2.empty()) v2 = ParseScanValue(value2, kind);

    ScanSession session{};
    session.kind = kind;
    session.width = width;
    session.description = type + " " + op;

    const auto regs = detail::EnumerateRegions();
    for (const auto& r : regs) {
        std::vector<u8> bytes(r.size, 0);
        if (!memory_.ReadRaw(r.base, bytes.data(), bytes.size())) continue;
        for (u64 off = 0; off + width <= r.size; ++off) {
            u64 current = 0;
            std::memcpy(&current, bytes.data() + off, width);
            // sign extend for signed kinds
            if (kind == ScanValueKind::I8)  current = static_cast<u64>(static_cast<i64>(static_cast<i8>(current & 0xFF)));
            if (kind == ScanValueKind::I16) current = static_cast<u64>(static_cast<i64>(static_cast<i16>(current & 0xFFFF)));
            if (kind == ScanValueKind::I32) current = static_cast<u64>(static_cast<i64>(static_cast<i32>(current & 0xFFFFFFFFu)));

            if (!EvaluateOp(*op_opt, kind, current, std::nullopt, v1, v2)) continue;
            if (session.matches.size() >= max_matches) break;
            session.matches.push_back(ScanMatch{.address = r.base + off, .last_bits = current});
        }
        if (session.matches.size() >= max_matches) break;
    }

    const auto total = session.matches.size();
    scan_ = std::move(session);

    std::ostringstream oss;
    oss << "[Scan] " << type << " " << op;
    if (!value1.empty()) oss << " v1=" << value1;
    if (!value2.empty()) oss << " v2=" << value2;
    oss << "\n";
    oss << "matches=" << total << "\n";
    const auto limit = std::min<std::size_t>(total, 32);
    for (std::size_t i = 0; i < limit; ++i) {
        const auto& m = scan_->matches[i];
        oss << HexAddress(m.address) << " = " << ScanBitsToText(m.last_bits, kind) << "\n";
    }
    if (total > limit) oss << "... (peek further with scan_peek)\n";
    return oss.str();
}

std::string Service::ScanNext(const std::string& op,
                                 const std::string& value1, const std::string& value2) {
    if (!scan_) return "no active scan session\n";
    const auto op_opt = ParseScanOp(op);
    if (!op_opt) return "bad op\n";
    const auto kind = scan_->kind;
    std::optional<u64> v1;
    std::optional<u64> v2;
    if (!value1.empty()) v1 = ParseScanValue(value1, kind);
    if (!value2.empty()) v2 = ParseScanValue(value2, kind);

    std::vector<ScanMatch> kept;
    kept.reserve(scan_->matches.size());
    for (const auto& m : scan_->matches) {
        const auto current = ReadScanValueAt(memory_, m.address, kind);
        if (!current) continue;
        if (!EvaluateOp(*op_opt, kind, *current, m.last_bits, v1, v2)) continue;
        kept.push_back(ScanMatch{.address = m.address, .last_bits = *current});
    }
    scan_->matches = std::move(kept);

    std::ostringstream oss;
    oss << "[ScanNext] op=" << op;
    if (!value1.empty()) oss << " v1=" << value1;
    if (!value2.empty()) oss << " v2=" << value2;
    oss << "\n";
    oss << "matches=" << scan_->matches.size() << "\n";
    const auto limit = std::min<std::size_t>(scan_->matches.size(), 32);
    for (std::size_t i = 0; i < limit; ++i) {
        const auto& m = scan_->matches[i];
        oss << HexAddress(m.address) << " = " << ScanBitsToText(m.last_bits, kind) << "\n";
    }
    return oss.str();
}

std::string Service::ScanAob(const std::string& pattern, u32 max_matches) {
    const auto parsed = ParseAob(pattern);
    if (parsed.empty()) return "bad pattern\n";
    ScanSession session{};
    session.kind = ScanValueKind::U8;
    session.width = 1;
    session.description = "aob:" + pattern;

    const auto regs = detail::EnumerateRegions();
    const std::size_t plen = parsed.size();
    for (const auto& r : regs) {
        if (r.size < plen) continue;
        std::vector<u8> bytes(r.size, 0);
        if (!memory_.ReadRaw(r.base, bytes.data(), bytes.size())) continue;
        const u64 limit = r.size - plen;
        for (u64 off = 0; off <= limit; ++off) {
            bool match = true;
            for (std::size_t i = 0; i < plen; ++i) {
                if (!parsed[i].wildcard && bytes[off + i] != parsed[i].value) { match = false; break; }
            }
            if (!match) continue;
            if (session.matches.size() >= max_matches) break;
            session.matches.push_back(ScanMatch{.address = r.base + off, .last_bits = 0});
        }
        if (session.matches.size() >= max_matches) break;
    }

    const auto total = session.matches.size();
    scan_ = std::move(session);
    std::ostringstream oss;
    oss << "[AOB] pattern=" << pattern << "\nmatches=" << total << "\n";
    const auto limit = std::min<std::size_t>(total, 64);
    for (std::size_t i = 0; i < limit; ++i) oss << HexAddress(scan_->matches[i].address) << "\n";
    return oss.str();
}

std::string Service::ScanAobInModule(const std::string& module_name,
                                        const std::string& section,
                                        const std::string& pattern, u32 max_matches) {
    HMODULE mod = ::GetModuleHandleA(module_name.empty() ? nullptr : module_name.c_str());
    if (!mod) return "module not found\n";
    const u64 base = reinterpret_cast<u64>(mod);
    const auto image = detail::ReadImageInfo(memory_, base);
    if (!image) return "image info unavailable\n";

    const auto parsed = ParseAob(pattern);
    if (parsed.empty()) return "bad pattern\n";
    const std::size_t plen = parsed.size();

    std::vector<detail::RemoteSectionInfo> sections;
    for (const auto& s : image->sections) {
        if (section.empty() || s.name == section) sections.push_back(s);
    }
    if (sections.empty()) return "section not found\n";

    ScanSession session{};
    session.kind = ScanValueKind::U8;
    session.width = 1;
    session.description = "aob_mod:" + pattern;

    for (const auto& s : sections) {
        std::vector<u8> bytes(s.size, 0);
        if (!memory_.ReadRaw(s.address, bytes.data(), bytes.size())) continue;
        if (bytes.size() < plen) continue;
        const u64 limit = bytes.size() - plen;
        for (u64 off = 0; off <= limit; ++off) {
            bool match = true;
            for (std::size_t i = 0; i < plen; ++i) {
                if (!parsed[i].wildcard && bytes[off + i] != parsed[i].value) { match = false; break; }
            }
            if (!match) continue;
            if (session.matches.size() >= max_matches) break;
            session.matches.push_back(ScanMatch{.address = s.address + off, .last_bits = 0});
        }
        if (session.matches.size() >= max_matches) break;
    }

    const auto total = session.matches.size();
    scan_ = std::move(session);
    std::ostringstream oss;
    oss << "[AOB in module] module=" << (module_name.empty() ? "<host>" : module_name)
        << " section=" << (section.empty() ? "<all>" : section)
        << " pattern=" << pattern
        << "\nmatches=" << total << "\n";
    const auto limit = std::min<std::size_t>(total, 64);
    for (std::size_t i = 0; i < limit; ++i) oss << HexAddress(scan_->matches[i].address) << "\n";
    return oss.str();
}

std::string Service::ScanPointer(u64 target, u64 max_distance, u32 max_matches) {
    ScanSession session{};
    session.kind = ScanValueKind::U64;
    session.width = 8;
    session.description = "ptr_to " + HexAddress(target);

    const u64 lo = target > max_distance ? target - max_distance : 0;
    const u64 hi = target + max_distance;

    const auto regs = detail::EnumerateRegions(0x10000ULL, 0x00007FFF'00000000ULL, true, true);
    for (const auto& r : regs) {
        std::vector<u8> bytes(r.size, 0);
        if (!memory_.ReadRaw(r.base, bytes.data(), bytes.size())) continue;
        for (u64 off = 0; off + 8 <= r.size; off += 8) {
            u64 v; std::memcpy(&v, bytes.data() + off, 8);
            if (v >= lo && v <= hi) {
                if (session.matches.size() >= max_matches) break;
                session.matches.push_back(ScanMatch{.address = r.base + off, .last_bits = v});
            }
        }
        if (session.matches.size() >= max_matches) break;
    }

    const auto total = session.matches.size();
    scan_ = std::move(session);
    std::ostringstream oss;
    oss << "[ScanPointer] target=" << HexAddress(target)
        << " range=+/-" << HexValue(max_distance, 8)
        << "\nmatches=" << total << "\n";
    const auto limit = std::min<std::size_t>(total, 32);
    for (std::size_t i = 0; i < limit; ++i) {
        oss << HexAddress(scan_->matches[i].address) << " -> "
            << HexAddress(scan_->matches[i].last_bits) << "\n";
    }
    return oss.str();
}

std::string Service::ScanString(const std::string& text, bool unicode, bool ci, u32 max_matches) {
    if (text.empty()) return "empty text\n";

    std::vector<u8> needle;
    if (unicode) {
        needle.resize(text.size() * 2);
        for (std::size_t i = 0; i < text.size(); ++i) {
            needle[i * 2] = static_cast<u8>(text[i]);
            needle[i * 2 + 1] = 0;
        }
    } else {
        needle.assign(text.begin(), text.end());
    }

    auto canon = [&](u8 b) -> u8 {
        if (ci && b >= 'A' && b <= 'Z') return static_cast<u8>(b + ('a' - 'A'));
        return b;
    };

    ScanSession session{};
    session.kind = ScanValueKind::U8;
    session.width = 1;
    session.description = std::string{"str:"} + (unicode ? "u16:" : "ascii:") + text;

    const auto regs = detail::EnumerateRegions();
    for (const auto& r : regs) {
        std::vector<u8> bytes(r.size, 0);
        if (!memory_.ReadRaw(r.base, bytes.data(), bytes.size())) continue;
        if (bytes.size() < needle.size()) continue;
        const u64 limit = bytes.size() - needle.size();
        const std::size_t step = unicode ? 2 : 1;
        for (u64 off = 0; off <= limit; off += step) {
            bool match = true;
            for (std::size_t i = 0; i < needle.size(); ++i) {
                if (canon(bytes[off + i]) != canon(needle[i])) { match = false; break; }
            }
            if (!match) continue;
            if (session.matches.size() >= max_matches) break;
            session.matches.push_back(ScanMatch{.address = r.base + off, .last_bits = 0});
        }
        if (session.matches.size() >= max_matches) break;
    }

    const auto total = session.matches.size();
    scan_ = std::move(session);
    std::ostringstream oss;
    oss << "[ScanString] needle=\"" << text << "\" "
        << (unicode ? "utf16" : "ascii")
        << (ci ? " case_insensitive" : "")
        << "\nmatches=" << total << "\n";
    const auto limit = std::min<std::size_t>(total, 64);
    for (std::size_t i = 0; i < limit; ++i) oss << HexAddress(scan_->matches[i].address) << "\n";
    return oss.str();
}

std::string Service::ScanStatus() {
    std::ostringstream oss;
    oss << "[ScanStatus] ";
    if (!scan_) { oss << "no session\n"; return oss.str(); }
    oss << "kind=" << ScanKindName(scan_->kind) << " width=" << scan_->width
        << " matches=" << scan_->matches.size()
        << " description=" << scan_->description << "\n";
    return oss.str();
}

std::string Service::ScanPeek(u32 offset, u32 count) {
    if (!scan_) return "no active scan\n";
    std::ostringstream oss;
    const auto total = scan_->matches.size();
    oss << "[ScanPeek] offset=" << offset << " count=" << count << " total=" << total << "\n";
    if (offset >= total) return oss.str();
    const std::size_t end = std::min<std::size_t>(total, static_cast<std::size_t>(offset) + count);
    for (std::size_t i = offset; i < end; ++i) {
        const auto& m = scan_->matches[i];
        oss << "[" << i << "] " << HexAddress(m.address)
            << " = " << ScanBitsToText(m.last_bits, scan_->kind) << "\n";
    }
    return oss.str();
}

std::string Service::ScanClear() { scan_.reset(); return "cleared\n"; }

// ---------------------------------------------------------------------------
// find_code_refs — search the .text section of the main module for RIP-
// relative operands (call/jmp/lea/mov rel32) whose effective target equals the
// given address. Useful for reverse-walking who calls a function.
// ---------------------------------------------------------------------------

std::string Service::FindCodeRefs(u64 target, u32 max_matches) {
    HMODULE mod = ::GetModuleHandleW(nullptr);
    const u64 base = reinterpret_cast<u64>(mod);
    const auto image = detail::ReadImageInfo(memory_, base);
    if (!image) return "image info unavailable\n";

    detail::RemoteSectionInfo text{};
    for (const auto& s : image->sections) {
        if (s.name == ".text") { text = s; break; }
    }
    if (text.address == 0) return ".text section not found\n";

    std::vector<u8> bytes(text.size, 0);
    if (!memory_.ReadRaw(text.address, bytes.data(), bytes.size())) {
        return "read .text failed\n";
    }

    std::ostringstream oss;
    oss << "[FindCodeRefs] target=" << HexAddress(target) << "\n";
    u32 found = 0;
    for (std::size_t i = 0; i + 5 < bytes.size() && found < max_matches; ++i) {
        const u8 b0 = bytes[i];
        // Common single-byte opcodes with RIP-relative disp32:
        //   E8 disp32 (call rel32)
        //   E9 disp32 (jmp rel32)
        if (b0 == 0xE8 || b0 == 0xE9) {
            i32 disp; std::memcpy(&disp, bytes.data() + i + 1, 4);
            const u64 effective = text.address + i + 5 + static_cast<i64>(disp);
            if (effective == target) {
                oss << HexAddress(text.address + i) << " "
                    << (b0 == 0xE8 ? "call" : "jmp ")
                    << " " << HexAddress(effective) << "\n";
                ++found;
            }
            continue;
        }
        // 4C/48 + (8D | 8B) + ModRM=RIP+disp32 pattern (lea/mov rel32)
        if ((b0 == 0x48 || b0 == 0x4C || b0 == 0x49 || b0 == 0x4D) && i + 6 < bytes.size()) {
            const u8 b1 = bytes[i + 1];
            const u8 modrm = bytes[i + 2];
            const bool mod_rel = (modrm & 0xC7) == 0x05;
            if (!mod_rel) continue;
            if (b1 != 0x8D && b1 != 0x8B && b1 != 0x89 && b1 != 0x39) continue;
            i32 disp; std::memcpy(&disp, bytes.data() + i + 3, 4);
            const u64 effective = text.address + i + 7 + static_cast<i64>(disp);
            if (effective == target) {
                const char* mnem =
                    (b1 == 0x8D) ? "lea " :
                    (b1 == 0x8B) ? "mov " :
                    (b1 == 0x89) ? "mov " : "cmp ";
                oss << HexAddress(text.address + i) << " " << mnem
                    << " " << HexAddress(effective) << "\n";
                ++found;
            }
        }
    }
    if (found == 0) oss << "no references found\n";
    else oss << "total=" << found << "\n";
    return oss.str();
}

// ---------------------------------------------------------------------------
// pointer_path — iterative breadth-first reverse walk:
//   depth=1: find addresses A where A holds a ptr within [target-max_off, target].
//   depth=2: same for A, then recurse to find addresses B that point at A.
//   ...
// Output is a list of base + offset chains leading to target.
// ---------------------------------------------------------------------------

std::string Service::PointerPath(u64 target, u32 max_depth, u32 max_offset, u32 max_results) {
    if (max_depth == 0 || max_depth > 6) return "depth must be in [1,6]\n";

    struct Node { u64 addr; std::vector<std::pair<u64, i64>> chain; }; // chain: (ptr_slot, offset)

    std::vector<Node> frontier;
    frontier.push_back(Node{target, {}});

    std::vector<Node> results;

    const auto regs = detail::EnumerateRegions(0x10000ULL, 0x00007FFF'00000000ULL, true, true);

    for (u32 d = 0; d < max_depth; ++d) {
        std::vector<Node> next_frontier;
        for (const auto& cur : frontier) {
            const u64 lo = cur.addr > max_offset ? cur.addr - max_offset : 0;
            const u64 hi = cur.addr;
            u32 found_in_level = 0;
            for (const auto& r : regs) {
                if (results.size() >= max_results) break;
                if (next_frontier.size() >= max_results) break;
                std::vector<u8> bytes(r.size, 0);
                if (!memory_.ReadRaw(r.base, bytes.data(), bytes.size())) continue;
                for (u64 off = 0; off + 8 <= r.size; off += 8) {
                    u64 v; std::memcpy(&v, bytes.data() + off, 8);
                    if (v < lo || v > hi) continue;
                    Node n{r.base + off, cur.chain};
                    n.chain.push_back({r.base + off, static_cast<i64>(cur.addr - v)});
                    results.push_back(n);
                    next_frontier.push_back(std::move(n));
                    if (++found_in_level >= 64) break;  // spread cap per level
                }
            }
        }
        frontier = std::move(next_frontier);
        if (results.size() >= max_results) break;
    }

    std::ostringstream oss;
    oss << "[PointerPath] target=" << HexAddress(target)
        << " depth=" << max_depth << " max_offset=" << HexValue(max_offset, 4)
        << "\nresults=" << results.size() << "\n";
    const auto limit = std::min<std::size_t>(results.size(), 64);
    for (std::size_t i = 0; i < limit; ++i) {
        const auto& n = results[i];
        if (n.chain.empty()) continue;
        oss << "[" << i << "] ";
        oss << HexAddress(n.chain.back().first);
        for (auto it = n.chain.rbegin(); it != n.chain.rend(); ++it) {
            oss << " -> +" << HexValue(it->second, 4);
        }
        oss << "  (=" << HexAddress(target) << ")\n";
    }
    return oss.str();
}

} // namespace inspector
