#include "inspector/service.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <ios>
#include <sstream>

#include "inspector/formatting.hpp"
#include "inspector/service_util.hpp"

namespace inspector {

namespace {

[[nodiscard]] std::vector<u8> ParseHexBytes(const std::string& text) {
    std::vector<u8> out;
    std::size_t i = 0;
    while (i < text.size()) {
        while (i < text.size() && std::isspace(static_cast<unsigned char>(text[i]))) ++i;
        if (i + 1 >= text.size()) break;
        auto hv = [](char ch) -> int {
            if (ch >= '0' && ch <= '9') return ch - '0';
            if (ch >= 'a' && ch <= 'f') return 10 + (ch - 'a');
            if (ch >= 'A' && ch <= 'F') return 10 + (ch - 'A');
            return -1;
        };
        const int hi = hv(text[i]);
        const int lo = hv(text[i + 1]);
        if (hi < 0 || lo < 0) return {};
        out.push_back(static_cast<u8>((hi << 4) | lo));
        i += 2;
    }
    return out;
}

// Render hex bytes in a shape similar to `xxd` but with upper-case and fixed
// 16-column width (overrideable). Used by default MemoryRead.
[[nodiscard]] std::string RenderHexDump(u64 base, const std::vector<u8>& bytes, u32 row = 16) {
    std::ostringstream oss;
    for (std::size_t off = 0; off < bytes.size(); off += row) {
        oss << HexAddress(base + off) << " ";
        const std::size_t end = std::min(off + row, bytes.size());
        for (std::size_t i = off; i < end; ++i) {
            oss << "0x" << std::uppercase << std::hex
                << std::setw(2) << std::setfill('0') << static_cast<unsigned>(bytes[i]) << " ";
        }
        oss << "\n";
    }
    return oss.str();
}

} // namespace

// ---------------------------------------------------------------------------
// Memory primitives
// ---------------------------------------------------------------------------

std::string Service::MemoryRegions(const std::string& filter, u32 max_results) {
    const bool readable = filter.empty() || filter == "readable";
    const bool writable = filter == "writable";
    const bool execable = filter == "executable";

    const auto regs = detail::EnumerateRegions(0x10000ULL, 0x00007FFF'00000000ULL,
                                                 readable || (!writable && !execable),
                                                 writable, execable);
    std::ostringstream oss;
    oss << "[Regions] filter=" << (filter.empty() ? "readable" : filter)
        << " total=" << regs.size() << "\n";
    const u32 show = std::min<u32>(static_cast<u32>(regs.size()), max_results);
    for (u32 i = 0; i < show; ++i) {
        const auto& r = regs[i];
        oss << HexAddress(r.base) << " size=" << HexValue(r.size, 8)
            << " protect=" << ProtectName(r.protect)
            << " type=" << HexValue(r.type, 8) << "\n";
    }
    return oss.str();
}

std::string Service::MemoryRead(u64 address, u32 size, const std::string& format) {
    const u32 clamped = std::min<u32>(size, 0x4000);
    std::vector<u8> buf(clamped, 0);
    if (!memory_.ReadRaw(address, buf.data(), buf.size())) {
        return "read failed\n";
    }
    std::ostringstream oss;
    oss << "[Memory Read] addr=" << HexAddress(address) << " size=" << clamped
        << " fmt=" << (format.empty() ? "hex" : format) << "\n";

    if (format.empty() || format == "hex") {
        oss << RenderHexDump(address, buf);
    } else if (format == "ascii") {
        oss << HexAddress(address) << " ";
        for (u8 b : buf) oss << (b >= 0x20 && b < 0x7F ? static_cast<char>(b) : '.');
        oss << "\n";
    } else if (format == "u32") {
        for (std::size_t i = 0; i + 4 <= buf.size(); i += 4) {
            u32 v; std::memcpy(&v, buf.data() + i, 4);
            oss << HexAddress(address + i) << " " << v << "\n";
        }
    } else if (format == "u64") {
        for (std::size_t i = 0; i + 8 <= buf.size(); i += 8) {
            u64 v; std::memcpy(&v, buf.data() + i, 8);
            oss << HexAddress(address + i) << " " << v << "\n";
        }
    } else if (format == "f32") {
        for (std::size_t i = 0; i + 4 <= buf.size(); i += 4) {
            f32 v; std::memcpy(&v, buf.data() + i, 4);
            oss << HexAddress(address + i) << " " << v << "\n";
        }
    } else if (format == "f64") {
        for (std::size_t i = 0; i + 8 <= buf.size(); i += 8) {
            f64 v; std::memcpy(&v, buf.data() + i, 8);
            oss << HexAddress(address + i) << " " << v << "\n";
        }
    } else {
        oss << RenderHexDump(address, buf);
    }
    return oss.str();
}

// Raw write — must already be on a writable page.
std::string Service::MemoryWrite(u64 address, const std::string& hex_bytes) {
    const auto bytes = ParseHexBytes(hex_bytes);
    if (bytes.empty()) return "no bytes parsed\n";
    MEMORY_BASIC_INFORMATION mbi{};
    if (::VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) != sizeof(mbi)) {
        return "VirtualQuery failed\n";
    }
    if (mbi.State != MEM_COMMIT || !MemoryView::IsWritable(mbi.Protect)) {
        return "target not writable (use 'patch' for RX pages)\n";
    }
    std::memcpy(reinterpret_cast<void*>(address), bytes.data(), bytes.size());
    ::FlushInstructionCache(::GetCurrentProcess(), reinterpret_cast<LPCVOID>(address), bytes.size());
    std::ostringstream oss;
    oss << "[Write] addr=" << HexAddress(address) << " wrote=" << bytes.size() << " bytes\n";
    return oss.str();
}

// Patch — wraps MemoryWrite with a VirtualProtect flip so .text etc. become
// writable for the duration of the patch. Safe for code patches (hook thunks,
// NOP-out, etc.).
std::string Service::PatchBytes(u64 address, const std::string& hex_bytes) {
    const auto bytes = ParseHexBytes(hex_bytes);
    if (bytes.empty()) return "no bytes parsed\n";

    DWORD old_protect = 0;
    if (!::VirtualProtect(reinterpret_cast<LPVOID>(address), bytes.size(),
                            PAGE_EXECUTE_READWRITE, &old_protect)) {
        return "VirtualProtect(RWX) failed\n";
    }
    std::memcpy(reinterpret_cast<void*>(address), bytes.data(), bytes.size());
    ::FlushInstructionCache(::GetCurrentProcess(), reinterpret_cast<LPCVOID>(address), bytes.size());

    DWORD dummy = 0;
    ::VirtualProtect(reinterpret_cast<LPVOID>(address), bytes.size(), old_protect, &dummy);

    std::ostringstream oss;
    oss << "[Patch] addr=" << HexAddress(address)
        << " bytes=" << bytes.size()
        << " old_protect=" << ProtectName(old_protect) << "\n";
    return oss.str();
}

std::string Service::NopRange(u64 address, u32 size) {
    if (size == 0 || size > 0x1000) return "size must be in [1, 0x1000]\n";

    DWORD old_protect = 0;
    if (!::VirtualProtect(reinterpret_cast<LPVOID>(address), size,
                            PAGE_EXECUTE_READWRITE, &old_protect)) {
        return "VirtualProtect(RWX) failed\n";
    }
    std::memset(reinterpret_cast<void*>(address), 0x90, size);
    ::FlushInstructionCache(::GetCurrentProcess(), reinterpret_cast<LPCVOID>(address), size);
    DWORD dummy = 0;
    ::VirtualProtect(reinterpret_cast<LPVOID>(address), size, old_protect, &dummy);

    std::ostringstream oss;
    oss << "[Nop] addr=" << HexAddress(address) << " size=" << size
        << " old_protect=" << ProtectName(old_protect) << "\n";
    return oss.str();
}

std::string Service::PointerChain(u64 base, const std::string& offsets_text,
                                    u32 hexdump_bytes, bool include_hexdump) {
    // normalize delimiters
    std::string normalized = offsets_text;
    for (char& ch : normalized) if (ch == ';' || ch == '\n' || ch == '\r' || ch == '\t') ch = ',';
    if (normalized.find(',') == std::string::npos) {
        for (char& ch : normalized) if (ch == ' ') ch = ',';
    }

    struct Step { i64 offset{}; bool deref{}; };
    std::vector<Step> steps;
    std::istringstream iss(normalized);
    std::string token;
    while (std::getline(iss, token, ',')) {
        token = Trim(token);
        if (token.empty()) continue;
        bool deref = false;
        if (token.front() == '[' && token.back() == ']') {
            deref = true;
            token = Trim(token.substr(1, token.size() - 2));
        }
        const auto val = ParseI64(token);
        if (!val) return "bad offset token\n";
        steps.push_back(Step{.offset = *val, .deref = deref});
    }

    std::ostringstream oss;
    oss << "[Pointer Chain] base=" << HexAddress(base) << " offsets=" << offsets_text << "\n";
    u64 addr = base;
    for (std::size_t i = 0; i < steps.size(); ++i) {
        const auto& s = steps[i];
        addr = static_cast<u64>(static_cast<i64>(addr) + s.offset);
        oss << "step[" << i << "] addr=" << HexAddress(addr);
        if (s.deref) {
            const auto next = memory_.TryRead<u64>(addr);
            if (!next) { oss << " deref=<read_fail>\n"; return oss.str(); }
            oss << " deref=" << HexAddress(*next) << "\n";
            addr = *next;
        } else {
            oss << "\n";
        }
    }
    oss << "final=" << HexAddress(addr) << "\n";

    if (include_hexdump) {
        const u32 clamped = std::min<u32>(hexdump_bytes, 0x200);
        std::vector<u8> buf(clamped, 0);
        if (memory_.ReadRaw(addr, buf.data(), buf.size())) {
            oss << RenderHexDump(addr, buf);
        } else {
            oss << "<read_fail>\n";
        }
    }
    return oss.str();
}

// ---------------------------------------------------------------------------
// HexView — CE memoryview clone
// cell_type: hex8/hex16/hex32/hex64 | u8..u64 | i8..i64 | f32 | f64 | ascii | utf16
// row_width is in BYTES. ascii pane on the right is optional.
// ---------------------------------------------------------------------------

std::string Service::HexView(u64 address, u32 size, const std::string& cell_type,
                                u32 row_width, bool show_ascii, bool show_signed) {
    if (size == 0 || size > 0x4000) return "size must be in [1, 0x4000]\n";
    if (row_width == 0 || row_width > 64) row_width = 16;

    std::vector<u8> buf(size, 0);
    if (!memory_.ReadRaw(address, buf.data(), buf.size())) {
        return "read failed\n";
    }

    std::string ct = cell_type.empty() ? std::string{"hex8"} : cell_type;
    for (auto& c : ct) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    u32 cell_size = 1;
    if (ct == "hex8"  || ct == "u8"  || ct == "i8"  || ct == "ascii") cell_size = 1;
    else if (ct == "hex16" || ct == "u16" || ct == "i16" || ct == "utf16") cell_size = 2;
    else if (ct == "hex32" || ct == "u32" || ct == "i32" || ct == "f32")  cell_size = 4;
    else if (ct == "hex64" || ct == "u64" || ct == "i64" || ct == "f64")  cell_size = 8;
    else return "unknown cell_type\n";

    if (row_width % cell_size != 0) row_width = (row_width / cell_size) * cell_size;
    if (row_width == 0) row_width = cell_size;

    auto fmt_cell = [&](const u8* p) -> std::string {
        std::ostringstream c;
        if (ct.rfind("hex", 0) == 0) {
            c << "0x" << std::uppercase << std::hex << std::setw(cell_size * 2) << std::setfill('0');
            switch (cell_size) {
            case 1: c << static_cast<unsigned>(p[0]); break;
            case 2: { u16 v; std::memcpy(&v, p, 2); c << static_cast<unsigned>(v); break; }
            case 4: { u32 v; std::memcpy(&v, p, 4); c << static_cast<unsigned>(v); break; }
            case 8: { u64 v; std::memcpy(&v, p, 8); c << static_cast<unsigned long long>(v); break; }
            }
        } else if (ct == "u8" || ct == "u16" || ct == "u32" || ct == "u64") {
            switch (cell_size) {
            case 1: c << static_cast<unsigned>(p[0]); break;
            case 2: { u16 v; std::memcpy(&v, p, 2); c << v; break; }
            case 4: { u32 v; std::memcpy(&v, p, 4); c << v; break; }
            case 8: { u64 v; std::memcpy(&v, p, 8); c << v; break; }
            }
        } else if (ct == "i8" || ct == "i16" || ct == "i32" || ct == "i64") {
            (void)show_signed;
            switch (cell_size) {
            case 1: { i8 v = static_cast<i8>(p[0]); c << static_cast<int>(v); break; }
            case 2: { i16 v; std::memcpy(&v, p, 2); c << v; break; }
            case 4: { i32 v; std::memcpy(&v, p, 4); c << v; break; }
            case 8: { i64 v; std::memcpy(&v, p, 8); c << static_cast<long long>(v); break; }
            }
        } else if (ct == "f32") {
            f32 v; std::memcpy(&v, p, 4); c << v;
        } else if (ct == "f64") {
            f64 v; std::memcpy(&v, p, 8); c << v;
        } else if (ct == "ascii") {
            c << (p[0] >= 0x20 && p[0] < 0x7F ? static_cast<char>(p[0]) : '.');
        } else if (ct == "utf16") {
            u16 v; std::memcpy(&v, p, 2);
            if (v < 0x80 && v >= 0x20) {
                c << static_cast<char>(v);
            } else {
                c << "U+" << std::uppercase << std::hex << std::setw(4) << std::setfill('0') << v;
            }
        }
        return c.str();
    };

    std::ostringstream oss;
    oss << "[HexView] addr=" << HexAddress(address) << " size=" << size
        << " cell=" << ct << " row=" << row_width << "\n";

    const std::size_t cells_per_row = row_width / cell_size;
    for (std::size_t off = 0; off < buf.size(); off += row_width) {
        oss << HexAddress(address + off) << "  ";
        const std::size_t row_end = std::min<std::size_t>(off + row_width, buf.size());
        std::size_t emitted_bytes = 0;
        for (std::size_t c = 0; c < cells_per_row; ++c) {
            const std::size_t byte_start = off + c * cell_size;
            if (byte_start + cell_size > row_end) {
                // pad with blanks so ASCII column aligns
                const int pad_width = static_cast<int>(cell_size * 2 + 2);
                oss << std::string(static_cast<std::size_t>(pad_width), ' ');
                continue;
            }
            oss << fmt_cell(buf.data() + byte_start) << " ";
            emitted_bytes += cell_size;
        }
        if (show_ascii) {
            oss << " ";
            for (std::size_t i = off; i < row_end; ++i) {
                const u8 b = buf[i];
                oss << (b >= 0x20 && b < 0x7F ? static_cast<char>(b) : '.');
            }
            if (emitted_bytes < row_width) {
                oss << std::string(row_width - emitted_bytes, ' ');
            }
        }
        oss << "\n";
    }
    return oss.str();
}

} // namespace inspector
