#include "inspector/service.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#include "inspector/formatting.hpp"

namespace inspector {

namespace {

[[nodiscard]] std::string DissectRow(const MemoryView& mem, u64 addr, const u8* p, u32 step,
                                        PointerRange range) {
    std::ostringstream oss;
    oss << "@" << HexAddress(addr) << " ";

    if (step >= 8) {
        u64 q = 0; std::memcpy(&q, p, 8);
        oss << "u64=" << HexValue(q, 16);
        if (IsLikelyPointer(q, range)) {
            oss << " ptr";
            const auto deref = mem.TryRead<u64>(q);
            if (deref) oss << "[" << HexAddress(*deref) << "]";
        }
    }
    if (step >= 4) {
        u32 d = 0; std::memcpy(&d, p, 4);
        oss << " u32=" << d;
        f32 f = 0; std::memcpy(&f, p, 4);
        if (std::isfinite(f) && std::fabs(f) > 1e-6f && std::fabs(f) < 1e6f) {
            oss << " f32=" << f;
        }
    }
    oss << " ascii=";
    for (u32 i = 0; i < step; ++i) {
        oss << (p[i] >= 0x20 && p[i] < 0x7F ? static_cast<char>(p[i]) : '.');
    }
    return oss.str();
}

} // namespace

std::string Service::Dissect(u64 base, u32 size, u32 step) {
    if (size == 0 || size > 0x4000) size = 0x200;
    if (step == 0 || step > 32) step = 8;

    std::vector<u8> bytes(size, 0);
    if (!memory_.ReadRaw(base, bytes.data(), bytes.size())) return "read failed\n";

    std::ostringstream oss;
    oss << "[Structure Dissect] base=" << HexAddress(base)
        << " size=" << HexValue(size, 4) << " step=" << step << "\n";
    for (u64 off = 0; off + step <= size; off += step) {
        oss << "+" << HexValue(static_cast<u32>(off), 4) << " "
            << DissectRow(memory_, base + off, bytes.data() + off, step, pointer_range_) << "\n";
    }
    return oss.str();
}

std::string Service::Compare(u64 base_a, u64 base_b, u32 size, u32 step) {
    if (size == 0 || size > 0x4000 || step == 0 || step > 32) return "bad args\n";
    std::vector<u8> a(size, 0);
    std::vector<u8> b(size, 0);
    if (!memory_.ReadRaw(base_a, a.data(), a.size())) return "read A failed\n";
    if (!memory_.ReadRaw(base_b, b.data(), b.size())) return "read B failed\n";

    std::ostringstream oss;
    oss << "[Compare] A=" << HexAddress(base_a) << " B=" << HexAddress(base_b)
        << " size=" << HexValue(size, 4) << " step=" << step << "\n";
    std::size_t diff = 0;
    for (u64 off = 0; off + step <= size; off += step) {
        if (std::memcmp(a.data() + off, b.data() + off, step) == 0) continue;
        if (diff < 128) {
            oss << "+" << HexValue(static_cast<u32>(off), 4);
            if (step == 8) {
                u64 va, vb;
                std::memcpy(&va, a.data() + off, 8);
                std::memcpy(&vb, b.data() + off, 8);
                oss << " A=" << HexValue(va, 16) << " B=" << HexValue(vb, 16);
            } else if (step == 4) {
                u32 va, vb;
                std::memcpy(&va, a.data() + off, 4);
                std::memcpy(&vb, b.data() + off, 4);
                oss << " A=" << HexValue(va, 8) << " B=" << HexValue(vb, 8);
            } else {
                oss << " A=";
                for (u32 i = 0; i < step; ++i) oss << HexValue(a[off + i], 2);
                oss << " B=";
                for (u32 i = 0; i < step; ++i) oss << HexValue(b[off + i], 2);
            }
            oss << "\n";
        }
        ++diff;
    }
    oss << "diff_slots=" << diff << "\n";
    return oss.str();
}

std::string Service::CompareMany(const std::string& csv, u32 size, u32 step) {
    std::vector<u64> addrs;
    std::string token;
    std::istringstream iss(csv);
    while (std::getline(iss, token, ',')) {
        auto v = ParseU64(Trim(token));
        if (v) addrs.push_back(*v);
    }
    if (addrs.size() < 2) return "need >=2 addresses\n";

    std::vector<std::vector<u8>> bufs(addrs.size(), std::vector<u8>(size, 0));
    for (std::size_t i = 0; i < addrs.size(); ++i) {
        if (!memory_.ReadRaw(addrs[i], bufs[i].data(), size)) return "read failed\n";
    }

    std::ostringstream oss;
    oss << "[Compare Many] n=" << addrs.size() << " size=" << HexValue(size, 4) << " step=" << step << "\n";
    for (u64 off = 0; off + step <= size; off += step) {
        bool identical = true;
        for (std::size_t i = 1; i < bufs.size(); ++i) {
            if (std::memcmp(bufs[0].data() + off, bufs[i].data() + off, step) != 0) { identical = false; break; }
        }
        if (identical) continue;
        oss << "+" << HexValue(static_cast<u32>(off), 4) << " ";
        for (std::size_t i = 0; i < bufs.size(); ++i) {
            if (step == 8) {
                u64 v; std::memcpy(&v, bufs[i].data() + off, 8);
                oss << "[" << i << "]=" << HexValue(v, 16) << " ";
            } else if (step == 4) {
                u32 v; std::memcpy(&v, bufs[i].data() + off, 4);
                oss << "[" << i << "]=" << HexValue(v, 8) << " ";
            } else {
                oss << "[" << i << "]=";
                for (u32 k = 0; k < step; ++k) oss << HexValue(bufs[i][off + k], 2);
                oss << " ";
            }
        }
        oss << "\n";
    }
    return oss.str();
}

std::string Service::Infer(u64 base, u32 size) {
    if (size == 0 || size > 0x4000) size = 0x200;
    std::vector<u8> bytes(size, 0);
    if (!memory_.ReadRaw(base, bytes.data(), bytes.size())) return "read failed\n";

    std::ostringstream oss;
    oss << "[Infer] base=" << HexAddress(base) << " size=" << HexValue(size, 4) << "\n";
    for (u64 off = 0; off + 8 <= size; off += 8) {
        u64 q; std::memcpy(&q, bytes.data() + off, 8);
        std::string hint;
        if (IsLikelyPointer(q, pointer_range_)) {
            hint = "ptr";
            const auto deref = memory_.TryRead<u64>(q);
            if (deref) hint += "(resolves)";
        } else if (q == 0) {
            hint = "zero";
        } else if ((q & 0xFFFFFFFF00000000ULL) == 0) {
            u32 lo = static_cast<u32>(q);
            f32 f; std::memcpy(&f, &lo, 4);
            if (std::isfinite(f) && std::fabs(f) > 1e-4f && std::fabs(f) < 1e7f) {
                hint = "f32=" + std::to_string(f);
            } else {
                hint = "u32=" + std::to_string(lo);
            }
        } else {
            hint = "q=" + HexValue(q, 16);
        }
        oss << "+" << HexValue(static_cast<u32>(off), 4) << " " << hint << "\n";
    }
    return oss.str();
}

} // namespace inspector
