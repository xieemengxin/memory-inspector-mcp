#include "inspector/service.hpp"

#include <chrono>
#include <cstring>
#include <iomanip>
#include <sstream>

#include "inspector/formatting.hpp"

namespace inspector {

namespace {

[[nodiscard]] std::optional<std::pair<WatcherType, u32>> ParseWatcherSpec(const std::string& spec) {
    const auto t = Trim(spec);
    if (t == "u8")   return std::pair{WatcherType::U8, 1u};
    if (t == "u16")  return std::pair{WatcherType::U16, 2u};
    if (t == "u32")  return std::pair{WatcherType::U32, 4u};
    if (t == "u64")  return std::pair{WatcherType::U64, 8u};
    if (t == "i8")   return std::pair{WatcherType::I8, 1u};
    if (t == "i16")  return std::pair{WatcherType::I16, 2u};
    if (t == "i32")  return std::pair{WatcherType::I32, 4u};
    if (t == "i64")  return std::pair{WatcherType::I64, 8u};
    if (t == "f32")  return std::pair{WatcherType::F32, 4u};
    if (t == "f64")  return std::pair{WatcherType::F64, 8u};
    if (t == "vec3") return std::pair{WatcherType::Vec3, 12u};
    if (t.rfind("bytes:", 0) == 0) {
        try {
            auto n = std::stoul(t.substr(6));
            if (n == 0 || n > 0x100) return std::nullopt;
            return std::pair{WatcherType::Bytes, static_cast<u32>(n)};
        } catch (...) {}
    }
    return std::nullopt;
}

[[nodiscard]] std::string WatcherTypeName(WatcherType t) {
    switch (t) {
    case WatcherType::U8: return "u8";
    case WatcherType::U16: return "u16";
    case WatcherType::U32: return "u32";
    case WatcherType::U64: return "u64";
    case WatcherType::I8: return "i8";
    case WatcherType::I16: return "i16";
    case WatcherType::I32: return "i32";
    case WatcherType::I64: return "i64";
    case WatcherType::F32: return "f32";
    case WatcherType::F64: return "f64";
    case WatcherType::Vec3: return "vec3";
    case WatcherType::Bytes: return "bytes";
    }
    return "?";
}

[[nodiscard]] std::string FormatWatcherBytes(const std::vector<u8>& b, WatcherType t, u32 width) {
    std::ostringstream oss;
    auto rd_u64 = [&]() -> u64 { u64 v = 0; std::memcpy(&v, b.data(), std::min<std::size_t>(b.size(), 8)); return v; };
    switch (t) {
    case WatcherType::U8: case WatcherType::U16:
    case WatcherType::U32: case WatcherType::U64:
        oss << rd_u64(); return oss.str();
    case WatcherType::I8: {
        i8 v = 0; if (b.size() >= 1) std::memcpy(&v, b.data(), 1); oss << static_cast<int>(v); return oss.str();
    }
    case WatcherType::I16: { i16 v = 0; std::memcpy(&v, b.data(), 2); oss << v; return oss.str(); }
    case WatcherType::I32: { i32 v = 0; std::memcpy(&v, b.data(), 4); oss << v; return oss.str(); }
    case WatcherType::I64: { i64 v = 0; std::memcpy(&v, b.data(), 8); oss << static_cast<long long>(v); return oss.str(); }
    case WatcherType::F32: { f32 v = 0; std::memcpy(&v, b.data(), 4); oss << v; return oss.str(); }
    case WatcherType::F64: { f64 v = 0; std::memcpy(&v, b.data(), 8); oss << v; return oss.str(); }
    case WatcherType::Vec3: {
        f32 x, y, z;
        std::memcpy(&x, b.data() + 0, 4);
        std::memcpy(&y, b.data() + 4, 4);
        std::memcpy(&z, b.data() + 8, 4);
        oss << "(" << x << ", " << y << ", " << z << ")";
        return oss.str();
    }
    case WatcherType::Bytes: {
        for (u32 i = 0; i < width && i < b.size(); ++i) {
            oss << std::uppercase << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<unsigned>(b[i]);
            if (i + 1 < width) oss << " ";
        }
        return oss.str();
    }
    }
    return oss.str();
}

} // namespace

std::string Service::WatchAdd(const std::string& name, u64 address,
                                 const std::string& type_spec, f64 eps) {
    if (name.empty()) return "empty name\n";
    const auto parsed = ParseWatcherSpec(type_spec);
    if (!parsed) return "bad type spec (u8..f64|vec3|bytes:N)\n";
    {
        std::lock_guard<std::mutex> lock(watch_mu_);
        Watcher w{};
        w.name = name;
        w.address = address;
        w.type = parsed->first;
        w.width = parsed->second;
        w.eps = eps;
        watchers_[name] = std::move(w);
    }
    watch_cv_.notify_all();
    std::ostringstream oss;
    oss << "[WatchAdd] name=" << name << " addr=" << HexAddress(address)
        << " type=" << type_spec << " width=" << parsed->second
        << " eps=" << eps << "\n";
    return oss.str();
}

std::string Service::WatchRemove(const std::string& name) {
    std::lock_guard<std::mutex> lock(watch_mu_);
    const auto removed = watchers_.erase(name);
    std::ostringstream oss;
    oss << "removed=" << removed << "\n";
    return oss.str();
}

std::string Service::WatchList() {
    std::lock_guard<std::mutex> lock(watch_mu_);
    std::ostringstream oss;
    oss << "[WatchList] count=" << watchers_.size() << "\n";
    for (const auto& [name, w] : watchers_) {
        oss << name << " addr=" << HexAddress(w.address)
            << " type=" << WatcherTypeName(w.type) << "/" << w.width
            << " seeded=" << (w.seeded ? 1 : 0) << "\n";
    }
    return oss.str();
}

std::string Service::WatchClear() {
    std::lock_guard<std::mutex> lock(watch_mu_);
    const auto n = watchers_.size();
    watchers_.clear();
    std::ostringstream oss;
    oss << "cleared=" << n << "\n";
    return oss.str();
}

std::string Service::WatchEvents(u64 since_seq, u32 max_wait_ms, u32 max_events) {
    std::unique_lock<std::mutex> lock(watch_mu_);
    auto has_newer = [&] {
        return !watch_events_.empty() && watch_events_.back().seq > since_seq;
    };
    if (!has_newer() && max_wait_ms > 0) {
        watch_cv_.wait_for(lock, std::chrono::milliseconds(max_wait_ms), has_newer);
    }

    std::ostringstream oss;
    oss << "[WatchEvents] since_seq=" << since_seq << "\n";
    u32 emitted = 0;
    u64 last_seq = since_seq;
    for (const auto& ev : watch_events_) {
        if (ev.seq <= since_seq) continue;
        if (emitted >= max_events) break;
        last_seq = ev.seq;
        oss << "[" << ev.seq << "] t=" << ev.timestamp_ms
            << " " << ev.name
            << " old=" << FormatWatcherBytes(ev.old_bytes, ev.type, ev.width)
            << " new=" << FormatWatcherBytes(ev.new_bytes, ev.type, ev.width)
            << "\n";
        ++emitted;
    }
    oss << "emitted=" << emitted << " last_seq=" << last_seq
        << " dropped=" << watch_events_drop_count_ << "\n";
    return oss.str();
}

} // namespace inspector
