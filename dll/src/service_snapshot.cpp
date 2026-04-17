#include "inspector/service.hpp"

#include <algorithm>
#include <cstring>
#include <sstream>

#include "inspector/formatting.hpp"

namespace inspector {

std::string Service::SnapshotTake(const std::string& name, u64 base, u32 size) {
    if (name.empty() || size == 0 || size > 0x100000) return "bad args\n";
    std::vector<u8> bytes(size, 0);
    if (!memory_.ReadRaw(base, bytes.data(), bytes.size())) return "read failed\n";
    snapshots_[name] = SnapshotEntry{.base = base, .bytes = std::move(bytes)};
    std::ostringstream oss;
    oss << "[Snapshot Taken] name=" << name << " base=" << HexAddress(base)
        << " size=" << size << "\n";
    return oss.str();
}

std::string Service::SnapshotDiff(const std::string& name, u64 base, u32 size) {
    const auto it = snapshots_.find(name);
    if (it == snapshots_.end()) return "snapshot not found\n";
    const auto& snap = it->second;
    const u64 cmp_base = base == 0 ? snap.base : base;
    const u32 cmp_size = size == 0 ? static_cast<u32>(snap.bytes.size())
                                    : std::min<u32>(size, static_cast<u32>(snap.bytes.size()));

    std::vector<u8> current(cmp_size, 0);
    if (!memory_.ReadRaw(cmp_base, current.data(), current.size())) return "read failed\n";

    std::ostringstream oss;
    oss << "[Snapshot Diff] name=" << name << " base=" << HexAddress(cmp_base)
        << " size=" << cmp_size << "\n";
    std::size_t changed = 0;
    for (std::size_t i = 0; i < cmp_size; ++i) {
        if (current[i] == snap.bytes[i]) continue;
        if (changed < 128) {
            oss << "+" << HexValue(static_cast<u32>(i), 4)
                << " 0x" << HexValue(snap.bytes[i], 2)
                << " -> 0x" << HexValue(current[i], 2) << "\n";
        }
        ++changed;
    }
    oss << "changed_bytes=" << changed << "\n";
    if (changed > 128) oss << "(truncated, showing first 128)\n";
    return oss.str();
}

std::string Service::SnapshotList() {
    std::ostringstream oss;
    oss << "[Snapshot List] count=" << snapshots_.size() << "\n";
    for (const auto& [name, e] : snapshots_) {
        oss << name << " base=" << HexAddress(e.base) << " size=" << e.bytes.size() << "\n";
    }
    return oss.str();
}

std::string Service::SnapshotClear(const std::string& name) {
    if (name.empty()) {
        const auto n = snapshots_.size();
        snapshots_.clear();
        std::ostringstream oss;
        oss << "cleared " << n << " snapshots\n";
        return oss.str();
    }
    const auto removed = snapshots_.erase(name);
    std::ostringstream oss;
    oss << "removed=" << removed << "\n";
    return oss.str();
}

} // namespace inspector
