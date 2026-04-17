#include "inspector/service.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>

#include <chrono>
#include <cmath>
#include <cstring>
#include <sstream>
#include <thread>

#include "inspector/formatting.hpp"

namespace inspector {

u32 ScanKindWidth(ScanValueKind kind) noexcept {
    switch (kind) {
    case ScanValueKind::U8:  case ScanValueKind::I8:  return 1;
    case ScanValueKind::U16: case ScanValueKind::I16: return 2;
    case ScanValueKind::U32: case ScanValueKind::I32: case ScanValueKind::F32: return 4;
    case ScanValueKind::U64: case ScanValueKind::I64: case ScanValueKind::F64: return 8;
    }
    return 4;
}

std::string ScanKindName(ScanValueKind kind) noexcept {
    switch (kind) {
    case ScanValueKind::U8: return "u8";
    case ScanValueKind::I8: return "i8";
    case ScanValueKind::U16: return "u16";
    case ScanValueKind::I16: return "i16";
    case ScanValueKind::U32: return "u32";
    case ScanValueKind::I32: return "i32";
    case ScanValueKind::U64: return "u64";
    case ScanValueKind::I64: return "i64";
    case ScanValueKind::F32: return "f32";
    case ScanValueKind::F64: return "f64";
    }
    return "?";
}

Service::Service()
    : host_base_(reinterpret_cast<u64>(::GetModuleHandleW(nullptr))) {
    StartWatcherThread();
}

Service::~Service() {
    StopWatcherThread();
}

// ---------------------------------------------------------------------------
// Watcher thread lifecycle
// ---------------------------------------------------------------------------

void Service::StartWatcherThread() {
    bool expected = false;
    if (!watch_running_.compare_exchange_strong(expected, true)) return;
    watch_thread_ = std::thread([this] {
        while (watch_running_.load()) {
            WatcherTick();
            std::this_thread::sleep_for(std::chrono::milliseconds(kWatchPollIntervalMs));
        }
    });
}

void Service::StopWatcherThread() {
    if (!watch_running_.exchange(false)) return;
    watch_cv_.notify_all();
    if (watch_thread_.joinable()) watch_thread_.join();
}

std::vector<u8> Service::ReadWatcherBytes(const Watcher& w) const {
    std::vector<u8> buf(w.width, 0);
    if (!memory_.ReadRaw(w.address, buf.data(), buf.size())) {
        return {};
    }
    return buf;
}

void Service::WatcherTick() {
    std::lock_guard<std::mutex> lock(watch_mu_);
    const auto now_ms = static_cast<u64>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());

    for (auto& [name, w] : watchers_) {
        auto bytes = ReadWatcherBytes(w);
        if (bytes.size() != w.width) continue;

        if (!w.seeded) {
            w.last_bytes = bytes;
            w.seeded = true;
            continue;
        }
        if (bytes == w.last_bytes) continue;

        // Float epsilon filter
        if (w.eps > 0.0 && (w.type == WatcherType::F32 || w.type == WatcherType::F64)) {
            f64 old_v = 0.0, new_v = 0.0;
            if (w.type == WatcherType::F32 && w.width == 4) {
                f32 a = 0, b = 0;
                std::memcpy(&a, w.last_bytes.data(), 4);
                std::memcpy(&b, bytes.data(), 4);
                old_v = a; new_v = b;
            } else if (w.type == WatcherType::F64 && w.width == 8) {
                std::memcpy(&old_v, w.last_bytes.data(), 8);
                std::memcpy(&new_v, bytes.data(), 8);
            }
            if (std::abs(new_v - old_v) < w.eps) { w.last_bytes = bytes; continue; }
        }

        WatchEvent ev{};
        ev.seq = watch_next_seq_++;
        ev.timestamp_ms = now_ms;
        ev.name = name;
        ev.width = w.width;
        ev.type = w.type;
        ev.old_bytes = w.last_bytes;
        ev.new_bytes = bytes;

        if (watch_events_.size() >= kWatchEventRingMax) {
            watch_events_.erase(watch_events_.begin());
            ++watch_events_drop_count_;
        }
        watch_events_.push_back(std::move(ev));
        w.last_bytes = bytes;
    }
    if (!watch_events_.empty()) watch_cv_.notify_all();
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

std::string Service::HandleCommand(const std::string& request_line) {
    const auto parts = SplitTab(request_line);
    if (parts.empty()) return JsonResponse(false, "", "empty command");
    const auto cmd = Trim(parts[0]);
    auto arg = [&](std::size_t i) -> std::string {
        return i < parts.size() ? Trim(parts[i]) : std::string{};
    };

    try {
        if (cmd == "process_info") return JsonResponse(true, cmd, ProcessInfo());

        if (cmd == "modules")      return JsonResponse(true, cmd, Modules());
        if (cmd == "module_info") {
            return JsonResponse(true, cmd, ModuleInfo(arg(1)));
        }
        if (cmd == "resolve_symbol") {
            return JsonResponse(true, cmd, ResolveSymbol(arg(1), arg(2)));
        }

        if (cmd == "regions") {
            const auto max = ParseU32(arg(2));
            return JsonResponse(true, cmd, MemoryRegions(arg(1), max.value_or(128)));
        }
        if (cmd == "read") {
            const auto addr = ParseU64(arg(1));
            const auto sz = ParseU32(arg(2));
            if (!addr || !sz) return JsonResponse(false, cmd, "usage: read<TAB>addr<TAB>size[<TAB>fmt]");
            return JsonResponse(true, cmd, MemoryRead(*addr, *sz, arg(3)));
        }
        if (cmd == "write") {
            const auto addr = ParseU64(arg(1));
            if (!addr) return JsonResponse(false, cmd, "usage: write<TAB>addr<TAB>hex");
            return JsonResponse(true, cmd, MemoryWrite(*addr, arg(2)));
        }
        if (cmd == "patch") {
            const auto addr = ParseU64(arg(1));
            if (!addr) return JsonResponse(false, cmd, "usage: patch<TAB>addr<TAB>hex");
            return JsonResponse(true, cmd, PatchBytes(*addr, arg(2)));
        }
        if (cmd == "nop") {
            const auto addr = ParseU64(arg(1));
            const auto sz = ParseU32(arg(2));
            if (!addr || !sz) return JsonResponse(false, cmd, "usage: nop<TAB>addr<TAB>size");
            return JsonResponse(true, cmd, NopRange(*addr, *sz));
        }
        if (cmd == "chain") {
            const auto base = ParseU64(arg(1));
            const auto bytes = ParseU32(arg(3));
            if (!base || !bytes) return JsonResponse(false, cmd, "usage: chain<TAB>base<TAB>offsets<TAB>bytes<TAB>hexdump0|1");
            return JsonResponse(true, cmd, PointerChain(*base, arg(2), *bytes, arg(4) == "1"));
        }

        if (cmd == "hexview") {
            const auto addr = ParseU64(arg(1));
            const auto size = ParseU32(arg(2));
            if (!addr || !size) return JsonResponse(false, cmd, "usage: hexview<TAB>addr<TAB>size<TAB>cell<TAB>row_width<TAB>ascii<TAB>signed");
            const auto row_w = ParseU32(arg(4));
            const bool ascii = arg(5) != "0";
            const bool sgn   = arg(6) == "1";
            return JsonResponse(true, cmd, HexView(*addr, *size, arg(3), row_w.value_or(16), ascii, sgn));
        }

        if (cmd == "scan") {
            const auto max = ParseU32(arg(5));
            return JsonResponse(true, cmd, ScanValue(arg(1), arg(2), arg(3), arg(4), max.value_or(1'000'000)));
        }
        if (cmd == "scan_next") {
            return JsonResponse(true, cmd, ScanNext(arg(1), arg(2), arg(3)));
        }
        if (cmd == "scan_aob") {
            const auto max = ParseU32(arg(2));
            return JsonResponse(true, cmd, ScanAob(arg(1), max.value_or(4096)));
        }
        if (cmd == "scan_aob_in_module") {
            const auto max = ParseU32(arg(4));
            return JsonResponse(true, cmd, ScanAobInModule(arg(1), arg(2), arg(3), max.value_or(4096)));
        }
        if (cmd == "scan_pointer") {
            const auto tgt = ParseU64(arg(1));
            if (!tgt) return JsonResponse(false, cmd, "usage: scan_pointer<TAB>target[<TAB>max_delta[<TAB>max]]");
            const auto delta = ParseU64(arg(2));
            const auto max = ParseU32(arg(3));
            return JsonResponse(true, cmd, ScanPointer(*tgt, delta.value_or(0x10000ULL), max.value_or(2048)));
        }
        if (cmd == "scan_string") {
            const auto max = ParseU32(arg(4));
            const bool uni = arg(2) == "1";
            const bool ci  = arg(3) == "1";
            return JsonResponse(true, cmd, ScanString(arg(1), uni, ci, max.value_or(2048)));
        }
        if (cmd == "scan_status") return JsonResponse(true, cmd, ScanStatus());
        if (cmd == "scan_peek") {
            return JsonResponse(true, cmd,
                ScanPeek(ParseU32(arg(1)).value_or(0), ParseU32(arg(2)).value_or(32)));
        }
        if (cmd == "scan_clear") return JsonResponse(true, cmd, ScanClear());

        if (cmd == "find_code_refs") {
            const auto tgt = ParseU64(arg(1));
            if (!tgt) return JsonResponse(false, cmd, "usage: find_code_refs<TAB>target[<TAB>max]");
            const auto max = ParseU32(arg(2));
            return JsonResponse(true, cmd, FindCodeRefs(*tgt, max.value_or(2048)));
        }
        if (cmd == "pointer_path") {
            const auto tgt = ParseU64(arg(1));
            if (!tgt) return JsonResponse(false, cmd, "usage: pointer_path<TAB>target<TAB>depth<TAB>max_off<TAB>max_res");
            const auto depth   = ParseU32(arg(2));
            const auto max_off = ParseU32(arg(3));
            const auto max_res = ParseU32(arg(4));
            return JsonResponse(true, cmd,
                PointerPath(*tgt, depth.value_or(3), max_off.value_or(0x1000), max_res.value_or(1024)));
        }

        if (cmd == "dissect") {
            const auto base = ParseU64(arg(1));
            if (!base) return JsonResponse(false, cmd, "usage: dissect<TAB>base[<TAB>size[<TAB>step]]");
            const auto size = ParseU32(arg(2));
            const auto step = ParseU32(arg(3));
            return JsonResponse(true, cmd, Dissect(*base, size.value_or(0x200), step.value_or(8)));
        }
        if (cmd == "compare") {
            const auto a = ParseU64(arg(1));
            const auto b = ParseU64(arg(2));
            const auto size = ParseU32(arg(3));
            if (!a || !b || !size) return JsonResponse(false, cmd, "usage: compare<TAB>a<TAB>b<TAB>size[<TAB>step]");
            return JsonResponse(true, cmd, Compare(*a, *b, *size, ParseU32(arg(4)).value_or(8)));
        }
        if (cmd == "compare_many") {
            const auto size = ParseU32(arg(2));
            if (!size) return JsonResponse(false, cmd, "usage: compare_many<TAB>csv<TAB>size[<TAB>step]");
            return JsonResponse(true, cmd, CompareMany(arg(1), *size, ParseU32(arg(3)).value_or(8)));
        }
        if (cmd == "infer") {
            const auto base = ParseU64(arg(1));
            if (!base) return JsonResponse(false, cmd, "usage: infer<TAB>base[<TAB>size]");
            return JsonResponse(true, cmd, Infer(*base, ParseU32(arg(2)).value_or(0x200)));
        }

        if (cmd == "snapshot_take") {
            const auto base = ParseU64(arg(2));
            const auto size = ParseU32(arg(3));
            if (!base || !size) return JsonResponse(false, cmd, "usage: snapshot_take<TAB>name<TAB>base<TAB>size");
            return JsonResponse(true, cmd, SnapshotTake(arg(1), *base, *size));
        }
        if (cmd == "snapshot_diff") {
            const auto base = ParseU64(arg(2));
            const auto size = ParseU32(arg(3));
            return JsonResponse(true, cmd, SnapshotDiff(arg(1), base.value_or(0), size.value_or(0)));
        }
        if (cmd == "snapshot_list")  return JsonResponse(true, cmd, SnapshotList());
        if (cmd == "snapshot_clear") return JsonResponse(true, cmd, SnapshotClear(arg(1)));

        if (cmd == "watch_add") {
            const auto addr = ParseU64(arg(2));
            if (!addr) return JsonResponse(false, cmd, "usage: watch_add<TAB>name<TAB>addr<TAB>type[<TAB>eps]");
            f64 eps = 0.0;
            if (!arg(4).empty()) { try { eps = std::stod(arg(4)); } catch (...) {} }
            return JsonResponse(true, cmd, WatchAdd(arg(1), *addr, arg(3), eps));
        }
        if (cmd == "watch_remove") return JsonResponse(true, cmd, WatchRemove(arg(1)));
        if (cmd == "watch_list")   return JsonResponse(true, cmd, WatchList());
        if (cmd == "watch_clear")  return JsonResponse(true, cmd, WatchClear());
        if (cmd == "watch_events") {
            return JsonResponse(true, cmd,
                WatchEvents(ParseU64(arg(1)).value_or(0),
                             ParseU32(arg(2)).value_or(0),
                             ParseU32(arg(3)).value_or(64)));
        }

        if (cmd == "struct_define") {
            return JsonResponse(true, cmd, StructDefine(arg(1), arg(2) == "1"));
        }
        if (cmd == "struct_delete") return JsonResponse(true, cmd, StructDelete(arg(1)));
        if (cmd == "struct_list")   return JsonResponse(true, cmd, StructList());
        if (cmd == "struct_show")   return JsonResponse(true, cmd, StructShow(arg(1)));
        if (cmd == "struct_add_field") {
            const auto off = ParseI64(arg(2));
            if (!off) return JsonResponse(false, cmd, "usage: struct_add_field<TAB>name<TAB>offset<TAB>kind<TAB>field<TAB>bytesize<TAB>hex<TAB>child<TAB>child_start");
            const auto bs = ParseU32(arg(5));
            const bool hex = arg(6) == "1";
            const auto cs = ParseI64(arg(8));
            return JsonResponse(true, cmd,
                StructAddField(arg(1), *off, arg(3), arg(4), bs.value_or(0), hex, arg(7), cs.value_or(0)));
        }
        if (cmd == "struct_remove_field") {
            const auto idx = ParseU32(arg(2));
            if (!idx && arg(2) != "0") return JsonResponse(false, cmd, "bad index");
            return JsonResponse(true, cmd, StructRemoveField(arg(1), idx.value_or(0)));
        }
        if (cmd == "struct_edit_field") {
            const auto idx = ParseU32(arg(2));
            return JsonResponse(true, cmd, StructEditField(arg(1), idx.value_or(0), arg(3)));
        }
        if (cmd == "struct_apply") {
            const auto depth = ParseU32(arg(3));
            return JsonResponse(true, cmd, StructApply(arg(1), arg(2), depth.value_or(1)));
        }
        if (cmd == "struct_guess") {
            const auto base = ParseU64(arg(2));
            const auto size = ParseU32(arg(3));
            if (!base || !size) return JsonResponse(false, cmd, "usage: struct_guess<TAB>name<TAB>base<TAB>size<TAB>overwrite");
            const bool ow = arg(4) == "1";
            return JsonResponse(true, cmd, StructGuess(arg(1), *base, *size, ow));
        }
        if (cmd == "struct_save_xml") return JsonResponse(true, cmd, StructSaveXml());
        if (cmd == "struct_load_xml") return JsonResponse(true, cmd, StructLoadXml(arg(1)));

        if (cmd == "disasm") {
            const auto addr = ParseU64(arg(1));
            if (!addr) return JsonResponse(false, cmd, "usage: disasm<TAB>addr<TAB>count[<TAB>max_bytes]");
            const auto n = ParseU32(arg(2));
            const auto max_bytes = ParseU32(arg(3));
            return JsonResponse(true, cmd, Disasm(*addr, n.value_or(32), max_bytes.value_or(0)));
        }
        if (cmd == "disasm_range") {
            const auto lo = ParseU64(arg(1));
            const auto hi = ParseU64(arg(2));
            if (!lo || !hi || *hi <= *lo) return JsonResponse(false, cmd, "usage: disasm_range<TAB>lo<TAB>hi");
            return JsonResponse(true, cmd, DisasmRange(*lo, *hi));
        }

        if (cmd == "thread_list")    return JsonResponse(true, cmd, ThreadList());
        if (cmd == "thread_context") {
            const auto tid = ParseU32(arg(1));
            if (!tid) return JsonResponse(false, cmd, "usage: thread_context<TAB>tid");
            return JsonResponse(true, cmd, ThreadContext(*tid));
        }

        return JsonResponse(false, cmd, "unknown command");
    } catch (const std::exception& ex) {
        return JsonResponse(false, cmd, std::string{"exception: "} + ex.what());
    } catch (...) {
        return JsonResponse(false, cmd, "unknown exception");
    }
}

// ---------------------------------------------------------------------------
// Process info (very small; lives here rather than its own TU).
// ---------------------------------------------------------------------------

std::string Service::ProcessInfo() {
    std::ostringstream oss;
    oss << "[Process Info]\n";
    oss << "pid=" << ::GetCurrentProcessId() << "\n";
    oss << "host_module=" << HexAddress(host_base_) << "\n";

    wchar_t path_w[MAX_PATH]{};
    ::GetModuleFileNameW(reinterpret_cast<HMODULE>(host_base_), path_w, MAX_PATH);
    char path_a[MAX_PATH * 2]{};
    ::WideCharToMultiByte(CP_UTF8, 0, path_w, -1, path_a, sizeof(path_a), nullptr, nullptr);
    oss << "host_path=" << path_a << "\n";
    oss << "os_build=" << HexValue(::GetVersion(), 8) << "\n";
    oss << "watcher_poll_ms=" << kWatchPollIntervalMs << "\n";
    return oss.str();
}

} // namespace inspector
