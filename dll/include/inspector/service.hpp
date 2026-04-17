#pragma once

#include <atomic>
#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "inspector/memory_view.hpp"
#include "inspector/types.hpp"

namespace inspector {

// ============================================================================
// Scan session (CE-like first/next scan)
// ============================================================================

enum class ScanValueKind : std::uint8_t {
    U8, U16, U32, U64,
    I8, I16, I32, I64,
    F32, F64,
};

[[nodiscard]] u32 ScanKindWidth(ScanValueKind) noexcept;
[[nodiscard]] std::string ScanKindName(ScanValueKind) noexcept;

struct ScanMatch {
    u64 address{};
    u64 last_bits{};
};

struct ScanSession {
    ScanValueKind kind{ScanValueKind::U32};
    u32 width{4};
    std::vector<ScanMatch> matches{};
    std::string description{};
};

// ============================================================================
// Watcher (value-change stream, long-poll)
// ============================================================================

enum class WatcherType : std::uint8_t {
    U8, U16, U32, U64,
    I8, I16, I32, I64,
    F32, F64,
    Vec3,
    Bytes,
};

struct Watcher {
    std::string name;
    u64 address{};
    WatcherType type{WatcherType::U32};
    u32 width{4};
    f64 eps{0.0};
    std::vector<u8> last_bytes{};
    bool seeded{false};
};

struct WatchEvent {
    u64 seq{};
    u64 timestamp_ms{};
    std::string name;
    u32 width{};
    WatcherType type{};
    std::vector<u8> old_bytes{};
    std::vector<u8> new_bytes{};
};

// ============================================================================
// CE-style structure session
//
// Each struct has an ordered list of fields. Fields carry a display/decode
// type (byte/word/dword/qword/float/double/ptr/str/ubytes/bin) plus an optional
// child-struct reference (by name) so pointer-fields can be expanded.
// ============================================================================

enum class FieldKind : std::uint8_t {
    Byte = 0, Word = 1, Dword = 2, Qword = 3,
    Single = 4, Double = 5,
    String = 6, UnicodeString = 7,
    ByteArray = 8, Binary = 9,
    Pointer = 12,
};

struct StructField {
    std::string name;
    i64 offset = 0;
    FieldKind kind = FieldKind::Byte;
    u32 bytesize = 1;          // for ByteArray/String/Binary/variable-width
    bool display_hex = false;
    std::string child_struct;  // non-empty => expand as nested struct when rendering
    i64 child_start = 0;       // start offset into child struct
};

struct StructDef {
    std::string name;
    bool default_hex = false;
    std::vector<StructField> fields{};
};

// ============================================================================
// Service — dispatches tab-delimited line commands to the real work functions.
// All commands return a JSON envelope `{ok, command, text}`.
// ============================================================================

class Service {
public:
    Service();
    ~Service();
    Service(const Service&) = delete;
    Service& operator=(const Service&) = delete;

    [[nodiscard]] std::string HandleCommand(const std::string& request_line);

    // ---- Process / module introspection --------------------------------
    [[nodiscard]] std::string ProcessInfo();
    [[nodiscard]] std::string Modules();
    [[nodiscard]] std::string ModuleInfo(const std::string& name);
    [[nodiscard]] std::string ResolveSymbol(const std::string& module_name,
                                             const std::string& symbol);

    // ---- Memory primitives --------------------------------------------
    [[nodiscard]] std::string MemoryRegions(const std::string& filter, u32 max_results);
    [[nodiscard]] std::string MemoryRead(u64 address, u32 size, const std::string& format);
    [[nodiscard]] std::string MemoryWrite(u64 address, const std::string& hex_bytes);
    [[nodiscard]] std::string PatchBytes(u64 address, const std::string& hex_bytes);
    [[nodiscard]] std::string NopRange(u64 address, u32 size);
    [[nodiscard]] std::string PointerChain(u64 base, const std::string& offsets_text,
                                            u32 hexdump_bytes, bool include_hexdump);

    // ---- Hex view (CE memoryview clone) -------------------------------
    // cell_type = hex8/hex16/hex32/hex64 / u8/u16/u32/u64 / i8/i16/i32/i64 /
    //             f32/f64 / ascii / utf16
    [[nodiscard]] std::string HexView(u64 address, u32 size,
                                       const std::string& cell_type,
                                       u32 row_width,
                                       bool show_ascii,
                                       bool show_signed);

    // ---- Scans --------------------------------------------------------
    [[nodiscard]] std::string ScanValue(const std::string& type, const std::string& op,
                                         const std::string& value1, const std::string& value2,
                                         u32 max_matches);
    [[nodiscard]] std::string ScanNext(const std::string& op,
                                        const std::string& value1, const std::string& value2);
    [[nodiscard]] std::string ScanAob(const std::string& pattern, u32 max_matches);
    [[nodiscard]] std::string ScanAobInModule(const std::string& module_name,
                                                const std::string& section,
                                                const std::string& pattern, u32 max_matches);
    [[nodiscard]] std::string ScanPointer(u64 target, u64 max_distance, u32 max_matches);
    [[nodiscard]] std::string ScanString(const std::string& text, bool unicode,
                                           bool case_insensitive, u32 max_matches);
    [[nodiscard]] std::string ScanStatus();
    [[nodiscard]] std::string ScanPeek(u32 offset, u32 count);
    [[nodiscard]] std::string ScanClear();
    [[nodiscard]] std::string FindCodeRefs(u64 target, u32 max_matches);
    [[nodiscard]] std::string PointerPath(u64 target, u32 max_depth,
                                           u32 max_offset, u32 max_results);

    // ---- Dissect / compare / infer / export ---------------------------
    [[nodiscard]] std::string Dissect(u64 base, u32 size, u32 step);
    [[nodiscard]] std::string Compare(u64 base_a, u64 base_b, u32 size, u32 step);
    [[nodiscard]] std::string CompareMany(const std::string& addresses_csv, u32 size, u32 step);
    [[nodiscard]] std::string Infer(u64 base, u32 size);

    // ---- Snapshots ----------------------------------------------------
    [[nodiscard]] std::string SnapshotTake(const std::string& name, u64 base, u32 size);
    [[nodiscard]] std::string SnapshotDiff(const std::string& name, u64 base, u32 size);
    [[nodiscard]] std::string SnapshotList();
    [[nodiscard]] std::string SnapshotClear(const std::string& name);

    // ---- Watchers -----------------------------------------------------
    [[nodiscard]] std::string WatchAdd(const std::string& name, u64 address,
                                        const std::string& type_spec, f64 eps);
    [[nodiscard]] std::string WatchRemove(const std::string& name);
    [[nodiscard]] std::string WatchList();
    [[nodiscard]] std::string WatchClear();
    [[nodiscard]] std::string WatchEvents(u64 since_seq, u32 max_wait_ms, u32 max_events);

    // ---- CE-style structure sessions ---------------------------------
    [[nodiscard]] std::string StructDefine(const std::string& name, bool default_hex);
    [[nodiscard]] std::string StructDelete(const std::string& name);
    [[nodiscard]] std::string StructList();
    [[nodiscard]] std::string StructShow(const std::string& name);
    [[nodiscard]] std::string StructAddField(const std::string& name, i64 offset,
                                               const std::string& kind_spec,
                                               const std::string& field_name,
                                               u32 bytesize,
                                               bool display_hex,
                                               const std::string& child_struct,
                                               i64 child_start);
    [[nodiscard]] std::string StructRemoveField(const std::string& name, u32 index);
    [[nodiscard]] std::string StructEditField(const std::string& name, u32 index,
                                                const std::string& json_delta);
    [[nodiscard]] std::string StructApply(const std::string& name,
                                           const std::string& addresses_csv,
                                           u32 depth);
    [[nodiscard]] std::string StructGuess(const std::string& name, u64 base,
                                            u32 size, bool overwrite);
    [[nodiscard]] std::string StructSaveXml();                       // export all structs
    [[nodiscard]] std::string StructLoadXml(const std::string& xml); // import, replace

    // ---- Disassembler (Zydis) ----------------------------------------
    [[nodiscard]] std::string Disasm(u64 address, u32 instruction_count, u32 max_bytes);
    [[nodiscard]] std::string DisasmRange(u64 lo, u64 hi);

    // ---- Thread introspection ----------------------------------------
    [[nodiscard]] std::string ThreadList();
    [[nodiscard]] std::string ThreadContext(u32 thread_id);

private:
    void StartWatcherThread();
    void StopWatcherThread();
    void WatcherTick();
    [[nodiscard]] std::vector<u8> ReadWatcherBytes(const Watcher& w) const;

    MemoryView memory_{};
    PointerRange pointer_range_{0x10000ULL, 0x000F000000000000ULL};
    u64 host_base_{};

    std::optional<ScanSession> scan_{};

    struct SnapshotEntry {
        u64 base{};
        std::vector<u8> bytes;
    };
    std::unordered_map<std::string, SnapshotEntry> snapshots_{};

    // Structure sessions (name -> definition).
    std::map<std::string, StructDef> structs_{};

    // Watchers
    mutable std::mutex watch_mu_{};
    std::condition_variable watch_cv_{};
    std::map<std::string, Watcher> watchers_{};
    std::vector<WatchEvent> watch_events_{};
    u64 watch_next_seq_{1};
    u64 watch_events_drop_count_{0};
    std::atomic<bool> watch_running_{false};
    std::thread watch_thread_{};

    static constexpr std::size_t kWatchEventRingMax = 4096;
    static constexpr u32 kWatchPollIntervalMs = 50;
};

} // namespace inspector
