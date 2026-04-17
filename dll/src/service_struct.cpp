#include "inspector/service.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstring>
#include <functional>
#include <iomanip>
#include <sstream>

#include "inspector/formatting.hpp"

// ---------------------------------------------------------------------------
// CE-compatible dissected-structure sessions.
//
// Each struct is a named, ordered list of typed fields. Apply walks one or
// more base addresses and emits one value per field. Pointer fields can name
// a child struct which will be followed for `depth` levels of expansion.
//
// XML export uses the same element names as CE (`Structure`, `Elements`,
// `Element`) so a definition can be round-tripped through Cheat Engine's
// "Save structure" menu.
// ---------------------------------------------------------------------------

namespace inspector {

namespace {

[[nodiscard]] std::optional<FieldKind> ParseFieldKind(const std::string& s) {
    const auto t = Trim(s);
    if (t == "byte"  || t == "u8" || t == "vt0") return FieldKind::Byte;
    if (t == "word"  || t == "u16" || t == "vt1") return FieldKind::Word;
    if (t == "dword" || t == "u32" || t == "vt2") return FieldKind::Dword;
    if (t == "qword" || t == "u64" || t == "vt3") return FieldKind::Qword;
    if (t == "single"|| t == "f32" || t == "vt4") return FieldKind::Single;
    if (t == "double"|| t == "f64" || t == "vt5") return FieldKind::Double;
    if (t == "string"|| t == "ascii" || t == "vt6") return FieldKind::String;
    if (t == "unicodestring" || t == "utf16" || t == "wstring" || t == "vt7") return FieldKind::UnicodeString;
    if (t == "bytearray" || t == "bytes" || t == "vt8") return FieldKind::ByteArray;
    if (t == "binary" || t == "vt9") return FieldKind::Binary;
    if (t == "pointer" || t == "ptr" || t == "vt12") return FieldKind::Pointer;
    return std::nullopt;
}

[[nodiscard]] std::string FieldKindName(FieldKind k) {
    switch (k) {
    case FieldKind::Byte: return "byte";
    case FieldKind::Word: return "word";
    case FieldKind::Dword: return "dword";
    case FieldKind::Qword: return "qword";
    case FieldKind::Single: return "single";
    case FieldKind::Double: return "double";
    case FieldKind::String: return "string";
    case FieldKind::UnicodeString: return "unicodestring";
    case FieldKind::ByteArray: return "bytearray";
    case FieldKind::Binary: return "binary";
    case FieldKind::Pointer: return "pointer";
    }
    return "?";
}

[[nodiscard]] u32 NaturalWidth(FieldKind k) {
    switch (k) {
    case FieldKind::Byte:   return 1;
    case FieldKind::Word:   return 2;
    case FieldKind::Dword:  return 4;
    case FieldKind::Qword:  return 8;
    case FieldKind::Single: return 4;
    case FieldKind::Double: return 8;
    case FieldKind::Pointer:return 8;
    default: return 0;  // variable-width
    }
}

[[nodiscard]] std::string RenderFieldValue(const MemoryView& mem, u64 address,
                                              const StructField& f, bool default_hex) {
    std::ostringstream oss;
    const bool hex = f.display_hex || default_hex;
    switch (f.kind) {
    case FieldKind::Byte: {
        auto v = mem.TryRead<u8>(address);
        if (!v) return "<read_fail>";
        if (hex) oss << HexValue(*v, 2); else oss << static_cast<unsigned>(*v);
        break;
    }
    case FieldKind::Word: {
        auto v = mem.TryRead<u16>(address);
        if (!v) return "<read_fail>";
        if (hex) oss << HexValue(*v, 4); else oss << *v;
        break;
    }
    case FieldKind::Dword: {
        auto v = mem.TryRead<u32>(address);
        if (!v) return "<read_fail>";
        if (hex) oss << HexValue(*v, 8); else oss << *v;
        break;
    }
    case FieldKind::Qword: {
        auto v = mem.TryRead<u64>(address);
        if (!v) return "<read_fail>";
        if (hex) oss << HexValue(*v, 16); else oss << *v;
        break;
    }
    case FieldKind::Single: {
        auto v = mem.TryRead<f32>(address);
        if (!v) return "<read_fail>";
        oss << *v;
        break;
    }
    case FieldKind::Double: {
        auto v = mem.TryRead<f64>(address);
        if (!v) return "<read_fail>";
        oss << *v;
        break;
    }
    case FieldKind::Pointer: {
        auto v = mem.TryRead<u64>(address);
        if (!v) return "<read_fail>";
        oss << HexAddress(*v);
        break;
    }
    case FieldKind::String: {
        const u32 n = f.bytesize == 0 ? 32 : std::min<u32>(f.bytesize, 256);
        std::vector<u8> buf(n, 0);
        if (!mem.ReadRaw(address, buf.data(), buf.size())) return "<read_fail>";
        oss << "\"";
        for (u8 b : buf) {
            if (b == 0) break;
            oss << (b >= 0x20 && b < 0x7F ? static_cast<char>(b) : '.');
        }
        oss << "\"";
        break;
    }
    case FieldKind::UnicodeString: {
        const u32 n = f.bytesize == 0 ? 64 : std::min<u32>(f.bytesize, 512);
        std::vector<u8> buf(n, 0);
        if (!mem.ReadRaw(address, buf.data(), buf.size())) return "<read_fail>";
        oss << "u\"";
        for (std::size_t i = 0; i + 1 < buf.size(); i += 2) {
            u16 w; std::memcpy(&w, buf.data() + i, 2);
            if (w == 0) break;
            if (w < 0x80 && w >= 0x20) oss << static_cast<char>(w);
            else oss << '.';
        }
        oss << "\"";
        break;
    }
    case FieldKind::ByteArray:
    case FieldKind::Binary: {
        const u32 n = f.bytesize == 0 ? 8 : std::min<u32>(f.bytesize, 64);
        std::vector<u8> buf(n, 0);
        if (!mem.ReadRaw(address, buf.data(), buf.size())) return "<read_fail>";
        for (u32 i = 0; i < n; ++i) oss << HexValue(buf[i], 2) << (i + 1 < n ? " " : "");
        break;
    }
    }
    return oss.str();
}

[[nodiscard]] std::string SanitizeXml(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
        case '<': out += "&lt;"; break;
        case '>': out += "&gt;"; break;
        case '&': out += "&amp;"; break;
        case '"': out += "&quot;"; break;
        default:  out += c; break;
        }
    }
    return out;
}

[[nodiscard]] u8 CeVartypeIndex(FieldKind k) {
    return static_cast<u8>(k);
}

} // namespace

std::string Service::StructDefine(const std::string& name, bool default_hex) {
    if (name.empty()) return "empty name\n";
    auto& st = structs_[name];
    st.name = name;
    st.default_hex = default_hex;
    std::ostringstream oss;
    oss << "[struct_define] name=" << name << " default_hex=" << (default_hex ? 1 : 0)
        << " fields=" << st.fields.size() << "\n";
    return oss.str();
}

std::string Service::StructDelete(const std::string& name) {
    const auto removed = structs_.erase(name);
    std::ostringstream oss;
    oss << "removed=" << removed << "\n";
    return oss.str();
}

std::string Service::StructList() {
    std::ostringstream oss;
    oss << "[struct_list] count=" << structs_.size() << "\n";
    for (const auto& [n, s] : structs_) {
        oss << n << " fields=" << s.fields.size()
            << " default_hex=" << (s.default_hex ? 1 : 0) << "\n";
    }
    return oss.str();
}

std::string Service::StructShow(const std::string& name) {
    const auto it = structs_.find(name);
    if (it == structs_.end()) return "struct not found\n";
    const auto& st = it->second;
    std::ostringstream oss;
    oss << "[struct_show] name=" << name
        << " default_hex=" << (st.default_hex ? 1 : 0)
        << " fields=" << st.fields.size() << "\n";
    for (std::size_t i = 0; i < st.fields.size(); ++i) {
        const auto& f = st.fields[i];
        oss << "[" << i << "] +" << HexValue(static_cast<u32>(f.offset), 4)
            << " " << FieldKindName(f.kind)
            << " name='" << f.name << "'"
            << " bytesize=" << f.bytesize
            << " hex=" << (f.display_hex ? 1 : 0);
        if (!f.child_struct.empty()) {
            oss << " child=" << f.child_struct << "+" << f.child_start;
        }
        oss << "\n";
    }
    return oss.str();
}

std::string Service::StructAddField(const std::string& name, i64 offset,
                                       const std::string& kind_spec,
                                       const std::string& field_name,
                                       u32 bytesize, bool display_hex,
                                       const std::string& child_struct, i64 child_start) {
    auto it = structs_.find(name);
    if (it == structs_.end()) return "struct not found (call struct_define first)\n";
    const auto kind = ParseFieldKind(kind_spec);
    if (!kind) return "bad kind\n";

    StructField f{};
    f.name = field_name;
    f.offset = offset;
    f.kind = *kind;
    f.bytesize = bytesize == 0 ? NaturalWidth(*kind) : bytesize;
    f.display_hex = display_hex;
    f.child_struct = child_struct;
    f.child_start = child_start;

    it->second.fields.push_back(std::move(f));
    std::sort(it->second.fields.begin(), it->second.fields.end(),
                [](const StructField& a, const StructField& b) { return a.offset < b.offset; });

    std::ostringstream oss;
    oss << "[struct_add_field] name=" << name
        << " +" << HexValue(static_cast<u32>(offset), 4)
        << " " << FieldKindName(*kind) << "\n";
    return oss.str();
}

std::string Service::StructRemoveField(const std::string& name, u32 index) {
    auto it = structs_.find(name);
    if (it == structs_.end()) return "struct not found\n";
    if (index >= it->second.fields.size()) return "index out of range\n";
    it->second.fields.erase(it->second.fields.begin() + index);
    std::ostringstream oss;
    oss << "removed index=" << index << " remaining=" << it->second.fields.size() << "\n";
    return oss.str();
}

std::string Service::StructEditField(const std::string& name, u32 index, const std::string& delta) {
    auto it = structs_.find(name);
    if (it == structs_.end()) return "struct not found\n";
    if (index >= it->second.fields.size()) return "index out of range\n";
    auto& f = it->second.fields[index];

    // delta format: space-separated key=value pairs.
    // Recognized keys: name, offset, kind, bytesize, hex, child, child_start.
    std::istringstream iss(delta);
    std::string token;
    while (std::getline(iss, token, ' ')) {
        const auto eq = token.find('=');
        if (eq == std::string::npos) continue;
        const auto key = token.substr(0, eq);
        const auto val = token.substr(eq + 1);
        if (key == "name") f.name = val;
        else if (key == "offset") { auto v = ParseI64(val); if (v) f.offset = *v; }
        else if (key == "kind")   { auto v = ParseFieldKind(val); if (v) f.kind = *v; }
        else if (key == "bytesize") { auto v = ParseU32(val); if (v) f.bytesize = *v; }
        else if (key == "hex")    f.display_hex = (val == "1" || val == "true");
        else if (key == "child")  f.child_struct = val;
        else if (key == "child_start") { auto v = ParseI64(val); if (v) f.child_start = *v; }
    }

    std::ostringstream oss;
    oss << "[struct_edit_field] name=" << name << " index=" << index
        << " -> " << FieldKindName(f.kind) << " +" << HexValue(static_cast<u32>(f.offset), 4)
        << " '" << f.name << "'\n";
    return oss.str();
}

std::string Service::StructApply(const std::string& name,
                                    const std::string& addresses_csv, u32 depth) {
    auto it = structs_.find(name);
    if (it == structs_.end()) return "struct not found\n";
    const auto& st = it->second;

    std::vector<u64> addrs;
    {
        std::string token;
        std::istringstream iss(addresses_csv);
        while (std::getline(iss, token, ',')) {
            auto v = ParseU64(Trim(token));
            if (v) addrs.push_back(*v);
        }
    }
    if (addrs.empty()) return "no valid addresses\n";
    if (depth == 0 || depth > 4) depth = 1;

    std::ostringstream oss;
    oss << "[struct_apply] name=" << name << " addrs=" << addrs.size()
        << " depth=" << depth << "\n";
    oss << "offset field:type ";
    for (std::size_t i = 0; i < addrs.size(); ++i) oss << "[" << i << "]=" << HexAddress(addrs[i]) << " ";
    oss << "\n";

    std::function<void(const StructDef&, u32, const std::vector<u64>&, const std::string&)> render;
    render = [&](const StructDef& def, u32 cur_depth,
                   const std::vector<u64>& bases, const std::string& indent) {
        for (const auto& f : def.fields) {
            oss << indent << "+" << HexValue(static_cast<u32>(f.offset), 4)
                << " " << (f.name.empty() ? "_" : f.name)
                << ":" << FieldKindName(f.kind) << " ";
            for (std::size_t i = 0; i < bases.size(); ++i) {
                const u64 addr = bases[i] + static_cast<i64>(f.offset);
                oss << "[" << i << "]=" << RenderFieldValue(memory_, addr, f, def.default_hex) << " ";
            }
            oss << "\n";

            if (f.kind == FieldKind::Pointer && !f.child_struct.empty() && cur_depth > 0) {
                auto child_it = structs_.find(f.child_struct);
                if (child_it == structs_.end()) continue;
                std::vector<u64> child_bases;
                child_bases.reserve(bases.size());
                for (u64 b : bases) {
                    auto p = memory_.TryRead<u64>(b + static_cast<i64>(f.offset));
                    if (p && IsLikelyPointer(*p, pointer_range_)) {
                        child_bases.push_back(*p + f.child_start);
                    } else {
                        child_bases.push_back(0);
                    }
                }
                render(child_it->second, cur_depth - 1, child_bases, indent + "  ");
            }
        }
    };

    render(st, depth - 1, addrs, "");
    return oss.str();
}

std::string Service::StructGuess(const std::string& name, u64 base, u32 size, bool overwrite) {
    auto it = structs_.find(name);
    if (it == structs_.end()) return "struct not found (call struct_define first)\n";
    if (size == 0 || size > 0x1000) return "bad size\n";

    if (overwrite) it->second.fields.clear();

    std::vector<u8> bytes(size, 0);
    if (!memory_.ReadRaw(base, bytes.data(), bytes.size())) return "read failed\n";

    auto has_field_at = [&](u32 off) {
        for (const auto& f : it->second.fields)
            if (f.offset == static_cast<i64>(off)) return true;
        return false;
    };

    u32 off = 0;
    u32 added = 0;
    while (off + 8 <= size) {
        if (has_field_at(off)) { off += 8; continue; }
        u64 q; std::memcpy(&q, bytes.data() + off, 8);
        StructField f{};
        f.offset = off;
        if (IsLikelyPointer(q, pointer_range_)) {
            f.kind = FieldKind::Pointer;
            f.bytesize = 8;
            off += 8;
        } else if (q == 0) {
            f.kind = FieldKind::Qword;
            f.bytesize = 8;
            off += 8;
        } else if ((q & 0xFFFFFFFF00000000ULL) == 0) {
            u32 lo = static_cast<u32>(q);
            f32 fv; std::memcpy(&fv, &lo, 4);
            if (std::isfinite(fv) && std::fabs(fv) > 1e-4f && std::fabs(fv) < 1e7f) {
                f.kind = FieldKind::Single; f.bytesize = 4;
            } else {
                f.kind = FieldKind::Dword; f.bytesize = 4; f.display_hex = true;
            }
            off += 4;
        } else {
            f.kind = FieldKind::Qword; f.bytesize = 8; f.display_hex = true;
            off += 8;
        }
        it->second.fields.push_back(std::move(f));
        ++added;
    }

    std::ostringstream oss;
    oss << "[struct_guess] name=" << name << " base=" << HexAddress(base)
        << " size=" << size << " added=" << added << "\n";
    return oss.str();
}

std::string Service::StructSaveXml() {
    std::ostringstream oss;
    oss << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
    oss << "<InspectorStructures>\n";
    for (const auto& [n, s] : structs_) {
        oss << "  <Structure Name=\"" << SanitizeXml(n)
            << "\" DefaultHex=\"" << (s.default_hex ? 1 : 0) << "\">\n";
        oss << "    <Elements>\n";
        for (const auto& f : s.fields) {
            oss << "      <Element Offset=\"" << f.offset
                << "\" Vartype=\"" << static_cast<int>(CeVartypeIndex(f.kind))
                << "\" Bytesize=\"" << f.bytesize
                << "\" DisplayMethod=\"" << (f.display_hex ? "dtHexadecimal" : "dtUnsignedInteger")
                << "\" Name=\"" << SanitizeXml(f.name) << "\"";
            if (!f.child_struct.empty()) {
                oss << " ChildStruct=\"" << SanitizeXml(f.child_struct) << "\""
                    << " ChildStructStart=\"" << f.child_start << "\"";
            }
            oss << "/>\n";
        }
        oss << "    </Elements>\n";
        oss << "  </Structure>\n";
    }
    oss << "</InspectorStructures>\n";
    return oss.str();
}

std::string Service::StructLoadXml(const std::string& xml) {
    // Minimal tag-based parser: walk looking for <Structure ...> and <Element ...>.
    // Not a full XML parser — enough to round-trip what StructSaveXml emits AND
    // what CE writes.
    auto find_attr = [](const std::string& tag, const std::string& key) -> std::string {
        const auto pos = tag.find(key + "=\"");
        if (pos == std::string::npos) return {};
        const auto start = pos + key.size() + 2;
        const auto end = tag.find('"', start);
        if (end == std::string::npos) return {};
        return tag.substr(start, end - start);
    };

    structs_.clear();
    std::size_t i = 0;
    StructDef* cur = nullptr;
    u32 loaded_structs = 0;
    u32 loaded_fields = 0;
    while (i < xml.size()) {
        if (xml[i] != '<') { ++i; continue; }
        const auto close = xml.find('>', i);
        if (close == std::string::npos) break;
        const auto tag = xml.substr(i + 1, close - i - 1);
        i = close + 1;

        if (tag.rfind("Structure ", 0) == 0) {
            StructDef d{};
            d.name = find_attr(tag, "Name");
            d.default_hex = find_attr(tag, "DefaultHex") == "1";
            auto [it, inserted] = structs_.emplace(d.name, std::move(d));
            (void)inserted;
            cur = &it->second;
            ++loaded_structs;
        } else if (tag.rfind("Element", 0) == 0 && cur) {
            StructField f{};
            const auto off = find_attr(tag, "Offset");
            const auto vt  = find_attr(tag, "Vartype");
            const auto bs  = find_attr(tag, "Bytesize");
            const auto dm  = find_attr(tag, "DisplayMethod");
            f.name = find_attr(tag, "Name");
            f.child_struct = find_attr(tag, "ChildStruct");
            if (!off.empty()) { auto v = ParseI64(off); if (v) f.offset = *v; }
            if (!vt.empty())  { auto v = ParseU32(vt);  if (v && *v <= 12) f.kind = static_cast<FieldKind>(*v); }
            if (!bs.empty())  { auto v = ParseU32(bs);  if (v) f.bytesize = *v; }
            f.display_hex = dm.find("Hex") != std::string::npos;
            const auto cs = find_attr(tag, "ChildStructStart");
            if (!cs.empty())  { auto v = ParseI64(cs);  if (v) f.child_start = *v; }
            if (f.bytesize == 0) f.bytesize = NaturalWidth(f.kind);
            cur->fields.push_back(std::move(f));
            ++loaded_fields;
        } else if (tag == "/Structure") {
            cur = nullptr;
        }
    }

    std::ostringstream oss;
    oss << "[struct_load_xml] loaded_structs=" << loaded_structs
        << " loaded_fields=" << loaded_fields << "\n";
    return oss.str();
}

} // namespace inspector
