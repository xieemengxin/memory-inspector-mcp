#pragma once

#include <cctype>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "inspector/types.hpp"

namespace inspector {

template <typename T>
[[nodiscard]] inline std::string HexValue(T value, int width = static_cast<int>(sizeof(T) * 2)) {
    std::ostringstream oss;
    oss << "0x" << std::uppercase << std::hex << std::setw(width) << std::setfill('0')
        << static_cast<unsigned long long>(value);
    return oss.str();
}

[[nodiscard]] inline std::string HexAddress(u64 value) { return HexValue(value, 16); }

[[nodiscard]] inline std::string HexOptional(const std::optional<u64>& value) {
    return value ? HexAddress(*value) : std::string{"<null>"};
}

[[nodiscard]] inline std::string Trim(std::string text) {
    const auto first = text.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const auto last = text.find_last_not_of(" \t\r\n");
    return text.substr(first, last - first + 1);
}

[[nodiscard]] inline std::vector<std::string> SplitTab(const std::string& line) {
    std::vector<std::string> out;
    std::string current;
    for (char ch : line) {
        if (ch == '\t' || ch == '\n' || ch == '\r') {
            out.push_back(current);
            current.clear();
            continue;
        }
        current.push_back(ch);
    }
    out.push_back(current);
    return out;
}

[[nodiscard]] inline std::optional<u64> ParseU64(const std::string& text) {
    const auto trimmed = Trim(text);
    if (trimmed.empty()) return std::nullopt;
    int base = 10;
    if (trimmed.rfind("0x", 0) == 0 || trimmed.rfind("0X", 0) == 0
        || trimmed.find_first_of("abcdefABCDEF") != std::string::npos) {
        base = 16;
    }
    try {
        std::size_t consumed = 0;
        const auto value = std::stoull(trimmed, &consumed, base);
        if (consumed != trimmed.size()) return std::nullopt;
        return static_cast<u64>(value);
    } catch (...) {
        return std::nullopt;
    }
}

[[nodiscard]] inline std::optional<u32> ParseU32(const std::string& text) {
    const auto value = ParseU64(text);
    if (!value || *value > std::numeric_limits<u32>::max()) return std::nullopt;
    return static_cast<u32>(*value);
}

[[nodiscard]] inline std::optional<i64> ParseI64(const std::string& text) {
    const auto trimmed = Trim(text);
    if (trimmed.empty()) return std::nullopt;
    int base = 10;
    bool negative = false;
    std::string digits = trimmed;
    if (!digits.empty() && (digits.front() == '+' || digits.front() == '-')) {
        negative = digits.front() == '-';
        digits = digits.substr(1);
    }
    if (digits.rfind("0x", 0) == 0 || digits.rfind("0X", 0) == 0
        || digits.find_first_of("abcdefABCDEF") != std::string::npos) {
        base = 16;
    }
    try {
        std::size_t consumed = 0;
        const auto value = std::stoll(digits, &consumed, base);
        if (consumed != digits.size()) return std::nullopt;
        return negative ? -value : value;
    } catch (...) {
        return std::nullopt;
    }
}

[[nodiscard]] inline std::optional<f64> ParseF64(const std::string& text) {
    const auto trimmed = Trim(text);
    if (trimmed.empty()) return std::nullopt;
    try {
        std::size_t consumed = 0;
        const auto value = std::stod(trimmed, &consumed);
        if (consumed != trimmed.size()) return std::nullopt;
        return value;
    } catch (...) {
        return std::nullopt;
    }
}

[[nodiscard]] inline std::string EscapeJsonString(const std::string& src) {
    std::ostringstream oss;
    for (unsigned char ch : src) {
        switch (ch) {
        case '\\': oss << "\\\\"; break;
        case '"':  oss << "\\\""; break;
        case '\n': oss << "\\n";  break;
        case '\r': oss << "\\r";  break;
        case '\t': oss << "\\t";  break;
        default:
            if (ch < 0x20) {
                oss << "\\u" << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
                    << static_cast<unsigned int>(ch);
            } else {
                oss << static_cast<char>(ch);
            }
        }
    }
    return oss.str();
}

[[nodiscard]] inline std::string JsonResponse(bool ok, std::string_view command, const std::string& text) {
    std::ostringstream oss;
    oss << "{\"ok\":" << (ok ? "true" : "false")
        << ",\"command\":\"" << EscapeJsonString(std::string{command}) << "\""
        << ",\"text\":\"" << EscapeJsonString(text) << "\"}";
    return oss.str();
}

// ---- AOB parser (CE-compatible: hex pairs + ? / ?? wildcards) ----
struct AobByte { u8 value{}; bool wildcard{}; };

[[nodiscard]] inline std::vector<AobByte> ParseAob(const std::string& text) {
    std::vector<AobByte> out;
    std::size_t i = 0;
    while (i < text.size()) {
        while (i < text.size() && std::isspace(static_cast<unsigned char>(text[i]))) ++i;
        if (i >= text.size()) break;
        if (text[i] == '?') {
            out.push_back(AobByte{.wildcard = true});
            ++i;
            if (i < text.size() && text[i] == '?') ++i;
            continue;
        }
        if (i + 1 >= text.size()) return {};
        auto hex_val = [](char ch) -> int {
            if (ch >= '0' && ch <= '9') return ch - '0';
            if (ch >= 'a' && ch <= 'f') return 10 + (ch - 'a');
            if (ch >= 'A' && ch <= 'F') return 10 + (ch - 'A');
            return -1;
        };
        const int hi = hex_val(text[i]);
        const int lo = hex_val(text[i + 1]);
        if (hi < 0 || lo < 0) return {};
        out.push_back(AobByte{.value = static_cast<u8>((hi << 4) | lo)});
        i += 2;
    }
    return out;
}

[[nodiscard]] inline std::string ProtectName(unsigned long protect) {
    const unsigned long base = protect & 0xFFu;
    std::string name;
    switch (base) {
    case 0x01: name = "NA";  break; // PAGE_NOACCESS
    case 0x02: name = "R";   break; // PAGE_READONLY
    case 0x04: name = "RW";  break; // PAGE_READWRITE
    case 0x08: name = "WC";  break; // PAGE_WRITECOPY
    case 0x10: name = "X";   break; // PAGE_EXECUTE
    case 0x20: name = "RX";  break; // PAGE_EXECUTE_READ
    case 0x40: name = "RWX"; break; // PAGE_EXECUTE_READWRITE
    case 0x80: name = "XWC"; break; // PAGE_EXECUTE_WRITECOPY
    default:   name = HexValue(static_cast<unsigned>(base), 2); break;
    }
    if ((protect & 0x100u) != 0) name += "+G"; // PAGE_GUARD
    return name;
}

} // namespace inspector
