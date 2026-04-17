#include "inspector/service.hpp"

#include <algorithm>
#include <sstream>
#include <vector>

#include <Zydis/Zydis.h>

#include "inspector/formatting.hpp"

namespace inspector {

namespace {

[[nodiscard]] std::string FormatOneInstruction(ZydisDecoder& decoder, ZydisFormatter& formatter,
                                                  u64 runtime_addr, const u8* buffer, std::size_t max_len) {
    ZydisDecodedInstruction ins;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    const ZyanStatus st = ZydisDecoderDecodeFull(&decoder, buffer, max_len, &ins, ops);
    if (!ZYAN_SUCCESS(st)) return {};

    char text[256];
    ZydisFormatterFormatInstruction(&formatter, &ins, ops, ins.operand_count_visible,
                                     text, sizeof(text), runtime_addr, ZYAN_NULL);

    std::ostringstream oss;
    oss << HexAddress(runtime_addr) << "  ";
    for (u8 i = 0; i < ins.length; ++i) {
        oss << HexValue(buffer[i], 2);
    }
    for (u8 i = ins.length; i < 10; ++i) oss << "  ";
    oss << "  " << text;
    return oss.str();
}

} // namespace

std::string Service::Disasm(u64 address, u32 instruction_count, u32 max_bytes) {
    if (instruction_count == 0 || instruction_count > 2048) return "count out of range\n";

    // Read a reasonable buffer — 15 bytes per instruction is the x86-64 max.
    const u32 buf_size = std::min<u32>(
        max_bytes == 0 ? instruction_count * 16u : max_bytes, 0x4000);
    std::vector<u8> buf(buf_size, 0);
    if (!memory_.ReadRaw(address, buf.data(), buf.size())) return "read failed\n";

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisFormatter fmt;
    ZydisFormatterInit(&fmt, ZYDIS_FORMATTER_STYLE_INTEL);

    std::ostringstream oss;
    oss << "[Disasm] addr=" << HexAddress(address)
        << " count=" << instruction_count
        << " bytes_read=" << buf_size << "\n";

    std::size_t offset = 0;
    u32 emitted = 0;
    while (emitted < instruction_count && offset < buf.size()) {
        ZydisDecodedInstruction ins;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        const ZyanStatus st = ZydisDecoderDecodeFull(&decoder, buf.data() + offset,
                                                         buf.size() - offset, &ins, ops);
        if (!ZYAN_SUCCESS(st)) {
            oss << HexAddress(address + offset) << "  " << HexValue(buf[offset], 2)
                << "  <decode_fail>\n";
            ++offset;
            continue;
        }
        char text[256];
        ZydisFormatterFormatInstruction(&fmt, &ins, ops, ins.operand_count_visible,
                                         text, sizeof(text), address + offset, ZYAN_NULL);
        oss << HexAddress(address + offset) << "  ";
        for (u8 i = 0; i < ins.length; ++i) oss << HexValue(buf[offset + i], 2);
        for (u8 i = ins.length; i < 10; ++i) oss << "  ";
        oss << "  " << text << "\n";
        offset += ins.length;
        ++emitted;
    }
    return oss.str();
}

std::string Service::DisasmRange(u64 lo, u64 hi) {
    if (hi <= lo) return "bad range\n";
    const u64 span = hi - lo;
    if (span > 0x1000) return "range too large (max 0x1000)\n";
    return Disasm(lo, static_cast<u32>(span) / 3 + 1, static_cast<u32>(span));
}

} // namespace inspector
