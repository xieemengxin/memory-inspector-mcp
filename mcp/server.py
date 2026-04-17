#!/usr/bin/env python3
"""MCP bridge for the inspector DLL.

The inspector DLL is injected into a target process and exposes a loopback TCP
line protocol on 127.0.0.1:37651. Each request is a tab-separated line; each
response is a JSON object: ``{"ok": bool, "command": str, "text": str}``.

This server provides a Cheat-Engine-style toolbox:

* Memory primitives (regions, read/write, patch-with-VirtualProtect, NOP).
* CE memoryview (typed hex view — 8/16/32/64 bit hex, int, float, ASCII, UTF-16).
* CE scan flow (first-scan, next-scan refine, AOB, pointer, string).
* Reverse-walk helpers (pointer_path, find_code_refs).
* Named snapshots + diff, watchers with long-poll events.
* Structure dissect/compare/infer (ReClass-style).
* CE-style structure sessions with named fields, nested pointer expansion,
  auto-guess, and XML round-trip compatible with Cheat Engine.
* Zydis-backed disassembler (disasm, disasm_range).
* Module / symbol / thread introspection.
"""
from __future__ import annotations

import json
import os
import socket
import sys
from typing import Any, Dict, List

HOST = os.environ.get("INSPECTOR_HOST", "127.0.0.1")
PORT = int(os.environ.get("INSPECTOR_PORT", "37651"))


def _tool(name: str, description: str, properties: Dict[str, Any] | None = None,
          required: List[str] | None = None) -> Dict[str, Any]:
    schema: Dict[str, Any] = {
        "type": "object",
        "properties": properties or {},
        "additionalProperties": False,
    }
    if required:
        schema["required"] = required
    return {"name": name, "description": description, "inputSchema": schema}


ADDR = {"type": "string", "description": "Hex address like 0x7FF7..."}
HEXBYTES = {"type": "string", "description": "Hex bytes, e.g. '90 90 90' or '909090'"}

TOOLS: List[Dict[str, Any]] = [
    # ------------------------------------------------------------------
    # Process / module introspection
    # ------------------------------------------------------------------
    _tool(
        "inspector_process_info",
        "Show pid, host module base, full path, and inspector state.",
    ),
    _tool(
        "inspector_modules",
        "Enumerate all loaded modules with base address, size, entry point, and name.",
    ),
    _tool(
        "inspector_module_info",
        "Dump a module's PE layout: base, size, entry, path, all sections (name / addr / size / characteristics).",
        {"name": {"type": "string", "description": "Module basename (e.g. 'Overwatch.exe'). Empty = host module."}},
    ),
    _tool(
        "inspector_resolve_symbol",
        "Resolve a symbol in a module via GetProcAddress (exported functions).",
        {
            "module": {"type": "string"},
            "symbol": {"type": "string"},
        },
        ["symbol"],
    ),

    # ------------------------------------------------------------------
    # Memory primitives
    # ------------------------------------------------------------------
    _tool(
        "inspector_memory_regions",
        "Enumerate committed memory regions with protect + size.",
        {
            "filter": {"type": "string", "description": "'readable' (default), 'writable', or 'executable'"},
            "max_results": {"type": "integer", "default": 128, "minimum": 1, "maximum": 65535},
        },
    ),
    _tool(
        "inspector_memory_read",
        "Read raw bytes with optional formatting.",
        {
            "address": ADDR,
            "size": {"type": "integer", "default": 256, "minimum": 1, "maximum": 0x4000},
            "format": {"type": "string", "description": "hex (default) | ascii | u32 | u64 | f32 | f64"},
        },
        ["address"],
    ),
    _tool(
        "inspector_memory_write",
        "Write raw bytes. Target must already be on a writable page.",
        {"address": ADDR, "hex_bytes": HEXBYTES},
        ["address", "hex_bytes"],
    ),
    _tool(
        "inspector_patch",
        "Write bytes to any page by flipping protection to RWX for the write and restoring the old protection afterwards. Use for code patches.",
        {"address": ADDR, "hex_bytes": HEXBYTES},
        ["address", "hex_bytes"],
    ),
    _tool(
        "inspector_nop",
        "Write N NOP bytes (0x90) at address, auto-flipping page protection.",
        {"address": ADDR, "size": {"type": "integer", "minimum": 1, "maximum": 0x1000}},
        ["address", "size"],
    ),
    _tool(
        "inspector_pointer_chain",
        "Walk a pointer chain: base + offsets. Wrap an offset in [] to dereference after adding the offset (e.g. '0x10,[0x20],0x8').",
        {
            "base": ADDR,
            "offsets": {"type": "string"},
            "hexdump_bytes": {"type": "integer", "default": 128, "minimum": 16, "maximum": 512},
            "include_hexdump": {"type": "boolean", "default": False},
        },
        ["base", "offsets"],
    ),

    # ------------------------------------------------------------------
    # CE memoryview
    # ------------------------------------------------------------------
    _tool(
        "inspector_hexview",
        "Render memory as a CE-style grid. cell_type chooses how each cell is decoded: hex8/hex16/hex32/hex64, u8..u64, i8..i64, f32, f64, ascii, utf16. row_width is in BYTES; defaults to 16.",
        {
            "address": ADDR,
            "size": {"type": "integer", "minimum": 1, "maximum": 0x4000},
            "cell_type": {"type": "string", "default": "hex8"},
            "row_width": {"type": "integer", "default": 16, "minimum": 1, "maximum": 64},
            "show_ascii": {"type": "boolean", "default": True},
            "show_signed": {"type": "boolean", "default": False},
        },
        ["address", "size"],
    ),

    # ------------------------------------------------------------------
    # Scans
    # ------------------------------------------------------------------
    _tool(
        "inspector_scan_value",
        "First-scan: search all committed readable memory for a typed value. Creates a scan session that next-scan/peek refine.",
        {
            "type": {"type": "string", "description": "u8|u16|u32|u64|i8|i16|i32|i64|f32|f64"},
            "op":   {"type": "string", "description": "== != > < >= <= between unknown"},
            "value1": {"type": "string", "description": "Primary value (decimal or 0x-prefixed)"},
            "value2": {"type": "string", "description": "Secondary value for 'between'"},
            "max_matches": {"type": "integer", "default": 1_000_000, "minimum": 1},
        },
        ["type", "op"],
    ),
    _tool(
        "inspector_scan_next",
        "Refine the active scan session. ops: changed, unchanged, increased, decreased, == != > < >= <= between.",
        {
            "op": {"type": "string"},
            "value1": {"type": "string"},
            "value2": {"type": "string"},
        },
        ["op"],
    ),
    _tool(
        "inspector_scan_aob",
        "Array-of-bytes scan across readable regions. '?' / '??' wildcard supported.",
        {
            "pattern": {"type": "string", "description": "e.g. '48 89 5C 24 ? 55 56'"},
            "max_matches": {"type": "integer", "default": 4096, "minimum": 1},
        },
        ["pattern"],
    ),
    _tool(
        "inspector_scan_aob_in_module",
        "AOB scan restricted to a specific module + optional section (.text etc.). Much faster than global scan.",
        {
            "module":  {"type": "string", "description": "module basename; empty = host module"},
            "section": {"type": "string", "description": "section name (.text, .rdata, ...); empty = all"},
            "pattern": {"type": "string"},
            "max_matches": {"type": "integer", "default": 4096, "minimum": 1},
        },
        ["pattern"],
    ),
    _tool(
        "inspector_scan_pointer",
        "Scan aligned qwords pointing at (or near) a target address.",
        {
            "target": ADDR,
            "max_delta": {"type": "integer", "default": 0x10000, "minimum": 0},
            "max_matches": {"type": "integer", "default": 2048, "minimum": 1},
        },
        ["target"],
    ),
    _tool(
        "inspector_scan_string",
        "Search for an ASCII or UTF-16LE string across readable memory.",
        {
            "text": {"type": "string"},
            "unicode": {"type": "boolean", "default": False},
            "case_insensitive": {"type": "boolean", "default": False},
            "max_matches": {"type": "integer", "default": 2048, "minimum": 1},
        },
        ["text"],
    ),
    _tool("inspector_scan_status",
          "Report active scan session kind + match count."),
    _tool(
        "inspector_scan_peek",
        "List a window of matches from the active scan session.",
        {
            "offset": {"type": "integer", "default": 0, "minimum": 0},
            "count":  {"type": "integer", "default": 32, "minimum": 1, "maximum": 1024},
        },
    ),
    _tool("inspector_scan_clear", "Drop the active scan session."),

    _tool(
        "inspector_find_code_refs",
        "Scan the host module's .text for RIP-relative call/jmp/mov/lea whose target equals the given address. Useful for reverse-walking call sites.",
        {
            "target": ADDR,
            "max_matches": {"type": "integer", "default": 2048, "minimum": 1},
        },
        ["target"],
    ),
    _tool(
        "inspector_pointer_path",
        "Iterative reverse pointer walk. For each level, finds 8-byte slots pointing within [target-max_offset, target] and recurses up to `depth` levels.",
        {
            "target": ADDR,
            "depth":  {"type": "integer", "default": 3, "minimum": 1, "maximum": 6},
            "max_offset":  {"type": "integer", "default": 0x1000, "minimum": 0},
            "max_results": {"type": "integer", "default": 1024, "minimum": 1},
        },
        ["target"],
    ),

    # ------------------------------------------------------------------
    # Dissect / compare / infer
    # ------------------------------------------------------------------
    _tool(
        "inspector_dissect",
        "Dissect a memory block as a struct: per-offset u64/u32/f32 + ASCII + pointer hints.",
        {
            "base": ADDR,
            "size": {"type": "integer", "default": 0x200, "minimum": 8, "maximum": 0x4000},
            "step": {"type": "integer", "default": 8, "minimum": 1, "maximum": 32},
        },
        ["base"],
    ),
    _tool(
        "inspector_compare",
        "Compare two memory blocks slot-by-slot and report differences.",
        {
            "base_a": ADDR,
            "base_b": ADDR,
            "size":   {"type": "integer", "minimum": 1, "maximum": 0x4000},
            "step":   {"type": "integer", "default": 8, "minimum": 1, "maximum": 32},
        },
        ["base_a", "base_b", "size"],
    ),
    _tool(
        "inspector_compare_many",
        "Compare N memory blocks (comma-separated addresses) and report slots that disagree.",
        {
            "addresses": {"type": "string"},
            "size":      {"type": "integer", "minimum": 1, "maximum": 0x4000},
            "step":      {"type": "integer", "default": 8, "minimum": 1, "maximum": 32},
        },
        ["addresses", "size"],
    ),
    _tool(
        "inspector_infer",
        "Best-guess type summary of a memory block.",
        {
            "base": ADDR,
            "size": {"type": "integer", "default": 0x200, "minimum": 8, "maximum": 0x4000},
        },
        ["base"],
    ),

    # ------------------------------------------------------------------
    # Snapshots
    # ------------------------------------------------------------------
    _tool(
        "inspector_snapshot_take",
        "Capture a named snapshot of a memory block.",
        {
            "name": {"type": "string"},
            "base": ADDR,
            "size": {"type": "integer", "minimum": 1, "maximum": 0x100000},
        },
        ["name", "base", "size"],
    ),
    _tool(
        "inspector_snapshot_diff",
        "Diff current bytes against a saved snapshot.",
        {
            "name": {"type": "string"},
            "base": {"type": "string", "description": "optional: diff at a different address"},
            "size": {"type": "integer", "default": 0},
        },
        ["name"],
    ),
    _tool("inspector_snapshot_list", "List saved snapshots with base + size."),
    _tool(
        "inspector_snapshot_clear",
        "Drop a specific snapshot, or all if name is empty.",
        {"name": {"type": "string"}},
    ),

    # ------------------------------------------------------------------
    # Watchers
    # ------------------------------------------------------------------
    _tool(
        "inspector_watch_add",
        "Attach a time-series watcher. Type: u8..u64, i8..i64, f32, f64, vec3, bytes:N.",
        {
            "name": {"type": "string"},
            "address": ADDR,
            "type": {"type": "string"},
            "eps": {"type": "number", "default": 0.0},
        },
        ["name", "address", "type"],
    ),
    _tool("inspector_watch_remove", "Remove a watcher by name.",
          {"name": {"type": "string"}}, ["name"]),
    _tool("inspector_watch_list", "List active watchers."),
    _tool("inspector_watch_clear", "Drop all watchers."),
    _tool(
        "inspector_watch_events",
        "Long-poll the watcher event ring. `since_seq=0` returns everything still in the ring.",
        {
            "since_seq": {"type": "integer", "minimum": 0, "default": 0},
            "max_wait_ms": {"type": "integer", "minimum": 0, "maximum": 60000, "default": 0},
            "max_events":  {"type": "integer", "minimum": 1, "maximum": 512, "default": 64},
        },
    ),

    # ------------------------------------------------------------------
    # CE-style structure sessions
    # ------------------------------------------------------------------
    _tool(
        "inspector_struct_define",
        "Create (or reset) a named structure. Fields are added with struct_add_field.",
        {
            "name": {"type": "string"},
            "default_hex": {"type": "boolean", "default": False},
        },
        ["name"],
    ),
    _tool("inspector_struct_delete", "Delete a named structure.",
          {"name": {"type": "string"}}, ["name"]),
    _tool("inspector_struct_list", "List all defined structures."),
    _tool(
        "inspector_struct_show",
        "Dump a structure's field list (offset, kind, bytesize, display_hex, child).",
        {"name": {"type": "string"}},
        ["name"],
    ),
    _tool(
        "inspector_struct_add_field",
        "Append a field to a structure. kind = byte|word|dword|qword|single|double|string|unicodestring|bytearray|binary|pointer (or u8..f64 aliases).",
        {
            "name":   {"type": "string"},
            "offset": {"type": "integer"},
            "kind":   {"type": "string"},
            "field_name":   {"type": "string", "default": ""},
            "bytesize":     {"type": "integer", "default": 0},
            "display_hex":  {"type": "boolean", "default": False},
            "child_struct": {"type": "string", "default": ""},
            "child_start":  {"type": "integer", "default": 0},
        },
        ["name", "offset", "kind"],
    ),
    _tool(
        "inspector_struct_remove_field",
        "Remove a field by index.",
        {"name": {"type": "string"}, "index": {"type": "integer", "minimum": 0}},
        ["name", "index"],
    ),
    _tool(
        "inspector_struct_edit_field",
        "Edit a field in place. `delta` is space-separated key=value: name, offset, kind, bytesize, hex, child, child_start.",
        {
            "name":  {"type": "string"},
            "index": {"type": "integer", "minimum": 0},
            "delta": {"type": "string"},
        },
        ["name", "index", "delta"],
    ),
    _tool(
        "inspector_struct_apply",
        "Render a structure against one or more base addresses. If multiple addresses are given the output aligns columns (CE's multi-address compare view). `depth` controls nested pointer expansion.",
        {
            "name": {"type": "string"},
            "addresses": {"type": "string", "description": "comma-separated base addresses"},
            "depth": {"type": "integer", "default": 1, "minimum": 1, "maximum": 4},
        },
        ["name", "addresses"],
    ),
    _tool(
        "inspector_struct_guess",
        "Auto-guess a structure's fields from a base address (CE's 'Auto-guess structure'). Overwrite clears existing fields first.",
        {
            "name": {"type": "string"},
            "base": ADDR,
            "size": {"type": "integer", "minimum": 8, "maximum": 0x1000},
            "overwrite": {"type": "boolean", "default": False},
        },
        ["name", "base", "size"],
    ),
    _tool(
        "inspector_struct_save_xml",
        "Export all defined structures as a CE-compatible XML blob (round-trips through Cheat Engine's 'Save structure' dialog).",
    ),
    _tool(
        "inspector_struct_load_xml",
        "Replace the current structure set from a CE-style XML blob.",
        {"xml": {"type": "string"}},
        ["xml"],
    ),

    # ------------------------------------------------------------------
    # Disassembler
    # ------------------------------------------------------------------
    _tool(
        "inspector_disasm",
        "Zydis-backed x86-64 disassembler. Emits `count` instructions starting at `address`.",
        {
            "address": ADDR,
            "count": {"type": "integer", "default": 32, "minimum": 1, "maximum": 2048},
            "max_bytes": {"type": "integer", "default": 0, "description": "cap bytes read; 0 = count*16"},
        },
        ["address"],
    ),
    _tool(
        "inspector_disasm_range",
        "Disassemble all instructions in [lo, hi). Max span 0x1000.",
        {"lo": ADDR, "hi": ADDR},
        ["lo", "hi"],
    ),

    # ------------------------------------------------------------------
    # Threads
    # ------------------------------------------------------------------
    _tool("inspector_thread_list", "Enumerate threads of the host process."),
    _tool(
        "inspector_thread_context",
        "Suspend a thread, read its CPU context (RIP/RSP/GPRs/debug regs), and resume it.",
        {"thread_id": {"type": "integer", "minimum": 1}},
        ["thread_id"],
    ),
]


# ----------------------------------------------------------------------
# Backend transport
# ----------------------------------------------------------------------
def call_backend(command: str) -> str:
    sock = socket.create_connection((HOST, PORT), timeout=5.0)
    try:
        sock.settimeout(300.0)
        sock.sendall((command.rstrip("\n") + "\n").encode("utf-8"))
        chunks: List[bytes] = []
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
    finally:
        sock.close()
    if not chunks:
        raise RuntimeError("no response from inspector backend")
    payload = b"".join(chunks).decode("utf-8", errors="replace").strip()
    obj = json.loads(payload)
    if not obj.get("ok"):
        raise RuntimeError(obj.get("text", "backend error"))
    return obj.get("text", "")


def tab(*parts: Any) -> str:
    return "\t".join("" if p is None else str(p) for p in parts)


def _bool(value: Any) -> int:
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, (int, float)):
        return 1 if value != 0 else 0
    if isinstance(value, str):
        return 1 if value.strip().lower() in ("true", "1", "yes", "on") else 0
    return 0


def dispatch(name: str, args: Dict[str, Any]) -> str:
    if name == "inspector_process_info": return call_backend("process_info")

    if name == "inspector_modules":     return call_backend("modules")
    if name == "inspector_module_info": return call_backend(tab("module_info", args.get("name", "")))
    if name == "inspector_resolve_symbol":
        return call_backend(tab("resolve_symbol", args.get("module", ""), args["symbol"]))

    if name == "inspector_memory_regions":
        return call_backend(tab("regions", args.get("filter", ""), int(args.get("max_results", 128))))
    if name == "inspector_memory_read":
        return call_backend(tab("read", args["address"], int(args.get("size", 256)), args.get("format", "")))
    if name == "inspector_memory_write":
        return call_backend(tab("write", args["address"], args["hex_bytes"]))
    if name == "inspector_patch":
        return call_backend(tab("patch", args["address"], args["hex_bytes"]))
    if name == "inspector_nop":
        return call_backend(tab("nop", args["address"], int(args["size"])))
    if name == "inspector_pointer_chain":
        return call_backend(tab(
            "chain",
            args["base"],
            args["offsets"],
            int(args.get("hexdump_bytes", 128)),
            _bool(args.get("include_hexdump")),
        ))

    if name == "inspector_hexview":
        return call_backend(tab(
            "hexview",
            args["address"],
            int(args["size"]),
            args.get("cell_type", "hex8"),
            int(args.get("row_width", 16)),
            _bool(args.get("show_ascii", True)),
            _bool(args.get("show_signed", False)),
        ))

    if name == "inspector_scan_value":
        return call_backend(tab(
            "scan",
            args["type"], args["op"],
            args.get("value1", ""), args.get("value2", ""),
            int(args.get("max_matches", 1_000_000)),
        ))
    if name == "inspector_scan_next":
        return call_backend(tab("scan_next", args["op"], args.get("value1", ""), args.get("value2", "")))
    if name == "inspector_scan_aob":
        return call_backend(tab("scan_aob", args["pattern"], int(args.get("max_matches", 4096))))
    if name == "inspector_scan_aob_in_module":
        return call_backend(tab(
            "scan_aob_in_module",
            args.get("module", ""), args.get("section", ""),
            args["pattern"], int(args.get("max_matches", 4096)),
        ))
    if name == "inspector_scan_pointer":
        return call_backend(tab(
            "scan_pointer",
            args["target"],
            int(args.get("max_delta", 0x10000)),
            int(args.get("max_matches", 2048)),
        ))
    if name == "inspector_scan_string":
        return call_backend(tab(
            "scan_string",
            args["text"],
            _bool(args.get("unicode", False)),
            _bool(args.get("case_insensitive", False)),
            int(args.get("max_matches", 2048)),
        ))
    if name == "inspector_scan_status": return call_backend("scan_status")
    if name == "inspector_scan_peek":
        return call_backend(tab("scan_peek", int(args.get("offset", 0)), int(args.get("count", 32))))
    if name == "inspector_scan_clear":  return call_backend("scan_clear")

    if name == "inspector_find_code_refs":
        return call_backend(tab("find_code_refs", args["target"], int(args.get("max_matches", 2048))))
    if name == "inspector_pointer_path":
        return call_backend(tab(
            "pointer_path",
            args["target"],
            int(args.get("depth", 3)),
            int(args.get("max_offset", 0x1000)),
            int(args.get("max_results", 1024)),
        ))

    if name == "inspector_dissect":
        return call_backend(tab("dissect", args["base"], int(args.get("size", 0x200)), int(args.get("step", 8))))
    if name == "inspector_compare":
        return call_backend(tab(
            "compare", args["base_a"], args["base_b"],
            int(args["size"]), int(args.get("step", 8)),
        ))
    if name == "inspector_compare_many":
        return call_backend(tab("compare_many", args["addresses"],
                                   int(args["size"]), int(args.get("step", 8))))
    if name == "inspector_infer":
        return call_backend(tab("infer", args["base"], int(args.get("size", 0x200))))

    if name == "inspector_snapshot_take":
        return call_backend(tab("snapshot_take", args["name"], args["base"], int(args["size"])))
    if name == "inspector_snapshot_diff":
        return call_backend(tab("snapshot_diff",
                                  args["name"],
                                  args.get("base", "0"),
                                  int(args.get("size", 0))))
    if name == "inspector_snapshot_list":  return call_backend("snapshot_list")
    if name == "inspector_snapshot_clear": return call_backend(tab("snapshot_clear", args.get("name", "")))

    if name == "inspector_watch_add":
        return call_backend(tab("watch_add", args["name"], args["address"],
                                  args["type"], str(args.get("eps", 0.0))))
    if name == "inspector_watch_remove": return call_backend(tab("watch_remove", args["name"]))
    if name == "inspector_watch_list":   return call_backend("watch_list")
    if name == "inspector_watch_clear":  return call_backend("watch_clear")
    if name == "inspector_watch_events":
        return call_backend(tab(
            "watch_events",
            int(args.get("since_seq", 0)),
            int(args.get("max_wait_ms", 0)),
            int(args.get("max_events", 64)),
        ))

    if name == "inspector_struct_define":
        return call_backend(tab("struct_define", args["name"],
                                  _bool(args.get("default_hex", False))))
    if name == "inspector_struct_delete": return call_backend(tab("struct_delete", args["name"]))
    if name == "inspector_struct_list":   return call_backend("struct_list")
    if name == "inspector_struct_show":   return call_backend(tab("struct_show", args["name"]))
    if name == "inspector_struct_add_field":
        return call_backend(tab(
            "struct_add_field",
            args["name"], int(args["offset"]), args["kind"],
            args.get("field_name", ""),
            int(args.get("bytesize", 0)),
            _bool(args.get("display_hex", False)),
            args.get("child_struct", ""),
            int(args.get("child_start", 0)),
        ))
    if name == "inspector_struct_remove_field":
        return call_backend(tab("struct_remove_field", args["name"], int(args["index"])))
    if name == "inspector_struct_edit_field":
        return call_backend(tab("struct_edit_field", args["name"], int(args["index"]), args["delta"]))
    if name == "inspector_struct_apply":
        return call_backend(tab("struct_apply", args["name"], args["addresses"],
                                  int(args.get("depth", 1))))
    if name == "inspector_struct_guess":
        return call_backend(tab(
            "struct_guess", args["name"], args["base"], int(args["size"]),
            _bool(args.get("overwrite", False)),
        ))
    if name == "inspector_struct_save_xml": return call_backend("struct_save_xml")
    if name == "inspector_struct_load_xml": return call_backend(tab("struct_load_xml", args["xml"]))

    if name == "inspector_disasm":
        return call_backend(tab("disasm", args["address"],
                                  int(args.get("count", 32)), int(args.get("max_bytes", 0))))
    if name == "inspector_disasm_range":
        return call_backend(tab("disasm_range", args["lo"], args["hi"]))

    if name == "inspector_thread_list":    return call_backend("thread_list")
    if name == "inspector_thread_context": return call_backend(tab("thread_context", int(args["thread_id"])))

    raise RuntimeError(f"unknown tool: {name}")


# ----------------------------------------------------------------------
# MCP stdio loop
# ----------------------------------------------------------------------
def send(msg: Dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(msg, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def tool_result(request_id: Any, text: str) -> None:
    send({
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {"content": [{"type": "text", "text": text}], "isError": False},
    })


def tool_error(request_id: Any, text: str) -> None:
    send({
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {"content": [{"type": "text", "text": text}], "isError": True},
    })


def main() -> int:
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except Exception as exc:
            send({"jsonrpc": "2.0", "id": None,
                  "error": {"code": -32700, "message": f"parse error: {exc}"}})
            continue

        method = msg.get("method")
        request_id = msg.get("id")

        if method == "initialize":
            send({
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "inspector-mcp", "version": "1.0.0"},
                },
            })
            continue

        if method == "notifications/initialized":
            continue

        if method == "tools/list":
            send({"jsonrpc": "2.0", "id": request_id, "result": {"tools": TOOLS}})
            continue

        if method == "tools/call":
            params = msg.get("params", {})
            name = params.get("name")
            args = params.get("arguments", {}) or {}
            try:
                result = dispatch(name, args)
                tool_result(request_id, result)
            except Exception as exc:
                tool_error(request_id, f"tool call failed: {exc}")
            continue

        send({"jsonrpc": "2.0", "id": request_id,
              "error": {"code": -32601, "message": f"method not found: {method}"}})

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
