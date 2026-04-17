# inspector

注入到任意 64 位 Windows 进程的通用运行时调试工具。DLL 在目标进程内启动一个
loopback TCP 服务（`127.0.0.1:37651`），通过一个 tab-separated line 协议对外
暴露 Cheat Engine 风格的调试能力；MCP 桥则把这些能力转成 50 个 Claude tools。

---

## 1. 概述

| 层           | 位置                          | 职责                                                         |
| ------------ | ----------------------------- | ------------------------------------------------------------ |
| `inspector.dll` | `inspector/dll/`          | 在目标进程内执行所有内存 / 扫描 / 反汇编 / 结构操作，暴露 TCP 37651 |
| `server.py`  | `inspector/mcp/`              | MCP stdio 桥，把 JSON-RPC 的 `tools/call` 翻译成 TCP 命令     |
| Zydis        | `inspector/dll/thirdparty/`   | 静态内嵌的 x86-64 反汇编器                                    |
| 参考         | `reference/cheat-engine/`     | CE 源码本地副本，仅作语义对照，不参与构建                      |

设计原则：
- **零项目耦合**：DLL / MCP 都不依赖任何特定游戏结构。
- **有状态**：扫描会话、snapshot、watcher、structure 定义在 DLL 里常驻，MCP 调用不会在中途重建。
- **协议极简**：每次请求一行 tab 分隔的文本，响应一个 JSON envelope `{ok, command, text}`。

---

## 2. 目录结构

```
inspector/
├── README.md                      # 本文
├── dll/
│   ├── CMakeLists.txt
│   ├── toolchain-mingw-w64.cmake
│   ├── include/inspector/
│   │   ├── types.hpp              # u8..f64 基础类型
│   │   ├── formatting.hpp         # 解析 / hex / JSON 小工具
│   │   ├── memory_view.hpp        # SEH 保护的本地内存读
│   │   ├── service_util.hpp       # 区域枚举 / PE 解析
│   │   ├── service.hpp            # Service 公共 API
│   │   └── server.hpp
│   ├── src/
│   │   ├── dllmain.cpp / server.cpp
│   │   ├── service.cpp            # 分发 + watcher 线程
│   │   ├── service_memory.cpp     # 内存读写 / patch / hexview / pointer_chain
│   │   ├── service_scan.cpp       # 所有 scan_* / find_code_refs / pointer_path
│   │   ├── service_snapshot.cpp   # snapshot_*
│   │   ├── service_watch.cpp      # watch_* + event 队列
│   │   ├── service_dissect.cpp    # dissect / compare / compare_many / infer
│   │   ├── service_struct.cpp     # CE structure 会话
│   │   ├── service_module.cpp     # modules / module_info / resolve_symbol
│   │   ├── service_disasm.cpp     # Zydis 反汇编
│   │   └── service_thread.cpp     # thread_list / thread_context
│   └── thirdparty/zydis/
└── mcp/
    └── server.py
```

---

## 3. 编译

依赖：MinGW-w64（`brew install mingw-w64`）+ CMake ≥ 3.24。

```bash
cd inspector/dll
mkdir build && cd build
cmake -DCMAKE_TOOLCHAIN_FILE=../toolchain-mingw-w64.cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . --parallel
# 产物: build/inspector.dll  (约 15 MB，静态链接 Zydis/Zycore/libstdc++)
```

> 在 Windows 本地直接用 MSVC 也可以；CMakeLists 在 MSVC 下会启用 `/W4 /permissive- /utf-8`。

---

## 4. 注入与启动

1. 把 `inspector.dll` 注入目标进程（手动注入器 / DLL injector / LoadLibrary 均可）。
2. `DllMain` → `DLL_PROCESS_ATTACH` 会：
   - 调 `AllocConsole()` 拉一个控制台窗口用于日志；
   - 绑定 `127.0.0.1:37651` + 启动 accept 线程；
   - 启动 20 Hz 的 watcher 轮询线程。
3. 控制台里看到：

   ```
   inspector (generic memory / CE-style debug)
   pid         = ...
   host module = 0x00007FF7...
   wire port   = 127.0.0.1:37651
   [inspector] server started
   ```

   就可以从 MCP 端发命令了。

4. 卸载时 `DLL_PROCESS_DETACH` 会停 accept 线程 + watcher 线程并释放 socket。

> 远程联通：DLL 是 `bind(INADDR_ANY, 37651)`，如果 MCP 和游戏不在同一台机器，把
> 端口穿透出来（或走 SSH 转发 / 内网直连）即可。**这是开发工具，别暴露给非可信网络。**

---

## 5. MCP 配置

### 5.1 本仓库已写好的 `.mcp.json`

```json
{
  "mcpServers": {
    "inspector": {
      "command": "python3",
      "args": [
        "/绝对路径/inspector/mcp/server.py"
      ],
      "env": {
        "INSPECTOR_HOST": "127.0.0.1",
        "INSPECTOR_PORT": "37651"
      }
    }
  }
}
```

- 名称 `inspector` 决定了 Claude 里看到的工具前缀：
  `mcp__inspector__inspector_process_info` 等。
- `INSPECTOR_HOST` / `INSPECTOR_PORT` 可选；默认 `127.0.0.1:37651`。
- 远程机器把 `INSPECTOR_HOST` 改成游戏机的 IP 即可。

### 5.2 Claude Code

- 项目级配置：直接把 `.mcp.json` 放到仓库根目录（本仓已经有了）。
- 用户级配置：放 `~/.claude/mcp.json`，内容同上。
- 首次注册需要重启一次 Claude，让工具 schema 被加载进 tool list。

### 5.3 Cursor / 其它 MCP 客户端

同样的 JSON 片段塞进该客户端的 MCP 注册文件（具体路径参考各客户端文档）。

### 5.4 验证

不开游戏也可以先烟雾测试 MCP 桥本身：

```bash
printf '{"jsonrpc":"2.0","id":1,"method":"initialize"}\n{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n' \
  | python3 inspector/mcp/server.py
```

应该看到 `serverInfo` 与 50 条工具列表。

---

## 6. 协议

- 端口：`37651/TCP`。
- 请求：一行 `\t` 分隔的文本，以 `\n` 结束。
  示例：`read\t0x7FF712345000\t256\thex\n`
- 响应：`{"ok":bool,"command":str,"text":str}` 后跟 `\n`。
  - `ok=false` 时 `text` 是错误原因（如 `"bad args"`、`"read failed"`）。
  - `text` 里直接是人类可读的报告，MCP 会原样透传给 Claude。
- 每个连接只处理一次请求-响应就关闭，便于客户端做超时。

---

## 7. 工具全表

工具名都带 `inspector_` 前缀。分组列出：

### 7.1 进程 / 模块

| 工具 | 作用 |
| --- | --- |
| `process_info` | 宿主 PID、主模块基址、完整路径、watcher 轮询周期 |
| `modules` | 枚举所有已加载模块（base/size/entry/basename） |
| `module_info` | 单模块 PE 布局：入口、完整路径、所有 section（name/addr/size/characteristics） |
| `resolve_symbol` | `GetProcAddress(module, symbol)` 查导出符号 |

### 7.2 内存原语

| 工具 | 作用 |
| --- | --- |
| `memory_regions` | 提交态的内存段列表，支持 `filter=readable/writable/executable` |
| `memory_read` | 按 `hex/ascii/u32/u64/f32/f64` 格式读取原始字节 |
| `memory_write` | 直接写（要求目标页本身可写） |
| `patch` | 自动 `VirtualProtect → RWX → 写 → 还原旧权限` 的安全改码 |
| `nop` | 把一段地址填成 `0x90`，自动切权限 |
| `pointer_chain` | `base + offsets` 走链，`[off]` 语法表示先加后解引用；可选输出终点附近的 hexdump |

### 7.3 内存视图（CE MemoryView 等价）

| 工具 | 作用 |
| --- | --- |
| `hexview` | 按自定义 `cell_type` 渲染表格：`hex8/16/32/64`、`u8..u64`、`i8..i64`、`f32`、`f64`、`ascii`、`utf16`；`row_width` 控字节宽度；可选 ASCII 侧栏 |

示例：

```
inspector_hexview  address=0x7FF712340000  size=64  cell_type=f32  row_width=16
```

### 7.4 扫描（CE first/next 流）

| 工具 | 作用 |
| --- | --- |
| `scan_value` | 首扫：`type=u8..f64`、`op===/!=/>/</>=/<=/between/unknown` |
| `scan_next` | 精炼：`changed/unchanged/increased/decreased/==/!=/…/between` |
| `scan_aob` | 全局可读段里的 AOB（支持 `?`/`??` 通配） |
| `scan_aob_in_module` | 限定模块 + 可选 section 的 AOB，比全局快得多 |
| `scan_pointer` | 找指向 `target ± max_delta` 的对齐 qword |
| `scan_string` | ASCII / UTF-16LE，支持 `case_insensitive` |
| `scan_status` / `scan_peek` / `scan_clear` | 会话状态 / 分页查看 / 清空 |

### 7.5 逆向辅助

| 工具 | 作用 |
| --- | --- |
| `find_code_refs` | 宿主 `.text` 内查 RIP 相对 `call/jmp/lea/mov/cmp` 指向 target 的位置 |
| `pointer_path` | 反向指针链搜索：自 target 逐级找 `[target-max_offset, target]` 的指针槽，最多 `depth=6` 层 |

### 7.6 结构 Dissect（ReClass 风格）

| 工具 | 作用 |
| --- | --- |
| `dissect` | 单地址按 step 扫描：每槽给 u64/u32/f32 + ASCII + 指针提示 |
| `compare` | 两地址 slot-by-slot diff |
| `compare_many` | 多地址（CSV）同步 diff |
| `infer` | 单块粗糙猜类型（ptr / f32 / u32 / qword） |

### 7.7 Snapshot

| 工具 | 作用 |
| --- | --- |
| `snapshot_take` | 捕获命名快照 |
| `snapshot_diff` | 当前 vs 快照按字节差异 |
| `snapshot_list` / `snapshot_clear` | 列表 / 清空 |

### 7.8 Watcher（长轮询）

| 工具 | 作用 |
| --- | --- |
| `watch_add` | 注册监控；类型：`u8..u64 / i8..i64 / f32 / f64 / vec3 / bytes:N`，`eps` 做浮点抑抖 |
| `watch_remove` / `watch_list` / `watch_clear` | 常规管理 |
| `watch_events` | 长轮询事件环：`since_seq` 控起点，`max_wait_ms>0` 阻塞直到新事件或超时 |

### 7.9 CE Structure 会话

CE 的 Dissect Data/Structures 功能的线协议版本。字段类型完全对齐 CE 的
`TVariableType`：

| kind 别名 | CE Vartype | 默认宽度 |
| --- | --- | --- |
| `byte` / `u8` / `vt0` | vtByte | 1 |
| `word` / `u16` / `vt1` | vtWord | 2 |
| `dword` / `u32` / `vt2` | vtDword | 4 |
| `qword` / `u64` / `vt3` | vtQword | 8 |
| `single` / `f32` / `vt4` | vtSingle | 4 |
| `double` / `f64` / `vt5` | vtDouble | 8 |
| `string` / `ascii` / `vt6` | vtString | 可变（`bytesize`） |
| `unicodestring` / `utf16` / `wstring` / `vt7` | vtUnicodeString | 可变 |
| `bytearray` / `bytes` / `vt8` | vtByteArray | 可变 |
| `binary` / `vt9` | vtBinary | 可变 |
| `pointer` / `ptr` / `vt12` | vtPointer | 8 |

| 工具 | 作用 |
| --- | --- |
| `struct_define` | 创建 / 重置命名结构（`default_hex`） |
| `struct_delete` / `struct_list` / `struct_show` | 管理与查看 |
| `struct_add_field` | 追加字段，可选 `child_struct` + `child_start` 让指针字段自动展开 |
| `struct_remove_field` / `struct_edit_field` | 按 index 删改；`edit_field` 的 `delta` 用 `name=.. offset=.. kind=.. hex=.. child=.. child_start=..` 语法 |
| `struct_apply` | 多地址并排渲染 + 嵌套展开（等价 CE 多实例对比视图） |
| `struct_guess` | 自动推测（遍历 8 字节槽：ptr→pointer、正常浮点→single、其余→dword/qword） |
| `struct_save_xml` / `struct_load_xml` | CE 兼容 XML 往返；可直接丢进 Cheat Engine 的 Save/Load structure |

典型流程：

```
struct_define name=Player default_hex=false
struct_add_field name=Player offset=0x10 kind=pointer field_name=pActor
struct_add_field name=Player offset=0x40 kind=single field_name=hp
struct_add_field name=Player offset=0x44 kind=single field_name=hpMax
struct_apply name=Player addresses=0x1B6160F9BD8,0x1B6B0DB4B48 depth=1
struct_save_xml
```

### 7.10 反汇编

| 工具 | 作用 |
| --- | --- |
| `disasm` | 从 `address` 反汇编 `count` 条（Zydis，Intel 语法） |
| `disasm_range` | 反汇编 `[lo, hi)`，最大 0x1000 |

### 7.11 线程

| 工具 | 作用 |
| --- | --- |
| `thread_list` | 宿主进程所有线程（tid, 基础优先级） |
| `thread_context` | 挂起指定线程，读 RIP/RSP/GPR/DR0..DR7，再恢复 |

---

## 8. 典型流程

### 8.1 找一个浮点血量

```
scan_value  type=f32 op=between value1=99.0 value2=101.0
# 让游戏里角色掉血到 50
scan_next   op=decreased
scan_next   op=between value1=49.0 value2=51.0
scan_peek   offset=0 count=32
```

### 8.2 patch 一段代码

```
scan_aob_in_module module= pattern="E8 ? ? ? ? 48 8B 5C 24 ? 48 83 C4 20"
# 记录命中地址 A
disasm      address=A count=4
patch       address=A hex_bytes="90 90 90 90 90"
disasm      address=A count=4         # 确认 NOP 生效
```

### 8.3 监控坐标抖动

```
watch_add   name=pos   address=0x...1F0  type=vec3 eps=0.01
watch_events since_seq=0 max_wait_ms=2000 max_events=32
```

### 8.4 结构对齐 + 导出给 CE

```
struct_define name=Hero default_hex=1
struct_guess  name=Hero base=0x1B6...  size=0x200 overwrite=1
struct_apply  name=Hero addresses=0x1B6...,0x1B7...  depth=2
struct_save_xml     # 把返回的 XML 粘到 CE Load structure
```

---

## 9. 限制 / 注意事项

- **只调试 64 位**。Zydis 的模式固定在 `LONG_64`；thread_context 只打印 x64 寄存器。
- 全局扫描会读大段已提交页，几秒到几十秒都可能；MCP 桥把单次请求超时设为 300 s。
- DLL 被注入的进程退出后会卡住 accept 线程的阻塞 recv — 正常卸载 DLL（`FreeLibrary` / 进程退出）会触发 `DLL_PROCESS_DETACH`，stop 干净。
- `patch/nop` 会自动 `FlushInstructionCache`，但不会 hook 反作弊信号；别往有完整性校验的段写东西。
- 结构定义只在 DLL 进程内内存；宿主进程一关就丢。需要持久化请用 `struct_save_xml` 落盘。

---

## 10. 版本

- inspector.dll：`1.0.0`
- MCP serverInfo：`inspector-mcp / 1.0.0`
- Zydis：v4.1.0（vendored）
- 依赖的 CE 语义参照：上游 `cheat-engine/cheat-engine`（仅参考，不构建）
