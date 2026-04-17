#include "inspector/service.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <tlhelp32.h>

#include <sstream>

#include "inspector/formatting.hpp"

namespace inspector {

std::string Service::ThreadList() {
    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return "snapshot failed\n";
    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    std::ostringstream oss;
    oss << "[Threads] pid=" << ::GetCurrentProcessId() << "\n";
    if (::Thread32First(snap, &entry)) {
        do {
            if (entry.th32OwnerProcessID != ::GetCurrentProcessId()) continue;
            oss << "tid=" << entry.th32ThreadID
                << " priority_base=" << entry.tpBasePri
                << "\n";
        } while (::Thread32Next(snap, &entry));
    }
    ::CloseHandle(snap);
    return oss.str();
}

std::string Service::ThreadContext(u32 thread_id) {
    HANDLE th = ::OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                                FALSE, thread_id);
    if (!th) return "OpenThread failed\n";

    if (::SuspendThread(th) == static_cast<DWORD>(-1)) {
        ::CloseHandle(th);
        return "SuspendThread failed\n";
    }
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
    const bool ok = !!::GetThreadContext(th, &ctx);
    ::ResumeThread(th);
    ::CloseHandle(th);

    if (!ok) return "GetThreadContext failed\n";

    std::ostringstream oss;
    oss << "[ThreadContext] tid=" << thread_id << "\n";
#if defined(_M_X64) || defined(__x86_64__)
    oss << "rip=" << HexAddress(ctx.Rip) << "\n";
    oss << "rsp=" << HexAddress(ctx.Rsp) << "\n";
    oss << "rbp=" << HexAddress(ctx.Rbp) << "\n";
    oss << "rax=" << HexAddress(ctx.Rax) << " rbx=" << HexAddress(ctx.Rbx)
        << " rcx=" << HexAddress(ctx.Rcx) << " rdx=" << HexAddress(ctx.Rdx) << "\n";
    oss << "rsi=" << HexAddress(ctx.Rsi) << " rdi=" << HexAddress(ctx.Rdi)
        << " r8=" << HexAddress(ctx.R8) << " r9=" << HexAddress(ctx.R9) << "\n";
    oss << "r10=" << HexAddress(ctx.R10) << " r11=" << HexAddress(ctx.R11)
        << " r12=" << HexAddress(ctx.R12) << " r13=" << HexAddress(ctx.R13) << "\n";
    oss << "r14=" << HexAddress(ctx.R14) << " r15=" << HexAddress(ctx.R15) << "\n";
    oss << "eflags=" << HexValue(ctx.EFlags, 8) << "\n";
    oss << "dr0=" << HexAddress(ctx.Dr0) << " dr1=" << HexAddress(ctx.Dr1)
        << " dr2=" << HexAddress(ctx.Dr2) << " dr3=" << HexAddress(ctx.Dr3) << "\n";
    oss << "dr6=" << HexAddress(ctx.Dr6) << " dr7=" << HexAddress(ctx.Dr7) << "\n";
#else
    oss << "eip=" << HexValue(ctx.Eip, 8) << "\n";
#endif
    return oss.str();
}

} // namespace inspector
