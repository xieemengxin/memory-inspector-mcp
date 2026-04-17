#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>

#include <cstdio>
#include <ios>
#include <iostream>

#include "inspector/server.hpp"

namespace {

inspector::Server g_server{};

void EnsureConsole() {
    if (::GetConsoleWindow() != nullptr) return;
    if (!::AllocConsole()) return;
    ::SetConsoleTitleA("inspector");
    FILE* fp = nullptr;
    fp = std::freopen("CONOUT$", "w", stdout); (void)fp;
    fp = std::freopen("CONOUT$", "w", stderr); (void)fp;
    fp = std::freopen("CONIN$",  "r", stdin);  (void)fp;
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::setvbuf(stderr, nullptr, _IONBF, 0);
    std::ios::sync_with_stdio(true);
    const HANDLE out = ::GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (out != INVALID_HANDLE_VALUE && ::GetConsoleMode(out, &mode)) {
        ::SetConsoleMode(out, mode | 0x0004);
    }
}

void PrintBanner() {
    const auto module = ::GetModuleHandleW(nullptr);
    std::printf("================================================================\n");
    std::printf("  inspector (generic memory / CE-style debug)\n");
    std::printf("  pid         = %lu\n", static_cast<unsigned long>(::GetCurrentProcessId()));
    std::printf("  host module = %p\n", static_cast<void*>(module));
    std::printf("  wire port   = 127.0.0.1:37651\n");
    std::printf("================================================================\n");
    std::fflush(stdout);
}

DWORD WINAPI BootstrapProc(LPVOID) {
    EnsureConsole();
    PrintBanner();
    if (!g_server.Start()) {
        std::fprintf(stderr, "[inspector] server failed to start\n");
        std::fflush(stderr);
        return 1;
    }
    std::printf("[inspector] server started\n");
    std::fflush(stdout);
    return 0;
}

} // namespace

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        ::DisableThreadLibraryCalls(module);
        const HANDLE th = ::CreateThread(nullptr, 0, &BootstrapProc, nullptr, 0, nullptr);
        if (th) ::CloseHandle(th);
    } else if (reason == DLL_PROCESS_DETACH) {
        g_server.Stop();
    }
    return TRUE;
}
