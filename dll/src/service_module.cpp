#include "inspector/service.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <psapi.h>

#include <sstream>
#include <string>
#include <vector>

#include "inspector/formatting.hpp"
#include "inspector/service_util.hpp"

#pragma comment(lib, "psapi.lib")

namespace inspector {

namespace {

[[nodiscard]] std::string WideToUtf8(const wchar_t* w) {
    if (!w) return {};
    int n = ::WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(static_cast<std::size_t>(n - 1), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w, -1, out.data(), n, nullptr, nullptr);
    return out;
}

[[nodiscard]] std::string ModuleBasename(const std::string& path) {
    auto pos = path.find_last_of("\\/");
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

} // namespace

std::string Service::Modules() {
    HANDLE proc = ::GetCurrentProcess();
    std::vector<HMODULE> modules(512);
    DWORD needed = 0;
    if (!::EnumProcessModules(proc, modules.data(),
                                 static_cast<DWORD>(modules.size() * sizeof(HMODULE)), &needed)) {
        return "EnumProcessModules failed\n";
    }
    const auto count = std::min<std::size_t>(modules.size(), needed / sizeof(HMODULE));
    std::ostringstream oss;
    oss << "[Modules] count=" << count << "\n";
    for (std::size_t i = 0; i < count; ++i) {
        MODULEINFO mi{};
        if (!::GetModuleInformation(proc, modules[i], &mi, sizeof(mi))) continue;
        wchar_t path_w[MAX_PATH]{};
        ::GetModuleFileNameExW(proc, modules[i], path_w, MAX_PATH);
        const auto path = WideToUtf8(path_w);
        const auto name = ModuleBasename(path);
        oss << HexAddress(reinterpret_cast<u64>(mi.lpBaseOfDll))
            << " size=" << HexValue(mi.SizeOfImage, 8)
            << " entry=" << HexAddress(reinterpret_cast<u64>(mi.EntryPoint))
            << " " << name << "\n";
    }
    return oss.str();
}

std::string Service::ModuleInfo(const std::string& name) {
    HMODULE mod = ::GetModuleHandleA(name.empty() ? nullptr : name.c_str());
    if (!mod) return "module not found\n";
    const u64 base = reinterpret_cast<u64>(mod);
    const auto image = detail::ReadImageInfo(memory_, base);
    if (!image) return "image info unavailable\n";

    MODULEINFO mi{};
    ::GetModuleInformation(::GetCurrentProcess(), mod, &mi, sizeof(mi));
    wchar_t path_w[MAX_PATH]{};
    ::GetModuleFileNameW(mod, path_w, MAX_PATH);

    std::ostringstream oss;
    oss << "[ModuleInfo] " << (name.empty() ? "<host>" : name) << "\n";
    oss << "base=" << HexAddress(base) << "\n";
    oss << "size=" << HexValue(image->size_of_image, 8) << "\n";
    oss << "entry=" << HexAddress(reinterpret_cast<u64>(mi.EntryPoint)) << "\n";
    oss << "path=" << WideToUtf8(path_w) << "\n";
    oss << "sections=" << image->sections.size() << "\n";
    for (const auto& s : image->sections) {
        oss << "  " << s.name
            << " addr=" << HexAddress(s.address)
            << " size=" << HexValue(s.size, 8)
            << " chars=" << HexValue(s.characteristics, 8) << "\n";
    }
    return oss.str();
}

std::string Service::ResolveSymbol(const std::string& module_name, const std::string& symbol) {
    HMODULE mod = ::GetModuleHandleA(module_name.empty() ? nullptr : module_name.c_str());
    if (!mod) return "module not found\n";
    FARPROC p = ::GetProcAddress(mod, symbol.c_str());
    std::ostringstream oss;
    oss << "[ResolveSymbol] module=" << (module_name.empty() ? "<host>" : module_name)
        << " symbol=" << symbol << "\n";
    if (!p) oss << "address=<null>\n";
    else    oss << "address=" << HexAddress(reinterpret_cast<u64>(p)) << "\n";
    return oss.str();
}

} // namespace inspector
