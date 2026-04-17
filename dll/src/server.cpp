#include "inspector/server.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <array>
#include <string>

#include "inspector/service.hpp"

#pragma comment(lib, "ws2_32.lib")

namespace inspector {

namespace {
constexpr unsigned short kInspectorPort = 37651;
}

Server::Server() = default;
Server::~Server() { Stop(); }

bool Server::Start() {
    bool expected = false;
    if (!running_.compare_exchange_strong(expected, true)) return true;
    thread_ = ::CreateThread(nullptr, 0, &Server::ThreadProc, this, 0, nullptr);
    if (!thread_) { running_.store(false); return false; }
    return true;
}

void Server::Stop() {
    if (!running_.exchange(false)) return;
    if (thread_) {
        ::WaitForSingleObject(thread_, 1500);
        ::CloseHandle(thread_);
        thread_ = nullptr;
    }
}

DWORD WINAPI Server::ThreadProc(LPVOID p) {
    auto* self = static_cast<Server*>(p);
    if (self) self->Run();
    return 0;
}

void Server::Run() {
    WSADATA wsa{};
    if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        running_.store(false); return;
    }

    SOCKET listen_s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_s == INVALID_SOCKET) { ::WSACleanup(); running_.store(false); return; }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(kInspectorPort);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    BOOL reuse = TRUE;
    ::setsockopt(listen_s, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));

    if (::bind(listen_s, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR
        || ::listen(listen_s, 4) == SOCKET_ERROR) {
        ::closesocket(listen_s); ::WSACleanup();
        running_.store(false); return;
    }

    Service service{};
    while (running_.load()) {
        fd_set fds{};
        FD_ZERO(&fds);
        FD_SET(listen_s, &fds);
        timeval tv{1, 0};
        const int ready = ::select(0, &fds, nullptr, nullptr, &tv);
        if (ready <= 0) continue;

        SOCKET client = ::accept(listen_s, nullptr, nullptr);
        if (client == INVALID_SOCKET) continue;

        std::string request;
        std::array<char, 4096> buf{};
        for (;;) {
            const int r = ::recv(client, buf.data(), static_cast<int>(buf.size()), 0);
            if (r <= 0) break;
            request.append(buf.data(), static_cast<std::size_t>(r));
            if (request.find('\n') != std::string::npos) break;
            if (request.size() > 1 << 22) break;
        }

        const auto response = service.HandleCommand(request) + "\n";
        std::size_t sent = 0;
        while (sent < response.size()) {
            const int s = ::send(client, response.data() + sent,
                                    static_cast<int>(response.size() - sent), 0);
            if (s <= 0) break;
            sent += static_cast<std::size_t>(s);
        }
        ::shutdown(client, SD_BOTH);
        ::closesocket(client);
    }

    ::closesocket(listen_s);
    ::WSACleanup();
}

} // namespace inspector
