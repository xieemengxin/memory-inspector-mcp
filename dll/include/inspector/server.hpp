#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>

#include <atomic>

namespace inspector {

class Server {
public:
    Server();
    ~Server();
    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    bool Start();
    void Stop();

private:
    static DWORD WINAPI ThreadProc(LPVOID);
    void Run();

    std::atomic<bool> running_{false};
    HANDLE thread_{};
};

} // namespace inspector
