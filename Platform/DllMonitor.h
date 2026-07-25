#pragma once
#include <windows.h>
#include <string.h>
#include <functional>
#include <thread>
#include <atomic>
#include <string>


struct DllEvent {
    std::string  Category;
    DWORD        ProcessId;
    DWORD        ThreadId;
    ULONGLONG    Timestamp;
};


#define DLL_PIPE_NAME        L"\\\\.\\pipe\\ApiMonitorPipe"
#define DLL_PIPE_BUFFER_SIZE 4096

class DllMonitor {
public:
    using Callback = std::function<void(const DllEvent&)>;

    DllMonitor()
        : M_Pipe(INVALID_HANDLE_VALUE), M_Running(false), M_Ready(false), M_CreateFailed(false) {}
    ~DllMonitor() { Stop(); }

    DllMonitor(const DllMonitor&) = delete;
    DllMonitor& operator=(const DllMonitor&) = delete;

    void SetCallback(Callback Cb) { M_Callback = std::move(Cb); }

    bool Start() {
        if (M_Running) return true;
        M_Ready = false;
        M_CreateFailed = false;
        M_Running = true;
        M_Thread = std::thread(&DllMonitor::PipeLoop, this);

        
        
        for (int I = 0; I < 40 && !M_Ready; ++I) Sleep(25);
        if (!M_Ready || M_CreateFailed) {
            Stop();
            return false;
        }
        return true;
    }

    void Stop() {
        const bool WasRunning = M_Running.exchange(false);
        if (WasRunning) {
            if (M_Pipe != INVALID_HANDLE_VALUE) {
                CancelIoEx(M_Pipe, nullptr);
                DisconnectNamedPipe(M_Pipe);
            }
            if (M_Thread.joinable()) {
                CancelSynchronousIo(M_Thread.native_handle());
            }
            HANDLE WakePipe = CreateFileW(DLL_PIPE_NAME, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (WakePipe != INVALID_HANDLE_VALUE) CloseHandle(WakePipe);
        }
        if (M_Thread.joinable()) M_Thread.join();
    }

    bool IsRunning() const { return M_Running; }

private:
    static DllEvent ParseEvent(const char* Json) {
        DllEvent Evt = {};
        auto FindValue = [&](const char* Key) -> const char* {
            const char* Found = strstr(Json, Key);
            if (!Found) return nullptr;
            Found = strchr(Found, ':');
            if (!Found) return nullptr;
            ++Found;
            while (*Found == ' ' || *Found == '\t') ++Found;
            return Found;
        };
        auto ReadString = [&](const char* Key) -> std::string {
            const char* P = FindValue(Key);
            if (!P || *P != '"') return {};
            ++P;
            std::string Value;
            while (*P && *P != '"') {
                if (*P == '\\' && P[1]) ++P;
                Value.push_back(*P++);
            }
            return Value;
        };
        auto ReadNumber = [&](const char* Key) -> ULONGLONG {
            const char* P = FindValue(Key);
            if (!P) return 0;
            ULONGLONG Value = 0;
            while (*P >= '0' && *P <= '9') {
                Value = Value * 10 + static_cast<ULONGLONG>(*P - '0');
                ++P;
            }
            return Value;
        };

        Evt.Category = ReadString("\"cat\"");
        Evt.Timestamp = ReadNumber("\"ts\"");
        Evt.ProcessId = static_cast<DWORD>(ReadNumber("\"pid\""));
        Evt.ThreadId = static_cast<DWORD>(ReadNumber("\"tid\""));
        return Evt;
    }

    void PipeLoop() {
        M_Pipe = CreateNamedPipeW(DLL_PIPE_NAME, PIPE_ACCESS_INBOUND,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            10, DLL_PIPE_BUFFER_SIZE, DLL_PIPE_BUFFER_SIZE, 0, NULL);
        if (M_Pipe == INVALID_HANDLE_VALUE) {
            M_CreateFailed = true;
            M_Ready = true;
            M_Running = false;
            return;
        }
        M_Ready = true;

        char Buf[DLL_PIPE_BUFFER_SIZE];
        DWORD BytesRead;

        while (M_Running) {
            if (!ConnectNamedPipe(M_Pipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
                Sleep(100);
                continue;
            }
            while (M_Running && ReadFile(M_Pipe, Buf, sizeof(Buf) - 1, &BytesRead, NULL) && BytesRead > 0) {
                Buf[BytesRead] = '\0';
                if (M_Callback) M_Callback(ParseEvent(Buf));
            }
            DisconnectNamedPipe(M_Pipe);
        }
        CloseHandle(M_Pipe);
        M_Pipe = INVALID_HANDLE_VALUE;
    }

    HANDLE            M_Pipe;
    std::thread       M_Thread;
    std::atomic<bool> M_Running;
    std::atomic<bool> M_Ready;
    std::atomic<bool> M_CreateFailed;
    Callback          M_Callback;
};
