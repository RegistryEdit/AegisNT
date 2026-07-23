#pragma once
#include <windows.h>
#include <functional>
#include <thread>
#include <atomic>
#include <stdexcept>
#include <string>

/* ──── Mirror of kernel driver structs (keep in sync with driver.cpp) ──── */
#pragma pack(push, 1)
enum MonitorEventType : ULONG {
    EventNone = 0,
    EventProcessCreate,
    EventProcessExit,
    EventThreadCreate,
    EventThreadExit,
    EventImageLoad,
    EventRegistryOperation,
    EventHandleOperation,
    EventFileOperation,
    EventDriverLoad,
    EventDriverUnload,
    EventVolumeMount,
    EventVolumeDismount,
    EventNetworkConnect,
    EventNetworkAccept,
};

struct MonitorEvent {
    MonitorEventType Type;
    ULONG            ProcessId;
    ULONG            ThreadId;
    ULONG            ParentPid;
    ULONG            Data1;
    ULONG            Data2;
    LARGE_INTEGER    TimeStamp;
    WCHAR            Path[260];
    WCHAR            Extra[260];
};

struct MonitorWatchDirectoryInput {
    WCHAR DirectoryPath[260];
};

struct MonitorWatchDirectoryOutput {
    BOOLEAN Active;
    UCHAR   Reserved[3];
    WCHAR   DirectoryPath[260];
};

#define MONITOR_PROTOCOL_VERSION 2u
#define MONITOR_EVENT_FLAG_TRUNCATED 0x00000001u
#define MONITOR_FILTER_REGISTRY_PREVIEW 0x00000001u
struct MonitorFilterV2 {
    ULONG Size; ULONG Version; ULONG Flags; ULONG ProcessId; ULONG64 EventMask;
    ULONG RegistryPreviewBytes; WCHAR PathPrefix[260];
};
struct MonitorEventV2 {
    ULONG Size; ULONG Version; ULONG Type; ULONG Flags; ULONG64 Sequence; LARGE_INTEGER TimeStamp;
    LONG Status; ULONG ProcessId; ULONG ThreadId; ULONG ParentPid; ULONG TargetProcessId;
    ULONG TargetThreadId; ULONG Operation; ULONG DataType; ULONG64 Address; ULONG64 SizeBytes;
    ULONG64 Offset; ULONG64 Value1; ULONG64 Value2; WCHAR Path[260]; WCHAR Extra[260]; WCHAR TargetPath[260];
};
struct MonitorStatsV2 {
    ULONG Size; ULONG Version; ULONG SystemQueued; ULONG FileQueued; ULONG NetworkQueued; ULONG Reserved;
    ULONG64 SystemDropped; ULONG64 FileDropped; ULONG64 NetworkDropped; ULONG64 LastSequence;
};
#pragma pack(pop)

static_assert(sizeof(MonitorFilterV2) == 548, "Monitor V2 filter ABI mismatch");
static_assert(sizeof(MonitorEventV2) == 1664, "Monitor V2 event ABI mismatch");
static_assert(sizeof(MonitorStatsV2) == 56, "Monitor V2 stats ABI mismatch");

static constexpr const WCHAR* EventTypeToString(MonitorEventType T) {
    switch (T) {
    case EventProcessCreate:     return L"Process Create";
    case EventProcessExit:       return L"Process Exit";
    case EventThreadCreate:      return L"Thread Create";
    case EventThreadExit:        return L"Thread Exit";
    case EventImageLoad:         return L"Image Load";
    case EventRegistryOperation: return L"Registry Op";
    case EventHandleOperation:   return L"Handle Op";
    case EventFileOperation:     return L"File Op";
    case EventDriverLoad:        return L"Driver Load";
    case EventDriverUnload:      return L"Driver Unload";
    case EventVolumeMount:       return L"Volume Mount";
    case EventVolumeDismount:    return L"Volume Dismount";
    case EventNetworkConnect:    return L"Network Connect";
    case EventNetworkAccept:     return L"Network Accept";
    default:                     return L"Unknown";
    }
}
#define USER_DEVICE_NAME       L"\\\\.\\MonitorDrv"
#define IOCTL_MONITOR_GET_EVENT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MONITOR_GET_FILE_EVENT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MONITOR_SET_WATCH_DIRECTORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MONITOR_CLEAR_WATCH_DIRECTORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MONITOR_QUERY_WATCH_DIRECTORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MONITOR_GET_EVENT_V2 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MONITOR_GET_NETWORK_EVENT_V2 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MONITOR_SET_FILTER_V2 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MONITOR_QUERY_STATS_V2 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)

enum class MonitorChannel : DWORD {
    System = IOCTL_MONITOR_GET_EVENT,
    File = IOCTL_MONITOR_GET_FILE_EVENT,
};

static inline HANDLE OpenMonitorDrvDevice() {
    return CreateFileW(USER_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
}

static inline bool MonitorDrvSetWatchDirectory(const wchar_t* NtDirectoryPath) {
    if (!NtDirectoryPath || !NtDirectoryPath[0]) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }

    HANDLE Device = OpenMonitorDrvDevice();
    if (Device == INVALID_HANDLE_VALUE) {
        return false;
    }

    MonitorWatchDirectoryInput Input{};
    wcsncpy_s(Input.DirectoryPath, NtDirectoryPath, _TRUNCATE);
    DWORD Bytes = 0;
    const BOOL Ok = DeviceIoControl(Device, IOCTL_MONITOR_SET_WATCH_DIRECTORY,
        &Input, sizeof(Input), nullptr, 0, &Bytes, nullptr);
    const DWORD Error = Ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(Device);
    SetLastError(Error);
    return Ok == TRUE;
}

static inline bool MonitorDrvClearWatchDirectory() {
    HANDLE Device = OpenMonitorDrvDevice();
    if (Device == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD Bytes = 0;
    const BOOL Ok = DeviceIoControl(Device, IOCTL_MONITOR_CLEAR_WATCH_DIRECTORY,
        nullptr, 0, nullptr, 0, &Bytes, nullptr);
    const DWORD Error = Ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(Device);
    SetLastError(Error);
    return Ok == TRUE;
}

static inline bool MonitorDrvQueryWatchDirectory(std::wstring* DirectoryPath, bool* Active = nullptr) {
    HANDLE Device = OpenMonitorDrvDevice();
    if (Device == INVALID_HANDLE_VALUE) {
        return false;
    }

    MonitorWatchDirectoryOutput Output{};
    DWORD Bytes = 0;
    const BOOL Ok = DeviceIoControl(Device, IOCTL_MONITOR_QUERY_WATCH_DIRECTORY,
        nullptr, 0, &Output, sizeof(Output), &Bytes, nullptr);
    const DWORD Error = Ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(Device);
    if (!Ok || Bytes < sizeof(Output)) {
        SetLastError(Ok ? ERROR_INSUFFICIENT_BUFFER : Error);
        return false;
    }

    if (DirectoryPath) {
        *DirectoryPath = Output.DirectoryPath;
    }
    if (Active) {
        *Active = Output.Active != FALSE;
    }
    SetLastError(ERROR_SUCCESS);
    return true;
}

static inline bool MonitorDrvSetFilterV2(const MonitorFilterV2& Filter) {
    HANDLE Device = OpenMonitorDrvDevice();
    if (Device == INVALID_HANDLE_VALUE) return false;
    MonitorFilterV2 Input = Filter;
    Input.Size = sizeof(Input); Input.Version = MONITOR_PROTOCOL_VERSION;
    if (Input.EventMask == 0) Input.EventMask = ~0ull;
    if (Input.RegistryPreviewBytes > 512) Input.RegistryPreviewBytes = 512;
    DWORD Bytes = 0;
    const BOOL Ok = DeviceIoControl(Device, IOCTL_MONITOR_SET_FILTER_V2, &Input, sizeof(Input), nullptr, 0, &Bytes, nullptr);
    const DWORD Error = Ok ? ERROR_SUCCESS : GetLastError(); CloseHandle(Device); SetLastError(Error); return Ok == TRUE;
}

static inline bool MonitorDrvQueryStatsV2(MonitorStatsV2* Stats) {
    if (!Stats) { SetLastError(ERROR_INVALID_PARAMETER); return false; }
    HANDLE Device = OpenMonitorDrvDevice(); if (Device == INVALID_HANDLE_VALUE) return false;
    ZeroMemory(Stats, sizeof(*Stats)); DWORD Bytes = 0;
    const BOOL Ok = DeviceIoControl(Device, IOCTL_MONITOR_QUERY_STATS_V2, nullptr, 0, Stats, sizeof(*Stats), &Bytes, nullptr);
    const DWORD Error = Ok ? ERROR_SUCCESS : GetLastError(); CloseHandle(Device);
    if (!Ok || Bytes < sizeof(*Stats) || Stats->Version != MONITOR_PROTOCOL_VERSION) { SetLastError(Ok ? ERROR_INVALID_DATA : Error); return false; }
    SetLastError(ERROR_SUCCESS); return true;
}

class KernelMonitorV2 {
public:
    using Callback = std::function<void(const MonitorEventV2&)>;
    explicit KernelMonitorV2(bool Network = false) : M_Ioctl(Network ? IOCTL_MONITOR_GET_NETWORK_EVENT_V2 : IOCTL_MONITOR_GET_EVENT_V2) {
        M_Device = OpenMonitorDrvDevice();
        if (M_Device == INVALID_HANDLE_VALUE) throw std::runtime_error("Failed to open MonitorDrv device: " + std::to_string(GetLastError()));
    }
    ~KernelMonitorV2() { Stop(); if (M_Device != INVALID_HANDLE_VALUE) CloseHandle(M_Device); }
    KernelMonitorV2(const KernelMonitorV2&) = delete;
    KernelMonitorV2& operator=(const KernelMonitorV2&) = delete;
    void SetCallback(Callback Value) { M_Callback = std::move(Value); }
    bool Start() { if (M_Running.exchange(true)) return true; M_Thread = std::thread([this] { Poll(); }); return true; }
    void Stop() { if (!M_Running.exchange(false)) return; if (M_Thread.joinable()) M_Thread.join(); }
    bool IsRunning() const { return M_Running.load(); }
private:
    void Poll() {
        while (M_Running) {
            MonitorEventV2 Event{}; DWORD Bytes = 0;
            const BOOL Ok = DeviceIoControl(M_Device, M_Ioctl, nullptr, 0, &Event, sizeof(Event), &Bytes, nullptr);
            if (Ok && Bytes == sizeof(Event) && Event.Version == MONITOR_PROTOCOL_VERSION && M_Callback) M_Callback(Event);
            else Sleep(10);
        }
    }
    HANDLE M_Device = INVALID_HANDLE_VALUE;
    DWORD M_Ioctl = IOCTL_MONITOR_GET_EVENT_V2;
    std::thread M_Thread;
    std::atomic_bool M_Running = false;
    Callback M_Callback;
};

class KernelMonitor {
public:
    using Callback = std::function<void(const MonitorEvent&)>;

    explicit KernelMonitor(MonitorChannel Channel = MonitorChannel::System)
        : M_Device(INVALID_HANDLE_VALUE), M_Running(false), M_IoControlCode(static_cast<DWORD>(Channel)) {
        M_Device = OpenMonitorDrvDevice();
        if (M_Device == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("Failed to open MonitorDrv device. "
                "Run 'sc start MonitorDrv' as Administrator. "
                "Error: " + std::to_string(GetLastError()));
        }
    }

    ~KernelMonitor() {
        Stop();
        if (M_Device != INVALID_HANDLE_VALUE) {
            CloseHandle(M_Device);
            M_Device = INVALID_HANDLE_VALUE;
        }
    }

    KernelMonitor(const KernelMonitor&) = delete;
    KernelMonitor& operator=(const KernelMonitor&) = delete;

    KernelMonitor(KernelMonitor&& Other) noexcept
        : M_Device(Other.M_Device),
          M_Running(Other.M_Running.load()),
          M_IoControlCode(Other.M_IoControlCode) {
        Other.M_Device = INVALID_HANDLE_VALUE;
        Other.M_Running = false;
    }

    KernelMonitor& operator=(KernelMonitor&& Other) noexcept {
        if (this != &Other) {
            Stop();
            if (M_Device != INVALID_HANDLE_VALUE) CloseHandle(M_Device);
            M_Device = Other.M_Device;
            M_Running = Other.M_Running.load();
            M_IoControlCode = Other.M_IoControlCode;
            Other.M_Device = INVALID_HANDLE_VALUE;
            Other.M_Running = false;
        }
        return *this;
    }

    void SetCallback(Callback Cb) {
        M_Callback = std::move(Cb);
    }

    bool Start() {
        if (M_Running) return true;
        if (M_Device == INVALID_HANDLE_VALUE) return false;
        M_Running = true;
        M_Thread = std::thread(&KernelMonitor::PollLoop, this);
        return true;
    }

    void Stop() {
        if (!M_Running) return;
        M_Running = false;
        if (M_Thread.joinable()) M_Thread.join();
    }

    bool IsRunning() const { return M_Running; }

private:
    void PollLoop() {
        MonitorEvent Evt;
        DWORD Bytes;
        while (M_Running) {
            BOOL Ok = DeviceIoControl(M_Device, M_IoControlCode,
                nullptr, 0, &Evt, sizeof(Evt), &Bytes, nullptr);
            if (Ok && Bytes == sizeof(Evt) && Evt.Type != EventNone && M_Callback) {
                M_Callback(Evt);
            }
            else {
                Sleep(10);
            }
        }
    }

    HANDLE                M_Device;
    std::thread           M_Thread;
    std::atomic<bool>     M_Running;
    DWORD                 M_IoControlCode;
    Callback              M_Callback;
};
