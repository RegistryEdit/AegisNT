// ============================================================
// AegisSentinel 驱动的用户态调用封装：进程监控事件订阅、
// 文件/目录防护与放行、热点路径输出等 IOCTL 封装。
// ============================================================
#pragma once
#include <atomic>
#include <functional>
#include <stdexcept>
#include <string>
#include <thread>
#include <windows.h>

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
  EventDnsQuery,
  EventHttpRequest,
  EventFileCapture,
  EventProcessInject,
  EventServiceStateChange,
  EventNamedPipeConnect,
  EventUsbDeviceArrival,
  EventUsbDeviceRemoval,
  EventCallbackChange,
};

struct MonitorSimpleEvent {
  MonitorEventType Type;
  ULONG ProcessId;
  ULONG ThreadId;
  ULONG ParentPid;
  ULONG Data1;
  ULONG Data2;
  LARGE_INTEGER TimeStamp;
  WCHAR Path[260];
  WCHAR Extra[260];
  /* 通用富字段（与驱动 Include/Sentinel/Protocol.h 同序，须同步） */
  ULONG Flags2;
  ULONG CreatorPid;
  ULONG CreatorTid;
  ULONG DataBytes;
  ULONG ValueType;
  UCHAR Data[256];
  WCHAR Name[128];
};

static_assert(sizeof(MonitorSimpleEvent) == 1604,
              "MonitorSimpleEvent ABI mismatch");

/* Flags2 通用标志位（与驱动同步） */
#define MONITOR_FLAG2_DATA_TRUNCATED 0x00000001u
#define MONITOR_FLAG2_KERNEL_HANDLE 0x00000002u
#define MONITOR_FLAG2_SYSTEM_MODE_IMAGE 0x00000004u
#define MONITOR_FLAG2_SUBSYSTEM_PROCESS 0x00000008u
#define MONITOR_FLAG2_CREATOR_DIFFERS 0x00000010u
#define MONITOR_FLAG2_TARGET_IS_THREAD 0x00000020u
#define MONITOR_FLAG2_BLOCKED 0x00000040u
#define MONITOR_FLAG2_FILE_CAPTURE 0x00000080u

/* 服务事件的 Operation 取值（与驱动同步） */
#define MONITOR_SERVICE_OP_REGISTERED 1u
#define MONITOR_SERVICE_OP_REMOVED 2u
#define MONITOR_SERVICE_OP_START 3u

struct MonitorWatchDirectoryInput {
  WCHAR DirectoryPath[260];
};

struct MonitorWatchDirectoryOutput {
  BOOLEAN Active;
  UCHAR Reserved[3];
  WCHAR DirectoryPath[260];
};

#define MONITOR_PROTOCOL_VERSION 4u
#define MONITOR_EVENT_FLAG_TRUNCATED 0x00000001u
#define MONITOR_FILTER_REGISTRY_PREVIEW 0x00000001u
struct MonitorFilter {
  ULONG Size;
  ULONG Version;
  ULONG Flags;
  ULONG ProcessId;
  ULONG64 EventMask;
  ULONG RegistryPreviewBytes;
  WCHAR PathPrefix[260];
};
struct MonitorEvent {
  ULONG Size;
  ULONG Version;
  ULONG Type;
  ULONG Flags;
  ULONG64 Sequence;
  LARGE_INTEGER TimeStamp;
  LONG Status;
  ULONG ProcessId;
  ULONG ThreadId;
  ULONG ParentPid;
  ULONG TargetProcessId;
  ULONG TargetThreadId;
  ULONG Operation;
  ULONG DataType;
  ULONG64 Address;
  ULONG64 SizeBytes;
  ULONG64 Offset;
  ULONG64 Value1;
  ULONG64 Value2;
  WCHAR Path[260];
  WCHAR Extra[260];
  WCHAR TargetPath[260];
  /* 通用富字段（与驱动 Include/Sentinel/Protocol.h 同序，须同步） */
  ULONG Flags2;
  ULONG CreatorPid;
  ULONG CreatorTid;
  ULONG DataBytes;
  ULONG ValueType;
  UCHAR Data[256];
  WCHAR Name[128];
};
struct MonitorStats {
  ULONG Size;
  ULONG Version;
  ULONG SystemQueued;
  ULONG FileQueued;
  ULONG NetworkQueued;
  ULONG Reserved;
  ULONG64 SystemDropped;
  ULONG64 FileDropped;
  ULONG64 NetworkDropped;
  ULONG64 LastSequence;
  ULONG QueueCapacity;
  ULONG SystemHighWatermark;
  ULONG FileHighWatermark;
  ULONG NetworkHighWatermark;
};
#pragma pack(pop)

static_assert(sizeof(MonitorFilter) == 548, "Monitor V2 filter ABI mismatch");
static_assert(sizeof(MonitorEvent) == 2196, "Monitor V4 event ABI mismatch");
static_assert(sizeof(MonitorStats) == 72, "Monitor V3 stats ABI mismatch");

static constexpr const WCHAR *EventTypeToString(MonitorEventType T) {
  switch (T) {
  case EventProcessCreate:
    return L"Process Create";
  case EventProcessExit:
    return L"Process Exit";
  case EventThreadCreate:
    return L"Thread Create";
  case EventThreadExit:
    return L"Thread Exit";
  case EventImageLoad:
    return L"Image Load";
  case EventRegistryOperation:
    return L"Registry Op";
  case EventHandleOperation:
    return L"Handle Op";
  case EventFileOperation:
    return L"File Op";
  case EventDriverLoad:
    return L"Driver Load";
  case EventDriverUnload:
    return L"Driver Unload";
  case EventVolumeMount:
    return L"Volume Mount";
  case EventVolumeDismount:
    return L"Volume Dismount";
  case EventNetworkConnect:
    return L"Network Connect";
  case EventNetworkAccept:
    return L"Network Accept";
  case EventUsbDeviceArrival:
    return L"USB Device Arrival";
  case EventUsbDeviceRemoval:
    return L"USB Device Removal";
  case EventCallbackChange:
    return L"Kernel Callback Change";
  case EventDnsQuery:
    return L"DNS Query";
  case EventHttpRequest:
    return L"HTTP Request";
  case EventFileCapture:
    return L"File Capture";
  case EventProcessInject:
    return L"Process Inject";
  case EventServiceStateChange:
    return L"Service State";
  case EventNamedPipeConnect:
    return L"Named Pipe Connect";
  default:
    return L"Unknown";
  }
}
#define USER_DEVICE_NAME L"\\\\.\\AegisSentinel"
#define IOCTL_MONITOR_GET_FILE_EVENT                                           \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MONITOR_SET_WATCH_DIRECTORY                                      \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MONITOR_CLEAR_WATCH_DIRECTORY                                    \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MONITOR_QUERY_WATCH_DIRECTORY                                    \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MONITOR_GET_EVENT                                             \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MONITOR_GET_NETWORK_EVENT                                     \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MONITOR_SET_FILTER                                            \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MONITOR_QUERY_STATS                                           \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MONITOR_RULE_OPERATION                                        \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MONITOR_ENUM_RULES                                            \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MONITOR_GET_PNP_EVENT                                            \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MONITOR_SET_PNP_FILTER                                           \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80C, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MONITOR_QUERY_PNP_FILTER                                         \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80D, METHOD_BUFFERED, FILE_ANY_ACCESS)

constexpr ULONG MONITOR_PNP_FILTER_FLAG_ARRIVAL = 0x00000001u;
constexpr ULONG MONITOR_PNP_FILTER_FLAG_REMOVAL = 0x00000002u;
constexpr ULONG MONITOR_PNP_FILTER_FLAG_BLOCK = 0x00000004u;
constexpr ULONG MONITOR_PNP_OP_SET_FILTER = 1u;
constexpr ULONG MONITOR_PNP_OP_CLEAR_FILTER = 2u;

#pragma pack(push, 1)
struct MonitorPnpFilter {
  ULONG Size;
  ULONG Version;
  ULONG Flags;
  ULONG Reserved;
  GUID InterfaceClass;
  BOOLEAN MatchAllInterfaces;
  UCHAR Padding1[3];
  WCHAR HardwareIdPrefix[260];
  WCHAR VendorId[8];
  WCHAR ProductId[8];
  WCHAR InstancePrefix[260];
};

struct MonitorPnpFilterInput {
  ULONG Size;
  ULONG Version;
  ULONG Operation;
  ULONG Reserved;
  MonitorPnpFilter Filter;
};
#pragma pack(pop)

static_assert(sizeof(MonitorPnpFilter) == 1108,
              "Monitor PNP filter ABI mismatch");
static_assert(sizeof(MonitorPnpFilterInput) == 1124,
              "Monitor PNP filter input ABI mismatch");

enum MonitorRuleType : ULONG {
  MonitorRuleFile = 1,
  MonitorRuleRegistry = 2,
  MonitorRuleNetwork = 3,
};

enum MonitorRuleAction : ULONG {
  MonitorRuleAudit = 1,
  MonitorRuleBlock = 2,
};

enum MonitorRuleOp : ULONG {
  MonitorRuleAdd = 1,
  MonitorRuleRemove = 2,
  MonitorRuleClear = 3,
};

constexpr ULONG MONITOR_MAX_RULES = 64;

#pragma pack(push, 1)
struct MonitorRule {
  ULONG Id;
  ULONG Type;
  ULONG Action;
  ULONG ProcessId;
  ULONG Protocol;
  ULONG RemotePort;
  ULONG64 HitCount;
  WCHAR Target[260];
};

struct MonitorRuleOperation {
  ULONG Size;
  ULONG Version;
  ULONG Operation;
  ULONG Reserved;
  MonitorRule Rule;
};

struct MonitorRuleList {
  ULONG Size;
  ULONG Version;
  ULONG Count;
  ULONG Reserved;
  MonitorRule Rules[MONITOR_MAX_RULES];
};
#pragma pack(pop)

static_assert(sizeof(MonitorRule) == 552, "Monitor rule ABI mismatch");
static_assert(sizeof(MonitorRuleOperation) == 568,
              "Monitor rule operation ABI mismatch");
static_assert(sizeof(MonitorRuleList) == 35344,
              "Monitor rule list ABI mismatch");

enum class MonitorChannel : DWORD {
  File = IOCTL_MONITOR_GET_FILE_EVENT,
};

static inline HANDLE OpenAegisSentinelDevice() {
  return CreateFileW(USER_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                     OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
}

static inline bool AegisSentinelSetPnpFilter(const MonitorPnpFilter &Filter,
                                             ULONG Operation) {
  MonitorPnpFilterInput Input{};
  Input.Size = sizeof(Input);
  Input.Version = MONITOR_PROTOCOL_VERSION;
  Input.Operation = Operation;
  Input.Filter = Filter;

  HANDLE Device = OpenAegisSentinelDevice();
  if (Device == INVALID_HANDLE_VALUE)
    return false;
  DWORD Bytes = 0;
  const BOOL Ok = DeviceIoControl(Device, IOCTL_MONITOR_SET_PNP_FILTER, &Input,
                                  sizeof(Input), nullptr, 0, &Bytes, nullptr);
  const DWORD Error = Ok ? ERROR_SUCCESS : GetLastError();
  CloseHandle(Device);
  SetLastError(Error);
  return Ok == TRUE;
}

static inline bool AegisSentinelQueryPnpFilter(MonitorPnpFilter *Filter) {
  if (!Filter) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return false;
  }
  HANDLE Device = OpenAegisSentinelDevice();
  if (Device == INVALID_HANDLE_VALUE)
    return false;
  ZeroMemory(Filter, sizeof(*Filter));
  DWORD Bytes = 0;
  const BOOL Ok = DeviceIoControl(Device, IOCTL_MONITOR_QUERY_PNP_FILTER,
                                  nullptr, 0, Filter, sizeof(*Filter), &Bytes,
                                  nullptr);
  const DWORD Error = Ok ? ERROR_SUCCESS : GetLastError();
  CloseHandle(Device);
  if (!Ok || Bytes < sizeof(*Filter) ||
      Filter->Version != MONITOR_PROTOCOL_VERSION) {
    SetLastError(Ok ? ERROR_INVALID_DATA : Error);
    return false;
  }
  SetLastError(ERROR_SUCCESS);
  return true;
}

static inline bool AegisSentinelPopPnpEvent(MonitorSimpleEvent *Event) {
  if (!Event) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return false;
  }
  HANDLE Device = OpenAegisSentinelDevice();
  if (Device == INVALID_HANDLE_VALUE)
    return false;
  ZeroMemory(Event, sizeof(*Event));
  DWORD Bytes = 0;
  const BOOL Ok = DeviceIoControl(Device, IOCTL_MONITOR_GET_PNP_EVENT, nullptr,
                                  0, Event, sizeof(*Event), &Bytes, nullptr);
  const DWORD Error = Ok ? ERROR_SUCCESS : GetLastError();
  CloseHandle(Device);
  if (!Ok || Bytes < sizeof(*Event) || Event->Type == EventNone) {
    SetLastError(Ok ? ERROR_INVALID_DATA : Error);
    return false;
  }
  SetLastError(ERROR_SUCCESS);
  return true;
}

static inline bool AegisSentinelOperateRule(MonitorRuleOp Operation,
                                         const MonitorRule *Rule = nullptr) {
  MonitorRuleOperation Input{};
  Input.Size = sizeof(Input);
  Input.Version = MONITOR_PROTOCOL_VERSION;
  Input.Operation = Operation;
  if (Rule)
    Input.Rule = *Rule;

  HANDLE Device = OpenAegisSentinelDevice();
  if (Device == INVALID_HANDLE_VALUE)
    return false;
  DWORD Bytes = 0;
  const BOOL Ok = DeviceIoControl(Device, IOCTL_MONITOR_RULE_OPERATION,
                                  &Input, sizeof(Input), nullptr, 0, &Bytes,
                                  nullptr);
  const DWORD Error = Ok ? ERROR_SUCCESS : GetLastError();
  CloseHandle(Device);
  SetLastError(Error);
  return Ok == TRUE;
}

static inline bool AegisSentinelEnumerateRules(MonitorRuleList *Rules) {
  if (!Rules) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return false;
  }
  HANDLE Device = OpenAegisSentinelDevice();
  if (Device == INVALID_HANDLE_VALUE)
    return false;
  ZeroMemory(Rules, sizeof(*Rules));
  DWORD Bytes = 0;
  const BOOL Ok = DeviceIoControl(Device, IOCTL_MONITOR_ENUM_RULES, nullptr,
                                  0, Rules, sizeof(*Rules), &Bytes, nullptr);
  const DWORD Error = Ok ? ERROR_SUCCESS : GetLastError();
  CloseHandle(Device);
  if (!Ok || Bytes < offsetof(MonitorRuleList, Rules) ||
      Rules->Version != MONITOR_PROTOCOL_VERSION ||
      Rules->Count > MONITOR_MAX_RULES) {
    SetLastError(Ok ? ERROR_INVALID_DATA : Error);
    return false;
  }
  SetLastError(ERROR_SUCCESS);
  return true;
}

static inline bool AegisSentinelSetWatchDirectory(const wchar_t *NtDirectoryPath) {
  if (!NtDirectoryPath || !NtDirectoryPath[0]) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return false;
  }

  HANDLE Device = OpenAegisSentinelDevice();
  if (Device == INVALID_HANDLE_VALUE) {
    return false;
  }

  MonitorWatchDirectoryInput Input{};
  wcsncpy_s(Input.DirectoryPath, NtDirectoryPath, _TRUNCATE);
  DWORD Bytes = 0;
  const BOOL Ok =
      DeviceIoControl(Device, IOCTL_MONITOR_SET_WATCH_DIRECTORY, &Input,
                      sizeof(Input), nullptr, 0, &Bytes, nullptr);
  const DWORD Error = Ok ? ERROR_SUCCESS : GetLastError();
  CloseHandle(Device);
  SetLastError(Error);
  return Ok == TRUE;
}

static inline bool AegisSentinelClearWatchDirectory() {
  HANDLE Device = OpenAegisSentinelDevice();
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

static inline bool AegisSentinelQueryWatchDirectory(std::wstring *DirectoryPath,
                                                 bool *Active = nullptr) {
  HANDLE Device = OpenAegisSentinelDevice();
  if (Device == INVALID_HANDLE_VALUE) {
    return false;
  }

  MonitorWatchDirectoryOutput Output{};
  DWORD Bytes = 0;
  const BOOL Ok =
      DeviceIoControl(Device, IOCTL_MONITOR_QUERY_WATCH_DIRECTORY, nullptr, 0,
                      &Output, sizeof(Output), &Bytes, nullptr);
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

static inline bool AegisSentinelSetFilter(const MonitorFilter &Filter) {
  HANDLE Device = OpenAegisSentinelDevice();
  if (Device == INVALID_HANDLE_VALUE)
    return false;
  MonitorFilter Input = Filter;
  Input.Size = sizeof(Input);
  Input.Version = MONITOR_PROTOCOL_VERSION;
  if (Input.EventMask == 0)
    Input.EventMask = ~0ull;
  if (Input.RegistryPreviewBytes > 512)
    Input.RegistryPreviewBytes = 512;
  DWORD Bytes = 0;
  const BOOL Ok = DeviceIoControl(Device, IOCTL_MONITOR_SET_FILTER, &Input,
                                  sizeof(Input), nullptr, 0, &Bytes, nullptr);
  const DWORD Error = Ok ? ERROR_SUCCESS : GetLastError();
  CloseHandle(Device);
  SetLastError(Error);
  return Ok == TRUE;
}

static inline bool AegisSentinelQueryStats(MonitorStats *Stats) {
  if (!Stats) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return false;
  }
  HANDLE Device = OpenAegisSentinelDevice();
  if (Device == INVALID_HANDLE_VALUE)
    return false;
  ZeroMemory(Stats, sizeof(*Stats));
  DWORD Bytes = 0;
  const BOOL Ok = DeviceIoControl(Device, IOCTL_MONITOR_QUERY_STATS, nullptr,
                                  0, Stats, sizeof(*Stats), &Bytes, nullptr);
  const DWORD Error = Ok ? ERROR_SUCCESS : GetLastError();
  CloseHandle(Device);
  if (!Ok || Bytes < sizeof(*Stats) ||
      Stats->Version != MONITOR_PROTOCOL_VERSION) {
    SetLastError(Ok ? ERROR_INVALID_DATA : Error);
    return false;
  }
  SetLastError(ERROR_SUCCESS);
  return true;
}

class KernelMonitor {
public:
  using Callback = std::function<void(const MonitorEvent &)>;
  explicit KernelMonitor(bool Network = false)
      : M_Ioctl(Network ? IOCTL_MONITOR_GET_NETWORK_EVENT
                        : IOCTL_MONITOR_GET_EVENT) {
    M_Device = OpenAegisSentinelDevice();
    if (M_Device == INVALID_HANDLE_VALUE)
      throw std::runtime_error("Failed to open AegisSentinel device: " +
                               std::to_string(GetLastError()));
  }
  ~KernelMonitor() {
    Stop();
    if (M_Device != INVALID_HANDLE_VALUE)
      CloseHandle(M_Device);
  }
  KernelMonitor(const KernelMonitor &) = delete;
  KernelMonitor &operator=(const KernelMonitor &) = delete;
  void SetCallback(Callback Value) { M_Callback = std::move(Value); }
  bool Start() {
    if (M_Running.exchange(true))
      return true;
    M_Thread = std::thread([this] { Poll(); });
    return true;
  }
  void Stop() {
    if (!M_Running.exchange(false))
      return;
    if (M_Thread.joinable())
      M_Thread.join();
  }
  bool IsRunning() const { return M_Running.load(); }

private:
  void Poll() {
    while (M_Running) {
      MonitorEvent Event{};
      DWORD Bytes = 0;
      const BOOL Ok = DeviceIoControl(M_Device, M_Ioctl, nullptr, 0, &Event,
                                      sizeof(Event), &Bytes, nullptr);
      if (Ok && Bytes == sizeof(Event) &&
          Event.Version == MONITOR_PROTOCOL_VERSION && M_Callback)
        M_Callback(Event);
      else
        Sleep(10);
    }
  }
  HANDLE M_Device = INVALID_HANDLE_VALUE;
  DWORD M_Ioctl = IOCTL_MONITOR_GET_EVENT;
  std::thread M_Thread;
  std::atomic_bool M_Running = false;
  Callback M_Callback;
};

class SimpleEventMonitor {
public:
  using Callback = std::function<void(const MonitorSimpleEvent &)>;

  explicit SimpleEventMonitor(MonitorChannel Channel = MonitorChannel::File)
      : M_Device(INVALID_HANDLE_VALUE), M_Running(false),
        M_IoControlCode(static_cast<DWORD>(Channel)) {
    M_Device = OpenAegisSentinelDevice();
    if (M_Device == INVALID_HANDLE_VALUE) {
      throw std::runtime_error("Failed to open AegisSentinel device. "
                               "Run 'sc start Ring0Core' as Administrator. "
                               "Error: " +
                               std::to_string(GetLastError()));
    }
  }

  ~SimpleEventMonitor() {
    Stop();
    if (M_Device != INVALID_HANDLE_VALUE) {
      CloseHandle(M_Device);
      M_Device = INVALID_HANDLE_VALUE;
    }
  }

  SimpleEventMonitor(const SimpleEventMonitor &) = delete;
  SimpleEventMonitor &operator=(const SimpleEventMonitor &) = delete;

  SimpleEventMonitor(SimpleEventMonitor &&Other) noexcept
      : M_Device(Other.M_Device), M_Running(Other.M_Running.load()),
        M_IoControlCode(Other.M_IoControlCode) {
    Other.M_Device = INVALID_HANDLE_VALUE;
    Other.M_Running = false;
  }

  SimpleEventMonitor &operator=(SimpleEventMonitor &&Other) noexcept {
    if (this != &Other) {
      Stop();
      if (M_Device != INVALID_HANDLE_VALUE)
        CloseHandle(M_Device);
      M_Device = Other.M_Device;
      M_Running = Other.M_Running.load();
      M_IoControlCode = Other.M_IoControlCode;
      Other.M_Device = INVALID_HANDLE_VALUE;
      Other.M_Running = false;
    }
    return *this;
  }

  void SetCallback(Callback Cb) { M_Callback = std::move(Cb); }

  bool Start() {
    if (M_Running)
      return true;
    if (M_Device == INVALID_HANDLE_VALUE)
      return false;
    M_Running = true;
    M_Thread = std::thread(&SimpleEventMonitor::PollLoop, this);
    return true;
  }

  void Stop() {
    if (!M_Running)
      return;
    M_Running = false;
    if (M_Thread.joinable())
      M_Thread.join();
  }

  bool IsRunning() const { return M_Running; }

private:
  void PollLoop() {
    MonitorSimpleEvent Evt;
    DWORD Bytes;
    while (M_Running) {
      BOOL Ok = DeviceIoControl(M_Device, M_IoControlCode, nullptr, 0, &Evt,
                                sizeof(Evt), &Bytes, nullptr);
      if (Ok && Bytes == sizeof(Evt) && Evt.Type != EventNone && M_Callback) {
        M_Callback(Evt);
      } else {
        Sleep(10);
      }
    }
  }

  HANDLE M_Device;
  std::thread M_Thread;
  std::atomic<bool> M_Running;
  DWORD M_IoControlCode;
  Callback M_Callback;
};
