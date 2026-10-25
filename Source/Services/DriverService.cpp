#include "IDriverService.h"
#include "../../Platform/AegisCoreClient.h"
#include "../../Platform/AegisCoreCall.h"
#include "DriverServiceEnumImpl.h"
#include <QDir>
#include <QFileInfo>
#include <cstring>
#include <limits>
#include <vector>

namespace AegisNT {

namespace {
struct ServiceHandle {
    SC_HANDLE Value;
    explicit ServiceHandle(SC_HANDLE Handle) : Value(Handle) {}
    ~ServiceHandle() { if (Value) ::CloseServiceHandle(Value); }
    ServiceHandle(const ServiceHandle &) = delete;
    ServiceHandle &operator=(const ServiceHandle &) = delete;
};

template<size_t N> QString WireString(const WCHAR (&Text)[N]) {
    return QString::fromWCharArray(Text, static_cast<qsizetype>(wcsnlen_s(Text, N)));
}

bool ValidServiceName(const QString &Name) {
    return !Name.isEmpty() && Name.size() <= 256 && !Name.contains(QChar(0)) &&
        !Name.contains('/') && !Name.contains('\\');
}

QString MemoryProtectionName(DWORD Protection) {
    QString Name;
    switch (Protection & 0xff) {
    case PAGE_NOACCESS: Name = "NOACCESS"; break;
    case PAGE_READONLY: Name = "R"; break;
    case PAGE_READWRITE: Name = "RW"; break;
    case PAGE_WRITECOPY: Name = "WC"; break;
    case PAGE_EXECUTE: Name = "X"; break;
    case PAGE_EXECUTE_READ: Name = "RX"; break;
    case PAGE_EXECUTE_READWRITE: Name = "RWX"; break;
    case PAGE_EXECUTE_WRITECOPY: Name = "WXC"; break;
    default: Name = QString::number(Protection, 16); break;
    }
    if (Protection & PAGE_GUARD) Name += "|GUARD";
    if (Protection & PAGE_NOCACHE) Name += "|NOCACHE";
    if (Protection & PAGE_WRITECOMBINE) Name += "|WRITECOMBINE";
    return Name;
}
}

/**
 * DriverServiceSimple - IDriverService 的简化实现
 *
 * 已接通的操作统一经 AegisCoreClient 传输并保留驱动错误。
 * Native management operations preserve Windows access checks.
 */
class DriverServiceSimple : public IDriverService {
    AegisCoreClient Client;
    mutable std::atomic<DWORD> LastError{ERROR_SUCCESS};

    template<typename T> Result<T> Error(DWORD Code, const QString &Message = "Operation failed") const {
        LastError = Code ? Code : ERROR_GEN_FAILURE;
        return Result<T>::Error(LastError.load(), QString("%1: %2").arg(Message).arg(LastError.load()));
    }
    template<typename T> Result<T> Success(const T &Value) const {
        LastError = ERROR_SUCCESS;
        return Result<T>::Ok(Value);
    }

    Result<void> OperationResult(bool Success) const {
        if (Success) { LastError = ERROR_SUCCESS; return Result<void>::Ok(); }
        const DWORD Error = Client.GetLastError();
        LastError = Error ? Error : ERROR_GEN_FAILURE;
        return Result<void>::Error(Error ? Error : ERROR_GEN_FAILURE,
                                  QString("AegisCore error: %1").arg(Error));
    }

    template<typename Model, typename Query, typename Parse>
    Result<QVector<Model>> ParsedCountedList(Query Fetch, size_t CountOffset,
                                             size_t HeaderBytes, size_t EntryBytes,
                                             Parse ParseRaw) {
        constexpr size_t Limit = 64 * 1024 * 1024;
        if (CountOffset > HeaderBytes || HeaderBytes > Limit ||
            EntryBytes == 0 || EntryBytes > Limit - HeaderBytes)
            return Error<QVector<Model>>(ERROR_INVALID_PARAMETER);
        std::vector<BYTE> Buffer(HeaderBytes + EntryBytes);
        for (unsigned Attempt = 0; Attempt < 8; ++Attempt) {
            DWORD Bytes = 0;
            if (!Fetch(Buffer.data(), static_cast<DWORD>(Buffer.size()), &Bytes))
                return Error<QVector<Model>>(Client.GetLastError());
            if (Bytes < CountOffset + sizeof(ULONG) || Bytes > Buffer.size())
                return Error<QVector<Model>>(ERROR_INVALID_DATA);
            ULONG Count = 0;
            std::memcpy(&Count, Buffer.data() + CountOffset, sizeof(Count));
            if (Count > (Limit - HeaderBytes) / EntryBytes)
                return Error<QVector<Model>>(ERROR_INVALID_DATA);
            const size_t Required = HeaderBytes + static_cast<size_t>(Count) * EntryBytes;
            if (Required > Buffer.size()) { Buffer.resize(Required); continue; }
            if (Required > Bytes) {
                // Some count + flexible-array IOCTLs return just the ULONG count
                // for an empty result. Let each protocol parser validate that
                // short form (notably, driver lists still require their NTSTATUS
                // header even when Count is zero).
                if (Count == 0) {
                    auto Empty = ParseRaw(Buffer.data(), Bytes);
                    if (Empty.IsError())
                        return Error<QVector<Model>>(Empty.GetErrorCode(), Empty.GetErrorMessage());
                    return Success(Empty.Value());
                }
                return Error<QVector<Model>>(ERROR_INVALID_DATA);
            }
            auto Parsed = ParseRaw(Buffer.data(), Bytes);
            if (Parsed.IsError())
                return Error<QVector<Model>>(Parsed.GetErrorCode(), Parsed.GetErrorMessage());
            return Success(Parsed.Value());
        }
        return Error<QVector<Model>>(ERROR_RETRY);
    }

    template<typename Model, typename Query, typename Convert>
    Result<QVector<Model>> InventoryList(Query Fetch, ULONG Kind, Convert Map) {
        constexpr DWORD Size = sizeof(INVENTORY_LIST_HEADER) + INVENTORY_MAX_PAGE_RECORDS * sizeof(INVENTORY_RECORD);
        std::vector<BYTE> Buffer(Size);
        QVector<Model> Items;
        ULONG64 Cursor = 0;
        for (unsigned Page = 0; Page < 4096; ++Page) {
            DWORD Bytes = 0;
            if (!Fetch(Buffer.data(), Size, &Bytes, Cursor)) return Error<QVector<Model>>(Client.GetLastError());
            INVENTORY_LIST_HEADER Header;
            std::memcpy(&Header, Buffer.data(), sizeof(Header));
            if (Items.size() + Header.ReturnedCount > 1024 * 1024)
                return Error<QVector<Model>>(ERROR_NOT_ENOUGH_MEMORY);
            for (ULONG Index = 0; Index < Header.ReturnedCount; ++Index) {
                INVENTORY_RECORD Record;
                std::memcpy(&Record, Buffer.data() + sizeof(Header) + Index * sizeof(Record), sizeof(Record));
                if (Record.Kind != Kind) return Error<QVector<Model>>(ERROR_INVALID_DATA);
                Items.append(Map(Record));
            }
            if (!Header.NextCursor) return Success(Items);
            Cursor = Header.NextCursor;
        }
        return Error<QVector<Model>>(ERROR_RETRY);
    }

    Result<void> WaitService(SC_HANDLE Service, DWORD Desired) {
        const ULONGLONG Deadline = ::GetTickCount64() + 10000;
        SERVICE_STATUS_PROCESS Status = {};
        do {
            DWORD Needed = 0;
            if (!::QueryServiceStatusEx(Service, SC_STATUS_PROCESS_INFO,
                reinterpret_cast<BYTE *>(&Status), sizeof(Status), &Needed)) return Error<void>(::GetLastError());
            if (Status.dwCurrentState == Desired) { LastError = 0; return Result<void>::Ok(); }
            if (Desired == SERVICE_RUNNING && Status.dwCurrentState == SERVICE_STOPPED)
                return Error<void>(Status.dwWin32ExitCode ? Status.dwWin32ExitCode : ERROR_SERVICE_NOT_ACTIVE);
            ::Sleep(100);
        } while (::GetTickCount64() < Deadline);
        return Error<void>(ERROR_TIMEOUT);
    }

    Result<void> ManageService(const QString &Name, int Operation) {
        if (!ValidServiceName(Name)) return Error<void>(ERROR_INVALID_NAME);
        ServiceHandle Scm(::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
        if (!Scm.Value) return Error<void>(::GetLastError());
        const DWORD Access = Operation == 0 ? SERVICE_START : Operation == 1 ? SERVICE_STOP : DELETE;
        ServiceHandle Service(::OpenServiceW(Scm.Value, Name.toStdWString().c_str(), Access | SERVICE_QUERY_STATUS));
        if (!Service.Value) return Error<void>(::GetLastError());
        BOOL Ok;
        if (Operation == 0) {
            Ok = ::StartServiceW(Service.Value, 0, nullptr);
            if (!Ok && ::GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) return Error<void>(::GetLastError());
            return WaitService(Service.Value, SERVICE_RUNNING);
        }
        if (Operation == 1) {
            SERVICE_STATUS Status = {};
            Ok = ::ControlService(Service.Value, SERVICE_CONTROL_STOP, &Status);
            if (!Ok && ::GetLastError() != ERROR_SERVICE_NOT_ACTIVE) return Error<void>(::GetLastError());
            return WaitService(Service.Value, SERVICE_STOPPED);
        }
        if (!::DeleteService(Service.Value)) return Error<void>(::GetLastError());
        LastError = 0;
        return Result<void>::Ok();
    }

public:
    // ============================================================
    // 进程管理
    // ============================================================

    Result<void> KillProcess(DWORD Pid) override {
        return OperationResult(Client.KillProcess(Pid));
    }

    Result<void> SuspendProcess(DWORD Pid) override {
        return OperationResult(Client.SuspendProcess(Pid));
    }

    Result<void> ResumeProcess(DWORD Pid) override {
        return OperationResult(Client.ResumeProcess(Pid));
    }

    Result<void> ProtectProcess(DWORD Pid) override {
        return OperationResult(Client.ProtectProcess(Pid));
    }

    Result<void> UnprotectProcess(DWORD Pid) override {
        return OperationResult(Client.UnprotectProcess(Pid));
    }

    Result<void> SetProcessPpl(DWORD Pid, UCHAR Level) override {
        return OperationResult(Client.SetProcessPpl(Pid, Level));
    }

    Result<void> RemoveProcessPpl(DWORD Pid) override {
        return OperationResult(Client.RemoveProcessPpl(Pid));
    }

    Result<void> SetProcessCritical(DWORD Pid, bool Critical) override {
        return OperationResult(Critical ? Client.SetProcessCritical(Pid)
                                        : Client.RemoveProcessCritical(Pid));
    }

    Result<void> HideProcess(DWORD Pid, bool Hide) override {
        return OperationResult(Hide ? Client.HideProcess(Pid) : Client.UnhideProcess(Pid));
    }

    // ============================================================
    // 枚举操作
    // ============================================================

    Result<QVector<ProcessInfo>> EnumProcesses() override {
        return ParsedCountedList<ProcessInfo>(
            [&](void *Out, DWORD Size, DWORD *Bytes) { return Client.EnumProcesses(Out, Size, Bytes); },
            offsetof(PROCESS_ENUM_OUTPUT, Count), offsetof(PROCESS_ENUM_OUTPUT, Entries),
            sizeof(PROCESS_ENUM_ENTRY),
            [](const void *Buffer, size_t Bytes) {
                return DriverServiceEnum::ParseProcesses(Buffer, Bytes);
            });
    }

    Result<QVector<ThreadInfo>> EnumThreads(DWORD Pid) override {
        constexpr DWORD Size = sizeof(INVENTORY_LIST_HEADER) +
            INVENTORY_MAX_PAGE_RECORDS * sizeof(INVENTORY_RECORD);
        std::vector<BYTE> Buffer(Size);
        QVector<ThreadInfo> Items;
        ULONG64 Cursor = 0;
        for (unsigned Page = 0; Page < 4096; ++Page) {
            DWORD Bytes = 0;
            if (!Client.EnumThreads(Pid, Buffer.data(), Size, &Bytes, Cursor))
                return Error<QVector<ThreadInfo>>(Client.GetLastError());

            ULONG64 NextCursor = 0;
            auto Parsed = DriverServiceEnum::ParseThreadInventoryPage(
                Buffer.data(), Bytes, Pid, Cursor, &NextCursor);
            if (Parsed.IsError())
                return Error<QVector<ThreadInfo>>(Parsed.GetErrorCode(), Parsed.GetErrorMessage());
            if (Items.size() + Parsed.Value().size() > 1024 * 1024)
                return Error<QVector<ThreadInfo>>(ERROR_NOT_ENOUGH_MEMORY);
            Items += Parsed.Value();
            if (NextCursor == 0)
                return Success(Items);
            if (NextCursor <= Cursor)
                return Error<QVector<ThreadInfo>>(ERROR_INVALID_DATA);
            Cursor = NextCursor;
        }
        return Error<QVector<ThreadInfo>>(ERROR_RETRY);
    }

    Result<QVector<DriverInfo>> EnumDrivers() override {
        return ParsedCountedList<DriverInfo>(
            [&](void *Out, DWORD Size, DWORD *Bytes) { return Client.EnumDrivers(Out, Size, Bytes); },
            offsetof(DRIVER_ENUM_HEADER, Count), offsetof(DRIVER_ENUM_OUTPUT, Entries),
            sizeof(DRIVER_ENUM_ENTRY),
            [](const void *Buffer, size_t Bytes) {
                return DriverServiceEnum::ParseDrivers(Buffer, Bytes);
            });
    }

    Result<QVector<ModuleInfo>> EnumModules(DWORD Pid) override {
        return InventoryList<ModuleInfo>(
            [&](void *Out, DWORD Size, DWORD *Bytes, ULONG64 Cursor) { return Client.EnumModules(Pid, Out, Size, Bytes, Cursor); }, 4,
            [Pid](const INVENTORY_RECORD &Entry) {
                ModuleInfo Info;
                Info.Name = WireString(Entry.Name); Info.Path = WireString(Entry.Path);
                Info.BaseAddress = Entry.Address; Info.Size = Entry.SizeBytes; Info.ProcessId = Pid;
                return Info;
            });
    }

    Result<QVector<HandleInfo>> EnumHandles(DWORD Pid) override {
        return InventoryList<HandleInfo>(
            [&](void *Out, DWORD Size, DWORD *Bytes, ULONG64 Cursor) { return Client.EnumHandles(Pid, Out, Size, Bytes, Cursor); }, 3,
            [](const INVENTORY_RECORD &Entry) {
                HandleInfo Info;
                Info.Handle = reinterpret_cast<HANDLE>(Entry.Value[0]); Info.Object = Entry.Address;
                Info.GrantedAccess = static_cast<DWORD>(Entry.Value[1]); Info.ProcessId = Entry.ProcessId;
                Info.TypeName = WireString(Entry.TypeName); Info.ObjectName = WireString(Entry.Name);
                return Info;
            });
    }

    Result<QVector<WindowInfo>> EnumWindows() override {
        // Use the kernel snapshot when win32k offsets are resolved. The
        // user-mode fallback preserves enumeration on systems that cannot
        // service this optional IOCTL.
        constexpr size_t MaxDriverWindows = 8192;
        constexpr size_t PerWindowBytes = sizeof(KERNEL_WINDOW_ENUM_ENTRY) + 512;
        constexpr size_t DriverBufferSize = sizeof(ULONG) + MaxDriverWindows * PerWindowBytes;
        static_assert(DriverBufferSize <= (std::numeric_limits<DWORD>::max)());
        std::vector<BYTE> DriverBuffer(DriverBufferSize);
        DWORD DriverBytes = 0;
        if (Client.EnumWindows(DriverBuffer.data(), static_cast<DWORD>(DriverBuffer.size()), &DriverBytes)) {
            auto Parsed = DriverServiceEnum::ParseKernelWindows(DriverBuffer.data(), DriverBytes);
            if (Parsed.IsError())
                return Error<QVector<WindowInfo>>(Parsed.GetErrorCode(), Parsed.GetErrorMessage());
            return Success(Parsed.Value());
        }

        QVector<WindowInfo> Items;
        ::SetLastError(ERROR_SUCCESS);
        const BOOL Ok = ::EnumWindows([](HWND Window, LPARAM Context) -> BOOL {
            auto &List = *reinterpret_cast<QVector<WindowInfo> *>(Context);
            WindowInfo Info;
            Info.Hwnd = Window; Info.ThreadId = ::GetWindowThreadProcessId(Window, &Info.ProcessId);
            Info.Visible = ::IsWindowVisible(Window) != FALSE;
            const int Length = (std::min)(::GetWindowTextLengthW(Window), 32767);
            std::vector<WCHAR> Text(static_cast<size_t>(Length) + 1);
            const int Copied = ::GetWindowTextW(Window, Text.data(), static_cast<int>(Text.size()));
            Info.Title = QString::fromWCharArray(Text.data(), Copied);
            WCHAR Class[256] = {};
            Info.ClassName = QString::fromWCharArray(Class, ::GetClassNameW(Window, Class, 256));
            List.append(Info);
            return TRUE;
        }, reinterpret_cast<LPARAM>(&Items));
        if (!Ok) return Error<QVector<WindowInfo>>(::GetLastError());
        return Success(Items);
    }

    Result<QVector<CallbackInfo>> EnumCallbacks() override {
        return ParsedCountedList<CallbackInfo>(
            [&](void *Out, DWORD Size, DWORD *Bytes) { return Client.EnumCallbacks(Out, Size, Bytes); },
            offsetof(CALLBACK_ENUM_OUTPUT, Count), offsetof(CALLBACK_ENUM_OUTPUT, Entries),
            sizeof(CALLBACK_ENTRY),
            [](const void *Buffer, size_t Bytes) {
                return DriverServiceEnum::ParseCallbacks(Buffer, Bytes);
            });
    }

    Result<QVector<ServiceInfo>> EnumServices() override {
        ServiceHandle Scm(::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE));
        if (!Scm.Value) return Error<QVector<ServiceInfo>>(::GetLastError());
        std::vector<BYTE> Buffer(256 * 1024);
        QVector<ServiceInfo> Items;
        DWORD Cursor = 0;
        for (unsigned Page = 0; Page < 4096; ++Page) {
            DWORD Needed = 0, Count = 0, Previous = Cursor;
            const BOOL Ok = ::EnumServicesStatusExW(Scm.Value, SC_ENUM_PROCESS_INFO, SERVICE_WIN32 | SERVICE_DRIVER,
                SERVICE_STATE_ALL, Buffer.data(), static_cast<DWORD>(Buffer.size()), &Needed, &Count, &Cursor, nullptr);
            const DWORD Code = Ok ? ERROR_SUCCESS : ::GetLastError();
            if (!Ok && Code != ERROR_MORE_DATA) return Error<QVector<ServiceInfo>>(Code);
            const auto *Entries = reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW *>(Buffer.data());
            for (DWORD Index = 0; Index < Count; ++Index) {
                const auto &Entry = Entries[Index];
                ServiceInfo Info;
                Info.Name = QString::fromWCharArray(Entry.lpServiceName);
                Info.DisplayName = QString::fromWCharArray(Entry.lpDisplayName);
                Info.ServiceType = Entry.ServiceStatusProcess.dwServiceType;
                Info.CurrentState = Entry.ServiceStatusProcess.dwCurrentState;
                Info.ProcessId = Entry.ServiceStatusProcess.dwProcessId;
                Info.StartType = SERVICE_NO_CHANGE;
                ServiceHandle Service(::OpenServiceW(Scm.Value, Entry.lpServiceName, SERVICE_QUERY_CONFIG));
                if (Service.Value) {
                    DWORD ConfigSize = 0;
                    ::QueryServiceConfigW(Service.Value, nullptr, 0, &ConfigSize);
                    if (ConfigSize && ConfigSize <= 64 * 1024) {
                        std::vector<BYTE> Config(ConfigSize);
                        auto *Value = reinterpret_cast<QUERY_SERVICE_CONFIGW *>(Config.data());
                        if (::QueryServiceConfigW(Service.Value, Value, ConfigSize, &ConfigSize)) {
                            Info.ImagePath = QString::fromWCharArray(Value->lpBinaryPathName);
                            Info.StartType = Value->dwStartType;
                        }
                    }
                }
                Items.append(Info);
            }
            if (Ok) return Success(Items);
            if (!Count && Needed > Buffer.size() && Needed <= 1024 * 1024) { Buffer.resize(Needed); continue; }
            if (Cursor == Previous || !Count) return Error<QVector<ServiceInfo>>(ERROR_INVALID_DATA);
        }
        return Error<QVector<ServiceInfo>>(ERROR_RETRY);
    }

    Result<QVector<MemoryRegionInfo>> EnumMemoryRegions(DWORD Pid) override {
        return InventoryList<MemoryRegionInfo>(
            [&](void *Out, DWORD Size, DWORD *Bytes, ULONG64 Cursor) { return Client.EnumMemoryRegions(Pid, Out, Size, Bytes, Cursor); }, 10,
            [](const INVENTORY_RECORD &Entry) {
                MemoryRegionInfo Info;
                Info.BaseAddress = Entry.Address; Info.Size = Entry.SizeBytes;
                Info.State = static_cast<DWORD>(Entry.Value[2]); Info.Protection = static_cast<DWORD>(Entry.Value[3]);
                Info.Type = static_cast<DWORD>(Entry.Value[4]); Info.ProtectionString = MemoryProtectionName(Info.Protection);
                return Info;
            });
    }

    // ============================================================
    // 线程管理
    // ============================================================

    Result<void> TerminateThread(DWORD Tid) override {
        return OperationResult(Client.TerminateThread(Tid));
    }

    Result<void> SuspendThread(DWORD Tid) override {
        return OperationResult(Client.SuspendThread(Tid));
    }

    Result<void> ResumeThread(DWORD Tid) override {
        return OperationResult(Client.ResumeThread(Tid));
    }

    // ============================================================
    // 内存操作
    // ============================================================

    Result<QByteArray> ReadProcessMemory(DWORD Pid, quint64 Address, size_t Size) override {
        if (!Size || Size > 64 * 1024 * 1024) return Error<QByteArray>(ERROR_INVALID_PARAMETER);
        QByteArray Data(static_cast<qsizetype>(Size), '\0');
        if (!Client.ReadProcessMemory(Pid, Address, Data.data(), Size)) return Error<QByteArray>(Client.GetLastError());
        return Success(Data);
    }

    Result<void> WriteProcessMemory(DWORD Pid, quint64 Address, const QByteArray &Data) override {
        return OperationResult(Client.WriteProcessMemory(Pid, Address, Data.constData(), Data.size()));
    }

    Result<QByteArray> ReadKernelMemory(quint64 Address, size_t Size) override {
        if (!Size || Size > 64 * 1024 * 1024) return Error<QByteArray>(ERROR_INVALID_PARAMETER);
        QByteArray Data(static_cast<qsizetype>(Size), '\0');
        if (!Client.ReadKernelMemory(Address, Data.data(), Size)) return Error<QByteArray>(Client.GetLastError());
        return Success(Data);
    }

    Result<void> WriteKernelMemory(quint64 Address, const QByteArray &Data) override {
        return OperationResult(Client.WriteKernelMemory(Address, Data.constData(), Data.size()));
    }

    Result<quint64> AllocateMemory(DWORD Pid, size_t Size, DWORD Protection) override {
        ULONG64 Address = 0;
        if (!Client.AllocateMemory(Pid, Size, Protection, &Address)) return Error<quint64>(Client.GetLastError());
        return Success<quint64>(Address);
    }

    Result<void> FreeMemory(DWORD Pid, quint64 Address) override {
        return OperationResult(Client.FreeMemory(Pid, Address));
    }

    Result<DWORD> ProtectMemory(DWORD Pid, quint64 Address, size_t Size, DWORD NewProtection) override {
        DWORD Old = 0;
        if (!Client.ProtectMemory(Pid, Address, Size, NewProtection, &Old)) return Error<DWORD>(Client.GetLastError());
        return Success(Old);
    }

    // ============================================================
    // 驱动和模块
    // ============================================================

    Result<void> LoadDriver(const QString &Path, const QString &ServiceName) override {
        if (!ValidServiceName(ServiceName) || Path.isEmpty() || Path.contains(QChar(0)))
            return Error<void>(ERROR_INVALID_PARAMETER);
        const QFileInfo File(Path);
        if (!File.isFile()) return Error<void>(ERROR_FILE_NOT_FOUND);
        const QString FullPath = QDir::toNativeSeparators(File.absoluteFilePath());
        const std::wstring Name = ServiceName.toStdWString();
        const std::wstring Binary = (QString("\"") + FullPath + "\"").toStdWString();
        ServiceHandle Scm(::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE));
        if (!Scm.Value) return Error<void>(::GetLastError());
        SC_HANDLE Handle = ::CreateServiceW(Scm.Value, Name.c_str(), Name.c_str(),
            SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | DELETE, SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, Binary.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
        const bool Created = Handle != nullptr;
        if (!Handle) {
            if (::GetLastError() != ERROR_SERVICE_EXISTS) return Error<void>(::GetLastError());
            Handle = ::OpenServiceW(Scm.Value, Name.c_str(), SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
        }
        ServiceHandle Service(Handle);
        if (!Service.Value) return Error<void>(::GetLastError());
        if (!Created) {
            DWORD Needed = 0;
            ::QueryServiceConfigW(Service.Value, nullptr, 0, &Needed);
            if (!Needed || Needed > 64 * 1024) return Error<void>(ERROR_INVALID_DATA);
            std::vector<BYTE> Buffer(Needed);
            auto *Config = reinterpret_cast<QUERY_SERVICE_CONFIGW *>(Buffer.data());
            if (!::QueryServiceConfigW(Service.Value, Config, Needed, &Needed)) return Error<void>(::GetLastError());
            QString Existing = QString::fromWCharArray(Config->lpBinaryPathName);
            if (Existing.startsWith('"') && Existing.endsWith('"')) Existing = Existing.mid(1, Existing.size() - 2);
            if (Config->dwServiceType != SERVICE_KERNEL_DRIVER ||
                QDir::cleanPath(QDir::fromNativeSeparators(Existing)).compare(
                    QDir::cleanPath(QDir::fromNativeSeparators(FullPath)), Qt::CaseInsensitive) != 0)
                return Error<void>(ERROR_SERVICE_EXISTS, "Existing service has a different type or binary");
        }
        if (!::StartServiceW(Service.Value, 0, nullptr) && ::GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
            const DWORD Code = ::GetLastError();
            if (Created) ::DeleteService(Service.Value);
            return Error<void>(Code);
        }
        return WaitService(Service.Value, SERVICE_RUNNING);
    }

    Result<void> UnloadDriver(const QString &ServiceName) override {
        return ManageService(ServiceName, 1);
    }

    // ============================================================
    // 句柄操作
    // ============================================================

    Result<void> CloseHandle(DWORD Pid, HANDLE Handle) override {
        return OperationResult(Client.CloseRemoteHandle(Pid, Handle));
    }

    Result<HANDLE> DuplicateHandle(DWORD SourcePid, HANDLE SourceHandle, DWORD TargetPid) override {
        HANDLE Target = nullptr;
        if (!Client.DuplicateRemoteHandle(SourcePid, SourceHandle, TargetPid, &Target)) return Error<HANDLE>(Client.GetLastError());
        return Success(Target);
    }

    // ============================================================
    // 窗口操作
    // ============================================================

    Result<void> WindowOperation(HWND Window, int Operation) override {
        return OperationResult(Client.WindowOperation(Window, Operation));
    }

    Result<void> ProtectWindow(HWND Window, bool Protect) override {
        return OperationResult(Protect ? Client.ProtectWindow(Window) : Client.UnprotectWindow(Window));
    }

    // ============================================================
    // 回调管理
    // ============================================================

    Result<void> RemoveCallback(quint64 Address) override {
        return OperationResult(Client.RemoveCallback(Address));
    }

    Result<void> RemoveAllObCallbacks() override {
        return OperationResult(Client.RemoveAllObCallbacks());
    }

    Result<void> RemoveAllRegistryCallbacks() override {
        return OperationResult(Client.RemoveAllRegistryCallbacks());
    }

    // ============================================================
    // 服务管理
    // ============================================================

    Result<void> StartService(const QString &Name) override {
        return ManageService(Name, 0);
    }

    Result<void> StopService(const QString &Name) override {
        return ManageService(Name, 1);
    }

    Result<void> DeleteService(const QString &Name) override {
        return ManageService(Name, 2);
    }

    // ============================================================
    // 保护操作
    // ============================================================

    Result<void> ProtectRegistry(const QString &Path) override {
        return OperationResult(Client.ProtectRegistry(Path.toStdWString().c_str()));
    }

    Result<void> UnprotectRegistry(const QString &Path) override {
        return OperationResult(Client.UnprotectRegistry(Path.toStdWString().c_str()));
    }

    Result<void> ProtectFile(const QString &Path) override {
        return OperationResult(Client.ProtectFile(Path.toStdWString().c_str()));
    }

    Result<void> UnprotectFile(const QString &Path) override {
        return OperationResult(Client.UnprotectFile(Path.toStdWString().c_str()));
    }

    Result<void> ForceDeleteFile(const QString &Path) override {
        return OperationResult(Client.ForceDeleteFile(Path.toStdWString().c_str()));
    }

    // ============================================================
    // 注入操作
    // ============================================================

    Result<void> InjectDllApc(DWORD Pid, const QString &DllPath) override {
        return OperationResult(Client.InjectDllApc(Pid, DllPath.toStdWString().c_str()));
    }

    Result<void> InjectDllThread(DWORD Pid, const QString &DllPath) override {
        return OperationResult(Client.InjectDllThread(Pid, DllPath.toStdWString().c_str()));
    }

    // ============================================================
    // 系统操作
    // ============================================================

    Result<void> DisableDSE() override {
        return OperationResult(Client.DisableDSE());
    }

    Result<void> RestoreDSE() override {
        return OperationResult(Client.RestoreDSE());
    }

    Result<void> EnableDebug() override {
        return Result<void>::Error(ERROR_NOT_SUPPORTED, "Not implemented yet");
    }

    Result<void> DisableDebug() override {
        return Result<void>::Error(ERROR_NOT_SUPPORTED, "Not implemented yet");
    }

    Result<bool> QueryDebugState() override {
        BOOL Enabled = FALSE;
        if (!Client.QueryDebugState(&Enabled)) return Error<bool>(Client.GetLastError());
        return Success(Enabled != FALSE);
    }

    Result<void> ClearAllProtection() override {
        return OperationResult(Client.ClearAllProtection());
    }

    Result<quint64> QueryCapabilities() override {
        ULONG64 Capabilities = 0;
        if (!Client.QueryCapabilities(&Capabilities))
            return Error<quint64>(Client.GetLastError(), "Capabilities query failed");
        return Success<quint64>(Capabilities);
    }

    // ============================================================
    // 状态查询
    // ============================================================

    bool IsDriverLoaded() const override {
        SC_HANDLE Scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!Scm) return false;
        SC_HANDLE Service = OpenServiceW(Scm, L"Ring0Core", SERVICE_QUERY_STATUS);
        SERVICE_STATUS Status = {};
        const bool Loaded = Service && QueryServiceStatus(Service, &Status) &&
                            Status.dwCurrentState == SERVICE_RUNNING;
        if (Service) CloseServiceHandle(Service);
        CloseServiceHandle(Scm);
        return Loaded;
    }

    QString GetLastError() const override {
        return QString("Error code: %1").arg(LastError.load());
    }
};

// ============================================================
// 工厂函数
// ============================================================

std::unique_ptr<IDriverService> CreateDriverService() {
    return std::make_unique<DriverServiceSimple>();
}

} // namespace AegisNT
