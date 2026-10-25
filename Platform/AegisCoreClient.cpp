#include "AegisCoreClient.h"
#include "AegisCoreCall.h"
#include <limits>

namespace AegisNT {

thread_local DWORD G_LastAegisCoreError = ERROR_SUCCESS;

AegisCoreClient::AegisCoreClient()
    : m_deviceHandle(INVALID_HANDLE_VALUE), m_lastError(ERROR_SUCCESS) {}

AegisCoreClient::~AegisCoreClient() { CloseDevice(); }

bool AegisCoreClient::Fail(DWORD Error) {
    m_lastError = Error;
    G_LastAegisCoreError = Error;
    return false;
}

bool AegisCoreClient::Succeed() {
    m_lastError = G_LastAegisCoreError = ERROR_SUCCESS;
    return true;
}

namespace {
struct NativeHandle {
    HANDLE Value;
    explicit NativeHandle(HANDLE Handle) : Value(Handle) {}
    ~NativeHandle() { if (Value && Value != INVALID_HANDLE_VALUE) ::CloseHandle(Value); }
    NativeHandle(const NativeHandle &) = delete;
    NativeHandle &operator=(const NativeHandle &) = delete;
};

bool ValidMemoryRange(ULONG64 Address, SIZE_T Size) {
    return Address && Size && Address <= (std::numeric_limits<ULONG_PTR>::max)() &&
           Size <= (std::numeric_limits<ULONG_PTR>::max)() - Address;
}
}

bool AegisCoreClient::OpenDeviceLocked() {
    if (m_deviceHandle == INVALID_HANDLE_VALUE) {
        m_deviceHandle = CreateFileW(L"\\\\.\\AegisCore", GENERIC_READ | GENERIC_WRITE,
                                     0, nullptr, OPEN_EXISTING,
                                     FILE_ATTRIBUTE_NORMAL, nullptr);
        if (m_deviceHandle == INVALID_HANDLE_VALUE)
            return Fail(::GetLastError());
    }
    m_lastError = G_LastAegisCoreError = ERROR_SUCCESS;
    return true;
}

bool AegisCoreClient::OpenDevice() {
    std::lock_guard<std::mutex> Lock(::G_DeviceMutex);
    return OpenDeviceLocked();
}

void AegisCoreClient::CloseDevice() {
    std::lock_guard<std::mutex> Lock(::G_DeviceMutex);
    if (m_deviceHandle != INVALID_HANDLE_VALUE) {
        ::CloseHandle(m_deviceHandle);
        m_deviceHandle = INVALID_HANDLE_VALUE;
    }
}

bool AegisCoreClient::IsDeviceOpened() const {
    std::lock_guard<std::mutex> Lock(::G_DeviceMutex);
    return m_deviceHandle != INVALID_HANDLE_VALUE;
}

bool AegisCoreClient::DeviceIoControl(DWORD Code, void *Input, DWORD InputSize,
                                     void *Output, DWORD OutputSize,
                                     DWORD *BytesReturned) {
    std::lock_guard<std::mutex> Lock(::G_DeviceMutex);
    if (BytesReturned) *BytesReturned = 0;
    if (!OpenDeviceLocked()) return false;
    DWORD Returned = 0;
    const BOOL Success = ::DeviceIoControl(m_deviceHandle, Code, Input, InputSize,
                                         Output, OutputSize, &Returned, nullptr);
    const DWORD Error = Success ? ERROR_SUCCESS : ::GetLastError();
    // The legacy adapter also opens exclusively; do not retain a competing handle.
    ::CloseHandle(m_deviceHandle);
    m_deviceHandle = INVALID_HANDLE_VALUE;
    if (!Success) return Fail(Error);
    if (BytesReturned) *BytesReturned = Returned;
    m_lastError = G_LastAegisCoreError = ERROR_SUCCESS;
    return true;
}

bool AegisCoreClient::KillProcess(DWORD Pid) {
    KILL_PROCESS_INPUT Input = {Pid};
    return DeviceIoControl(IOCTL_KILL_PROCESS, &Input, sizeof(Input), nullptr, 0, nullptr);
}
bool AegisCoreClient::ProtectProcess(DWORD Pid) {
    PROCESS_PROTECT_INPUT Input = {Pid};
    return DeviceIoControl(IOCTL_ADD_PROCESS_PROTECT, &Input, sizeof(Input), nullptr, 0, nullptr);
}
bool AegisCoreClient::UnprotectProcess(DWORD Pid) {
    PROCESS_PROTECT_INPUT Input = {Pid};
    return DeviceIoControl(IOCTL_REMOVE_PROCESS_PROTECT, &Input, sizeof(Input), nullptr, 0, nullptr);
}
bool AegisCoreClient::SetProcessPpl(DWORD Pid, UCHAR Level) {
    PPL_CONTROL_INPUT Input = {};
    Input.ProcessId = Pid;
    Input.ProtectionType = Level;
    return DeviceIoControl(IOCTL_SET_PPL, &Input, sizeof(Input), nullptr, 0, nullptr);
}
bool AegisCoreClient::RemoveProcessPpl(DWORD Pid) {
    PPL_CONTROL_INPUT Input = {};
    Input.ProcessId = Pid;
    Input.RemoveProtection = TRUE;
    return DeviceIoControl(IOCTL_REMOVE_PPL, &Input, sizeof(Input), nullptr, 0, nullptr);
}
bool AegisCoreClient::SetProcessCritical(DWORD Pid) {
    CRITICAL_PROCESS_INPUT Input = {Pid};
    return DeviceIoControl(IOCTL_SET_CRITICAL, &Input, sizeof(Input), nullptr, 0, nullptr);
}
bool AegisCoreClient::RemoveProcessCritical(DWORD Pid) {
    CRITICAL_PROCESS_INPUT Input = {Pid};
    return DeviceIoControl(IOCTL_REMOVE_CRITICAL, &Input, sizeof(Input), nullptr, 0, nullptr);
}
bool AegisCoreClient::HideProcess(DWORD Pid) {
    CRITICAL_PROCESS_INPUT Input = {Pid};
    return DeviceIoControl(IOCTL_HIDE_PROCESS, &Input, sizeof(Input), nullptr, 0, nullptr);
}
bool AegisCoreClient::UnhideProcess(DWORD Pid) {
    CRITICAL_PROCESS_INPUT Input = {Pid};
    return DeviceIoControl(IOCTL_UNHIDE_PROCESS, &Input, sizeof(Input), nullptr, 0, nullptr);
}
bool AegisCoreClient::RemoveAllObCallbacks() {
    return DeviceIoControl(IOCTL_REMOVE_ALL_OBCALLBACKS, nullptr, 0, nullptr, 0, nullptr);
}
bool AegisCoreClient::RemoveAllRegistryCallbacks() {
    return DeviceIoControl(IOCTL_REMOVE_ALL_REGISTRYCALLBACKS, nullptr, 0, nullptr, 0, nullptr);
}
bool AegisCoreClient::ClearAllProtection() {
    return DeviceIoControl(IOCTL_CLEAR_ALL_PROTECTION, nullptr, 0, nullptr, 0, nullptr);
}

template <size_t N>
static bool CopyProtocolPath(WCHAR (&Output)[N], const wchar_t *Path) {
    if (!Path || !Path[0] || wcsnlen_s(Path, N) >= N) return false;
    return wcscpy_s(Output, N, Path) == 0;
}

bool AegisCoreClient::ProtectRegistry(const wchar_t *Path) {
    REGISTRY_PROTECT_INPUT Input = {};
    if (!CopyProtocolPath(Input.KeyPath, Path)) return Fail(ERROR_INVALID_PARAMETER);
    return DeviceIoControl(IOCTL_ADD_REGISTRY_PROTECT, &Input, sizeof(Input), nullptr, 0, nullptr);
}
bool AegisCoreClient::UnprotectRegistry(const wchar_t *Path) {
    REGISTRY_PROTECT_INPUT Input = {};
    if (!CopyProtocolPath(Input.KeyPath, Path)) return Fail(ERROR_INVALID_PARAMETER);
    return DeviceIoControl(IOCTL_REMOVE_REGISTRY_PROTECT, &Input, sizeof(Input), nullptr, 0, nullptr);
}
bool AegisCoreClient::ProtectFile(const wchar_t *Path) {
    FILE_PROTECT_INPUT Input = {};
    if (!CopyProtocolPath(Input.FilePath, Path)) return Fail(ERROR_INVALID_PARAMETER);
    return DeviceIoControl(IOCTL_ADD_FILE_PROTECT, &Input, sizeof(Input), nullptr, 0, nullptr);
}
bool AegisCoreClient::UnprotectFile(const wchar_t *Path) {
    FILE_PROTECT_INPUT Input = {};
    if (!CopyProtocolPath(Input.FilePath, Path)) return Fail(ERROR_INVALID_PARAMETER);
    return DeviceIoControl(IOCTL_REMOVE_FILE_PROTECT, &Input, sizeof(Input), nullptr, 0, nullptr);
}

AegisCoreClient &GlobalAegisCoreClient() {
    static AegisCoreClient Instance;
    return Instance;
}

bool AegisCoreClient::ForceDeleteFile(const wchar_t *Path) {
    if (!Path || !Path[0]) return Fail(ERROR_INVALID_NAME);
    std::wstring NtPath(Path);
    for (wchar_t &Character : NtPath)
        if (Character == L'/') Character = L'\\';
    if (NtPath.rfind(L"\\??\\", 0) != 0 && NtPath.rfind(L"\\Device\\", 0) != 0) {
        if (NtPath.rfind(L"\\\\?\\", 0) == 0)
            NtPath = L"\\??\\" + NtPath.substr(4);
        else if (NtPath.rfind(L"\\\\", 0) == 0)
            NtPath = L"\\??\\UNC\\" + NtPath.substr(2);
        else if (NtPath.size() >= 2 && NtPath[1] == L':')
            NtPath = L"\\??\\" + NtPath;
        else return Fail(ERROR_INVALID_NAME);
    }
    FORCE_DELETE_INPUT Input = {};
    if (!CopyProtocolPath(Input.FilePath, NtPath.c_str()))
        return Fail(ERROR_FILENAME_EXCED_RANGE);
    return DeviceIoControl(IOCTL_FORCE_DELETE_FILE, &Input, sizeof(Input), nullptr, 0, nullptr);
}

bool AegisCoreClient::ChangeProcessSuspension(DWORD Pid, bool Suspend) {
    if (!Pid) return Fail(ERROR_INVALID_PARAMETER);
    using Function = NTSTATUS(NTAPI *)(HANDLE);
    const auto Call = reinterpret_cast<Function>(::GetProcAddress(
        ::GetModuleHandleW(L"ntdll.dll"), Suspend ? "NtSuspendProcess" : "NtResumeProcess"));
    if (!Call) return Fail(ERROR_PROC_NOT_FOUND);
    NativeHandle Process(::OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, Pid));
    if (!Process.Value) return Fail(::GetLastError());
    const NTSTATUS Status = Call(Process.Value);
    return Status < 0 ? Fail(::AegisCoreNtStatusToWin32(Status)) : Succeed();
}
bool AegisCoreClient::SuspendProcess(DWORD Pid) { return ChangeProcessSuspension(Pid, true); }
bool AegisCoreClient::ResumeProcess(DWORD Pid) { return ChangeProcessSuspension(Pid, false); }

bool AegisCoreClient::EnumRaw(DWORD Code, void *Output, DWORD Size, DWORD *Returned, DWORD Minimum) {
    if (Returned) *Returned = 0;
    if (!Output || Size < Minimum) return Fail(ERROR_INVALID_PARAMETER);
    DWORD Bytes = 0;
    if (!DeviceIoControl(Code, nullptr, 0, Output, Size, &Bytes)) return false;
    if (Bytes < Minimum || Bytes > Size) return Fail(ERROR_INVALID_DATA);
    if (Returned) *Returned = Bytes;
    return true;
}

bool AegisCoreClient::EnumProcesses(void *Output, DWORD Size, DWORD *Returned) {
    return EnumRaw(IOCTL_ENUM_PROCESSES, Output, Size, Returned, sizeof(ULONG));
}

bool AegisCoreClient::ChangeThreadState(DWORD Tid, int Operation) {
    if (!Tid) return Fail(ERROR_INVALID_PARAMETER);
    NativeHandle Thread(::OpenThread(Operation == 0 ? THREAD_TERMINATE : THREAD_SUSPEND_RESUME, FALSE, Tid));
    if (!Thread.Value) return Fail(::GetLastError());
    const bool Success = Operation == 0 ? ::TerminateThread(Thread.Value, 0) != FALSE :
        (Operation == 1 ? ::SuspendThread(Thread.Value) : ::ResumeThread(Thread.Value)) != DWORD(-1);
    return Success ? Succeed() : Fail(::GetLastError());
}
bool AegisCoreClient::TerminateThread(DWORD Tid) { return ChangeThreadState(Tid, 0); }
bool AegisCoreClient::SuspendThread(DWORD Tid) { return ChangeThreadState(Tid, 1); }
bool AegisCoreClient::ResumeThread(DWORD Tid) { return ChangeThreadState(Tid, 2); }

bool AegisCoreClient::EnumInventory(DWORD Code, DWORD Pid, ULONG64 Cursor,
                                   void *Output, DWORD Size, DWORD *Returned) {
    if (Returned) *Returned = 0;
    if (!Output || Size < sizeof(INVENTORY_LIST_HEADER)) return Fail(ERROR_INVALID_PARAMETER);
    INVENTORY_QUERY_INPUT Input = {};
    Input.Size = sizeof(Input);
    Input.Version = INVENTORY_PROTOCOL_VERSION;
    Input.ProcessId = Pid;
    Input.Cursor = Cursor;
    Input.MaxEntries = (std::min<ULONG>)(INVENTORY_MAX_PAGE_RECORDS,
        static_cast<ULONG>((Size - sizeof(INVENTORY_LIST_HEADER)) / sizeof(INVENTORY_RECORD)));
    if (!Input.MaxEntries) return Fail(ERROR_INSUFFICIENT_BUFFER);
    DWORD Bytes = 0;
    if (!DeviceIoControl(Code, &Input, sizeof(Input), Output, Size, &Bytes)) return false;
    if (Bytes < sizeof(INVENTORY_LIST_HEADER) || Bytes > Size) return Fail(ERROR_INVALID_DATA);
    INVENTORY_LIST_HEADER Header;
    std::memcpy(&Header, Output, sizeof(Header));
    if (Header.Size != sizeof(Header) || Header.Version != INVENTORY_PROTOCOL_VERSION ||
        Header.ReturnedCount > Input.MaxEntries ||
        Header.ReturnedCount > (Bytes - sizeof(Header)) / sizeof(INVENTORY_RECORD) ||
        (Header.NextCursor && (Header.NextCursor <= Cursor || !Header.ReturnedCount)))
        return Fail(ERROR_INVALID_DATA);
    if (Header.Status < 0) return Fail(::AegisCoreNtStatusToWin32(Header.Status));
    const auto *Records = static_cast<const BYTE *>(Output) + sizeof(Header);
    for (ULONG Index = 0; Index < Header.ReturnedCount; ++Index) {
        INVENTORY_RECORD Record;
        std::memcpy(&Record, Records + Index * sizeof(Record), sizeof(Record));
        if (Record.Size != sizeof(Record)) return Fail(ERROR_INVALID_DATA);
        if (Record.Status < 0) return Fail(::AegisCoreNtStatusToWin32(Record.Status));
    }
    if (Returned) *Returned = Bytes;
    return true;
}

bool AegisCoreClient::EnumThreads(DWORD Pid, void *Output, DWORD Size, DWORD *Returned, ULONG64 Cursor) {
    return EnumInventory(IOCTL_ENUM_THREADS, Pid, Cursor, Output, Size, Returned);
}
bool AegisCoreClient::EnumModules(DWORD Pid, void *Output, DWORD Size, DWORD *Returned, ULONG64 Cursor) {
    return EnumInventory(IOCTL_ENUM_MODULES, Pid, Cursor, Output, Size, Returned);
}
bool AegisCoreClient::EnumHandles(DWORD Pid, void *Output, DWORD Size, DWORD *Returned, ULONG64 Cursor) {
    return EnumInventory(IOCTL_ENUM_HANDLES, Pid, Cursor, Output, Size, Returned);
}
bool AegisCoreClient::EnumMemoryRegions(DWORD Pid, void *Output, DWORD Size, DWORD *Returned, ULONG64 Cursor) {
    return EnumInventory(IOCTL_ENUM_MEMORY, Pid, Cursor, Output, Size, Returned);
}

bool AegisCoreClient::ReadProcessMemory(DWORD Pid, ULONG64 Address, void *Buffer, SIZE_T Size) {
    if (!Pid || !Buffer || !ValidMemoryRange(Address, Size)) return Fail(ERROR_INVALID_PARAMETER);
    NativeHandle Process(::OpenProcess(PROCESS_VM_READ, FALSE, Pid));
    if (!Process.Value) return Fail(::GetLastError());
    SIZE_T Bytes = 0;
    if (!::ReadProcessMemory(Process.Value, reinterpret_cast<LPCVOID>(Address), Buffer, Size, &Bytes))
        return Fail(::GetLastError());
    return Bytes == Size ? Succeed() : Fail(ERROR_PARTIAL_COPY);
}
bool AegisCoreClient::WriteProcessMemory(DWORD Pid, ULONG64 Address, const void *Buffer, SIZE_T Size) {
    if (!Pid || !Buffer || !ValidMemoryRange(Address, Size)) return Fail(ERROR_INVALID_PARAMETER);
    NativeHandle Process(::OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, Pid));
    if (!Process.Value) return Fail(::GetLastError());
    SIZE_T Bytes = 0;
    if (!::WriteProcessMemory(Process.Value, reinterpret_cast<LPVOID>(Address), Buffer, Size, &Bytes))
        return Fail(::GetLastError());
    return Bytes == Size ? Succeed() : Fail(ERROR_PARTIAL_COPY);
}
bool AegisCoreClient::AllocateMemory(DWORD Pid, SIZE_T Size, DWORD Protection, ULONG64 *Address) {
    if (Address) *Address = 0;
    if (!Pid || !Size || !Address) return Fail(ERROR_INVALID_PARAMETER);
    NativeHandle Process(::OpenProcess(PROCESS_VM_OPERATION, FALSE, Pid));
    if (!Process.Value) return Fail(::GetLastError());
    const auto Base = ::VirtualAllocEx(Process.Value, nullptr, Size, MEM_RESERVE | MEM_COMMIT, Protection);
    if (!Base) return Fail(::GetLastError());
    *Address = reinterpret_cast<ULONG64>(Base);
    return Succeed();
}
bool AegisCoreClient::FreeMemory(DWORD Pid, ULONG64 Address) {
    if (!Pid || !ValidMemoryRange(Address, 1)) return Fail(ERROR_INVALID_PARAMETER);
    NativeHandle Process(::OpenProcess(PROCESS_VM_OPERATION, FALSE, Pid));
    if (!Process.Value) return Fail(::GetLastError());
    return ::VirtualFreeEx(Process.Value, reinterpret_cast<LPVOID>(Address), 0, MEM_RELEASE) ?
        Succeed() : Fail(::GetLastError());
}
bool AegisCoreClient::ProtectMemory(DWORD Pid, ULONG64 Address, SIZE_T Size, DWORD Protection, DWORD *Old) {
    if (Old) *Old = 0;
    if (!Pid || !Old || !ValidMemoryRange(Address, Size)) return Fail(ERROR_INVALID_PARAMETER);
    NativeHandle Process(::OpenProcess(PROCESS_VM_OPERATION, FALSE, Pid));
    if (!Process.Value) return Fail(::GetLastError());
    DWORD Previous = 0;
    if (!::VirtualProtectEx(Process.Value, reinterpret_cast<LPVOID>(Address), Size, Protection, &Previous))
        return Fail(::GetLastError());
    *Old = Previous;
    return Succeed();
}

// Security-sensitive kernel mutation and injection controls are not enabled here.
bool AegisCoreClient::ReadKernelMemory(ULONG64, void *, SIZE_T) { return Fail(ERROR_NOT_SUPPORTED); }
bool AegisCoreClient::WriteKernelMemory(ULONG64, const void *, SIZE_T) { return Fail(ERROR_NOT_SUPPORTED); }
bool AegisCoreClient::EnumDrivers(void *Output, DWORD Size, DWORD *Returned) {
    if (!EnumRaw(IOCTL_ENUM_DRIVERS, Output, Size, Returned, sizeof(DRIVER_ENUM_HEADER))) return false;
    DRIVER_ENUM_HEADER Header;
    std::memcpy(&Header, Output, sizeof(Header));
    if (Header.NtStatus < 0) {
        if (Returned) *Returned = 0;
        return Fail(::AegisCoreNtStatusToWin32(Header.NtStatus));
    }
    return true;
}

bool AegisCoreClient::DuplicateRemoteHandle(DWORD SourcePid, HANDLE Source, DWORD TargetPid, HANDLE *Target) {
    if (Target) *Target = nullptr;
    if (!SourcePid || !TargetPid || !Source || Source == INVALID_HANDLE_VALUE || !Target)
        return Fail(ERROR_INVALID_PARAMETER);
    NativeHandle From(::OpenProcess(PROCESS_DUP_HANDLE, FALSE, SourcePid));
    if (!From.Value) return Fail(::GetLastError());
    NativeHandle To(::OpenProcess(PROCESS_DUP_HANDLE, FALSE, TargetPid));
    if (!To.Value) return Fail(::GetLastError());
    return ::DuplicateHandle(From.Value, Source, To.Value, Target, 0, FALSE, DUPLICATE_SAME_ACCESS) ?
        Succeed() : Fail(::GetLastError());
}
bool AegisCoreClient::CloseRemoteHandle(DWORD Pid, HANDLE Handle) {
    if (!Pid || !Handle || Handle == INVALID_HANDLE_VALUE) return Fail(ERROR_INVALID_PARAMETER);
    NativeHandle Process(::OpenProcess(PROCESS_DUP_HANDLE, FALSE, Pid));
    if (!Process.Value) return Fail(::GetLastError());
    HANDLE Copy = nullptr;
    const BOOL Success = ::DuplicateHandle(Process.Value, Handle, ::GetCurrentProcess(), &Copy,
        0, FALSE, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE);
    const DWORD Error = Success ? ERROR_SUCCESS : ::GetLastError();
    NativeHandle Local(Copy);
    return Success ? Succeed() : Fail(Error);
}
bool AegisCoreClient::EnumWindows(void *Output, DWORD Size, DWORD *Returned) {
    return EnumRaw(IOCTL_ENUM_WINDOWS, Output, Size, Returned, sizeof(ULONG));
}
bool AegisCoreClient::ProtectWindow(HWND Window) {
    WINDOW_PROTECT_INPUT Input = {};
    Input.Hwnd = reinterpret_cast<ULONG64>(Window);
    Input.Flags = WINPROT_ALL;
    if (!::GetWindowThreadProcessId(Window, &Input.ProcessId)) return Fail(ERROR_INVALID_WINDOW_HANDLE);
    return DeviceIoControl(IOCTL_ADD_WINDOW_PROTECT, &Input, sizeof(Input), nullptr, 0, nullptr);
}
bool AegisCoreClient::UnprotectWindow(HWND Window) {
    WINDOW_PROTECT_INPUT Input = {};
    Input.Hwnd = reinterpret_cast<ULONG64>(Window);
    if (!::GetWindowThreadProcessId(Window, &Input.ProcessId)) return Fail(ERROR_INVALID_WINDOW_HANDLE);
    return DeviceIoControl(IOCTL_REMOVE_WINDOW_PROTECT, &Input, sizeof(Input), nullptr, 0, nullptr);
}
bool AegisCoreClient::WindowOperation(HWND Window, int Operation) {
    if (!::IsWindow(Window)) return Fail(ERROR_INVALID_WINDOW_HANDLE);
    // This interface has no arguments for title, position or size changes.
    BOOL Success = FALSE;
    switch (Operation) {
    case 0: Success = ::PostMessageW(Window, WM_CLOSE, 0, 0); break;
    case 1: case 2: case 4: case 5: case 14:
        Success = ::ShowWindowAsync(Window, Operation == 1 ? SW_HIDE : Operation == 2 ? SW_SHOW :
            Operation == 4 ? SW_MINIMIZE : Operation == 5 ? SW_RESTORE : SW_MAXIMIZE); break;
    case 8: case 9:
        ::EnableWindow(Window, Operation == 8);
        return ::IsWindowEnabled(Window) == (Operation == 8) ? Succeed() : Fail(ERROR_ACCESS_DENIED);
    case 10: case 11:
        Success = ::SetWindowPos(Window, Operation == 10 ? HWND_TOPMOST : HWND_NOTOPMOST,
            0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE); break;
    case 12: {
        FLASHWINFO Info = {sizeof(Info), Window, FLASHW_ALL, 3, 0};
        ::FlashWindowEx(&Info);
        return Succeed();
    }
    case 13: Success = ::RedrawWindow(Window, nullptr, nullptr, RDW_INVALIDATE | RDW_ALLCHILDREN); break;
    case 15: {
        DWORD_PTR Reply = 0;
        ::SetLastError(ERROR_SUCCESS);
        Success = ::SendMessageTimeoutW(Window, WM_NULL, 0, 0, SMTO_ABORTIFHUNG, 1000, &Reply) != 0;
        if (!Success) return Fail(::GetLastError() ? ::GetLastError() : ERROR_TIMEOUT);
        break;
    }
    default: return Fail(ERROR_INVALID_PARAMETER);
    }
    return Success ? Succeed() : Fail(::GetLastError() ? ::GetLastError() : ERROR_GEN_FAILURE);
}
bool AegisCoreClient::EnumCallbacks(void *Output, DWORD Size, DWORD *Returned) {
    return EnumRaw(IOCTL_ENUM_CALLBACKS, Output, Size, Returned, sizeof(ULONG));
}
bool AegisCoreClient::RemoveCallback(ULONG64) { return Fail(ERROR_NOT_SUPPORTED); }
bool AegisCoreClient::InjectDllApc(DWORD, const wchar_t *) { return Fail(ERROR_NOT_SUPPORTED); }
bool AegisCoreClient::InjectDllThread(DWORD, const wchar_t *) { return Fail(ERROR_NOT_SUPPORTED); }
bool AegisCoreClient::DisableDSE() { return Fail(ERROR_NOT_SUPPORTED); }
bool AegisCoreClient::RestoreDSE() { return Fail(ERROR_NOT_SUPPORTED); }
bool AegisCoreClient::EnableDebug() { return Fail(ERROR_NOT_SUPPORTED); }
bool AegisCoreClient::DisableDebug() { return Fail(ERROR_NOT_SUPPORTED); }
bool AegisCoreClient::QueryDebugState(BOOL *State) {
    if (!State) return Fail(ERROR_INVALID_PARAMETER);
    *State = FALSE;
    DEBUG_STATE_OUTPUT Output = {};
    DWORD Returned = 0;
    if (!DeviceIoControl(IOCTL_QUERY_DEBUG_STATE, nullptr, 0, &Output, sizeof(Output), &Returned)) return false;
    if (Returned != sizeof(Output)) return Fail(ERROR_INVALID_DATA);
    if (Output.Status != 0) return Fail(::AegisCoreNtStatusToWin32(Output.Status));
    *State = Output.IsDebuggerEnabled != FALSE;
    return true;
}
bool AegisCoreClient::QueryCapabilities(ULONG64 *Capabilities) {
    if (!Capabilities) return Fail(ERROR_INVALID_PARAMETER);
    *Capabilities = 0;
    INVENTORY_CAPABILITIES_OUTPUT Output = {};
    DWORD Returned = 0;
    if (!DeviceIoControl(IOCTL_QUERY_CAPABILITIES, nullptr, 0,
                         &Output, sizeof(Output), &Returned)) return false;
    if (Returned != sizeof(Output) || Output.Header.Version != INVENTORY_PROTOCOL_VERSION)
        return Fail(ERROR_INVALID_DATA);
    if (Output.Header.Status != 0)
        return Fail(::AegisCoreNtStatusToWin32(Output.Header.Status));
    *Capabilities = Output.StableCapabilities;
    return true;
}

} // namespace AegisNT
