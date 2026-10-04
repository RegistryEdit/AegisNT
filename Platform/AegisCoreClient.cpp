#include "AegisCoreClient.h"
#include <mutex>

namespace AegisNT {

// 全局错误变量（后向兼容）
DWORD G_LastAegisCoreError = 0;

static std::mutex g_deviceMutex;

AegisCoreClient::AegisCoreClient()
    : m_deviceHandle(INVALID_HANDLE_VALUE), m_lastError(0) {}

AegisCoreClient::~AegisCoreClient() {
    CloseDevice();
}

bool AegisCoreClient::OpenDevice() {
    std::lock_guard<std::mutex> lock(g_deviceMutex);

    if (m_deviceHandle != INVALID_HANDLE_VALUE)
        return true;

    m_deviceHandle = CreateFileW(
        L"\\\\.\\AegisCore",
        GENERIC_READ | GENERIC_WRITE,
        0, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);

    if (m_deviceHandle == INVALID_HANDLE_VALUE) {
        m_lastError = ::GetLastError();
        G_LastAegisCoreError = m_lastError;
        return false;
    }

    return true;
}

void AegisCoreClient::CloseDevice() {
    std::lock_guard<std::mutex> lock(g_deviceMutex);

    if (m_deviceHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(m_deviceHandle);
        m_deviceHandle = INVALID_HANDLE_VALUE;
    }
}

bool AegisCoreClient::IsDeviceOpened() const {
    return m_deviceHandle != INVALID_HANDLE_VALUE;
}

bool AegisCoreClient::DeviceIoControl(DWORD IoControlCode,
                                     void *InputBuffer, DWORD InputSize,
                                     void *OutputBuffer, DWORD OutputSize,
                                     DWORD *BytesReturned) {
    if (!IsDeviceOpened()) {
        if (!OpenDevice()) {
            return false;
        }
    }

    DWORD bytesRet = 0;
    BOOL result = ::DeviceIoControl(
        m_deviceHandle,
        IoControlCode,
        InputBuffer, InputSize,
        OutputBuffer, OutputSize,
        &bytesRet, nullptr);

    if (BytesReturned)
        *BytesReturned = bytesRet;

    if (!result) {
        m_lastError = ::GetLastError();
        G_LastAegisCoreError = m_lastError;
    }

    return result != FALSE;
}

// 进程操作实现
bool AegisCoreClient::KillProcess(DWORD Pid) {
    DWORD input = Pid;
    return DeviceIoControl(
        CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS),
        &input, sizeof(input),
        nullptr, 0, nullptr);
}

bool AegisCoreClient::ProtectProcess(DWORD Pid) {
    DWORD input = Pid;
    return DeviceIoControl(
        CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS),
        &input, sizeof(input),
        nullptr, 0, nullptr);
}

bool AegisCoreClient::UnprotectProcess(DWORD Pid) {
    DWORD input = Pid;
    return DeviceIoControl(
        CTL_CODE(0x8000, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS),
        &input, sizeof(input),
        nullptr, 0, nullptr);
}

bool AegisCoreClient::SetProcessPpl(DWORD Pid, UCHAR Level) {
    struct {
        DWORD Pid;
        UCHAR Level;
    } input = { Pid, Level };

    return DeviceIoControl(
        CTL_CODE(0x8000, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS),
        &input, sizeof(input),
        nullptr, 0, nullptr);
}

bool AegisCoreClient::RemoveProcessPpl(DWORD Pid) {
    DWORD input = Pid;
    return DeviceIoControl(
        CTL_CODE(0x8000, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS),
        &input, sizeof(input),
        nullptr, 0, nullptr);
}

bool AegisCoreClient::SetProcessCritical(DWORD Pid) {
    DWORD input = Pid;
    return DeviceIoControl(
        CTL_CODE(0x8000, 0x816, METHOD_BUFFERED, FILE_ANY_ACCESS),
        &input, sizeof(input),
        nullptr, 0, nullptr);
}

bool AegisCoreClient::RemoveProcessCritical(DWORD Pid) {
    DWORD input = Pid;
    return DeviceIoControl(
        CTL_CODE(0x8000, 0x817, METHOD_BUFFERED, FILE_ANY_ACCESS),
        &input, sizeof(input),
        nullptr, 0, nullptr);
}

bool AegisCoreClient::HideProcess(DWORD Pid) {
    DWORD input = Pid;
    return DeviceIoControl(
        CTL_CODE(0x8000, 0x818, METHOD_BUFFERED, FILE_ANY_ACCESS),
        &input, sizeof(input),
        nullptr, 0, nullptr);
}

bool AegisCoreClient::UnhideProcess(DWORD Pid) {
    DWORD input = Pid;
    return DeviceIoControl(
        CTL_CODE(0x8000, 0x819, METHOD_BUFFERED, FILE_ANY_ACCESS),
        &input, sizeof(input),
        nullptr, 0, nullptr);
}

bool AegisCoreClient::RemoveAllObCallbacks() {
    return DeviceIoControl(
        CTL_CODE(0x8000, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS),
        nullptr, 0, nullptr, 0, nullptr);
}

bool AegisCoreClient::RemoveAllRegistryCallbacks() {
    return DeviceIoControl(
        CTL_CODE(0x8000, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS),
        nullptr, 0, nullptr, 0, nullptr);
}

bool AegisCoreClient::ClearAllProtection() {
    return DeviceIoControl(
        CTL_CODE(0x8000, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS),
        nullptr, 0, nullptr, 0, nullptr);
}

bool AegisCoreClient::DisableDSE() {
    return DeviceIoControl(
        CTL_CODE(0x8000, 0x850, METHOD_BUFFERED, FILE_ANY_ACCESS),
        nullptr, 0, nullptr, 0, nullptr);
}

bool AegisCoreClient::RestoreDSE() {
    return DeviceIoControl(
        CTL_CODE(0x8000, 0x851, METHOD_BUFFERED, FILE_ANY_ACCESS),
        nullptr, 0, nullptr, 0, nullptr);
}

// 注册表/文件保护
bool AegisCoreClient::ProtectRegistry(const wchar_t *KeyPath) {
    size_t len = wcslen(KeyPath) * sizeof(wchar_t);
    return DeviceIoControl(
        CTL_CODE(0x8000, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS),
        (void*)KeyPath, static_cast<DWORD>(len),
        nullptr, 0, nullptr);
}

bool AegisCoreClient::UnprotectRegistry(const wchar_t *KeyPath) {
    size_t len = wcslen(KeyPath) * sizeof(wchar_t);
    return DeviceIoControl(
        CTL_CODE(0x8000, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS),
        (void*)KeyPath, static_cast<DWORD>(len),
        nullptr, 0, nullptr);
}

bool AegisCoreClient::ProtectFile(const wchar_t *FilePath) {
    size_t len = wcslen(FilePath) * sizeof(wchar_t);
    return DeviceIoControl(
        CTL_CODE(0x8000, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS),
        (void*)FilePath, static_cast<DWORD>(len),
        nullptr, 0, nullptr);
}

bool AegisCoreClient::UnprotectFile(const wchar_t *FilePath) {
    size_t len = wcslen(FilePath) * sizeof(wchar_t);
    return DeviceIoControl(
        CTL_CODE(0x8000, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS),
        (void*)FilePath, static_cast<DWORD>(len),
        nullptr, 0, nullptr);
}

bool AegisCoreClient::ForceDeleteFile(const wchar_t *FilePath) {
    size_t len = wcslen(FilePath) * sizeof(wchar_t);
    return DeviceIoControl(
        CTL_CODE(0x8000, 0x81A, METHOD_BUFFERED, FILE_ANY_ACCESS),
        (void*)FilePath, static_cast<DWORD>(len),
        nullptr, 0, nullptr);
}

// 全局实例
AegisCoreClient &GlobalAegisCoreClient() {
    static AegisCoreClient instance;
    return instance;
}

// 占位符实现（完整实现需要解析驱动返回数据）
bool AegisCoreClient::SuspendProcess(DWORD Pid) { return false; }
bool AegisCoreClient::ResumeProcess(DWORD Pid) { return false; }
bool AegisCoreClient::EnumProcesses(void *OutputBuffer, DWORD OutputSize, DWORD *BytesReturned) { return false; }
bool AegisCoreClient::TerminateThread(DWORD Tid) { return false; }
bool AegisCoreClient::EnumThreads(DWORD Pid, void *OutputBuffer, DWORD OutputSize, DWORD *BytesReturned) { return false; }
bool AegisCoreClient::ReadProcessMemory(DWORD Pid, ULONG64 Address, void *Buffer, SIZE_T Size) { return false; }
bool AegisCoreClient::WriteProcessMemory(DWORD Pid, ULONG64 Address, const void *Buffer, SIZE_T Size) { return false; }
bool AegisCoreClient::ReadKernelMemory(ULONG64 Address, void *Buffer, SIZE_T Size) { return false; }
bool AegisCoreClient::WriteKernelMemory(ULONG64 Address, const void *Buffer, SIZE_T Size) { return false; }
bool AegisCoreClient::EnumDrivers(void *OutputBuffer, DWORD OutputSize, DWORD *BytesReturned) { return false; }
bool AegisCoreClient::EnumModules(DWORD Pid, void *OutputBuffer, DWORD OutputSize, DWORD *BytesReturned) { return false; }
bool AegisCoreClient::EnumHandles(DWORD Pid, void *OutputBuffer, DWORD OutputSize, DWORD *BytesReturned) { return false; }
bool AegisCoreClient::CloseRemoteHandle(DWORD Pid, HANDLE Handle) { return false; }
bool AegisCoreClient::EnumWindows(void *OutputBuffer, DWORD OutputSize, DWORD *BytesReturned) { return false; }
bool AegisCoreClient::ProtectWindow(HWND Hwnd) { return false; }
bool AegisCoreClient::UnprotectWindow(HWND Hwnd) { return false; }
bool AegisCoreClient::EnumCallbacks(void *OutputBuffer, DWORD OutputSize, DWORD *BytesReturned) { return false; }
bool AegisCoreClient::RemoveCallback(ULONG64 Address) { return false; }
bool AegisCoreClient::InjectDllApc(DWORD Pid, const wchar_t *DllPath) { return false; }
bool AegisCoreClient::InjectDllThread(DWORD Pid, const wchar_t *DllPath) { return false; }
bool AegisCoreClient::EnableDebug() { return false; }
bool AegisCoreClient::DisableDebug() { return false; }
bool AegisCoreClient::QueryDebugState(BOOL *State) { return false; }
bool AegisCoreClient::QueryCapabilities(ULONG64 *Capabilities) { return false; }

} // namespace AegisNT
