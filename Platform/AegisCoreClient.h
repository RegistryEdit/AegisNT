#pragma once

#include "../Models/CoreModels.h"
#include <QString>
#include <QVector>
#include <windows.h>

namespace AegisNT {

/**
 * AegisCoreClient - Platform 层客户端
 *
 * 封装与 Ring0Core 驱动的所有 IOCTL 通信
 * 将原本 4710 行的内联头文件拆分为声明和实现
 */
class AegisCoreClient {
public:
    AegisCoreClient();
    ~AegisCoreClient();

    // 连接管理
    bool OpenDevice();
    void CloseDevice();
    bool IsDeviceOpened() const;

    // 进程操作
    bool KillProcess(DWORD Pid);
    bool SuspendProcess(DWORD Pid);
    bool ResumeProcess(DWORD Pid);
    bool ProtectProcess(DWORD Pid);
    bool UnprotectProcess(DWORD Pid);
    bool SetProcessPpl(DWORD Pid, UCHAR Level);
    bool RemoveProcessPpl(DWORD Pid);
    bool SetProcessCritical(DWORD Pid);
    bool RemoveProcessCritical(DWORD Pid);
    bool HideProcess(DWORD Pid);
    bool UnhideProcess(DWORD Pid);

    // 进程枚举
    bool EnumProcesses(void *OutputBuffer, DWORD OutputSize, DWORD *BytesReturned);

    // 线程操作
    bool TerminateThread(DWORD Tid);
    bool EnumThreads(DWORD Pid, void *OutputBuffer, DWORD OutputSize, DWORD *BytesReturned);

    // 内存操作
    bool ReadProcessMemory(DWORD Pid, ULONG64 Address, void *Buffer, SIZE_T Size);
    bool WriteProcessMemory(DWORD Pid, ULONG64 Address, const void *Buffer, SIZE_T Size);
    bool ReadKernelMemory(ULONG64 Address, void *Buffer, SIZE_T Size);
    bool WriteKernelMemory(ULONG64 Address, const void *Buffer, SIZE_T Size);

    // 驱动操作
    bool EnumDrivers(void *OutputBuffer, DWORD OutputSize, DWORD *BytesReturned);

    // 模块操作
    bool EnumModules(DWORD Pid, void *OutputBuffer, DWORD OutputSize, DWORD *BytesReturned);

    // 句柄操作
    bool EnumHandles(DWORD Pid, void *OutputBuffer, DWORD OutputSize, DWORD *BytesReturned);
    bool CloseRemoteHandle(DWORD Pid, HANDLE Handle);

    // 窗口操作
    bool EnumWindows(void *OutputBuffer, DWORD OutputSize, DWORD *BytesReturned);
    bool ProtectWindow(HWND Hwnd);
    bool UnprotectWindow(HWND Hwnd);

    // 回调操作
    bool EnumCallbacks(void *OutputBuffer, DWORD OutputSize, DWORD *BytesReturned);
    bool RemoveCallback(ULONG64 Address);
    bool RemoveAllObCallbacks();
    bool RemoveAllRegistryCallbacks();

    // 注册表保护
    bool ProtectRegistry(const wchar_t *KeyPath);
    bool UnprotectRegistry(const wchar_t *KeyPath);

    // 文件保护
    bool ProtectFile(const wchar_t *FilePath);
    bool UnprotectFile(const wchar_t *FilePath);
    bool ForceDeleteFile(const wchar_t *FilePath);

    // DLL 注入
    bool InjectDllApc(DWORD Pid, const wchar_t *DllPath);
    bool InjectDllThread(DWORD Pid, const wchar_t *DllPath);

    // 系统控制
    bool DisableDSE();
    bool RestoreDSE();
    bool EnableDebug();
    bool DisableDebug();
    bool QueryDebugState(BOOL *State);

    // 其他
    bool ClearAllProtection();
    bool QueryCapabilities(ULONG64 *Capabilities);

    // 错误处理
    DWORD GetLastError() const { return m_lastError; }

private:
    // 通用 IOCTL 调用
    bool DeviceIoControl(DWORD IoControlCode,
                        void *InputBuffer, DWORD InputSize,
                        void *OutputBuffer, DWORD OutputSize,
                        DWORD *BytesReturned);

    HANDLE m_deviceHandle;
    DWORD m_lastError;
};

// 全局客户端实例
AegisCoreClient &GlobalAegisCoreClient();

// 后向兼容：保留旧的全局变量名
extern DWORD G_LastAegisCoreError;

} // namespace AegisNT
