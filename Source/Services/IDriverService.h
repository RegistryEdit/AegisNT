#pragma once

#include "../Models/CoreModels.h"
#include <QString>
#include <QVector>
#include <memory>

namespace AegisNT {

/**
 * IDriverService - 驱动服务接口
 *
 * 抽象了与 Ring0Core 驱动的所有交互，提供类型安全的操作接口。
 * UI 层通过此接口与驱动通信，便于测试和模拟。
 */
class IDriverService {
public:
    virtual ~IDriverService() = default;

    // ============================================================
    // 进程管理
    // ============================================================

    /**
     * 枚举所有进程
     */
    virtual Result<QVector<ProcessInfo>> EnumProcesses() = 0;

    /**
     * 终止进程
     */
    virtual Result<void> KillProcess(DWORD Pid) = 0;

    /**
     * 挂起进程
     */
    virtual Result<void> SuspendProcess(DWORD Pid) = 0;

    /**
     * 恢复进程
     */
    virtual Result<void> ResumeProcess(DWORD Pid) = 0;

    /**
     * 添加进程保护
     */
    virtual Result<void> ProtectProcess(DWORD Pid) = 0;

    /**
     * 移除进程保护
     */
    virtual Result<void> UnprotectProcess(DWORD Pid) = 0;

    /**
     * 设置进程 PPL
     */
    virtual Result<void> SetProcessPpl(DWORD Pid, UCHAR PplLevel) = 0;

    /**
     * 移除进程 PPL
     */
    virtual Result<void> RemoveProcessPpl(DWORD Pid) = 0;

    /**
     * 设置关键进程
     */
    virtual Result<void> SetProcessCritical(DWORD Pid, bool Critical) = 0;

    /**
     * 隐藏/显示进程
     */
    virtual Result<void> HideProcess(DWORD Pid, bool Hide) = 0;

    // ============================================================
    // 线程管理
    // ============================================================

    /**
     * 枚举进程的线程
     */
    virtual Result<QVector<ThreadInfo>> EnumThreads(DWORD Pid) = 0;

    /**
     * 终止线程
     */
    virtual Result<void> TerminateThread(DWORD Tid) = 0;

    /**
     * 挂起线程
     */
    virtual Result<void> SuspendThread(DWORD Tid) = 0;

    /**
     * 恢复线程
     */
    virtual Result<void> ResumeThread(DWORD Tid) = 0;

    // ============================================================
    // 内存操作
    // ============================================================

    /**
     * 读取进程内存
     */
    virtual Result<QByteArray> ReadProcessMemory(DWORD Pid, quint64 Address,
                                                 size_t Size) = 0;

    /**
     * 写入进程内存
     */
    virtual Result<void> WriteProcessMemory(DWORD Pid, quint64 Address,
                                           const QByteArray &Data) = 0;

    /**
     * 读取内核内存
     */
    virtual Result<QByteArray> ReadKernelMemory(quint64 Address, size_t Size) = 0;

    /**
     * 写入内核内存
     */
    virtual Result<void> WriteKernelMemory(quint64 Address,
                                          const QByteArray &Data) = 0;

    /**
     * 枚举进程内存区域
     */
    virtual Result<QVector<MemoryRegionInfo>> EnumMemoryRegions(DWORD Pid) = 0;

    /**
     * 分配进程内存
     */
    virtual Result<quint64> AllocateMemory(DWORD Pid, size_t Size,
                                          DWORD Protection) = 0;

    /**
     * 释放进程内存
     */
    virtual Result<void> FreeMemory(DWORD Pid, quint64 Address) = 0;

    /**
     * 修改内存保护
     */
    virtual Result<DWORD> ProtectMemory(DWORD Pid, quint64 Address,
                                        size_t Size, DWORD NewProtection) = 0;

    // ============================================================
    // 驱动管理
    // ============================================================

    /**
     * 枚举内核驱动
     */
    virtual Result<QVector<DriverInfo>> EnumDrivers() = 0;

    /**
     * 加载驱动
     */
    virtual Result<void> LoadDriver(const QString &DriverPath,
                                   const QString &ServiceName) = 0;

    /**
     * 卸载驱动
     */
    virtual Result<void> UnloadDriver(const QString &ServiceName) = 0;

    // ============================================================
    // 模块管理
    // ============================================================

    /**
     * 枚举进程模块
     */
    virtual Result<QVector<ModuleInfo>> EnumModules(DWORD Pid) = 0;

    // ============================================================
    // 句柄管理
    // ============================================================

    /**
     * 枚举进程句柄
     */
    virtual Result<QVector<HandleInfo>> EnumHandles(DWORD Pid) = 0;

    /**
     * 关闭句柄
     */
    virtual Result<void> CloseHandle(DWORD Pid, HANDLE Handle) = 0;

    /**
     * 复制句柄
     */
    virtual Result<HANDLE> DuplicateHandle(DWORD SourcePid, HANDLE SourceHandle,
                                          DWORD TargetPid) = 0;

    // ============================================================
    // 窗口管理
    // ============================================================

    /**
     * 枚举所有窗口
     */
    virtual Result<QVector<WindowInfo>> EnumWindows() = 0;

    /**
     * 窗口操作（显示/隐藏/最小化/最大化/关闭）
     */
    virtual Result<void> WindowOperation(HWND Hwnd, int Operation) = 0;

    /**
     * 保护/取消保护窗口
     */
    virtual Result<void> ProtectWindow(HWND Hwnd, bool Protect) = 0;

    // ============================================================
    // 回调管理
    // ============================================================

    /**
     * 枚举内核回调
     */
    virtual Result<QVector<CallbackInfo>> EnumCallbacks() = 0;

    /**
     * 移除回调
     */
    virtual Result<void> RemoveCallback(quint64 Address) = 0;

    /**
     * 移除所有 ObCallback
     */
    virtual Result<void> RemoveAllObCallbacks() = 0;

    /**
     * 移除所有注册表回调
     */
    virtual Result<void> RemoveAllRegistryCallbacks() = 0;

    // ============================================================
    // 服务管理
    // ============================================================

    /**
     * 枚举系统服务
     */
    virtual Result<QVector<ServiceInfo>> EnumServices() = 0;

    /**
     * 启动服务
     */
    virtual Result<void> StartService(const QString &ServiceName) = 0;

    /**
     * 停止服务
     */
    virtual Result<void> StopService(const QString &ServiceName) = 0;

    /**
     * 删除服务
     */
    virtual Result<void> DeleteService(const QString &ServiceName) = 0;

    // ============================================================
    // 注册表操作
    // ============================================================

    /**
     * 添加注册表保护
     */
    virtual Result<void> ProtectRegistry(const QString &KeyPath) = 0;

    /**
     * 移除注册表保护
     */
    virtual Result<void> UnprotectRegistry(const QString &KeyPath) = 0;

    // ============================================================
    // 文件操作
    // ============================================================

    /**
     * 添加文件保护
     */
    virtual Result<void> ProtectFile(const QString &FilePath) = 0;

    /**
     * 移除文件保护
     */
    virtual Result<void> UnprotectFile(const QString &FilePath) = 0;

    /**
     * 强制删除文件
     */
    virtual Result<void> ForceDeleteFile(const QString &FilePath) = 0;

    // ============================================================
    // DLL 注入
    // ============================================================

    /**
     * APC 注入 DLL
     */
    virtual Result<void> InjectDllApc(DWORD Pid, const QString &DllPath) = 0;

    /**
     * 线程注入 DLL
     */
    virtual Result<void> InjectDllThread(DWORD Pid, const QString &DllPath) = 0;

    // ============================================================
    // 系统调试
    // ============================================================

    /**
     * 禁用 DSE（驱动签名强制）
     */
    virtual Result<void> DisableDSE() = 0;

    /**
     * 恢复 DSE
     */
    virtual Result<void> RestoreDSE() = 0;

    /**
     * 启用调试模式
     */
    virtual Result<void> EnableDebug() = 0;

    /**
     * 禁用调试模式
     */
    virtual Result<void> DisableDebug() = 0;

    /**
     * 查询调试状态
     */
    virtual Result<bool> QueryDebugState() = 0;

    // ============================================================
    // 其他
    // ============================================================

    /**
     * 清除所有保护
     */
    virtual Result<void> ClearAllProtection() = 0;

    /**
     * 查询驱动能力
     */
    virtual Result<quint64> QueryCapabilities() = 0;

    /**
     * 检查驱动是否已加载
     */
    virtual bool IsDriverLoaded() const = 0;

    /**
     * 获取最后的错误信息
     */
    virtual QString GetLastError() const = 0;
};

/**
 * 创建驱动服务实例
 */
std::unique_ptr<IDriverService> CreateDriverService();

} // namespace AegisNT
