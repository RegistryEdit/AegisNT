#pragma once

#include <QString>
#include <QStringList>
#include <atomic>
#include <string>
#include <vector>
#include <windows.h>
#include "../../../Module/ModuleBase.h"

namespace AegisNT {

// 模块选项
struct ModuleOption {
    std::string Name;
    std::string Type;
    std::string Value;
    std::string Default;
    std::string Description;
    bool Required = false;
};

// 模块条目
struct ModuleEntry {
    std::string Name;
    std::string Path;
    std::string Category;
    std::string Description;
    std::string Author;
    std::string ServiceName;
    std::vector<ModuleOption> Options;

    HMODULE Handle = nullptr;
    void *ModuleInstance = nullptr;
    bool Loaded = false;
    bool Valid = false;
};

/**
 * ModuleService - 模块管理服务
 *
 * 职责：
 * - DLL 模块的扫描、加载、卸载
 * - 驱动服务的加载、卸载、状态查询
 * - 模块运行时管理（后台线程执行）
 * - 模块输出捕获
 */
class ModuleService {
public:
    ModuleService();
    ~ModuleService();

    // 模块扫描
    void ScanRuntimeModules();
    void EnsureModulesScanned();
    bool IsModulesScanned() const { return ModulesScanned; }

    // DLL 模块访问
    const std::vector<ModuleEntry> &GetDllModules() const { return DllModules; }
    std::vector<ModuleEntry> &GetDllModules() { return DllModules; }

    ModuleEntry *FindDllModule(const QString &Path);
    const ModuleEntry *FindDllModule(const QString &Path) const;

    // 驱动模块访问
    const std::vector<ModuleEntry> &GetDriverModules() const { return DriverModules; }
    std::vector<ModuleEntry> &GetDriverModules() { return DriverModules; }

    ModuleEntry *FindDriverModule(const QString &Path);
    const ModuleEntry *FindDriverModule(const QString &Path) const;

    // DLL 模块操作
    bool LoadModuleInstance(ModuleEntry &Module, QString *Error = nullptr);
    void DestroyModuleInstance(ModuleEntry &Module);
    ModuleEntry ProbeModuleFile(const QString &Path);

    // 驱动服务操作
    bool SetDriverLoaded(ModuleEntry &Module, bool Loaded, QString *Error = nullptr);
    bool QueryDriverLoadedState(ModuleEntry &Module);

    // 模块运行状态
    bool IsModuleRunning() const { return ModuleRunning.load(); }
    void SetModuleRunning(bool Running) { ModuleRunning.store(Running); }

    QString GetRunningModulePath() const { return RunningModulePath; }
    void SetRunningModulePath(const QString &Path) { RunningModulePath = Path; }

    // SEH 保护的模块调用
    bool InvokeModuleWithSeh(ModuleBase *Instance, bool *Result,
                            DWORD *ExceptionCode);
    bool InvokeModuleCheckWithSeh(ModuleBase *Instance, bool *Result,
                                  DWORD *ExceptionCode);

    // 模块选项管理
    QString GetCachedModuleOptionValue(const ModuleEntry &Module,
                                      const QStringList &Aliases) const;
    void SetCachedModuleOptionValue(ModuleEntry &Module,
                                   const QStringList &Aliases,
                                   const QString &Value);

    // 清理
    void CleanupManagedDriversOnExit();

private:
    std::vector<ModuleEntry> DllModules;
    std::vector<ModuleEntry> DriverModules;
    std::atomic_bool ModuleRunning{false};
    bool ModulesScanned = false;
    QString RunningModulePath;

    // 辅助函数
    QString NormalizedServiceName(QString Name) const;
    bool OptionNameMatches(const std::string &Name, const QStringList &Aliases) const;
};

// 全局实例访问
ModuleService &GlobalModuleService();

} // namespace AegisNT
