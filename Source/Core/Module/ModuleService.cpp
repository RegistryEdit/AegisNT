#include "ModuleService.h"
#include "../Configuration/ConfigurationManager.h"
// #include "../../Platform/DriverControl.h"
#include <QDir>
#include <QFileInfo>

namespace AegisNT {

// 外部函数声明（来自 Platform 层）
extern DWORD LoadDriverService(LPCWSTR DriverPath, LPCWSTR ServiceName);
extern DWORD UnloadDriverService(LPCWSTR ServiceName);
extern BOOL IsDriverServiceRunning(LPCWSTR ServiceName);

// 辅助函数：UTF-8 转换
static std::string Utf8Bytes(const QString &Str) {
    return Str.toUtf8().toStdString();
}

static QString ResolveRuntimePath(const QString &Path) {
    if (QFileInfo(Path).isAbsolute())
        return Path;
    return QDir::current().absoluteFilePath(Path);
}

ModuleService::ModuleService() = default;

ModuleService::~ModuleService() {
    // 清理加载的模块
    for (ModuleEntry &Module : DllModules)
        DestroyModuleInstance(Module);
}

QString ModuleService::NormalizedServiceName(QString Name) const {
    if (Name.isEmpty())
        Name = "Driver";
    for (QChar &Character : Name) {
        if (!Character.isLetterOrNumber() && Character != '_' && Character != '-')
            Character = '_';
    }
    return Name.left(120);
}

bool ModuleService::OptionNameMatches(const std::string &Name,
                                     const QStringList &Aliases) const {
    const QString CurrentName = QString::fromStdString(Name);
    for (const QString &Alias : Aliases) {
        if (CurrentName.compare(Alias, Qt::CaseInsensitive) == 0)
            return true;
    }
    return false;
}

QString ModuleService::GetCachedModuleOptionValue(const ModuleEntry &Module,
                                                 const QStringList &Aliases) const {
    for (const ModuleOption &Option : Module.Options) {
        if (OptionNameMatches(Option.Name, Aliases))
            return QString::fromStdString(Option.Value);
    }
    return {};
}

void ModuleService::SetCachedModuleOptionValue(ModuleEntry &Module,
                                              const QStringList &Aliases,
                                              const QString &Value) {
    for (ModuleOption &Option : Module.Options) {
        if (OptionNameMatches(Option.Name, Aliases))
            Option.Value = Utf8Bytes(Value);
    }
    // 暂时禁用 ModuleBase
    /*
    if (Module.ModuleInstance) {
        auto *Instance = static_cast<ModuleBase *>(Module.ModuleInstance);
        for (const auto &[Name, OptionPointer] : Instance->GetOptions()) {
            Q_UNUSED(OptionPointer);
            if (OptionNameMatches(Name, Aliases))
                Instance->SetOption(Name, Utf8Bytes(Value));
        }
    }
    */
}

void ModuleService::DestroyModuleInstance(ModuleEntry &Module) {
    if (!Module.Handle)
        return;
    // 暂时禁用 ModuleBase
    /*
    if (Module.ModuleInstance) {
        const auto Destroy = reinterpret_cast<void (*)(ModuleBase *)>(
            GetProcAddress(Module.Handle, "DestroyModule"));
        if (Destroy)
            Destroy(static_cast<ModuleBase *>(Module.ModuleInstance));
        Module.ModuleInstance = nullptr;
    }
    */
    FreeLibrary(Module.Handle);
    Module.Handle = nullptr;
    Module.Loaded = false;
}

bool ModuleService::LoadModuleInstance(ModuleEntry &Module, QString *Error) {
    if (Module.Loaded && Module.Handle && Module.ModuleInstance)
        return true;

    const std::wstring Path = QString::fromStdString(Module.Path).toStdWString();
    HMODULE Handle = LoadLibraryW(Path.c_str());
    if (!Handle) {
        if (Error)
            *Error = QString("LoadLibrary failed (%1)").arg(GetLastError());
        return false;
    }

    // 暂时禁用 ModuleBase 相关功能
    /*
    const auto Create = reinterpret_cast<ModuleBase *(*)()>(
        GetProcAddress(Handle, "CreateModule"));
    const auto Destroy = reinterpret_cast<void (*)(ModuleBase *)>(
        GetProcAddress(Handle, "DestroyModule"));

    if (!Create || !Destroy) {
        FreeLibrary(Handle);
        if (Error)
            *Error = "CreateModule/DestroyModule exports were not found.";
        return false;
    }

    ModuleBase *Instance = Create();
    if (!Instance) {
        FreeLibrary(Handle);
        if (Error)
            *Error = "CreateModule returned null.";
        return false;
    }

    Module.Handle = Handle;
    Module.ModuleInstance = Instance;

    // 应用缓存的选项值
    for (const ModuleOption &Option : Module.Options) {
        if (!Option.Value.empty())
            Instance->SetOption(Option.Name, Option.Value);
    }
    */

    Module.Handle = Handle;
    Module.Loaded = true;
    return true;
}

#if 0  // 暂时禁用 ProbeModuleFile - 需要 ModuleBase
ModuleEntry ModuleService::ProbeModuleFile(const QString &Path) {
    ModuleEntry Module;
    Module.Path = Utf8Bytes(QFileInfo(Path).absoluteFilePath());
    Module.Name = Utf8Bytes(QFileInfo(Path).completeBaseName());
    Module.Category = "DLL Module";
    Module.Description = Module.Name;
    Module.Author = "Unknown";

    QString Error;
    if (!LoadModuleInstance(Module, &Error)) {
        Module.Valid = false;
        Module.Description = Utf8Bytes(Error);
        return Module;
    }

    ModuleBase *Instance = static_cast<ModuleBase *>(Module.ModuleInstance);
    const ModuleInfo Info = Instance->Info();

    Module.Name = Info.Name.empty() ? Module.Name : Info.Name;
    Module.Description = Info.Description.empty() ? Module.Name : Info.Description;
    Module.Author = Info.Author.empty() ? "Unknown" : Info.Author;
    Module.Category = "Unknown";  // ModuleTypeToString(Info.Type);

    // 提取选项 - 暂时禁用，需要 ModuleBase
    // for (const auto &[Name, OptionPointer] : Instance->GetOptions()) {
    //     ModuleOption Item;
    //     Item.Name = Name;
    //     ...
    // }

    DestroyModuleInstance(Module);
    Module.Valid = true;
    return Module;
}

bool ModuleService::SetDriverLoaded(ModuleEntry &Module, bool Loaded, QString *Error) {
    const std::wstring Service =
        QString::fromStdString(Module.ServiceName).toStdWString();
    DWORD Result = 1;

    if (Loaded) {
        const std::wstring Path =
            QString::fromStdString(Module.Path).toStdWString();
        Result = LoadDriverService(Path.c_str(), Service.c_str());
    } else {
        Result = UnloadDriverService(Service.c_str());
    }

    if (Result != 0) {
        Module.Loaded = QueryDriverLoadedState(Module);
        if (Error)
            *Error = Loaded ? "Failed to load the driver service."
                           : "Failed to unload the driver service.";
        return false;
    }

    Module.Loaded = QueryDriverLoadedState(Module);
    return true;
}

bool ModuleService::QueryDriverLoadedState(ModuleEntry &Module) {
    const std::wstring Service =
        QString::fromStdString(Module.ServiceName).toStdWString();
    if (Service.empty())
        return false;
    return IsDriverServiceRunning(Service.c_str());
}

void ModuleService::ScanRuntimeModules() {
    if (ModuleRunning.load())
        return;

    // 清理旧模块
    for (ModuleEntry &Module : DllModules)
        DestroyModuleInstance(Module);
    for (ModuleEntry &Driver : DriverModules)
        Driver.Loaded = QueryDriverLoadedState(Driver);

    DllModules.clear();
    DriverModules.clear();

    // 扫描 DLL 模块
    ConfigurationManager &Config = GlobalConfiguration();
    for (const QString &ConfiguredPath : Config.ModulePaths()) {
        QDir Directory(ResolveRuntimePath(ConfiguredPath));
        for (const QFileInfo &File :
             Directory.entryInfoList({"*.dll"}, QDir::Files, QDir::Name)) {
            DllModules.push_back(ProbeModuleFile(File.absoluteFilePath()));
        }
    }

    // 扫描驱动模块
    for (const QString &ConfiguredPath : Config.DriverPaths()) {
        QDir Directory(ResolveRuntimePath(ConfiguredPath));
        for (const QFileInfo &File :
             Directory.entryInfoList({"*.sys"}, QDir::Files, QDir::Name)) {
            ModuleEntry Module;
            Module.Name = Utf8Bytes(File.completeBaseName());
            Module.Path = Utf8Bytes(File.absoluteFilePath());
            Module.Category = "System Driver";
            Module.Description = Module.Name;
            Module.Author = "Unknown";
            Module.ServiceName = Utf8Bytes(NormalizedServiceName(File.completeBaseName()));
            Module.Loaded = QueryDriverLoadedState(Module);
            Module.Valid = true;
            DriverModules.push_back(Module);
        }
    }

    // 自动加载
    if (Config.ModulesAutoLoad()) {
        for (ModuleEntry &Module : DllModules) {
            if (Module.Valid)
                LoadModuleInstance(Module);
        }
    }

    if (Config.DriversAutoLoad()) {
        for (ModuleEntry &Driver : DriverModules)
            SetDriverLoaded(Driver, true);
    }

    ModulesScanned = true;
}

void ModuleService::EnsureModulesScanned() {
    if (!ModulesScanned)
        ScanRuntimeModules();
}

ModuleEntry *ModuleService::FindDllModule(const QString &Path) {
    for (ModuleEntry &Module : DllModules) {
        if (QString::fromStdString(Module.Path) == Path)
            return &Module;
    }
    return nullptr;
}

const ModuleEntry *ModuleService::FindDllModule(const QString &Path) const {
    for (const ModuleEntry &Module : DllModules) {
        if (QString::fromStdString(Module.Path) == Path)
            return &Module;
    }
    return nullptr;
}

ModuleEntry *ModuleService::FindDriverModule(const QString &Path) {
    for (ModuleEntry &Module : DriverModules) {
        if (QString::fromStdString(Module.Path) == Path)
            return &Module;
    }
    return nullptr;
}

const ModuleEntry *ModuleService::FindDriverModule(const QString &Path) const {
    for (const ModuleEntry &Module : DriverModules) {
        if (QString::fromStdString(Module.Path) == Path)
            return &Module;
    }
    return nullptr;
}

#if 0  // 暂时禁用 ModuleBase 相关功能
bool ModuleService::InvokeModuleWithSeh(ModuleBase *Instance, bool *Result,
                                       DWORD *ExceptionCode) {
    if (Result)
        *Result = false;
    if (ExceptionCode)
        *ExceptionCode = ERROR_SUCCESS;

    __try {
        if (Result)
            *Result = Instance->Run();
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (ExceptionCode)
            *ExceptionCode = GetExceptionCode();
        return false;
    }
}

bool ModuleService::InvokeModuleCheckWithSeh(ModuleBase *Instance, bool *Result,
                                            DWORD *ExceptionCode) {
    if (Result)
        *Result = false;
    if (ExceptionCode)
        *ExceptionCode = ERROR_SUCCESS;

    __try {
        if (Result)
            *Result = Instance->Check();
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (ExceptionCode)
            *ExceptionCode = GetExceptionCode();
        return false;
    }
}

void ModuleService::CleanupManagedDriversOnExit() {
    if (!ModulesScanned && DriverModules.empty())
        return;

    QStringList Failures;
    for (auto It = DriverModules.rbegin(); It != DriverModules.rend(); ++It) {
        ModuleEntry &Driver = *It;
        if (!Driver.Loaded)
            continue;

        QString Error;
        if (!SetDriverLoaded(Driver, false, &Error)) {
            const QString Name = QString::fromStdString(
                Driver.ServiceName.empty() ? Driver.Name : Driver.ServiceName);
            Failures.append(Name + ": " +
                          (Error.isEmpty() ? "Failed to unload driver service." : Error));
        }
    }

    if (!Failures.isEmpty()) {
        qWarning("Driver shutdown cleanup failures:\n%s",
                qPrintable(Failures.join('\n')));
    }
}

// 全局实例
ModuleService &GlobalModuleService() {
    static ModuleService Instance;
    return Instance;
}

} // namespace AegisNT

