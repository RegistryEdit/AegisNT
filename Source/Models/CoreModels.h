#pragma once

#include <QByteArray>
#include <QString>
#include <QVector>
#include <windows.h>

namespace AegisNT {

/**
 * ProcessInfo - 进程信息模型
 */
struct ProcessInfo {
    DWORD Pid = 0;
    DWORD ParentPid = 0;
    DWORD ThreadCount = 0;
    DWORD HandleCount = 0;
    DWORD SessionId = 0;
    DWORD IntegrityRid = 0;
    quint64 Eprocess = 0;

    QString Name;
    QString User;
    QString ImagePath;

    bool Protected = false;
    bool Ppl = false;
    bool Critical = false;
    bool Hidden = false;
    UCHAR PplRaw = 0;
};

/**
 * ThreadInfo - 线程信息模型
 */
struct ThreadInfo {
    DWORD Tid = 0;
    DWORD ProcessId = 0;
    UCHAR PreviousMode = 0;
    UCHAR ApcQueueable = 0;
    quint64 Ethread = 0;
    quint64 StartAddress = 0;
    DWORD Priority = 0;
    DWORD State = 0;
    QString ProcessName;
};

/**
 * DriverInfo - 驱动信息模型
 */
struct DriverInfo {
    QString Name;
    QString Path;
    quint64 BaseAddress = 0;
    quint64 Size = 0;
    quint64 DriverObject = 0;
    bool Loaded = false;
};

/**
 * ModuleInfo - 模块信息模型
 */
struct ModuleInfo {
    QString Name;
    QString Path;
    quint64 BaseAddress = 0;
    quint64 Size = 0;
    DWORD ProcessId = 0;
};

/**
 * MemoryRegionInfo - 内存区域信息模型
 */
struct MemoryRegionInfo {
    quint64 BaseAddress = 0;
    quint64 Size = 0;
    DWORD Protection = 0;
    DWORD State = 0;
    DWORD Type = 0;
    QString ProtectionString;
};

/**
 * HandleInfo - 句柄信息模型
 */
struct HandleInfo {
    HANDLE Handle = nullptr;
    QString TypeName;
    QString ObjectName;
    quint64 Object = 0;
    DWORD GrantedAccess = 0;
    DWORD ProcessId = 0;
};

/**
 * WindowInfo - 窗口信息模型
 */
struct WindowInfo {
    HWND Hwnd = nullptr;
    QString Title;
    QString ClassName;
    DWORD ProcessId = 0;
    DWORD ThreadId = 0;
    bool Visible = false;
    bool Protected = false;
};

/**
 * CallbackInfo - 回调信息模型
 */
struct CallbackInfo {
    QString Type;
    quint64 Address = 0;
    QString Module;
    int Index = -1;
};

/**
 * ServiceInfo - 服务信息模型
 */
struct ServiceInfo {
    QString Name;
    QString DisplayName;
    QString ImagePath;
    DWORD ServiceType = 0;
    DWORD StartType = 0;
    DWORD CurrentState = 0;
    DWORD ProcessId = 0;
};

/**
 * Result<T> - 操作结果封装
 */
template<typename T>
class Result {
public:
    Result() : Success(false), ErrorCode(0) {}
    Result(const T &Value) : Success(true), ErrorCode(0), Data(Value) {}
    Result(DWORD Code, const QString &Message)
        : Success(false), ErrorCode(Code), ErrorMessage(Message) {}

    // 静态工厂方法
    static Result<T> Ok() {
        return Result<T>(T{});
    }

    static Result<T> Ok(const T &Value) {
        return Result<T>(Value);
    }

    static Result<T> Error(DWORD Code, const QString &Message) {
        return Result<T>(Code, Message);
    }

    bool IsSuccess() const { return Success; }
    bool IsError() const { return !Success; }

    const T &Value() const { return Data; }
    T &Value() { return Data; }

    DWORD GetErrorCode() const { return ErrorCode; }
    const QString &GetErrorMessage() const { return ErrorMessage; }

    // 便捷操作符
    operator bool() const { return Success; }
    const T &operator*() const { return Data; }
    T &operator*() { return Data; }

private:
    bool Success;
    DWORD ErrorCode;
    QString ErrorMessage;
    T Data{};
};

/**
 * Result<void> - 无返回值操作结果
 */
template<>
class Result<void> {
public:
    Result() : Success(false), ErrorCode(0) {}
    Result(bool Ok) : Success(Ok), ErrorCode(Ok ? 0 : 1) {}
    Result(DWORD Code, const QString &Message)
        : Success(false), ErrorCode(Code), ErrorMessage(Message) {}

    bool IsSuccess() const { return Success; }
    bool IsError() const { return !Success; }

    DWORD GetErrorCode() const { return ErrorCode; }
    const QString &GetErrorMessage() const { return ErrorMessage; }

    operator bool() const { return Success; }

    static Result<void> Ok() { return Result<void>(true); }
    static Result<void> Error(DWORD Code, const QString &Message) {
        return Result<void>(Code, Message);
    }

private:
    bool Success;
    DWORD ErrorCode;
    QString ErrorMessage;
};

} // namespace AegisNT
