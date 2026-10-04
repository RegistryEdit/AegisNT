#include "../Services/DriverService.cpp"

// 补充完善关键的枚举方法实现

namespace AegisNT {

// ============================================================
// 进程枚举实现
// ============================================================

Result<QVector<ProcessInfo>> DriverService::EnumProcesses() {
    // 分配输出缓冲区（假设最多 1024 个进程）
    constexpr DWORD MaxProcesses = 1024;
    constexpr DWORD BufferSize = MaxProcesses * 512; // 每个进程约 512 字节

    std::vector<BYTE> buffer(BufferSize);
    DWORD bytesReturned = 0;

    AegisCoreClient &client = GlobalAegisCoreClient();

    if (!client.EnumProcesses(buffer.data(), BufferSize, &bytesReturned)) {
        return Result<QVector<ProcessInfo>>(
            client.GetLastError(),
            QString("Failed to enumerate processes: %1").arg(FormatError(client.GetLastError()))
        );
    }

    // 解析返回的数据结构
    QVector<ProcessInfo> processes;

    // TODO: 根据驱动返回的实际结构解析
    // 这里需要匹配 Protocol 头文件中定义的结构

    // 示例占位符
    struct PROCESS_ENTRY {
        DWORD Pid;
        DWORD ParentPid;
        DWORD ThreadCount;
        DWORD HandleCount;
        WCHAR Name[260];
        WCHAR ImagePath[520];
        ULONG64 Eprocess;
        UCHAR Protected;
        UCHAR Ppl;
    };

    const DWORD entryCount = bytesReturned / sizeof(PROCESS_ENTRY);
    const PROCESS_ENTRY *entries = reinterpret_cast<const PROCESS_ENTRY *>(buffer.data());

    for (DWORD i = 0; i < entryCount; ++i) {
        ProcessInfo info;
        info.Pid = entries[i].Pid;
        info.ParentPid = entries[i].ParentPid;
        info.ThreadCount = entries[i].ThreadCount;
        info.HandleCount = entries[i].HandleCount;
        info.Name = QString::fromWCharArray(entries[i].Name);
        info.ImagePath = QString::fromWCharArray(entries[i].ImagePath);
        info.Eprocess = entries[i].Eprocess;
        info.Protected = entries[i].Protected != 0;
        info.Ppl = entries[i].Ppl != 0;

        processes.append(info);
    }

    return Result<QVector<ProcessInfo>>(processes);
}

// ============================================================
// 线程枚举实现
// ============================================================

Result<QVector<ThreadInfo>> DriverService::EnumThreads(DWORD Pid) {
    constexpr DWORD MaxThreads = 512;
    constexpr DWORD BufferSize = MaxThreads * 128;

    std::vector<BYTE> buffer(BufferSize);
    DWORD bytesReturned = 0;

    AegisCoreClient &client = GlobalAegisCoreClient();

    if (!client.EnumThreads(Pid, buffer.data(), BufferSize, &bytesReturned)) {
        return Result<QVector<ThreadInfo>>(
            client.GetLastError(),
            QString("Failed to enumerate threads: %1").arg(FormatError(client.GetLastError()))
        );
    }

    QVector<ThreadInfo> threads;

    // TODO: 解析驱动返回的线程结构

    return Result<QVector<ThreadInfo>>(threads);
}

// ============================================================
// 驱动枚举实现
// ============================================================

Result<QVector<DriverInfo>> DriverService::EnumDrivers() {
    constexpr DWORD MaxDrivers = 512;
    constexpr DWORD BufferSize = MaxDrivers * 512;

    std::vector<BYTE> buffer(BufferSize);
    DWORD bytesReturned = 0;

    AegisCoreClient &client = GlobalAegisCoreClient();

    if (!client.EnumDrivers(buffer.data(), BufferSize, &bytesReturned)) {
        return Result<QVector<DriverInfo>>(
            client.GetLastError(),
            QString("Failed to enumerate drivers: %1").arg(FormatError(client.GetLastError()))
        );
    }

    QVector<DriverInfo> drivers;

    // TODO: 解析驱动返回的驱动结构

    return Result<QVector<DriverInfo>>(drivers);
}

// ============================================================
// 内存操作实现
// ============================================================

Result<QByteArray> DriverService::ReadProcessMemory(DWORD Pid, quint64 Address, size_t Size) {
    QByteArray data(static_cast<int>(Size), 0);

    AegisCoreClient &client = GlobalAegisCoreClient();

    if (!client.ReadProcessMemory(Pid, Address, data.data(), Size)) {
        return Result<QByteArray>(
            client.GetLastError(),
            QString("Failed to read memory: %1").arg(FormatError(client.GetLastError()))
        );
    }

    return Result<QByteArray>(data);
}

Result<void> DriverService::WriteProcessMemory(DWORD Pid, quint64 Address, const QByteArray &Data) {
    AegisCoreClient &client = GlobalAegisCoreClient();

    if (!client.WriteProcessMemory(Pid, Address, Data.constData(), Data.size())) {
        return Result<void>::Error(
            client.GetLastError(),
            QString("Failed to write memory: %1").arg(FormatError(client.GetLastError()))
        );
    }

    return Result<void>::Ok();
}

Result<QByteArray> DriverService::ReadKernelMemory(quint64 Address, size_t Size) {
    QByteArray data(static_cast<int>(Size), 0);

    AegisCoreClient &client = GlobalAegisCoreClient();

    if (!client.ReadKernelMemory(Address, data.data(), Size)) {
        return Result<QByteArray>(
            client.GetLastError(),
            QString("Failed to read kernel memory: %1").arg(FormatError(client.GetLastError()))
        );
    }

    return Result<QByteArray>(data);
}

Result<void> DriverService::WriteKernelMemory(quint64 Address, const QByteArray &Data) {
    AegisCoreClient &client = GlobalAegisCoreClient();

    if (!client.WriteKernelMemory(Address, Data.constData(), Data.size())) {
        return Result<void>::Error(
            client.GetLastError(),
            QString("Failed to write kernel memory: %1").arg(FormatError(client.GetLastError()))
        );
    }

    return Result<void>::Ok();
}

// ============================================================
// 窗口枚举实现
// ============================================================

Result<QVector<WindowInfo>> DriverService::EnumWindows() {
    constexpr DWORD MaxWindows = 2048;
    constexpr DWORD BufferSize = MaxWindows * 256;

    std::vector<BYTE> buffer(BufferSize);
    DWORD bytesReturned = 0;

    AegisCoreClient &client = GlobalAegisCoreClient();

    if (!client.EnumWindows(buffer.data(), BufferSize, &bytesReturned)) {
        return Result<QVector<WindowInfo>>(
            client.GetLastError(),
            QString("Failed to enumerate windows: %1").arg(FormatError(client.GetLastError()))
        );
    }

    QVector<WindowInfo> windows;

    // TODO: 解析驱动返回的窗口结构

    return Result<QVector<WindowInfo>>(windows);
}

// ============================================================
// 回调枚举实现
// ============================================================

Result<QVector<CallbackInfo>> DriverService::EnumCallbacks() {
    constexpr DWORD MaxCallbacks = 1024;
    constexpr DWORD BufferSize = MaxCallbacks * 128;

    std::vector<BYTE> buffer(BufferSize);
    DWORD bytesReturned = 0;

    AegisCoreClient &client = GlobalAegisCoreClient();

    if (!client.EnumCallbacks(buffer.data(), BufferSize, &bytesReturned)) {
        return Result<QVector<CallbackInfo>>(
            client.GetLastError(),
            QString("Failed to enumerate callbacks: %1").arg(FormatError(client.GetLastError()))
        );
    }

    QVector<CallbackInfo> callbacks;

    // TODO: 解析驱动返回的回调结构

    return Result<QVector<CallbackInfo>>(callbacks);
}

} // namespace AegisNT
