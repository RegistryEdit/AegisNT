#include "DriverServiceEnumImpl.h"

#include "../../Platform/AegisCoreCall.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <vector>

namespace AegisNT::DriverServiceEnum {
namespace {

constexpr DWORD kInvalidData = ERROR_INVALID_DATA;
constexpr ULONG kMaxRecords = 1024 * 1024;

template <typename T>
Result<T> InvalidData(const char *Message) {
    return Result<T>::Error(kInvalidData, QString::fromLatin1(Message));
}

template <typename T>
Result<T> NtError(NTSTATUS Status, const char *Message) {
    DWORD Code = AegisCoreNtStatusToWin32(Status);
    if (Code == ERROR_SUCCESS)
        Code = ERROR_GEN_FAILURE;
    return Result<T>::Error(Code, QString::fromLatin1(Message));
}

template <size_t N>
QString WireString(const WCHAR (&Text)[N]) {
    size_t Length = 0;
    while (Length < N && Text[Length] != L'\0')
        ++Length;
    return QString::fromWCharArray(Text, static_cast<qsizetype>(Length));
}

template <typename T>
bool ReadRecord(const BYTE *Buffer, size_t Bytes, size_t Offset, T &Record) {
    if (Buffer == nullptr || Offset > Bytes || sizeof(T) > Bytes - Offset)
        return false;
    std::memcpy(&Record, Buffer + Offset, sizeof(T));
    return true;
}

template <typename Model>
Result<QVector<Model>> InvalidList(const char *Message) {
    return InvalidData<QVector<Model>>(Message);
}

} // namespace

Result<QVector<ProcessInfo>> ParseProcesses(const void *RawBuffer, size_t Bytes) {
    constexpr size_t HeaderBytes = offsetof(PROCESS_ENUM_OUTPUT, Entries);
    if (RawBuffer == nullptr || Bytes < sizeof(ULONG))
        return InvalidList<ProcessInfo>("Truncated process enumeration header");

    const auto *Buffer = static_cast<const BYTE *>(RawBuffer);
    ULONG Count = 0;
    std::memcpy(&Count, Buffer, sizeof(Count));
    if (Count == 0 && Bytes < HeaderBytes)
        return Result<QVector<ProcessInfo>>::Ok({});
    if (Bytes < HeaderBytes)
        return InvalidList<ProcessInfo>("Truncated process enumeration header");

    const size_t Available = (Bytes - HeaderBytes) / sizeof(PROCESS_ENUM_ENTRY);
    if (Count > kMaxRecords || Count > Available)
        return InvalidList<ProcessInfo>("Process count exceeds returned data");

    QVector<ProcessInfo> Items;
    Items.reserve(static_cast<qsizetype>(Count));
    for (ULONG Index = 0; Index < Count; ++Index) {
        PROCESS_ENUM_ENTRY Entry{};
        const size_t Offset = HeaderBytes + static_cast<size_t>(Index) * sizeof(Entry);
        if (!ReadRecord(Buffer, Bytes, Offset, Entry))
            return InvalidList<ProcessInfo>("Truncated process entry");

        ProcessInfo Info;
        Info.Pid = Entry.ProcessId;
        Info.ParentPid = Entry.ParentPid;
        Info.ThreadCount = Entry.ThreadCount;
        Info.SessionId = Entry.SessionId;
        Info.Eprocess = static_cast<quint64>(Entry.ObjectAddress);
        Info.Name = WireString(Entry.ImageName);
        Info.Ppl = Entry.IsPplProtected != FALSE;
        Info.PplRaw = Entry.PplRawLevel;
        Info.Critical = Entry.IsCritical != FALSE;
        Info.Hidden = Entry.IsHidden != FALSE;
        Items.append(std::move(Info));
    }
    return Result<QVector<ProcessInfo>>::Ok(Items);
}

Result<QVector<ThreadInfo>> ParseThreadInventoryPage(
    const void *RawBuffer, size_t Bytes, DWORD ExpectedProcessId,
    ULONG64 RequestedCursor, ULONG64 *NextCursor) {
    if (NextCursor == nullptr)
        return InvalidList<ThreadInfo>("Missing thread cursor output");
    *NextCursor = 0;

    if (RawBuffer == nullptr || Bytes < sizeof(INVENTORY_LIST_HEADER))
        return InvalidList<ThreadInfo>("Truncated thread inventory header");

    const auto *Buffer = static_cast<const BYTE *>(RawBuffer);
    INVENTORY_LIST_HEADER Header{};
    std::memcpy(&Header, Buffer, sizeof(Header));
    if (Header.Size != sizeof(Header) || Header.Version != INVENTORY_PROTOCOL_VERSION ||
        Header.ReturnedCount > INVENTORY_MAX_PAGE_RECORDS ||
        Header.ReturnedCount > (Bytes - sizeof(Header)) / sizeof(INVENTORY_RECORD))
        return InvalidList<ThreadInfo>("Invalid thread inventory header or count");
    if (Header.Status < 0)
        return NtError<QVector<ThreadInfo>>(Header.Status, "Thread inventory query failed");
    if (Header.NextCursor != 0 &&
        (Header.NextCursor <= RequestedCursor || Header.ReturnedCount == 0))
        return InvalidList<ThreadInfo>("Thread inventory cursor did not advance");

    QVector<ThreadInfo> Items;
    Items.reserve(static_cast<qsizetype>(Header.ReturnedCount));
    for (ULONG Index = 0; Index < Header.ReturnedCount; ++Index) {
        INVENTORY_RECORD Entry{};
        const size_t Offset = sizeof(Header) + static_cast<size_t>(Index) * sizeof(Entry);
        if (!ReadRecord(Buffer, Bytes, Offset, Entry) || Entry.Size != sizeof(Entry) ||
            Entry.Kind != 2 || Entry.ProcessId != ExpectedProcessId)
            return InvalidList<ThreadInfo>("Invalid thread inventory record");
        if (Entry.Status < 0)
            return NtError<QVector<ThreadInfo>>(Entry.Status, "Thread inventory record failed");

        ThreadInfo Info;
        Info.Tid = Entry.ThreadId;
        Info.ProcessId = Entry.ProcessId;
        Info.StartAddress = Entry.Address;
        Info.Priority = static_cast<DWORD>(Entry.Value[0]);
        Info.State = static_cast<DWORD>(Entry.Value[2]);
        Info.ProcessName = WireString(Entry.Name);
        Items.append(std::move(Info));
    }
    *NextCursor = Header.NextCursor;
    return Result<QVector<ThreadInfo>>::Ok(Items);
}

Result<QVector<DriverInfo>> ParseDrivers(const void *RawBuffer, size_t Bytes) {
    constexpr size_t HeaderBytes = offsetof(DRIVER_ENUM_OUTPUT, Entries);
    if (RawBuffer == nullptr || Bytes < HeaderBytes)
        return InvalidList<DriverInfo>("Truncated driver enumeration header");

    const auto *Buffer = static_cast<const BYTE *>(RawBuffer);
    DRIVER_ENUM_HEADER Header{};
    std::memcpy(&Header, Buffer, sizeof(Header));
    if (Header.NtStatus < 0)
        return NtError<QVector<DriverInfo>>(Header.NtStatus, "Driver enumeration failed");

    const size_t Available = (Bytes - HeaderBytes) / sizeof(DRIVER_ENUM_ENTRY);
    if (Header.Count > kMaxRecords || Header.Count > Available)
        return InvalidList<DriverInfo>("Driver count exceeds returned data");

    QVector<DriverInfo> Items;
    Items.reserve(static_cast<qsizetype>(Header.Count));
    for (ULONG Index = 0; Index < Header.Count; ++Index) {
        DRIVER_ENUM_ENTRY Entry{};
        const size_t Offset = HeaderBytes + static_cast<size_t>(Index) * sizeof(Entry);
        if (!ReadRecord(Buffer, Bytes, Offset, Entry))
            return InvalidList<DriverInfo>("Truncated driver entry");

        DriverInfo Info;
        Info.Name = WireString(Entry.ServiceName);
        Info.Path = WireString(Entry.ImagePath);
        Info.BaseAddress = static_cast<quint64>(Entry.ImageBase);
        Info.Size = Entry.ImageSize;
        Info.DriverObject = static_cast<quint64>(Entry.DriverObject);
        Info.Loaded = Entry.State == SERVICE_RUNNING;
        Items.append(std::move(Info));
    }
    return Result<QVector<DriverInfo>>::Ok(Items);
}

Result<QVector<WindowInfo>> ParseKernelWindows(const void *RawBuffer, size_t Bytes) {
    // EnumerateWindowsKernel currently emits the count followed immediately by
    // entries (4-byte header); don't use sizeof(KERNEL_WINDOW_ENUM_OUTPUT), whose
    // naturally aligned Entries member starts at byte 8 on x64.
    constexpr size_t HeaderBytes = sizeof(ULONG);
    if (RawBuffer == nullptr || Bytes < HeaderBytes)
        return InvalidList<WindowInfo>("Truncated window enumeration header");

    const auto *Buffer = static_cast<const BYTE *>(RawBuffer);
    ULONG Count = 0;
    std::memcpy(&Count, Buffer, sizeof(Count));
    if (Count > kMaxRecords || Count > (Bytes - HeaderBytes) / sizeof(KERNEL_WINDOW_ENUM_ENTRY))
        return InvalidList<WindowInfo>("Window count exceeds returned data");

    QVector<WindowInfo> Items;
    Items.reserve(static_cast<qsizetype>(Count));
    size_t Offset = HeaderBytes;
    for (ULONG Index = 0; Index < Count; ++Index) {
        KERNEL_WINDOW_ENUM_ENTRY Entry{};
        if (!ReadRecord(Buffer, Bytes, Offset, Entry))
            return InvalidList<WindowInfo>("Truncated window entry");
        if ((Entry.TitleLength % sizeof(WCHAR)) != 0 || Entry.TitleLength > 510)
            return InvalidList<WindowInfo>("Invalid window title length");

        const size_t TitleStorage = (static_cast<size_t>(Entry.TitleLength) + 1u) & ~size_t(1u);
        const size_t RecordBytes = sizeof(Entry) + TitleStorage;
        if (RecordBytes > Bytes - Offset)
            return InvalidList<WindowInfo>("Truncated window title");

        WindowInfo Info;
        Info.Hwnd = reinterpret_cast<HWND>(static_cast<ULONG_PTR>(Entry.Hwnd));
        Info.ProcessId = Entry.ProcessId;
        Info.ThreadId = Entry.ThreadId;
        Info.Visible = (Entry.Flags & WINDOW_FLAG_VISIBLE) != 0;
        if (Entry.TitleLength != 0) {
            const size_t TitleCharacters = Entry.TitleLength / sizeof(WCHAR);
            std::vector<WCHAR> Title(TitleCharacters);
            std::memcpy(Title.data(), Buffer + Offset + sizeof(Entry), Entry.TitleLength);
            Info.Title = QString::fromWCharArray(
                Title.data(), static_cast<qsizetype>(TitleCharacters));
        }
        Items.append(std::move(Info));
        Offset += RecordBytes;
    }
    return Result<QVector<WindowInfo>>::Ok(Items);
}

Result<QVector<CallbackInfo>> ParseCallbacks(const void *RawBuffer, size_t Bytes) {
    constexpr size_t HeaderBytes = offsetof(CALLBACK_ENUM_OUTPUT, Entries);
    if (RawBuffer == nullptr || Bytes < sizeof(ULONG))
        return InvalidList<CallbackInfo>("Truncated callback enumeration header");

    const auto *Buffer = static_cast<const BYTE *>(RawBuffer);
    ULONG Count = 0;
    std::memcpy(&Count, Buffer, sizeof(Count));
    if (Count == 0 && Bytes < HeaderBytes)
        return Result<QVector<CallbackInfo>>::Ok({});
    if (Bytes < HeaderBytes)
        return InvalidList<CallbackInfo>("Truncated callback enumeration header");

    const size_t Available = (Bytes - HeaderBytes) / sizeof(CALLBACK_ENTRY);
    if (Count > kMaxRecords || Count > Available)
        return InvalidList<CallbackInfo>("Callback count exceeds returned data");

    QVector<CallbackInfo> Items;
    Items.reserve(static_cast<qsizetype>(Count));
    for (ULONG Index = 0; Index < Count; ++Index) {
        CALLBACK_ENTRY Entry{};
        const size_t Offset = HeaderBytes + static_cast<size_t>(Index) * sizeof(Entry);
        if (!ReadRecord(Buffer, Bytes, Offset, Entry))
            return InvalidList<CallbackInfo>("Truncated callback entry");

        CallbackInfo Info;
        Info.Type = QString::number(Entry.Type);
        Info.Address = static_cast<quint64>(Entry.Address);
        Info.Module = WireString(Entry.ModuleName);
        Info.Index = static_cast<int>(Index);
        Items.append(std::move(Info));
    }
    return Result<QVector<CallbackInfo>>::Ok(Items);
}

} // namespace AegisNT::DriverServiceEnum
