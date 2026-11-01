#pragma once

// 句柄权限表：对象类型 -> 专属访问掩码位。
// ------------------------------------------------------------
// 本文件是句柄权限条目与掩码解码的唯一实现，同时供
// TaskManagerPage 的权限选择框（PromptHandleAccessMask）和
// Handles 表的 Access 列解码使用。此前这两处各自手写一份表，
// 且只有一处归一化类型名，导致带前缀/别名的类型丢失专属权限。
//
// 未在 Windows SDK 用户态头文件中声明的对象权限位来自 WDK km
// 头文件与 phnt 的公开定义；无公开定义的对象类型不臆造权限位。
// ------------------------------------------------------------

#include <Windows.h>
#include <wmistr.h>

#include <QString>
#include <QStringList>

#include <array>
#include <span>
#include <vector>

namespace HandleAccessData {

struct Entry {
  quint32 Mask = 0;
  const char *Name = nullptr;
};

// Windows SDK / 用户态头文件未声明的对象权限，取值来自 WDK km 头与 phnt。
static constexpr quint32 KEventQueryState = 0x0001;
static constexpr quint32 KEventModifyState = 0x0002;
static constexpr quint32 KSemaphoreQueryState = 0x0001;
static constexpr quint32 KMutantQueryState = 0x0001;
static constexpr quint32 KIoCompletionQueryState = 0x0001;
static constexpr quint32 KDirectoryQuery = 0x0001;
static constexpr quint32 KDirectoryTraverse = 0x0002;
static constexpr quint32 KDirectoryCreateObject = 0x0004;
static constexpr quint32 KDirectoryCreateSubdirectory = 0x0008;
static constexpr quint32 KSymbolicLinkQuery = 0x0001;
static constexpr quint32 KSymbolicLinkSet = 0x0002;
static constexpr quint32 KPortConnect = 0x0001;
static constexpr quint32 KFilterPortConnect = 0x0001;
static constexpr quint32 KProfileControl = 0x0001;
static constexpr quint32 KKeyedEventWait = 0x0001;
static constexpr quint32 KKeyedEventWake = 0x0002;
static constexpr quint32 KWorkerFactoryReleaseWorker = 0x0001;
static constexpr quint32 KWorkerFactoryWait = 0x0002;
static constexpr quint32 KWorkerFactorySetInformation = 0x0004;
static constexpr quint32 KWorkerFactoryQueryInformation = 0x0008;
static constexpr quint32 KWorkerFactoryReadyWorker = 0x0010;
static constexpr quint32 KWorkerFactoryShutdown = 0x0020;
static constexpr quint32 KWaitCompletionPacketSetState = 0x0001;
static constexpr quint32 KDebugReadEvent = 0x0001;
static constexpr quint32 KDebugProcessAssign = 0x0002;
static constexpr quint32 KDebugSetInformation = 0x0004;
static constexpr quint32 KDebugQueryInformation = 0x0008;
static constexpr quint32 KCallbackModifyState = 0x0001;

namespace Detail {

// 所有对象类型共用的标准权限与泛型权限，顺序固定。
inline constexpr auto GenericRights = std::to_array<Entry>({
    {DELETE, "DELETE"},
    {READ_CONTROL, "READ_CONTROL"},
    {WRITE_DAC, "WRITE_DAC"},
    {WRITE_OWNER, "WRITE_OWNER"},
    {SYNCHRONIZE, "SYNCHRONIZE"},
    {ACCESS_SYSTEM_SECURITY, "ACCESS_SYSTEM_SECURITY"},
    {GENERIC_READ, "GENERIC_READ"},
    {GENERIC_WRITE, "GENERIC_WRITE"},
    {GENERIC_EXECUTE, "GENERIC_EXECUTE"},
    {GENERIC_ALL, "GENERIC_ALL"},
});

inline constexpr auto ProcessRights = std::to_array<Entry>({
    {PROCESS_TERMINATE, "PROCESS_TERMINATE"},
    {PROCESS_CREATE_THREAD, "PROCESS_CREATE_THREAD"},
    {PROCESS_SET_SESSIONID, "PROCESS_SET_SESSIONID"},
    {PROCESS_VM_OPERATION, "PROCESS_VM_OPERATION"},
    {PROCESS_VM_READ, "PROCESS_VM_READ"},
    {PROCESS_VM_WRITE, "PROCESS_VM_WRITE"},
    {PROCESS_DUP_HANDLE, "PROCESS_DUP_HANDLE"},
    {PROCESS_CREATE_PROCESS, "PROCESS_CREATE_PROCESS"},
    {PROCESS_SET_QUOTA, "PROCESS_SET_QUOTA"},
    {PROCESS_SET_INFORMATION, "PROCESS_SET_INFORMATION"},
    {PROCESS_QUERY_INFORMATION, "PROCESS_QUERY_INFORMATION"},
    {PROCESS_SUSPEND_RESUME, "PROCESS_SUSPEND_RESUME"},
    {PROCESS_QUERY_LIMITED_INFORMATION, "PROCESS_QUERY_LIMITED_INFORMATION"},
    {PROCESS_SET_LIMITED_INFORMATION, "PROCESS_SET_LIMITED_INFORMATION"},
});

inline constexpr auto ThreadRights = std::to_array<Entry>({
    {THREAD_TERMINATE, "THREAD_TERMINATE"},
    {THREAD_SUSPEND_RESUME, "THREAD_SUSPEND_RESUME"},
    {THREAD_GET_CONTEXT, "THREAD_GET_CONTEXT"},
    {THREAD_SET_CONTEXT, "THREAD_SET_CONTEXT"},
    {THREAD_SET_INFORMATION, "THREAD_SET_INFORMATION"},
    {THREAD_QUERY_INFORMATION, "THREAD_QUERY_INFORMATION"},
    {THREAD_SET_THREAD_TOKEN, "THREAD_SET_THREAD_TOKEN"},
    {THREAD_IMPERSONATE, "THREAD_IMPERSONATE"},
    {THREAD_DIRECT_IMPERSONATION, "THREAD_DIRECT_IMPERSONATION"},
    {THREAD_SET_LIMITED_INFORMATION, "THREAD_SET_LIMITED_INFORMATION"},
    {THREAD_QUERY_LIMITED_INFORMATION, "THREAD_QUERY_LIMITED_INFORMATION"},
    {THREAD_RESUME, "THREAD_RESUME"},
});

inline constexpr auto TokenRights = std::to_array<Entry>({
    {TOKEN_ASSIGN_PRIMARY, "TOKEN_ASSIGN_PRIMARY"},
    {TOKEN_DUPLICATE, "TOKEN_DUPLICATE"},
    {TOKEN_IMPERSONATE, "TOKEN_IMPERSONATE"},
    {TOKEN_QUERY, "TOKEN_QUERY"},
    {TOKEN_QUERY_SOURCE, "TOKEN_QUERY_SOURCE"},
    {TOKEN_ADJUST_PRIVILEGES, "TOKEN_ADJUST_PRIVILEGES"},
    {TOKEN_ADJUST_GROUPS, "TOKEN_ADJUST_GROUPS"},
    {TOKEN_ADJUST_DEFAULT, "TOKEN_ADJUST_DEFAULT"},
    {TOKEN_ADJUST_SESSIONID, "TOKEN_ADJUST_SESSIONID"},
});

inline constexpr auto JobRights = std::to_array<Entry>({
    {JOB_OBJECT_ASSIGN_PROCESS, "JOB_OBJECT_ASSIGN_PROCESS"},
    {JOB_OBJECT_SET_ATTRIBUTES, "JOB_OBJECT_SET_ATTRIBUTES"},
    {JOB_OBJECT_QUERY, "JOB_OBJECT_QUERY"},
    {JOB_OBJECT_TERMINATE, "JOB_OBJECT_TERMINATE"},
    {JOB_OBJECT_SET_SECURITY_ATTRIBUTES, "JOB_OBJECT_SET_SECURITY_ATTRIBUTES"},
    {JOB_OBJECT_IMPERSONATE, "JOB_OBJECT_IMPERSONATE"},
});

inline constexpr auto FileRights = std::to_array<Entry>({
    {FILE_READ_DATA, "FILE_READ_DATA"},
    {FILE_WRITE_DATA, "FILE_WRITE_DATA"},
    {FILE_APPEND_DATA, "FILE_APPEND_DATA"},
    {FILE_READ_EA, "FILE_READ_EA"},
    {FILE_WRITE_EA, "FILE_WRITE_EA"},
    {FILE_EXECUTE, "FILE_EXECUTE"},
    {FILE_DELETE_CHILD, "FILE_DELETE_CHILD"},
    {FILE_READ_ATTRIBUTES, "FILE_READ_ATTRIBUTES"},
    {FILE_WRITE_ATTRIBUTES, "FILE_WRITE_ATTRIBUTES"},
});

inline constexpr auto KeyRights = std::to_array<Entry>({
    {KEY_QUERY_VALUE, "KEY_QUERY_VALUE"},
    {KEY_SET_VALUE, "KEY_SET_VALUE"},
    {KEY_CREATE_SUB_KEY, "KEY_CREATE_SUB_KEY"},
    {KEY_ENUMERATE_SUB_KEYS, "KEY_ENUMERATE_SUB_KEYS"},
    {KEY_NOTIFY, "KEY_NOTIFY"},
    {KEY_CREATE_LINK, "KEY_CREATE_LINK"},
    {KEY_WOW64_32KEY, "KEY_WOW64_32KEY"},
    {KEY_WOW64_64KEY, "KEY_WOW64_64KEY"},
});

inline constexpr auto SectionRights = std::to_array<Entry>({
    {SECTION_QUERY, "SECTION_QUERY"},
    {SECTION_MAP_WRITE, "SECTION_MAP_WRITE"},
    {SECTION_MAP_READ, "SECTION_MAP_READ"},
    {SECTION_MAP_EXECUTE, "SECTION_MAP_EXECUTE"},
    {SECTION_EXTEND_SIZE, "SECTION_EXTEND_SIZE"},
    {SECTION_MAP_EXECUTE_EXPLICIT, "SECTION_MAP_EXECUTE_EXPLICIT"},
});

inline constexpr auto EventRights = std::to_array<Entry>({
    {KEventQueryState, "EVENT_QUERY_STATE"},
    {KEventModifyState, "EVENT_MODIFY_STATE"},
});

inline constexpr auto MutantRights = std::to_array<Entry>({
    {KMutantQueryState, "MUTANT_QUERY_STATE"},
});

inline constexpr auto SemaphoreRights = std::to_array<Entry>({
    {KSemaphoreQueryState, "SEMAPHORE_QUERY_STATE"},
    {SEMAPHORE_MODIFY_STATE, "SEMAPHORE_MODIFY_STATE"},
});

inline constexpr auto TimerRights = std::to_array<Entry>({
    {TIMER_QUERY_STATE, "TIMER_QUERY_STATE"},
    {TIMER_MODIFY_STATE, "TIMER_MODIFY_STATE"},
});

inline constexpr auto IoCompletionRights = std::to_array<Entry>({
    {KIoCompletionQueryState, "IO_COMPLETION_QUERY_STATE"},
    {IO_COMPLETION_MODIFY_STATE, "IO_COMPLETION_MODIFY_STATE"},
});

inline constexpr auto WaitCompletionPacketRights = std::to_array<Entry>({
    {KWaitCompletionPacketSetState, "WAIT_COMPLETION_PACKET_SET_STATE"},
});

inline constexpr auto TpWorkerFactoryRights = std::to_array<Entry>({
    {KWorkerFactoryReleaseWorker, "WORKER_FACTORY_RELEASE_WORKER"},
    {KWorkerFactoryWait, "WORKER_FACTORY_WAIT"},
    {KWorkerFactorySetInformation, "WORKER_FACTORY_SET_INFORMATION"},
    {KWorkerFactoryQueryInformation, "WORKER_FACTORY_QUERY_INFORMATION"},
    {KWorkerFactoryReadyWorker, "WORKER_FACTORY_READY_WORKER"},
    {KWorkerFactoryShutdown, "WORKER_FACTORY_SHUTDOWN"},
});

inline constexpr auto DirectoryRights = std::to_array<Entry>({
    {KDirectoryQuery, "DIRECTORY_QUERY"},
    {KDirectoryTraverse, "DIRECTORY_TRAVERSE"},
    {KDirectoryCreateObject, "DIRECTORY_CREATE_OBJECT"},
    {KDirectoryCreateSubdirectory, "DIRECTORY_CREATE_SUBDIRECTORY"},
});

inline constexpr auto SymbolicLinkRights = std::to_array<Entry>({
    {KSymbolicLinkQuery, "SYMBOLIC_LINK_QUERY"},
    {KSymbolicLinkSet, "SYMBOLIC_LINK_SET"},
});

inline constexpr auto AlpcPortRights = std::to_array<Entry>({
    {KPortConnect, "PORT_CONNECT"},
});

inline constexpr auto DesktopRights = std::to_array<Entry>({
    {DESKTOP_READOBJECTS, "DESKTOP_READOBJECTS"},
    {DESKTOP_CREATEWINDOW, "DESKTOP_CREATEWINDOW"},
    {DESKTOP_CREATEMENU, "DESKTOP_CREATEMENU"},
    {DESKTOP_HOOKCONTROL, "DESKTOP_HOOKCONTROL"},
    {DESKTOP_JOURNALRECORD, "DESKTOP_JOURNALRECORD"},
    {DESKTOP_JOURNALPLAYBACK, "DESKTOP_JOURNALPLAYBACK"},
    {DESKTOP_ENUMERATE, "DESKTOP_ENUMERATE"},
    {DESKTOP_WRITEOBJECTS, "DESKTOP_WRITEOBJECTS"},
    {DESKTOP_SWITCHDESKTOP, "DESKTOP_SWITCHDESKTOP"},
});

inline constexpr auto WindowStationRights = std::to_array<Entry>({
    {WINSTA_ENUMDESKTOPS, "WINSTA_ENUMDESKTOPS"},
    {WINSTA_READATTRIBUTES, "WINSTA_READATTRIBUTES"},
    {WINSTA_ACCESSCLIPBOARD, "WINSTA_ACCESSCLIPBOARD"},
    {WINSTA_CREATEDESKTOP, "WINSTA_CREATEDESKTOP"},
    {WINSTA_WRITEATTRIBUTES, "WINSTA_WRITEATTRIBUTES"},
    {WINSTA_ACCESSGLOBALATOMS, "WINSTA_ACCESSGLOBALATOMS"},
    {WINSTA_EXITWINDOWS, "WINSTA_EXITWINDOWS"},
    {WINSTA_ENUMERATE, "WINSTA_ENUMERATE"},
    {WINSTA_READSCREEN, "WINSTA_READSCREEN"},
});

inline constexpr auto SessionRights = std::to_array<Entry>({
    {SESSION_QUERY_ACCESS, "SESSION_QUERY_ACCESS"},
    {SESSION_MODIFY_ACCESS, "SESSION_MODIFY_ACCESS"},
});

inline constexpr auto WmiGuidRights = std::to_array<Entry>({
    {WMIGUID_QUERY, "WMIGUID_QUERY"},
    {WMIGUID_SET, "WMIGUID_SET"},
    {WMIGUID_NOTIFICATION, "WMIGUID_NOTIFICATION"},
    {WMIGUID_READ_DESCRIPTION, "WMIGUID_READ_DESCRIPTION"},
    {WMIGUID_EXECUTE, "WMIGUID_EXECUTE"},
    {TRACELOG_CREATE_REALTIME, "TRACELOG_CREATE_REALTIME"},
    {TRACELOG_CREATE_ONDISK, "TRACELOG_CREATE_ONDISK"},
    {TRACELOG_GUID_ENABLE, "TRACELOG_GUID_ENABLE"},
    {TRACELOG_ACCESS_KERNEL_LOGGER, "TRACELOG_ACCESS_KERNEL_LOGGER"},
    {TRACELOG_LOG_EVENT, "TRACELOG_LOG_EVENT"},
    {TRACELOG_ACCESS_REALTIME, "TRACELOG_ACCESS_REALTIME"},
    {TRACELOG_REGISTER_GUIDS, "TRACELOG_REGISTER_GUIDS"},
    {TRACELOG_JOIN_GROUP, "TRACELOG_JOIN_GROUP"},
});

inline constexpr auto ProfileRights = std::to_array<Entry>({
    {KProfileControl, "PROFILE_CONTROL"},
});

inline constexpr auto DebugObjectRights = std::to_array<Entry>({
    {KDebugReadEvent, "DEBUG_READ_EVENT"},
    {KDebugProcessAssign, "DEBUG_PROCESS_ASSIGN"},
    {KDebugSetInformation, "DEBUG_SET_INFORMATION"},
    {KDebugQueryInformation, "DEBUG_QUERY_INFORMATION"},
});

inline constexpr auto CallbackRights = std::to_array<Entry>({
    {KCallbackModifyState, "CALLBACK_MODIFY_STATE"},
});

inline constexpr auto KeyedEventRights = std::to_array<Entry>({
    {KKeyedEventWait, "KEYEDEVENT_WAIT"},
    {KKeyedEventWake, "KEYEDEVENT_WAKE"},
});

inline constexpr auto FilterConnectionPortRights = std::to_array<Entry>({
    {KFilterPortConnect, "FLT_PORT_CONNECT"},
});

inline constexpr auto MemoryPartitionRights = std::to_array<Entry>({
    {MEMORY_PARTITION_QUERY_ACCESS, "MEMORY_PARTITION_QUERY_ACCESS"},
    {MEMORY_PARTITION_MODIFY_ACCESS, "MEMORY_PARTITION_MODIFY_ACCESS"},
});

inline constexpr auto TmTmRights = std::to_array<Entry>({
    {TRANSACTIONMANAGER_QUERY_INFORMATION,
     "TRANSACTIONMANAGER_QUERY_INFORMATION"},
    {TRANSACTIONMANAGER_SET_INFORMATION,
     "TRANSACTIONMANAGER_SET_INFORMATION"},
    {TRANSACTIONMANAGER_RECOVER, "TRANSACTIONMANAGER_RECOVER"},
    {TRANSACTIONMANAGER_RENAME, "TRANSACTIONMANAGER_RENAME"},
    {TRANSACTIONMANAGER_CREATE_RM, "TRANSACTIONMANAGER_CREATE_RM"},
    {TRANSACTIONMANAGER_BIND_TRANSACTION,
     "TRANSACTIONMANAGER_BIND_TRANSACTION"},
});

inline constexpr auto TmTxRights = std::to_array<Entry>({
    {TRANSACTION_QUERY_INFORMATION, "TRANSACTION_QUERY_INFORMATION"},
    {TRANSACTION_SET_INFORMATION, "TRANSACTION_SET_INFORMATION"},
    {TRANSACTION_ENLIST, "TRANSACTION_ENLIST"},
    {TRANSACTION_COMMIT, "TRANSACTION_COMMIT"},
    {TRANSACTION_ROLLBACK, "TRANSACTION_ROLLBACK"},
    {TRANSACTION_PROPAGATE, "TRANSACTION_PROPAGATE"},
});

inline constexpr auto TmRmRights = std::to_array<Entry>({
    {RESOURCEMANAGER_QUERY_INFORMATION, "RESOURCEMANAGER_QUERY_INFORMATION"},
    {RESOURCEMANAGER_SET_INFORMATION, "RESOURCEMANAGER_SET_INFORMATION"},
    {RESOURCEMANAGER_RECOVER, "RESOURCEMANAGER_RECOVER"},
    {RESOURCEMANAGER_ENLIST, "RESOURCEMANAGER_ENLIST"},
    {RESOURCEMANAGER_GET_NOTIFICATION, "RESOURCEMANAGER_GET_NOTIFICATION"},
    {RESOURCEMANAGER_REGISTER_PROTOCOL, "RESOURCEMANAGER_REGISTER_PROTOCOL"},
    {RESOURCEMANAGER_COMPLETE_PROPAGATION,
     "RESOURCEMANAGER_COMPLETE_PROPAGATION"},
});

inline constexpr auto TmEnRights = std::to_array<Entry>({
    {ENLISTMENT_QUERY_INFORMATION, "ENLISTMENT_QUERY_INFORMATION"},
    {ENLISTMENT_SET_INFORMATION, "ENLISTMENT_SET_INFORMATION"},
    {ENLISTMENT_RECOVER, "ENLISTMENT_RECOVER"},
    {ENLISTMENT_SUBORDINATE_RIGHTS, "ENLISTMENT_SUBORDINATE_RIGHTS"},
    {ENLISTMENT_SUPERIOR_RIGHTS, "ENLISTMENT_SUPERIOR_RIGHTS"},
});

} // namespace Detail

// 规范键：去 "Type " 前缀与命名空间路径后，把已知别名折叠到表键。
// 未识别的类型原样返回，其专属权限段为空。
inline QString NormalizeTypeName(const QString &TypeName) {
  QString Type = TypeName.trimmed();
  if (Type.startsWith("Type ", Qt::CaseInsensitive))
    Type = Type.mid(5).trimmed();
  if (Type.contains(QLatin1Char('\\')))
    Type = Type.section(QLatin1Char('\\'), -1).trimmed();
  if (Type.compare("Mutex", Qt::CaseInsensitive) == 0)
    return "Mutant";
  if (Type.compare("Registry", Qt::CaseInsensitive) == 0 ||
      Type.compare("RegistryKey", Qt::CaseInsensitive) == 0)
    return "Key";
  if (Type.compare("IoCompletionReserve", Qt::CaseInsensitive) == 0)
    return "IoCompletion";
  if (Type.compare("IRTimer", Qt::CaseInsensitive) == 0)
    return "Timer";
  if (Type.compare("FilterCommunicationPort", Qt::CaseInsensitive) == 0)
    return "FilterConnectionPort";
  return Type;
}

// 对象类型的专属权限表；未覆盖的类型返回空 span。
inline std::span<const Entry> SpecificRights(const QString &TypeName) {
  const QString Key = NormalizeTypeName(TypeName);
  const auto Matches = [&Key](const char *Name) {
    return Key.compare(Name, Qt::CaseInsensitive) == 0;
  };
  if (Matches("Process")) return Detail::ProcessRights;
  if (Matches("Thread")) return Detail::ThreadRights;
  if (Matches("Token")) return Detail::TokenRights;
  if (Matches("Job")) return Detail::JobRights;
  if (Matches("File")) return Detail::FileRights;
  if (Matches("Key")) return Detail::KeyRights;
  if (Matches("Section")) return Detail::SectionRights;
  if (Matches("Event")) return Detail::EventRights;
  if (Matches("Mutant")) return Detail::MutantRights;
  if (Matches("Semaphore")) return Detail::SemaphoreRights;
  if (Matches("Timer")) return Detail::TimerRights;
  if (Matches("IoCompletion")) return Detail::IoCompletionRights;
  if (Matches("WaitCompletionPacket")) return Detail::WaitCompletionPacketRights;
  if (Matches("TpWorkerFactory")) return Detail::TpWorkerFactoryRights;
  if (Matches("Directory")) return Detail::DirectoryRights;
  if (Matches("SymbolicLink")) return Detail::SymbolicLinkRights;
  if (Matches("ALPC Port")) return Detail::AlpcPortRights;
  if (Matches("Desktop")) return Detail::DesktopRights;
  if (Matches("WindowStation")) return Detail::WindowStationRights;
  if (Matches("Session")) return Detail::SessionRights;
  if (Matches("WmiGuid")) return Detail::WmiGuidRights;
  if (Matches("Profile")) return Detail::ProfileRights;
  if (Matches("DebugObject")) return Detail::DebugObjectRights;
  if (Matches("Callback")) return Detail::CallbackRights;
  if (Matches("KeyedEvent")) return Detail::KeyedEventRights;
  if (Matches("FilterConnectionPort")) return Detail::FilterConnectionPortRights;
  if (Matches("MemoryPartition")) return Detail::MemoryPartitionRights;
  if (Matches("TmTm")) return Detail::TmTmRights;
  if (Matches("TmTx")) return Detail::TmTxRights;
  if (Matches("TmRm")) return Detail::TmRmRights;
  if (Matches("TmEn")) return Detail::TmEnRights;
  return {};
}

// 权限选择框的条目：通用权限在前，专属权限在后。
inline std::vector<Entry> PickerEntries(const QString &TypeName) {
  std::vector<Entry> Entries;
  const auto Specific = SpecificRights(TypeName);
  Entries.reserve(Detail::GenericRights.size() + Specific.size());
  Entries.insert(Entries.end(), Detail::GenericRights.begin(),
                 Detail::GenericRights.end());
  Entries.insert(Entries.end(), Specific.begin(), Specific.end());
  return Entries;
}

// 按表顺序解码掩码；未映射的剩余位以十六进制保留，不静默丢弃。
inline void AppendDecoded(QStringList &Parts, quint32 Mask,
                          std::span<const Entry> Entries) {
  quint32 Remaining = Mask;
  for (const Entry &Item : Entries) {
    if (Item.Mask == 0)
      continue;
    if ((Mask & Item.Mask) == Item.Mask) {
      Parts.append(QString::fromLatin1(Item.Name));
      Remaining &= ~Item.Mask;
    }
  }
  if (Remaining != 0)
    Parts.append(QString("0x%1").arg(Remaining, 0, 16).toUpper());
}

// 单表解码：通用权限表或专属权限表各自的完整解码结果。
inline QString DecodeMask(quint32 Mask, std::span<const Entry> Entries) {
  QStringList Parts;
  AppendDecoded(Parts, Mask, Entries);
  return Parts.join(" | ");
}

// 通用权限段 + 专属权限段，共用同一个剩余位累加器，
// 避免两段各自再追加一遍未映射的十六进制剩余值。
inline QString DescribeAccess(const QString &TypeName, quint32 Mask) {
  QStringList Parts;
  quint32 Remaining = Mask;
  const auto Collect = [&Parts, &Remaining, Mask](std::span<const Entry> List) {
    for (const Entry &Item : List) {
      if (Item.Mask == 0)
        continue;
      if ((Mask & Item.Mask) == Item.Mask) {
        Parts.append(QString::fromLatin1(Item.Name));
        Remaining &= ~Item.Mask;
      }
    }
  };
  Collect(Detail::GenericRights);
  Collect(SpecificRights(TypeName));
  if (Remaining != 0)
    Parts.append(QString("0x%1").arg(Remaining, 0, 16).toUpper());
  Parts.removeDuplicates();
  return Parts.join(" | ");
}

// Handles 表 Access 列的显示文本：原始掩码 + 解码结果。
inline QString FormatDisplay(const QString &TypeName, quint32 Mask) {
  const QString Decoded = DescribeAccess(TypeName, Mask);
  const QString Raw = QString("0x%1").arg(Mask, 0, 16).toUpper();
  return Decoded.isEmpty() ? Raw : Raw + " | " + Decoded;
}

} // namespace HandleAccessData
