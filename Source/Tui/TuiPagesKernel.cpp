// Source/Tui/TuiPagesKernel.cpp
// ============================================================
// 内核相关页面（索引 6/8/9/16/17/21/22）：
//   Driver / ServiceManager / Table / KernelInspector /
//   KernelResearch / Hook
// ------------------------------------------------------------
// 与 GUI 对应页面共用同一套后端调用与文案：
//   - 表格列、状态文本、错误文本逐字对齐 Qt 页面
//   - 所有枚举/驱动调用走 TuiAsync，回调在 UI 线程执行
//   - 驱动缺失时不崩溃，状态栏显示 GUI 的失败文案
// 说明：TUI 没有文件选择器（控制台模式下只有 QCoreApplication），
// 因此 GUI 的 Browse 按钮在控制台里改为在对话框内直接输入路径。
// ============================================================

#include "TuiAsync.h"
#include "TuiPages.h"
#include "TuiSync.h"
#include "TuiWidgets.h"

namespace AegisNT::Tui {

// ------------------------------------------------------------
// 页面共用的小工具（独立命名空间，避免与其它 Tui*.cpp 里的
// 匿名 namespace 助手重名——它们在同一个 TU 里会合并）。
// ------------------------------------------------------------
namespace Kd {

std::string Utf8(const QString &Text) { return Text.toStdString(); }

std::string Wide(const WCHAR *Text) {
  return Text != nullptr ? Utf8(QString::fromWCharArray(Text)) : std::string();
}

// 0x0000000000000000（按指针宽度补零）
std::string HexPad(ULONG_PTR Value) {
  char Buffer[40] = {};
  std::snprintf(Buffer, sizeof(Buffer), "0x%0*llX",
                static_cast<int>(sizeof(ULONG_PTR) * 2),
                static_cast<unsigned long long>(Value));
  return Buffer;
}

// 0x1A2B（无补零，与 GUI 的 QString("0x%1").arg(V,0,16).toUpper() 一致）
std::string HexAuto(uint64_t Value) {
  char Buffer[32] = {};
  std::snprintf(Buffer, sizeof(Buffer), "0x%llX",
                static_cast<unsigned long long>(Value));
  return Buffer;
}

// 0x00000000（8 位，NTSTATUS / Win32 错误码）
std::string Hex32(uint32_t Value) {
  char Buffer[24] = {};
  std::snprintf(Buffer, sizeof(Buffer), "0x%08X", Value);
  return Buffer;
}

QString QHexAuto(uint64_t Value) { return QString::fromStdString(HexAuto(Value)); }

QString QHexPad(ULONG_PTR Value) { return QString::fromStdString(HexPad(Value)); }

// ---- 驱动 ----
QString DriverStateName(DWORD State) {
  switch (State) {
  case SERVICE_STOPPED:
    return "Stopped";
  case SERVICE_START_PENDING:
    return "StartPending";
  case SERVICE_STOP_PENDING:
    return "StopPending";
  case SERVICE_RUNNING:
    return "Running";
  case SERVICE_CONTINUE_PENDING:
    return "ContinuePending";
  case SERVICE_PAUSE_PENDING:
    return "PausePending";
  case SERVICE_PAUSED:
    return "Paused";
  default:
    return "Unknown";
  }
}

QString DriverStartTypeName(DWORD Value) {
  switch (Value) {
  case 0:
    return "Boot";
  case 1:
    return "System";
  case 2:
    return "Auto";
  case 3:
    return "Demand";
  case 4:
    return "Disabled";
  default:
    return QString::number(Value);
  }
}

// ---- 服务（ServicePage.cpp 的文案与驱动页不同，单独一套）----
QString ServiceStateName(DWORD State) {
  switch (State) {
  case SERVICE_RUNNING:
    return "Running";
  case SERVICE_STOPPED:
    return "Stopped";
  case SERVICE_PAUSED:
    return "Paused";
  case SERVICE_START_PENDING:
    return "Starting...";
  case SERVICE_STOP_PENDING:
    return "Stopping...";
  default:
    return QString("Unknown(%1)").arg(State);
  }
}

QString ServiceStartTypeName(DWORD Value) {
  switch (Value) {
  case SERVICE_BOOT_START:
    return "Boot";
  case SERVICE_SYSTEM_START:
    return "System";
  case SERVICE_AUTO_START:
    return "Auto";
  case SERVICE_DEMAND_START:
    return "Manual";
  case SERVICE_DISABLED:
    return "Disabled";
  default:
    return QString::number(Value);
  }
}

QString DriverRecordAddressText(const INVENTORY_RECORD &Record) {
  if (Record.Address != 0)
    return QHexAuto(Record.Address);
  for (const ULONG64 Value : Record.Value) {
    if (Value != 0)
      return QHexAuto(Value);
  }
  return "-";
}

// 通用的单行动作结果。
struct ActionOutcome {
  bool Success = false;
  std::string Message;
};

// ============================================================
// 驱动：枚举 + 加载/卸载/隐藏/阻断（逐字复用 GUI 文案）
// ============================================================

struct DriverRowData {
  QString Name;
  QString DisplayName;
  QString Path;
  QString RegistryPath;
  QString SymbolNames;
  QString DeviceLinks;
  QString SearchText;
  DWORD State = 0;
  DWORD Type = 0;
  DWORD StartType = 0;
  DWORD ErrorControl = 0;
  ULONG_PTR DriverObject = 0;
  ULONG_PTR ImageBase = 0;
  DWORD ImageSize = 0;
  UserFileTrustInfo Trust;
};

struct DriverFetch {
  std::vector<DriverRowData> Rows;
  std::map<QString, std::pair<QString, QString>> DecorationCache;
  std::map<QString, UserFileTrustInfo> TrustCache;
  DWORD ErrorCode = ERROR_SUCCESS;
  LONG NtStatus = 0;
  bool Success = false;
  QString Error;
};

DriverFetch FetchDrivers(
    const std::map<QString, std::pair<QString, QString>> &DecorationIn,
    const std::map<QString, UserFileTrustInfo> &TrustIn) {
  DriverFetch Result;
  Result.DecorationCache = DecorationIn;
  Result.TrustCache = TrustIn;

  DRIVER_ENUM_HEADER Header{};
  std::vector<DRIVER_ENUM_ENTRY> Entries;
  Result.Success = QueryDriverEntries(Entries, &Header) != FALSE;
  Result.ErrorCode = G_LastAegisCoreError;
  Result.NtStatus = Header.NtStatus;
  if (!Result.Success && Header.NtStatus == 0) {
    Result.Error = QString("Kernel enumeration failed (error %1).")
                       .arg(Result.ErrorCode);
    return Result;
  }
  Result.Success = true;

  for (const DRIVER_ENUM_ENTRY &Entry : Entries) {
    DriverRowData Row;
    Row.Name = QString::fromWCharArray(Entry.ServiceName);
    Row.DisplayName = QString::fromWCharArray(Entry.DisplayName);
    Row.Path = QString::fromWCharArray(Entry.ImagePath);
    Row.RegistryPath = QString::fromWCharArray(Entry.RegistryPath);
    Row.State = Entry.State;
    Row.Type = Entry.Type;
    Row.StartType = Entry.StartType;
    Row.ErrorControl = Entry.ErrorControl;
    Row.DriverObject = Entry.DriverObject;
    Row.ImageBase = Entry.ImageBase;
    Row.ImageSize = Entry.ImageSize;
    Row.Path = NormalizeUserDriverPath(Row.Path);

    const QString DecorationKey =
        (!Row.Name.isEmpty() ? Row.Name : QFileInfo(Row.Path).completeBaseName())
            .trimmed()
            .toCaseFolded();
    const auto CachedDecoration = Result.DecorationCache.find(DecorationKey);
    if (!DecorationKey.isEmpty() &&
        CachedDecoration != Result.DecorationCache.end()) {
      Row.SymbolNames = CachedDecoration->second.first;
      Row.DeviceLinks = CachedDecoration->second.second;
    } else if (Row.State == SERVICE_RUNNING || Row.DriverObject != 0 ||
               Row.ImageBase != 0) {
      std::vector<INVENTORY_RECORD> DetailRecords;
      INVENTORY_LIST_HEADER DetailHeader{};
      const QStringList Candidates{
          Row.Name, Row.Name.isEmpty() ? QString() : "\\Driver\\" + Row.Name,
          QFileInfo(Row.Path).completeBaseName()};
      for (const QString &Candidate : Candidates) {
        if (Candidate.isEmpty())
          continue;
        DetailRecords.clear();
        if (QueryNamedDriverRecords(Candidate.toStdWString(), DetailRecords,
                                    &DetailHeader) &&
            !DetailRecords.empty()) {
          QStringList Symbols;
          QStringList Links;
          const auto AppendUnique = [](QStringList &List, const QString &Text) {
            if (!Text.isEmpty() && !List.contains(Text, Qt::CaseInsensitive))
              List.append(Text);
          };
          for (const INVENTORY_RECORD &Record : DetailRecords) {
            const QString RecordName =
                QString::fromWCharArray(Record.Name).trimmed();
            const QString RecordType =
                QString::fromWCharArray(Record.TypeName).trimmed();
            const QString RecordPath =
                QString::fromWCharArray(Record.Path).trimmed();
            const QString RecordDetail =
                QString::fromWCharArray(Record.Detail).trimmed();
            const QString RecordAddress = DriverRecordAddressText(Record);
            const QString RecordLabel =
                !RecordName.isEmpty()
                    ? RecordName
                    : (!RecordPath.isEmpty()
                           ? RecordPath
                           : (!RecordDetail.isEmpty() ? RecordDetail
                                                      : RecordAddress));
            const bool LooksLikeDevice =
                Record.Kind == 15 ||
                RecordType.contains("Device", Qt::CaseInsensitive) ||
                RecordPath.contains("\\Device\\", Qt::CaseInsensitive) ||
                RecordDetail.contains("\\Device\\", Qt::CaseInsensitive);
            const bool LooksLikeSymbol =
                Record.Kind == 8 ||
                RecordType.contains("Symbol", Qt::CaseInsensitive) ||
                RecordType.contains("Dispatch", Qt::CaseInsensitive) ||
                RecordPath.contains("Dispatch", Qt::CaseInsensitive) ||
                RecordDetail.contains("Dispatch", Qt::CaseInsensitive);
            const bool LooksLikeLink =
                RecordType.contains("SymbolicLink", Qt::CaseInsensitive) ||
                RecordType.contains("Link", Qt::CaseInsensitive) ||
                RecordPath.contains("\\DosDevices\\", Qt::CaseInsensitive) ||
                RecordDetail.contains("\\DosDevices\\", Qt::CaseInsensitive);
            if (LooksLikeLink) {
              const QString TargetText =
                  !RecordDetail.isEmpty()
                      ? RecordDetail
                      : (!RecordPath.isEmpty() ? RecordPath : RecordAddress);
              AppendUnique(Links, TargetText.isEmpty()
                                      ? RecordLabel
                                      : RecordLabel + " -> " + TargetText);
            } else if (LooksLikeDevice) {
              AppendUnique(Links, RecordLabel.isEmpty()
                                      ? (RecordPath.isEmpty() ? RecordDetail
                                                              : RecordPath)
                                      : RecordLabel);
            } else if (LooksLikeSymbol) {
              AppendUnique(Symbols,
                           RecordLabel + (RecordAddress.isEmpty()
                                              ? QString()
                                              : " @ " + RecordAddress));
            }
          }
          Row.SymbolNames = Symbols.join(" | ");
          Row.DeviceLinks = Links.join(" | ");
          if (!DecorationKey.isEmpty()) {
            Result.DecorationCache[DecorationKey] =
                std::make_pair(Row.SymbolNames, Row.DeviceLinks);
          }
          break;
        }
      }
    }

    if (!Row.Path.isEmpty()) {
      const QString TrustKey =
          QDir::toNativeSeparators(Row.Path).toCaseFolded();
      const auto CachedTrust = Result.TrustCache.find(TrustKey);
      if (CachedTrust != Result.TrustCache.end()) {
        Row.Trust = CachedTrust->second;
      } else if (QFileInfo::exists(Row.Path)) {
        Row.Trust = QueryUserFileTrustCached(Row.Path);
        Result.TrustCache[TrustKey] = Row.Trust;
      }
    }

    Row.SearchText =
        (Row.Name + ' ' + Row.DisplayName + ' ' + Row.Path + ' ' +
         Row.RegistryPath + ' ' + Row.SymbolNames + ' ' + Row.DeviceLinks + ' ' +
         DriverStateName(Row.State) + ' ' + Row.Trust.Signer + ' ' +
         Row.Trust.Sha256 + ' ' + QHexPad(Row.DriverObject) + ' ' +
         QHexPad(Row.ImageBase))
            .toCaseFolded();
    Result.Rows.push_back(std::move(Row));
  }

  std::sort(Result.Rows.begin(), Result.Rows.end(),
            [](const DriverRowData &Left, const DriverRowData &Right) {
              if (Left.State != Right.State)
                return Left.State == SERVICE_RUNNING;
              return Left.Name.compare(Right.Name, Qt::CaseInsensitive) < 0;
            });
  return Result;
}

std::string BuildLoadDriverError(const DRIVER_CONTROL_OUTPUT &Output,
                                 const std::wstring &ServiceName,
                                 const std::wstring &RequestedPath,
                                 const std::wstring &KernelPath) {
  const bool HasKernelResult =
      Output.NtStatus != 0 || Output.Message[0] != L'\0' ||
      Output.RegistryPath[0] != L'\0' || Output.ImagePath[0] != L'\0' ||
      Output.State != 0 || Output.Type != 0 || Output.StartType != 0 ||
      Output.ErrorControl != 0 || Output.DriverObject != 0 ||
      Output.ImageBase != 0 || Output.ImageSize != 0;
  const QString DriverMessage =
      HasKernelResult
          ? QString::fromWCharArray(
                Output.Message[0] ? Output.Message : L"Kernel driver load failed.")
          : QString("DeviceIoControl(IOCTL_LOAD_DRIVER) failed before the "
                    "driver returned a result.");
  const QString DriverDetails = QString::fromStdWString(G_LastAegisCoreDetails);
  const QString EffectiveKernelPath = QString::fromWCharArray(
      Output.ImagePath[0] ? Output.ImagePath : KernelPath.c_str());
  const QString EffectiveRegistryPath =
      QString::fromWCharArray(Output.RegistryPath);
  QString Message =
      QString("%1\nService: %2\nRequested path: %3\nKernel path: %4\n"
              "Win32 error: %5")
          .arg(DriverMessage)
          .arg(QString::fromStdWString(ServiceName))
          .arg(QString::fromStdWString(RequestedPath))
          .arg(EffectiveKernelPath)
          .arg(G_LastAegisCoreError);
  if (HasKernelResult)
    Message += QString("\nNTSTATUS: 0x%1")
                   .arg(static_cast<quint32>(Output.NtStatus), 8, 16,
                        QLatin1Char('0'));
  else
    Message += "\nNTSTATUS: unavailable (IOCTL failed)";
  if (HasKernelResult && !EffectiveRegistryPath.isEmpty())
    Message += "\nRegistry: " + EffectiveRegistryPath;
  if (HasKernelResult && !DriverDetails.isEmpty())
    Message += "\nDetails: " + DriverDetails;
  return Utf8(Message);
}

std::string BuildUnloadDriverError(const DRIVER_CONTROL_OUTPUT &Output,
                                   const QString &ServiceName) {
  const bool HasKernelResult =
      Output.NtStatus != 0 || Output.Message[0] != L'\0' ||
      Output.RegistryPath[0] != L'\0' || Output.ImagePath[0] != L'\0' ||
      Output.State != 0 || Output.Type != 0 || Output.StartType != 0 ||
      Output.ErrorControl != 0 || Output.DriverObject != 0 ||
      Output.ImageBase != 0 || Output.ImageSize != 0;
  const QString DriverMessage =
      HasKernelResult
          ? QString::fromWCharArray(
                Output.Message[0] ? Output.Message
                                  : L"Kernel driver unload failed.")
          : QString("DeviceIoControl(IOCTL_UNLOAD_DRIVER) failed before the "
                    "driver returned a result.");
  QString Message = QString("%1\nService: %2\nWin32 error: %3")
                        .arg(DriverMessage)
                        .arg(ServiceName)
                        .arg(G_LastAegisCoreError);
  if (HasKernelResult)
    Message += QString("\nNTSTATUS: 0x%1")
                   .arg(static_cast<quint32>(Output.NtStatus), 8, 16,
                        QLatin1Char('0'));
  else
    Message += "\nNTSTATUS: unavailable (IOCTL failed)";
  if (HasKernelResult && Output.RegistryPath[0] != L'\0')
    Message += "\nRegistry: " + QString::fromWCharArray(Output.RegistryPath);
  if (HasKernelResult && Output.ImagePath[0] != L'\0')
    Message += "\nImagePath: " + QString::fromWCharArray(Output.ImagePath);
  return Utf8(Message);
}

ActionOutcome LoadDriverAction(const QString &ServiceNameIn,
                               const QString &PathIn, bool KernelMode,
                               bool BypassSignature) {
  ActionOutcome Out;
  const QString ServiceName = ServiceNameIn.trimmed();
  const QString RequestedPathText = QDir::toNativeSeparators(PathIn.trimmed());
  const std::wstring Path = RequestedPathText.toStdWString();
  const std::wstring Name = ServiceName.toStdWString();
  if (Path.empty() || Name.empty()) {
    Out.Message = "Enter a service name and driver path.";
    return Out;
  }
  if (!KernelMode) {
    if (LoadDriverService(Path.c_str(), Name.c_str()) == 0) {
      Out.Success = true;
      Out.Message = "Driver loaded via SCM mode.\nRequested path: " +
                    Utf8(RequestedPathText);
      return Out;
    }
    Out.Message = "SCM mode load failed.\nRequested path: " +
                  Utf8(RequestedPathText) + "\n" +
                  Utf8(DescribeWin32ErrorMessage(GetLastError()));
    return Out;
  }

  QString KernelPathText;
  if (!ConvertDriverServiceImagePath(RequestedPathText, KernelPathText)) {
    Out.Message = "Unable to convert path to kernel path.\nRequested path: " +
                  Utf8(RequestedPathText);
    return Out;
  }

  const std::wstring KernelPath = KernelPathText.toStdWString();
  DRIVER_CONTROL_OUTPUT Output{};
  if (BypassSignature)
    DisableDse();
  const bool Loaded =
      LoadDriverKernel(Name.c_str(), KernelPath.c_str(), &Output) != FALSE;
  if (!Loaded) {
    const std::string KernelError =
        BuildLoadDriverError(Output, Name, Path, KernelPath);
    if (BypassSignature)
      RestoreDse();
    if (LoadDriverService(Path.c_str(), Name.c_str()) == 0) {
      Out.Success = true;
      Out.Message =
          "Kernel load failed; loaded via SCM fallback.\nRequested path: " +
          Utf8(RequestedPathText) + "\nKernel path: " + Utf8(KernelPathText);
      return Out;
    }
    const DWORD ScmError = GetLastError();
    Out.Message = KernelError + "\n\nSCM fallback failed.\nRequested path: " +
                  Utf8(RequestedPathText) + "\n" +
                  Utf8(DescribeWin32ErrorMessage(ScmError));
    return Out;
  }

  Out.Success = true;
  Out.Message = "Kernel driver loaded.\nKernel path: " + Utf8(KernelPathText);
  if (BypassSignature)
    RestoreDse();
  return Out;
}

ActionOutcome UnloadDriverAction(const QString &ServiceName) {
  ActionOutcome Out;
  DRIVER_CONTROL_OUTPUT Output{};
  const std::wstring Service = ServiceName.toStdWString();
  const bool IsRing0Core =
      QString::compare(ServiceName, "Ring0Core", Qt::CaseInsensitive) == 0 ||
      QString::compare(ServiceName, "AegisCore", Qt::CaseInsensitive) == 0;
  if (IsRing0Core) {
    if (UnloadDriverService(Service.c_str()) == 0) {
      Out.Success = true;
      Out.Message = "Driver unloaded via SCM mode.";
    } else {
      Out.Message = Utf8(QString("SCM unload failed.\nService: %1\n%2")
                             .arg(ServiceName, DescribeWin32ErrorMessage(
                                                   GetLastError())));
    }
    return Out;
  }

  if (!UnloadDriverKernel(Service.c_str(), FALSE, &Output)) {
    const std::string KernelError = BuildUnloadDriverError(Output, ServiceName);
    if (UnloadDriverService(Service.c_str()) == 0) {
      Out.Success = true;
      Out.Message = "Kernel unload failed; unloaded via SCM fallback.\n"
                    "Service: " +
                    Utf8(ServiceName);
      return Out;
    }
    const DWORD ScmError = GetLastError();
    Out.Message = KernelError + "\n\nSCM fallback failed.\nService: " +
                  Utf8(ServiceName) + "\n" +
                  Utf8(DescribeWin32ErrorMessage(ScmError));
    return Out;
  }

  std::string Message =
      Wide(Output.Message[0] ? Output.Message : L"Kernel driver unloaded.");
  if (UnloadDriverService(Service.c_str()) == 0)
    Message += "\nSCM cleanup completed.";
  else
    Message += "\nSCM cleanup failed.\n" +
               Utf8(DescribeWin32ErrorMessage(GetLastError()));
  Out.Success = true;
  Out.Message = Message;
  return Out;
}

ActionOutcome HideDriverAction(const QString &ServiceName, bool Permanent) {
  ActionOutcome Out;
  const std::wstring Service = ServiceName.toStdWString();
  DRIVER_HIDE_OUTPUT Output{};
  if (Permanent) {
    if (!HideDriverKernelCid(Service.c_str(), &Output)) {
      const QString DriverMessage =
          Output.Message[0]
              ? QString::fromWCharArray(Output.Message)
              : (G_LastAegisCoreDetails.empty()
                     ? QString("Kernel driver permanent hide failed.")
                     : QString::fromStdWString(G_LastAegisCoreDetails));
      QString Message = QString("%1\nService: %2\nWin32 error: %3")
                            .arg(DriverMessage)
                            .arg(ServiceName)
                            .arg(G_LastAegisCoreError);
      if (Output.NtStatus != 0)
        Message += QString("\nNTSTATUS: 0x%1")
                       .arg(static_cast<quint32>(Output.NtStatus), 8, 16,
                            QLatin1Char('0'));
      Out.Message = Utf8(Message);
      return Out;
    }
    Out.Success = true;
    Out.Message = Wide(Output.Message[0] ? Output.Message
                                         : L"Driver permanently hidden.");
    return Out;
  }

  if (!HideDriverKernel(Service.c_str(), &Output)) {
    const bool HasKernelResult = Output.NtStatus != 0 || Output.Message[0] != L'\0';
    const QString DriverMessage =
        HasKernelResult
            ? QString::fromWCharArray(
                  Output.Message[0] ? Output.Message
                                    : L"Kernel driver hide failed.")
            : QString("DeviceIoControl(IOCTL_HIDE_DRIVER) failed before the "
                      "driver returned a result.");
    QString Message = QString("%1\nService: %2\nWin32 error: %3")
                          .arg(DriverMessage)
                          .arg(ServiceName)
                          .arg(G_LastAegisCoreError);
    if (HasKernelResult)
      Message += QString("\nNTSTATUS: 0x%1")
                     .arg(static_cast<quint32>(Output.NtStatus), 8, 16,
                          QLatin1Char('0'));
    Out.Message = Utf8(Message);
    return Out;
  }
  Out.Success = true;
  Out.Message = Wide(Output.Message[0]
                         ? Output.Message
                         : L"Driver unlinked from PsLoadedModuleList.");
  return Out;
}

ActionOutcome BlockDriverLoadAction(const QString &Pattern) {
  ActionOutcome Out;
  DRIVER_IMAGE_BLOCK_ENTRY Entry{};
  const std::wstring ImagePattern = Pattern.toStdWString();
  wcsncpy_s(Entry.ImagePattern, ImagePattern.c_str(), ImagePattern.size());
  if (DriverImageBlockOperation(DRIVER_IMAGE_BLOCK_OP_ADD, Entry)) {
    Out.Success = true;
    Out.Message = "Driver-load block rule added:\n" + Utf8(Pattern);
    return Out;
  }
  Out.Message = "DriverImageBlockOperation failed.\nWin32 error: " +
                std::to_string(G_LastAegisCoreError);
  return Out;
}

// ---- 驱动检视（Inspector 浮层）----
struct DriverInspectData {
  std::vector<INVENTORY_RECORD> Records;
  std::vector<INVENTORY_RECORD> Modules;
  LONG HeaderStatus = 0;
  bool Ok = false;
};

DriverInspectData FetchDriverRecords(const QString &Name) {
  DriverInspectData Result;
  INVENTORY_LIST_HEADER Header{};
  const QStringList Candidates{
      Name, Name.isEmpty() ? QString() : "\\Driver\\" + Name,
      QFileInfo(Name).completeBaseName()};
  for (const QString &Candidate : Candidates) {
    if (Candidate.isEmpty())
      continue;
    Result.Records.clear();
    if (QueryNamedDriverRecords(Candidate.toStdWString(), Result.Records,
                                &Header) &&
        !Result.Records.empty())
      break;
  }
  Result.HeaderStatus = Header.Status;
  Result.Ok = true;
  Result.Modules = AegisNT::KernelResearch::QueryAll(IOCTL_ENUM_KERNEL_MODULES);
  return Result;
}

// ============================================================
// 服务枚举
// ============================================================
struct ServiceRowData {
  QString Name;
  QString DisplayName;
  QString State;
  QString StartType;
  QString BinaryPath;
  DWORD Pid = 0;
  DWORD Type = 0;
};

std::vector<ServiceRowData> FetchServices() {
  std::vector<ServiceRowData> Result;
  SC_HANDLE Scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
  if (Scm == nullptr)
    return Result;

  DWORD Needed = 0, Count = 0, Resume = 0;
  EnumServicesStatusExW(Scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32 | SERVICE_DRIVER,
                        SERVICE_STATE_ALL, NULL, 0, &Needed, &Count, &Resume,
                        NULL);
  if (Needed != 0) {
    std::vector<BYTE> Buffer(Needed);
    if (EnumServicesStatusExW(Scm, SC_ENUM_PROCESS_INFO,
                              SERVICE_WIN32 | SERVICE_DRIVER,
                              SERVICE_STATE_ALL, Buffer.data(), Needed, &Needed,
                              &Count, &Resume, NULL)) {
      auto *Services =
          reinterpret_cast<LPENUM_SERVICE_STATUS_PROCESSW>(Buffer.data());
      for (DWORD Index = 0; Index < Count; ++Index) {
        ServiceRowData Row;
        Row.Name = QString::fromWCharArray(Services[Index].lpServiceName);
        Row.DisplayName = QString::fromWCharArray(Services[Index].lpDisplayName);
        Row.Pid = Services[Index].ServiceStatusProcess.dwProcessId;
        Row.Type = Services[Index].ServiceStatusProcess.dwServiceType;
        Row.State =
            ServiceStateName(Services[Index].ServiceStatusProcess.dwCurrentState);

        SC_HANDLE Service =
            OpenServiceW(Scm, Services[Index].lpServiceName, SERVICE_QUERY_CONFIG);
        if (Service != nullptr) {
          DWORD ConfigSize = 0;
          QueryServiceConfigW(Service, NULL, 0, &ConfigSize);
          if (ConfigSize >= sizeof(QUERY_SERVICE_CONFIGW)) {
            std::vector<BYTE> ConfigBuffer(ConfigSize);
            auto *Config =
                reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(ConfigBuffer.data());
            DWORD ConfigOutSize = static_cast<DWORD>(ConfigBuffer.size());
            if (QueryServiceConfigW(Service, Config, ConfigOutSize,
                                    &ConfigSize)) {
              Row.BinaryPath = QString::fromWCharArray(Config->lpBinaryPathName);
              Row.StartType = ServiceStartTypeName(Config->dwStartType);
            }
          }
          CloseServiceHandle(Service);
        } else {
          Row.BinaryPath = "-";
          Row.StartType = "-";
        }
        Result.push_back(std::move(Row));
      }
    }
  }
  CloseServiceHandle(Scm);
  return Result;
}

} // namespace Kd

// ============================================================
// 索引 6：Driver
// ============================================================
class DriverPage final : public TuiPage {
public:
  explicit DriverPage(int Index) : Index_(Index) {
    (void)Index_;
    Table_.Headers = {"Service", "Display name", "State", "Type", "Object",
                      "Base", "Size", "Symbol", "Device links", "Signature",
                      "SHA-256", "Path"};
    Table_.RightAlign = {false, false, false, false, true, true, true,
                         false, false, false, false, false};
    OwnedCommands.push_back(TuiCommand{
        "refresh", "refresh  (re-enumerate kernel drivers)",
        [this](std::vector<std::string>) { Refresh(true); }});
    OwnedCommands.push_back(TuiCommand{
        "load", "load  (Load Driver dialog: service name, path, mode)",
        [this](std::vector<std::string>) { ShowLoadDialog(); }});
    OwnedCommands.push_back(TuiCommand{
        "unload", "unload  (unload the selected driver service)",
        [this](std::vector<std::string>) { ConfirmUnload(); }});
    OwnedCommands.push_back(TuiCommand{
        "hide", "hide  (unlink the selected driver from PsLoadedModuleList)",
        [this](std::vector<std::string>) { ConfirmHide(false); }});
    OwnedCommands.push_back(TuiCommand{
        "hide-cid",
        "hide-cid  (permanent hide: PsLoadedModuleList + PiDDBCache + "
        "MmUnloadedDrivers)",
        [this](std::vector<std::string>) { ConfirmHide(true); }});
    OwnedCommands.push_back(TuiCommand{
        "block-load", "block-load <pattern>  (block future loads of an image)",
        [this](std::vector<std::string> Args) { BlockLoad(Args); }});
    OwnedCommands.push_back(TuiCommand{
        "inspect", "inspect  (overview / dispatch / fast I/O / devices)",
        [this](std::vector<std::string>) { Inspect(); }});
  }

  std::string Title() const override { return "Driver"; }

  std::string Subtitle() const override {
    return "loaded kernel drivers: state, image base, signature, path";
  }

  void OnEnter() override { Refresh(false); }

  TuiTable *ActiveTable() override { return &Table_; }

  std::string RenderText() override {
    // `show` 是查看操作：只有从未取过数据时才触发一次异步枚举，
    // 其余情况直接用缓存重新填表，避免每次 show 都重算签名。
    Populate();
    if (Rows_.empty())
      Refresh(false);
    return TuiTableToText(Table_, 200);
  }

private:
  void Refresh(bool ShowResult) {
    if (Refreshing_.exchange(true))
      return;
    SetStatus("Enumerating drivers...");
    auto Decoration = DecorationCache_;
    auto Trust = TrustCache_;
    TuiAsync<Kd::DriverFetch>(
        [Decoration, Trust] { return Kd::FetchDrivers(Decoration, Trust); },
        [this, ShowResult](Kd::DriverFetch Result) {
          Refreshing_ = false;
          DecorationCache_ = std::move(Result.DecorationCache);
          TrustCache_ = std::move(Result.TrustCache);
          if (!Result.Success) {
            Rows_.clear();
            Table_.Rows.clear();
            Table_.Rebuild();
            SetStatus(Result.Error.toStdString());
            if (ShowResult)
              Notify(Result.Error.toStdString(), NoticeKind::Error);
            return;
          }
          Rows_ = std::move(Result.Rows);
          Populate();
          if (ShowResult)
            Notify("Enumerated " + std::to_string(Rows_.size()) + " driver(s).",
                   NoticeKind::Success);
        });
  }

  void Populate() {
    Table_.Filter = Filter;
    Table_.Rows.clear();
    Table_.Rows.reserve(Rows_.size());
    for (const Kd::DriverRowData &Driver : Rows_) {
      const QString SignatureText =
          Driver.Trust.Trusted
              ? Driver.Trust.SignatureKind + " | " + Driver.Trust.Signer
              : QString("Untrusted");
      TuiRow Row;
      Row.Cells = {
          Kd::Utf8(Driver.Name),
          Kd::Utf8(Driver.DisplayName),
          Kd::Utf8(Kd::DriverStateName(Driver.State)),
          Kd::Utf8(QString("0x%1").arg(Driver.Type, 0, 16)),
          Kd::Utf8(Kd::QHexPad(Driver.DriverObject)),
          Kd::Utf8(Kd::QHexPad(Driver.ImageBase)),
          Kd::Utf8(QString("0x%1").arg(Driver.ImageSize, 0, 16)),
          Driver.SymbolNames.isEmpty() ? "-" : Kd::Utf8(Driver.SymbolNames),
          Driver.DeviceLinks.isEmpty() ? "-" : Kd::Utf8(Driver.DeviceLinks),
          Kd::Utf8(SignatureText),
          Kd::Utf8(Driver.Trust.Sha256),
          Kd::Utf8(Driver.Path),
      };
      Row.Detail = Kd::Utf8(QString("Service: %1\nDisplay name: %2\nState: %3\n"
                                    "Type: 0x%4\nStart type: %5\n"
                                    "Object: %6\nBase: %7\nSize: 0x%8\n"
                                    "Signature: %9\nSHA-256: %10\n"
                                    "Registry: %11\nPath: %12")
                                .arg(Driver.Name)
                                .arg(Driver.DisplayName)
                                .arg(Kd::DriverStateName(Driver.State))
                                .arg(Driver.Type, 0, 16)
                                .arg(Kd::DriverStartTypeName(Driver.StartType))
                                .arg(Kd::QHexPad(Driver.DriverObject))
                                .arg(Kd::QHexPad(Driver.ImageBase))
                                .arg(Driver.ImageSize, 0, 16)
                                .arg(SignatureText)
                                .arg(Driver.Trust.Sha256)
                                .arg(Driver.RegistryPath)
                                .arg(Driver.Path));
      Table_.Rows.push_back(std::move(Row));
    }
    Table_.Rebuild();
    SetStatus(std::to_string(Rows_.size()) + " driver(s)");
  }

  const Kd::DriverRowData *CurrentDriver() const {
    const int RowIndex = Table_.CurrentRowIndex();
    if (RowIndex < 0 || RowIndex >= static_cast<int>(Rows_.size()))
      return nullptr;
    return &Rows_[static_cast<size_t>(RowIndex)];
  }

  void ShowLoadDialog() {
    TuiDialog Dialog;
    Dialog.Title = "Load Driver";
    Dialog.Body = "Kernel mode loads through Ring0Core; SCM mode uses the "
                  "service control manager.";
    TuiField Service;
    Service.Label = "Service name";
    Service.Placeholder = "Service name";
    TuiField Path;
    Path.Label = "Driver path";
    Path.Placeholder = "Driver .sys path";
    TuiField Mode;
    Mode.Label = "Load mode";
    Mode.Kind = TuiFieldKind::Combo;
    Mode.Choices = {"KernelMode", "SCMMode"};
    Mode.Choice = 0;
    TuiField Bypass;
    Bypass.Label = "Bypass Signature Verification (BSOD Warning)";
    Bypass.Kind = TuiFieldKind::Check;
    Bypass.Checked = false;
    Dialog.Fields = {Service, Path, Mode, Bypass};
    Dialog.PrimaryLabel = "Load";
    Dialog.Validate = [](const TuiDialog &Value) -> std::string {
      const std::string Name = TrimAscii(Value.Fields[0].Value);
      const std::string File = TrimAscii(Value.Fields[1].Value);
      if (Name.empty() || File.empty())
        return "Enter a service name and driver path.";
      return {};
    };
    Dialog.OnSubmit = [this](TuiDialog &Value) {
      const QString Name = QString::fromStdString(TrimAscii(Value.Fields[0].Value));
      const QString File = QString::fromStdString(TrimAscii(Value.Fields[1].Value));
      const bool KernelMode = Value.Fields[2].Choice == 0;
      const bool BypassSignature = Value.Fields[3].Checked;
      SetStatus("Loading driver...");
      TuiAsync<Kd::ActionOutcome>(
          [Name, File, KernelMode, BypassSignature] {
            return Kd::LoadDriverAction(Name, File, KernelMode,
                                        BypassSignature);
          },
          [this](Kd::ActionOutcome Outcome) {
            Notify(Outcome.Message,
                   Outcome.Success ? NoticeKind::Success : NoticeKind::Error);
            if (Outcome.Success)
              Refresh(false);
            SetStatus(Outcome.Success ? "Driver load requested"
                                      : "Driver load failed");
          });
    };
    Dialogs->Push(std::move(Dialog));
  }

  void ConfirmUnload() {
    const Kd::DriverRowData *Driver = CurrentDriver();
    if (Driver == nullptr) {
      Notify("Select a driver row first.", NoticeKind::Warning);
      return;
    }
    const QString Name = Driver->Name;
    ConfirmDialog(*Dialogs, "Unload Driver",
                  Kd::Utf8(QString("Unload driver and remove service %1 if "
                                   "possible?")
                               .arg(Name)),
                  [this, Name] {
                    SetStatus("Unloading driver...");
                    TuiAsync<Kd::ActionOutcome>(
                        [Name] { return Kd::UnloadDriverAction(Name); },
                        [this](Kd::ActionOutcome Outcome) {
                          Notify(Outcome.Message, Outcome.Success
                                                      ? NoticeKind::Success
                                                      : NoticeKind::Error);
                          SetStatus(Outcome.Success ? "Driver unloaded"
                                                    : "Driver unload failed");
                          Refresh(false);
                        });
                  },
                  "Unload", "Cancel");
  }

  void ConfirmHide(bool Permanent) {
    const Kd::DriverRowData *Driver = CurrentDriver();
    if (Driver == nullptr) {
      Notify("Select a driver row first.", NoticeKind::Warning);
      return;
    }
    const QString Name = Driver->Name;
    if (Permanent) {
      ConfirmDialog(
          *Dialogs, "Hide Driver (Can't Unhide)",
          Kd::Utf8(QString("Permanently hide driver %1?\n\n"
                           "Unlinks it from PsLoadedModuleList, removes its "
                           "PiDDBCacheTable entry and clears its "
                           "MmUnloadedDrivers record.\n"
                           "This is not reversible by this tool.")
                       .arg(Name)),
          [this, Name] {
            SetStatus("Hiding driver permanently...");
            TuiAsync<Kd::ActionOutcome>(
                [Name] { return Kd::HideDriverAction(Name, true); },
                [this](Kd::ActionOutcome Outcome) {
                  Notify(Outcome.Message, Outcome.Success ? NoticeKind::Success
                                                          : NoticeKind::Error);
                  SetStatus(Outcome.Success ? "Driver permanently hidden"
                                            : "Driver hide failed");
                  Refresh(false);
                });
          },
          "Hide", "Cancel");
      return;
    }
    ConfirmDialog(
        *Dialogs, "Hide Driver",
        Kd::Utf8(QString("Hide driver %1 by unlinking it from "
                         "PsLoadedModuleList (DKOM)?\n\n"
                         "The driver stays loaded; it will only disappear "
                         "from standard kernel module listings.")
                     .arg(Name)),
        [this, Name] {
          SetStatus("Hiding driver...");
          TuiAsync<Kd::ActionOutcome>(
              [Name] { return Kd::HideDriverAction(Name, false); },
              [this](Kd::ActionOutcome Outcome) {
                Notify(Outcome.Message, Outcome.Success ? NoticeKind::Success
                                                        : NoticeKind::Error);
                SetStatus(Outcome.Success ? "Driver hidden"
                                          : "Driver hide failed");
              });
        },
        "Hide", "Cancel");
  }

  void BlockLoad(std::vector<std::string> Args) {
    QString Pattern;
    if (!Args.empty())
      Pattern = QString::fromStdString(TrimAscii(Args.front()));
    if (Pattern.isEmpty()) {
      const Kd::DriverRowData *Driver = CurrentDriver();
      if (Driver != nullptr)
        Pattern = Driver->Path.trimmed();
    }
    if (Pattern.isEmpty()) {
      const std::string Name =
          CurrentDriver() != nullptr ? Kd::Utf8(CurrentDriver()->Name)
                                     : std::string("the selected driver");
      Notify("No image path available for " + Name +
                 "; enter a pattern manually.",
             NoticeKind::Error);
      PromptTextDialog(*Dialogs, "Block Driver Load",
                       "Image path pattern (supports * and ?):", {},
                       [this](std::string Text) {
                         const QString Value =
                             QString::fromStdString(TrimAscii(Text));
                         if (!Value.isEmpty())
                           ConfirmBlock(Value);
                       });
      return;
    }
    ConfirmBlock(Pattern);
  }

  void ConfirmBlock(const QString &Pattern) {
    ConfirmDialog(
        *Dialogs, "Block Driver Load",
        Kd::Utf8(QString("Block future load attempts of driver image\n"
                         "%1\n\nThe minifilter will deny executable access "
                         "(section creation) for this image path.")
                     .arg(Pattern)),
        [this, Pattern] {
          TuiAsync<Kd::ActionOutcome>(
              [Pattern] { return Kd::BlockDriverLoadAction(Pattern); },
              [this](Kd::ActionOutcome Outcome) {
                Notify(Outcome.Message, Outcome.Success ? NoticeKind::Success
                                                        : NoticeKind::Error);
                SetStatus(Outcome.Success ? "Driver-load block rule added"
                                          : "Block rule failed");
              });
        });
  }

  void Inspect() {
    const Kd::DriverRowData *Driver = CurrentDriver();
    if (Driver == nullptr) {
      Notify("Select a driver row first.", NoticeKind::Warning);
      return;
    }
    const QString Name = Driver->Name;
    SetStatus("Reading driver details...");
    TuiAsync<Kd::DriverInspectData>(
        [Name] { return Kd::FetchDriverRecords(Name); },
        [this, Name](Kd::DriverInspectData Result) {
          SetStatus("Driver Inspector - " + Name.toStdString());
          std::vector<TuiRow> Overview;
          std::vector<TuiRow> Dispatch;
          std::vector<TuiRow> FastIo;
          std::vector<TuiRow> Devices;
          for (const INVENTORY_RECORD &Record : Result.Records) {
            const QString Address = Kd::QHexAuto(Record.Address);
            if (Record.Kind == 8) {
              TuiRow Row;
              Row.Cells = {Kd::Wide(Record.Name), Kd::Utf8(Address),
                           std::to_string(Record.Source)};
              Dispatch.push_back(std::move(Row));
            } else if (Record.Kind == 16) {
              const auto Owner = AegisNT::KernelResearch::ResolveAddress(
                  Record.Address, Result.Modules);
              TuiRow Row;
              Row.Cells = {
                  Kd::Wide(Record.Name),
                  Kd::Utf8(Address),
                  Kd::Utf8(Kd::QHexAuto(Record.Value[0])),
                  Kd::Utf8(Owner.Module + (Owner.Symbol.isEmpty()
                                               ? QString()
                                               : "!" + Owner.Symbol))};
              FastIo.push_back(std::move(Row));
            } else if (Record.Kind == 15) {
              TuiRow Row;
              Row.Cells = {Kd::Utf8(Address),
                           Kd::Utf8(Kd::QHexAuto(Record.Value[0])),
                           Kd::Utf8(Kd::QHexAuto(Record.Value[5])),
                           std::to_string(Record.Value[1]),
                           Kd::Utf8(Kd::QHexAuto(Record.Value[3])),
                           std::to_string(Record.Value[4]),
                           Kd::Utf8(Kd::QHexAuto(Record.Value[6]))};
              Devices.push_back(std::move(Row));
            } else {
              TuiRow Row;
              Row.Cells = {std::to_string(Record.Kind), Kd::Wide(Record.Name),
                           Kd::Utf8(Address),
                           Kd::Utf8(Kd::QHexAuto(Record.Value[0])),
                           std::to_string(Record.Source)};
              Overview.push_back(std::move(Row));
            }
          }
          if (Result.Records.empty()) {
            TuiRow Row;
            Row.Cells = {"Unavailable", {},
                         {},
                         Kd::Hex32(static_cast<uint32_t>(Result.HeaderStatus)),
                         {}};
            Overview.push_back(std::move(Row));
          }
          if (FastIo.empty()) {
            TuiRow Row;
            Row.Cells = {"(none)", {},
                         {},
                         Result.Records.empty() ? "Driver details unavailable"
                                                : "No Fast I/O callbacks"};
            FastIo.push_back(std::move(Row));
          }

          std::string Body;
          Body += "overview\n";
          Body += "  Kind | Name | Address | Value | Source\n";
          for (const TuiRow &Row : Overview) {
            Body += "  ";
            for (size_t Index = 0; Index < Row.Cells.size(); ++Index) {
              if (Index)
                Body += " | ";
              Body += Row.Cells[Index].empty() ? "-" : Row.Cells[Index];
            }
            Body += '\n';
          }
          Body += "\ndispatch\n";
          Body += "  Major function | Address | Source\n";
          for (const TuiRow &Row : Dispatch) {
            Body += "  ";
            for (size_t Index = 0; Index < Row.Cells.size(); ++Index) {
              if (Index)
                Body += " | ";
              Body += Row.Cells[Index];
            }
            Body += '\n';
          }
          Body += "\nfastio\n";
          Body += "  Fast I/O routine | Address | Dispatch | Owner\n";
          for (const TuiRow &Row : FastIo) {
            Body += "  ";
            for (size_t Index = 0; Index < Row.Cells.size(); ++Index) {
              if (Index)
                Body += " | ";
              Body += Row.Cells[Index];
            }
            Body += '\n';
          }
          Body += "\ndevices\n";
          Body += "  Device | Attached | Next | Type | Flags | Stack | Driver\n";
          for (const TuiRow &Row : Devices) {
            Body += "  ";
            for (size_t Index = 0; Index < Row.Cells.size(); ++Index) {
              if (Index)
                Body += " | ";
              Body += Row.Cells[Index];
            }
            Body += '\n';
          }

          TuiDialog Dialog;
          Dialog.Title = "Driver Inspector - " + Name.toStdString();
          Dialog.Body = std::move(Body);
          Dialog.PrimaryLabel = "Close";
          Dialog.SecondaryLabel.clear();
          Dialog.OnSubmit = [](TuiDialog &) {};
          Dialogs->Push(std::move(Dialog));
        });
  }

  int Index_ = 0;
  TuiTable Table_;
  std::vector<Kd::DriverRowData> Rows_;
  std::map<QString, std::pair<QString, QString>> DecorationCache_;
  std::map<QString, UserFileTrustInfo> TrustCache_;
  std::atomic_bool Refreshing_{false};
};

// ============================================================
// 索引 17：ServiceManager
// ============================================================
class ServicePage final : public TuiPage {
public:
  explicit ServicePage(int Index) : Index_(Index) {
    (void)Index_;
    Table_.Headers = {"Service", "Display Name", "State", "Start Type", "PID",
                      "Path"};
    Table_.RightAlign = {false, false, false, false, true, false};
    OwnedCommands.push_back(TuiCommand{
        "refresh", "refresh  (re-enumerate Windows services and drivers)",
        [this](std::vector<std::string>) { Refresh(true); }});
    OwnedCommands.push_back(TuiCommand{
        "start", "start  (StartServiceW for the selected service)",
        [this](std::vector<std::string>) { StartSelected(); }});
    OwnedCommands.push_back(TuiCommand{
        "stop", "stop  (ControlService(SERVICE_CONTROL_STOP))",
        [this](std::vector<std::string>) { StopSelected(); }});
    OwnedCommands.push_back(TuiCommand{
        "disable", "disable  (kernel driver route or ChangeServiceConfigW)",
        [this](std::vector<std::string>) { SetStartType(false); }});
    OwnedCommands.push_back(TuiCommand{
        "enable", "enable  (kernel driver route or ChangeServiceConfigW)",
        [this](std::vector<std::string>) { SetStartType(true); }});
  }

  std::string Title() const override { return "ServiceManager"; }

  std::string Subtitle() const override {
    return "windows services and drivers: state, start type, pid, path";
  }

  void OnEnter() override { Refresh(false); }

  TuiTable *ActiveTable() override { return &Table_; }

  std::string RenderText() override {
    Populate();
    if (Rows_.empty())
      Refresh(false);
    return TuiTableToText(Table_, 200);
  }

private:
  void Refresh(bool ShowResult) {
    if (Refreshing_.exchange(true))
      return;
    SetStatus("Enumerating services...");
    TuiAsync<std::vector<Kd::ServiceRowData>>(
        [] { return Kd::FetchServices(); },
        [this, ShowResult](std::vector<Kd::ServiceRowData> Result) {
          Refreshing_ = false;
          Rows_ = std::move(Result);
          Populate();
          SetStatus(std::to_string(Rows_.size()) + " service(s)");
          if (ShowResult)
            Notify("Service list refreshed.", NoticeKind::Success);
        });
  }

  void Populate() {
    Table_.Filter = Filter;
    Table_.Rows.clear();
    Table_.Rows.reserve(Rows_.size());
    for (const Kd::ServiceRowData &Service : Rows_) {
      TuiRow Row;
      Row.Cells = {
          Kd::Utf8(Service.Name),
          Kd::Utf8(Service.DisplayName),
          Kd::Utf8(Service.State),
          Kd::Utf8(Service.StartType),
          Service.Pid != 0 ? std::to_string(Service.Pid) : std::string("-"),
          Kd::Utf8(Service.BinaryPath),
      };
      Row.Detail = Kd::Utf8(QString("Service: %1\nDisplay name: %2\n"
                                    "State: %3\nStart type: %4\nPID: %5\n"
                                    "Type: 0x%6\nPath: %7")
                                .arg(Service.Name)
                                .arg(Service.DisplayName)
                                .arg(Service.State)
                                .arg(Service.StartType)
                                .arg(Service.Pid)
                                .arg(Service.Type, 0, 16)
                                .arg(Service.BinaryPath));
      Table_.Rows.push_back(std::move(Row));
    }
    Table_.Rebuild();
  }

  // 关键：TuiTable 的选中行是 Visible 的下标，必须先映射回 Rows_，
  // 否则筛选状态下的动作会作用到错误的服务（GUI 上下文菜单有此 bug）。
  const Kd::ServiceRowData *CurrentService() const {
    const int RowIndex = Table_.CurrentRowIndex();
    if (RowIndex < 0 || RowIndex >= static_cast<int>(Rows_.size()))
      return nullptr;
    return &Rows_[static_cast<size_t>(RowIndex)];
  }

  void StartSelected() {
    const Kd::ServiceRowData *Service = CurrentService();
    if (Service == nullptr) {
      Notify("Select a service row first.", NoticeKind::Warning);
      return;
    }
    const QString Name = Service->Name;
    const std::wstring Wide = Name.toStdWString();
    SetStatus("Starting " + Name.toStdString() + "...");
    TuiAsyncVoid(
        [Wide] {
          SC_HANDLE Scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
          if (Scm != nullptr) {
            SC_HANDLE Service = OpenServiceW(Scm, Wide.c_str(), SERVICE_START);
            if (Service != nullptr) {
              StartServiceW(Service, 0, NULL);
              CloseServiceHandle(Service);
            }
            CloseServiceHandle(Scm);
          }
        },
        [this, Name] {
          MarkMutated();
          Notify("Start requested for " + Kd::Utf8(Name) + ".",
                 NoticeKind::Info);
          Refresh(false);
        });
  }

  void StopSelected() {
    const Kd::ServiceRowData *Service = CurrentService();
    if (Service == nullptr) {
      Notify("Select a service row first.", NoticeKind::Warning);
      return;
    }
    const QString Name = Service->Name;
    const std::wstring Wide = Name.toStdWString();
    SetStatus("Stopping " + Name.toStdString() + "...");
    TuiAsyncVoid(
        [Wide] {
          SC_HANDLE Scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
          if (Scm != nullptr) {
            SC_HANDLE Service = OpenServiceW(Scm, Wide.c_str(), SERVICE_STOP);
            if (Service != nullptr) {
              SERVICE_STATUS Status;
              ControlService(Service, SERVICE_CONTROL_STOP, &Status);
              CloseServiceHandle(Service);
            }
            CloseServiceHandle(Scm);
          }
        },
        [this, Name] {
          MarkMutated();
          Notify("Stop requested for " + Kd::Utf8(Name) + ".",
                 NoticeKind::Info);
          Refresh(false);
        });
  }

  void SetStartType(bool Enable) {
    const Kd::ServiceRowData *Service = CurrentService();
    if (Service == nullptr) {
      Notify("Select a service row first.", NoticeKind::Warning);
      return;
    }
    const QString Name = Service->Name;
    const DWORD Type = Service->Type;
    const std::wstring Wide = Name.toStdWString();
    SetStatus((Enable ? "Enabling " : "Disabling ") + Name.toStdString() +
              "...");
    TuiAsync<bool>(
        [Wide, Type, Enable] {
          // 内核驱动优先走驱动的服务操作 IOCTL（绕过 SCM 保护），
          // 其余情况退回 ChangeServiceConfigW。
          if (G_DeviceHandle != INVALID_HANDLE_VALUE &&
              Type == SERVICE_KERNEL_DRIVER) {
            return Enable ? ServiceEnable(Wide.c_str()) != FALSE
                          : ServiceDisable(Wide.c_str()) != FALSE;
          }
          bool Ok = false;
          SC_HANDLE Scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
          if (Scm != nullptr) {
            SC_HANDLE Service =
                OpenServiceW(Scm, Wide.c_str(), SERVICE_CHANGE_CONFIG);
            if (Service != nullptr) {
              Ok = ChangeServiceConfigW(
                       Service, SERVICE_NO_CHANGE,
                       Enable ? SERVICE_AUTO_START : SERVICE_DISABLED,
                       SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL,
                       NULL) != FALSE;
              CloseServiceHandle(Service);
            }
            CloseServiceHandle(Scm);
          }
          return Ok;
        },
        [this, Name, Enable](bool Ok) {
          MarkMutated();
          Notify(Kd::Utf8(QString("%1 \"%2\"%3")
                              .arg(Enable ? "Enable" : "Disable")
                              .arg(Name)
                              .arg(Ok ? " requested." : " failed.")),
                 Ok ? NoticeKind::Success : NoticeKind::Error);
          Refresh(false);
        });
  }

  int Index_ = 0;
  TuiTable Table_;
  std::vector<Kd::ServiceRowData> Rows_;
  std::atomic_bool Refreshing_{false};
};

// ============================================================
// 索引 8：Table
// ============================================================

namespace Kd {

const std::vector<std::string> &TableKindNames() {
  static const std::vector<std::string> Names{
      "InterruptDescriptorTable", "I/O Timer",
      "SSDT",                     "ShadowSSDT",
      "GlobalDescriptorTable",    "PiDDBCacheTable",
      "CPU Registers",            "MSR Watch",
      "HalDispatchTable",         "HalPrivateDispatchTable",
      "DPC",                      "APC"};
  return Names;
}

struct TableQueryResult {
  SYSTEM_TABLES_OUTPUT Summary{};
  std::array<SYSTEM_TABLE_ENTRIES_OUTPUT, 5> Entries{};
  std::array<bool, 5> Available{};
  PIDDB_CACHE_ENUM_OUTPUT PiDDB{};
  bool PiDDBAvailable = false;
  bool PiDDBQueried = false;
  MSR_QUERY_OUTPUT Msr{};
  bool MsrQueried = false;
  SYSTEM_TABLE_ENTRIES_OUTPUT HalDisp{};
  bool HalDispAvailable = false;
  bool HalDispQueried = false;
  DPC_ENUM_OUTPUT Dpc{};
  bool DpcAvailable = false;
  bool DpcQueried = false;
  APC_CANCEL_OUTPUT Apc{};
  bool ApcAvailable = false;
  bool ApcQueried = false;
  DWORD ApcError = ERROR_SUCCESS;
  DWORD ErrorCode = ERROR_SUCCESS;
  bool Success = false;
  // 模块清单在刷新线程里取一次，Populate 用它解析地址归属。
  std::vector<INVENTORY_RECORD> Modules;
  // APC 投递捕获：装载 APC 标签页时在 worker 线程一次性 Drain，
  // 避免在 UI 线程发 IOCTL。
  bool CaptureQueried = false;
  bool CaptureEnabled = false;
  std::string CaptureSummary;
  std::vector<APC_CAPTURE_ENTRY> CaptureEntries;
};

std::string ApcScanSummary(const TableQueryResult &Result) {
  if (!Result.ApcAvailable)
    return "APC query failed (Win32 error " +
           std::to_string(Result.ApcError) + "); scan completeness unknown.";
  const APC_CANCEL_OUTPUT &Apc = Result.Apc;
  if (Apc.Status != 0)
    return "APC query failed (NTSTATUS " +
           Hex32(static_cast<uint32_t>(Apc.Status)) +
           "); scan completeness unknown.";
  if (Apc.NtoskrnlSize == 0)
    return "Kernel image metadata unavailable; scan completeness unknown.";
  if (!Apc.Resolved || (Apc.Flags & APC_CANCEL_FLAG_ROUTINE_UNRESOLVED))
    return "Full APC inventory listed; PG classification unavailable "
           "(resolver).";
  if (Apc.Flags & APC_CANCEL_FLAG_SCAN_PARTIAL)
    return "Partial scan; some thread queues could not be inspected.";
  if (Apc.ThreadCount == 0)
    return "No threads scanned; scan completeness unknown.";
  if (Apc.Flags & APC_CANCEL_FLAG_TRUNCATED)
    return "Scan finished; APC list truncated at the entry limit.";
  return "Scan finished; APC inventory complete.";
}

// 单个标签页的装载结果。
struct TableTabLoad {
  std::shared_ptr<TableQueryResult> Result;
  bool Success = false;
  DWORD ErrorCode = ERROR_SUCCESS;
};

// 输入是当前查询快照（共享只读），worker 内复制一份再装载该标签页，
// 回调里整体替换，避免与 UI 线程的 Populate 竞争。
TableTabLoad LoadTableTab(std::shared_ptr<const TableQueryResult> Snapshot,
                          int Kind) {
  TableTabLoad Load;
  TableQueryResult Result = Snapshot ? *Snapshot : TableQueryResult{};
  DWORD ErrorCode = ERROR_SUCCESS;
  bool Success = false;
  if (Kind >= 0 && Kind < 5) {
    Success = QuerySystemTableEntries(static_cast<ULONG>(Kind),
                                      &Result.Entries[Kind]) != FALSE;
    Result.Available[Kind] = Success;
    if (Success) {
      if (Kind == 2)
        (void)ServiceNamesForTable(SYSTEM_TABLE_KIND_SSDT);
      else if (Kind == 3)
        (void)ServiceNamesForTable(SYSTEM_TABLE_KIND_SHADOW_SSDT);
    }
  } else if (Kind == 5) {
    Success = QueryPiDDBCacheEntries(&Result.PiDDB) != FALSE;
    ErrorCode = G_LastAegisCoreError;
    Result.PiDDBQueried = true;
    Result.PiDDBAvailable = Success || ErrorCode == ERROR_NOT_FOUND;
  } else if (Kind == 6) {
    Success = true;
  } else if (Kind == 7) {
    Success = MsrQueryValues(&Result.Msr) != FALSE;
    ErrorCode = G_LastAegisCoreError;
    Result.MsrQueried = true;
  } else if (Kind == 8 || Kind == 9) {
    Success = QueryHalDispatchEntries(
                  Kind == 8 ? HAL_DISPATCH_TABLE_KIND_PUBLIC
                            : HAL_DISPATCH_TABLE_KIND_PRIVATE,
                  &Result.HalDisp) != FALSE;
    ErrorCode = G_LastAegisCoreError;
    Result.HalDispQueried = true;
    Result.HalDispAvailable = Success || ErrorCode == ERROR_NOT_FOUND;
  } else if (Kind == 10) {
    Success = EnumerateDpcQueue(&Result.Dpc) != FALSE;
    ErrorCode = G_LastAegisCoreError;
    Result.DpcQueried = true;
    Result.DpcAvailable = Success || ErrorCode == ERROR_NOT_FOUND;
  } else if (Kind == 11) {
    APC_CANCEL_OUTPUT Output{};
    Success = EnumerateApcs(&Output) != FALSE;
    Result.Apc = Output;
    ErrorCode = G_LastAegisCoreError;
    Result.ApcQueried = true;
    Result.ApcAvailable = Success || ErrorCode == ERROR_NOT_FOUND;
    Result.ApcError = ErrorCode;

    // 投递捕获：进入 APC 页时一次性 Drain 填充；之后由 500ms tick 增量追加。
    const ULONG MaxShow = APC_CAPTURE_MAX_ENTRIES;
    std::vector<BYTE> Buffer(sizeof(APC_CAPTURE_OUTPUT) +
                             sizeof(APC_CAPTURE_ENTRY) * (MaxShow - 1));
    auto *Capture = reinterpret_cast<PAPC_CAPTURE_OUTPUT>(Buffer.data());
    DWORD CapReturned = 0;
    if (ApcCaptureDrain(Capture, static_cast<DWORD>(Buffer.size()),
                        &CapReturned)) {
      Result.CaptureQueried = true;
      Result.CaptureEnabled = Capture->Enabled != 0;
      const ULONG CapCount = std::min<ULONG>(Capture->EntryCount, MaxShow);
      Result.CaptureEntries.assign(Capture->Entries,
                                   Capture->Entries + CapCount);
      Result.CaptureSummary = Utf8(
          QString("enabled %1 | captured %2 | dropped %3 | blocked %4 | "
                  "block PG %5 | hooks export %6 internal %7")
              .arg(Capture->Enabled ? "yes" : "no")
              .arg(Capture->Captured)
              .arg(Capture->Dropped)
              .arg(Capture->Blocked)
              .arg(Capture->BlockPgEnabled ? "on" : "off")
              .arg((Capture->Flags & APC_CAPTURE_FLAG_HOOK_EXPORT_OK) ? "ok"
                                                                     : "no")
              .arg((Capture->Flags & APC_CAPTURE_FLAG_HOOK_INTERNAL_OK) ? "ok"
                                                                       : "no"));
    }
  }
  // ERROR_NOT_FOUND 视为"表存在但为空"而非加载失败。
  const bool NotFoundTolerated =
      (Kind == 5 && ErrorCode == ERROR_NOT_FOUND) ||
      ((Kind == 8 || Kind == 9) && ErrorCode == ERROR_NOT_FOUND) ||
      (Kind == 10 && ErrorCode == ERROR_NOT_FOUND) ||
      (Kind == 11 && ErrorCode == ERROR_NOT_FOUND);
  Load.Result = std::make_shared<TableQueryResult>(std::move(Result));
  Load.Success = Success;
  Load.ErrorCode = NotFoundTolerated ? ErrorCode : G_LastAegisCoreError;
  Load.Result->ErrorCode = Load.ErrorCode;
  return Load;
}

// 免查已装载的条件（与 GUI 的 AlreadyLoaded 判定一致）。
bool TableTabAlreadyLoaded(const TableQueryResult &Result, int Tab) {
  return Tab == 6 || (Tab >= 0 && Tab < 5 && Result.Available[Tab]) ||
         (Tab == 5 && Result.PiDDBQueried) || (Tab == 7 && Result.MsrQueried) ||
         ((Tab == 8 || Tab == 9) && Result.HalDispQueried) ||
         (Tab == 10 && Result.DpcQueried) || (Tab == 11 && Result.ApcQueried);
}

} // namespace Kd

class TablePage final : public TuiPage {
public:
  explicit TablePage(int Index) : Index_(Index) {
    (void)Index_;
    Table_.Headers = {"Index", "Name", "Address", "Module / Symbol", "State",
                      "Metadata"};
    Table_.RightAlign = {true, false, true, false, false, false};
    OwnedCommands.push_back(TuiCommand{
        "kind", "kind <n|name>  (select one of the 12 system tables)",
        [this](std::vector<std::string> Args) { SelectKind(Args); }});
    OwnedCommands.push_back(TuiCommand{
        "refresh", "refresh  (re-read system table summary and the selected tab)",
        [this](std::vector<std::string>) { Refresh(true); }});
    OwnedCommands.push_back(TuiCommand{
        "watch-on", "watch-on  (MsrWatchEnable: capture the MSR baseline)",
        [this](std::vector<std::string>) { SetMsrWatch(true); }});
    OwnedCommands.push_back(TuiCommand{
        "watch-off", "watch-off  (MsrWatchDisable)",
        [this](std::vector<std::string>) { SetMsrWatch(false); }});
    OwnedCommands.push_back(TuiCommand{
        "capture", "capture  (toggle APC delivery capture)",
        [this](std::vector<std::string>) { ToggleCapture(); }});
    OwnedCommands.push_back(TuiCommand{
        "inject-apc", "inject-apc  (InjectTestApc, then reload the APC tab)",
        [this](std::vector<std::string>) { InjectTestApcAction(); }});
    OwnedCommands.push_back(TuiCommand{
        "remove", "remove  (remove the selected table entry)",
        [this](std::vector<std::string>) { RemoveSelected(); }});
    OwnedCommands.push_back(TuiCommand{
        "search", "search <text>  (filter the current tab)",
        [this](std::vector<std::string> Args) { SetSearch(Args); }});
  }

  std::string Title() const override { return "Table"; }

  std::string Subtitle() const override {
    return "system tables: IDT, SSDT, GDT, PiDDB, registers, MSR, DPC, APC";
  }

  void OnEnter() override {
    SummaryQueried_ = false;
    Refresh(false);
  }

  void OnTick(int64_t NowMs) override {
    // 仅 APC 捕获页需要 500 ms 一次的 drain；非当前页 shell 不会 tick。
    if (Kind_ != 11)
      return;
    if (LastDrainMs_ != 0 && NowMs - LastDrainMs_ < 500)
      return;
    LastDrainMs_ = NowMs;
    DrainCapture();
  }

  TuiTable *ActiveTable() override { return &Table_; }

  std::string RenderText() override {
    if (!SummaryQueried_)
      Refresh(false);
    Populate();
    // 先用一行 tab 列出 12 张系统表（当前表加方括号），再是顶部状态行，
    // 最后是表格本体——与 GUI 顶部的 "table / capture" 栏对应。
    std::string Text = KindStrip();
    Text += '\n';
    Text += "table: " + Kd::TableKindNames()[static_cast<size_t>(Kind_)] +
            " | capture " + (CaptureEnabled_ ? "on" : "off") + '\n';
    Text += TuiTableToText(Table_, 200);
    return Text;
  }

private:
  std::string KindStrip() const {
    return ::AegisNT::Tui::TabStrip(Kd::TableKindNames(), static_cast<int>(Kind_));
  }

  void SelectKind(std::vector<std::string> Args) {
    if (Args.empty()) {
      Notify("Usage: kind <0-11> or kind <name>", NoticeKind::Warning);
      return;
    }
    const std::string Needle = LowerAscii(TrimAscii(Args.front()));
    int Selected = -1;
    const auto &Names = Kd::TableKindNames();
    for (size_t Index = 0; Index < Names.size(); ++Index) {
      if (LowerAscii(Names[Index]).find(Needle) != std::string::npos) {
        Selected = static_cast<int>(Index);
        break;
      }
    }
    if (Selected < 0) {
      try {
        const int Value = std::stoi(Needle);
        if (Value >= 0 && Value < static_cast<int>(Names.size()))
          Selected = Value;
      } catch (...) {
        Selected = -1;
      }
    }
    if (Selected < 0) {
      Notify("Unknown table kind: " + std::string(Args.front()),
             NoticeKind::Warning);
      return;
    }
    Kind_ = Selected;
    CaptureRows_.clear();
    LastCaptureSequence_ = 0;
    Populate();
    LoadSelectedTab(false);
  }

  void SetSearch(std::vector<std::string> Args) {
    std::string Text;
    for (const std::string &Arg : Args) {
      if (!Text.empty())
        Text += ' ';
      Text += Arg;
    }
    Filter = TrimAscii(Text);
    Table_.Filter = Filter;
    Table_.Rebuild();
    SetStatus(Filter.empty() ? "filter cleared" : "filter: " + Filter);
  }

  void Refresh(bool ShowResult) {
    if (Refreshing_.exchange(true))
      return;
    SetStatus("Reading system tables...");
    TuiAsync<std::shared_ptr<Kd::TableQueryResult>>(
        [] {
          auto Result = std::make_shared<Kd::TableQueryResult>();
          Result->Success = QuerySystemTables(&Result->Summary) != FALSE;
          Result->ErrorCode = G_LastAegisCoreError;
          const auto Modules =
              AegisNT::KernelResearch::QueryAll(IOCTL_ENUM_KERNEL_MODULES);
          auto &Symbols = AegisNT::KernelResearch::SymbolService::Instance();
          Symbols.Initialize();
          Symbols.ReloadModules(Modules);
          Result->Modules = Modules;
          return Result;
        },
        [this, ShowResult](std::shared_ptr<Kd::TableQueryResult> Result) {
          Refreshing_ = false;
          Result_ = std::move(Result);
          SummaryQueried_ = true;
          if (!Result_ || !Result_->Success) {
            const std::string Message =
                "Query failed (error " +
                std::to_string(Result_ ? Result_->ErrorCode
                                       : G_LastAegisCoreError) +
                ").";
            SetStatus(Message);
            if (ShowResult)
              Notify(Message, NoticeKind::Error);
            Populate();
            return;
          }
          SetStatus("System table summary updated.");
          if (ShowResult)
            Notify("System tables updated from AegisCore.",
                   NoticeKind::Success);
          Populate();
          LoadSelectedTab(false);
        });
  }

  void LoadSelectedTab(bool ShowResult) {
    if (!Result_)
      return;
    const int Tab = Kind_;
    if (Kd::TableTabAlreadyLoaded(*Result_, Tab)) {
      Populate();
      return;
    }
    if (TabLoading_.exchange(true))
      return;
    SetStatus("Loading " + Kd::TableKindNames()[static_cast<size_t>(Tab)] +
              "...");
    std::shared_ptr<const Kd::TableQueryResult> Snapshot = Result_;
    TuiAsync<Kd::TableTabLoad>(
        [Snapshot, Tab] { return Kd::LoadTableTab(Snapshot, Tab); },
        [this, Tab, ShowResult](Kd::TableTabLoad Load) {
          TabLoading_ = false;
          if (Load.Result)
            Result_ = Load.Result;
          const bool Loaded =
              Load.Success ||
              (Result_ != nullptr &&
               ((Tab == 5 && Result_->PiDDBAvailable) ||
                ((Tab == 8 || Tab == 9) && Result_->HalDispAvailable) ||
                (Tab == 10 && Result_->DpcAvailable) ||
                (Tab == 11 && Result_->ApcAvailable)));
          if (!Loaded) {
            const std::string Message =
                "Load failed (error " + std::to_string(Load.ErrorCode) + ")";
            SetStatus(Message);
            if (Tab == 11 && Kind_ == Tab)
              Populate();
            if (ShowResult)
              Notify(Message, NoticeKind::Error);
            return;
          }
          if (Kind_ == Tab)
            Populate();
          if (Tab != 11)
            SetStatus("Loaded " +
                      Kd::TableKindNames()[static_cast<size_t>(Tab)]);
          if (ShowResult && Tab != 11)
            Notify("Selected table loaded.", NoticeKind::Success);
        });
  }

  struct RowMeta {
    quintptr Target = 0;
    ULONG DpcCpu = 0;
  };

  void ResetRows() {
    Table_.Rows.clear();
    Meta_.clear();
    CaptureRowCount_ = 0;
  }

  void AddRow(const std::string &Index, const std::string &Name,
              const std::string &Address, const std::string &Metadata = {},
              uint64_t TargetAddress = 0, quintptr RemoveTarget = 0,
              ULONG DpcCpu = 0) {
    AegisNT::KernelResearch::AddressInfo Owner;
    if (TargetAddress != 0) {
      static const std::vector<INVENTORY_RECORD> NoModules;
      Owner = AegisNT::KernelResearch::ResolveAddress(
          TargetAddress, ModulesPtr_ != nullptr ? *ModulesPtr_ : NoModules);
    }
    const std::string Ownership =
        TargetAddress != 0
            ? (Owner.Module.isEmpty()
                   ? std::string("-")
                   : Kd::Utf8(QString("%1+0x%2")
                                  .arg(Owner.Module)
                                  .arg(Owner.Rva, 0, 16)
                                  .toUpper()) +
                         (Owner.Symbol.isEmpty()
                              ? std::string()
                              : " | " + Kd::Utf8(Owner.Symbol)))
            : std::string("-");
    const std::string OwnershipState =
        TargetAddress != 0 ? Kd::Utf8(Owner.Status) : std::string("-");
    TuiRow Row;
    Row.Cells = {Index, Name, Address, Ownership, OwnershipState, Metadata};
    Row.Detail = Name + "\n" + Address + "\n" + Ownership + "\n" + Metadata;
    Table_.Rows.push_back(std::move(Row));
    Meta_.push_back(RowMeta{RemoveTarget, DpcCpu});
  }

  // 直接构造 capture 行（已带完整元数据）。
  void AppendCaptureRows(const APC_CAPTURE_ENTRY *Entries, ULONG Count) {
    for (ULONG Index = 0; Index < Count; ++Index) {
      const APC_CAPTURE_ENTRY &Entry = Entries[Index];
      const bool Blocked = (Entry.Flags & APC_CANCEL_REASON_BLOCKED) != 0;
      const bool Test = (Entry.Flags & APC_CANCEL_REASON_TEST_APC) != 0;
      const std::string Name = Blocked ? "BLOCKED"
                                       : (Test ? "TEST-APC" : "hooked insert");
      std::string TimeText = "-";
      if (Entry.TimeStamp != 0) {
        const qint64 UnixSecs =
            static_cast<qint64>(Entry.TimeStamp / 10000000ULL) - 11644473600LL;
        TimeText = Kd::Utf8(
            QDateTime::fromSecsSinceEpoch(UnixSecs).toString("HH:mm:ss.zzz"));
      }
      const std::string Meta = Kd::Utf8(
          QString("Time %1 | seq %2 | TID %3 | mode %4 | Kernel %5 | "
                  "Rundown %6 | Normal %7 | Arg1 %8 | Arg2 %9 | flags 0x%10")
              .arg(QString::fromStdString(TimeText))
              .arg(Entry.Sequence)
              .arg(Entry.TargetThreadId)
              .arg(Entry.ApcMode == 0 ? "kernel" : "user")
              .arg(Kd::QHexPad(Entry.KernelRoutine))
              .arg(Kd::QHexPad(Entry.RundownRoutine))
              .arg(Kd::QHexPad(Entry.NormalRoutine))
              .arg(Kd::QHexPad(Entry.SystemArgument1))
              .arg(Kd::QHexPad(Entry.SystemArgument2))
              .arg(Entry.Flags, 0, 16)
              .toUpper());
      TuiRow Row;
      Row.Cells = {"cap", Name, Kd::HexPad(Entry.ApcObject), "-", "-", Meta};
      Row.Detail = Name + "\n" + Meta;
      CaptureRows_.insert(CaptureRows_.begin(), std::move(Row));
      if (Entry.Sequence > LastCaptureSequence_)
        LastCaptureSequence_ = Entry.Sequence;
    }
    while (CaptureRows_.size() > APC_CAPTURE_UI_LIMIT)
      CaptureRows_.pop_back();
  }

  void Populate() {
    ResetRows();
    if (!Result_)
      return;
    Table_.Filter = Filter;
    Kd::TableQueryResult &Result = *Result_;
    ModulesPtr_ = &Result.Modules;
    const int Tab = Kind_;
    const auto Hex = [](ULONG_PTR Value) { return Kd::HexPad(Value); };
    const auto Hex64 = [](ULONG64 Value) {
      char Buffer[32] = {};
      std::snprintf(Buffer, sizeof(Buffer), "0x%016llX",
                    static_cast<unsigned long long>(Value));
      return std::string(Buffer);
    };

    if (Tab < 5 && Result.Available[Tab]) {
      const SYSTEM_TABLE_ENTRIES_OUTPUT &Output = Result.Entries[Tab];
      AddRow("-", "Table Base", Hex(Output.TableBase),
             std::to_string(Output.Count) + " of " +
                 std::to_string(Output.TotalCount) + " entries",
             Output.TableBase, 0);
      for (ULONG Index = 0; Index < Output.Count; ++Index) {
        const SYSTEM_TABLE_ENTRY &Entry = Output.Entries[Index];
        AddRow(std::to_string(Entry.Index),
               Kd::Utf8(SystemTableEntryName(Tab, Entry)), Hex(Entry.Address),
               std::to_string(Entry.ArgumentBytes), Entry.Address, 0);
      }
    } else if (Tab == 5 && Result.PiDDBQueried && Result.PiDDBAvailable) {
      const PIDDB_CACHE_ENUM_OUTPUT &PiDDB = Result.PiDDB;
      AddRow("-", "PiDDBCacheTable", Hex(PiDDB.TableAddress),
             std::to_string(PiDDB.Count) + " of " +
                 std::to_string(PiDDB.TotalCount) + " entries",
             0, 0);
      AddRow("-", "Table Discovery", "-",
             Kd::Utf8(QString("LEA %1/%2  LIST %3/%4  SIG %5/%6")
                          .arg(PiDDB.LeaScore)
                          .arg(PiDDB.LeaCandidates)
                          .arg(PiDDB.ListScore)
                          .arg(PiDDB.ListCandidates)
                          .arg(PiDDB.SigScore)
                          .arg(PiDDB.SigCandidates)),
             0, 0);
      if (PiDDB.Count == 0) {
        const bool Found = PiDDB.TableAddress != 0;
        AddRow("-", Found ? "(no entries)" : "(not found)", "-",
               Found ? "No entries were returned; the cache may be empty or "
                       "may have changed during enumeration."
                     : "No validated AVL or LIST candidate was found.",
               0, 0);
      }
      for (ULONG Index = 0; Index < PiDDB.Count; ++Index) {
        const PIDDB_CACHE_ENTRY_INFO &Entry = PiDDB.Entries[Index];
        const std::string Name =
            Entry.DriverName[0] ? Kd::Wide(Entry.DriverName) : "(unknown)";
        AddRow(std::to_string(Entry.Index), Name, Hex(Entry.Address),
               Kd::Utf8(QString("TimeDateStamp: %1 | LoadStatus: 0x%2")
                            .arg(FormatPeTimeDateStamp(Entry.TimeDateStamp))
                            .arg(static_cast<quint32>(Entry.LoadStatus), 8, 16,
                                 QLatin1Char('0'))
                            .toUpper()),
               0, static_cast<quintptr>(Entry.Address));
      }
    } else if ((Tab == 8 || Tab == 9) && Result.HalDispQueried &&
               Result.HalDispAvailable) {
      const SYSTEM_TABLE_ENTRIES_OUTPUT &Output = Result.HalDisp;
      const int NameKind =
          Tab == 8 ? HAL_DISPATCH_TABLE_KIND_PUBLIC : HAL_DISPATCH_TABLE_KIND_PRIVATE;
      const auto HalSlotName = [](int Kind, ULONG Index) -> std::string {
        if (Kind == HAL_DISPATCH_TABLE_KIND_PUBLIC) {
          static const char *PublicSlots[] = {"HaliQuerySystemInformation",
                                              "HalSetSystemInformation"};
          if (Index < 2)
            return PublicSlots[Index];
          char Buffer[32] = {};
          std::snprintf(Buffer, sizeof(Buffer), "HalDispatchSlot %X", Index);
          return Buffer;
        }
        char Buffer[32] = {};
        std::snprintf(Buffer, sizeof(Buffer), "PrivateSlot %X", Index);
        return Buffer;
      };
      AddRow("-", "Table Base", Hex(Output.TableBase),
             std::to_string(Output.Count) + " of " +
                 std::to_string(Output.TotalCount) + " entries",
             Output.TableBase, 0);
      for (ULONG Index = 0; Index < Output.Count; ++Index) {
        const SYSTEM_TABLE_ENTRY &Entry = Output.Entries[Index];
        AddRow(std::to_string(Entry.Index), HalSlotName(NameKind, Entry.Index),
               Hex(Entry.Address), {}, Entry.Address, 0);
      }
    } else if (Tab == 10 && Result.DpcQueried && Result.DpcAvailable) {
      const DPC_ENUM_OUTPUT &Dpc = Result.Dpc;
      const ULONG RowCount = std::min<ULONG>(Dpc.Count, DPC_MAX_ENTRIES);
      const bool HasDiagnostics =
          (Dpc.SnapshotFlags & DPC_SNAPSHOT_DIAGNOSTICS_VALID) != 0;
      const bool TimerSource = Dpc.DpcSource == DPC_SOURCE_TIMER_TABLE;
      ULONG RepresentedCpus = 0;
      for (ULONG Index = 0; Index < RowCount; ++Index) {
        bool Seen = false;
        for (ULONG Previous = 0; Previous < Index; ++Previous) {
          if (Dpc.Entries[Previous].Cpu == Dpc.Entries[Index].Cpu) {
            Seen = true;
            break;
          }
        }
        if (!Seen)
          ++RepresentedCpus;
      }
      AddRow("-", TimerSource ? "Timer-associated DPCs" : "DPC Queue", "-",
             std::to_string(RowCount) + " shown | " +
                 std::to_string(RepresentedCpus) + " CPUs represented | " +
                 std::to_string(Dpc.CpuCount) + " active CPUs",
             0, 0);
      AddRow("-", "CPU Coverage", "-",
             Kd::Utf8(QString("PRCBs read %1/%2 | %3 | CPU labels identify "
                              "the owning table/queue")
                          .arg(Dpc.DpcPrcbCount)
                          .arg(Dpc.CpuCount)
                          .arg(HasDiagnostics && TimerSource
                                   ? QString("TimerTables located %1/%2")
                                         .arg(Dpc.DpcAcceptedCount)
                                         .arg(Dpc.CpuCount)
                                   : QString("table coverage unavailable"))),
             0, 0);
      if (HasDiagnostics) {
        AddRow("-", "Snapshot", "-",
               Kd::Utf8(
                   QString("%1 valid references observed before deduplication "
                           "| %2 | %3")
                       .arg(Dpc.TotalCount)
                       .arg(Dpc.SnapshotFlags & DPC_SNAPSHOT_TRUNCATED
                                ? QString("truncated: CPU-balanced sample, "
                                          "limit %1")
                                      .arg(DPC_MAX_ENTRIES)
                                : QString("within output capacity"))
                       .arg(Dpc.SnapshotFlags & DPC_SNAPSHOT_SCAN_INCOMPLETE
                                ? QString("some reads or walks incomplete; see "
                                          "driver log")
                                : QString("bounded scan finished"))),
               0, 0);
      } else {
        AddRow("-", "Snapshot", "-",
               "Legacy driver: CPU coverage/truncation diagnostics "
               "unavailable",
               0, 0);
      }
      AddRow("-", "TimerTable", "-",
             Dpc.DpcSource == DPC_SOURCE_TIMER_TABLE
                 ? Kd::Utf8(QString("KPRCB+0x%1 | entry+0x%2 | %3 buckets | "
                                    "decoded %4 | undecodable %5")
                                .arg(Dpc.TimerTableOffset, 0, 16)
                                .arg(Dpc.TimerTableEntryOffset, 0, 16)
                                .arg(Dpc.TimerTableBuckets)
                                .arg(Dpc.TimerDecodedCount)
                                .arg(Dpc.TimerDecodeFailCount)
                                .toUpper())
                 : std::string("not located — window-scan fallback in use"),
             0, 0);
      AddRow("-", "KiWait Keys", "-",
             Dpc.KeyResolveSource == 1
                 ? Kd::Utf8(QString("Never 0x%1 @ %2 | Always 0x%3 @ %4")
                                .arg(Dpc.KiWaitNeverValue, 0, 16)
                                .arg(QString::fromStdString(Hex(Dpc.KiWaitNeverAddress)))
                                .arg(Dpc.KiWaitAlwaysValue, 0, 16)
                                .arg(QString::fromStdString(Hex(Dpc.KiWaitAlwaysAddress)))
                                .toUpper())
                 : std::string("not resolved — encoded timer DPCs unavailable"),
             0, 0);
      AddRow("-", "PRCB Source", "-",
             Dpc.PrcbResolveSource == 1
                 ? std::string("KiProcessorBlock export")
                 : (Dpc.PrcbResolveSource == 2
                        ? std::string("KiProcessorBlock via verified accessor")
                        : std::string("unresolved")),
             0, 0);
      if (Dpc.DpcSource == DPC_SOURCE_WINDOW_SCAN) {
        AddRow("-", "DPC Scan", "-",
               Kd::Utf8(QString("PRCBs %1 | candidates %2 | accepted heads "
                                "%3 | window 0x%4")
                            .arg(Dpc.DpcPrcbCount)
                            .arg(Dpc.DpcCandidateCount)
                            .arg(Dpc.DpcAcceptedCount)
                            .arg(Dpc.DpcScanWindow, 0, 16)
                            .toUpper()),
               0, 0);
      }
      if (Dpc.Count == 0) {
        AddRow("-", "(idle)", "-",
               Dpc.DpcSource == DPC_SOURCE_TIMER_TABLE
                   ? Kd::Utf8(QString("No usable timer DPCs found; "
                                      "TimerTable at KPRCB+0x%1. Check key "
                                      "resolution and skipped entries")
                                  .arg(Dpc.TimerTableOffset, 0, 16)
                                  .toUpper())
                   : std::string("No DPCs currently queued — normal when the "
                                 "CPU is idle; accepted heads > 0 confirms "
                                 "the queue scan works"),
               0, 0);
      }
      for (ULONG Index = 0; Index < RowCount; ++Index) {
        const DPC_ENUM_ENTRY &Entry = Dpc.Entries[Index];
        const std::string Due =
            Entry.DueTime != 0
                ? Kd::Utf8(QString("Due: 0x%1").arg(Entry.DueTime, 0, 16)
                               .toUpper())
                : std::string("Due: -");
        AddRow(std::to_string(Entry.Index),
               Kd::Utf8(QString(TimerSource ? "Timer CPU %1" : "Queue CPU %1")
                            .arg(Entry.Cpu)),
               Hex(Entry.Routine),
               Kd::Utf8(QString("Context: %1 | %2 | %3")
                            .arg(QString::fromStdString(Hex(Entry.Context)))
                            .arg(QString::fromStdString(Due))
                            .arg((Entry.Flags & DPC_ENTRY_FLAG_IN_QUEUE)
                                     ? ((Entry.Flags & DPC_ENTRY_FLAG_THREADED)
                                            ? "queued/threaded"
                                            : "queued")
                                     : "timer reference")),
               Entry.Routine, static_cast<quintptr>(Entry.DpcObject),
               Entry.Cpu);
      }
    } else if (Tab == 11 && Result.ApcQueried) {
      const APC_CANCEL_OUTPUT &Apc = Result.Apc;
      const std::string Summary = Kd::ApcScanSummary(Result);
      SetStatus(Summary);
      AddRow("-", "APC query", "-", Summary, 0, 0);
      if (!Result.ApcAvailable || Apc.Status != 0) {
        AddRow("-", "Metadata", "-",
               "Unavailable because the APC query failed.", 0, 0);
      } else {
        AddRow("-", "Kernel APC", "-",
               Kd::Utf8(QString("%1 listed | scanned %2 | suspects %3 | "
                                "threads %4 | flags 0x%5")
                            .arg(Apc.EntryCount)
                            .arg(Apc.Scanned)
                            .arg(Apc.Suspects)
                            .arg(Apc.ThreadCount)
                            .arg(Apc.Flags, 0, 16)),
               0, 0);
        AddRow("-", "Resolver", "-",
               Kd::Utf8(
                   QString("ntoskrnl size %1 | KiDispatchCallout %2 | base low "
                           "32 bits %3 | ApcListHead +0x%4")
                       .arg(Apc.NtoskrnlSize
                                ? QString("0x%1").arg(Apc.NtoskrnlSize, 0, 16)
                                : QString("unavailable"))
                       .arg(Apc.Resolved ? "resolved" : "unresolved")
                       .arg(Apc.NtoskrnlSize
                                ? QString("0x%1").arg(Apc.NtoskrnlBaseLow, 8, 16,
                                                      QLatin1Char('0'))
                                : QString("unavailable"))
                       .arg(Apc.ApcListHeadOffset, 0, 16)),
               0, 0);
        for (ULONG Index = 0;
             Index < std::min<ULONG>(Apc.EntryCount, APC_CANCEL_MAX_ENTRIES);
             ++Index) {
          const APC_CANCEL_ENTRY &Entry = Apc.Entries[Index];
          const bool Suspect =
              (Entry.Flags & APC_CANCEL_REASON_KERNELROUTINE_MATCH) &&
              (Entry.Flags & APC_CANCEL_REASON_RUNDOWN_NULL);
          AddRow(std::to_string(Index),
                 Kd::Utf8(QString("TID %1").arg(Entry.ThreadId)),
                 Suspect ? "PG-SUSPECT" : "normal",
                 Kd::Utf8(QString("Kernel %1 | Rundown %2 | Context %3 | "
                                  "Queue %4 | flags 0x%5")
                              .arg(QString::fromStdString(Hex(Entry.KernelRoutine)))
                              .arg(QString::fromStdString(Hex(Entry.RundownRoutine)))
                              .arg(QString::fromStdString(Hex(Entry.Context)))
                              .arg(QString::fromStdString(Hex(Entry.QueueHead)))
                              .arg(Entry.Flags, 0, 16)
                              .toUpper()),
                 Entry.KernelRoutine, static_cast<quintptr>(Entry.ApcObject));
        }
        if (Apc.EntryCount == 0)
          AddRow("-", "(empty)", "-",
                 "No kernel APCs are queued right now; the inventory is "
                 "empty.",
                 0, 0);

        // 投递捕获（装载 APC 页时已在 worker 线程 Drain；之后由 500ms tick 追加）。
        if (Result.CaptureQueried) {
          CaptureEnabled_ = Result.CaptureEnabled;
          AppendCaptureRows(Result.CaptureEntries.data(),
                            static_cast<ULONG>(Result.CaptureEntries.size()));
          CaptureSummary_ = Result.CaptureSummary;
          // 只消费一次：否则每次 Populate 都会把同一批条目重复插入。
          Result.CaptureQueried = false;
          Result.CaptureEntries.clear();
        }
        if (!CaptureSummary_.empty())
          AddRow("-", "Capture", "-", CaptureSummary_, 0, 0);
      }
    } else if (Tab == 0) {
      AddRow("-", "IDT Base", Hex(Result.Summary.IdtBase));
      AddRow("-", "IDT Limit", std::to_string(Result.Summary.IdtLimit));
    } else if (Tab == 1) {
      AddRow("-", "KUSER_SHARED_DATA", Hex(Result.Summary.KuserSharedData));
      AddRow("-", "System Time", Hex64(Result.Summary.SystemTime));
      AddRow("-", "Interrupt Time", Hex64(Result.Summary.InterruptTime));
      AddRow("-", "Tick Count", std::to_string(Result.Summary.TickCount));
    } else if (Tab == 2) {
      AddRow("-", "SSDT Base", Hex(Result.Summary.SsdtBase));
      AddRow("-", "Service Count", std::to_string(Result.Summary.SsdtCount));
      AddRow("-", "Argument Table", Hex(Result.Summary.SsdtArgTable));
    } else if (Tab == 3) {
      AddRow("-", "Shadow SSDT Base", Hex(Result.Summary.ShadowSsdtBase));
      AddRow("-", "Service Count", std::to_string(Result.Summary.ShadowSsdtCount));
      AddRow("-", "Argument Table", Hex(Result.Summary.ShadowSsdtArgTable));
    } else if (Tab == 4) {
      AddRow("-", "GDT Base", Hex(Result.Summary.GdtBase));
      AddRow("-", "GDT Limit", std::to_string(Result.Summary.GdtLimit));
    } else if (Tab == 5) {
      AddRow("-", "PiDDBCacheTable", Hex(Result.Summary.PiDDBCacheTable));
    } else if (Tab == 7 && Result.MsrQueried) {
      const MSR_QUERY_OUTPUT &Msr = Result.Msr;
      const auto AddMsrRow = [this](const std::string &Name, uint64_t Value,
                                    const std::string &Metadata,
                                    const std::string &State) {
        AddRow("-", Name, Kd::HexAuto(Value), Metadata,
               0, 0);
        if (!State.empty() && !Table_.Rows.empty())
          Table_.Rows.back().Cells[4] = State;
      };
      AddMsrRow("KiSystemCall64", Msr.KiSystemCall64, "Expected LSTAR target",
                Msr.KiSystemCall64 ? "OK" : "Unknown");
      AddMsrRow("IA32_LSTAR", Msr.LstarValue,
                Msr.LstarHooked ? "Mismatch vs KiSystemCall64"
                                : "Matches KiSystemCall64",
                Msr.LstarHooked ? "Hooked"
                                : (Msr.LstarUnknown ? "Unknown" : "OK"));
      AddMsrRow("IA32_EFER", Msr.EferValue, "Extended feature enable", "-");
      AddMsrRow("IA32_STAR", Msr.StarValue, "Syscall segment selectors", "-");
      AddMsrRow("IA32_FMASK", Msr.FmaskValue, "Syscall RFLAGS mask", "-");
      AddMsrRow("IA32_SYSENTER_EIP", Msr.SysenterEip, "x86 SYSENTER entry", "-");
      AddRow("-", "Watch Status", Msr.WatchActive ? "Active" : "Inactive",
             "Baseline captured on Enable Watch", 0, 0);
      for (ULONG Index = 0; Index < MSR_WATCH_COUNT; ++Index) {
        const MSR_WATCH_VALUE &Watch = Msr.WatchValues[Index];
        AddMsrRow(Kd::Wide(Watch.Name), Watch.Value,
                  Kd::Utf8(QString("Baseline: 0x%1")
                               .arg(Watch.Baseline, 16, 16, QLatin1Char('0'))
                               .toUpper()),
                  Watch.Changed ? "Changed" : "OK");
      }
    } else if (Tab == 6) {
      AddRow("-", "CR0", Hex64(Result.Summary.Cr0),
             "Protection and paging controls", 0, 0);
      AddRow("-", "CR2", Hex64(Result.Summary.Cr2),
             "Last page-fault linear address", 0, 0);
      AddRow("-", "CR3", Hex64(Result.Summary.Cr3),
             "Current page-table root", 0, 0);
      AddRow("-", "CR4", Hex64(Result.Summary.Cr4),
             "Extended processor controls", 0, 0);
      AddRow("-", "IA32_LSTAR", Hex64(Result.Summary.MsrLstar),
             "64-bit syscall entry", 0, 0);
      AddRow("-", "IA32_STAR", Hex64(Result.Summary.MsrStar),
             "Syscall segment selectors", 0, 0);
      AddRow("-", "IA32_FMASK", Hex64(Result.Summary.MsrFmask),
             "Syscall RFLAGS mask", 0, 0);
      AddRow("-", "IA32_EFER", Hex64(Result.Summary.MsrEfer),
             "Extended feature enable", 0, 0);
    } else {
      AddRow("-", "(not loaded)", "-",
             "Press F5 or run \"refresh\" to query this table.", 0, 0);
    }

    // 捕获条目固定在最上方（最新在上），与 GUI 的 insertRow(0) 一致。
    if (!CaptureRows_.empty()) {
      std::vector<TuiRow> Combined;
      std::vector<RowMeta> CombinedMeta;
      Combined.reserve(CaptureRows_.size() + Table_.Rows.size());
      CombinedMeta.reserve(Combined.capacity());
      for (const TuiRow &Row : CaptureRows_) {
        Combined.push_back(Row);
        CombinedMeta.push_back(RowMeta{});
      }
      for (size_t Index = 0; Index < Table_.Rows.size(); ++Index) {
        Combined.push_back(std::move(Table_.Rows[Index]));
        CombinedMeta.push_back(Meta_[Index]);
      }
      Table_.Rows = std::move(Combined);
      Meta_ = std::move(CombinedMeta);
    }
    CaptureRowCount_ = static_cast<int>(CaptureRows_.size());
    Table_.Rebuild();
  }

  void DrainCapture() {
    if (DrainInFlight_.exchange(true))
      return;
    TuiAsync<std::vector<APC_CAPTURE_ENTRY>>(
        [] {
          const ULONG MaxShow = APC_CAPTURE_MAX_ENTRIES;
          std::vector<BYTE> Buffer(sizeof(APC_CAPTURE_OUTPUT) +
                                   sizeof(APC_CAPTURE_ENTRY) * (MaxShow - 1));
          auto *Capture = reinterpret_cast<PAPC_CAPTURE_OUTPUT>(Buffer.data());
          DWORD Returned = 0;
          std::vector<APC_CAPTURE_ENTRY> Copy;
          if (ApcCaptureDrain(Capture, static_cast<DWORD>(Buffer.size()),
                              &Returned)) {
            const ULONG Count = std::min<ULONG>(Capture->EntryCount, MaxShow);
            Copy.assign(Capture->Entries, Capture->Entries + Count);
          }
          return Copy;
        },
        [this](std::vector<APC_CAPTURE_ENTRY> Copy) {
          DrainInFlight_ = false;
          if (Copy.empty() || Kind_ != 11)
            return;
          AppendCaptureRows(Copy.data(), static_cast<ULONG>(Copy.size()));
          Populate();
        });
  }

  void SetMsrWatch(bool Enable) {
    SetStatus(Enable ? "Enabling MSR watch..." : "Disabling MSR watch...");
    TuiAsync<bool>(
        [Enable] {
          return Enable ? MsrWatchEnable() != FALSE : MsrWatchDisable() != FALSE;
        },
        [this, Enable](bool Ok) {
          if (!Ok) {
            Notify(Kd::Utf8(QString("Failed to %1 watch (error %2).")
                                .arg(Enable ? "enable" : "disable")
                                .arg(G_LastAegisCoreError)),
                   NoticeKind::Error);
            return;
          }
          MarkMutated();
          Notify(Enable ? "Watch enabled, baseline captured."
                        : "Watch disabled.",
                 NoticeKind::Success);
          if (Result_)
            Result_->MsrQueried = false;
          Kind_ = 7;
          LoadSelectedTab(false);
        });
  }

  void ToggleCapture() {
    SetStatus("Querying APC capture state...");
    struct CaptureToggle {
      bool QueryOk = false;
      bool ToggleOk = false;
      APC_CAPTURE_CTL_OUTPUT Result{};
    };
    TuiAsync<CaptureToggle>(
        [] {
          CaptureToggle Value;
          APC_CAPTURE_CTL_OUTPUT Current{};
          if (!ApcCaptureQuery(&Current)) {
            Value.QueryOk = false;
            return Value;
          }
          Value.QueryOk = true;
          const bool Enable = Current.Enabled == 0;
          APC_CAPTURE_CTL_OUTPUT Result{};
          Value.ToggleOk = ApcCaptureCtl(Enable, false, &Result) != FALSE;
          Value.Result = Result;
          return Value;
        },
        [this](CaptureToggle Value) {
          if (!Value.QueryOk) {
            Notify(Kd::Utf8(QString("Failed to query capture state (error "
                                    "%1).")
                                .arg(G_LastAegisCoreError)),
                   NoticeKind::Error);
            return;
          }
          if (!Value.ToggleOk) {
            Notify(Kd::Utf8(QString("Failed to toggle capture (error %1).")
                                .arg(G_LastAegisCoreError)),
                   NoticeKind::Error);
            return;
          }
          CaptureEnabled_ = Value.Result.Enabled != 0;
          MarkMutated();
          Notify(Kd::Utf8(Value.Result.Enabled
                              ? QString("Capture enabled (export hook %1, "
                                        "internal hook %2).")
                                    .arg(Value.Result.HookExportOk ? "yes"
                                                                   : "no")
                                    .arg(Value.Result.HookInternalOk ? "yes"
                                                                     : "no")
                              : QString("Capture disabled.")),
                 NoticeKind::Success);
          if (Result_)
            Result_->ApcQueried = false;
          Kind_ = 11;
          LoadSelectedTab(false);
        });
  }

  void InjectTestApcAction() {
    SetStatus("Injecting test APC...");
    TuiAsync<std::pair<bool, APC_TEST_OUTPUT>>(
        [] {
          APC_TEST_OUTPUT Result{};
          const bool Ok = InjectTestApc(&Result) != FALSE;
          return std::make_pair(Ok, Result);
        },
        [this](std::pair<bool, APC_TEST_OUTPUT> Value) {
          if (!Value.first) {
            Notify(Kd::Utf8(QString("Test APC injection failed (error %1).")
                                .arg(G_LastAegisCoreError)),
                   NoticeKind::Error);
            return;
          }
          MarkMutated();
          Notify(Kd::Utf8(QString("Injected %1 test APC(s) into TID %2.")
                              .arg(Value.second.Injected)
                              .arg(Value.second.TargetThreadId)),
                 NoticeKind::Success);
          if (Result_)
            Result_->ApcQueried = false;
          Kind_ = 11;
          LoadSelectedTab(false);
        });
  }

  void RemoveSelected() {
    const int RowIndex = Table_.CurrentRowIndex();
    if (RowIndex < 0 || RowIndex >= static_cast<int>(Meta_.size()))
      return;
    const RowMeta Meta = Meta_[static_cast<size_t>(RowIndex)];
    const int ShortcutTab = Kind_;
    if (ShortcutTab == 1) {
      Notify("KUSER_SHARED_DATA fields are fixed system values and cannot be "
             "removed.",
             NoticeKind::Error);
      return;
    }
    if (Meta.Target == 0) {
      Notify("This table entry cannot be removed.", NoticeKind::Error);
      return;
    }
    if (ShortcutTab != 5 && ShortcutTab != 10 && ShortcutTab != 11) {
      Notify("Removal is not supported for this table.", NoticeKind::Error);
      return;
    }
    SetStatus("Removing entry...");
    const quintptr Target = Meta.Target;
    const ULONG DpcCpu = Meta.DpcCpu;
    TuiAsync<std::pair<bool, std::string>>(
        [Target, DpcCpu, ShortcutTab] {
          bool Ok = false;
          std::string Description;
          if (ShortcutTab == 5) {
            Ok = RemovePiDDBCacheEntry(static_cast<ULONG_PTR>(Target)) != FALSE;
            Description = "PiDDBCacheTable entry";
          } else if (ShortcutTab == 10) {
            Ok = RemoveDpcEntry(static_cast<ULONG_PTR>(Target), DpcCpu) != FALSE;
            Description = "DPC entry";
          } else {
            APC_CANCEL_OUTPUT Output{};
            Ok = CancelPatchGuardApcs(&Output, FALSE, 1,
                                      static_cast<ULONG_PTR>(Target), 0) !=
                     FALSE &&
                 Output.Cancelled > 0;
            Description = "APC entry";
          }
          return std::make_pair(Ok, Description);
        },
        [this, ShortcutTab](std::pair<bool, std::string> Value) {
          if (Value.first) {
            MarkMutated();
            Notify(Value.second + " removed.", NoticeKind::Success);
            if (Result_)
              Result_->ApcQueried = false;
            Refresh(false);
            return;
          }
          const DWORD Error = G_LastAegisCoreError;
          if (ShortcutTab == 10 &&
              (Error == ERROR_NOT_FOUND || Error == ERROR_RETRY ||
               Error == ERROR_NOT_SUPPORTED)) {
            const std::string Detail =
                Error == ERROR_NOT_FOUND
                    ? "The timer/DPC is no longer present in the scanned "
                      "tables. Refreshing the snapshot."
                    : (Error == ERROR_RETRY
                           ? "The timer/DPC changed during the scan, or the "
                             "scan was incomplete. Refresh and retry."
                           : "The timer layout or pointer-decoding keys could "
                             "not be resolved on this kernel build.");
            Notify(Detail + "\nWin32 error: " + std::to_string(Error),
                   NoticeKind::Error);
            Refresh(false);
            return;
          }
          Notify("Failed to remove " + Value.second +
                     ".\nWin32 error: " + std::to_string(Error),
                 NoticeKind::Error);
        });
  }

  int Index_ = 0;
  int Kind_ = 0;
  bool SummaryQueried_ = false;
  bool CaptureEnabled_ = false;
  int CaptureRowCount_ = 0;
  uint64_t LastCaptureSequence_ = 0;
  int64_t LastDrainMs_ = 0;
  std::shared_ptr<Kd::TableQueryResult> Result_;
  std::vector<TuiRow> CaptureRows_;
  std::string CaptureSummary_;
  std::vector<RowMeta> Meta_;
  const std::vector<INVENTORY_RECORD> *ModulesPtr_ = nullptr;
  TuiTable Table_;
  std::atomic_bool Refreshing_{false};
  std::atomic_bool TabLoading_{false};
  std::atomic_bool DrainInFlight_{false};
};

// ============================================================
// 索引 16：KernelInspector
// ============================================================

namespace Kd {

struct KernelControlState {
  bool Queried = false;
  bool DebugOk = false;
  DWORD DebugError = ERROR_SUCCESS;
  DEBUG_STATE_OUTPUT Debug{};
  bool DseOk = false;
  DWORD DseError = ERROR_SUCCESS;
  DSE_CONTROL_OUTPUT Dse{};
  bool PatchGuardOk = false;
  DWORD PatchGuardError = ERROR_SUCCESS;
  PG_CONTROL_OUTPUT PatchGuard{};
};

struct InspectorRecordSet {
  INVENTORY_LIST_HEADER Header{};
  std::vector<INVENTORY_RECORD> Records;
};

struct InspectorSnapshot {
  KernelControlState Control;
  std::vector<InspectorRecordSet> Records; // 顺序：MiniFilters/WFP/NDIS/Security
  KernelInspectorData::SyncEntries SyncEntries;
  KernelInspectorData::SessionEntries SessionEntries;
};

QString DescribeStage(ULONG Stage) {
  if (Stage == 0)
    return "stage none (resolution never ran)";
  QStringList Parts;
  if (Stage & PG_RESOLVE_STAGE_KPRCB_CONTEXT)
    Parts << "ctx";
  if (Stage & PG_RESOLVE_STAGE_DEBUG_IRQL)
    Parts << "irql";
  if (Stage & PG_RESOLVE_STAGE_HW_TRIGGER)
    Parts << "hwtrig";
  if (Stage & PG_RESOLVE_STAGE_BUGCHECK2)
    Parts << "bc2";
  if (Stage & PG_RESOLVE_STAGE_BUGCHECK_ACTIVE)
    Parts << "bcactive";
  if (Stage & PG_RESOLVE_STAGE_FREEZE_LOCK)
    Parts << "freezelock";
  if (Stage & PG_RESOLVE_STAGE_NT_BASE)
    Parts << "ntbase";
  return QString("stage %1 [%2]")
      .arg(QHexAuto(Stage))
      .arg(Parts.isEmpty() ? QString("unknown") : Parts.join('+'));
}

QString DescribeOffsetSource(ULONG Source) {
  switch (Source) {
  case PG_OFFSET_SOURCE_DETERMINISTIC:
    return "deterministic";
  case PG_OFFSET_SOURCE_HEURISTIC:
    return "heuristic (!)";
  default:
    return "none";
  }
}

QString DescribePatchedSymbol(const char *Name, ULONG64 Address,
                              bool Resolved) {
  return QString("%1 %2%3")
      .arg(QLatin1String(Name))
      .arg(Resolved ? QHexAuto(Address) : QString("unresolved"))
      .arg(Resolved ? QString() : QString(" (!)"));
}

const char *InspectorSourceName(ULONG Source) {
  static const char *Names[] = {"Unknown",
                                "Public API",
                                "System Info",
                                "Object Manager",
                                "Registry",
                                "Process Environment",
                                "Memory Map",
                                "Version Profile",
                                "Signature Scan",
                                "Cross-view"};
  return Source < 10 ? Names[Source] : "Source";
}

const char *InspectorConfidenceName(ULONG Confidence) {
  static const char *Names[] = {"Unavailable", "Low", "Medium", "High"};
  return Confidence < 4 ? Names[Confidence] : "Level";
}

QString RecordAddressText(const INVENTORY_RECORD &Record) {
  if (Record.Address != 0)
    return QHexAuto(Record.Address);
  for (const ULONG64 Value : Record.Value) {
    if (Value != 0)
      return QHexAuto(Value);
  }
  return "-";
}

// 四个 INVENTORY 分区（与 GUI 的 Definitions 同序）。
const std::array<DWORD, 4> &InspectorIoctls() {
  static const std::array<DWORD, 4> Values{IOCTL_ENUM_MINIFILTERS, IOCTL_ENUM_WFP,
                                          IOCTL_ENUM_NDIS,
                                          IOCTL_QUERY_SECURITY};
  return Values;
}

InspectorSnapshot FetchInspectorSnapshot() {
  InspectorSnapshot Snapshot;
  Snapshot.Control.DebugOk = QueryDebugState(&Snapshot.Control.Debug) != FALSE;
  Snapshot.Control.DebugError = G_LastAegisCoreError;
  Snapshot.Control.DseOk = QueryDse(&Snapshot.Control.Dse) != FALSE;
  Snapshot.Control.DseError = G_LastAegisCoreError;
  Snapshot.Control.PatchGuardOk =
      QueryPatchGuard(&Snapshot.Control.PatchGuard) != FALSE;
  Snapshot.Control.PatchGuardError = G_LastAegisCoreError;
  Snapshot.Control.Queried = true;

  for (const DWORD Ioctl : InspectorIoctls()) {
    InspectorRecordSet Set;
    INVENTORY_QUERY_INPUT Request{};
    Request.MaxEntries = INVENTORY_MAX_PAGE_RECORDS;
    QueryAegisCoreRecords(Ioctl, Request, Set.Records, &Set.Header);
    Snapshot.Records.push_back(std::move(Set));
  }

  {
    BYTE SyncBuffer[65536] = {};
    ULONG SyncReturned = 0;
    if (EnumSyncObjectsKernel(SyncBuffer, sizeof(SyncBuffer), &SyncReturned) &&
        SyncReturned <= sizeof(SyncBuffer)) {
      KernelInspectorData::ParseSyncObjects(SyncBuffer, SyncReturned,
                                            Snapshot.SyncEntries);
    }
  }
  // WTS 提供真实站名与连接状态；进程快照仅作回退。
  if (!EnumerateSessionsFallback(Snapshot.SessionEntries)) {
    BYTE SessionBuffer[KernelInspectorData::SessionBufferBytes] = {};
    ULONG SessionReturned = 0;
    if (EnumSessions(SessionBuffer, sizeof(SessionBuffer), &SessionReturned) &&
        SessionReturned <= sizeof(SessionBuffer)) {
      KernelInspectorData::ParseProcessSessions(SessionBuffer, SessionReturned,
                                                Snapshot.SessionEntries);
    }
  }
  EnumerateSyncObjectsFallback(Snapshot.SyncEntries);
  KernelInspectorData::DeduplicateSyncObjects(Snapshot.SyncEntries);
  return Snapshot;
}

// 会话动作结果
struct SessionActionResult {
  bool Success = false;
  std::string Message;
};

} // namespace Kd

class KernelInspectorPage final : public TuiPage {
public:
  explicit KernelInspectorPage(int Index) : Index_(Index) {
    (void)Index_;
    Table_.Headers = {"Name", "Type", "Address", "Size/Value", "Path/Detail",
                      "Source", "Confidence", "Status"};
    Table_.RightAlign = {false, false, true, true, false, false, false, false};
    OwnedCommands.push_back(TuiCommand{
        "refresh", "refresh  (read kernel controls and every inventory section)",
        [this](std::vector<std::string>) { Refresh(); }});
    OwnedCommands.push_back(TuiCommand{
        "section", "section <1-7>  (switch section)",
        [this](std::vector<std::string> Args) { SelectSection(Args); }});
    OwnedCommands.push_back(TuiCommand{
        "enable-debug", "enable-debug  (EnableDebug)",
        [this](std::vector<std::string>) {
          RunControl("Enabling kernel debug...", "EnableDebug",
                     [] { return EnableDebug() != FALSE; });
        }});
    OwnedCommands.push_back(TuiCommand{
        "disable-debug", "disable-debug  (DisableDebug)",
        [this](std::vector<std::string>) {
          RunControl("Disabling kernel debug...", "DisableDebug",
                     [] { return DisableDebug() != FALSE; });
        }});
    OwnedCommands.push_back(TuiCommand{
        "disable-dse", "disable-dse  (DisableDse)",
        [this](std::vector<std::string>) {
          RunControl("Disabling DSE...", "DisableDse",
                     [] { return DisableDse() != FALSE; });
        }});
    OwnedCommands.push_back(TuiCommand{
        "restore-dse", "restore-dse  (RestoreDse)",
        [this](std::vector<std::string>) {
          RunControl("Restoring DSE...", "RestoreDse",
                     [] { return RestoreDse() != FALSE; });
        }});
    OwnedCommands.push_back(TuiCommand{
        "disable-pg", "disable-pg  (DisablePatchGuard)",
        [this](std::vector<std::string>) {
          RunControl("Disabling PatchGuard...", "DisablePatchGuard",
                     [] { return DisablePatchGuard() != FALSE; });
        }});
    OwnedCommands.push_back(TuiCommand{
        "pg-intercept", "pg-intercept  (EnablePatchGuardInterception)",
        [this](std::vector<std::string>) {
          RunControl("Enabling PatchGuard HAL interception...",
                     "HAL interception",
                     [] { return EnablePatchGuardInterception() != FALSE; });
        }});
    OwnedCommands.push_back(TuiCommand{
        "kprcb-clear", "kprcb-clear  (ClearPatchGuardKprcbContexts)",
        [this](std::vector<std::string>) {
          RunControl("Clearing PatchGuard KPRCB contexts...", "KPRCB clear",
                     [] { return ClearPatchGuardKprcbContexts() != FALSE; });
        }});
    OwnedCommands.push_back(TuiCommand{
        "dpc-apc-unlink", "dpc-apc-unlink  (DPC first, then APC)",
        [this](std::vector<std::string>) { RunDpcApcUnlink(); }});
    OwnedCommands.push_back(TuiCommand{
        "trigger-pg", "trigger-pg  (SetIdtLimit: trigger PatchGuard)",
        [this](std::vector<std::string>) { RunTriggerPatchGuard(); }});
    OwnedCommands.push_back(TuiCommand{
        "enable-ppn", "enable-ppn  (EnablePPN)",
        [this](std::vector<std::string>) {
          RunControl("Enabling PPN page guard...", "EnablePPN",
                     [] { return EnablePPN() != FALSE; });
        }});
    OwnedCommands.push_back(TuiCommand{
        "restore-ppn", "restore-ppn  (DisablePPN)",
        [this](std::vector<std::string>) {
          RunControl("Restoring PPN IDT/PTE state...", "DisablePPN",
                     [] { return DisablePPN() != FALSE; });
        }});
    OwnedCommands.push_back(TuiCommand{
        "logoff", "logoff  (log off the selected interactive session)",
        [this](std::vector<std::string>) { LogoffSessionAction(); }});
    OwnedCommands.push_back(TuiCommand{
        "disconnect", "disconnect  (disconnect the selected session)",
        [this](std::vector<std::string>) { DisconnectSessionAction(); }});
    OwnedCommands.push_back(TuiCommand{
        "message", "message  (send a popup message into the selected session)",
        [this](std::vector<std::string>) { MessageSessionAction(); }});
    OwnedCommands.push_back(TuiCommand{
        "run-in-session",
        "run-in-session  (launch an executable with the session user token)",
        [this](std::vector<std::string>) { RunInSessionAction(); }});
  }

  std::string Title() const override { return "KernelInspector"; }

  std::string Subtitle() const override {
    return "kernel controls, minifilters, WFP, NDIS, security, sync, sessions";
  }

  void OnEnter() override { Refresh(); }

  TuiTable *ActiveTable() override { return &Table_; }

  std::string RenderText() override {
    if (!Control_.Queried)
      Refresh();
    Populate();
    std::string Text = SectionStrip();
    Text += '\n';
    Text += "section: " + SectionName() + " | " + ControlSummary() + '\n';
    Text += TuiTableToText(Table_, 200);
    return Text;
  }

private:
  std::string SectionStrip() const {
    return ::AegisNT::Tui::TabStrip(SectionNames(), static_cast<int>(Section_));
  }

  static const std::vector<std::string> &SectionNames() {
    static const std::vector<std::string> Names{
        "Kernel Controls", "MiniFilters", "WFP",      "NDIS",
        "Security",        "Sync Objects", "Sessions"};
    return Names;
  }

  std::string SectionName() const {
    const auto &Names = SectionNames();
    if (Section_ < 0 || Section_ >= static_cast<int>(Names.size()))
      return "-";
    return Names[static_cast<size_t>(Section_)];
  }

  std::string ControlSummary() const {
    if (!Control_.Queried)
      return "kernel controls: loading";
    const QString DebugStateText =
        !Control_.DebugOk ? "Unavailable"
                          : (Control_.Debug.HookInstalled ? "Blocked"
                                                          : "Pass-through");
    const QString DseStateText =
        !Control_.DseOk ? "Unavailable"
                        : (Control_.Dse.CurrentValue == Control_.Dse.OriginalValue
                               ? "Restored"
                               : "Modified");
    const QString PgStateText =
        !Control_.PatchGuardOk ? "Unavailable"
                               : (Control_.PatchGuard.IsPatched ? "Disabled"
                                                                : "Active");
    int RecordCount = 0;
    for (const auto &Set : Records_)
      RecordCount += static_cast<int>(Set.Records.size());
    return Kd::Utf8(QString("Dbg %1 · DSE %2 · PG %3 · %4 records")
                        .arg(DebugStateText)
                        .arg(DseStateText)
                        .arg(PgStateText)
                        .arg(RecordCount));
  }

  void SelectSection(std::vector<std::string> Args) {
    if (Args.empty()) {
      Notify("Usage: section <1-7>", NoticeKind::Warning);
      return;
    }
    int Value = -1;
    try {
      Value = std::stoi(TrimAscii(Args.front())) - 1;
    } catch (...) {
      Value = -1;
    }
    if (Value < 0 || Value >= static_cast<int>(SectionNames().size())) {
      const std::string Needle = LowerAscii(TrimAscii(Args.front()));
      const auto &Names = SectionNames();
      for (size_t Index = 0; Index < Names.size(); ++Index) {
        if (LowerAscii(Names[Index]).find(Needle) != std::string::npos) {
          Value = static_cast<int>(Index);
          break;
        }
      }
    }
    if (Value < 0) {
      Notify("Unknown section: " + std::string(Args.front()),
             NoticeKind::Warning);
      return;
    }
    Section_ = Value;
    Populate();
  }

  void Refresh() {
    if (Refreshing_.exchange(true))
      return;
    SetStatus("Reading kernel inventory...");
    TuiAsync<Kd::InspectorSnapshot>(
        [] { return Kd::FetchInspectorSnapshot(); },
        [this](Kd::InspectorSnapshot Snapshot) {
          Refreshing_ = false;
          Control_ = Snapshot.Control;
          Records_ = std::move(Snapshot.Records);
          SyncEntries_ = std::move(Snapshot.SyncEntries);
          SessionEntries_ = std::move(Snapshot.SessionEntries);
          Populate();
          int Total = 0;
          for (const auto &Set : Records_)
            Total += static_cast<int>(Set.Records.size());
          SetStatus(std::to_string(Total) + " records");
          const bool Incomplete = !Control_.DebugOk || !Control_.DseOk ||
                                  !Control_.PatchGuardOk;
          if (Incomplete)
            Notify("Some kernel fields are unavailable. See the reported "
                   "errors.",
                   NoticeKind::Warning);
        });
  }

  void Populate() {
    Table_.Filter = Filter;
    Table_.Rows.clear();
    switch (Section_) {
    case 0:
      BuildControlRows();
      break;
    case 1:
    case 2:
    case 3:
    case 4:
      BuildInventoryRows(Section_ - 1);
      break;
    case 5:
      BuildSyncRows();
      break;
    default:
      BuildSessionRows();
      break;
    }
    Table_.Rebuild();
  }

  void BuildControlRows() {
    const auto Add = [this](const std::string &Field, const std::string &Value,
                            const std::string &Detail) {
      TuiRow Row;
      Row.Cells = {Field, Value, Detail};
      Row.Detail = Field + ": " + Value + "\n" + Detail;
      Table_.Rows.push_back(std::move(Row));
    };
    if (!Control_.Queried) {
      Add("Kernel state", "Loading...", "Reading kernel control state.");
      return;
    }
    if (Control_.DebugOk) {
      Add("Debug Hook",
          Control_.Debug.HookInstalled ? "Installed (blocking)"
                                       : "Not installed",
          Kd::Utf8(QString("query status %1\ndebugger flag %2")
                       .arg(Kd::QHexAuto(Control_.Debug.Status))
                       .arg(Control_.Debug.IsDebuggerEnabled ? "on" : "off")));
      Add("IsDebuggerEnabled",
          Kd::Utf8(Control_.Debug.Status == 0
                       ? (Control_.Debug.IsDebuggerEnabled
                              ? QString("1 (debugger present)")
                              : QString("0 (no debugger)"))
                       : QString("Query error %1")
                             .arg(Control_.Debug.Status)),
          "Runtime debugger presence reported by the kernel query.");
    } else {
      Add("Debug Hook", "Unavailable",
          "Win32 error " + std::to_string(Control_.DebugError));
    }

    const QString DseStateText =
        Control_.DseOk
            ? (Control_.Dse.CurrentValue == Control_.Dse.OriginalValue
                   ? "Restored"
                   : "Modified")
            : QString("Unavailable");
    Add("DSE.CiOptionsAddress",
        Kd::Utf8(Control_.DseOk ? Kd::QHexAuto(Control_.Dse.CiOptionsAddress)
                                : QString("-")),
        {});
    Add("DSE.OriginalValue",
        Kd::Utf8(Control_.DseOk
                     ? Kd::QHexAuto(Control_.Dse.OriginalValue)
                     : QString("-")),
        {});
    Add("DSE.CurrentValue",
        Kd::Utf8(Control_.DseOk
                     ? Kd::QHexAuto(Control_.Dse.CurrentValue)
                     : QString("-")),
        {});
    Add("DSE.Status", Kd::Utf8(DseStateText),
        Kd::Utf8(Control_.DseOk
                     ? QString("address %1\noriginal %2\ncurrent %3")
                           .arg(Kd::QHexAuto(Control_.Dse.CiOptionsAddress))
                           .arg(Kd::QHexAuto(Control_.Dse.OriginalValue))
                           .arg(Kd::QHexAuto(Control_.Dse.CurrentValue))
                     : QString("Win32 error %1").arg(Control_.DseError)));

    const PG_CONTROL_OUTPUT &Pg = Control_.PatchGuard;
    const QString PgStateText =
        Control_.PatchGuardOk ? (Pg.IsPatched ? "Disabled" : "Active")
                              : QString("Unavailable");
    Add("PatchGuard.PgContextOffset",
        Kd::Utf8(Control_.PatchGuardOk ? Kd::QHexAuto(Pg.PgContextOffset)
                                       : QString("-")),
        {});
    Add("PatchGuard.IsPatched",
        Kd::Utf8(Control_.PatchGuardOk
                     ? (Pg.IsPatched ? QString("DISABLED") : QString("ACTIVE"))
                     : QString("-")),
        {});
    Add("PatchGuard.Status", Kd::Utf8(PgStateText),
        Kd::Utf8(Control_.PatchGuardOk
                     ? QString("IOCTL status %1 | resolve %2 | intercept %3")
                           .arg(Kd::QHexAuto(Pg.Status))
                           .arg(Kd::QHexAuto(Pg.ResolveStage))
                           .arg(Pg.InterceptEnabled ? "enabled" : "off")
                     : QString("Win32 error %1")
                           .arg(Control_.PatchGuardError)));
    Add("PatchGuard.DpcsFound",
        Control_.PatchGuardOk ? std::to_string(Pg.DpcFound) : "-",
        Kd::Utf8(Control_.PatchGuardOk
                     ? QString("scanned %1, cancelled %2")
                           .arg(Pg.DpcScanned)
                           .arg(Pg.DpcCancelled)
                     : QString("Win32 error %1")
                           .arg(Control_.PatchGuardError)));
    Add("PatchGuard.ApcsFound",
        Control_.PatchGuardOk ? std::to_string(Pg.ApcFound) : "-",
        Kd::Utf8(Control_.PatchGuardOk
                     ? QString("scanned %1, cancelled %2")
                           .arg(Pg.ApcScanned)
                           .arg(Pg.ApcCancelled)
                     : QString("Win32 error %1")
                           .arg(Control_.PatchGuardError)));
    Add("PatchGuard.Intercept",
        Kd::Utf8(Control_.PatchGuardOk
                     ? (Pg.InterceptEnabled ? QString("Enabled")
                                            : QString("Disabled"))
                     : QString("-")),
        Kd::Utf8(Control_.PatchGuardOk
                     ? QString("%1, HAL v%2, hooks %3, status 0x%4, critical %5")
                           .arg(Kd::DescribeStage(Pg.ResolveStage))
                           .arg(Pg.HalVersion)
                           .arg(Kd::QHexAuto(Pg.HalHookMask))
                           .arg(Pg.InterceptStatus, 8, 16, QLatin1Char('0'))
                           .arg(Pg.AllCriticalResolved ? "OK" : "INCOMPLETE")
                     : QString()));
    Add("PatchGuard.Suppressed",
        Control_.PatchGuardOk ? std::to_string(Pg.SuppressedCount) : "-",
        Kd::Utf8(Control_.PatchGuardOk
                     ? QString("freeze %1, bugcheck %2, last 0x%3 @ %4")
                           .arg(Pg.FreezeNotifies)
                           .arg(Pg.BugCheckNotifies)
                           .arg(Pg.LastBugCheckCode, 0, 16)
                           .arg(Kd::QHexAuto(Pg.LastBugCheckRip))
                     : QString()));
    Add("PatchGuard.KprcbContextOffset",
        Kd::Utf8(Control_.PatchGuardOk ? Kd::QHexAuto(Pg.KprcbContextOffset)
                                       : QString("-")),
        Kd::Utf8(Control_.PatchGuardOk
                     ? QString("offset in _KPRCB; %1 | %2 | %3")
                           .arg(Kd::DescribePatchedSymbol(
                               "KiHardwareTrigger", Pg.KiHardwareTriggerAddr,
                               Pg.KiHardwareTriggerResolved != FALSE))
                           .arg(Kd::DescribePatchedSymbol(
                               "KiBugCheckActive", Pg.KiBugCheckActiveAddr,
                               Pg.KiBugCheckActiveResolved != FALSE))
                           .arg(Kd::DescribePatchedSymbol(
                               "KiFreezeExecutionLock",
                               Pg.KiFreezeExecutionLockAddr,
                               Pg.KiFreezeLockResolved != FALSE))
                     : QString()));
    Add("PatchGuard.ClearOffset",
        Kd::Utf8(Control_.PatchGuardOk ? Kd::QHexAuto(Pg.ClearOffset)
                                       : QString("-")),
        Kd::Utf8(Control_.PatchGuardOk
                     ? QString("source %1; ctx offset %2")
                           .arg(Kd::DescribeOffsetSource(Pg.OffsetSource))
                           .arg(Kd::QHexAuto(Pg.KprcbContextOffset))
                     : QString()));
    Add("PatchGuard.PpnPageGuard",
        Kd::Utf8(Control_.PatchGuardOk ? (Pg.PpnActive ? QString("Active")
                                                       : QString("Off"))
                                       : QString("-")),
        Kd::Utf8(Control_.PatchGuardOk
                     ? QString("%1 pages | %2 NX faults | %3 passthrough | "
                               "status 0x%4\ntargets: %5, %6, %7, %8")
                           .arg(Pg.PpnTargetCount)
                           .arg(Pg.PpnNxFaults)
                           .arg(Pg.PpnPassthrough)
                           .arg(Pg.PpnStatus, 8, 16, QLatin1Char('0'))
                           .arg(Kd::QHexAuto(Pg.PpnTargetPages[0]))
                           .arg(Kd::QHexAuto(Pg.PpnTargetPages[1]))
                           .arg(Kd::QHexAuto(Pg.PpnTargetPages[2]))
                           .arg(Kd::QHexAuto(Pg.PpnTargetPages[3]))
                     : QString()));
    Add("PatchGuard.CpuCoverage",
        Kd::Utf8(Control_.PatchGuardOk
                     ? QString("%1/%2 cleared")
                           .arg(Pg.CpuCleared)
                           .arg(Pg.CpuTotal)
                     : QString("-")),
        Kd::Utf8(Control_.PatchGuardOk
                     ? QString("attempted %1, failed %2, groups %3/%4")
                           .arg(Pg.CpuAttempted)
                           .arg(Pg.CpuFailed)
                           .arg(Pg.ProcessorGroupsCovered)
                           .arg(Pg.ProcessorGroupCount)
                     : QString("Win32 error %1")
                           .arg(Control_.PatchGuardError)));
    Add("PatchGuard.ContextConfidence",
        Kd::Utf8(Control_.PatchGuardOk
                     ? QString("%1%%").arg(Pg.ContextConfidence)
                     : QString("-")),
        Kd::Utf8(Control_.PatchGuardOk
                     ? QString("evidence %1").arg(Kd::QHexAuto(Pg.ContextEvidence))
                     : QString()));
    Add("PatchGuard.DpcConfidence",
        Kd::Utf8(Control_.PatchGuardOk
                     ? QString("%1 high / %2 low")
                           .arg(Pg.DpcHighConfidenceCount)
                           .arg(Pg.DpcLowConfidenceCount)
                     : QString("-")),
        "H = high confidence, L = low confidence; score threshold >= 70.");
    Add("PatchGuard.ApcResolver",
        Kd::Utf8(Control_.PatchGuardOk
                     ? QString("%1%% / %2 anchors")
                           .arg(Pg.ApcResolverConfidence)
                           .arg(Pg.ApcResolverAnchorCount)
                     : QString("-")),
        Kd::Utf8(Control_.PatchGuardOk
                     ? QString("%1 high / %2 low")
                           .arg(Pg.ApcHighConfidenceCount)
                           .arg(Pg.ApcLowConfidenceCount)
                     : QString()));
  }

  void BuildInventoryRows(int Index) {
    if (Index < 0 || Index >= static_cast<int>(Records_.size())) {
      TuiRow Row;
      Row.Cells = {"No records", {}, {}, {}, {}, {}, {},
                   Kd::Hex32(static_cast<uint32_t>(G_LastAegisCoreError))};
      Table_.Rows.push_back(std::move(Row));
      return;
    }
    const Kd::InspectorRecordSet &Set = Records_[static_cast<size_t>(Index)];
    for (const INVENTORY_RECORD &Record : Set.Records) {
      const QString PathText = QString::fromWCharArray(Record.Path);
      const QString DetailText = QString::fromWCharArray(Record.Detail);
      const QString Detail =
          PathText.isEmpty()
              ? DetailText
              : (DetailText.isEmpty() ? PathText : PathText + " | " + DetailText);
      std::string SizeOrValue;
      if (Record.SizeBytes != 0)
        SizeOrValue = Kd::Utf8(QString("%1 B").arg(Record.SizeBytes));
      else if (Record.Value[0] != 0)
        SizeOrValue = Kd::HexAuto(Record.Value[0]);
      else if (Record.Value[1] != 0)
        SizeOrValue = Kd::HexAuto(Record.Value[1]);
      else
        SizeOrValue = "-";
      TuiRow Row;
      Row.Cells = {
          Kd::Wide(Record.Name),
          Kd::Wide(Record.TypeName),
          Kd::Utf8(Kd::RecordAddressText(Record)),
          SizeOrValue,
          Kd::Utf8(Detail),
          Kd::InspectorSourceName(Record.Source),
          Kd::InspectorConfidenceName(Record.Confidence),
          Record.Status == 0
              ? std::string("Success")
              : Kd::Hex32(static_cast<uint32_t>(Record.Status)),
      };
      Row.Detail = Row.Cells[0] + "\n" + Row.Cells[4];
      Table_.Rows.push_back(std::move(Row));
    }
    if (Set.Records.empty()) {
      TuiRow Row;
      Row.Cells = {"No records", {}, {}, {}, {}, {}, {},
                   Set.Header.Status == 0
                       ? std::string("Success")
                       : Kd::Hex32(static_cast<uint32_t>(Set.Header.Status))};
      Table_.Rows.push_back(std::move(Row));
    }
  }

  void BuildSyncRows() {
    for (const auto &[Name, Type, Directory] : SyncEntries_) {
      TuiRow Row;
      Row.Cells = {Kd::Utf8(Name), Kd::Utf8(Type),
                   Directory == 0 ? std::string("Global")
                                  : std::string("Session"),
                   {}};
      Table_.Rows.push_back(std::move(Row));
    }
    if (Table_.Rows.empty()) {
      TuiRow Row;
      Row.Cells = {"No sync objects", {}, {}, {}};
      Table_.Rows.push_back(std::move(Row));
    }
  }

  void BuildSessionRows() {
    for (const auto &[SessionId, State, ProcessCount, WinStation] :
         SessionEntries_) {
      TuiRow Row;
      Row.Cells = {
          std::to_string(SessionId),
          State == (std::numeric_limits<ULONG>::max)()
              ? std::string("Unavailable")
              : Kd::Utf8(SessionStateText(State)),
          std::to_string(ProcessCount),
          Kd::Utf8(WinStation),
      };
      Table_.Rows.push_back(std::move(Row));
    }
    if (Table_.Rows.empty()) {
      TuiRow Row;
      Row.Cells = {"No sessions", {}, {}, {}};
      Table_.Rows.push_back(std::move(Row));
    }
  }

  // 当前选中的会话（0 视为不可交互，与 GUI 一致）。
  std::pair<bool, ULONG> CurrentSessionId() const {
    if (Section_ != 6)
      return {false, 0};
    const int RowIndex = Table_.CurrentRowIndex();
    if (RowIndex < 0 || RowIndex >= static_cast<int>(SessionEntries_.size()))
      return {false, 0};
    return {true, std::get<0>(SessionEntries_[static_cast<size_t>(RowIndex)])};
  }

  bool RequireSession(ULONG *SessionId) {
    const auto [HasSession, Id] = CurrentSessionId();
    if (!HasSession || Id == 0) {
      Notify("Select an interactive session first.", NoticeKind::Warning);
      return false;
    }
    *SessionId = Id;
    return true;
  }

  void RunControl(const std::string &BusyText, const std::string &ActionName,
                  std::function<bool()> Action) {
    SetStatus(BusyText);
    TuiAsync<bool>(std::move(Action),
                   [this, ActionName](bool Ok) {
                     const DWORD ErrorCode = G_LastAegisCoreError;
                     if (!Ok) {
                       const bool PpnTargetNotFound =
                           ActionName == "EnablePPN" &&
                           (ErrorCode == ERROR_NOT_FOUND ||
                            ErrorCode == ERROR_FILE_NOT_FOUND);
                       SetStatus(ActionName + " failed");
                       Notify(
                           PpnTargetNotFound
                               ? "No verified PatchGuard code page was found. "
                                 "The operation aborted without changing page "
                                 "permissions or IDT entries. Inspect the "
                                 "Ring0Core driver log for [PPN-DPC], "
                                 "[PPN-CTX], and [PPN-TGT] diagnostics."
                               : ActionName + " failed (error " +
                                     std::to_string(ErrorCode) + ").",
                           NoticeKind::Error);
                       return;
                     }
                     MarkMutated();
                     Notify(ActionName + " completed.", NoticeKind::Success);
                     Refresh();
                   });
  }

  void RunDpcApcUnlink() {
    SetStatus("Unlinking PatchGuard DPC/APC...");
    struct DpcApcResult {
      bool DpcSuccess = false;
      bool ApcSuccess = false;
      DWORD DpcError = ERROR_SUCCESS;
      DWORD ApcError = ERROR_SUCCESS;
      DPC_CANCEL_OUTPUT Dpc{};
      APC_CANCEL_OUTPUT Apc{};
    };
    TuiAsync<DpcApcResult>(
        [] {
          DpcApcResult Value;
          Value.DpcSuccess = CancelPatchGuardDpcs(&Value.Dpc) != FALSE;
          Value.DpcError = Value.DpcSuccess ? ERROR_SUCCESS
                                            : G_LastAegisCoreError;
          Value.ApcSuccess = CancelPatchGuardApcs(&Value.Apc) != FALSE;
          Value.ApcError = Value.ApcSuccess ? ERROR_SUCCESS
                                            : G_LastAegisCoreError;
          return Value;
        },
        [this](DpcApcResult Value) {
          const std::string DpcLine = Kd::Utf8(
              QString("DPC %1: scanned %2, suspects %3, unlinked %4, "
                      "NTSTATUS 0x%5, error %6")
                  .arg(Value.DpcSuccess ? "OK" : "failed")
                  .arg(Value.Dpc.Scanned)
                  .arg(Value.Dpc.Suspects)
                  .arg(Value.Dpc.Cancelled)
                  .arg(QString::number(Value.Dpc.Status, 16)
                           .rightJustified(8, '0')
                           .toUpper())
                  .arg(Value.DpcError));
          const std::string ApcLine = Kd::Utf8(
              QString("APC %1: scanned %2, suspects %3, unlinked %4, "
                      "NTSTATUS 0x%5, error %6")
                  .arg(Value.ApcSuccess ? "OK" : "failed")
                  .arg(Value.Apc.Scanned)
                  .arg(Value.Apc.Suspects)
                  .arg(Value.Apc.Cancelled)
                  .arg(QString::number(Value.Apc.Status, 16)
                           .rightJustified(8, '0')
                           .toUpper())
                  .arg(Value.ApcError));
          const std::string ResultText = DpcLine + '\n' + ApcLine;
          const bool BothOk = Value.DpcSuccess && Value.ApcSuccess;
          SetStatus(BothOk ? "DPC/APC unlink completed"
                           : "DPC/APC unlink partially failed");
          Notify(ResultText, BothOk ? NoticeKind::Success : NoticeKind::Error);
          if (BothOk)
            MarkMutated();
          Refresh();
        });
  }

  void RunTriggerPatchGuard() {
    SetStatus("Triggering PatchGuard...");
    TuiAsync<bool>([] { return SetIdtLimit() != FALSE; },
                   [this](bool Ok) {
                     const DWORD ErrorCode = G_LastAegisCoreError;
                     if (!Ok) {
                       SetStatus("TriggerPatchGuard failed");
                       Notify(Kd::Utf8(QString("TriggerPatchGuard failed "
                                               "(error %1).")
                                           .arg(ErrorCode)),
                              NoticeKind::Error);
                       return;
                     }
                     MarkMutated();
                     Notify("TriggerPatchGuard completed.",
                            NoticeKind::Success);
                     Refresh();
                   });
  }

  void LogoffSessionAction() {
    ULONG SessionId = 0;
    if (!RequireSession(&SessionId))
      return;
    ConfirmDialog(
        *Dialogs, "Log off session",
        Kd::Utf8(QString("Log off session %1? This will terminate that user's "
                         "session processes.")
                     .arg(SessionId)),
        [this, SessionId] {
          TuiAsync<Kd::SessionActionResult>(
              [SessionId] {
                Kd::SessionActionResult Value;
                Value.Success = LogoffSession(SessionId) != FALSE;
                Value.Message =
                    Value.Success
                        ? Kd::Utf8(QString("Session %1 logoff requested.")
                                       .arg(SessionId))
                        : Kd::Utf8(QString("Unable to log off session %1 "
                                           "(error %2).")
                                       .arg(SessionId)
                                       .arg(G_LastAegisCoreError));
                return Value;
              },
              [this](Kd::SessionActionResult Value) {
                Notify(Value.Message, Value.Success ? NoticeKind::Success
                                                    : NoticeKind::Error);
                if (Value.Success) {
                  MarkMutated();
                  Refresh();
                }
              });
        },
        "Logoff", "Cancel");
  }

  void DisconnectSessionAction() {
    ULONG SessionId = 0;
    if (!RequireSession(&SessionId))
      return;
    ConfirmDialog(
        *Dialogs, "Disconnect session",
        Kd::Utf8(QString("Disconnect session %1 and keep its apps running in "
                         "the background.")
                     .arg(SessionId)),
        [this, SessionId] {
          TuiAsync<Kd::SessionActionResult>(
              [SessionId] {
                Kd::SessionActionResult Value;
                Value.Success = DisconnectSessionFallback(SessionId);
                Value.Message =
                    Value.Success
                        ? Kd::Utf8(QString("Session %1 disconnected.")
                                       .arg(SessionId))
                        : Kd::Utf8(QString("Unable to disconnect session "
                                           "%1.\n%2")
                                       .arg(SessionId)
                                       .arg(DescribeWin32ErrorMessage(
                                           GetLastError())));
                return Value;
              },
              [this](Kd::SessionActionResult Value) {
                Notify(Value.Message, Value.Success ? NoticeKind::Success
                                                    : NoticeKind::Error);
                if (Value.Success) {
                  MarkMutated();
                  Refresh();
                }
              });
        },
        "Disconnect", "Cancel");
  }

  void MessageSessionAction() {
    ULONG SessionId = 0;
    if (!RequireSession(&SessionId))
      return;
    TuiDialog Dialog;
    Dialog.Title = "Send session message";
    Dialog.Body = Kd::Utf8(QString("Deliver a popup message to session %1.")
                               .arg(SessionId));
    TuiField Title;
    Title.Label = "Title";
    Title.Value = "Kernel Inspector";
    TuiField Body;
    Body.Label = "Message text";
    Body.Kind = TuiFieldKind::Multiline;
    TuiField Style;
    Style.Label = "Style";
    Style.Kind = TuiFieldKind::Combo;
    Style.Choices = {"Information", "Warning", "Error", "Question"};
    TuiField Timeout;
    Timeout.Label = "Timeout (seconds)";
    Timeout.Kind = TuiFieldKind::Int;
    Timeout.Value = "30";
    TuiField Wait;
    Wait.Label = "Wait for user response";
    Wait.Kind = TuiFieldKind::Check;
    Dialog.Fields = {Title, Body, Style, Timeout, Wait};
    Dialog.PrimaryLabel = "Send";
    Dialog.Validate = [](const TuiDialog &Value) -> std::string {
      if (TrimAscii(Value.Fields[0].Value).empty() ||
          TrimAscii(Value.Fields[1].Value).empty())
        return "Enter both a title and message text.";
      const std::string TimeoutText = TrimAscii(Value.Fields[3].Value);
      bool Ok = false;
      long Seconds = 0;
      try {
        Seconds = std::stol(TimeoutText);
        Ok = true;
      } catch (...) {
        Ok = false;
      }
      if (!Ok || Seconds <= 0)
        return "Enter a valid timeout in seconds.";
      return {};
    };
    Dialog.OnSubmit = [this, SessionId](TuiDialog &Value) {
      const QString Title = QString::fromStdString(TrimAscii(Value.Fields[0].Value));
      const QString Body = QString::fromStdString(TrimAscii(Value.Fields[1].Value));
      UINT Style = MB_OK | MB_TOPMOST;
      switch (Value.Fields[2].Choice) {
      case 1:
        Style |= MB_ICONWARNING;
        break;
      case 2:
        Style |= MB_ICONERROR;
        break;
      case 3:
        Style |= MB_ICONQUESTION;
        break;
      default:
        Style |= MB_ICONINFORMATION;
        break;
      }
      ULONG TimeoutSeconds = 30;
      try {
        TimeoutSeconds = static_cast<ULONG>(
            std::stoul(TrimAscii(Value.Fields[3].Value)));
      } catch (...) {
        TimeoutSeconds = 30;
      }
      const bool Wait = Value.Fields[4].Checked;
      SetStatus("Sending session message...");
      TuiAsync<Kd::SessionActionResult>(
          [SessionId, Title, Body, Style, TimeoutSeconds, Wait] {
            Kd::SessionActionResult Outcome;
            DWORD Response = 0;
            Outcome.Success = SendSessionMessageFallback(
                SessionId, Title, Body, Style, TimeoutSeconds, Wait, &Response);
            if (Outcome.Success) {
              Outcome.Message = Kd::Utf8(
                  QString("Message sent to session %1.%2")
                      .arg(SessionId)
                      .arg(Wait ? QString(" Response=%1.").arg(Response)
                                : QString()));
            } else {
              Outcome.Message =
                  Kd::Utf8(QString("Unable to send a message to session %1.\n%2")
                               .arg(SessionId)
                               .arg(DescribeWin32ErrorMessage(GetLastError())));
            }
            return Outcome;
          },
          [this](Kd::SessionActionResult Outcome) {
            Notify(Outcome.Message, Outcome.Success ? NoticeKind::Success
                                                   : NoticeKind::Error);
          });
    };
    Dialogs->Push(std::move(Dialog));
  }

  void RunInSessionAction() {
    ULONG SessionId = 0;
    if (!RequireSession(&SessionId))
      return;
    TuiDialog Dialog;
    Dialog.Title = "Run in session";
    Dialog.Body =
        Kd::Utf8(QString("Launch a process with the user token from session %1.")
                     .arg(SessionId));
    TuiField Executable;
    Executable.Label = "Executable";
    Executable.Placeholder = "Full path to the executable";
    TuiField Arguments;
    Arguments.Label = "Arguments";
    Arguments.Placeholder = "Optional arguments";
    TuiField ShowWindow;
    ShowWindow.Label = "Show window";
    ShowWindow.Kind = TuiFieldKind::Check;
    ShowWindow.Checked = true;
    Dialog.Fields = {Executable, Arguments, ShowWindow};
    Dialog.PrimaryLabel = "Run";
    Dialog.Validate = [](const TuiDialog &Value) -> std::string {
      const QString Path = QString::fromStdString(TrimAscii(Value.Fields[0].Value));
      if (Path.isEmpty() || !QFileInfo::exists(Path))
        return "Select an existing executable file.";
      return {};
    };
    Dialog.OnSubmit = [this, SessionId](TuiDialog &Value) {
      const QString Path = QString::fromStdString(TrimAscii(Value.Fields[0].Value));
      const QString Arguments =
          QString::fromStdString(TrimAscii(Value.Fields[1].Value));
      const bool Show = Value.Fields[2].Checked;
      SetStatus("Launching process in session...");
      TuiAsync<Kd::SessionActionResult>(
          [SessionId, Path, Arguments, Show] {
            Kd::SessionActionResult Outcome;
            DWORD ProcessId = 0;
            Outcome.Success =
                LaunchProcessInSession(SessionId, Path, Arguments, Show,
                                       &ProcessId);
            Outcome.Message =
                Outcome.Success
                    ? Kd::Utf8(QString("Process launched in session %1 with "
                                       "PID %2.")
                                   .arg(SessionId)
                                   .arg(ProcessId))
                    : Kd::Utf8(QString("Unable to launch the process in "
                                       "session %1.\n%2")
                                   .arg(SessionId)
                                   .arg(DescribeWin32ErrorMessage(GetLastError())));
            return Outcome;
          },
          [this](Kd::SessionActionResult Outcome) {
            Notify(Outcome.Message, Outcome.Success ? NoticeKind::Success
                                                   : NoticeKind::Error);
            if (Outcome.Success)
              Refresh();
          });
    };
    Dialogs->Push(std::move(Dialog));
  }

  int Index_ = 0;
  int Section_ = 0;
  TuiTable Table_;
  Kd::KernelControlState Control_;
  std::vector<Kd::InspectorRecordSet> Records_;
  KernelInspectorData::SyncEntries SyncEntries_;
  KernelInspectorData::SessionEntries SessionEntries_;
  std::atomic_bool Refreshing_{false};
};

// ============================================================
// 索引 21：KernelResearch
// ============================================================

namespace Kd {

struct ResearchSymbolRow {
  std::string Module;
  std::string Base;
  std::string Size;
  std::string Symbol;
  std::string Path;
  std::string Status;
};

struct ResearchOwnershipRow {
  std::string Source;
  std::string Address;
  std::string Module;
  std::string Rva;
  std::string Symbol;
  std::string Status;
};

struct ResearchIntegrityRow {
  std::string Kind;
  std::string Index;
  std::string Address;
  std::string Baseline;
  std::string Owner;
  std::string State;
};

struct ResearchPoolRow {
  std::string Tag;
  std::string Count;
  std::string Bytes;
  std::string Largest;
  std::string Paged;
  std::string Status;
};

struct ResearchObjectRow {
  std::string Name;
  std::string Type;
  std::string Address;
  std::string Detail;
};

struct ResearchRootkitRow {
  std::string Kind;
  std::string Severity;
  std::string Address;
  std::string Size;
  std::string Module;
  std::string Detail;
};

struct ResearchResult {
  std::vector<INVENTORY_RECORD> Modules;
  std::vector<ResearchSymbolRow> Symbols;
  std::vector<ResearchOwnershipRow> Ownership;
  std::vector<ResearchIntegrityRow> Integrity;
  std::vector<ResearchPoolRow> BigPool;
  std::vector<ResearchObjectRow> Objects;
  std::vector<ResearchRootkitRow> Rootkit;
  QJsonObject CurrentBaseline;
  bool SymbolsOk = false;
  std::string SymbolError;
};

std::string ResearchHex(uint64_t Value) {
  return AegisNT::KernelResearch::Hex(Value).toStdString();
}

ResearchResult FetchResearch(const QJsonObject &Baseline) {
  using namespace AegisNT::KernelResearch;
  ResearchResult Result;
  Result.Modules = QueryAll(IOCTL_ENUM_KERNEL_MODULES);
  auto &Symbols = SymbolService::Instance();
  QString SymbolError;
  Result.SymbolsOk = Symbols.Initialize(&SymbolError);
  Result.SymbolError = SymbolError.toStdString();
  if (Result.SymbolsOk)
    Symbols.ReloadModules(Result.Modules);

  for (const auto &Module : Result.Modules) {
    const auto Owner = ResolveAddress(Module.Address, Result.Modules);
    Result.Symbols.push_back(
        {Kd::Wide(Module.Name), ResearchHex(Module.Address),
         std::to_string(Module.SizeBytes),
         Owner.Symbol.isEmpty() ? std::string("-") : Utf8(Owner.Symbol),
         Kd::Wide(Module.Path),
         Result.SymbolsOk ? std::string("Loaded/Deferred") : Result.SymbolError});
  }

  const auto AddAddress = [&Result](const QString &Source, quint64 Address) {
    const auto Info = ResolveAddress(Address, Result.Modules);
    Result.Ownership.push_back(
        {Utf8(Source), ResearchHex(Address), Utf8(Info.Module),
         ResearchHex(Info.Rva),
         Info.Symbol.isEmpty() ? std::string("-") : Utf8(Info.Symbol),
         Utf8(Info.Status)});
  };

  SYSTEM_TABLES_OUTPUT Summary{};
  if (QuerySystemTables(&Summary) != FALSE) {
    AddAddress("SSDT", Summary.SsdtBase);
    AddAddress("ShadowSSDT", Summary.ShadowSsdtBase);
    AddAddress("IDT", Summary.IdtBase);
    AddAddress("GDT", Summary.GdtBase);
  }
  const auto CallbackRecords = QueryAll(IOCTL_ENUM_CALLBACKS);
  ULONG CallbackCount = 0;
  if (CallbackRecords.empty() &&
      SendIoctlWithOutput(IOCTL_ENUM_CALLBACKS, nullptr, 0, &CallbackCount,
                          sizeof(CallbackCount), nullptr) &&
      CallbackCount != 0) {
    const size_t Bytes = FIELD_OFFSET(CALLBACK_ENUM_OUTPUT, Entries) +
                         CallbackCount * sizeof(CALLBACK_ENTRY);
    std::vector<unsigned char> Buffer(Bytes);
    if (SendIoctlWithOutput(IOCTL_ENUM_CALLBACKS, nullptr, 0, Buffer.data(),
                            static_cast<DWORD>(Bytes), nullptr)) {
      const auto *Output =
          reinterpret_cast<const CALLBACK_ENUM_OUTPUT *>(Buffer.data());
      for (ULONG Index = 0; Index < Output->Count; ++Index)
        AddAddress("Callback", Output->Entries[Index].Address);
    }
  }

  for (const ULONG Kind : {SYSTEM_TABLE_KIND_IDT, SYSTEM_TABLE_KIND_SSDT,
                           SYSTEM_TABLE_KIND_SHADOW_SSDT}) {
    SYSTEM_TABLE_ENTRIES_OUTPUT Entries{};
    if (QuerySystemTableEntries(Kind, &Entries) == FALSE)
      continue;
    const QString KindName = Kind == SYSTEM_TABLE_KIND_IDT
                                 ? "IDT"
                                 : (Kind == SYSTEM_TABLE_KIND_SSDT
                                        ? "SSDT"
                                        : "ShadowSSDT");
    QJsonArray Values;
    const QJsonArray BaselineValues = Baseline.value(KindName).toArray();
    for (ULONG Index = 0; Index < Entries.Count; ++Index) {
      const auto &Entry = Entries.Entries[Index];
      const QString Now = QString::fromStdString(ResearchHex(Entry.Address));
      const QString Old =
          static_cast<int>(Index) < BaselineValues.size()
              ? BaselineValues.at(static_cast<int>(Index)).toString()
              : QString();
      const auto Owner = ResolveAddress(Entry.Address, Result.Modules);
      Result.Integrity.push_back(
          {Utf8(KindName), std::to_string(Entry.Index), Utf8(Now),
           Old.isEmpty() ? std::string("-") : Utf8(Old),
           Utf8(Owner.Module + (Owner.Symbol.isEmpty()
                                    ? QString()
                                    : "!" + Owner.Symbol)),
           Old.isEmpty() ? std::string("Unknown")
                         : (Old == Now ? std::string("Clean")
                                       : std::string("Changed"))});
      Values.append(Now);
    }
    Result.CurrentBaseline.insert(KindName, Values);
  }
  Result.CurrentBaseline.insert(
      "capturedAtUtc",
      QDateTime::currentDateTimeUtc().toString(Qt::ISODate));
  Result.CurrentBaseline.insert("schemaVersion", 1);

  struct PoolAggregate {
    quint64 Count = 0, Bytes = 0, Largest = 0, Paged = 0;
  };
  std::map<QString, PoolAggregate> Pools;
  std::vector<INVENTORY_RECORD> BigPoolRecords = QueryAll(IOCTL_ENUM_BIG_POOL);
  bool BigPoolOk = !BigPoolRecords.empty();

  // 较旧的 Ring0Core 构建可能不暴露 SystemBigPoolInformation：
  // 回退到用户态原生查询，避免页面静默渲染空表。
  if (BigPoolRecords.empty()) {
    using NtQuerySystemInformationFn =
        NTSTATUS(NTAPI *)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    struct NativeBigPoolEntry {
      union {
        PVOID VirtualAddress;
        ULONG_PTR NonPaged : 1;
      };
      ULONG_PTR SizeInBytes;
      union {
        UCHAR Tag[4];
        ULONG TagUlong;
      };
    };
    struct NativeBigPoolInformation {
      ULONG Count;
      NativeBigPoolEntry AllocatedInfo[1];
    };
    const auto QueryNative = reinterpret_cast<NtQuerySystemInformationFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                       "NtQuerySystemInformation"));
    constexpr SYSTEM_INFORMATION_CLASS BigPoolClass =
        static_cast<SYSTEM_INFORMATION_CLASS>(66);
    constexpr NTSTATUS ResizeStatuses[] = {static_cast<NTSTATUS>(0xC0000004L),
                                          static_cast<NTSTATUS>(0x80000005L),
                                          static_cast<NTSTATUS>(0xC0000023L)};
    const auto IsResizeStatus = [&](NTSTATUS Status) {
      return Status == ResizeStatuses[0] || Status == ResizeStatuses[1] ||
             Status == ResizeStatuses[2];
    };
    if (QueryNative != nullptr) {
      ULONG Size = 1u << 20;
      std::vector<BYTE> Buffer(Size);
      ULONG ReturnLength = 0;
      NTSTATUS Status =
          QueryNative(BigPoolClass, Buffer.data(), Size, &ReturnLength);
      for (int Attempt = 0; IsResizeStatus(Status) && Attempt < 8; ++Attempt) {
        Size = std::max(Size * 2u, ReturnLength + 0x1000u);
        Buffer.resize(Size);
        Status = QueryNative(BigPoolClass, Buffer.data(), Size, &ReturnLength);
      }
      if (Status >= 0 && Buffer.size() >= sizeof(ULONG)) {
        const auto *Native =
            reinterpret_cast<const NativeBigPoolInformation *>(Buffer.data());
        const size_t Required =
            FIELD_OFFSET(NativeBigPoolInformation, AllocatedInfo) +
            static_cast<size_t>(Native->Count) * sizeof(NativeBigPoolEntry);
        if (Required <= Buffer.size()) {
          BigPoolRecords.reserve(Native->Count);
          for (ULONG Index = 0; Index < Native->Count; ++Index) {
            const auto &Pool = Native->AllocatedInfo[Index];
            INVENTORY_RECORD Record{};
            Record.Kind = 5;
            Record.Address =
                reinterpret_cast<ULONG64>(Pool.VirtualAddress) & ~1ull;
            Record.SizeBytes = Pool.SizeInBytes;
            Record.Flags = (reinterpret_cast<ULONG_PTR>(Pool.VirtualAddress) & 1)
                               ? 1u
                               : 0u;
            for (ULONG Char = 0; Char < 4; ++Char)
              Record.Name[Char] = static_cast<WCHAR>(Pool.Tag[Char]);
            Record.Name[4] = L'\0';
            BigPoolRecords.push_back(Record);
          }
          BigPoolOk = true;
        }
      }
    }
  }
  for (const auto &Record : BigPoolRecords) {
    QString Tag = QString::fromWCharArray(Record.Name);
    if (Tag.isEmpty())
      Tag = QString::fromWCharArray(Record.TypeName);
    auto &Aggregate = Pools[Tag.isEmpty() ? "????" : Tag];
    ++Aggregate.Count;
    Aggregate.Bytes += Record.SizeBytes;
    Aggregate.Largest = std::max(Aggregate.Largest, Record.SizeBytes);
    Aggregate.Paged += (Record.Flags & 1) ? 1 : 0;
  }
  for (const auto &[Tag, Aggregate] : Pools) {
    Result.BigPool.push_back(
        {Utf8(Tag), std::to_string(Aggregate.Count),
         std::to_string(Aggregate.Bytes), std::to_string(Aggregate.Largest),
         std::to_string(Aggregate.Paged),
         Aggregate.Bytes > 64ull * 1024 * 1024 ? "Large" : "Normal"});
  }
  if (Result.BigPool.empty())
    Result.BigPool.push_back({"(none)", "0", "0", "0", "0",
                              BigPoolOk ? "No allocations" : "Unavailable"});

  for (const auto &Record : QueryAll(IOCTL_ENUM_OBJECTS, "\\")) {
    Result.Objects.push_back({Wide(Record.Name), Wide(Record.TypeName),
                              ResearchHex(Record.Address),
                              Wide(Record.Detail)});
  }

  ROOTKIT_SCAN_INPUT ScanInput{};
  ScanInput.Size = sizeof(ScanInput);
  ScanInput.Version = 1;
  ScanInput.Kind = ROOTKIT_SCAN_KIND_ALL;
  ScanInput.Flags = ROOTKIT_SCAN_FLAG_REPORT_ONLY;
  std::vector<unsigned char> ScanBuffer(sizeof(ROOTKIT_SCAN_OUTPUT));
  if (SendIoctlWithOutput(IOCTL_ROOTKIT_SCAN, &ScanInput, sizeof(ScanInput),
                          ScanBuffer.data(),
                          static_cast<DWORD>(ScanBuffer.size()), nullptr)) {
    const auto *Scan =
        reinterpret_cast<const ROOTKIT_SCAN_OUTPUT *>(ScanBuffer.data());
    const auto DescribeKind = [](ULONG Kind) -> const char * {
      switch (Kind) {
      case ROOTKIT_SCAN_KIND_HIDDEN_MODULES:
        return "Hidden Module";
      case ROOTKIT_SCAN_KIND_TEXT_INTEGRITY:
        return "Text Integrity";
      case ROOTKIT_SCAN_KIND_CALLBACKS:
        return "Callback";
      default:
        return "Scan";
      }
    };
    const auto DescribeSeverity = [](ULONG Severity) -> const char * {
      switch (Severity) {
      case 1:
        return "Warning";
      case 2:
        return "Critical";
      default:
        return "Info";
      }
    };
    for (ULONG Index = 0;
         Index < Scan->Count && Index < ROOTKIT_SCAN_MAX_RECORDS; ++Index) {
      const auto &Record = Scan->Records[Index];
      Result.Rootkit.push_back(
          {DescribeKind(Record.Kind), DescribeSeverity(Record.Severity),
           ResearchHex(Record.Address), ResearchHex(Record.Size),
           Wide(Record.ModuleName), Wide(Record.Detail)});
    }
  }
  if (Result.Rootkit.empty())
    Result.Rootkit.push_back(
        {"Scan", "Info", "-", "-", "-", "No findings or scan unavailable"});
  return Result;
}

} // namespace Kd

class KernelResearchPage final : public TuiPage {
public:
  explicit KernelResearchPage(int Index) : Index_(Index) {
    (void)Index_;
    Table_.Headers = {"Module", "Base", "Size", "PDB/Symbol", "Path", "Status"};
    Table_.RightAlign = {false, true, true, false, false, false};
    OwnedCommands.push_back(TuiCommand{
        "refresh", "refresh  (reload symbols, ownership, pools, objects, scan)",
        [this](std::vector<std::string>) { Refresh(); }});
    OwnedCommands.push_back(TuiCommand{
        "save-baseline", "save-baseline <path>  (write the integrity baseline)",
        [this](std::vector<std::string> Args) { SaveBaseline(Args); }});
    OwnedCommands.push_back(TuiCommand{
        "load-baseline", "load-baseline <path>  (read a baseline JSON)",
        [this](std::vector<std::string> Args) { LoadBaseline(Args); }});
    OwnedCommands.push_back(TuiCommand{
        "scan", "scan [module] <pattern>  (kernel byte-pattern scan)",
        [this](std::vector<std::string> Args) { PatternScan(Args); }});
    OwnedCommands.push_back(TuiCommand{
        "search", "search <text>  (filter the current tab)",
        [this](std::vector<std::string> Args) { SetSearch(Args); }});
    OwnedCommands.push_back(TuiCommand{
        "tab", "tab <1-7>  (Symbols/Ownership/Integrity/Big Pool/Objects/"
               "Rootkit/Pattern Scan)",
        [this](std::vector<std::string> Args) { SelectTab(Args); }});
  }

  std::string Title() const override { return "KernelResearch"; }

  std::string Subtitle() const override {
    return "symbols, address ownership, integrity, big pool, objects, rootkit";
  }

  void OnEnter() override { Refresh(); }

  TuiTable *ActiveTable() override { return &Table_; }

  std::string RenderText() override {
    if (!Result_)
      Refresh();
    Populate();
    std::string Text = TabStrip();
    Text += '\n';
    Text += "tab: " + TabName() + " | " + StatusText() + '\n';
    Text += TuiTableToText(Table_, 200);
    return Text;
  }

private:
  std::string TabStrip() const {
    return ::AegisNT::Tui::TabStrip(TabNames(), static_cast<int>(Tab_));
  }

  static const std::vector<std::string> &TabNames() {
    static const std::vector<std::string> Names{
        "Symbols", "Address Ownership", "Integrity", "Big Pool",
        "Objects", "Rootkit",           "Pattern Scan"};
    return Names;
  }

  std::string TabName() const {
    const auto &Names = TabNames();
    if (Tab_ < 0 || Tab_ >= static_cast<int>(Names.size()))
      return "-";
    return Names[static_cast<size_t>(Tab_)];
  }

  std::string StatusText() const {
    if (!Result_)
      return "not queried";
    return std::to_string(Result_->Modules.size()) + " modules | " +
           (Result_->SymbolsOk ? "symbols ready" : "symbols offline") + " | " +
           std::to_string(Result_->BigPool.size()) + " pool tags | " +
           std::to_string(Result_->Objects.size()) + " objects | " +
           std::to_string(Result_->Rootkit.size()) + " rootkit";
  }

  void SelectTab(std::vector<std::string> Args) {
    if (Args.empty()) {
      Notify("Usage: tab <1-7>", NoticeKind::Warning);
      return;
    }
    int Value = -1;
    try {
      Value = std::stoi(TrimAscii(Args.front())) - 1;
    } catch (...) {
      Value = -1;
    }
    if (Value < 0 || Value >= static_cast<int>(TabNames().size())) {
      const std::string Needle = LowerAscii(TrimAscii(Args.front()));
      const auto &Names = TabNames();
      for (size_t Index = 0; Index < Names.size(); ++Index) {
        if (LowerAscii(Names[Index]).find(Needle) != std::string::npos) {
          Value = static_cast<int>(Index);
          break;
        }
      }
    }
    if (Value < 0) {
      Notify("Unknown tab: " + std::string(Args.front()), NoticeKind::Warning);
      return;
    }
    Tab_ = Value;
    Populate();
  }

  void SetSearch(std::vector<std::string> Args) {
    std::string Text;
    for (const std::string &Arg : Args) {
      if (!Text.empty())
        Text += ' ';
      Text += Arg;
    }
    Filter = TrimAscii(Text);
    Table_.Filter = Filter;
    Table_.Rebuild();
    SetStatus(Filter.empty() ? "filter cleared" : "filter: " + Filter);
  }

  void Refresh() {
    if (Refreshing_.exchange(true))
      return;
    SetStatus("Refreshing kernel research data...");
    const QJsonObject Baseline = Baseline_;
    TuiAsync<Kd::ResearchResult>(
        [Baseline] { return Kd::FetchResearch(Baseline); },
        [this](Kd::ResearchResult Result) {
          Refreshing_ = false;
          if (ScanRows_.empty())
            Result_ = std::make_shared<Kd::ResearchResult>(std::move(Result));
          else
            Result_ = std::make_shared<Kd::ResearchResult>(std::move(Result));
          Populate();
          SetStatus(StatusText());
        });
  }

  void SaveBaseline(std::vector<std::string> Args) {
    if (Args.empty()) {
      Notify("Usage: save-baseline <path>", NoticeKind::Warning);
      return;
    }
    const QString Path = QString::fromStdString(TrimAscii(Args.front()));
    const QJsonObject Baseline =
        Result_ ? Result_->CurrentBaseline : QJsonObject{};
    const QByteArray Data = QJsonDocument(Baseline).toJson(QJsonDocument::Compact);
    QFile File(Path);
    if (!File.open(QIODevice::WriteOnly)) {
      Notify(Kd::Utf8("Failed to save baseline: " + File.errorString()),
             NoticeKind::Error);
      return;
    }
    if (File.write(Data) != Data.size()) {
      Notify(Kd::Utf8("Failed to save baseline: " + File.errorString()),
             NoticeKind::Error);
      return;
    }
    File.close();
    Notify("Baseline saved.", NoticeKind::Success);
  }

  void LoadBaseline(std::vector<std::string> Args) {
    if (Args.empty()) {
      Notify("Usage: load-baseline <path>", NoticeKind::Warning);
      return;
    }
    const QString Path = QString::fromStdString(TrimAscii(Args.front()));
    QFile File(Path);
    if (!File.open(QIODevice::ReadOnly)) {
      Notify(Kd::Utf8("Failed to open baseline: " + File.errorString()),
             NoticeKind::Error);
      return;
    }
    const QJsonDocument Document = QJsonDocument::fromJson(File.readAll());
    if (!Document.isObject()) {
      Notify("Invalid baseline JSON.", NoticeKind::Error);
      return;
    }
    Baseline_ = Document.object();
    Notify("Baseline loaded.", NoticeKind::Success);
    Refresh();
  }

  void PatternScan(std::vector<std::string> Args) {
    if (Args.empty()) {
      Notify("Enter a byte pattern first.", NoticeKind::Error);
      return;
    }
    const std::string PatternText = TrimAscii(Args.back());
    if (PatternText.empty()) {
      Notify("Enter a byte pattern first.", NoticeKind::Error);
      return;
    }
    std::string Module;
    if (Args.size() >= 2) {
      for (size_t Index = 0; Index + 1 < Args.size(); ++Index) {
        if (!Module.empty())
          Module += ' ';
        Module += TrimAscii(Args[Index]);
      }
    }
    SetStatus("Scanning kernel memory...");
    TuiAsync<KERNEL_PATTERN_SCAN_OUTPUT>(
        [Module, PatternText] {
          KERNEL_PATTERN_SCAN_OUTPUT Output{};
          const std::wstring ModuleWide = QString::fromStdString(Module)
                                              .toStdWString();
          const std::wstring PatternWide = QString::fromStdString(PatternText)
                                               .toStdWString();
          KernelPatternScan(ModuleWide.empty() ? nullptr : ModuleWide.c_str(),
                            PatternWide.c_str(), &Output);
          return Output;
        },
        [this](KERNEL_PATTERN_SCAN_OUTPUT Output) {
          ScanRows_.clear();
          for (ULONG Index = 0; Index < Output.HitCount; ++Index) {
            TuiRow Row;
            Row.Cells = {
                Kd::Wide(Output.Hits[Index].ModuleName),
                Kd::ResearchHex(Output.Hits[Index].Address),
                Kd::ResearchHex(Output.Hits[Index].Rva),
                "Module base " +
                    Kd::ResearchHex(Output.Hits[Index].ModuleBase),
            };
            ScanRows_.push_back(std::move(Row));
          }
          Tab_ = 6;
          Populate();
          if (Output.HitCount == 0 && Output.TotalHits == 0) {
            SetStatus("Pattern scan failed");
            Notify(Kd::Utf8(QString("Kernel pattern scan failed.\nWin32 "
                                    "error: %1")
                                .arg(G_LastAegisCoreError)),
                   NoticeKind::Error);
            return;
          }
          SetStatus(Kd::Utf8(QString("Pattern scan: %1 hit(s) across %2 "
                                     "module(s) (per page, first hit)")
                                 .arg(Output.TotalHits)
                                 .arg(Output.ScannedModules)));
        });
  }

  void Populate() {
    if (Tab_ != 6)
      ScanRows_.clear();
    Table_.Filter = Filter;
    Table_.Rows.clear();
    switch (Tab_) {
    case 0:
      Table_.Headers = {"Module", "Base", "Size", "PDB/Symbol", "Path",
                        "Status"};
      Table_.RightAlign = {false, true, true, false, false, false};
      if (Result_) {
        for (const auto &Row : Result_->Symbols) {
          TuiRow Item;
          Item.Cells = {Row.Module, Row.Base, Row.Size, Row.Symbol, Row.Path,
                        Row.Status};
          Table_.Rows.push_back(std::move(Item));
        }
      }
      break;
    case 1:
      Table_.Headers = {"Source", "Address", "Module", "RVA", "Symbol",
                        "Status"};
      Table_.RightAlign = {false, true, false, true, false, false};
      if (Result_) {
        for (const auto &Row : Result_->Ownership) {
          TuiRow Item;
          Item.Cells = {Row.Source, Row.Address, Row.Module, Row.Rva,
                        Row.Symbol, Row.Status};
          Table_.Rows.push_back(std::move(Item));
        }
      }
      break;
    case 2:
      Table_.Headers = {"Kind", "Index", "Address", "Baseline", "Module/Symbol",
                        "State"};
      Table_.RightAlign = {false, true, true, true, false, false};
      if (Result_) {
        for (const auto &Row : Result_->Integrity) {
          TuiRow Item;
          Item.Cells = {Row.Kind, Row.Index, Row.Address, Row.Baseline,
                        Row.Owner, Row.State};
          Table_.Rows.push_back(std::move(Item));
        }
      }
      break;
    case 3:
      Table_.Headers = {"Tag", "Allocations", "Bytes", "Largest", "Paged",
                        "Status"};
      Table_.RightAlign = {false, true, true, true, true, false};
      if (Result_) {
        for (const auto &Row : Result_->BigPool) {
          TuiRow Item;
          Item.Cells = {Row.Tag, Row.Count, Row.Bytes, Row.Largest, Row.Paged,
                        Row.Status};
          Table_.Rows.push_back(std::move(Item));
        }
      }
      break;
    case 4:
      Table_.Headers = {"Object", "Type", "Address", "Detail"};
      Table_.RightAlign = {false, false, true, false};
      if (Result_) {
        for (const auto &Row : Result_->Objects) {
          TuiRow Item;
          Item.Cells = {Row.Name, Row.Type, Row.Address, Row.Detail};
          Table_.Rows.push_back(std::move(Item));
        }
      }
      break;
    case 5:
      Table_.Headers = {"Kind", "Severity", "Address", "Module", "Detail"};
      Table_.RightAlign = {false, false, true, false, false};
      if (Result_) {
        for (const auto &Row : Result_->Rootkit) {
          TuiRow Item;
          Item.Cells = {Row.Kind, Row.Severity, Row.Address, Row.Module,
                        Row.Detail};
          Table_.Rows.push_back(std::move(Item));
        }
      }
      break;
    default:
      Table_.Headers = {"Module", "Address", "RVA", "Detail"};
      Table_.RightAlign = {false, true, true, false};
      for (const TuiRow &Row : ScanRows_)
        Table_.Rows.push_back(Row);
      break;
    }
    if (Table_.Rows.empty()) {
      TuiRow Item;
      Item.Cells.assign(Table_.Headers.size(), {});
      Item.Cells[0] = "No data";
      Table_.Rows.push_back(std::move(Item));
    }
    Table_.Rebuild();
  }

  int Index_ = 0;
  int Tab_ = 0;
  std::shared_ptr<Kd::ResearchResult> Result_;
  std::vector<TuiRow> ScanRows_;
  QJsonObject Baseline_;
  TuiTable Table_;
  std::atomic_bool Refreshing_{false};
};

// ============================================================
// 索引 22：Hook
// ============================================================
class HookPage final : public TuiPage {
public:
  explicit HookPage(int Index) : Index_(Index) {
    (void)Index_;
    Table_.Headers = {"ID",     "State",  "Target", "Index",  "Vector",
                      "Driver", "Original", "Proxy", "Hits",  "Active",
                      "Status", "Detail"};
    Table_.RightAlign = {true,  false, false, true, true, false,
                         true, true,  true,  true, true, false};
    OwnedCommands.push_back(TuiCommand{
        "refresh", "refresh  (re-enumerate installed hooks and capabilities)",
        [this](std::vector<std::string>) { Refresh(); }});
    OwnedCommands.push_back(TuiCommand{
        "add", "add  (install a hook; target-specific fields)",
        [this](std::vector<std::string>) { ShowAddDialog(); }});
    OwnedCommands.push_back(TuiCommand{
        "enable", "enable  (enable the selected hook)",
        [this](std::vector<std::string>) { Operate(HOOK_OP_ENABLE,
                                                  IOCTL_HOOK_ENABLE,
                                                  "Enable"); }});
    OwnedCommands.push_back(TuiCommand{
        "disable", "disable  (disable the selected hook)",
        [this](std::vector<std::string>) { Operate(HOOK_OP_DISABLE,
                                                   IOCTL_HOOK_DISABLE,
                                                   "Disable"); }});
    OwnedCommands.push_back(TuiCommand{
        "verify", "verify  (verify the selected hook)",
        [this](std::vector<std::string>) { Operate(HOOK_OP_VERIFY,
                                                   IOCTL_HOOK_VERIFY,
                                                   "Verify"); }});
    OwnedCommands.push_back(TuiCommand{
        "remove", "remove  (remove the selected hook)",
        [this](std::vector<std::string>) { Operate(HOOK_OP_REMOVE,
                                                   IOCTL_HOOK_REMOVE,
                                                   "Remove"); }});
    OwnedCommands.push_back(TuiCommand{
        "restore-all", "restore-all  (IOCTL_HOOK_RESTORE_ALL)",
        [this](std::vector<std::string>) { RestoreAll(); }});
  }

  std::string Title() const override { return "Hook"; }

  std::string Subtitle() const override {
    return "kernel hooks: dispatch, fast I/O, SSDT, IDT, inline";
  }

  void OnEnter() override { Refresh(); }

  TuiTable *ActiveTable() override { return &Table_; }

  std::string RenderText() override {
    Populate();
    if (Records_.empty())
      Refresh();
    std::string Text = " " + Capabilities_ + '\n';
    Text += " DriverDispatch, FastIO.CheckIfPossible, SSDT, IDT (current CPU), "
            "and x64 Inline are available. SSDT/IDT/Inline require a kernel "
            "proxy address.\n";
    Text += TuiTableToText(Table_, 200);
    return Text;
  }

private:
  static std::string StateText(ULONG State) {
    switch (State) {
    case HOOK_STATE_PREPARED:
      return "Prepared";
    case HOOK_STATE_ACTIVE:
      return "Active";
    case HOOK_STATE_DISABLED:
      return "Disabled";
    case HOOK_STATE_RESTORED:
      return "Restored";
    case HOOK_STATE_FAILED:
      return "Failed";
    default:
      return "Empty";
    }
  }

  static std::string TargetText(ULONG TargetKind) {
    switch (TargetKind) {
    case HOOK_TARGET_DRIVER_DISPATCH:
      return "DriverDispatch";
    case HOOK_TARGET_FAST_IO:
      return "FastIO";
    case HOOK_TARGET_SSDT:
      return "SSDT";
    case HOOK_TARGET_IDT:
      return "IDT";
    case HOOK_TARGET_INLINE:
      return "Inline";
    case HOOK_TARGET_VT_EPT:
      return "VT/EPT";
    default:
      return "Other";
    }
  }

  static std::string HookHex(uint64_t Value) {
    return Value == 0 ? std::string("-") : Kd::HexAuto(Value);
  }

  void Refresh() {
    if (Refreshing_.exchange(true))
      return;
    TuiAsync<std::pair<std::vector<HOOK_RECORD>, HOOK_CAPABILITIES_OUTPUT>>(
        [this] {
          std::lock_guard<std::mutex> Lock(IoMutex_);
          std::vector<HOOK_RECORD> Records;
          QueryHooks(Records);
          HOOK_CAPABILITIES_OUTPUT Capabilities{};
          Capabilities.Size = sizeof(Capabilities);
          QueryHookCapabilities(&Capabilities);
          return std::make_pair(Records, Capabilities);
        },
        [this](std::pair<std::vector<HOOK_RECORD>, HOOK_CAPABILITIES_OUTPUT>
                    Value) {
          Refreshing_ = false;
          Records_ = std::move(Value.first);
          PopulateCapabilities(Value.second);
          Populate();
        });
  }

  void PopulateCapabilities(const HOOK_CAPABILITIES_OUTPUT &Output) {
    QStringList Targets;
    if (Output.SupportedTargets & (1u << HOOK_TARGET_DRIVER_DISPATCH))
      Targets << "DriverDispatch";
    if (Output.SupportedTargets & (1u << HOOK_TARGET_FAST_IO))
      Targets << "FastIO";
    if (Output.SupportedTargets & (1u << HOOK_TARGET_SSDT))
      Targets << "SSDT";
    if (Output.SupportedTargets & (1u << HOOK_TARGET_IDT))
      Targets << "IDT";
    if (Output.SupportedTargets & (1u << HOOK_TARGET_INLINE))
      Targets << "Inline";
    if (Output.SupportedTargets & (1u << HOOK_TARGET_VT_EPT))
      Targets << "VT/EPT";
    if (Targets.isEmpty()) {
      Capabilities_ = Kd::Utf8(QString("Capabilities unavailable (%1)")
                                   .arg(G_LastAegisCoreError));
      return;
    }
    Capabilities_ =
        Kd::Utf8(QString("Targets: %1 | Active: %2/%3")
                     .arg(Targets.join(", "))
                     .arg(Output.ActiveHooks)
                     .arg(Output.MaxHooks));
  }

  void Populate() {
    Table_.Filter = Filter;
    Table_.Rows.clear();
    for (const HOOK_RECORD &Item : Records_) {
      TuiRow Row;
      Row.Cells = {
          std::to_string(Item.HookId),
          StateText(Item.State),
          TargetText(Item.TargetKind),
          std::to_string(Item.TableIndex),
          std::to_string(Item.Vector),
          Kd::Wide(Item.DriverName),
          HookHex(Item.OriginalAddress),
          HookHex(Item.ProxyAddress),
          std::to_string(Item.HitCount),
          std::to_string(Item.ActiveCalls),
          Kd::Hex32(static_cast<uint32_t>(Item.Status)),
          Kd::Wide(Item.Detail),
      };
      Row.Detail = Kd::Wide(Item.Detail);
      Table_.Rows.push_back(std::move(Row));
    }
    Table_.Rebuild();
    SetStatus(std::to_string(Records_.size()) + " hook(s)");
  }

  std::pair<bool, ULONG> CurrentHookId() const {
    const int RowIndex = Table_.CurrentRowIndex();
    if (RowIndex < 0 || RowIndex >= static_cast<int>(Records_.size()))
      return {false, 0};
    return {true, Records_[static_cast<size_t>(RowIndex)].HookId};
  }

  void Operate(ULONG Operation, DWORD Ioctl, const std::string &Action) {
    const auto [HasHook, HookId] = CurrentHookId();
    if (!HasHook) {
      Notify("Select a hook row first.", NoticeKind::Warning);
      return;
    }
    if (HookId == 0) {
      Notify("The selected hook ID is invalid.", NoticeKind::Warning);
      return;
    }
    SetStatus(Action + "...");
    TuiAsync<bool>(
        [this, Operation, Ioctl, HookId] {
          std::lock_guard<std::mutex> Lock(IoMutex_);
          HOOK_RECORD Result{};
          return OperateHookById(Ioctl, Operation, HookId, &Result);
        },
        [this, HookId, Action](bool Ok) {
          const DWORD Error = G_LastAegisCoreError;
          if (!Ok) {
            SetStatus(Action + " failed (" + std::to_string(Error) + ")");
            Notify(Kd::Utf8(QString("Hook %1 %2 failed (%3).")
                                .arg(HookId)
                                .arg(QString::fromStdString(LowerAscii(Action)))
                                .arg(Error)),
                   NoticeKind::Error);
            return;
          }
          SetStatus("Hook " + std::to_string(HookId) + " " +
                    LowerAscii(Action) + ".");
          MarkMutated();
          Refresh();
        });
  }

  void RestoreAll() {
    SetStatus("Restoring hooks...");
    TuiAsync<bool>(
        [this] {
          std::lock_guard<std::mutex> Lock(IoMutex_);
          return SendIoctl(IOCTL_HOOK_RESTORE_ALL, nullptr, 0) != FALSE;
        },
        [this](bool Ok) {
          const DWORD Error = G_LastAegisCoreError;
          SetStatus(Ok ? "All hooks restored."
                       : "Restore failed (" + std::to_string(Error) + ")");
          if (!Ok)
            Notify("Restore failed (" + std::to_string(Error) + ")",
                   NoticeKind::Error);
          else
            MarkMutated();
          Refresh();
        });
  }

  void ShowAddDialog() {
    TuiDialog Dialog;
    Dialog.Title = "Add Hook";
    TuiField Target;
    Target.Label = "Target type";
    Target.Kind = TuiFieldKind::Combo;
    Target.Choices = {"DriverDispatch", "FastIO.CheckIfPossible", "SSDT", "IDT",
                      "Inline"};
    TuiField Driver;
    Driver.Label = "Driver";
    Driver.Placeholder = "Driver service or \\Driver\\Name";
    TuiField Major;
    Major.Label = "Major function";
    Major.Kind = TuiFieldKind::Combo;
    for (ULONG Index = 0; Index <= 0x1B; ++Index)
      Major.Choices.push_back("MajorFunction " + std::to_string(Index));
    TuiField IndexOrVector;
    IndexOrVector.Label = "Table index / vector";
    IndexOrVector.Placeholder = "Decimal or 0x...";
    TuiField TargetAddress;
    TargetAddress.Label = "Target address";
    TargetAddress.Kind = TuiFieldKind::Hex;
    TargetAddress.Placeholder = "Kernel address (0x...)";
    TuiField ProxyAddress;
    ProxyAddress.Label = "Proxy address";
    ProxyAddress.Kind = TuiFieldKind::Hex;
    ProxyAddress.Placeholder = "Kernel address (0x...)";
    TuiField ShadowSsdt;
    ShadowSsdt.Label = "Use Shadow SSDT";
    ShadowSsdt.Kind = TuiFieldKind::Check;
    Driver.Hint = "Required for DriverDispatch and FastIO targets.";
    IndexOrVector.Hint =
        "Required for FastIO / SSDT / IDT. Fast I/O slot is fixed at 0.";
    ProxyAddress.Hint =
        "Required for SSDT / IDT / Inline; must be kernel code.";
    Dialog.Fields = {Target,      Driver,      Major,        IndexOrVector,
                     TargetAddress, ProxyAddress, ShadowSsdt};
    Dialog.PrimaryLabel = "Install";
    Dialog.Validate = [](const TuiDialog &Value) -> std::string {
      const int Kind = Value.Fields[0].Choice;
      const ULONG TargetKind = Kind == 0   ? HOOK_TARGET_DRIVER_DISPATCH
                               : Kind == 1 ? HOOK_TARGET_FAST_IO
                               : Kind == 2 ? HOOK_TARGET_SSDT
                               : Kind == 3 ? HOOK_TARGET_IDT
                                           : HOOK_TARGET_INLINE;
      const std::string Name = TrimAscii(Value.Fields[1].Value);
      if ((TargetKind == HOOK_TARGET_DRIVER_DISPATCH ||
           TargetKind == HOOK_TARGET_FAST_IO) &&
          Name.empty())
        return "Enter a driver name for this target.";
      const std::string IndexText = TrimAscii(Value.Fields[3].Value);
      unsigned long Index = 0;
      if (!IndexText.empty()) {
        try {
          Index = std::stoul(IndexText, nullptr, 0);
        } catch (...) {
          return "Enter a valid decimal or hexadecimal index/vector.";
        }
      }
      if (TargetKind == HOOK_TARGET_IDT && Index > 255)
        return "Enter a valid decimal or hexadecimal index/vector.";
      const auto ParseAddress = [](const std::string &Text) -> uint64_t {
        std::string Value = TrimAscii(Text);
        if (Value.size() > 2 && Value[0] == '0' &&
            (Value[1] == 'x' || Value[1] == 'X'))
          Value = Value.substr(2);
        if (Value.empty())
          return 0;
        try {
          return std::stoull(Value, nullptr, 16);
        } catch (...) {
          return 0;
        }
      };
      const uint64_t Proxy = ParseAddress(Value.Fields[5].Value);
      if ((TargetKind == HOOK_TARGET_SSDT || TargetKind == HOOK_TARGET_IDT ||
           TargetKind == HOOK_TARGET_INLINE) &&
          Proxy == 0)
        return "Enter a kernel proxy address (0x...).";
      if (TargetKind == HOOK_TARGET_INLINE &&
          ParseAddress(Value.Fields[4].Value) == 0)
        return "Enter an inline target address (0x...).";
      return {};
    };
    Dialog.OnSubmit = [this](TuiDialog &Value) {
      const int Kind = Value.Fields[0].Choice;
      const ULONG TargetKind = Kind == 0   ? HOOK_TARGET_DRIVER_DISPATCH
                               : Kind == 1 ? HOOK_TARGET_FAST_IO
                               : Kind == 2 ? HOOK_TARGET_SSDT
                               : Kind == 3 ? HOOK_TARGET_IDT
                                           : HOOK_TARGET_INLINE;
      const QString Name =
          QString::fromStdString(TrimAscii(Value.Fields[1].Value));
      const ULONG MajorFunction =
          static_cast<ULONG>(Value.Fields[2].Choice);
      const std::string IndexText = TrimAscii(Value.Fields[3].Value);
      ULONG Index = 0;
      if (!IndexText.empty()) {
        try {
          Index = static_cast<ULONG>(std::stoul(IndexText, nullptr, 0));
        } catch (...) {
          Index = 0;
        }
      }
      const auto ParseAddress = [](const std::string &Text) -> uint64_t {
        std::string Raw = TrimAscii(Text);
        if (Raw.size() > 2 && Raw[0] == '0' &&
            (Raw[1] == 'x' || Raw[1] == 'X'))
          Raw = Raw.substr(2);
        if (Raw.empty())
          return 0;
        try {
          return std::stoull(Raw, nullptr, 16);
        } catch (...) {
          return 0;
        }
      };
      const uint64_t TargetValue = ParseAddress(Value.Fields[4].Value);
      const uint64_t ProxyValue = ParseAddress(Value.Fields[5].Value);
      const ULONG Flags =
          Value.Fields[6].Checked ? HOOK_FLAG_SHADOW_SSDT : 0;
      SetStatus("Installing hook...");
      TuiAsync<std::pair<bool, std::string>>(
          [this, Name, TargetKind, MajorFunction, Index, TargetValue,
           ProxyValue, Flags] {
            std::lock_guard<std::mutex> Lock(IoMutex_);
            HOOK_REQUEST Request{};
            Request.Operation = HOOK_OP_INSTALL;
            Request.TargetKind = TargetKind;
            Request.MajorFunction = MajorFunction;
            Request.TableIndex = Index;
            Request.Vector = Index;
            Request.TargetAddress = TargetValue;
            Request.ProxyAddress = ProxyValue;
            Request.Flags = Flags;
            wcsncpy_s(Request.DriverName, Name.toStdWString().c_str(),
                      _TRUNCATE);
            HOOK_RECORD Result{};
            const bool Ok = OperateHook(Request, &Result);
            return std::make_pair(
                Ok, Ok ? "Hook " + std::to_string(Result.HookId) + " active."
                       : "Hook install failed (" +
                             std::to_string(G_LastAegisCoreError) + ").");
          },
          [this](std::pair<bool, std::string> Value) {
            SetStatus(Value.second);
            Notify(Value.second, Value.first ? NoticeKind::Success
                                             : NoticeKind::Error);
            if (Value.first) {
              MarkMutated();
              Refresh();
            }
          });
    };
    Dialogs->Push(std::move(Dialog));
  }

  int Index_ = 0;
  // 与 GUI 的 IoMutex 一致：所有驱动交互串行化。
  std::mutex IoMutex_;
  std::vector<HOOK_RECORD> Records_;
  std::string Capabilities_ = "Capabilities: querying...";
  TuiTable Table_;
  std::atomic_bool Refreshing_{false};
};

// ------------------------------------------------------------
// 工厂
// ------------------------------------------------------------

std::unique_ptr<TuiPage> MakeDriverPage(int Index) {
  return std::make_unique<DriverPage>(Index);
}

std::unique_ptr<TuiPage> MakeServicePage(int Index) {
  return std::make_unique<ServicePage>(Index);
}

std::unique_ptr<TuiPage> MakeTablePage(int Index) {
  return std::make_unique<TablePage>(Index);
}

std::unique_ptr<TuiPage> MakeKernelInspectorPage(int Index) {
  return std::make_unique<KernelInspectorPage>(Index);
}

std::unique_ptr<TuiPage> MakeKernelResearchPage(int Index) {
  return std::make_unique<KernelResearchPage>(Index);
}

std::unique_ptr<TuiPage> MakeHookPage(int Index) {
  return std::make_unique<HookPage>(Index);
}

} // namespace AegisNT::Tui
