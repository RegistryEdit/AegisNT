// Source/Tui/TuiPagesTask.cpp
// ============================================================
// 索引 1/2/5/9/24：Task / Monitor / Window / Callback / HotKeys。
// ------------------------------------------------------------
// 每个页面与对应 Qt 页（TaskManagerPage / MonitorManagerPage /
// WindowManagerPage / CallbackPage / HotKeysPage）使用同一批后端调用、
// 同一套列名与提示文案；耗时调用一律经 TuiAsync 回到 UI 线程改表格。
// 驱动/AegisSentinel 缺失时显示 GUI 的失败文案，不解引用空数据。
// 所有类型定义都留在本文件内（unity 包含，全局作用域）。
// ============================================================

#include "TuiAsync.h"
#include "TuiPages.h"
#include "TuiSync.h"
#include "TuiWidgets.h"

namespace AegisNT::Tui {
namespace {

std::string Utf8(const QString &Text) { return Text.toStdString(); }

// 0x 前缀 + 大写/小写十六进制，按位宽左补零。
std::string HexValue(uint64_t Value, int Width, bool Upper = true) {
  const char *Digits = Upper ? "0123456789ABCDEF" : "0123456789abcdef";
  std::string Out;
  do {
    Out.insert(Out.begin(), Digits[Value & 0xF]);
    Value >>= 4;
  } while (Value != 0);
  while (static_cast<int>(Out.size()) < Width)
    Out.insert(Out.begin(), '0');
  return "0x" + Out;
}

bool ParseUInt32(const std::string &Text, DWORD &Out) {
  const QString Clean = QString::fromStdString(TrimAscii(Text));
  if (Clean.isEmpty())
    return false;
  bool Ok = false;
  const qulonglong Value = Clean.toULongLong(&Ok, 0);
  if (!Ok || Value > 0xFFFFFFFFull)
    return false;
  Out = static_cast<DWORD>(Value);
  return true;
}

bool ParseUInt64(const std::string &Text, uint64_t &Out) {
  const QString Clean = QString::fromStdString(TrimAscii(Text));
  if (Clean.isEmpty())
    return false;
  bool Ok = false;
  const qulonglong Value = Clean.toULongLong(&Ok, 0);
  if (!Ok)
    return false;
  Out = static_cast<uint64_t>(Value);
  return true;
}

// QString �� UTF-8 宽字符缓冲的拷贝（驱动结构体里的 WCHAR 字段）。
template <size_t N>
std::string WideField(const WCHAR (&Text)[N]) {
  return Utf8(QString::fromWCharArray(Text, static_cast<int>(wcsnlen_s(Text, N))));
}

void CopyWide(WCHAR *Target, size_t Capacity, const std::string &Text) {
  if (!Target || Capacity == 0)
    return;
  Target[0] = L'\0';
  if (Text.empty())
    return;
  const QString Wide = QString::fromStdString(Text);
  wcsncpy_s(Target, Capacity, reinterpret_cast<const WCHAR *>(Wide.utf16()),
            _TRUNCATE);
}

} // namespace
// ------------------------------------------------------------
// Task 页共用数据
// ------------------------------------------------------------

struct TaskProcessRow {
  DWORD Pid = 0;
  DWORD ParentPid = 0;
  DWORD ThreadCount = 0;
  DWORD HandleCount = 0;
  DWORD HandleCountError = ERROR_SUCCESS;
  DWORD SessionId = 0;
  DWORD IntegrityRid = 0;
  uint64_t Eprocess = 0;
  QString Name;
  QString User;
  QString EprocessText;
  bool DriverData = false;
  bool HandleCountAvailable = false;
  bool Protected = false;
  bool Ppl = false;
  bool Critical = false;
  bool Hidden = false;
  UCHAR PplRaw = 0;
};

struct TaskThreadRow {
  DWORD Tid = 0;
  DWORD ProcessId = 0;
  UCHAR PreviousMode = 0;
  UCHAR ApcQueueable = 0;
  UCHAR PrevModeStatus = THREAD_FIELD_OK;
  UCHAR ApcStatus = THREAD_FIELD_OK;
  uint64_t Ethread = 0;
  uint64_t StartAddress = 0;
  DWORD Priority = 0;
  DWORD State = 0;
  std::string ProcessName;
};

struct TaskHandleRow {
  uint64_t HandleValue = 0;
  uint64_t ObjectAddress = 0;
  uint32_t GrantedAccess = 0;
  uint32_t Attributes = 0;
  QString TypeName;
  QString ObjectName;
};

namespace {

QString IntegrityName(DWORD Rid) {
  if (Rid >= 0x5000)
    return "Protected";
  if (Rid >= 0x4000)
    return "System";
  if (Rid >= 0x3000)
    return "High";
  if (Rid >= 0x2000)
    return "Medium";
  if (Rid >= 0x1000)
    return "Low";
  return Rid == 0 ? "Unknown" : "Untrusted";
}

QString FormatTaskPointer(uint64_t Value) {
  if (Value == 0)
    return "-";
  return QString("0x%1")
      .arg(static_cast<qulonglong>(Value), static_cast<int>(sizeof(uintptr_t)) * 2,
           16, QLatin1Char('0'))
      .toUpper();
}

QString FormatPreviousMode(const TaskThreadRow &Row) {
  switch (Row.PrevModeStatus) {
  case THREAD_FIELD_NOT_APPLIC:
    return "N/A";
  case THREAD_FIELD_LOOKUP:
    return "Exited";
  case THREAD_FIELD_FAULT:
    return "Unavailable";
  default:
    break;
  }
  if (Row.PreviousMode == 1)
    return "UserMode";
  if (Row.PreviousMode == 0)
    return "KernelMode";
  return "Unavailable";
}

QString FormatApcQueueable(const TaskThreadRow &Row) {
  switch (Row.ApcStatus) {
  case THREAD_FIELD_NOT_APPLIC:
    return "N/A";
  case THREAD_FIELD_LOOKUP:
    return "Exited";
  case THREAD_FIELD_FAULT:
    return "Unavailable";
  default:
    break;
  }
  return Row.ApcQueueable ? "Yes" : "No";
}

// 与 GUI 的 QueryProcessDetails 相同：用户、完整性、句柄数一次取齐。
void QueryProcessDetails(DWORD Pid, TaskProcessRow &Row,
                         std::map<QByteArray, QString> &UserCache) {
  Row.User = "N/A";
  Row.IntegrityRid = 0;
  Row.HandleCount = 0;
  Row.HandleCountError = ERROR_SUCCESS;
  Row.HandleCountAvailable = false;

  HANDLE Process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
  if (!Process) {
    Row.HandleCountError = GetLastError();
    return;
  }

  Row.HandleCountAvailable = GetProcessHandleCount(Process, &Row.HandleCount);
  if (!Row.HandleCountAvailable)
    Row.HandleCountError = GetLastError();

  HANDLE Token = nullptr;
  if (OpenProcessToken(Process, TOKEN_QUERY, &Token)) {
    Row.IntegrityRid = GetIntegrityLevel(Token);
    DWORD Size = 0;
    GetTokenInformation(Token, TokenUser, nullptr, 0, &Size);
    std::vector<unsigned char> Buffer(Size);
    if (Size && GetTokenInformation(Token, TokenUser, Buffer.data(), Size, &Size)) {
      const auto *TokenUserInformation = reinterpret_cast<TOKEN_USER *>(Buffer.data());
      const QByteArray SidKey(
          reinterpret_cast<const char *>(TokenUserInformation->User.Sid),
          GetLengthSid(TokenUserInformation->User.Sid));
      const auto CachedUser = UserCache.find(SidKey);
      if (CachedUser != UserCache.end()) {
        Row.User = CachedUser->second;
        CloseHandle(Token);
        CloseHandle(Process);
        return;
      }
      wchar_t Name[256]{};
      wchar_t Domain[256]{};
      DWORD NameSize = ARRAYSIZE(Name);
      DWORD DomainSize = ARRAYSIZE(Domain);
      SID_NAME_USE Use = SidTypeUnknown;
      if (LookupAccountSidW(nullptr, TokenUserInformation->User.Sid, Name,
                            &NameSize, Domain, &DomainSize, &Use)) {
        Row.User = QString::fromWCharArray(Domain) + "\\" +
                   QString::fromWCharArray(Name);
        UserCache[SidKey] = Row.User;
      }
    }
    CloseHandle(Token);
  }
  CloseHandle(Process);
}

bool IsNtQueryObjectResizeStatus(NTSTATUS Status) {
  return Status == static_cast<NTSTATUS>(0xC0000004L) ||
         Status == static_cast<NTSTATUS>(0x80000005L) ||
         Status == static_cast<NTSTATUS>(0xC0000023L);
}

bool QueryObjectInformationBuffer(HANDLE Handle, OBJECT_INFORMATION_CLASS InfoClass,
                                  std::vector<BYTE> &Buffer) {
  using NtQueryObjectFn = NTSTATUS(NTAPI *)(HANDLE, OBJECT_INFORMATION_CLASS,
                                            PVOID, ULONG, PULONG);
  static const auto QueryObject = reinterpret_cast<NtQueryObjectFn>(
      GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject"));
  if (!QueryObject || !Handle)
    return false;
  ULONG Size = 0x200;
  ULONG ReturnLength = 0;
  NTSTATUS Status = static_cast<NTSTATUS>(0xC0000001L);
  Buffer.resize(Size);
  for (int Attempt = 0; Attempt < 8; ++Attempt) {
    Status = QueryObject(Handle, InfoClass, Buffer.data(), Size, &ReturnLength);
    if (Status >= 0) {
      if (ReturnLength != 0 && ReturnLength <= Size)
        Buffer.resize(ReturnLength);
      return true;
    }
    if (!IsNtQueryObjectResizeStatus(Status))
      return false;
    const ULONG NextSize = ReturnLength > Size ? ReturnLength + 0x100 : Size * 2;
    Size = std::max<ULONG>(NextSize, 0x200);
    Buffer.resize(Size);
  }
  return false;
}

QString QueryObjectTypeName(HANDLE Handle) {
  constexpr auto KObjectTypeInformationClass = static_cast<OBJECT_INFORMATION_CLASS>(2);
  std::vector<BYTE> Buffer;
  if (!QueryObjectInformationBuffer(Handle, KObjectTypeInformationClass, Buffer) ||
      Buffer.size() < sizeof(UNICODE_STRING))
    return {};
  const auto *Type = reinterpret_cast<const UNICODE_STRING *>(Buffer.data());
  if (!Type->Buffer || Type->Length == 0)
    return {};
  return QString::fromWCharArray(Type->Buffer, Type->Length / sizeof(WCHAR));
}

QString QueryObjectName(HANDLE Handle) {
  constexpr auto KObjectNameInformationClass = static_cast<OBJECT_INFORMATION_CLASS>(1);
  std::vector<BYTE> Buffer;
  if (!QueryObjectInformationBuffer(Handle, KObjectNameInformationClass, Buffer) ||
      Buffer.size() < sizeof(UNICODE_STRING))
    return {};
  const auto *Name = reinterpret_cast<const UNICODE_STRING *>(Buffer.data());
  if (!Name->Buffer || Name->Length == 0)
    return {};
  return QString::fromWCharArray(Name->Buffer, Name->Length / sizeof(WCHAR));
}

// GUI 的 QueryUserModeHandles 是私有静态成员，这里按原样重写。
bool QueryUserModeHandles(DWORD Pid, std::vector<TaskHandleRow> &Rows,
                          DWORD &ErrorCode) {
  using NtQuerySystemInformationFn =
      NTSTATUS(NTAPI *)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
  constexpr auto KSystemExtendedHandleInformation =
      static_cast<SYSTEM_INFORMATION_CLASS>(64);
  constexpr NTSTATUS KStatusInfoLengthMismatch = static_cast<NTSTATUS>(0xC0000004L);
  static const auto QuerySystemInformation =
      reinterpret_cast<NtQuerySystemInformationFn>(GetProcAddress(
          GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
  if (!QuerySystemInformation) {
    ErrorCode = ERROR_PROC_NOT_FOUND;
    return false;
  }

  struct HandleEntry {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
  };
  struct HandleInformation {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    HandleEntry Handles[1];
  };

  ULONG Size = 1 << 20;
  std::vector<BYTE> Buffer(Size);
  NTSTATUS Status = KStatusInfoLengthMismatch;
  ULONG ReturnLength = 0;
  for (int Attempt = 0; Attempt < 8 && Status == KStatusInfoLengthMismatch; ++Attempt) {
    Status = QuerySystemInformation(KSystemExtendedHandleInformation, Buffer.data(),
                                    Size, &ReturnLength);
    if (Status == KStatusInfoLengthMismatch) {
      if (Size >= 0x40000000u) {
        ErrorCode = ERROR_NOT_ENOUGH_MEMORY;
        return false;
      }
      Size = std::max(Size * 2, ReturnLength + 0x1000u);
      Buffer.resize(Size);
    }
  }
  if (Status < 0) {
    ErrorCode = static_cast<DWORD>(::RtlNtStatusToDosError(Status));
    return false;
  }

  HANDLE Process = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
                               FALSE, Pid);
  ErrorCode = Process ? ERROR_SUCCESS : GetLastError();

  const auto *Handles = reinterpret_cast<const HandleInformation *>(Buffer.data());
  Rows.clear();
  for (ULONG_PTR Index = 0; Index < Handles->NumberOfHandles; ++Index) {
    const auto &Entry = Handles->Handles[Index];
    if (static_cast<DWORD>(Entry.UniqueProcessId) != Pid)
      continue;
    TaskHandleRow Row;
    Row.HandleValue = static_cast<uint64_t>(Entry.HandleValue);
    Row.ObjectAddress = reinterpret_cast<uint64_t>(Entry.Object);
    Row.GrantedAccess = Entry.GrantedAccess;
    Row.Attributes = Entry.HandleAttributes;
    if (Process) {
      HANDLE Duplicate = nullptr;
      if (DuplicateHandle(Process, reinterpret_cast<HANDLE>(Entry.HandleValue),
                          GetCurrentProcess(), &Duplicate, 0, FALSE,
                          DUPLICATE_SAME_ACCESS)) {
        Row.TypeName = QueryObjectTypeName(Duplicate);
        const bool QueryName =
            Row.TypeName.compare("Key", Qt::CaseInsensitive) == 0 ||
            Row.TypeName.compare("Directory", Qt::CaseInsensitive) == 0 ||
            Row.TypeName.compare("SymbolicLink", Qt::CaseInsensitive) == 0 ||
            Row.TypeName.compare("Section", Qt::CaseInsensitive) == 0 ||
            Row.TypeName.compare("Event", Qt::CaseInsensitive) == 0 ||
            Row.TypeName.compare("Mutant", Qt::CaseInsensitive) == 0 ||
            Row.TypeName.compare("Process", Qt::CaseInsensitive) == 0 ||
            Row.TypeName.compare("Thread", Qt::CaseInsensitive) == 0 ||
            Row.TypeName.compare("Desktop", Qt::CaseInsensitive) == 0 ||
            Row.TypeName.compare("WindowStation", Qt::CaseInsensitive) == 0;
        if (QueryName)
          Row.ObjectName = QueryObjectName(Duplicate);
        CloseHandle(Duplicate);
      }
    }
    Rows.push_back(std::move(Row));
  }
  if (Process)
    CloseHandle(Process);
  return true;
}

void SortProcessRows(std::vector<TaskProcessRow> &Rows) {
  std::stable_sort(Rows.begin(), Rows.end(),
                   [](const TaskProcessRow &Left, const TaskProcessRow &Right) {
                     if (Left.Hidden != Right.Hidden)
                       return Left.Hidden;
                     return Left.Pid < Right.Pid;
                   });
}

std::vector<TuiRow> FieldRows(
    const std::vector<std::pair<std::string, std::string>> &Fields) {
  std::vector<TuiRow> Rows;
  Rows.reserve(Fields.size());
  for (const auto &Field : Fields)
    Rows.push_back(TuiRow{{Field.first, Field.second}, {}});
  return Rows;
}

} // namespace

// ------------------------------------------------------------
// Task 页
// ------------------------------------------------------------

class TaskPage final : public TuiPage {
public:
  explicit TaskPage(int Index) : Index_(Index) { RegisterCommands(); }

  std::string Title() const override { return "Task"; }

  std::string Subtitle() const override {
    return "process / thread manager: enumerate, inspect, suspend, terminate";
  }

  void OnEnter() override {
    Process_.Headers = {"PID", "Name", "User", "Integrity", "PPL", "EPROCESS",
                        "Parent PID"};
    Process_.RightAlign = {true, false, false, false, false, false, true};
    Process_.MultiSelect = true;
    Thread_.Headers = {"TID", "Parent ID", "Process", "ETHREAD", "Start Address",
                       "PreviousMode", "ApcQueueable", "Priority", "State"};
    Thread_.RightAlign = {true, true, false, false, false, false, false, true, true};
    Thread_.MultiSelect = true;
    RefreshCurrentView();
  }

  void OnTick(int64_t NowMs) override {
    if (LastAutoRefreshMs_ == 0) {
      LastAutoRefreshMs_ = NowMs;
      return;
    }
    if (NowMs - LastAutoRefreshMs_ < 10000)
      return;
    LastAutoRefreshMs_ = NowMs;
    RefreshCurrentView();
  }

  TuiTable *ActiveTable() override {
    return ViewTab_ == 1 ? &Thread_ : &Process_;
  }

  std::string RenderText() override {
    if (Process_.Headers.empty())
      OnEnter();
    // 首次显示（缓存为空）时才真正枚举；否则仅用缓存重绘，避免每次 show 都刷新。
    if (ProcessRows_.empty() && ThreadRows_.empty())
      RefreshCurrentView();
    // 立即用缓存行重建当前表，保证筛选/视图切换立即可见（异步刷新随后覆盖）。
    PopulateProcessTable();
    PopulateThreadTable();
    std::string Text;
    Text += ViewTab_ == 1 ? "Process [Thread]\n" : "[Process] Thread\n";
    if (!Filter.empty())
      Text += "filter: " + Filter + '\n';
    Text += TuiTableToText(*ActiveTable(), 0);
    return Text;
  }

private:

  void RegisterCommands() {
    auto Add = [this](const char *Name, const char *Usage,
                      std::function<void(std::vector<std::string>)> Handler) {
      OwnedCommands.push_back(TuiCommand{Name, Usage, std::move(Handler)});
    };
    Add("refresh", "refresh  (reload the current view)",
        [this](std::vector<std::string>) { RefreshCurrentView(); });
    Add("view", "view [process|thread]  (switch view)", [this](std::vector<std::string> Args) {
      if (!Args.empty())
        ViewTab_ = LowerAscii(Args.front()) == "thread" ? 1 : 0;
      else
        ViewTab_ = ViewTab_ == 0 ? 1 : 0;
      SwitchView();
    });
    Add("terminate", "terminate [pid...]  (choose kill method)",
        [this](std::vector<std::string> Args) { TerminateDialog(TargetPids(Args)); });
    Add("remove-ppl", "remove-ppl [pid...]", [this](std::vector<std::string> Args) {
      for (DWORD Pid : TargetPids(Args))
        RemovePpl(Pid);
      ReportDriverResult("RemovePPL");
    });
    Add("set-ppl", "set-ppl [pid...]", [this](std::vector<std::string> Args) {
      SetPplDialog(TargetPids(Args));
    });
    Add("protect", "protect [pid...]", [this](std::vector<std::string> Args) {
      for (DWORD Pid : TargetPids(Args)) {
        ProtectProcess(Pid);
        if (G_LastAegisCoreError == ERROR_SUCCESS)
          ProtectedPids_.insert(Pid);
      }
      ReportDriverResult("Protect");
    });
    Add("unprotect", "unprotect [pid...]", [this](std::vector<std::string> Args) {
      for (DWORD Pid : TargetPids(Args)) {
        UnprotectProcess(Pid);
        if (G_LastAegisCoreError == ERROR_SUCCESS)
          ProtectedPids_.remove(Pid);
      }
      ReportDriverResult("UnProtect");
    });
    Add("inject-protect", "inject-protect [pid...]",
        [this](std::vector<std::string> Args) {
          for (DWORD Pid : TargetPids(Args))
            AddInjectionProtectKernel(Pid);
          ReportDriverResult("InjectProtect");
        });
    Add("inject-unprotect", "inject-unprotect [pid...]",
        [this](std::vector<std::string> Args) {
          for (DWORD Pid : TargetPids(Args))
            RemoveInjectionProtectKernel(Pid);
          ReportDriverResult("InjectUnprotect");
        });
    Add("set-critical", "set-critical [pid...]", [this](std::vector<std::string> Args) {
      const std::vector<DWORD> Pids = TargetPids(Args);
      if (Pids.empty())
        return;
      QStringList Names;
      const size_t NameCount = std::min<size_t>(Pids.size(), 4);
      for (size_t Index = 0; Index < NameCount; ++Index) {
        if (const TaskProcessRow *Row = FindProcess(Pids[Index]))
          Names << QString("%1 (PID %2)").arg(Row->Name).arg(Pids[Index]);
      }
      if (Pids.size() > NameCount)
        Names << QString("... and %1 more").arg(Pids.size() - NameCount);
      const QString Text =
          QString("Mark %1 process(es) critical? Terminating them may crash "
                  "Windows.\n%2")
              .arg(Pids.size())
              .arg(Names.join("\n"));
      ConfirmDialog(*Dialogs, "SetCritical", Utf8(Text), [this, Pids] {
        for (DWORD Pid : Pids)
          SetCritical(Pid);
        ReportDriverResult("SetCritical");
      }, "Yes", "No");
    });
    Add("unset-critical", "unset-critical [pid...]",
        [this](std::vector<std::string> Args) {
          for (DWORD Pid : TargetPids(Args))
            RemoveCritical(Pid);
          ReportDriverResult("UnsetCritical");
        });
    Add("integrity", "integrity [pid]  (choose integrity level)",
        [this](std::vector<std::string> Args) { IntegrityDialog(FirstPid(Args)); });
    Add("apc-disable", "apc-disable [pid...]", [this](std::vector<std::string> Args) {
      for (DWORD Pid : TargetPids(Args))
        DisableApc(Pid);
      ReportDriverResult("DisableAPC");
    });
    Add("apc-enable", "apc-enable [pid...]", [this](std::vector<std::string> Args) {
      for (DWORD Pid : TargetPids(Args))
        EnableApc(Pid);
      ReportDriverResult("EnableAPC");
    });
    Add("apc-signal", "apc-signal [pid]  (NoOp / Terminate)",
        [this](std::vector<std::string> Args) { ApcSignalDialog(FirstPid(Args)); });
    Add("suspend", "suspend [pid...]", [this](std::vector<std::string> Args) {
      const std::vector<DWORD> Pids = TargetPids(Args);
      int Count = 0;
      for (DWORD Pid : Pids)
        if (Suspend(Pid))
          ++Count;
      Notify(std::to_string(Count) + " of " + std::to_string(Pids.size()) +
                 " process(es) suspended.",
             NoticeKind::Success);
    });
    Add("resume", "resume [pid...]", [this](std::vector<std::string> Args) {
      const std::vector<DWORD> Pids = TargetPids(Args);
      int Count = 0;
      for (DWORD Pid : Pids)
        if (Resume(Pid))
          ++Count;
      Notify(std::to_string(Count) + " of " + std::to_string(Pids.size()) +
                 " process(es) resumed.",
             NoticeKind::Success);
    });
    Add("set-token", "set-token [pid]  (SYSTEM / TRUSTEDINSTALLER / Custom)",
        [this](std::vector<std::string> Args) { TokenDialog(FirstPid(Args)); });
    Add("disguise", "disguise [pid]", [this](std::vector<std::string> Args) {
      DisguiseDialog(FirstPid(Args));
    });
    Add("hide", "hide [pid...]", [this](std::vector<std::string> Args) {
      HideSelection(TargetPids(Args), 0);
    });
    Add("hide-cid", "hide-cid [pid...]  (cannot be unhidden)",
        [this](std::vector<std::string> Args) {
          HideSelection(TargetPids(Args), 1);
        });
    Add("unhide", "unhide [pid...]", [this](std::vector<std::string> Args) {
      HideSelection(TargetPids(Args), 2);
    });
    Add("block-image", "block-image [pid...]", [this](std::vector<std::string> Args) {
      for (DWORD Pid : TargetPids(Args)) {
        const TaskProcessRow *Row = FindProcess(Pid);
        if (!Row)
          continue;
        BlockImageRule(*Row);
      }
    });
    Add("unblock-image", "unblock-image [name|pid...]",
        [this](std::vector<std::string> Args) { UnblockImage(Args); });
    Add("run", "run  (launch an executable as SYSTEM / TrustedInstaller)",
        [this](std::vector<std::string>) { LaunchAsDialog(); });
    Add("block-rules", "block-rules  (list / add / remove create-block rules)",
        [this](std::vector<std::string>) { ShowBlockRules(); });
    Add("inspect", "inspect <pid> [summary|token|threads|handles|modules|memory|"
                   "eprocess|mitigations|peb]",
        [this](std::vector<std::string> Args) {
          DWORD Pid = 0;
          std::string Tab = "summary";
          if (!Args.empty() && ParseUInt32(Args.front(), Pid))
            Args.erase(Args.begin());
          else
            Pid = FirstPid({});
          if (!Args.empty())
            Tab = LowerAscii(Args.front());
          if (Pid != 0)
            ShowInspector(Pid, Tab);
        });
    Add("modules", "modules <pid>  (module list)", [this](std::vector<std::string> Args) {
      ShowModuleList(FirstPid(Args));
    });
    Add("peb", "peb <pid>  (PEB details)", [this](std::vector<std::string> Args) {
      ShowPeb(FirstPid(Args));
    });
    Add("t-suspend", "t-suspend <tid...>", [this](std::vector<std::string> Args) {
      for (DWORD Tid : TargetTids(Args)) {
        if (SuspendThreadKernel(Tid))
          Notify("Thread " + std::to_string(Tid) + " suspended.", NoticeKind::Success);
        else
          Notify("Suspend failed (error " +
                     std::to_string(G_LastAegisCoreError) + ").",
                 NoticeKind::Error);
      }
      RefreshThreads();
    });
    Add("t-resume", "t-resume <tid...>", [this](std::vector<std::string> Args) {
      for (DWORD Tid : TargetTids(Args)) {
        if (ResumeThreadKernel(Tid))
          Notify("Thread " + std::to_string(Tid) + " resumed.", NoticeKind::Success);
        else
          Notify("Resume failed (error " + std::to_string(G_LastAegisCoreError) +
                     ").",
                 NoticeKind::Error);
      }
      RefreshThreads();
    });
    Add("t-prevmode", "t-prevmode <tid...>  (KernelMode / UserMode)",
        [this](std::vector<std::string> Args) {
          ThreadPreviousModeDialog(TargetTids(Args));
        });
    Add("p-prevmode", "p-prevmode <pid>  (KernelMode / UserMode)",
        [this](std::vector<std::string> Args) {
          ProcessPreviousModeDialog(FirstPid(Args));
        });
    Add("t-apc", "t-apc <tid...>  (Enable / Disable ApcQueueable)",
        [this](std::vector<std::string> Args) {
          ThreadApcQueueableDialog(TargetTids(Args));
        });
    Add("t-terminate", "t-terminate <tid...>", [this](std::vector<std::string> Args) {
      for (DWORD Tid : TargetTids(Args)) {
        const TaskThreadRow *Row = FindThread(Tid);
        if (!Row)
          continue;
        if (KillThread(Tid, Row->ProcessId))
          Notify("Thread " + std::to_string(Tid) + " terminated.",
                 NoticeKind::Success);
        else
          Notify("Terminate failed (error " + std::to_string(G_LastAegisCoreError) +
                     ").",
                 NoticeKind::Error);
      }
      RefreshThreads();
    });
    Add("t-find", "t-find <pid>  (switch to the process view)", [this](std::vector<std::string> Args) {
      FindThreadInProcess(FirstPid(Args));
    });
    Add("copy", "copy  (copy the selected row as TSV)",
        [this](std::vector<std::string>) {
          if (ViewTab_ == 1) {
            const TuiRow *Row = Thread_.Current();
            if (!Row)
              return;
            Thread_.CopyCurrentToClipboard();
            Notify("Thread information copied.", NoticeKind::Success);
            (void)Row;
          } else {
            if (!Process_.Current())
              return;
            Process_.CopyCurrentToClipboard();
            Notify("Copied 1 row(s).", NoticeKind::Success);
          }
        });
  }

  // ---- 选择 / 目标解析 ----

  std::vector<DWORD> TargetPids(const std::vector<std::string> &Args) {
    std::vector<DWORD> Pids;
    for (const std::string &Arg : Args) {
      DWORD Pid = 0;
      if (ParseUInt32(Arg, Pid) && Pid != 0)
        Pids.push_back(Pid);
    }
    if (!Pids.empty())
      return Pids;
    for (int RowIndex : Process_.Marked) {
      if (RowIndex >= 0 && RowIndex < static_cast<int>(ProcessRows_.size())) {
        const DWORD Pid = ProcessRows_[static_cast<size_t>(RowIndex)].Pid;
        if (Pid != 0)
          Pids.push_back(Pid);
      }
    }
    if (!Pids.empty())
      return Pids;
    if (const TuiRow *Row = Process_.Current()) {
      DWORD Pid = 0;
      if (!Row->Cells.empty() && ParseUInt32(Row->Cells[0], Pid) && Pid != 0)
        Pids.push_back(Pid);
    }
    if (Pids.empty())
      Notify("Select a process first.", NoticeKind::Warning);
    return Pids;
  }

  DWORD FirstPid(const std::vector<std::string> &Args) {
    for (const std::string &Arg : Args) {
      DWORD Pid = 0;
      if (ParseUInt32(Arg, Pid) && Pid != 0)
        return Pid;
    }
    const std::vector<DWORD> Pids = TargetPids({});
    return Pids.empty() ? 0 : Pids.front();
  }

  std::vector<DWORD> TargetTids(const std::vector<std::string> &Args) {
    std::vector<DWORD> Tids;
    for (const std::string &Arg : Args) {
      DWORD Tid = 0;
      if (ParseUInt32(Arg, Tid) && Tid != 0)
        Tids.push_back(Tid);
    }
    if (!Tids.empty())
      return Tids;
    for (int RowIndex : Thread_.Marked) {
      if (RowIndex >= 0 && RowIndex < static_cast<int>(ThreadRows_.size()))
        Tids.push_back(ThreadRows_[static_cast<size_t>(RowIndex)].Tid);
    }
    if (!Tids.empty())
      return Tids;
    if (const TuiRow *Row = Thread_.Current()) {
      DWORD Tid = 0;
      if (!Row->Cells.empty() && ParseUInt32(Row->Cells[0], Tid) && Tid != 0)
        Tids.push_back(Tid);
    }
    if (Tids.empty())
      Notify("Select a thread first.", NoticeKind::Warning);
    return Tids;
  }

  const TaskProcessRow *FindProcess(DWORD Pid) const {
    const auto Match =
        std::find_if(ProcessRows_.begin(), ProcessRows_.end(),
                     [Pid](const TaskProcessRow &Row) { return Row.Pid == Pid; });
    return Match == ProcessRows_.end() ? nullptr : &*Match;
  }

  const TaskThreadRow *FindThread(DWORD Tid) const {
    const auto Match =
        std::find_if(ThreadRows_.begin(), ThreadRows_.end(),
                     [Tid](const TaskThreadRow &Row) { return Row.Tid == Tid; });
    return Match == ThreadRows_.end() ? nullptr : &*Match;
  }

  // ---- 刷新 ----

  void RefreshCurrentView() {
    if (ViewTab_ == 1)
      RefreshThreads();
    else
      RefreshProcesses();
  }

  void RefreshProcesses() {
    if (Refreshing_.exchange(true)) {
      Notify("Already refreshing.", NoticeKind::Info);
      return;
    }
    SetStatus("Refreshing processes...");
    const QSet<DWORD> ProtectedSnapshot = ProtectedPids_;
    TuiAsyncVoid(
        [this, ProtectedSnapshot] {
          SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST);
          std::vector<TaskProcessRow> Result;
          std::vector<PROCESS_ENUM_ENTRY> DriverEntries;
          std::map<QByteArray, QString> UserCache;
          std::vector<WCHAR> ImagePath(32768);
          const bool UsedDriver =
              EnumProcessEntries(DriverEntries) && !DriverEntries.empty();
          if (UsedDriver) {
            for (const PROCESS_ENUM_ENTRY &Entry : DriverEntries) {
              TaskProcessRow Row;
              Row.Pid = Entry.ProcessId;
              Row.ParentPid = Entry.ParentPid;
              Row.ThreadCount = Entry.ThreadCount;
              Row.SessionId = Entry.SessionId;
              DWORD UserModeSessionId = 0;
              if (ProcessIdToSessionId(Row.Pid, &UserModeSessionId))
                Row.SessionId = UserModeSessionId;
              Row.Name = Entry.ImageName[0]
                             ? QString::fromWCharArray(Entry.ImageName)
                             : "Unknown";
              Row.DriverData = true;
              Row.Ppl = Entry.IsPplProtected != FALSE;
              Row.PplRaw = Entry.PplRawLevel;
              Row.Critical = Entry.IsCritical != FALSE;
              Row.Hidden = Entry.IsHidden != FALSE;
              QueryProcessDetails(Row.Pid, Row, UserCache);
              HANDLE Process =
                  OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Row.Pid);
              if (Process) {
                DWORD ImagePathLength = static_cast<DWORD>(ImagePath.size());
                if (QueryFullProcessImageNameW(Process, 0, ImagePath.data(),
                                               &ImagePathLength)) {
                  const QString FullPath =
                      QString::fromWCharArray(ImagePath.data(), ImagePathLength);
                  const QString FullName = QFileInfo(FullPath).fileName();
                  if (!FullName.isEmpty())
                    Row.Name = FullName;
                }
                CloseHandle(Process);
              }
              Row.Eprocess = Entry.ObjectAddress;
              Row.EprocessText = FormatTaskPointer(Row.Eprocess);
              Result.push_back(std::move(Row));
            }
          } else {
            HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (Snapshot != INVALID_HANDLE_VALUE) {
              PROCESSENTRY32W Entry{sizeof(Entry)};
              if (Process32FirstW(Snapshot, &Entry)) {
                do {
                  TaskProcessRow Row;
                  Row.Pid = Entry.th32ProcessID;
                  Row.ParentPid = Entry.th32ParentProcessID;
                  Row.ThreadCount = Entry.cntThreads;
                  Row.Name = QString::fromWCharArray(Entry.szExeFile);
                  ProcessIdToSessionId(Row.Pid, &Row.SessionId);
                  QueryProcessDetails(Row.Pid, Row, UserCache);
                  Row.EprocessText = "-";
                  Result.push_back(std::move(Row));
                } while (Process32NextW(Snapshot, &Entry));
              }
              CloseHandle(Snapshot);
            }
          }
          for (TaskProcessRow &Row : Result) {
            if (ProtectedSnapshot.contains(Row.Pid))
              Row.Protected = true;
          }
          TuiPost([this, Result = std::move(Result), UsedDriver]() mutable {
            // 隐藏进程不在驱动枚举结果里：按存活状态决定保留还是丢弃。
            for (auto Retained = Retained_.begin(); Retained != Retained_.end();) {
              const DWORD Pid = Retained->first;
              auto Match = std::find_if(
                  Result.begin(), Result.end(),
                  [Pid](const TaskProcessRow &Row) { return Row.Pid == Pid; });
              if (Match != Result.end()) {
                if (Retained->second.Hidden) {
                  Match->Hidden = true;
                  ++Retained;
                } else {
                  Retained = Retained_.erase(Retained);
                }
                continue;
              }
              bool ProcessExited = false;
              BOOLEAN Alive = FALSE;
              if (QueryProcessAliveKernel(Pid, &Alive)) {
                ProcessExited = (Alive == FALSE);
              } else {
                HANDLE Process = OpenProcess(SYNCHRONIZE, FALSE, Pid);
                if (Process) {
                  ProcessExited =
                      WaitForSingleObject(Process, 0) == WAIT_OBJECT_0;
                  CloseHandle(Process);
                }
              }
              if (ProcessExited) {
                Retained = Retained_.erase(Retained);
                continue;
              }
              Result.push_back(Retained->second);
              ++Retained;
            }
            SortProcessRows(Result);
            ProcessRows_ = std::move(Result);
            Refreshing_ = false;
            PopulateProcessTable();
            SetStatus(std::to_string(ProcessRows_.size()) + " processes  |  " +
                      (UsedDriver ? "Driver enumeration" : "Toolhelp fallback"));
          });
        },
        [] {});
  }

  void RefreshThreads() {
    if (ThreadsRefreshing_.exchange(true)) {
      Notify("Already refreshing.", NoticeKind::Info);
      return;
    }
    SetStatus("Refreshing threads...");
    TuiAsyncVoid(
        [this] {
          SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST);
          std::vector<TaskThreadRow> Result;
          ULONG Cursor = 0;
          auto Output = std::make_unique<THREAD_ENUM_OUTPUT>();
          for (int PageIndex = 0; PageIndex < 64; ++PageIndex) {
            ZeroMemory(Output.get(), sizeof(THREAD_ENUM_OUTPUT));
            if (!EnumerateThreadsAll(Output.get(), Cursor))
              break;
            for (ULONG Index = 0; Index < Output->Count; ++Index) {
              const THREAD_ENUM_ENTRY &Entry = Output->Entries[Index];
              TaskThreadRow Row;
              Row.Tid = Entry.ThreadId;
              Row.ProcessId = Entry.ProcessId;
              Row.PreviousMode = static_cast<UCHAR>(Entry.PreviousMode);
              Row.ApcQueueable = Entry.ApcQueueable;
              Row.PrevModeStatus = Entry.PrevModeStatus;
              Row.ApcStatus = Entry.ApcStatus;
              Row.Ethread = Entry.Ethread;
              Row.StartAddress = Entry.StartAddress;
              Row.Priority = Entry.Priority;
              Row.State = Entry.State;
              Result.push_back(std::move(Row));
            }
            if (Output->NextCursor == 0 || Output->Count == 0)
              break;
            Cursor = Output->NextCursor;
          }
          TuiPost([this, Result = std::move(Result)]() mutable {
            ThreadRows_ = std::move(Result);
            ThreadsRefreshing_ = false;
            PopulateThreadTable();
            SetStatus(std::to_string(ThreadRows_.size()) + " threads");
          });
        },
        [] {});
  }

  void PopulateProcessTable() {
    std::vector<TuiRow> Rows;
    Rows.reserve(ProcessRows_.size());
    for (const TaskProcessRow &Process : ProcessRows_) {
      TuiRow Row;
      Row.Cells = {
          std::to_string(Process.Pid),
          Utf8(Process.Name),
          Utf8(Process.User),
          Utf8(IntegrityName(Process.IntegrityRid)),
          Utf8(Process.Ppl ? QString("Yes (0x%1)")
                                 .arg(Process.PplRaw, 2, 16, QLatin1Char('0'))
                           : QString("No")),
          Utf8(Process.EprocessText.isEmpty() ? FormatTaskPointer(Process.Eprocess)
                                              : Process.EprocessText),
          std::to_string(Process.ParentPid),
      };
      Row.Detail = Row.Cells[1] + "  |  PID " + Row.Cells[0];
      Rows.push_back(std::move(Row));
    }
    Process_.Headers = {"PID", "Name", "User", "Integrity", "PPL", "EPROCESS",
                        "Parent PID"};
    Process_.RightAlign = {true, false, false, false, false, false, true};
    Process_.Rows = std::move(Rows);
    Process_.Filter = Filter;
    Process_.Rebuild();
  }

  void PopulateThreadTable() {
    std::map<DWORD, QString> PidNames;
    for (const TaskProcessRow &Process : ProcessRows_)
      PidNames[Process.Pid] = Process.Name;
    std::vector<TuiRow> Rows;
    Rows.reserve(ThreadRows_.size());
    for (TaskThreadRow &Row : ThreadRows_) {
      if (Row.ProcessId == 0) {
        Row.ProcessName = "System Idle";
      } else {
        const auto Match = PidNames.find(Row.ProcessId);
        Row.ProcessName = (Match != PidNames.end() && !Match->second.isEmpty())
                              ? Utf8(Match->second)
                              : std::string();
      }
      TuiRow TableRow;
      TableRow.Cells = {
          std::to_string(Row.Tid),
          std::to_string(Row.ProcessId),
          Row.ProcessName,
          Utf8(QString("0x%1")
                   .arg(static_cast<qulonglong>(Row.Ethread), 0, 16)
                   .toUpper()),
          Utf8(QString("0x%1")
                   .arg(static_cast<qulonglong>(Row.StartAddress), 0, 16)
                   .toUpper()),
          Utf8(FormatPreviousMode(Row)),
          Utf8(FormatApcQueueable(Row)),
          std::to_string(Row.Priority),
          std::to_string(Row.State),
      };
      TableRow.Detail = TableRow.Cells[2] + "  |  TID " + TableRow.Cells[0];
      Rows.push_back(std::move(TableRow));
    }
    Thread_.Headers = {"TID", "Parent ID", "Process", "ETHREAD", "Start Address",
                       "PreviousMode", "ApcQueueable", "Priority", "State"};
    Thread_.RightAlign = {true, true, false, false, false, false, false, true, true};
    Thread_.Rows = std::move(Rows);
    Thread_.Filter = Filter;
    Thread_.Rebuild();
  }

  void SwitchView() {
    PopulateProcessTable();
    PopulateThreadTable();
    if (ViewTab_ == 1 && ThreadRows_.empty())
      RefreshThreads();
    else
      SetStatus(ViewTab_ == 1 ? "Thread view" : "Process view");
  }

  // ---- 操作与对话框 ----

  void ReportDriverResult(const QString &Action) {
    if (G_LastAegisCoreError != ERROR_SUCCESS) {
      Notify(Utf8(QString("Driver operation failed (error %1).")
                      .arg(G_LastAegisCoreError)),
             NoticeKind::Error);
      return;
    }
    Notify("Operation completed successfully.", NoticeKind::Success);
    (void)Action;
    RefreshCurrentView();
  }

  void TerminateDialog(std::vector<DWORD> Pids) {
    if (Pids.empty())
      return;
    TuiDialog Dialog;
    Dialog.Title = "Terminate";
    Dialog.Body = Utf8(QString("Select how to terminate %1 selected process(es). "
                               "This may cause data loss.")
                           .arg(Pids.size()));
    TuiField Choice;
    Choice.Label = "Operation";
    Choice.Kind = TuiFieldKind::Combo;
    Choice.Choices = {"R0ZwTerminateProcess", "R0TerminateProcessThreads",
                      "R0WriteZeroMemoryToProcess", "R3PatchThreadRun",
                      "R3NtTerminate", "R3KillProcessForce", "R3RunInjectProc"};
    Choice.Choice = 0;
    Dialog.Fields.push_back(Choice);
    Dialog.PrimaryLabel = "Execute";
    Dialog.OnSubmit = [this, Pids](TuiDialog &Submitted) {
      const int Index = Submitted.Fields.empty() ? 0 : Submitted.Fields[0].Choice;
      TuiAsyncVoid(
          [this, Pids, Index] {
            int SuccessCount = 0;
            int PartialCount = 0;
            uint64_t EnumeratedThreads = 0;
            uint64_t TerminatedThreads = 0;
            uint64_t FailedThreads = 0;
            for (const DWORD Pid : Pids) {
              bool Success = false;
              switch (Index) {
              case 0:
                KillProcess(Pid);
                Success = G_LastAegisCoreError == ERROR_SUCCESS;
                break;
              case 1: {
                TERMINATE_PROCESS_THREADS_OUTPUT Result = {};
                Success = KillProcessByThreads(Pid, Result) != FALSE;
                EnumeratedThreads += Result.EnumeratedCount;
                TerminatedThreads += Result.TerminatedCount;
                FailedThreads += Result.FailedCount;
                if (!Success && Result.TerminatedCount != 0)
                  ++PartialCount;
                break;
              }
              case 2:
                ProcessWriteZeroMemory(Pid);
                Success = true;
                break;
              case 3:
                PatchThreadRun(Pid);
                Success = true;
                break;
              case 4:
                Success = NtTerminate(Pid);
                break;
              case 5:
                Success = KillProcessForce(Pid);
                break;
              case 6:
                Success = RunInjectProc(Pid);
                break;
              default:
                return;
              }
              if (Success)
                ++SuccessCount;
            }
            const int FinalSuccess = SuccessCount;
            const int FinalPartial = PartialCount;
            const uint64_t FinalEnumerated = EnumeratedThreads;
            const uint64_t FinalTerminated = TerminatedThreads;
            const uint64_t FinalFailed = FailedThreads;
            TuiPost([this, Index, Pids, FinalSuccess, FinalPartial,
                     FinalEnumerated, FinalTerminated, FinalFailed] {
              if (Index == 1) {
                const int FailedProcessCount =
                    static_cast<int>(Pids.size()) - FinalSuccess - FinalPartial;
                const QString Summary =
                    QString("Processes: %1 complete, %2 partial, %3 failed. "
                            "Threads: %4/%5 terminated, %6 failed.")
                        .arg(FinalSuccess)
                        .arg(FinalPartial)
                        .arg(FailedProcessCount)
                        .arg(FinalTerminated)
                        .arg(FinalEnumerated)
                        .arg(FinalFailed);
                if (FinalSuccess == 0 && FinalPartial == 0)
                  Notify(Utf8(Summary), NoticeKind::Error);
                else if (FinalPartial != 0 || FailedProcessCount != 0)
                  Notify(Utf8(Summary), NoticeKind::Warning);
                else
                  Notify(Utf8(Summary), NoticeKind::Success);
                RefreshProcesses();
                return;
              }
              if (FinalSuccess == 0)
                Notify("Unable to terminate the selected processes.",
                       NoticeKind::Error);
              else
                Notify(std::to_string(FinalSuccess) + " of " +
                           std::to_string(Pids.size()) + " process(es) processed.",
                       NoticeKind::Success);
              RefreshProcesses();
            });
          },
          [] {});
    };
    Dialogs->Push(std::move(Dialog));
  }

  void SetPplDialog(std::vector<DWORD> Pids) {
    if (Pids.empty())
      return;
    TuiDialog Dialog;
    Dialog.Title = "SetPPL";
    Dialog.Body = Utf8(QString("Configure protected process light settings for "
                               "%1 selected process(es).")
                           .arg(Pids.size()));
    TuiField Type;
    Type.Label = "Protection type";
    Type.Kind = TuiFieldKind::Combo;
    Type.Choices = {"None", "ProtectedLight", "Protected"};
    TuiField Signer;
    Signer.Label = "Signer";
    Signer.Kind = TuiFieldKind::Combo;
    Signer.Choices = {"None", "Authenticode", "CodeGen", "Antimalware", "Lsa",
                      "Windows", "WinTcb", "WinSystem", "App"};
    TuiField Audit;
    Audit.Label = "Audit";
    Audit.Kind = TuiFieldKind::Combo;
    Audit.Choices = {"Off", "On"};
    Dialog.Fields = {Type, Signer, Audit};
    Dialog.PrimaryLabel = "Apply";
    Dialog.OnSubmit = [this, Pids](TuiDialog &Submitted) {
      const int TypeIndex = Submitted.Fields[0].Choice;
      const int SignerIndex = Submitted.Fields[1].Choice;
      const bool AuditOn = Submitted.Fields[2].Choice == 1;
      for (DWORD Pid : Pids)
        SetPpl(Pid, static_cast<UCHAR>(TypeIndex), static_cast<UCHAR>(SignerIndex),
               AuditOn);
      ReportDriverResult("SetPPL");
    };
    Dialogs->Push(std::move(Dialog));
  }

  void IntegrityDialog(DWORD Pid) {
    if (Pid == 0)
      return;
    TuiDialog Dialog;
    Dialog.Title = "Set Integrity";
    Dialog.Body = Utf8(QString("Select the integrity level for PID %1.").arg(Pid));
    TuiField Choice;
    Choice.Label = "Integrity level";
    Choice.Kind = TuiFieldKind::Combo;
    Choice.Choices = {"Untrusted", "Low", "Medium", "High", "System", "Protected"};
    Dialog.Fields.push_back(Choice);
    Dialog.OnSubmit = [this, Pid](TuiDialog &Submitted) {
      static const std::array<const wchar_t *, 6> Levels{
          L"S-1-16-0",     L"S-1-16-4096",  L"S-1-16-8192",
          L"S-1-16-12288", L"S-1-16-16384", L"S-1-16-20480"};
      const int Index = Submitted.Fields.empty() ? 0 : Submitted.Fields[0].Choice;
      if (Index < 0 || Index >= static_cast<int>(Levels.size()))
        return;
      if (!SetIntegrity(Pid, Levels[Index]))
        Notify("SetTokenInformation failed.", NoticeKind::Error);
      else
        Notify("Integrity level updated.", NoticeKind::Success);
      RefreshProcesses();
    };
    Dialogs->Push(std::move(Dialog));
  }

  void ApcSignalDialog(DWORD Pid) {
    if (Pid == 0)
      return;
    TuiDialog Dialog;
    Dialog.Title = "SendAPCSignal";
    Dialog.Body = Utf8(QString("Select the APC signal for PID %1.").arg(Pid));
    TuiField Choice;
    Choice.Label = "APC signal";
    Choice.Kind = TuiFieldKind::Combo;
    Choice.Choices = {"NoOp", "Terminate"};
    Dialog.Fields.push_back(Choice);
    Dialog.PrimaryLabel = "Send";
    Dialog.OnSubmit = [this, Pid](TuiDialog &Submitted) {
      static const std::array<ULONG, 2> Actions{APC_ACTION_NOOP,
                                                APC_ACTION_TERMINATE};
      const int Index = Submitted.Fields.empty() ? 0 : Submitted.Fields[0].Choice;
      if (Index < 0 || Index >= static_cast<int>(Actions.size()))
        return;
      QueueApc(Pid, Actions[Index]);
      ReportDriverResult("APC");
    };
    Dialogs->Push(std::move(Dialog));
  }

  void TokenDialog(DWORD Pid) {
    if (Pid == 0)
      return;
    TuiDialog Dialog;
    Dialog.Title = "SetToken";
    Dialog.Body = Utf8(QString("Apply a token to PID %1.").arg(Pid));
    TuiField Mode;
    Mode.Label = "Source token";
    Mode.Kind = TuiFieldKind::Combo;
    Mode.Choices = {"SYSTEM", "TRUSTEDINSTALLER", "Custom"};
    TuiField SourcePid;
    SourcePid.Label = "Custom source PID";
    SourcePid.Placeholder = "Enter source PID";
    SourcePid.Hint = "Only used when Source token is Custom.";
    Dialog.Fields = {Mode, SourcePid};
    Dialog.PrimaryLabel = "Apply";
    Dialog.OnSubmit = [this, Pid](TuiDialog &Submitted) {
      const std::string Choice = Submitted.Fields[0].Choices[
          static_cast<size_t>(std::clamp(Submitted.Fields[0].Choice, 0,
                                         static_cast<int>(Submitted.Fields[0].Choices.size()) - 1))];
      bool Success = false;
      QString SuccessText;
      if (StartsWithCi(Choice, "Custom")) {
        DWORD SourcePid = 0;
        if (!ParseUInt32(Submitted.Fields[1].Value, SourcePid) || SourcePid == 0) {
          Notify("Enter a valid source PID.", NoticeKind::Warning);
          return;
        }
        Success = SetToken(SourcePid, Pid);
        SuccessText = QString("Custom token from PID %1 applied.").arg(SourcePid);
      } else {
        const bool System = StartsWithCi(Choice, "SYSTEM");
        const ULONG AccountType =
            System ? ACCOUNT_TYPE_SYSTEM : ACCOUNT_TYPE_TRUSTEDINSTALLER;
        Success = SetTokenAs(AccountType, Pid);
        SuccessText = System ? QString("SYSTEM token applied.")
                             : QString("TrustedInstaller token applied.");
      }
      if (!Success) {
        Notify(Utf8(DescribeSetTokenError(G_LastAegisCoreError)), NoticeKind::Error);
        return;
      }
      Notify(Utf8(SuccessText), NoticeKind::Success);
      RefreshProcesses();
    };
    Dialogs->Push(std::move(Dialog));
  }

  void DisguiseDialog(DWORD Pid) {
    if (Pid == 0)
      return;
    TuiDialog Dialog;
    Dialog.Title = "Process Disguise";
    Dialog.Body = Utf8(QString("Disguise PID %1.").arg(Pid));
    TuiField Mode;
    Mode.Label = "Disguise mode";
    Mode.Kind = TuiFieldKind::Combo;
    Mode.Choices = {"CurrentProcess", "Custom"};
    TuiField Rename;
    Rename.Label = "Rename window titles";
    Rename.Kind = TuiFieldKind::Check;
    Rename.Checked = true;
    TuiField SourcePid;
    SourcePid.Label = "Existing PID";
    SourcePid.Placeholder = "Enter an existing PID";
    TuiField ImagePath;
    ImagePath.Label = "ImagePath";
    ImagePath.Placeholder = "C:\\Windows\\System32\\svchost.exe";
    TuiField FakePid;
    FakePid.Label = "PID";
    FakePid.Value = std::to_string(Pid);
    FakePid.Placeholder = "Target PID to disguise";
    TuiField ParentPid;
    ParentPid.Label = "ParentPID";
    ParentPid.Placeholder = "Fake parent PID";
    Dialog.Fields = {Mode, Rename, SourcePid, ImagePath, FakePid, ParentPid};
    Dialog.PrimaryLabel = "Apply";
    Dialog.OnSubmit = [this, Pid](TuiDialog &Submitted) {
      const bool IsCustom = Submitted.Fields[0].Choice == 1;
      const bool RenameTitles = Submitted.Fields[1].Checked;
      QString BaseName;
      PROCESS_DISGUISE_ENTRY Entry{};
      Entry.TargetPid = Pid;
      if (IsCustom) {
        DWORD FakePidValue = 0;
        DWORD FakeParentPidValue = 0;
        if (!ParseUInt32(Submitted.Fields[4].Value, FakePidValue) ||
            FakePidValue == 0) {
          Notify("Enter a valid target PID.", NoticeKind::Warning);
          return;
        }
        if (!ParseUInt32(Submitted.Fields[5].Value, FakeParentPidValue) ||
            FakeParentPidValue == 0) {
          Notify("Enter a valid parent PID.", NoticeKind::Warning);
          return;
        }
        const QString Image = QString::fromStdString(TrimAscii(Submitted.Fields[3].Value));
        if (Image.isEmpty() || Image.length() >= 260) {
          Notify("Enter a valid image path.", NoticeKind::Warning);
          return;
        }
        Entry.Mode = PROCESS_DISGUISE_MODE_CUSTOM;
        Entry.FakePid = FakePidValue;
        Entry.FakeParentPid = FakeParentPidValue;
        Image.toWCharArray(Entry.FakeImagePath);
        Entry.FakeImagePath[Image.length()] = L'\0';
        const int NameStart = std::max(Image.lastIndexOf('\\'),
                                       Image.lastIndexOf('/')) + 1;
        BaseName = Image.mid(NameStart);
      } else {
        DWORD SourcePidValue = 0;
        if (!ParseUInt32(Submitted.Fields[2].Value, SourcePidValue) ||
            SourcePidValue == 0) {
          Notify("Enter a valid source PID.", NoticeKind::Warning);
          return;
        }
        const TaskProcessRow *Source = FindProcess(SourcePidValue);
        if (!Source) {
          Notify("PID " + std::to_string(SourcePidValue) + " does not exist.",
                 NoticeKind::Warning);
          return;
        }
        Entry.Mode = PROCESS_DISGUISE_MODE_CURRENT;
        Entry.SourcePid = SourcePidValue;
        BaseName = Source->Name;
      }
      if (!ApplyProcessDisguise(Entry)) {
        Notify(Utf8(QString("Driver operation failed (error %1).")
                        .arg(G_LastAegisCoreError)),
               NoticeKind::Error);
        return;
      }
      int RenamedCount = 0;
      if (RenameTitles && !BaseName.isEmpty()) {
        struct RenameContext {
          DWORD TargetPid;
          std::wstring Title;
          int Count;
        };
        RenameContext Context{Pid, BaseName.toStdWString(), 0};
        EnumWindows(
            [](HWND Hwnd, LPARAM LParam) -> BOOL {
              auto *Ctx = reinterpret_cast<RenameContext *>(LParam);
              DWORD WindowPid = 0;
              GetWindowThreadProcessId(Hwnd, &WindowPid);
              if (WindowPid != Ctx->TargetPid || !IsWindowVisible(Hwnd))
                return TRUE;
              if (SetWindowTextW(Hwnd, Ctx->Title.c_str()))
                ++Ctx->Count;
              return TRUE;
            },
            reinterpret_cast<LPARAM>(&Context));
        RenamedCount = Context.Count;
      }
      Notify(Utf8(RenameTitles
                      ? QString("Disguise applied. %1 window(s) renamed.")
                            .arg(RenamedCount)
                      : QString("Disguise applied successfully.")),
             NoticeKind::Success);
    };
    Dialogs->Push(std::move(Dialog));
  }

  void HideSelection(std::vector<DWORD> Pids, int Mode) {
    bool Changed = false;
    for (DWORD Pid : Pids) {
      const TaskProcessRow *Current = FindProcess(Pid);
      const std::optional<TaskProcessRow> Cached =
          Current ? std::optional<TaskProcessRow>(*Current) : std::nullopt;
      if (Mode == 0)
        HideProcess(Pid);
      else if (Mode == 1)
        HideProcessCid(Pid);
      else
        UnhideProcess(Pid);
      if (G_LastAegisCoreError != ERROR_SUCCESS || !Cached)
        continue;
      TaskProcessRow Retained = *Cached;
      Retained.Hidden = Mode != 2;
      Retained_.insert_or_assign(Pid, Retained);
      for (TaskProcessRow &Row : ProcessRows_) {
        if (Row.Pid == Pid)
          Row.Hidden = Mode != 2;
      }
      Changed = true;
    }
    if (Changed) {
      SortProcessRows(ProcessRows_);
      PopulateProcessTable();
    }
    ReportDriverResult(Mode == 0 ? "Hide" : (Mode == 1 ? "Hide (Can't Unhide)" : "Unhide"));
  }

  void BlockImageRule(const TaskProcessRow &Row) {
    PROCESS_CREATE_BLOCK_ENTRY Entry{};
    Entry.Action = PROCESS_CREATE_BLOCK_ACTION_BLOCK;
    Entry.Flags = PROCESS_CREATE_BLOCK_MATCH_IMAGE;
    Row.Name.toWCharArray(Entry.ImagePattern);
    Entry.ImagePattern[Row.Name.length()] = L'\0';
    if (AddProcessCreateBlock(Entry))
      Notify(Utf8(QString("Blocked image: %1").arg(Row.Name)), NoticeKind::Success);
    else
      Notify(Utf8(QString("Failed to add rule (error %1).")
                      .arg(G_LastAegisCoreError)),
             NoticeKind::Error);
  }

  void UnblockImage(const std::vector<std::string> &Args) {
    std::vector<QString> Names;
    for (const std::string &Arg : Args) {
      DWORD Pid = 0;
      if (ParseUInt32(Arg, Pid)) {
        if (const TaskProcessRow *Row = FindProcess(Pid))
          Names.push_back(Row->Name);
        continue;
      }
      Names.push_back(QString::fromStdString(Arg));
    }
    if (Names.empty()) {
      if (const TuiRow *Row = Process_.Current())
        Names.push_back(QString::fromStdString(Row->Cells[1]));
    }
    for (const QString &Name : Names) {
      if (Name.isEmpty())
        continue;
      PROCESS_CREATE_BLOCK_ENTRY Entry{};
      Name.toWCharArray(Entry.ImagePattern);
      Entry.ImagePattern[Name.length()] = L'\0';
      if (RemoveProcessCreateBlock(Entry))
        Notify(Utf8(QString("Unblocked image: %1").arg(Name)), NoticeKind::Success);
      else
        Notify(Utf8(QString("No matching block rule for %1 (error %2).")
                        .arg(Name)
                        .arg(G_LastAegisCoreError)),
               NoticeKind::Error);
    }
  }

  void ShowBlockRules() {
    TuiAsyncVoid(
        [this] {
          std::vector<TuiRow> Rows;
          auto Output = static_cast<PROCESS_CREATE_BLOCK_OUTPUT *>(
              malloc(sizeof(PROCESS_CREATE_BLOCK_OUTPUT)));
          if (Output) {
            if (EnumerateProcessCreateBlocks(Output)) {
              for (ULONG Index = 0; Index < Output->Count; ++Index) {
                const PROCESS_CREATE_BLOCK_ENTRY &Entry = Output->Entries[Index];
                QStringList Flags;
                if (Entry.Flags & PROCESS_CREATE_BLOCK_WHITELIST)
                  Flags << "WHITELIST";
                if (Entry.Flags & PROCESS_CREATE_BLOCK_MATCH_PARENT)
                  Flags << "MATCH_PARENT";
                if (Entry.Flags & PROCESS_CREATE_BLOCK_MATCH_COMMAND)
                  Flags << "MATCH_COMMAND";
                TuiRow Row;
                Row.Cells = {
                    std::to_string(Entry.Index),
                    Utf8(QString::fromWCharArray(Entry.ImagePattern)),
                    Utf8(QString::fromWCharArray(Entry.CommandPattern)),
                    Entry.Action == PROCESS_CREATE_BLOCK_ACTION_BLOCK ? "Block"
                                                                      : "Audit",
                    Entry.ParentPid ? std::to_string(Entry.ParentPid) : std::string("-"),
                    Utf8(Flags.isEmpty() ? QString("-") : Flags.join(",")),
                };
                Rows.push_back(std::move(Row));
              }
            }
            free(Output);
          }
          TuiPost([this, Rows = std::move(Rows)] {
            std::vector<TuiRow> Lines;
            Lines.push_back(TuiRow{{"Index", "Image Pattern", "Command Pattern",
                                    "Action", "Parent PID", "Flags"},
                                   {}});
            for (const TuiRow &Row : Rows)
              Lines.push_back(Row);
            Lines.push_back(TuiRow{{"add <image> [action] [parentpid]", "", "", "", "", ""}, {}});
            Lines.push_back(TuiRow{{"remove <index>", "", "", "", "", ""}, {}});
            Lines.push_back(TuiRow{{"clear", "", "", "", "", ""}, {}});
            DetailDialog(*Dialogs, "Process Block Rules", Lines);
          });
        },
        [] {});
  }

  void LaunchAsDialog() {
    TuiDialog Dialog;
    Dialog.Title = "Run Process";
    Dialog.Body = "Launch an executable as SYSTEM or TrustedInstaller.";
    TuiField Context_;
    Context_.Label = "Security context";
    Context_.Kind = TuiFieldKind::Combo;
    Context_.Choices = {"SYSTEM", "TrustedInstaller"};
    TuiField Executable;
    Executable.Label = "Executable";
    Executable.Placeholder = "Select an executable";
    TuiField Arguments;
    Arguments.Label = "Arguments";
    Arguments.Placeholder = "Arguments (currently unsupported)";
    TuiField FullPrivileges;
    FullPrivileges.Label = "Enable Full Privileges";
    FullPrivileges.Kind = TuiFieldKind::Check;
    Dialog.Fields = {Context_, Executable, Arguments, FullPrivileges};
    Dialog.PrimaryLabel = "Run";
    Dialog.OnSubmit = [this](TuiDialog &Submitted) {
      const QString Path = QString::fromStdString(TrimAscii(Submitted.Fields[1].Value));
      if (Path.isEmpty() || !QFileInfo::exists(Path)) {
        Notify("Select an existing executable file.", NoticeKind::Warning);
        return;
      }
      if (!TrimAscii(Submitted.Fields[2].Value).empty()) {
        Notify("The current LaunchAs backend supports executable paths only.",
               NoticeKind::Warning);
        return;
      }
      QString NtPath;
      if (!ConvertExecutablePathToDevicePath(Path, NtPath)) {
        Notify("Unable to convert the executable path to a kernel device path.",
               NoticeKind::Error);
        return;
      }
      const ULONG AccountType = Submitted.Fields[0].Choice == 0
                                    ? ACCOUNT_TYPE_SYSTEM
                                    : ACCOUNT_TYPE_TRUSTEDINSTALLER;
      ULONG ProcessId = 0;
      if (!LaunchAs(AccountType, NtPath.toStdWString().c_str(), &ProcessId)) {
        Notify(Utf8(DescribeLaunchAsError(AccountType, G_LastAegisCoreError)),
               NoticeKind::Error);
        return;
      }
      Notify(Utf8(AccountType == ACCOUNT_TYPE_SYSTEM
                      ? QString("Process launched as SYSTEM with pid %1.")
                            .arg(ProcessId)
                      : QString("Process launched as TrustedInstaller with pid  "
                                "%1.")
                            .arg(ProcessId)),
             NoticeKind::Success);
      if (Submitted.Fields[3].Checked)
        SetProcessPreviousMode(ProcessId);
    };
    Dialogs->Push(std::move(Dialog));
  }

  // ---- 线程操作对话框 ----

  void ProcessPreviousModeDialog(DWORD Pid) {
    if (Pid == 0)
      return;
    TuiDialog Dialog;
    Dialog.Title = "Set Process PreviousMode";
    Dialog.Body = Utf8(
        QString("Applies to every thread of process %1. PreviousMode controls "
                "whether the kernel treats a thread's last call as user- or "
                "kernel-originated.")
            .arg(Pid));
    TuiField Mode;
    Mode.Label = "Mode";
    Mode.Kind = TuiFieldKind::Combo;
    Mode.Choices = {"KernelMode (0)", "UserMode (1)"};
    Dialog.Fields.push_back(Mode);
    Dialog.PrimaryLabel = "Apply";
    Dialog.OnSubmit = [this, Pid](TuiDialog &Submitted) {
      const UCHAR ModeValue = Submitted.Fields[0].Choice == 1 ? 1 : 0;
      const QString ModeText = ModeValue == 1 ? "UserMode" : "KernelMode";
      if (SetProcessPreviousMode(Pid, ModeValue))
        Notify(Utf8(QString("Process %1 PreviousMode set to %2.")
                        .arg(Pid)
                        .arg(ModeText)),
               NoticeKind::Success);
      else
        Notify(Utf8(QString("Failed to set %1 (error %2).")
                        .arg(ModeText)
                        .arg(G_LastAegisCoreError)),
               NoticeKind::Error);
      RefreshThreads();
      RefreshProcesses();
    };
    Dialogs->Push(std::move(Dialog));
  }

  void ThreadPreviousModeDialog(std::vector<DWORD> Tids) {
    if (Tids.empty())
      return;
    TuiDialog Dialog;
    Dialog.Title = "Set Thread PreviousMode";
    Dialog.Body = "PreviousMode controls whether the kernel treats the thread's "
                  "last call as user- or kernel-originated.";
    TuiField Mode;
    Mode.Label = "Mode";
    Mode.Kind = TuiFieldKind::Combo;
    Mode.Choices = {"KernelMode (0)", "UserMode (1)"};
    Dialog.Fields.push_back(Mode);
    Dialog.PrimaryLabel = "Apply";
    Dialog.OnSubmit = [this, Tids](TuiDialog &Submitted) {
      const UCHAR ModeValue = Submitted.Fields[0].Choice == 1 ? 1 : 0;
      int Count = 0;
      for (DWORD Tid : Tids)
        if (SetThreadPreviousMode(Tid, ModeValue))
          ++Count;
      const QString ModeText = ModeValue == 1 ? "UserMode" : "KernelMode";
      if (Count > 0)
        Notify(Utf8(QString("%1 of %2 thread(s) PreviousMode set to %3.")
                        .arg(Count)
                        .arg(Tids.size())
                        .arg(ModeText)),
               NoticeKind::Success);
      else
        Notify(Utf8(QString("Set PreviousMode failed (error %1).")
                        .arg(G_LastAegisCoreError)),
               NoticeKind::Error);
      RefreshThreads();
    };
    Dialogs->Push(std::move(Dialog));
  }

  void ThreadApcQueueableDialog(std::vector<DWORD> Tids) {
    if (Tids.empty())
      return;
    TuiDialog Dialog;
    Dialog.Title = "Set Thread ApcQueueable";
    Dialog.Body = "ApcQueueable (KTHREAD+0x74 bit 13) gates whether APCs can be "
                  "queued to this thread.";
    TuiField Mode;
    Mode.Label = "Mode";
    Mode.Kind = TuiFieldKind::Combo;
    Mode.Choices = {"Enable (1)", "Disable (0)"};
    Dialog.Fields.push_back(Mode);
    Dialog.PrimaryLabel = "Apply";
    Dialog.OnSubmit = [this, Tids](TuiDialog &Submitted) {
      const UCHAR Value = Submitted.Fields[0].Choice == 1 ? 0 : 1;
      int Count = 0;
      for (DWORD Tid : Tids)
        if (SetThreadApcQueueable(Tid, Value))
          ++Count;
      if (Count > 0)
        Notify(Utf8(QString("%1 of %2 thread(s) ApcQueueable updated.")
                        .arg(Count)
                        .arg(Tids.size())),
               NoticeKind::Success);
      else
        Notify(Utf8(QString("Set ApcQueueable failed (error %1).")
                        .arg(G_LastAegisCoreError)),
               NoticeKind::Error);
      RefreshThreads();
    };
    Dialogs->Push(std::move(Dialog));
  }

  void FindThreadInProcess(DWORD Pid) {
    if (Pid == 0)
      return;
    Filter.clear();
    ViewTab_ = 0;
    PopulateProcessTable();
    for (size_t Index = 0; Index < ProcessRows_.size(); ++Index) {
      if (ProcessRows_[Index].Pid != Pid)
        continue;
      const auto Position = std::find(Process_.Visible.begin(), Process_.Visible.end(),
                                      static_cast<int>(Index));
      if (Position != Process_.Visible.end())
        Process_.Selected =
            static_cast<int>(std::distance(Process_.Visible.begin(), Position));
      Notify("Selected process " + std::to_string(Pid), NoticeKind::Success);
      return;
    }
    Notify("Process " + std::to_string(Pid) +
               " not found in the current process view.",
           NoticeKind::Warning);
  }

  // ---- 详情（按 tab 展开为只读对话框） ----

  void ShowInspector(DWORD Pid, const std::string &Tab) {
    const TaskProcessRow *Selected = FindProcess(Pid);
    const QString ProcessName =
        Selected && !Selected->Name.isEmpty() ? Selected->Name
                                             : QString("Process %1").arg(Pid);
    const std::string Title =
        Utf8(QString("%1 - Process Inspector (%2)")
                 .arg(ProcessName, QString::fromStdString(Tab)));
    const TaskProcessRow Snapshot = Selected ? *Selected : TaskProcessRow{};
    const bool HasSelected = Selected != nullptr;
    const std::vector<TaskThreadRow> ThreadSnapshot = ThreadRows_;

    TuiAsyncVoid(
        [this, Pid, Tab, Snapshot, HasSelected, ThreadSnapshot, Title] {
          std::vector<TuiRow> Rows;
          if (Tab == "summary") {
            std::vector<std::pair<std::string, std::string>> Fields;
            if (HasSelected) {
              Fields.emplace_back("PID", std::to_string(Snapshot.Pid));
              Fields.emplace_back("Image", Utf8(Snapshot.Name));
              Fields.emplace_back("User", Utf8(Snapshot.User));
              Fields.emplace_back("Integrity", Utf8(IntegrityName(Snapshot.IntegrityRid)));
              Fields.emplace_back("Parent PID", std::to_string(Snapshot.ParentPid));
              Fields.emplace_back("Threads", std::to_string(Snapshot.ThreadCount));
              Fields.emplace_back(
                  "Handles", Snapshot.HandleCountAvailable
                                 ? std::to_string(Snapshot.HandleCount)
                                 : Utf8(QString("Unavailable (error %1)")
                                            .arg(Snapshot.HandleCountError)));
              Fields.emplace_back("Session", std::to_string(Snapshot.SessionId));
              Fields.emplace_back("Tool protection", Snapshot.Protected ? "Yes" : "No");
              Fields.emplace_back(
                  "PPL", Snapshot.Ppl
                             ? Utf8(QString("Yes (0x%1)")
                                        .arg(Snapshot.PplRaw, 2, 16, QLatin1Char('0'))
                                        .toUpper())
                             : "No");
              Fields.emplace_back("Critical", Snapshot.Critical ? "Yes" : "No");
              Fields.emplace_back("Hidden", Snapshot.Hidden ? "Yes" : "No");
              Fields.emplace_back("Enumeration",
                                  Snapshot.DriverData ? "Kernel driver"
                                                      : "Toolhelp fallback");
            }
            std::vector<INVENTORY_RECORD> ProcessRows;
            INVENTORY_LIST_HEADER Header{};
            if (QueryProcessRecords(Pid, IOCTL_QUERY_PROCESS, ProcessRows, &Header) &&
                !ProcessRows.empty()) {
              const auto &Record = ProcessRows.front();
              if (!HasSelected) {
                Fields.emplace_back("Parent PID",
                                    std::to_string(static_cast<uint32_t>(Record.Value[0])));
                Fields.emplace_back("Threads",
                                    std::to_string(static_cast<uint32_t>(Record.Value[1])));
                Fields.emplace_back("Handles",
                                    std::to_string(static_cast<uint32_t>(Record.Value[2])));
                Fields.emplace_back("Session",
                                    std::to_string(static_cast<uint32_t>(Record.Value[3])));
              }
              Fields.emplace_back("EPROCESS", Utf8(FormatTaskPointer(Record.Address)));
              if (Record.Value[4] != 0) {
                LARGE_INTEGER CreateTime{};
                CreateTime.QuadPart = static_cast<LONGLONG>(Record.Value[4]);
                Fields.emplace_back("Create time",
                                    Utf8(MonitorTimestamp(CreateTime)));
              }
              Fields.emplace_back(
                  "User time",
                  Utf8(FormatDuration(static_cast<quint64>(Record.Value[5]) / 10000)));
              Fields.emplace_back(
                  "Kernel time",
                  Utf8(FormatDuration(static_cast<quint64>(Record.Value[6]) / 10000)));
              Fields.emplace_back("Working set", Utf8(FormatBytes(Record.SizeBytes)));
              Fields.emplace_back("Private bytes",
                                  Utf8(FormatBytes(Record.Value[7])));
              if (Record.Path[0])
                Fields.emplace_back("Path", WideField(Record.Path));
            } else {
              Fields.emplace_back(
                  "Kernel query",
                  Utf8(QString("0x%1")
                           .arg(static_cast<quint32>(Header.Status), 8, 16,
                                QLatin1Char('0'))
                           .toUpper()));
            }
            Rows = FieldRows(Fields);
          } else if (Tab == "token") {
            UserTokenInfo TokenInfo;
            const bool TokenOk = QueryUserTokenInfo(Pid, TokenInfo);
            std::vector<std::pair<std::string, std::string>> Fields;
            Fields.emplace_back(
                "User", TokenOk ? Utf8(TokenInfo.User)
                                : Utf8(QString("Unavailable (%1)").arg(TokenInfo.Error)));
            Fields.emplace_back("SID", TokenOk ? Utf8(TokenInfo.UserSid) : std::string());
            Fields.emplace_back("Elevated", TokenOk
                                                ? (TokenInfo.Elevated ? "Yes" : "No")
                                                : "Unknown");
            Fields.emplace_back("Integrity", Utf8(TokenInfo.Integrity));
            Fields.emplace_back("AppContainer",
                                TokenInfo.AppContainer ? "Yes" : "No");
            Fields.emplace_back("AppContainer SID", Utf8(TokenInfo.AppContainerSid));
            Rows = FieldRows(Fields);
            for (const UserTokenEntry &Entry : TokenInfo.Entries)
              Rows.push_back(TuiRow{{Utf8(Entry.Category), Utf8(Entry.Name),
                                     Utf8(Entry.Sid), Utf8(Entry.Attributes)},
                                    {}});
          } else if (Tab == "threads") {
            std::vector<INVENTORY_RECORD> ThreadRows;
            INVENTORY_LIST_HEADER Header{};
            QueryProcessRecords(Pid, IOCTL_ENUM_THREADS, ThreadRows, &Header);
            Rows.push_back(TuiRow{{"TID", "Start", "Priority", "State", "Wait",
                                   "CPU time", "PreviousMode", "ApcQueueable"},
                                  {}});
            for (const INVENTORY_RECORD &Record : ThreadRows) {
              const TaskThreadRow *Cached = nullptr;
              const auto Match = std::find_if(
                  ThreadSnapshot.begin(), ThreadSnapshot.end(),
                  [&Record](const TaskThreadRow &Row) {
                    return Row.Tid == Record.ThreadId;
                  });
              if (Match != ThreadSnapshot.end())
                Cached = &*Match;
              const QString PreviousMode =
                  Cached ? FormatPreviousMode(*Cached) : QString("-");
              const QString Apc =
                  Cached ? FormatApcQueueable(*Cached) : QString("-");
              Rows.push_back(TuiRow{
                  {std::to_string(Record.ThreadId),
                   Utf8(FormatTaskPointer(Record.Address)),
                   std::to_string(static_cast<uint32_t>(Record.Value[0])),
                   std::to_string(static_cast<uint32_t>(Record.Value[2])),
                   std::to_string(static_cast<uint32_t>(Record.Value[3])),
                   std::to_string(static_cast<uint64_t>(Record.Value[6] +
                                                        Record.Value[7])),
                   Utf8(PreviousMode), Utf8(Apc)},
                  {}});
            }
          } else if (Tab == "handles") {
            Rows.push_back(TuiRow{{"Handle", "Object", "Type", "Access",
                                   "Attributes"},
                                  {}});
            std::vector<INVENTORY_RECORD> HandleRows;
            INVENTORY_LIST_HEADER HandleHeader{};
            const bool KernelOk =
                QueryProcessRecords(Pid, IOCTL_ENUM_HANDLES, HandleRows, &HandleHeader);
            if (KernelOk && HandleHeader.Status == 0 && !HandleRows.empty()) {
              for (const INVENTORY_RECORD &Record : HandleRows) {
                const QString ObjectText =
                    Record.Path[0] ? QString::fromWCharArray(Record.Path)
                                   : FormatTaskPointer(Record.Address);
                const QString TypeText =
                    Record.TypeName[0]
                        ? QString::fromWCharArray(Record.TypeName)
                        : (Record.Detail[0] ? QString::fromWCharArray(Record.Detail)
                                            : QString::number(Record.Value[2]));
                Rows.push_back(TuiRow{
                    {Utf8(QString("0x%1").arg(Record.Value[0], 0, 16).toUpper()),
                     Utf8(ObjectText), Utf8(TypeText),
                     Utf8(HandleAccessData::FormatDisplay(
                         TypeText, static_cast<quint32>(Record.Value[1]))),
                     Utf8(QString("0x%1").arg(Record.Value[3], 0, 16).toUpper())},
                    {}});
              }
            } else {
              std::vector<TaskHandleRow> UserRows;
              DWORD ErrorCode = ERROR_SUCCESS;
              if (QueryUserModeHandles(Pid, UserRows, ErrorCode) && !UserRows.empty()) {
                for (const TaskHandleRow &Row : UserRows) {
                  const QString ObjectText =
                      Row.ObjectName.isEmpty()
                          ? FormatTaskPointer(Row.ObjectAddress)
                          : Row.ObjectName;
                  const QString TypeText =
                      Row.TypeName.isEmpty() ? QString("Unknown") : Row.TypeName;
                  Rows.push_back(TuiRow{
                      {Utf8(QString("0x%1").arg(Row.HandleValue, 0, 16).toUpper()),
                       Utf8(ObjectText), Utf8(TypeText),
                       Utf8(HandleAccessData::FormatDisplay(TypeText,
                                                            Row.GrantedAccess)),
                       Utf8(QString("0x%1").arg(Row.Attributes, 0, 16).toUpper())},
                      {}});
                }
              } else {
                Rows.push_back(TuiRow{{"Unavailable", {}, {},
                                       {},
                                       Utf8(KernelOk
                                                ? QString("0x%1")
                                                      .arg(static_cast<quint32>(
                                                               HandleHeader.Status),
                                                           8, 16, QLatin1Char('0'))
                                                      .toUpper()
                                                : QString("fallback error %1")
                                                      .arg(ErrorCode))},
                                      {}});
              }
            }
          } else if (Tab == "modules") {
            Rows.push_back(TuiRow{{"Name", "Base", "Size", "Path", "Source"}, {}});
            std::vector<INVENTORY_RECORD> ModuleRows;
            INVENTORY_LIST_HEADER Header{};
            QueryProcessRecords(Pid, IOCTL_ENUM_MODULES, ModuleRows, &Header);
            for (const INVENTORY_RECORD &Record : ModuleRows) {
              Rows.push_back(TuiRow{
                  {Record.Name[0] ? WideField(Record.Name) : std::string("-"),
                   Utf8(FormatTaskPointer(Record.Address)),
                   Utf8(FormatBytes(Record.SizeBytes)),
                   Record.Path[0] ? WideField(Record.Path) : std::string("-"),
                   "Kernel"},
                  {}});
            }
            if (ModuleRows.empty()) {
              std::vector<ToolModuleInfo> Modules;
              if (ProcessPeb::ReadModuleList(Pid, Modules)) {
                for (const ToolModuleInfo &Module : Modules)
                  Rows.push_back(TuiRow{
                      {Module.Name,
                       Utf8(FormatTaskPointer(Module.BaseAddress)),
                       Utf8(FormatBytes(Module.SizeOfImage)), Module.FullPath,
                       "Toolhelp"},
                      {}});
              } else {
                Rows.push_back(TuiRow{{"Unavailable", {}, {}, {},
                                       Utf8(QString("status=0x%1")
                                                .arg(static_cast<quint32>(Header.Status),
                                                     8, 16, QLatin1Char('0'))
                                                .toUpper())},
                                      {}});
              }
            }
          } else if (Tab == "memory") {
            Rows.push_back(TuiRow{{"Base", "Size", "State", "Protect", "Type"}, {}});
            std::vector<INVENTORY_RECORD> MemoryRows;
            INVENTORY_LIST_HEADER Header{};
            QueryProcessRecords(Pid, IOCTL_ENUM_MEMORY, MemoryRows, &Header);
            for (const INVENTORY_RECORD &Record : MemoryRows) {
              Rows.push_back(TuiRow{
                  {Utf8(FormatTaskPointer(Record.Address)),
                   Utf8(FormatBytes(Record.SizeBytes)),
                   Utf8(QString("0x%1").arg(Record.Value[2], 0, 16).toUpper()),
                   Utf8(QString("0x%1").arg(Record.Value[3], 0, 16).toUpper()),
                   Utf8(QString("0x%1").arg(Record.Value[4], 0, 16).toUpper())},
                  {}});
            }
            if (MemoryRows.empty()) {
              HANDLE Process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, Pid);
              if (Process) {
                uintptr_t Address = 0;
                MEMORY_BASIC_INFORMATION Info{};
                size_t Count = 0;
                while (VirtualQueryEx(Process, reinterpret_cast<LPCVOID>(Address),
                                      &Info, sizeof(Info)) == sizeof(Info) &&
                       Count < 65536) {
                  Rows.push_back(TuiRow{
                      {Utf8(FormatTaskPointer(
                           reinterpret_cast<uintptr_t>(Info.BaseAddress))),
                       Utf8(FormatBytes(Info.RegionSize)),
                       Utf8(QString("0x%1").arg(Info.State, 0, 16).toUpper()),
                       Utf8(QString("0x%1").arg(Info.Protect, 0, 16).toUpper()),
                       Utf8(QString("0x%1").arg(Info.Type, 0, 16).toUpper())},
                      {}});
                  const uintptr_t Next =
                      reinterpret_cast<uintptr_t>(Info.BaseAddress) + Info.RegionSize;
                  if (Next <= Address)
                    break;
                  Address = Next;
                  ++Count;
                }
                CloseHandle(Process);
              }
              if (Rows.size() == 1) {
                Rows.push_back(TuiRow{{"Unavailable", {}, {}, {},
                                       Utf8(QString("status=0x%1")
                                                .arg(static_cast<quint32>(Header.Status),
                                                     8, 16, QLatin1Char('0'))
                                                .toUpper())},
                                      {}});
              }
            }
          } else if (Tab == "eprocess") {
            Rows.push_back(TuiRow{{"Member", "Value", "Raw / Notes"}, {}});
            std::vector<INVENTORY_RECORD> Records;
            INVENTORY_LIST_HEADER Header{};
            QueryProcessRecords(Pid, IOCTL_QUERY_EPROCESS, Records, &Header);
            for (const INVENTORY_RECORD &Record : Records) {
              std::string Notes;
              if (Record.Value[0] != 0)
                Notes = "offset=" + HexValue(Record.Value[0], 0);
              if (Record.Detail[0]) {
                const std::string Detail = WideField(Record.Detail);
                Notes = Notes.empty() ? Detail : Notes + " | " + Detail;
              }
              if (Record.Status != 0) {
                const std::string StatusText =
                    "status=" + HexValue(static_cast<uint32_t>(Record.Status), 8);
                Notes = Notes.empty() ? StatusText : Notes + " | " + StatusText;
              }
              Rows.push_back(TuiRow{
                  {Record.Name[0] ? WideField(Record.Name) : std::string("-"),
                   Record.Path[0] ? WideField(Record.Path) : std::string("-"),
                   Notes},
                  {}});
            }
            if (Records.empty()) {
              Rows.push_back(TuiRow{{"Kernel query",
                                     HexValue(static_cast<uint32_t>(Header.Status), 8),
                                     "EPROCESS data unavailable"},
                                    {}});
            }
          } else if (Tab == "mitigations") {
            Rows.push_back(TuiRow{{"Property", "Value", "Source"}, {}});
            BYTE Buffer[4096] = {};
            ULONG Returned = 0;
            bool Attempted = false;
            if (QueryMitigationKernel(Pid, Buffer, sizeof(Buffer), &Returned) &&
                Returned >= sizeof(ULONG) && Returned <= sizeof(Buffer)) {
              Attempted = true;
              const ULONG Count = *reinterpret_cast<PULONG>(Buffer);
              const ULONG MaxEntries = static_cast<ULONG>(
                  (Returned - sizeof(ULONG)) / (4 + 8 + 64));
              const ULONG EntryCount = std::min(Count, MaxEntries);
              PUCHAR Data = Buffer + sizeof(ULONG);
              for (ULONG Index = 0; Index < EntryCount; ++Index) {
                Data += 4; // Id（GUI 不展示）
                ULONG64 Flags = *reinterpret_cast<ULONG64 *>(Data);
                Data += 8;
                const WCHAR *NameData = reinterpret_cast<const WCHAR *>(Data);
                const std::string Name =
                    Utf8(QString::fromWCharArray(
                        NameData, static_cast<int>(wcsnlen_s(NameData, 32))));
                Data += 64;
                Rows.push_back(TuiRow{
                    {Name,
                     Utf8(QString("0x%1 (%2)")
                              .arg(Flags, 16, 16, QLatin1Char('0'))
                              .arg((Flags & 1) ? "Enabled" : "Disabled")),
                     Utf8(QString("PID %1").arg(Pid))},
                    {}});
              }
            }
            if (!Attempted)
              Rows.push_back(TuiRow{{"Mitigation query", "No data / unsupported", {}},
                                    {}});
          } else {
            std::string PebOutput;
            if (ProcessPeb::ReadPebInfoText(Pid, PebOutput)) {
              std::string Line;
              for (char C : PebOutput) {
                if (C == '\n') {
                  Rows.push_back(TuiRow{{TrimAscii(Line)}, {}});
                  Line.clear();
                } else if (C != '\r') {
                  Line += C;
                }
              }
              if (!TrimAscii(Line).empty())
                Rows.push_back(TuiRow{{TrimAscii(Line)}, {}});
            } else {
              Rows.push_back(TuiRow{{"Unable to read the target process."}, {}});
            }
          }
          TuiPost([this, Title, Rows = std::move(Rows)] {
            DetailDialog(*Dialogs, Title, Rows);
          });
        },
        [] {});
  }

  void ShowModuleList(DWORD Pid) {
    if (Pid == 0)
      return;
    const std::string Title =
        Utf8(QString("ModuleList - PID %1").arg(Pid));
    TuiAsyncVoid(
        [this, Pid, Title] {
          std::vector<TuiRow> Rows;
          Rows.push_back(TuiRow{{"Module", "Base address", "Image size", "Path"},
                                {}});
          std::vector<ToolModuleInfo> Modules;
          if (!ProcessPeb::ReadModuleList(Pid, Modules)) {
            TuiPost([this] {
              Notify("Unable to enumerate target process modules.",
                     NoticeKind::Error);
            });
            return;
          }
          for (const ToolModuleInfo &Module : Modules) {
            Rows.push_back(TuiRow{
                {Module.Name, Utf8(FormatTaskPointer(Module.BaseAddress)),
                 Utf8(QString("%1 bytes (0x%2)")
                          .arg(Module.SizeOfImage)
                          .arg(Module.SizeOfImage, 0, 16)
                          .toUpper()),
                 Module.FullPath},
                {}});
          }
          TuiPost([this, Title, Rows = std::move(Rows)] {
            DetailDialog(*Dialogs, Title, Rows);
          });
        },
        [] {});
  }

  void ShowPeb(DWORD Pid) {
    if (Pid == 0)
      return;
    TuiAsyncVoid(
        [this, Pid] {
          std::string Output;
          if (!ProcessPeb::ReadPebInfoText(Pid, Output)) {
            TuiPost([this] {
              Notify("Unable to read the target process.", NoticeKind::Error);
            });
            return;
          }
          std::vector<TuiRow> Rows;
          std::string Line;
          for (char C : Output) {
            if (C == '\n') {
              Rows.push_back(TuiRow{{TrimAscii(Line)}, {}});
              Line.clear();
            } else if (C != '\r') {
              Line += C;
            }
          }
          if (!TrimAscii(Line).empty())
            Rows.push_back(TuiRow{{TrimAscii(Line)}, {}});
          TuiPost([this, Rows = std::move(Rows)] {
            DetailDialog(*Dialogs, "PEB", Rows);
          });
        },
        [] {});
  }

  int Index_ = 0;
  int64_t LastAutoRefreshMs_ = 0;
  int ViewTab_ = 0;
  std::vector<TaskProcessRow> ProcessRows_;
  std::vector<TaskThreadRow> ThreadRows_;
  std::map<DWORD, TaskProcessRow> Retained_;
  QSet<DWORD> ProtectedPids_;
  TuiTable Process_;
  TuiTable Thread_;
  std::atomic_bool Refreshing_{false};
  std::atomic_bool ThreadsRefreshing_{false};
};

std::unique_ptr<TuiPage> MakeTaskPage(int Index) {
  return std::make_unique<TaskPage>(Index);
}

// ------------------------------------------------------------
// Monitor 页：8 个标签页共用一份 MonitorSharedState
// ------------------------------------------------------------

namespace {

// GUI 的 FormatEtwEvent 是 MonitorManagerPage 的私有静态成员，这里原样重写。
QString FormatEtwEvent(const ParsedEvent &Event) {
  QString Text =
      QString("%1 | %2 | %3 | PID %4 | TID %5")
          .arg(MonitorTimestamp(Event.TimeStamp),
               QString::fromWCharArray(CategoryToString(Event.Category)),
               Event.ProcessName.empty()
                   ? "<unknown>"
                   : QString::fromStdWString(Event.ProcessName))
          .arg(Event.ProcessId)
          .arg(Event.ThreadId);
  if (!Event.ProviderName.empty())
    Text += " | Provider " + QString::fromStdWString(Event.ProviderName);
  if (Event.EventId)
    Text += QString(" | Id %1").arg(Event.EventId);
  if (Event.ParentPid)
    Text += QString(" | PPID %1").arg(Event.ParentPid);
  if (Event.StartAddr)
    Text += QString(" | Start 0x%1").arg(Event.StartAddr, 0, 16).toUpper();
  if (!Event.ImageName.empty())
    Text += " | Image " + QString::fromStdWString(Event.ImageName);
  if (!Event.FileName.empty())
    Text += " | File " + QString::fromStdWString(Event.FileName);
  if (!Event.RegistryPath.empty())
    Text += " | Key " + QString::fromStdWString(Event.RegistryPath);
  if (!Event.ValueName.empty())
    Text += " | Value " + QString::fromStdWString(Event.ValueName);
  if (!Event.LocalAddress.empty())
    Text += QString(" | Local %1:%2")
                .arg(QString::fromStdWString(Event.LocalAddress))
                .arg(Event.LocalPort);
  if (!Event.RemoteAddress.empty())
    Text += QString(" | Remote %1:%2")
                .arg(QString::fromStdWString(Event.RemoteAddress))
                .arg(Event.RemotePort);
  if (Event.InterfaceIndex)
    Text += QString(" | If %1").arg(Event.InterfaceIndex);
  if (Event.DataSize)
    Text += QString(" | Size %1").arg(Event.DataSize);
  return Text;
}

QString MonitorRegistryTypeName(ULONG Type) {
  switch (Type) {
  case REG_SZ: return "REG_SZ";
  case REG_EXPAND_SZ: return "REG_EXPAND_SZ";
  case REG_BINARY: return "REG_BINARY";
  case REG_DWORD: return "REG_DWORD";
  case REG_DWORD_BIG_ENDIAN: return "REG_DWORD_BIG_ENDIAN";
  case REG_LINK: return "REG_LINK";
  case REG_MULTI_SZ: return "REG_MULTI_SZ";
  case REG_QWORD: return "REG_QWORD";
  default: return QString("REG_0x%1").arg(Type, 0, 16).toUpper();
  }
}

QString MonitorRegistryDataText(const MonitorEvent &Event, int MaxChars) {
  if (Event.DataBytes == 0)
    return QString();
  const UCHAR *Data = Event.Data;
  const ULONG Bytes = Event.DataBytes;
  const ULONG Type = Event.DataType;
  const auto HexDump = [&](ULONG Limit) {
    QString Out;
    const ULONG Count = qMin(Bytes, Limit);
    for (ULONG Index = 0; Index < Count; ++Index)
      Out += QString("%1 ").arg(Data[Index], 2, 16, QLatin1Char('0'));
    if (Count < Bytes)
      Out += "…";
    return Out.trimmed().toUpper();
  };
  if (Type == REG_SZ || Type == REG_EXPAND_SZ) {
    const int Chars = static_cast<int>(Bytes / sizeof(WCHAR));
    QString Text =
        QString::fromWCharArray(reinterpret_cast<const wchar_t *>(Data), Chars);
    Text.replace(QChar('\0'), QChar(' '));
    if (MaxChars > 0 && Text.size() > MaxChars)
      Text = Text.left(MaxChars) + "…";
    return Text.trimmed();
  }
  if (Type == REG_MULTI_SZ) {
    const int Chars = static_cast<int>(Bytes / sizeof(WCHAR));
    const QString Raw =
        QString::fromWCharArray(reinterpret_cast<const wchar_t *>(Data), Chars);
    QStringList Parts = Raw.split(QChar('\0'), Qt::SkipEmptyParts);
    QString Text = Parts.join(" | ");
    if (MaxChars > 0 && Text.size() > MaxChars)
      Text = Text.left(MaxChars) + "…";
    return Text;
  }
  if (Type == REG_DWORD && Bytes >= sizeof(ULONG)) {
    ULONG Value = 0;
    memcpy(&Value, Data, sizeof(Value));
    return QString("%1 (0x%2)").arg(Value).arg(Value, 0, 16).toUpper();
  }
  if (Type == REG_QWORD && Bytes >= sizeof(ULONGLONG)) {
    ULONGLONG Value = 0;
    memcpy(&Value, Data, sizeof(Value));
    return QString("%1 (0x%2)").arg(Value).arg(Value, 0, 16).toUpper();
  }
  return HexDump(MaxChars > 0 ? static_cast<ULONG>(MaxChars / 3) : 32);
}

QString MonitorNetworkAddressPair(const MonitorEvent &Event) {
  if (Event.DataBytes < 32)
    return QString();
  const auto IsZero = [&](int Offset) {
    for (int Index = 0; Index < 16; ++Index)
      if (Event.Data[Offset + Index] != 0)
        return false;
    return true;
  };
  const bool IsIpv4 = IsZero(4) && IsZero(20);
  const auto AddrText = [&](int Offset, bool V4) {
    if (V4)
      return QString("%1.%2.%3.%4")
          .arg(Event.Data[Offset + 0])
          .arg(Event.Data[Offset + 1])
          .arg(Event.Data[Offset + 2])
          .arg(Event.Data[Offset + 3]);
    QStringList Groups;
    for (int Index = 0; Index < 16; Index += 2)
      Groups << QString("%1")
                    .arg((Event.Data[Offset + Index] << 8) |
                             Event.Data[Offset + Index + 1],
                         4, 16, QLatin1Char('0'));
    return Groups.join(':').toUpper();
  };
  return QString("%1:%2 -> %3:%4")
      .arg(AddrText(0, IsIpv4))
      .arg(Event.Value1 & 0xFFFF)
      .arg(AddrText(16, IsIpv4))
      .arg(Event.Value2 & 0xFFFF);
}

QString MonitorCallbackAddressText(const MonitorEvent &Event) {
  const QString Module =
      Event.Path[0] ? QString::fromWCharArray(Event.Path) : QString();
  const QString Address = QString("0x%1").arg(Event.Address, 0, 16).toUpper();
  if (Module.isEmpty() || Module == "<unknown>")
    return Address;
  return QString("%1 @ %2").arg(Module, Address);
}

// GUI 的 KernelEventTypeDetails（前 3 段必须是 时间|类型|进程，History 依赖）。
QString MonitorKernelEventTypeDetails(const MonitorEvent &Event) {
  QString Text;
  const bool Truncated = (Event.Flags & MONITOR_EVENT_FLAG_TRUNCATED) != 0;
  switch (Event.Type) {
  case EventProcessCreate: {
    if (Event.Name[0])
      Text += QString(" | Parent %1").arg(QString::fromWCharArray(Event.Name));
    if (Event.TargetPath[0])
      Text += QString(" | Parent path %1")
                  .arg(QString::fromWCharArray(Event.TargetPath));
    if (Event.CreatorPid)
      Text += QString(" | Creator PID %1").arg(Event.CreatorPid);
    if (Event.Flags2 & MONITOR_FLAG2_CREATOR_DIFFERS)
      Text += " | creator differs from parent";
    if (Event.Flags2 & MONITOR_FLAG2_SUBSYSTEM_PROCESS)
      Text += " | subsystem process";
    break;
  }
  case EventThreadCreate:
    if (Event.Name[0])
      Text += QString(" | Host %1").arg(QString::fromWCharArray(Event.Name));
    if (Event.Flags2 & MONITOR_FLAG2_CREATOR_DIFFERS)
      Text += QString(" | Creator PID %1 (remote)").arg(Event.CreatorPid);
    break;
  case EventProcessExit:
  case EventThreadExit:
    if (Event.Name[0])
      Text += QString(" | Image %1").arg(QString::fromWCharArray(Event.Name));
    break;
  case EventImageLoad:
  case EventDriverLoad:
  case EventDriverUnload:
    if (Event.Name[0])
      Text += QString(" | Module %1").arg(QString::fromWCharArray(Event.Name));
    if (Event.SizeBytes)
      Text += QString(" | Image size %1").arg(Event.SizeBytes);
    if (Event.Value1 || Event.Value2)
      Text += QString(" | Signature level %1 type %2")
                  .arg(Event.Value1)
                  .arg(Event.Value2);
    if (Event.Flags2 & MONITOR_FLAG2_SYSTEM_MODE_IMAGE)
      Text += " | kernel-mode image";
    break;
  case EventRegistryOperation: {
    if (Event.Name[0])
      Text += QString(" | Value %1").arg(QString::fromWCharArray(Event.Name));
    if (Event.DataType)
      Text += QString(" | %1").arg(MonitorRegistryTypeName(Event.DataType));
    const QString Data = MonitorRegistryDataText(Event, 96);
    if (!Data.isEmpty())
      Text += QString(" | Value data %1").arg(Data);
    if (Truncated)
      Text += " | data truncated";
    break;
  }
  case EventHandleOperation:
    if (Event.Name[0])
      Text += QString(" | Object %1").arg(QString::fromWCharArray(Event.Name));
    if (Event.Value1)
      Text += QString(" | Requested 0x%1")
                  .arg(static_cast<quint32>(Event.Value1), 0, 16)
                  .toUpper();
    if (Event.Flags2 & MONITOR_FLAG2_KERNEL_HANDLE)
      Text += " | kernel handle";
    if (Event.Flags2 & MONITOR_FLAG2_TARGET_IS_THREAD)
      Text += " | target is thread";
    break;
  case EventFileOperation:
  case EventFileCapture:
    if (Event.CreatorPid && Event.CreatorPid != Event.ProcessId)
      Text += QString(" | Requestor PID %1").arg(Event.CreatorPid);
    if (Event.Type == EventFileCapture) {
      if (Event.SizeBytes)
        Text += QString(" | Write %1 bytes").arg(Event.SizeBytes);
      if (Event.Offset)
        Text += QString(" | Offset 0x%1").arg(Event.Offset, 0, 16).toUpper();
    } else {
      if (Event.DataType) {
        const ULONG InfoClass = Event.DataType;
        const QString Name =
            (InfoClass == 10 || InfoClass == 65)
                ? QString("Rename")
                : (InfoClass == 13 || InfoClass == 64)
                      ? QString("Delete")
                      : (InfoClass == 4 ? QString("Delete (basic)")
                                        : QString("Class %1").arg(InfoClass));
        Text += QString(" | %1").arg(Name);
      }
      if (Event.TargetPath[0])
        Text += QString(" | Rename to %1")
                    .arg(QString::fromWCharArray(Event.TargetPath));
      if (Event.Value1)
        Text += QString(" | Access 0x%1")
                    .arg(static_cast<quint32>(Event.Value1), 0, 16)
                    .toUpper();
    }
    break;
  case EventNetworkConnect:
  case EventNetworkAccept:
  case EventDnsQuery:
  case EventHttpRequest: {
    const QString Pair = MonitorNetworkAddressPair(Event);
    if (!Pair.isEmpty())
      Text += QString(" | %1").arg(Pair);
    else if (Event.Value1 || Event.Value2)
      Text += QString(" | Local %1 | Remote %2").arg(Event.Value1).arg(Event.Value2);
    if (Event.DataBytes >= 32 && Event.Path[0])
      Text += QString(" | Family %1").arg(QString::fromWCharArray(Event.Path));
    if (Event.Name[0])
      Text += QString(" | Process path %1")
                  .arg(QString::fromWCharArray(Event.Name));
    if (Event.Flags2 & MONITOR_FLAG2_BLOCKED)
      Text += " | blocked";
    break;
  }
  case EventServiceStateChange: {
    const QString Op = Event.Operation == MONITOR_SERVICE_OP_REGISTERED
                           ? QString("registered")
                           : Event.Operation == MONITOR_SERVICE_OP_REMOVED
                                 ? QString("removed")
                                 : Event.Operation == MONITOR_SERVICE_OP_START
                                       ? QString("start state changed")
                                       : QString("changed");
    Text += QString(" | Service %1").arg(Op);
    if (Event.Name[0])
      Text += QString(" | %1").arg(QString::fromWCharArray(Event.Name));
    if (Event.Operation == MONITOR_SERVICE_OP_START && Event.Value1)
      Text += QString(" | Start type %1").arg(Event.Value1);
    break;
  }
  case EventCallbackChange:
    if (Event.Name[0])
      Text += QString(" | Source %1").arg(QString::fromWCharArray(Event.Name));
    if (Event.Address)
      Text += QString(" | %1").arg(MonitorCallbackAddressText(Event));
    break;
  case EventUsbDeviceArrival:
  case EventUsbDeviceRemoval:
    if (Event.Name[0])
      Text += QString(" | Instance %1").arg(QString::fromWCharArray(Event.Name));
    if (Event.Flags2 & MONITOR_FLAG2_BLOCKED)
      Text += " | blocked";
    break;
  case EventProcessInject:
    if (Event.Name[0])
      Text += QString(" | Target %1").arg(QString::fromWCharArray(Event.Name));
    if (Event.CreatorPid)
      Text += QString(" | Creator PID %1").arg(Event.CreatorPid);
    break;
  default:
    break;
  }
  return Text;
}

QString FormatKernelMonitorEvent(const MonitorEvent &Event) {
  std::wstring ProcessName;
  if (Event.Name[0] && (Event.Type == EventProcessExit ||
                        Event.Type == EventThreadExit ||
                        Event.Type == EventProcessCreate ||
                        Event.Type == EventThreadCreate))
    ProcessName = Event.Name;
  if (ProcessName.empty())
    ProcessName = GetProcessNameFromPid(Event.ProcessId);
  QString Text =
      QString("%1 | #%2 | %3 | %4 | PID %5 | TID %6")
          .arg(MonitorTimestamp(Event.TimeStamp))
          .arg(Event.Sequence)
          .arg(QString::fromWCharArray(
              EventTypeToString(static_cast<MonitorEventType>(Event.Type))))
          .arg(ProcessName.empty() ? "<unknown>"
                                   : QString::fromStdWString(ProcessName))
          .arg(Event.ProcessId)
          .arg(Event.ThreadId);
  if (Event.ParentPid)
    Text += QString(" | PPID %1").arg(Event.ParentPid);
  if (Event.TargetProcessId)
    Text += QString(" | Target PID %1").arg(Event.TargetProcessId);
  if (Event.TargetThreadId)
    Text += QString(" | Target TID %1").arg(Event.TargetThreadId);
  if (Event.Address && Event.Type != EventCallbackChange)
    Text += QString(" | Address 0x%1").arg(Event.Address, 0, 16).toUpper();
  if (Event.SizeBytes && Event.Type != EventFileCapture &&
      Event.Type != EventImageLoad && Event.Type != EventDriverLoad &&
      Event.Type != EventDriverUnload)
    Text += QString(" | Size %1").arg(Event.SizeBytes);
  Text += MonitorKernelEventTypeDetails(Event);
  if (Event.Path[0])
    Text += " | " + QString::fromWCharArray(Event.Path);
  if (Event.Extra[0])
    Text += " | " + QString::fromWCharArray(Event.Extra);
  if (Event.Status)
    Text += QString(" | Status 0x%1")
                .arg(static_cast<quint32>(Event.Status), 8, 16, QLatin1Char('0'))
                .toUpper();
  return Text;
}

QString FormatKernelMonitorEventDetail(const MonitorEvent &Event) {
  QStringList Lines;
  Lines << QString("Timestamp      : %1").arg(MonitorTimestamp(Event.TimeStamp));
  Lines << QString("Sequence       : %1").arg(Event.Sequence);
  Lines << QString("Type           : %1 (%2)")
               .arg(QString::fromWCharArray(
                   EventTypeToString(static_cast<MonitorEventType>(Event.Type))))
               .arg(Event.Type);
  const std::wstring ProcessName = GetProcessNameFromPid(Event.ProcessId);
  Lines << QString("Process        : %1 (PID %2)")
               .arg(ProcessName.empty() ? QString("<unknown>")
                                        : QString::fromStdWString(ProcessName))
               .arg(Event.ProcessId);
  Lines << QString("Thread         : TID %1").arg(Event.ThreadId);
  if (Event.ParentPid)
    Lines << QString("Parent PID     : %1").arg(Event.ParentPid);
  if (Event.Name[0])
    Lines << QString("Name           : %1").arg(QString::fromWCharArray(Event.Name));
  if (Event.TargetProcessId)
    Lines << QString("Target PID     : %1").arg(Event.TargetProcessId);
  if (Event.TargetThreadId)
    Lines << QString("Target TID     : %1").arg(Event.TargetThreadId);
  if (Event.Address)
    Lines << QString("Address        : 0x%1").arg(Event.Address, 0, 16).toUpper();
  if (Event.SizeBytes)
    Lines << QString("Size           : %1").arg(Event.SizeBytes);
  if (Event.Path[0])
    Lines << QString("Path           : %1").arg(QString::fromWCharArray(Event.Path));
  if (Event.Extra[0])
    Lines << QString("Extra          : %1").arg(QString::fromWCharArray(Event.Extra));
  if (Event.Status)
    Lines << QString("Status         : 0x%1")
                 .arg(static_cast<quint32>(Event.Status), 8, 16, QLatin1Char('0'))
                 .toUpper();
  Lines << "";
  Lines << "Summary        : " + FormatKernelMonitorEvent(Event);
  return Lines.join('\n');
}

QString FormatDeviceEvent(const MonitorSimpleEvent &Event) {
  const QString Description =
      Event.Path[0] ? QString::fromWCharArray(Event.Path) : QString();
  const QString DeviceId =
      Event.Extra[0] ? QString::fromWCharArray(Event.Extra) : QString();
  const QString Action =
      Event.Type == EventUsbDeviceArrival ? "Arrival" : "Removal";
  QString Text = QString("%1 | %2 | Device %3")
                     .arg(MonitorTimestamp(Event.TimeStamp), Action,
                          Description.isEmpty() ? "Unknown device" : Description);
  if (DeviceId.isEmpty())
    Text += QString(" | PID %1").arg(Event.ProcessId);
  if (!DeviceId.isEmpty())
    Text += " | " + DeviceId;
  if (Event.Data2 != 0 || (Event.Flags2 & MONITOR_FLAG2_BLOCKED))
    Text += " | BLOCKED";
  return Text;
}

QString FormatDeviceEventDetail(const MonitorSimpleEvent &Event) {
  QStringList Lines;
  Lines << QString("Timestamp      : %1").arg(MonitorTimestamp(Event.TimeStamp));
  Lines << QString("Type           : %1")
               .arg(QString::fromWCharArray(EventTypeToString(Event.Type)));
  if (Event.Path[0])
    Lines << QString("Description    : %1").arg(QString::fromWCharArray(Event.Path));
  if (Event.Extra[0])
    Lines << QString("Hardware / ID  : %1").arg(QString::fromWCharArray(Event.Extra));
  if (Event.Name[0])
    Lines << QString("Instance path  : %1").arg(QString::fromWCharArray(Event.Name));
  if (Event.Data2 != 0 || (Event.Flags2 & MONITOR_FLAG2_BLOCKED))
    Lines << QString("State          : blocked (interface disabled)");
  return Lines.join('\n');
}

QString HttpFlowAddress(uint32_t Address) {
  return QString("%1.%2.%3.%4")
      .arg((Address >> 24) & 0xFF)
      .arg((Address >> 16) & 0xFF)
      .arg((Address >> 8) & 0xFF)
      .arg(Address & 0xFF);
}

} // namespace

class MonitorPage final : public TuiPage {
public:
  explicit MonitorPage(int Index)
      : Index_(Index), State_(std::make_shared<MonitorSharedState>()) {
    G_ActiveMonitorState = State_;
    SelectedProviders_.assign(KProviders, KProviders + KProviderCount);
    RegisterCommands();
  }

  ~MonitorPage() override {
    StopHttp();
    StopNetwork();
    StopProcess();
    StopSystem();
    StopDevices();
    G_ActiveMonitorState.reset();
  }

  std::string Title() const override { return "Monitor"; }

  std::string Subtitle() const override {
    return "system/process/network/registry capture, history, rules, devices";
  }

  void OnEnter() override {
    for (auto &Table : Tables_) {
      Table.Headers = {"Event"};
      Table.RightAlign = {false};
    }
    History_.Headers = {"Timestamp", "Type", "PID", "Process", "Detail"};
    History_.RightAlign = {false, false, true, false, false};
    Rules_.Headers = {"ID", "Type", "Action", "PID", "Protocol", "Remote Port",
                      "Target", "Hit count"};
    Rules_.RightAlign = {true, false, false, true, true, true, false, true};
    Devices_.Headers = {"Event"};
    Alerts_.Headers = {"Alert"};
  }

  void OnTick(int64_t NowMs) override {
    if (LastVersionTickMs_ == 0 || NowMs - LastVersionTickMs_ >= 150) {
      LastVersionTickMs_ = NowMs;
      const uint64_t Version = State_->Streams[static_cast<size_t>(
          std::min(Tab_, 4))].Version.load(std::memory_order_relaxed);
      if (Tab_ >= 0 && Tab_ < 4) {
        if (DisplayedVersions_[static_cast<size_t>(Tab_)] != Version) {
          DisplayedVersions_[static_cast<size_t>(Tab_)] = Version;
          Populate(Tab_);
        }
      } else if (Tab_ == 4) {
        const uint64_t HistoryVersion =
            State_->HistoryVersion.load(std::memory_order_relaxed);
        if (DisplayedHistoryVersion_ != HistoryVersion) {
          DisplayedHistoryVersion_ = HistoryVersion;
          PopulateHistory();
        }
      } else if (Tab_ == 5) {
        if (NowMs - LastRulesTickMs_ >= 1500) {
          LastRulesTickMs_ = NowMs;
          RefreshRules();
        }
      } else if (Tab_ == 6) {
        const uint64_t DeviceVersion =
            State_->Streams[4].Version.load(std::memory_order_relaxed);
        if (DisplayedDeviceVersion_ != DeviceVersion) {
          DisplayedDeviceVersion_ = DeviceVersion;
          Populate(4);
        }
      } else if (Tab_ == 7) {
        const uint64_t AlertVersion =
            State_->Alerts.Version.load(std::memory_order_relaxed);
        if (DisplayedAlertsVersion_ != AlertVersion) {
          DisplayedAlertsVersion_ = AlertVersion;
          PopulateAlerts();
        }
      }
    }
    if (NowMs - LastTelemetryMs_ >= 1000) {
      LastTelemetryMs_ = NowMs;
      RefreshKernelTelemetry();
    }
  }

  TuiTable *ActiveTable() override {
    if (Tab_ >= 0 && Tab_ < 4)
      return &Tables_[static_cast<size_t>(Tab_)];
    switch (Tab_) {
    case 4: return &History_;
    case 5: return &Rules_;
    case 6: return &Devices_;
    case 7: return &Alerts_;
    default: return &Tables_[0];
    }
  }

  std::string RenderText() override {
    if (Tables_[0].Headers.empty())
      OnEnter();
    RepopulateActiveTab();
    if (Tab_ == 5)
      RefreshRules();
    std::string Text = ::AegisNT::Tui::TabStrip(
        std::vector<std::string>(KTabNames, KTabNames + KTabCount), Tab_);
    Text += '\n';
    if (!Filter.empty())
      Text += "filter: " + Filter + '\n';
    Text += TuiTableToText(*ActiveTable(), 0);
    return Text;
  }

private:
  static constexpr int KTabCount = 8;
  static constexpr const char *KTabNames[KTabCount] = {
      "System", "Process", "Network", "HTTP(S)",
      "History", "Rules",  "Devices", "Alerts"};

  void RegisterCommands() {
    auto Add = [this](const char *Name, const char *Usage,
                      std::function<void(std::vector<std::string>)> Handler) {
      OwnedCommands.push_back(TuiCommand{Name, Usage, std::move(Handler)});
    };
    Add("start", "start  (start the capture of the active tab)",
        [this](std::vector<std::string>) { StartActive(); });
    Add("stop", "stop  (stop the capture of the active tab)",
        [this](std::vector<std::string>) { StopActive(); });
    Add("mode", "mode [etw|kernel]  (System capture source)",
        [this](std::vector<std::string> Args) {
          if (!Args.empty())
            SystemMode_ = StartsWithCi(Args.front(), "kernel") ? 1 : 0;
          else
            SystemMode_ = SystemMode_ == 0 ? 1 : 0;
          SetStatus(SystemMode_ == 0 ? "System mode: ETWMode"
                                     : "System mode: KernelMode");
        });
    Add("providers", "providers [name=on|off ...]  (ETW providers)",
        [this](std::vector<std::string> Args) { ProvidersCommand(Args); });
    Add("etw-filter", "etw-filter [off|key=value ...]",
        [this](std::vector<std::string> Args) { EtwFilterCommand(Args); });
    Add("pid", "pid <n>  (kernel/system PID filter, 0 = all)",
        [this](std::vector<std::string> Args) {
          if (Args.empty()) {
            Notify("Usage: pid <n>", NoticeKind::Warning);
            return;
          }
          FilterPid_ = QString::fromStdString(Args.front());
          SetStatus("PID filter " + Args.front());
        });
    Add("prefix", "prefix <path>  (kernel/system path prefix)",
        [this](std::vector<std::string> Args) {
          FilterPrefix_ = Args.empty() ? std::string() : Args.front();
          SetStatus(FilterPrefix_.empty() ? "Path prefix cleared"
                                          : "Path prefix " + FilterPrefix_);
        });
    Add("registry-preview", "registry-preview [on|off]",
        [this](std::vector<std::string> Args) {
          RegistryPreview_ = Args.empty() ? !RegistryPreview_
                                          : StartsWithCi(Args.front(), "on");
          SetStatus(std::string("Registry preview ") +
                    (RegistryPreview_ ? "on" : "off"));
        });
    Add("rules-add", "rules-add <file|registry|network> <audit|block> [key=value ...]",
        [this](std::vector<std::string> Args) { AddRule(Args); });
    Add("rules-remove", "rules-remove [id]", [this](std::vector<std::string> Args) {
      RemoveRule(Args);
    });
    Add("rules-clear", "rules-clear  (remove all monitor rules)",
        [this](std::vector<std::string>) {
          ConfirmDialog(*Dialogs, "Clear rules", "Remove all monitor rules?",
                        [this] {
                          if (!AegisSentinelOperateRule(MonitorRuleClear)) {
                            Notify(Utf8(QString("Failed to clear rules (error %1).")
                                            .arg(GetLastError())),
                                   NoticeKind::Error);
                            return;
                          }
                          Notify("All monitor rules were removed.",
                                 NoticeKind::Success);
                          RulesDirty_ = true;
                          RefreshRules();
                        },
                        "Yes", "No");
        });
    Add("rules-refresh", "rules-refresh  (reload rules from the driver)",
        [this](std::vector<std::string>) { RefreshRules(); });
    Add("rules-import", "rules-import  (from Monitor/RulesV3 in the config)",
        [this](std::vector<std::string>) { ImportRules(); });
    Add("rules-export", "rules-export  (to Monitor/RulesV3 in the config)",
        [this](std::vector<std::string>) { ExportRules(); });
    Add("devices-filter", "devices-filter [hardware=..] [vid=..] [pid=..]",
        [this](std::vector<std::string> Args) { ApplyDeviceFilter(Args); });
    Add("devices-query", "devices-query  (read the current PnP filter)",
        [this](std::vector<std::string>) { QueryDeviceFilter(); });
    Add("devices-clear", "devices-clear  (clear the PnP filter)",
        [this](std::vector<std::string>) { ClearDeviceFilter(); });
    Add("history-export", "history-export <path>  (CSV)",
        [this](std::vector<std::string> Args) { ExportHistory(Args); });
    Add("history-clear", "history-clear", [this](std::vector<std::string>) {
      {
        std::lock_guard<std::mutex> Lock(State_->HistoryMutex);
        State_->HistoryRows.clear();
        State_->HistoryVersion.fetch_add(1, std::memory_order_relaxed);
      }
      PopulateHistory();
      Notify("Event history cleared.", NoticeKind::Success);
    });
    Add("alerts-clear", "alerts-clear", [this](std::vector<std::string>) {
      {
        std::lock_guard<std::mutex> Lock(State_->Alerts.Mutex);
        State_->Alerts.Rows.clear();
        State_->Alerts.Version.fetch_add(1, std::memory_order_relaxed);
      }
      PopulateAlerts();
      Notify("Alerts cleared.", NoticeKind::Success);
    });
    Add("details", "details  (show the selected event/detail)",
        [this](std::vector<std::string>) { ShowDetails(); });
    Add("block-device", "block-device  (prefill the device filter from the selection)",
        [this](std::vector<std::string>) { BlockDevice(); });
    Add("tab", "tab [system|process|network|http|history|rules|devices|alerts|0-7]",
        [this](std::vector<std::string> Args) { TabCommand(Args); });
  }

  // 行模式下没有 F7/F8：用 `tab` 命令切换 8 个标签页。
  void TabCommand(const std::vector<std::string> &Args) {
    if (Args.empty()) {
      Tab_ = (Tab_ + 1) % KTabCount;
    } else {
      const std::string Name = LowerAscii(Args.front());
      bool Matched = false;
      for (int Index = 0; Index < KTabCount; ++Index) {
        if (Name == LowerAscii(KTabNames[Index])) {
          Tab_ = Index;
          Matched = true;
          break;
        }
      }
      if (!Matched) {
        bool Ok = false;
        const int Value = QString::fromStdString(TrimAscii(Args.front())).toInt(&Ok);
        if (!Ok || Value < 0 || Value >= KTabCount) {
          Notify("tab: expected 0..7 or a tab name.", NoticeKind::Warning);
          return;
        }
        Tab_ = Value;
      }
    }
    RepopulateActiveTab();
    if (Tab_ == 5)
      RefreshRules();
    SetStatus(std::string("Tab: ") + KTabNames[Tab_]);
  }

  void RepopulateActiveTab() {
    if (Tab_ >= 0 && Tab_ < 4)
      Populate(Tab_);
    else if (Tab_ == 4)
      PopulateHistory();
    else if (Tab_ == 6)
      Populate(4);
    else if (Tab_ == 7)
      PopulateAlerts();
  }

  // ---- 事件表 ----

  void Populate(int Index) {
    if (Index < 0 || Index >= KMonitorStreamCount)
      return;
    std::vector<MonitorEventRow> Rows;
    {
      std::lock_guard<std::mutex> Lock(State_->Streams[static_cast<size_t>(Index)].Mutex);
      Rows = State_->Streams[static_cast<size_t>(Index)].Rows;
    }
    std::vector<TuiRow> TableRows;
    TableRows.reserve(Rows.size());
    for (const MonitorEventRow &Event : Rows) {
      TuiRow Row;
      Row.Cells = {Utf8(Event.Text)};
      Row.Detail = Utf8(Event.Detail.isEmpty() ? Event.Text : Event.Detail);
      TableRows.push_back(std::move(Row));
    }
    TuiTable &Table = Index == 4 ? Devices_ : Tables_[static_cast<size_t>(Index)];
    Table.Headers = {"Event"};
    Table.RightAlign = {false};
    Table.Filter = Filter;
    Table.Rows = std::move(TableRows);
    Table.Rebuild();
  }

  void PopulateAlerts() {
    std::vector<MonitorEventRow> Rows;
    {
      std::lock_guard<std::mutex> Lock(State_->Alerts.Mutex);
      Rows = State_->Alerts.Rows;
    }
    std::vector<TuiRow> TableRows;
    for (const MonitorEventRow &Event : Rows) {
      TuiRow Row;
      Row.Cells = {Utf8(Event.Text)};
      Row.Detail = Utf8(Event.Detail.isEmpty() ? Event.Text : Event.Detail);
      TableRows.push_back(std::move(Row));
    }
    Alerts_.Headers = {"Alert"};
    Alerts_.RightAlign = {false};
    Alerts_.Filter = Filter;
    Alerts_.Rows = std::move(TableRows);
    Alerts_.Rebuild();
  }

  void PopulateHistory() {
    std::vector<MonitorHistoryRow> Rows;
    {
      std::lock_guard<std::mutex> Lock(State_->HistoryMutex);
      Rows = State_->HistoryRows;
    }
    std::vector<TuiRow> TableRows;
    TableRows.reserve(Rows.size());
    for (const MonitorHistoryRow &Event : Rows) {
      TuiRow Row;
      Row.Cells = {Utf8(Event.Timestamp), Utf8(Event.Type),
                   std::to_string(Event.Pid), Utf8(Event.Process),
                   Utf8(Event.Detail)};
      TableRows.push_back(std::move(Row));
    }
    History_.Headers = {"Timestamp", "Type", "PID", "Process", "Detail"};
    History_.RightAlign = {false, false, true, false, false};
    History_.Filter = Filter;
    History_.Rows = std::move(TableRows);
    History_.Rebuild();
    SetStatus("Events: " + std::to_string(Rows.size()));
  }

  void ShowDetails() {
    TuiTable *Table = nullptr;
    if (Tab_ >= 0 && Tab_ < 4)
      Table = &Tables_[static_cast<size_t>(Tab_)];
    else if (Tab_ == 4)
      Table = &History_;
    else if (Tab_ == 6)
      Table = &Devices_;
    else if (Tab_ == 7)
      Table = &Alerts_;
    if (!Table) {
      Notify("This tab has no event details.", NoticeKind::Info);
      return;
    }
    const TuiRow *Row = Table->Current();
    if (!Row) {
      Notify("Select an event first.", NoticeKind::Warning);
      return;
    }
    std::vector<TuiRow> Rows;
    std::string Line;
    for (char C : Row->Detail) {
      if (C == '\n') {
        Rows.push_back(TuiRow{{Line}, {}});
        Line.clear();
      } else if (C != '\r') {
        Line += C;
      }
    }
    if (!Line.empty())
      Rows.push_back(TuiRow{{Line}, {}});
    DetailDialog(*Dialogs, "Monitor event details", Rows);
  }

  void ClearStream(int Index) {
    MonitorStreamState &Stream = State_->Streams[static_cast<size_t>(Index)];
    {
      std::lock_guard<std::mutex> Lock(Stream.Mutex);
      Stream.Rows.clear();
      Stream.Version.fetch_add(1, std::memory_order_relaxed);
    }
    Populate(Index);
  }

  // ---- 采集控制 ----

  void StartActive() {
    if (Tab_ == 0)
      StartSystem();
    else if (Tab_ == 1)
      StartProcess();
    else if (Tab_ == 2)
      StartNetwork();
    else if (Tab_ == 3)
      StartHttp();
    else if (Tab_ == 6)
      StartDevices();
    else
      Notify("Nothing to start on this tab.", NoticeKind::Info);
  }

  void StopActive() {
    if (Tab_ == 0)
      StopSystem();
    else if (Tab_ == 1)
      StopProcess();
    else if (Tab_ == 2)
      StopNetwork();
    else if (Tab_ == 3)
      StopHttp();
    else if (Tab_ == 6)
      StopDevices();
    else
      Notify("Nothing to stop on this tab.", NoticeKind::Info);
  }

  void StartSystem() {
    if (SystemStopping_ || SystemRunning_.exchange(true))
      return;
    ClearStream(0);
    if (SystemMode_ == 0) {
      SetStatus("Starting ETWMode...");
      std::vector<EtwProvider> ProvidersSnapshot;
      {
        std::lock_guard<std::mutex> Lock(EtwStateMutex_);
        ProvidersSnapshot = SelectedProviders_;
      }
      const std::weak_ptr<MonitorSharedState> WeakState = State_;
      SetEtwEventCallback([this, WeakState](const ParsedEvent &Event) {
        EtwDisplayFilter FilterCopy;
        {
          std::lock_guard<std::mutex> Lock(EtwStateMutex_);
          FilterCopy = EtwFilter_;
        }
        if (!EtwEventMatchesFilter(Event, FilterCopy))
          return;
        if (const auto State = WeakState.lock())
          PushMonitorEvent(State, 0, FormatEtwEvent(Event));
      });
      EtwThread_ = std::thread([this, WeakState,
                                Providers = std::move(ProvidersSnapshot)] {
        if (StartKernelTrace(&Providers)) {
          TuiPost([this] {
            if (SystemRunning_)
              SetStatus("ETWMode running");
          });
          OpenAndProcessTrace();
        } else if (const auto State = WeakState.lock()) {
          PushMonitorEvent(State, 0,
                           QString("ETW start failed: %1")
                               .arg(GetLastStartTraceStatus()));
        }
        StopTrace();
        SetEtwEventCallback(nullptr);
        TuiPost([this] { FinishSystemStop(); });
      });
    } else {
      try {
        MonitorFilter MonitorFilterValue{};
        MonitorFilterValue.Size = sizeof(MonitorFilterValue);
        MonitorFilterValue.Version = MONITOR_PROTOCOL_VERSION;
        MonitorFilterValue.EventMask = ~0ull;
        MonitorFilterValue.ProcessId = FilterPid_.toUInt();
        const std::wstring Prefix =
            QString::fromStdString(FilterPrefix_).toStdWString();
        if (!Prefix.empty())
          wcsncpy_s(MonitorFilterValue.PathPrefix, Prefix.c_str(), _TRUNCATE);
        if (RegistryPreview_) {
          MonitorFilterValue.Flags |= MONITOR_FILTER_REGISTRY_PREVIEW;
          MonitorFilterValue.RegistryPreviewBytes = 256;
        }
        AegisSentinelSetFilter(MonitorFilterValue);
        Kernel_ = std::make_unique<KernelMonitor>();
        const std::weak_ptr<MonitorSharedState> WeakState = State_;
        Kernel_->SetCallback([WeakState](const MonitorEvent &Event) {
          if (const auto State = WeakState.lock()) {
            if (Event.Version != MONITOR_PROTOCOL_VERSION) {
              static std::atomic_bool Warned{false};
              if (!Warned.exchange(true))
                PushMonitorEvent(State, 0,
                                 QString("AegisSentinel protocol mismatch (driver "
                                         "v%1, app v%2) — reload the driver and "
                                         "restart the app")
                                     .arg(Event.Version)
                                     .arg(MONITOR_PROTOCOL_VERSION));
              return;
            }
            PushMonitorEvent(State, 0, FormatKernelMonitorEvent(Event),
                             FormatKernelMonitorEventDetail(Event));
          }
        });
        if (!Kernel_->Start())
          throw std::runtime_error("Kernel monitor start failed");
        SetStatus("KernelMode running");
        RefreshKernelTelemetry();
      } catch (const std::exception &Error) {
        Kernel_.reset();
        SystemRunning_ = false;
        FinishSystemStop();
        Notify(QString::fromLocal8Bit(Error.what()).toStdString(),
               NoticeKind::Error);
        return;
      }
    }
    if (SystemRunning_)
      Notify("System monitor started.", NoticeKind::Success);
  }

  void FinishSystemStop() {
    SystemRunning_ = false;
    SystemStopping_ = false;
    SetStatus("Stopped");
    KernelTelemetryStatus_ = "V3 telemetry: idle";
  }

  void StopSystem() {
    if (SystemStopping_.exchange(true))
      return;
    if (!SystemRunning_.exchange(false) && !EtwThread_.joinable() && !Kernel_) {
      SystemStopping_ = false;
      return;
    }
    SetStatus("Stopping...");
    std::thread EtwWorker = std::move(EtwThread_);
    std::unique_ptr<KernelMonitor> KernelWorker = std::move(Kernel_);
    std::thread([this, EtwWorker = std::move(EtwWorker),
                 KernelWorker = std::move(KernelWorker)]() mutable {
      StopTrace();
      SetEtwEventCallback(nullptr);
      if (KernelWorker) {
        KernelWorker->Stop();
        KernelWorker.reset();
      }
      if (EtwWorker.joinable())
        EtwWorker.join();
      TuiPost([this] {
        FinishSystemStop();
        Notify("System monitor stopped.", NoticeKind::Success);
      });
    }).detach();
  }

  void RefreshKernelTelemetry() {
    if (!SystemRunning_ || SystemMode_ != 1)
      return;
    if (KernelTelemetryRefreshing_.exchange(true))
      return;
    TuiAsyncVoid(
        [this] {
          MonitorStats Stats{};
          const bool Ok = AegisSentinelQueryStats(&Stats);
          const DWORD Error = Ok ? ERROR_SUCCESS : GetLastError();
          TuiPost([this, Ok, Error, Stats] {
            KernelTelemetryRefreshing_ = false;
            if (!SystemRunning_ || SystemMode_ != 1)
              return;
            if (!Ok) {
              KernelTelemetryStatus_ = "V3 telemetry unavailable (" +
                                       std::to_string(Error) + ")";
              return;
            }
            const uint64_t Dropped =
                Stats.SystemDropped + Stats.FileDropped + Stats.NetworkDropped;
            KernelTelemetryStatus_ =
                "V3 seq " + std::to_string(Stats.LastSequence) + " | queue S " +
                std::to_string(Stats.SystemQueued) + "/" +
                std::to_string(Stats.SystemHighWatermark) + " F " +
                std::to_string(Stats.FileQueued) + "/" +
                std::to_string(Stats.FileHighWatermark) + " N " +
                std::to_string(Stats.NetworkQueued) + "/" +
                std::to_string(Stats.NetworkHighWatermark) + " (cap " +
                std::to_string(Stats.QueueCapacity) + ") | lost " +
                std::to_string(Dropped);
            SetStatus(KernelTelemetryStatus_);
          });
        },
        [] {});
  }

  void StartProcess() {
    if (ProcessStopping_ || ProcessRunning_)
      return;
    const QString Target = Target_.empty() ? QString()
                                           : QString::fromStdString(Target_);
    if (Target.isEmpty()) {
      Notify("Process not found.", NoticeKind::Error);
      return;
    }
    DWORD Pid = Target.toUInt();
    if (!Pid)
      Pid = GetProcessIdByName(Target.toStdWString());
    if (!Pid) {
      Notify("Process not found.", NoticeKind::Error);
      return;
    }
    ClearStream(1);
    const std::weak_ptr<MonitorSharedState> WeakState = State_;
    Dll_ = std::make_unique<DllMonitor>();
    Dll_->SetCallback([WeakState, Target](const DllEvent &Event) {
      if (const auto State = WeakState.lock())
        PushMonitorEvent(
            State, 1,
            QString("%1 | PID %2 | TID %3 | Timestamp %4 | Target %5")
                .arg(QString::fromStdString(Event.Category))
                .arg(Event.ProcessId)
                .arg(Event.ThreadId)
                .arg(Event.Timestamp)
                .arg(Target));
    });
    if (!Dll_->Start()) {
      Dll_.reset();
      Notify("Failed to create monitor pipe.", NoticeKind::Error);
      return;
    }
    const std::filesystem::path DllPath =
        std::filesystem::path(QCoreApplication::applicationDirPath().toStdWString()) /
        L"ExtraDLL" / L"MonitorHook.dll";
    if (!std::filesystem::exists(DllPath)) {
      Dll_->Stop();
      Dll_.reset();
      Notify("MonitorHook.dll was not found.", NoticeKind::Error);
      return;
    }
    EnableDebugPrivilege();
    BOOL Result = FALSE;
    switch (ProcessMethod_) {
    case 0: Result = Inject_RemoteThread(Pid, DllPath.wstring()); break;
    case 1: Result = Inject_NtCreateThreadEx(Pid, DllPath.wstring()); break;
    case 2: Result = Inject_QueueUserAPC(Pid, DllPath.wstring()); break;
    case 3: Result = Inject_SetWindowsHookEx(Pid, DllPath.wstring()); break;
    case 4: Result = DllInjectApc(Pid, DllPath.wstring().c_str()); break;
    case 5: Result = DllInjectThread(Pid, DllPath.wstring().c_str()); break;
    default: break;
    }
    if (!Result) {
      Dll_->Stop();
      Dll_.reset();
      Notify("MonitorHook.dll injection failed.", NoticeKind::Error);
      return;
    }
    ProcessRunning_ = true;
    SetStatus("Monitoring PID " + std::to_string(Pid));
    Notify("Process monitor started.", NoticeKind::Success);
  }

  void StopProcess() {
    if (ProcessStopping_.exchange(true))
      return;
    if (!ProcessRunning_.exchange(false) && !Dll_) {
      ProcessStopping_ = false;
      return;
    }
    SetStatus("Stopping...");
    std::unique_ptr<DllMonitor> DllWorker = std::move(Dll_);
    std::thread([this, DllWorker = std::move(DllWorker)]() mutable {
      if (DllWorker) {
        DllWorker->Stop();
        DllWorker.reset();
      }
      TuiPost([this] {
        ProcessStopping_ = false;
        SetStatus("Stopped");
        Notify("Process monitor stopped.", NoticeKind::Success);
      });
    }).detach();
  }

  void StartNetwork() {
    if (NetworkRunning_)
      return;
    if (HttpRunning_) {
      Notify("Stop HTTP(S) capture before starting Network capture.",
             NoticeKind::Warning);
      return;
    }
    ClearStream(2);
    const std::filesystem::path Directory =
        std::filesystem::path(QCoreApplication::applicationDirPath().toStdWString()) /
        L"ExtraDLL";
    if (!NetMon_LoadWinDivertDllFromDirectory(Directory.c_str())) {
      Notify(Utf8(QString("Unable to load WinDivert.dll (error %1).")
                      .arg(GetLastError())),
             NoticeKind::Error);
      return;
    }
    if (!NetMon_IsWinDivertDriverRunning()) {
      Notify(Utf8(QString("WinDivert driver is not running (error %1).")
                      .arg(GetLastError())),
             NoticeKind::Error);
      return;
    }
    if (!NetMon_Start(MonitorNetworkCallback)) {
      Notify(Utf8(QString("Network capture failed (error %1).")
                      .arg(GetLastError())),
             NoticeKind::Error);
      return;
    }
    NetworkRunning_ = true;
    SetStatus("WinDivert network capture running");
    Notify("Network capture started.", NoticeKind::Success);
  }

  void StopNetwork() {
    if (!NetworkRunning_.exchange(false))
      return;
    NetMon_Stop();
    SetStatus("Stopped");
    Notify("Network capture stopped.", NoticeKind::Success);
  }

  void StartHttp() {
    if (HttpRunning_)
      return;
    if (NetworkRunning_) {
      Notify("Stop Network capture before starting HTTP(S) capture.",
             NoticeKind::Warning);
      return;
    }
    if (ProxyPort_ < 1 || ProxyPort_ > 65535) {
      Notify("Proxy port must be between 1 and 65535.", NoticeKind::Error);
      return;
    }
    ClearStream(3);
    const std::filesystem::path Directory(
        QCoreApplication::applicationDirPath().toStdWString());
    http_capture::Config Config;
    Config.CaptureHttp = true;
    Config.CaptureHttps = true;
    Config.HttpsMitm = true;
    Config.ProxyPort = static_cast<uint16_t>(ProxyPort_);
    Config.WinDivertDllPath = (Directory / L"ExtraDLL" / L"WinDivert.dll").string();
    Config.CaCertPath = (Directory / L"Data" / L"CA_CERT.pem").string();
    Config.CaKeyPath = (Directory / L"Data" / L"CA_KEY.pem").string();
    Http_ = std::make_unique<http_capture::HttpCapture>(Config);
    const std::weak_ptr<MonitorSharedState> WeakState = State_;
    Http_->OnHttpRequest(
        [WeakState](const http_capture::FlowInfo &Flow,
                    const http_capture::HttpRequest &Request) {
          if (const auto State = WeakState.lock()) {
            const QString Host =
                Request.Host.empty() ? HttpFlowAddress(Flow.DstIp)
                                     : QString::fromStdString(Request.Host);
            const QString Text =
                QString("HTTP REQUEST | %1 %2%3 | %4:%5 -> %6:%7 | %8 bytes")
                    .arg(QString::fromStdString(Request.Method), Host,
                         QString::fromStdString(Request.Url),
                         HttpFlowAddress(Flow.SrcIp))
                    .arg(Flow.SrcPort)
                    .arg(HttpFlowAddress(Flow.DstIp))
                    .arg(Flow.DstPort)
                    .arg(Request.Body.size());
            QString Detail = Text + "\n\nHeaders:\n";
            for (const auto &Header : Request.Headers)
              Detail += QString::fromStdString(Header.Name + ": " + Header.Value +
                                               "\n");
            Detail += "\nBody:\n" +
                      QString::fromUtf8(
                          reinterpret_cast<const char *>(Request.Body.data()),
                          static_cast<qsizetype>(Request.Body.size()));
            PushMonitorEvent(State, 3, Text, Detail);
          }
        });
    Http_->OnHttpResponse(
        [WeakState](const http_capture::FlowInfo &Flow,
                    const http_capture::HttpResponse &Response) {
          if (const auto State = WeakState.lock()) {
            const QString Text =
                QString("HTTP RESPONSE | %1 %2 | %3:%4 -> %5:%6 | %7 bytes")
                    .arg(Response.StatusCode)
                    .arg(QString::fromStdString(Response.Reason),
                         HttpFlowAddress(Flow.SrcIp))
                    .arg(Flow.SrcPort)
                    .arg(HttpFlowAddress(Flow.DstIp))
                    .arg(Flow.DstPort)
                    .arg(Response.Body.size());
            QString Detail = Text + "\n\nHeaders:\n";
            for (const auto &Header : Response.Headers)
              Detail += QString::fromStdString(Header.Name + ": " + Header.Value +
                                               "\n");
            Detail += "\nBody:\n" +
                      QString::fromUtf8(
                          reinterpret_cast<const char *>(Response.Body.data()),
                          static_cast<qsizetype>(Response.Body.size()));
            PushMonitorEvent(State, 3, Text, Detail);
          }
        });
    Http_->OnTlsSni([WeakState](const http_capture::FlowInfo &Flow,
                                const http_capture::TlsSniInfo &Sni) {
      if (const auto State = WeakState.lock()) {
        const QString Text = QString("HTTPS SNI | %1 | %2:%3 -> %4:%5")
                                 .arg(QString::fromStdString(Sni.ServerName),
                                      HttpFlowAddress(Flow.SrcIp))
                                 .arg(Flow.SrcPort)
                                 .arg(HttpFlowAddress(Flow.DstIp))
                                 .arg(Flow.DstPort);
        PushMonitorEvent(State, 3, Text,
                         Text + QString("\nTLS version: %1\nClientHello: %2 bytes")
                                    .arg(Sni.TlsVersion)
                                    .arg(Sni.RawClientHello.size()));
      }
    });
    if (!Http_->Start()) {
      const QString Error = QString::fromStdString(Http_->LastError());
      Http_.reset();
      Notify(Utf8(Error.isEmpty()
                      ? QString("HTTP(S) capture failed to start.")
                      : QString("HTTP(S) capture failed to start.\n") + Error),
             NoticeKind::Error);
      return;
    }
    HttpRunning_ = true;
    SetStatus("HTTP(S) capture running | HTTPS proxy 127.0.0.1:" +
              std::to_string(ProxyPort_));
    Notify("HTTP(S) capture started.", NoticeKind::Success);
  }

  void StopHttp() {
    if (Http_) {
      Http_->Stop();
      Http_.reset();
    }
    if (!HttpRunning_.exchange(false))
      return;
    SetStatus("Stopped");
    Notify("HTTP(S) capture stopped.", NoticeKind::Success);
  }

  void StartDevices() {
    if (DeviceRunning_->exchange(true))
      return;
    SetStatus("Listening for device arrival / removal...");
    const auto State = State_;
    const auto Running = DeviceRunning_;
    std::thread([State, Running] {
      while (Running->load()) {
        MonitorSimpleEvent Event{};
        if (AegisSentinelPopPnpEvent(&Event)) {
          PushMonitorEvent(State, 4, FormatDeviceEvent(Event),
                           FormatDeviceEventDetail(Event));
        } else {
          Sleep(50);
        }
      }
    }).detach();
  }

  void StopDevices() {
    if (!DeviceRunning_->exchange(false))
      return;
    SetStatus("Stopped");
    Notify("Device monitoring stopped.", NoticeKind::Success);
  }

  // ---- ETW 提供程序 / 过滤器 ----

  void ProvidersCommand(const std::vector<std::string> &Args) {
    if (Args.empty()) {
      TuiAsyncVoid(
          [this] {
            std::vector<EtwProvider> Found;
            const bool Ok = EnumerateSystemProviders(Found);
            std::vector<TuiRow> Rows;
            {
              std::lock_guard<std::mutex> Lock(EtwStateMutex_);
              const auto Selected = [this](const GUID &Guid) {
                return std::any_of(
                    SelectedProviders_.begin(), SelectedProviders_.end(),
                    [&Guid](const EtwProvider &Provider) {
                      return memcmp(&Provider.Guid, &Guid, sizeof(GUID)) == 0;
                    });
              };
              Rows.push_back(TuiRow{{"[kernel]", "", ""}, {}});
              for (int Index = 0; Index < KProviderCount; ++Index)
                Rows.push_back(TuiRow{
                    {Utf8(QString::fromStdWString(KProviders[Index].Name)),
                     Utf8(EtwGuidToString(KProviders[Index].Guid)),
                     Selected(KProviders[Index].Guid) ? "on" : "off"},
                    {}});
              Rows.push_back(TuiRow{{"[system]", "", ""}, {}});
              for (int Index = 0; Index < KSystemProviderCount; ++Index)
                Rows.push_back(TuiRow{
                    {Utf8(QString::fromStdWString(KSystemProviders[Index].Name)),
                     Utf8(EtwGuidToString(KSystemProviders[Index].Guid)),
                     Selected(KSystemProviders[Index].Guid) ? "on" : "off"},
                    {}});
            }
            TuiPost([this, Ok, Found = std::move(Found), Rows = std::move(Rows)] {
              Notify(Utf8(Ok ? QString("Found %1 system provider(s).").arg(Found.size())
                             : QString("Failed to enumerate system providers "
                                       "(TdhEnumerateProviders).")),
                     Ok ? NoticeKind::Success : NoticeKind::Error);
              DetailDialog(*Dialogs, "ETW Providers", Rows);
            });
          },
          [] {});
      return;
    }
    // name=on|off
    std::lock_guard<std::mutex> Lock(EtwStateMutex_);
    for (const std::string &Arg : Args) {
      const size_t Equals = Arg.find('=');
      if (Equals == std::string::npos)
        continue;
      const std::string Name = Arg.substr(0, Equals);
      const bool Enable = StartsWithCi(Arg.substr(Equals + 1), "on");
      const auto Match = std::find_if(
          SelectedProviders_.begin(), SelectedProviders_.end(),
          [&Name](const EtwProvider &Provider) {
            return StartsWithCi(
                QString::fromStdWString(Provider.Name).toStdString(), Name);
          });
      if (Enable && Match == SelectedProviders_.end()) {
        const auto Source = std::find_if(
            std::begin(KProviders), std::end(KProviders),
            [&Name](const EtwProvider &Provider) {
              return StartsWithCi(
                  QString::fromStdWString(Provider.Name).toStdString(), Name);
            });
        if (Source != std::end(KProviders))
          SelectedProviders_.push_back(*Source);
      } else if (!Enable && Match != SelectedProviders_.end()) {
        SelectedProviders_.erase(Match);
      }
    }
    Notify("Providers: " + std::to_string(SelectedProviders_.size()),
           NoticeKind::Success);
  }

  void EtwFilterCommand(const std::vector<std::string> &Args) {
    std::lock_guard<std::mutex> Lock(EtwStateMutex_);
    if (Args.empty()) {
      DetailDialog(*Dialogs, "ETW Event Filter",
                   FieldRows({{"Filter", Utf8(EtwFilterSummary(EtwFilter_))}}));
      return;
    }
    if (StartsWithCi(Args.front(), "off")) {
      EtwFilter_ = EtwDisplayFilter{};
      SetStatus("ETW filter: off");
      return;
    }
    EtwFilter_.Enabled = true;
    for (const std::string &Arg : Args) {
      const size_t Equals = Arg.find('=');
      if (Equals == std::string::npos)
        continue;
      const QString Key = QString::fromStdString(Arg.substr(0, Equals));
      const QString Value = QString::fromStdString(Arg.substr(Equals + 1));
      if (Key.compare("pid", Qt::CaseInsensitive) == 0)
        EtwFilter_.Pid = Value;
      else if (Key.compare("process", Qt::CaseInsensitive) == 0)
        EtwFilter_.ProcessName = Value;
      else if (Key.compare("file", Qt::CaseInsensitive) == 0)
        EtwFilter_.FilePath = Value;
      else if (Key.compare("event", Qt::CaseInsensitive) == 0)
        EtwFilter_.EventId = Value;
      else if (Key.compare("behavior", Qt::CaseInsensitive) == 0)
        EtwFilter_.Behavior = Value;
      else if (Key.compare("addr", Qt::CaseInsensitive) == 0)
        EtwFilter_.NetworkAddress = Value;
      else if (Key.compare("registry", Qt::CaseInsensitive) == 0)
        EtwFilter_.RegistryPath = Value;
      else if (Key.compare("if", Qt::CaseInsensitive) == 0)
        EtwFilter_.Interface = Value;
    }
    SetStatus(Utf8(EtwFilterSummary(EtwFilter_)));
  }

  // ---- 规则 ----

  void RefreshRules() {
    if (RulesRefreshing_.exchange(true))
      return;
    SetStatus("Loading rules...");
    TuiAsyncVoid(
        [this] {
          auto List = std::make_shared<MonitorRuleList>();
          const bool Ok = AegisSentinelEnumerateRules(List.get());
          const DWORD Error = Ok ? ERROR_SUCCESS : GetLastError();
          TuiPost([this, Ok, Error, List] {
            RulesRefreshing_ = false;
            if (!Ok) {
              SetStatus("Rules unavailable (error " + std::to_string(Error) + ")");
              return;
            }
            RuleList_.assign(List->Rules, List->Rules + List->Count);
            PopulateRules();
          });
        },
        [] {});
  }

  void PopulateRules() {
    std::vector<TuiRow> Rows;
    Rows.reserve(RuleList_.size());
    for (const MonitorRule &Rule : RuleList_) {
      const QString Type = Rule.Type == MonitorRuleFile
                               ? "File"
                               : Rule.Type == MonitorRuleRegistry ? "Registry"
                                                                  : "Network";
      const QString Action = Rule.Action == MonitorRuleBlock ? "Block" : "Audit";
      TuiRow Row;
      Row.Cells = {std::to_string(Rule.Id), Utf8(Type), Utf8(Action),
                   std::to_string(Rule.ProcessId), std::to_string(Rule.Protocol),
                   std::to_string(Rule.RemotePort),
                   Utf8(QString::fromWCharArray(Rule.Target)),
                   std::to_string(Rule.HitCount)};
      Rows.push_back(std::move(Row));
    }
    Rules_.Headers = {"ID", "Type", "Action", "PID", "Protocol", "Remote Port",
                      "Target", "Hit count"};
    Rules_.RightAlign = {true, false, false, true, true, true, false, true};
    Rules_.Filter = Filter;
    Rules_.Rows = std::move(Rows);
    Rules_.Rebuild();
    SetStatus("Rules: " + std::to_string(RuleList_.size()));
    PersistRulesIfDirty();
  }

  bool ParseRuleField(const std::string &Value, ULONG Maximum, ULONG &Out,
                      const char *Field) {
    bool Ok = false;
    const qulonglong Number = QString::fromStdString(Value).toULongLong(&Ok);
    if (!Ok || Number > Maximum) {
      Notify(std::string("Invalid ") + Field + ".", NoticeKind::Error);
      return false;
    }
    Out = static_cast<ULONG>(Number);
    return true;
  }

  void AddRule(const std::vector<std::string> &Args) {
    if (Args.size() < 2) {
      Notify("Usage: rules-add <file|registry|network> <audit|block> "
             "[pid=..] [protocol=..] [port=..] [target=..]",
             NoticeKind::Warning);
      return;
    }
    MonitorRule Rule{};
    const std::string Type = LowerAscii(Args[0]);
    Rule.Type = Type == "file" ? MonitorRuleFile
                : Type == "registry" ? MonitorRuleRegistry
                                     : MonitorRuleNetwork;
    Rule.Action = StartsWithCi(Args[1], "block") ? MonitorRuleBlock
                                                 : MonitorRuleAudit;
    std::string Target;
    for (size_t Index = 2; Index < Args.size(); ++Index) {
      const size_t Equals = Args[Index].find('=');
      if (Equals == std::string::npos)
        continue;
      const std::string Key = LowerAscii(Args[Index].substr(0, Equals));
      const std::string Value = Args[Index].substr(Equals + 1);
      if (Key == "pid") {
        if (!ParseRuleField(Value, 0xFFFFFFFFu, Rule.ProcessId, "PID"))
          return;
      } else if (Key == "protocol") {
        if (!ParseRuleField(Value, 255, Rule.Protocol, "protocol"))
          return;
      } else if (Key == "port") {
        if (!ParseRuleField(Value, 65535, Rule.RemotePort, "remote port"))
          return;
      } else if (Key == "target") {
        Target = Value;
      }
    }
    if (Rule.Type != MonitorRuleNetwork) {
      if (Target.empty()) {
        Notify("A path or registry prefix is required for this rule.",
               NoticeKind::Error);
        return;
      }
      CopyWide(Rule.Target, _countof(Rule.Target), Target);
    }
    if (!AegisSentinelOperateRule(MonitorRuleAdd, &Rule)) {
      Notify(Utf8(QString("Failed to add rule (error %1).").arg(GetLastError())),
             NoticeKind::Error);
      return;
    }
    Notify("Rule added.", NoticeKind::Success);
    RulesDirty_ = true;
    RefreshRules();
  }

  void RemoveRule(const std::vector<std::string> &Args) {
    ULONG Id = 0;
    if (!Args.empty()) {
      if (!ParseRuleField(Args.front(), 0xFFFFFFFFu, Id, "rule ID"))
        return;
    } else {
      const TuiRow *Row = Rules_.Current();
      if (!Row) {
        Notify("Select a rule first.", NoticeKind::Error);
        return;
      }
      Id = static_cast<ULONG>(QString::fromStdString(Row->Cells[0]).toULong());
    }
    MonitorRule Rule{};
    Rule.Id = Id;
    if (!AegisSentinelOperateRule(MonitorRuleRemove, &Rule)) {
      Notify(Utf8(QString("Failed to remove rule (error %1).").arg(GetLastError())),
             NoticeKind::Error);
      return;
    }
    Notify("Rule removed.", NoticeKind::Success);
    RulesDirty_ = true;
    RefreshRules();
  }

  static QJsonArray RulesToJson(const std::vector<MonitorRule> &List) {
    QJsonArray Array;
    for (const MonitorRule &Rule : List) {
      QJsonObject Object;
      Object["type"] = static_cast<int>(Rule.Type);
      Object["action"] = static_cast<int>(Rule.Action);
      Object["pid"] = static_cast<qint64>(Rule.ProcessId);
      Object["protocol"] = static_cast<int>(Rule.Protocol);
      Object["port"] = static_cast<int>(Rule.RemotePort);
      Object["target"] = QString::fromWCharArray(Rule.Target);
      Array.append(Object);
    }
    return Array;
  }

  static std::vector<MonitorRule> RulesFromJson(const QJsonArray &Array) {
    std::vector<MonitorRule> List;
    for (const auto &Value : Array) {
      const QJsonObject Object = Value.toObject();
      MonitorRule Rule{};
      Rule.Type = static_cast<ULONG>(Object["type"].toInt(1));
      Rule.Action = static_cast<ULONG>(Object["action"].toInt(1));
      Rule.ProcessId = static_cast<ULONG>(Object["pid"].toInteger());
      Rule.Protocol = static_cast<ULONG>(Object["protocol"].toInt());
      Rule.RemotePort = static_cast<ULONG>(Object["port"].toInt());
      const QString Target = Object["target"].toString();
      if (!Target.isEmpty())
        wcsncpy_s(Rule.Target, Target.toStdWString().c_str(), _TRUNCATE);
      List.push_back(Rule);
    }
    return List;
  }

  void PersistRulesIfDirty() {
    if (!RulesDirty_)
      return;
    RulesDirty_ = false;
    SetConfigurationValue("Monitor", "RulesV3", RulesToJson(RuleList_));
  }

  void ExportRules() {
    SetConfigurationValue("Monitor", "RulesV3", RulesToJson(RuleList_));
    SaveConfiguration();
    Notify("Rules saved to Monitor/RulesV3.", NoticeKind::Success);
  }

  void ImportRules() {
    const QJsonArray Saved =
        ConfigurationValue("Monitor", "RulesV3", QJsonArray()).toArray();
    if (Saved.isEmpty()) {
      Notify("No saved rules in Monitor/RulesV3.", NoticeKind::Warning);
      return;
    }
    ULONG Added = 0;
    for (const MonitorRule &Rule : RulesFromJson(Saved))
      if (AegisSentinelOperateRule(MonitorRuleAdd, &Rule))
        ++Added;
    Notify("Imported " + std::to_string(Added) + " rule(s).", NoticeKind::Success);
    RulesDirty_ = true;
    RefreshRules();
  }

  void ExportHistory(const std::vector<std::string> &Args) {
    if (Args.empty()) {
      Notify("Usage: history-export <path>", NoticeKind::Warning);
      return;
    }
    const QString Path = QString::fromStdString(Args.front());
    std::vector<MonitorHistoryRow> Rows;
    {
      std::lock_guard<std::mutex> Lock(State_->HistoryMutex);
      Rows = State_->HistoryRows;
    }
    QFile File(Path);
    if (!File.open(QIODevice::WriteOnly | QIODevice::Text)) {
      Notify(Utf8("Failed to export events: " + File.errorString()),
             NoticeKind::Error);
      return;
    }
    QTextStream Out(&File);
    Out << "Timestamp,Type,PID,Process,Detail\n";
    for (const auto &Event : Rows)
      Out << Event.Timestamp << "," << Event.Type << "," << Event.Pid << ","
          << Event.Process << ",\"" << Event.Detail << "\"\n";
    if (Out.status() != QTextStream::Ok) {
      Notify(Utf8("Failed to export events: " + File.errorString()),
             NoticeKind::Error);
      return;
    }
    Notify(Utf8(QString("Exported %1 event(s).").arg(Rows.size())),
           NoticeKind::Success);
  }

  // ---- 设备过滤 ----

  void ApplyDeviceFilter(const std::vector<std::string> &Args) {
    MonitorPnpFilter Filter{};
    Filter.Size = sizeof(Filter);
    Filter.Version = MONITOR_PROTOCOL_VERSION;
    ULONG Flags = 0;
    if (DeviceArrival_)
      Flags |= MONITOR_PNP_FILTER_FLAG_ARRIVAL;
    if (DeviceRemoval_)
      Flags |= MONITOR_PNP_FILTER_FLAG_REMOVAL;
    if (DeviceBlock_)
      Flags |= MONITOR_PNP_FILTER_FLAG_BLOCK;
    Filter.Flags = Flags;
    std::string Hardware;
    std::string Vendor;
    std::string Product;
    std::string Instance;
    std::string ClassGuid;
    for (const std::string &Arg : Args) {
      const size_t Equals = Arg.find('=');
      if (Equals == std::string::npos)
        continue;
      const std::string Key = LowerAscii(Arg.substr(0, Equals));
      const std::string Value = Arg.substr(Equals + 1);
      if (Key == "hardware" || Key == "hwid")
        Hardware = Value;
      else if (Key == "vid" || Key == "vendor")
        Vendor = Value;
      else if (Key == "pid" || Key == "product")
        Product = Value;
      else if (Key == "instance")
        Instance = Value;
      else if (Key == "class")
        ClassGuid = Value;
      else if (Key == "block")
        DeviceBlock_ = StartsWithCi(Value, "on") || StartsWithCi(Value, "1");
    }
    if (!ClassGuid.empty()) {
      const QUuid Guid(QString::fromStdString(ClassGuid));
      if (Guid.isNull()) {
        Notify("Invalid interface class GUID.", NoticeKind::Error);
        return;
      }
      memcpy(&Filter.InterfaceClass, &Guid, sizeof(GUID));
      Filter.MatchAllInterfaces = FALSE;
    } else {
      Filter.MatchAllInterfaces = TRUE;
    }
    CopyWide(Filter.HardwareIdPrefix, _countof(Filter.HardwareIdPrefix), Hardware);
    CopyWide(Filter.VendorId, _countof(Filter.VendorId), Vendor);
    CopyWide(Filter.ProductId, _countof(Filter.ProductId), Product);
    CopyWide(Filter.InstancePrefix, _countof(Filter.InstancePrefix), Instance);
    DeviceHardwareId_ = Hardware;
    if (!AegisSentinelSetPnpFilter(Filter, MONITOR_PNP_OP_SET_FILTER)) {
      Notify(Utf8(QString("Apply filter failed (error %1).").arg(GetLastError())),
             NoticeKind::Error);
      return;
    }
    Notify("Device filter applied.", NoticeKind::Success);
  }

  void QueryDeviceFilter() {
    MonitorPnpFilter Filter{};
    if (!AegisSentinelQueryPnpFilter(&Filter)) {
      Notify(Utf8(QString("Query filter failed (error %1).").arg(GetLastError())),
             NoticeKind::Error);
      return;
    }
    DetailDialog(*Dialogs, "Device Filter",
                 FieldRows({{"Hardware ID",
                             Utf8(QString::fromWCharArray(Filter.HardwareIdPrefix))},
                            {"VID", Utf8(QString::fromWCharArray(Filter.VendorId))},
                            {"PID", Utf8(QString::fromWCharArray(Filter.ProductId))},
                            {"Instance",
                             Utf8(QString::fromWCharArray(Filter.InstancePrefix))},
                            {"Arrival", (Filter.Flags & MONITOR_PNP_FILTER_FLAG_ARRIVAL)
                                            ? "on" : "off"},
                            {"Removal", (Filter.Flags & MONITOR_PNP_FILTER_FLAG_REMOVAL)
                                            ? "on" : "off"},
                            {"Blocking", (Filter.Flags & MONITOR_PNP_FILTER_FLAG_BLOCK)
                                             ? "on" : "off"},
                            {"Class", Filter.MatchAllInterfaces
                                          ? "all classes"
                                          : Utf8(QUuid(Filter.InterfaceClass)
                                                     .toString())}}));
  }

  void ClearDeviceFilter() {
    MonitorPnpFilter Filter{};
    Filter.Size = sizeof(Filter);
    Filter.Version = MONITOR_PROTOCOL_VERSION;
    if (!AegisSentinelSetPnpFilter(Filter, MONITOR_PNP_OP_CLEAR_FILTER)) {
      Notify(Utf8(QString("Clear filter failed (error %1).").arg(GetLastError())),
             NoticeKind::Error);
      return;
    }
    DeviceHardwareId_.clear();
    DeviceBlock_ = false;
    Notify("Device filter cleared.", NoticeKind::Success);
  }

  void BlockDevice() {
    const TuiRow *Row = Devices_.Current();
    if (!Row) {
      Notify("Select a device event first.", NoticeKind::Warning);
      return;
    }
    const std::string Text = Row->Cells[0];
    const size_t Separator = Text.rfind(" | ");
    std::string DeviceId =
        Separator == std::string::npos ? Text : Text.substr(Separator + 3);
    if (DeviceId == "BLOCKED" || StartsWithCi(DeviceId, "PID ")) {
      Notify("This event has no usable device ID.", NoticeKind::Warning);
      return;
    }
    DeviceHardwareId_ = DeviceId;
    DeviceBlock_ = true;
    Notify("Device ID prefilled; run 'devices-filter' to block matching devices.",
           NoticeKind::Success);
  }

  int Index_ = 0;
  int Tab_ = 0;
  std::shared_ptr<MonitorSharedState> State_;
  std::array<TuiTable, KMonitorStreamCount> Tables_{};
  TuiTable Devices_;
  TuiTable History_;
  TuiTable Rules_;
  TuiTable Alerts_;
  std::array<uint64_t, KMonitorStreamCount> DisplayedVersions_{};
  uint64_t DisplayedDeviceVersion_ = 0;
  uint64_t DisplayedAlertsVersion_ = 0;
  uint64_t DisplayedHistoryVersion_ = 0;
  int64_t LastVersionTickMs_ = 0;
  int64_t LastRulesTickMs_ = 0;
  int64_t LastTelemetryMs_ = 0;
  std::mutex EtwStateMutex_;
  std::vector<EtwProvider> SelectedProviders_;
  EtwDisplayFilter EtwFilter_;
  int SystemMode_ = 0;
  QString FilterPid_;
  std::string FilterPrefix_;
  bool RegistryPreview_ = false;
  std::string KernelTelemetryStatus_ = "V3 telemetry: idle";
  std::atomic_bool KernelTelemetryRefreshing_{false};
  std::atomic_bool SystemRunning_{false};
  std::atomic_bool SystemStopping_{false};
  std::atomic_bool ProcessRunning_{false};
  std::atomic_bool ProcessStopping_{false};
  std::atomic_bool NetworkRunning_{false};
  std::atomic_bool HttpRunning_{false};
  std::shared_ptr<std::atomic_bool> DeviceRunning_ =
      std::make_shared<std::atomic_bool>(false);
  std::atomic_bool RulesRefreshing_{false};
  std::thread EtwThread_;
  std::unique_ptr<KernelMonitor> Kernel_;
  std::unique_ptr<DllMonitor> Dll_;
  std::unique_ptr<http_capture::HttpCapture> Http_;
  std::string Target_;
  int ProcessMethod_ = 0;
  int ProxyPort_ = 8443;
  std::vector<MonitorRule> RuleList_;
  bool RulesDirty_ = false;
  bool DeviceArrival_ = true;
  bool DeviceRemoval_ = true;
  bool DeviceBlock_ = false;
  std::string DeviceHardwareId_;
};

std::unique_ptr<TuiPage> MakeMonitorPage(int Index) {
  return std::make_unique<MonitorPage>(Index);
}

// ------------------------------------------------------------
// Window 页
// ------------------------------------------------------------

namespace {

struct WindowRow {
  HWND Handle = nullptr;
  DWORD Pid = 0;
  DWORD Tid = 0;
  QString Title;
  QString ClassName;
  QString ProcessPath;
  RECT Rect{};
  RECT ClientRect{};
  LONG Style = 0;
  LONG ExStyle = 0;
  HWND ParentHwnd = nullptr;
  HWND OwnerHwnd = nullptr;
  UINT Dpi = 0;
  int ZIndex = -1;
  DWORD Band = 0xFFFFFFFF;
  ULONG KernelFlags = 0;
  bool FromKernel = false;
  bool Visible = false;
  bool Enabled = false;
  bool Minimized = false;
  bool Maximized = false;
  bool IsHung = false;
  bool IsTopmost = false;
  bool IsLayered = false;
  bool IsToolWindow = false;
  bool IsPopup = false;
  bool IsChild = false;
  bool IsUnicode = false;
  bool IsAppWindow = false;
  UCHAR Alpha = 255;
  int Depth = 0;
};

QString ReadWindowText(HWND Handle) {
  const int Length = GetWindowTextLengthW(Handle);
  if (Length <= 0)
    return {};
  std::wstring Text(static_cast<size_t>(Length) + 1, L'\0');
  GetWindowTextW(Handle, Text.data(), static_cast<int>(Text.size()));
  return QString::fromWCharArray(Text.c_str());
}

QString ReadWindowClassName(HWND Handle) {
  wchar_t ClassName[256]{};
  GetClassNameW(Handle, ClassName, 256);
  return QString::fromWCharArray(ClassName);
}

QString FormatWindowFlags(ULONG Flags) {
  static const struct {
    ULONG Bit;
    const char *Name;
  } Names[] = {
      {WINDOW_FLAG_VISIBLE, "VISIBLE"},
      {WINDOW_FLAG_ENABLED, "ENABLED"},
      {WINDOW_FLAG_HUNG, "HUNG"},
      {WINDOW_FLAG_MINIMIZED, "MINIMIZED"},
      {WINDOW_FLAG_MAXIMIZED, "MAXIMIZED"},
      {WINDOW_FLAG_TOPMOST, "TOPMOST"},
      {WINDOW_FLAG_LAYERED, "LAYERED"},
      {WINDOW_FLAG_TOOLWINDOW, "TOOLWINDOW"},
      {WINDOW_FLAG_POPUP, "POPUP"},
      {WINDOW_FLAG_CHILD, "CHILD"},
      {WINDOW_FLAG_UNICODE, "UNICODE"},
      {WINDOW_FLAG_MDI, "MDI"},
      {WINDOW_FLAG_APPWINDOW, "APPWINDOW"},
      {WINDOW_FLAG_ACTIVE, "ACTIVE"},
      {WINDOW_FLAG_NOACTIVATE, "NOACTIVATE"},
      {WINDOW_FLAG_DISABLED_CLOSE, "DISABLED_CLOSE"},
      {WINDOW_FLAG_CLOAKED, "CLOAKED"},
      {WINDOW_FLAG_SKIPANIMATION, "SKIPANIMATION"},
      {WINDOW_FLAG_SKIPTHEME, "SKIPTHEME"},
      {WINDOW_FLAG_DESTROYED, "DESTROYED"},
  };
  QStringList Set;
  for (const auto &Entry : Names)
    if (Flags & Entry.Bit)
      Set.append(Entry.Name);
  return QString("0x%1").arg(Flags, 8, 16, QChar('0')) +
         (Set.isEmpty() ? QString() : " " + Set.join("|"));
}

DWORD QueryWindowBand(HWND Handle) {
  using GetWindowBandFn = BOOL(WINAPI *)(HWND, PDWORD);
  static GetWindowBandFn GetWindowBand = []() -> GetWindowBandFn {
    HMODULE User32 = GetModuleHandleW(L"user32.dll");
    if (!User32)
      User32 = LoadLibraryW(L"user32.dll");
    if (!User32)
      return nullptr;
    return reinterpret_cast<GetWindowBandFn>(
        GetProcAddress(User32, "GetWindowBand"));
  }();
  if (!GetWindowBand)
    return 0xFFFFFFFF;
  DWORD Band = 0xFFFFFFFF;
  if (!GetWindowBand(Handle, &Band))
    return 0xFFFFFFFF;
  return Band;
}

QString FormatWindowBand(DWORD Band) {
  if (Band == 0xFFFFFFFF)
    return "-";
  static const char *const Names[] = {
      "ZBID_DEFAULT",
      "ZBID_DESKTOP",
      "ZBID_UIACCESS",
      "ZBID_IMMERSIVE_IHM",
      "ZBID_IMMERSIVE_NOTIFICATION",
      "ZBID_IMMERSIVE_APPCHROME",
      "ZBID_IMMERSIVE_MOLL",
      "ZBID_IMMERSIVE_EDGY",
      "ZBID_IMMERSIVE_INACTIVEMOBODY",
      "ZBID_IMMERSIVE_INACTIVEDOCK",
      "ZBID_IMMERSIVE_ACTIVEMOBODY",
      "ZBID_IMMERSIVE_ACTIVEDOCK",
      "ZBID_IMMERSIVE_BACKGROUND",
      "ZBID_IMMERSIVE_SEARCH",
      "ZBID_GENUINE_WINDOWS",
      "ZBID_IMMERSIVE_RESTRICTED",
      "ZBID_SYSTEM_TOOLS",
      "ZBID_LOCK",
      "ZBID_ABOVELOCK_UX",
  };
  if (Band < _countof(Names))
    return Names[Band];
  return QString("ZBID_0x%1").arg(Band, 0, 16);
}

QString WindowProcessName(const WindowRow &Window) {
  if (!Window.ProcessPath.isEmpty()) {
    const QString Name = QFileInfo(Window.ProcessPath).fileName();
    if (!Name.isEmpty())
      return Name;
  }
  return QString("PID %1").arg(Window.Pid);
}

QString WindowStateText(const WindowRow &Window) {
  QStringList States{Window.Visible ? "Visible" : "Hidden",
                     Window.Enabled ? "Enabled" : "Disabled"};
  if (Window.Minimized)
    States.append("Minimized");
  if (Window.Maximized)
    States.append("Maximized");
  if (Window.IsHung)
    States.append("HUNG");
  if (Window.IsTopmost)
    States.append("Topmost");
  return States.join(" | ");
}

QString WindowPropertiesText(const WindowRow &Window) {
  QStringList Properties;
  if (Window.IsTopmost)
    Properties.append("Topmost");
  if (Window.IsLayered)
    Properties.append("Layered");
  if (Window.IsToolWindow)
    Properties.append("ToolWindow");
  if (Window.IsAppWindow)
    Properties.append("AppWindow");
  if (Window.IsPopup)
    Properties.append("Popup");
  if (Window.IsChild)
    Properties.append("Child");
  if (Window.IsUnicode)
    Properties.append("Unicode");
  Properties.append(QString("Alpha=%1").arg(Window.Alpha));
  if (Window.ParentHwnd)
    Properties.append(QString("Parent=0x%1")
                          .arg(reinterpret_cast<quintptr>(Window.ParentHwnd), 0, 16));
  if (Window.OwnerHwnd)
    Properties.append(QString("Owner=0x%1")
                          .arg(reinterpret_cast<quintptr>(Window.OwnerHwnd), 0, 16));
  return Properties.join(" | ");
}

QString WindowRectText(const WindowRow &Window) {
  return QString("(%1,%2)-(%3,%4) %5x%6")
      .arg(Window.Rect.left)
      .arg(Window.Rect.top)
      .arg(Window.Rect.right)
      .arg(Window.Rect.bottom)
      .arg(Window.Rect.right - Window.Rect.left)
      .arg(Window.Rect.bottom - Window.Rect.top);
}

} // namespace

class WindowPage final : public TuiPage {
public:
  explicit WindowPage(int Index) : Index_(Index) { RegisterCommands(); }

  std::string Title() const override { return "Window"; }

  std::string Subtitle() const override {
    return "enumerate / manipulate top-level windows; manage window protection";
  }

  void OnEnter() override {
    Windows_.Headers = {"HWND", "Z", "Band", "Title", "Class", "Process", "PID",
                        "Style", "State", "Flags", "Properties", "Rect", "Dpi"};
    Windows_.RightAlign = {false, true, false, false, false, false, true,
                           false, false, false, false, false, true};
    Protected_.Headers = {"HWND", "Title", "PID", "Flags"};
    Protected_.RightAlign = {false, false, true, false};
    Protected_.MultiSelect = true;
    Refresh();
  }

  TuiTable *ActiveTable() override {
    return Tab_ == 1 ? &Protected_ : &Windows_;
  }

  std::string RenderText() override {
    if (Windows_.Headers.empty())
      OnEnter();
    RebuildTables();
    std::string Text;
    Text += Tab_ == 0 ? "[Windows] Protected" : "Windows [Protected]";
    Text += KernelMode_ ? "   mode: kernel\n" : "   mode: user\n";
    if (!Filter.empty())
      Text += "filter: " + Filter + '\n';
    Text += TuiTableToText(*ActiveTable(), 0);
    return Text;
  }

private:
  void RegisterCommands() {
    auto Add = [this](const char *Name, const char *Usage,
                      std::function<void(std::vector<std::string>)> Handler) {
      OwnedCommands.push_back(TuiCommand{Name, Usage, std::move(Handler)});
    };
    Add("refresh", "refresh  (re-enumerate windows)",
        [this](std::vector<std::string>) { Refresh(); });
    Add("kernel", "kernel [on|off]  (use the kernel enumerator)",
        [this](std::vector<std::string> Args) {
          KernelMode_ = Args.empty() ? !KernelMode_ : StartsWithCi(Args.front(), "on");
          Refresh();
        });
    struct Op {
      const char *Name;
      const char *Usage;
      int Kind;
    };
    static const Op Ops[] = {
        {"show", "show  (show / activate the selected window)", 0},
        {"hide", "hide  (hide the selected window)", 1},
        {"minimize", "minimize", 2},
        {"maximize", "maximize", 3},
        {"restore", "restore", 4},
        {"enable", "enable  (enable the selected window)", 5},
        {"disable", "disable", 6},
        {"topmost", "topmost  (set HWND_TOPMOST)", 7},
        {"untopmost", "untopmost  (remove topmost)", 8},
        {"title", "title <text>  (set the window title)", 9},
        {"ping", "ping  (WM_NULL with timeout)", 10},
        {"close", "close  (post WM_CLOSE)", 11},
        {"sc-close", "sc-close  (WM_SYSCOMMAND SC_CLOSE)", 12},
        {"k-kill", "k-kill  (kernel close)", 13},
        {"k-hide", "k-hide  (kernel hide)", 14},
        {"k-show", "k-show  (kernel show)", 15},
        {"k-disable", "k-disable", 16},
        {"k-enable", "k-enable", 17},
        {"k-topmost", "k-topmost", 18},
        {"k-untopmost", "k-untopmost", 19},
        {"k-kill-direct", "k-kill-direct  (WINDOW_FLAG_DIRECT)", 20},
        {"k-hide-direct", "k-hide-direct  (WINDOW_FLAG_DIRECT)", 21},
        {"protect", "protect  (protect the selected window)", 22},
        {"unprotect", "unprotect  (remove protection from selected rows)", 23},
        {"copy", "copy  (copy the selected row as TSV)", 24},
    };
    for (const Op &Operation : Ops) {
      const int Kind = Operation.Kind;
      OwnedCommands.push_back(TuiCommand{
          Operation.Name, Operation.Usage,
          [this, Kind](std::vector<std::string> Args) { Execute(Kind, Args); }});
    }
    Add("tab", "tab [windows|protected]", [this](std::vector<std::string> Args) {
      Tab_ = (!Args.empty() && StartsWithCi(Args.front(), "prot")) ? 1 : 0;
      RebuildTables();
      SetStatus(Tab_ == 1 ? "Tab: Protected" : "Tab: Windows");
    });
  }

  // ---- 枚举 ----

  void Refresh() {
    if (Refreshing_.exchange(true))
      return;
    SetStatus("Enumerating windows...");
    const bool UseKernel = KernelMode_;
    TuiAsyncVoid(
        [this, UseKernel] {
          SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST);
          std::vector<WindowRow> Result;
          std::map<HWND, int> ZOrder;
          int ZPosition = 0;
          for (HWND Top = GetWindow(GetDesktopWindow(), GW_CHILD); Top;
               Top = GetWindow(Top, GW_HWNDNEXT))
            ZOrder.emplace(Top, ZPosition++);

          const auto ReadProcessPath = [](DWORD Pid) -> QString {
            HANDLE Process =
                OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
            QString Path;
            if (Process) {
              wchar_t Buffer[32768]{};
              DWORD Size = 32768;
              if (QueryFullProcessImageNameW(Process, 0, Buffer, &Size))
                Path = QString::fromWCharArray(Buffer, static_cast<qsizetype>(Size));
              CloseHandle(Process);
            }
            return Path;
          };

          bool KernelEnumerated = false;
          if (UseKernel) {
            if (G_DeviceHandle == INVALID_HANDLE_VALUE)
              OpenDeviceSilent();
            if (G_DeviceHandle != INVALID_HANDLE_VALUE) {
              const ULONG MaxEntryBytes = sizeof(KERNEL_WINDOW_ENUM_ENTRY) + 512;
              const ULONG Capacity = 8192;
              std::vector<unsigned char> Buffer(
                  sizeof(KERNEL_WINDOW_ENUM_OUTPUT) + Capacity * MaxEntryBytes);
              ULONG Count = 0;
              if (EnumerateWindowsKernel(Buffer.data(),
                                         static_cast<ULONG>(Buffer.size()),
                                         &Count) &&
                  Count > 0) {
                KernelEnumerated = true;
                const auto *Output =
                    reinterpret_cast<const KERNEL_WINDOW_ENUM_OUTPUT *>(Buffer.data());
                const unsigned char *Base =
                    reinterpret_cast<const unsigned char *>(Output->Entries);
                for (ULONG Index = 0; Index < Count; ++Index) {
                  const auto *Entry =
                      reinterpret_cast<const KERNEL_WINDOW_ENUM_ENTRY *>(Base);
                  if (Entry->Hwnd == 0)
                    break;
                  WindowRow Row;
                  Row.Handle = reinterpret_cast<HWND>(
                      static_cast<ULONG_PTR>(Entry->Hwnd));
                  Row.Pid = Entry->ProcessId;
                  Row.Tid = Entry->ThreadId;
                  Row.Style = static_cast<LONG>(Entry->Style);
                  Row.ExStyle = static_cast<LONG>(Entry->ExStyle);
                  Row.ParentHwnd = reinterpret_cast<HWND>(
                      static_cast<ULONG_PTR>(Entry->ParentHwnd));
                  Row.OwnerHwnd = reinterpret_cast<HWND>(
                      static_cast<ULONG_PTR>(Entry->OwnerHwnd));
                  Row.Alpha = Entry->Alpha;
                  Row.KernelFlags = Entry->Flags;
                  Row.FromKernel = true;
                  Row.Rect.left = Entry->Left;
                  Row.Rect.top = Entry->Top;
                  Row.Rect.right = Entry->Right;
                  Row.Rect.bottom = Entry->Bottom;
                  Row.ClientRect.left = Entry->ClientLeft;
                  Row.ClientRect.top = Entry->ClientTop;
                  Row.ClientRect.right = Entry->ClientRight;
                  Row.ClientRect.bottom = Entry->ClientBottom;
                  Row.Visible = (Entry->Flags & WINDOW_FLAG_VISIBLE) != 0;
                  Row.Enabled = (Entry->Flags & WINDOW_FLAG_ENABLED) != 0;
                  Row.Minimized = (Entry->Flags & WINDOW_FLAG_MINIMIZED) != 0;
                  Row.Maximized = (Entry->Flags & WINDOW_FLAG_MAXIMIZED) != 0;
                  Row.IsHung = (Entry->Flags & WINDOW_FLAG_HUNG) != 0;
                  Row.IsTopmost = (Entry->Flags & WINDOW_FLAG_TOPMOST) != 0;
                  Row.IsLayered = (Entry->Flags & WINDOW_FLAG_LAYERED) != 0;
                  Row.IsToolWindow = (Entry->Flags & WINDOW_FLAG_TOOLWINDOW) != 0;
                  Row.IsAppWindow = (Entry->Flags & WINDOW_FLAG_APPWINDOW) != 0;
                  Row.IsPopup = (Entry->Flags & WINDOW_FLAG_POPUP) != 0;
                  Row.IsChild = (Entry->Flags & WINDOW_FLAG_CHILD) != 0;
                  Row.IsUnicode = (Entry->Flags & WINDOW_FLAG_UNICODE) != 0;
                  if (Entry->TitleLength > 0 && Entry->TitleLength <= 510)
                    Row.Title = QString::fromWCharArray(
                        reinterpret_cast<const wchar_t *>(Entry + 1),
                        Entry->TitleLength / sizeof(wchar_t));
                  const auto ZIt = ZOrder.find(Row.Handle);
                  Row.ZIndex = ZIt != ZOrder.end() ? ZIt->second : -1;
                  Row.Band = QueryWindowBand(Row.Handle);
                  const ULONG EntryBytes =
                      sizeof(KERNEL_WINDOW_ENUM_ENTRY) +
                      ((static_cast<ULONG>(Entry->TitleLength) + 1) & ~1u);
                  Base += EntryBytes;
                  Result.push_back(std::move(Row));
                }
              }
            }
          }

          if (!KernelEnumerated) {
            struct EnumContext {
              std::vector<WindowRow> *Rows;
              const std::map<HWND, int> *ZOrder;
            } Context{&Result, &ZOrder};
            EnumWindows(
                [](HWND Handle, LPARAM Parameter) -> BOOL {
                  auto *Ctx = reinterpret_cast<EnumContext *>(Parameter);
                  WindowRow Row;
                  Row.Handle = Handle;
                  const auto ZIt = Ctx->ZOrder->find(Handle);
                  Row.ZIndex = ZIt != Ctx->ZOrder->end() ? ZIt->second : -1;
                  Row.Band = QueryWindowBand(Handle);
                  Row.Title = ReadWindowText(Handle);
                  wchar_t ClassName[256]{};
                  GetClassNameW(Handle, ClassName, 256);
                  Row.ClassName = QString::fromWCharArray(ClassName);
                  Row.Tid = GetWindowThreadProcessId(Handle, &Row.Pid);
                  Row.Visible = IsWindowVisible(Handle) != FALSE;
                  Row.Enabled = IsWindowEnabled(Handle) != FALSE;
                  Row.Minimized = IsIconic(Handle) != FALSE;
                  Row.Maximized = IsZoomed(Handle) != FALSE;
                  Row.IsHung = IsHungAppWindow(Handle) != FALSE;
                  Row.IsUnicode = IsWindowUnicode(Handle) != FALSE;
                  Row.Style = GetWindowLongW(Handle, GWL_STYLE);
                  Row.ExStyle = GetWindowLongW(Handle, GWL_EXSTYLE);
                  Row.IsTopmost = (Row.ExStyle & WS_EX_TOPMOST) != 0;
                  Row.IsLayered = (Row.ExStyle & WS_EX_LAYERED) != 0;
                  Row.IsToolWindow = (Row.ExStyle & WS_EX_TOOLWINDOW) != 0;
                  Row.IsAppWindow = (Row.ExStyle & WS_EX_APPWINDOW) != 0;
                  Row.IsPopup = (Row.Style & WS_POPUP) != 0;
                  Row.IsChild = (Row.Style & WS_CHILD) != 0;
                  Row.KernelFlags =
                      (Row.Visible ? WINDOW_FLAG_VISIBLE : 0u) |
                      (Row.Enabled ? WINDOW_FLAG_ENABLED : 0u) |
                      (Row.IsHung ? WINDOW_FLAG_HUNG : 0u) |
                      (Row.Minimized ? WINDOW_FLAG_MINIMIZED : 0u) |
                      (Row.Maximized ? WINDOW_FLAG_MAXIMIZED : 0u) |
                      (Row.IsTopmost ? WINDOW_FLAG_TOPMOST : 0u) |
                      (Row.IsLayered ? WINDOW_FLAG_LAYERED : 0u) |
                      (Row.IsToolWindow ? WINDOW_FLAG_TOOLWINDOW : 0u) |
                      (Row.IsPopup ? WINDOW_FLAG_POPUP : 0u) |
                      (Row.IsChild ? WINDOW_FLAG_CHILD : 0u) |
                      (Row.IsUnicode ? WINDOW_FLAG_UNICODE : 0u) |
                      ((Row.ExStyle & WS_EX_MDICHILD) ? WINDOW_FLAG_MDI : 0u) |
                      (Row.IsAppWindow ? WINDOW_FLAG_APPWINDOW : 0u) |
                      ((Row.ExStyle & WS_EX_NOACTIVATE) ? WINDOW_FLAG_NOACTIVATE : 0u) |
                      ((Row.Style & WS_DISABLED) ? WINDOW_FLAG_DISABLED_CLOSE : 0u) |
                      ((GetForegroundWindow() == Handle) ? WINDOW_FLAG_ACTIVE : 0u);
                  Row.ParentHwnd = GetParent(Handle);
                  Row.OwnerHwnd = GetWindow(Handle, GW_OWNER);
                  Row.Dpi = GetDpiForWindow(Handle);
                  GetWindowRect(Handle, &Row.Rect);
                  GetClientRect(Handle, &Row.ClientRect);
                  HANDLE Process =
                      OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Row.Pid);
                  if (Process) {
                    wchar_t Path[32768]{};
                    DWORD Size = 32768;
                    if (QueryFullProcessImageNameW(Process, 0, Path, &Size))
                      Row.ProcessPath = QString::fromWCharArray(
                          Path, static_cast<qsizetype>(Size));
                    CloseHandle(Process);
                  }
                  if (!Row.Title.isEmpty() || !Row.ClassName.isEmpty())
                    Ctx->Rows->push_back(std::move(Row));
                  return TRUE;
                },
                reinterpret_cast<LPARAM>(&Context));
          } else {
            for (WindowRow &Row : Result) {
              Row.ClassName = ReadWindowClassName(Row.Handle);
              if (Row.Dpi == 0)
                Row.Dpi = GetDpiForWindow(Row.Handle);
              if (Row.ProcessPath.isEmpty())
                Row.ProcessPath = ReadProcessPath(Row.Pid);
            }
            Result.erase(std::remove_if(Result.begin(), Result.end(),
                                        [](const WindowRow &Row) {
                                          return Row.Title.isEmpty() &&
                                                 Row.ClassName.isEmpty();
                                        }),
                         Result.end());
          }

          // 同 GUI 的树结构：按 PID 分组，组内按 Parent/Owner 关系算深度。
          std::map<HWND, int> DepthByHandle;
          std::function<int(HWND, int)> DepthOf = [&](HWND Handle, int Guard) -> int {
            if (Guard > 16)
              return 1;
            const auto Cached = DepthByHandle.find(Handle);
            if (Cached != DepthByHandle.end())
              return Cached->second;
            int Depth = 1;
            const auto Match = std::find_if(Result.begin(), Result.end(),
                                            [Handle](const WindowRow &Row) {
                                              return Row.Handle == Handle;
                                            });
            if (Match != Result.end()) {
              HWND Parent = nullptr;
              if (Match->IsChild && Match->ParentHwnd &&
                  Match->ParentHwnd != Match->Handle)
                Parent = Match->ParentHwnd;
              else if (Match->OwnerHwnd && Match->OwnerHwnd != Match->Handle)
                Parent = Match->OwnerHwnd;
              if (Parent) {
                const bool SameGroup = std::any_of(
                    Result.begin(), Result.end(), [Parent, &Match](const WindowRow &Row) {
                      return Row.Handle == Parent && Row.Pid == Match->Pid;
                    });
                if (SameGroup)
                  Depth = DepthOf(Parent, Guard + 1) + 1;
              }
            }
            DepthByHandle[Handle] = Depth;
            return Depth;
          };
          for (WindowRow &Row : Result)
            Row.Depth = DepthOf(Row.Handle, 0);

          std::sort(Result.begin(), Result.end(),
                    [](const WindowRow &Left, const WindowRow &Right) {
                      if (Left.Visible != Right.Visible)
                        return Left.Visible > Right.Visible;
                      if (Left.Pid != Right.Pid)
                        return Left.Pid < Right.Pid;
                      return Left.Depth < Right.Depth;
                    });
          TuiPost([this, Result = std::move(Result), KernelEnumerated]() mutable {
            Rows_ = std::move(Result);
            Refreshing_ = false;
            RebuildTables();
            SetStatus(std::to_string(Rows_.size()) + " window(s)  |  " +
                      (KernelEnumerated ? "Kernel enumeration"
                                        : "Win32 enumeration"));
          });
        },
        [] {});
  }

  // ---- 表格 ----

  void RebuildTables() {
    std::vector<TuiRow> TableRows;
    TableRows.reserve(Rows_.size() * 2);
    DWORD LastPid = 0;
    bool FirstGroup = true;
    for (const WindowRow &Window : Rows_) {
      if (FirstGroup || Window.Pid != LastPid) {
        const WindowRow &First = Window;
        TuiRow Group;
        Group.Cells = {"", "", "",
                       Utf8(QString("%1  (PID %2)")
                                .arg(WindowProcessName(First))
                                .arg(First.Pid)),
                       "", Utf8(First.ProcessPath), std::to_string(First.Pid),
                       "", "", "", "", "", ""};
        Group.Detail = "group";
        TableRows.push_back(std::move(Group));
        LastPid = Window.Pid;
        FirstGroup = false;
      }
      TuiRow Row;
      const std::string Indent(static_cast<size_t>(std::max(0, Window.Depth - 1) * 2),
                               ' ');
      Row.Cells = {
          Indent + Utf8(QString("0x%1").arg(
                            reinterpret_cast<quintptr>(Window.Handle), 0, 16)),
          Window.ZIndex >= 0 ? std::to_string(Window.ZIndex) : std::string("-"),
          Utf8(FormatWindowBand(Window.Band)),
          Indent + Utf8(Window.Title.isEmpty() ? QString("(untitled)")
                                               : Window.Title),
          Utf8(Window.ClassName),
          Utf8(Window.ProcessPath),
          std::to_string(Window.Pid),
          Utf8(QString("0x%1 | Ex:0x%2")
                   .arg(Window.Style, 8, 16, QChar('0'))
                   .arg(Window.ExStyle, 8, 16, QChar('0'))),
          Utf8(WindowStateText(Window)),
          Utf8(FormatWindowFlags(Window.KernelFlags)),
          Utf8(WindowPropertiesText(Window)),
          Utf8(WindowRectText(Window)),
          std::to_string(Window.Dpi),
      };
      Row.Detail = Row.Cells[3];
      TableRows.push_back(std::move(Row));
    }
    Windows_.Headers = {"HWND", "Z", "Band", "Title", "Class", "Process", "PID",
                        "Style", "State", "Flags", "Properties", "Rect", "Dpi"};
    Windows_.RightAlign = {false, true, false, false, false, false, true,
                           false, false, false, false, false, true};
    Windows_.Filter = Filter;
    Windows_.Rows = std::move(TableRows);
    Windows_.Rebuild();

    std::vector<TuiRow> ProtectedRows;
    for (const ProtectedWin &Entry : ProtectedWindows_) {
      TuiRow Row;
      Row.Cells = {Utf8(QString("0x%1").arg(Entry.Hwnd, 0, 16)), Utf8(Entry.Title),
                   std::to_string(Entry.Pid),
                   Utf8(QString("0x%1").arg(Entry.Flags, 8, 16, QLatin1Char('0')))};
      ProtectedRows.push_back(std::move(Row));
    }
    Protected_.Headers = {"HWND", "Title", "PID", "Flags"};
    Protected_.RightAlign = {false, false, true, false};
    Protected_.MultiSelect = true;
    Protected_.Filter = Filter;
    Protected_.Rows = std::move(ProtectedRows);
    Protected_.Rebuild();
  }

  // ---- 操作 ----

  const WindowRow *SelectedWindow() const {
    if (Tab_ == 1)
      return nullptr;
    const TuiRow *Row = Windows_.Current();
    if (!Row || Row->Detail == "group" || Row->Cells.empty())
      return nullptr;
    // 表格里还夹着分组行，行索引与 Rows_ 不是一一对应；按 HWND 反查最稳妥。
    uint64_t Handle = 0;
    if (!ParseUInt64(Row->Cells[0], Handle))
      return nullptr;
    for (const WindowRow &Window : Rows_) {
      if (static_cast<uint64_t>(reinterpret_cast<quintptr>(Window.Handle)) == Handle)
        return &Window;
    }
    return nullptr;
  }

  void Execute(int Kind, std::vector<std::string> Args) {
    if (Kind == 24) {
      if (Tab_ == 1) {
        if (Protected_.Current()) {
          Protected_.CopyCurrentToClipboard();
          Notify("Copied 1 row(s).", NoticeKind::Success);
        }
      } else if (Windows_.Current()) {
        Windows_.CopyCurrentToClipboard();
        Notify("Copied 1 row(s).", NoticeKind::Success);
      }
      return;
    }
    if (Kind == 23) {
      UnprotectSelected();
      return;
    }
    const WindowRow *Window = SelectedWindow();
    if (!Window) {
      Notify("Select a window first.", NoticeKind::Warning);
      return;
    }
    const HWND Handle = Window->Handle;
    const DWORD TargetPid = Window->Pid;
    const uint64_t HwndValue =
        static_cast<uint64_t>(reinterpret_cast<ULONG_PTR>(Handle));
    if (IsTrackedProtectedWindow(HwndValue)) {
      Notify("This window is protected. Unprotect it first.",
             NoticeKind::Warning);
      return;
    }
    if (Kind == 22) {
      ProtectWindowEntry(TargetPid, HwndValue, Window->Title);
      return;
    }
    if (!IsWindow(Handle)) {
      Notify("The window no longer exists.", NoticeKind::Warning);
      return;
    }
    // 内核路径只在 KernelMode 打开时使用（与 GUI 的菜单一致）。
    const bool UseKernel = KernelMode_;
    std::string TitleArgument;
    if (Kind == 9) {
      for (const std::string &Arg : Args)
        TitleArgument += (TitleArgument.empty() ? "" : " ") + Arg;
      if (TitleArgument.empty()) {
        PromptTextDialog(*Dialogs, "Set Window Title", "New title:", "",
                         [this, TargetPid, HwndValue](std::string NewTitle) {
                           if (NewTitle.empty())
                             return;
                           const std::wstring Wide =
                               QString::fromStdString(NewTitle).toStdWString();
                           const bool Ok =
                               KernelMode_
                                   ? WindowSetTitle(TargetPid, HwndValue, Wide.c_str()) != FALSE
                                   : SetWindowTextW(
                                         reinterpret_cast<HWND>(
                                             static_cast<ULONG_PTR>(HwndValue)),
                                         Wide.c_str()) != FALSE;
                           ReportWindowResult("Set Title", Ok);
                         });
        return;
      }
    }
    TuiAsyncVoid(
        [this, Kind, Handle, TargetPid, HwndValue, UseKernel, TitleArgument] {
          const bool KernelPath = UseKernel;
          const std::wstring WideTitle =
              QString::fromStdString(TitleArgument).toStdWString();
          BOOL Result = FALSE;
          const char *Action = "Window";
          switch (Kind) {
          case 0:
            Action = "Show / Activate";
            Result = KernelPath ? WindowShow(TargetPid, HwndValue)
                                : (ShowWindow(Handle, SW_SHOW),
                                   SetForegroundWindow(Handle) != FALSE);
            break;
          case 1:
            Action = "Hide";
            Result = KernelPath ? WindowHide(TargetPid, HwndValue)
                                : (ShowWindow(Handle, SW_HIDE),
                                   IsWindow(Handle) != FALSE);
            break;
          case 2:
            Action = "Minimize";
            Result = KernelPath ? WindowMinimize(TargetPid, HwndValue)
                                : (ShowWindow(Handle, SW_MINIMIZE),
                                   IsWindow(Handle) != FALSE);
            break;
          case 3:
            Action = "Maximize";
            Result = KernelPath ? WindowMaximize(TargetPid, HwndValue)
                                : (ShowWindow(Handle, SW_MAXIMIZE),
                                   IsWindow(Handle) != FALSE);
            break;
          case 4:
            Action = "Restore";
            Result = KernelPath ? WindowRestore(TargetPid, HwndValue)
                                : (ShowWindow(Handle, SW_RESTORE),
                                   SetForegroundWindow(Handle),
                                   IsWindow(Handle) != FALSE);
            break;
          case 5:
            Action = "Enable";
            Result = KernelPath ? WindowEnable(TargetPid, HwndValue)
                                : (EnableWindow(Handle, TRUE) != FALSE ||
                                   GetLastError() == ERROR_SUCCESS);
            break;
          case 6:
            Action = "Disable";
            Result = KernelPath ? WindowDisable(TargetPid, HwndValue)
                                : (EnableWindow(Handle, FALSE) != FALSE ||
                                   GetLastError() == ERROR_SUCCESS);
            break;
          case 7:
            Action = "Topmost";
            Result = KernelPath
                         ? WindowSetTopmost(TargetPid, HwndValue)
                         : SetWindowPos(Handle, HWND_TOPMOST, 0, 0, 0, 0,
                                        SWP_NOMOVE | SWP_NOSIZE) != FALSE;
            break;
          case 8:
            Action = "Remove topmost";
            Result = KernelPath
                         ? WindowRemoveTopmost(TargetPid, HwndValue)
                         : SetWindowPos(Handle, HWND_NOTOPMOST, 0, 0, 0, 0,
                                        SWP_NOMOVE | SWP_NOSIZE) != FALSE;
            break;
          case 9:
            Action = "Set Title";
            Result = KernelPath
                         ? WindowSetTitle(TargetPid, HwndValue, WideTitle.c_str())
                         : SetWindowTextW(Handle, WideTitle.c_str()) != FALSE;
            break;
          case 10: {
            Action = "Ping";
            DWORD_PTR PingResult = 0;
            Result = KernelPath
                         ? WindowPing(TargetPid, HwndValue)
                         : SendMessageTimeoutW(Handle, WM_NULL, 0, 0,
                                               SMTO_ABORTIFHUNG, 1000,
                                               &PingResult) != 0;
            break;
          }
          case 11:
            Action = "Post WM_CLOSE";
            Result = KernelPath
                         ? WindowKill(TargetPid, HwndValue)
                         : PostMessageW(Handle, WM_CLOSE, 0, 0) != FALSE;
            break;
          case 12: {
            Action = "Send SC_CLOSE";
            DWORD_PTR PingResult = 0;
            Result = KernelPath
                         ? WindowKill(TargetPid, HwndValue)
                         : SendMessageTimeoutW(Handle, WM_SYSCOMMAND, SC_CLOSE, 0,
                                               SMTO_ABORTIFHUNG, 1000,
                                               &PingResult) != 0;
            break;
          }
          case 13:
            Action = "Kill Window (Kernel)";
            Result = WindowKill(TargetPid, HwndValue);
            break;
          case 14:
            Action = "Force Hide";
            Result = WindowHide(TargetPid, HwndValue);
            break;
          case 15:
            Action = "Force Show";
            Result = WindowShow(TargetPid, HwndValue);
            break;
          case 16:
            Action = "Force Disable";
            Result = WindowDisable(TargetPid, HwndValue);
            break;
          case 17:
            Action = "Force Enable";
            Result = WindowEnable(TargetPid, HwndValue);
            break;
          case 18:
            Action = "Force Topmost";
            Result = WindowSetTopmost(TargetPid, HwndValue);
            break;
          case 19:
            Action = "Force Remove Topmost";
            Result = WindowRemoveTopmost(TargetPid, HwndValue);
            break;
          case 20:
            Action = "Kill (Direct)";
            Result = WindowKill(TargetPid, HwndValue, WINDOW_FLAG_DIRECT);
            break;
          case 21:
            Action = "Hide (Direct)";
            Result = WindowHide(TargetPid, HwndValue, WINDOW_FLAG_DIRECT);
            break;
          default:
            return;
          }
          const std::string ActionText = Action;
          const bool Success = Result != FALSE;
          TuiPost([this, ActionText, Success] {
            ReportWindowResult(QString::fromStdString(ActionText), Success);
          });
        },
        [] {});
  }

  void ReportWindowResult(const QString &Action, bool Success) {
    if (Success)
      Notify(Utf8(Action + " completed."), NoticeKind::Success);
    else
      Notify(Utf8(Action + " failed."), NoticeKind::Error);
    Refresh();
  }

  bool IsTrackedProtectedWindow(uint64_t Hwnd) const {
    return std::any_of(ProtectedWindows_.begin(), ProtectedWindows_.end(),
                       [Hwnd](const ProtectedWin &Entry) {
                         return Entry.Hwnd == Hwnd;
                       });
  }

  void ProtectWindowEntry(DWORD Pid, uint64_t Hwnd, const QString &Title) {
    if (IsTrackedProtectedWindow(Hwnd)) {
      Notify("This window is already protected.", NoticeKind::Warning);
      return;
    }
    if (G_DeviceHandle == INVALID_HANDLE_VALUE && !OpenDeviceSilent()) {
      const DWORD ErrorCode = GetLastError();
      G_LastAegisCoreError = ErrorCode;
      Notify(Utf8("Kernel driver is not available.\n" +
                  DescribeWin32ErrorMessage(ErrorCode)),
             NoticeKind::Error);
      return;
    }
    if (!ProtectWindowKernel(Pid, Hwnd, WINPROT_ALL)) {
      Notify(Utf8(QString("Protect failed.\n%1")
                      .arg(DescribeWin32ErrorMessage(G_LastAegisCoreError))),
             NoticeKind::Error);
      return;
    }
    ProtectedWindows_.push_back(
        ProtectedWin{Hwnd, Pid, Title.isEmpty() ? QString("(untitled)") : Title,
                     WINPROT_ALL});
    RebuildTables();
    Notify("Window protected.", NoticeKind::Success);
  }

  void UnprotectSelected() {
    std::vector<uint64_t> Targets;
    for (int RowIndex : Protected_.Marked) {
      if (RowIndex >= 0 && RowIndex < static_cast<int>(ProtectedWindows_.size()))
        Targets.push_back(ProtectedWindows_[static_cast<size_t>(RowIndex)].Hwnd);
    }
    if (Targets.empty()) {
      // 表格索引会受 Filter 影响：按当前行文本的 HWND 反查。
      if (const TuiRow *Row = Protected_.Current()) {
        uint64_t Hwnd = 0;
        if (!Row->Cells.empty() && ParseUInt64(Row->Cells[0], Hwnd))
          Targets.push_back(Hwnd);
      }
    }
    if (Targets.empty()) {
      Notify("Select a protected window first.", NoticeKind::Warning);
      return;
    }
    QStringList Failures;
    for (const ProtectedWin &Entry : ProtectedWindows_) {
      if (std::find(Targets.begin(), Targets.end(), Entry.Hwnd) == Targets.end())
        continue;
      if ((G_DeviceHandle == INVALID_HANDLE_VALUE && !OpenDeviceSilent()) ||
          !UnprotectWindowKernel(Entry.Pid, Entry.Hwnd)) {
        Failures.append(QString("0x%1 (error %2)")
                            .arg(Entry.Hwnd, 0, 16)
                            .arg(G_LastAegisCoreError));
        continue;
      }
      ProtectedWindows_.erase(
          std::remove_if(ProtectedWindows_.begin(), ProtectedWindows_.end(),
                         [&Entry](const ProtectedWin &Value) {
                           return Value.Hwnd == Entry.Hwnd;
                         }),
          ProtectedWindows_.end());
    }
    RebuildTables();
    if (Failures.isEmpty())
      Notify("Selected window protection removed.", NoticeKind::Success);
    else
      Notify(Utf8("Failed to unprotect:\n" + Failures.join('\n')),
             NoticeKind::Error);
  }

  struct ProtectedWin {
    uint64_t Hwnd = 0;
    DWORD Pid = 0;
    QString Title;
    ULONG Flags = 0;
  };

  int Index_ = 0;
  int Tab_ = 0;
  bool KernelMode_ = true;
  std::vector<WindowRow> Rows_;
  std::vector<ProtectedWin> ProtectedWindows_;
  TuiTable Windows_;
  TuiTable Protected_;
  std::atomic_bool Refreshing_{false};
};

std::unique_ptr<TuiPage> MakeWindowPage(int Index) {
  return std::make_unique<WindowPage>(Index);
}

// ------------------------------------------------------------
// Callback 页
// ------------------------------------------------------------

namespace {

// GUI 的 DescribeCallbackType 是 SnapshotLabPage 的私有静态成员，按 25 个
// 类型原样重写（顺序与 GUI 的过滤器下拉一致）。
std::string CallbackTypeName(ULONG Type) {
  switch (Type) {
  case CALLBACK_TYPE_OB_PROCESS: return "ObProcess";
  case CALLBACK_TYPE_OB_THREAD: return "ObThread";
  case CALLBACK_TYPE_REGISTRY: return "Registry";
  case CALLBACK_TYPE_FLT_PRE_CREATE: return "FltCreate";
  case CALLBACK_TYPE_FLT_PRE_SET_INFORMATION: return "FltSetInfo";
  case CALLBACK_TYPE_FLT_PRE_WRITE: return "FltWrite";
  case CALLBACK_TYPE_FLT_PRE_READ: return "FltRead";
  case CALLBACK_TYPE_FLT_PRE_QUERY_INFORMATION: return "FltQueryInfo";
  case CALLBACK_TYPE_FLT_PRE_DIRECTORY_CONTROL: return "FltDirCtrl";
  case CALLBACK_TYPE_FLT_PRE_CLEANUP: return "FltCleanup";
  case CALLBACK_TYPE_FLT_PRE_CLOSE: return "FltClose";
  case CALLBACK_TYPE_FLT_POST_CREATE: return "FltPostCreate";
  case CALLBACK_TYPE_FLT_POST_READ: return "FltPostRead";
  case CALLBACK_TYPE_FLT_POST_QUERY_INFORMATION: return "FltPostQuery";
  case CALLBACK_TYPE_FLT_POST_SET_INFORMATION: return "FltPostSet";
  case CALLBACK_TYPE_FLT_POST_DIRECTORY_CONTROL: return "FltPostDir";
  case CALLBACK_TYPE_FLT_POST_WRITE: return "FltPostWrite";
  case CALLBACK_TYPE_FLT_POST_CLEANUP: return "FltPostCleanup";
  case CALLBACK_TYPE_FLT_POST_CLOSE: return "FltPostClose";
  case CALLBACK_TYPE_PS_PROCESS_NOTIFY: return "PsProcess";
  case CALLBACK_TYPE_PS_THREAD_NOTIFY: return "PsThread";
  case CALLBACK_TYPE_PS_IMAGE_NOTIFY: return "PsImage";
  case CALLBACK_TYPE_BUGCHECK: return "BugCheck";
  case CALLBACK_TYPE_BUGCHECK_REASON: return "BugChkReason";
  case CALLBACK_TYPE_SHUTDOWN: return "Shutdown";
  default: return "Unknown";
  }
}

} // namespace

class CallbackPage final : public TuiPage {
public:
  explicit CallbackPage(int Index) : Index_(Index) { RegisterCommands(); }

  std::string Title() const override { return "Callback"; }

  std::string Subtitle() const override {
    return "enumerate kernel callbacks and remove opt-in ones";
  }

  void OnEnter() override {
    Table_.Headers = {"Type", "Address", "Module / Symbol", "State", "Source"};
    Table_.RightAlign = {false, false, false, false, false};
    Query(false);
  }

  TuiTable *ActiveTable() override { return &Table_; }

  std::string RenderText() override {
    if (Table_.Headers.empty())
      OnEnter();
    Populate();
    std::string Text = "filter: " + TypeFilter_ + '\n';
    if (!Filter.empty())
      Text += "row filter: " + Filter + '\n';
    Text += TuiTableToText(Table_, 0);
    return Text;
  }

private:
  void RegisterCommands() {
    auto Add = [this](const char *Name, const char *Usage,
                      std::function<void(std::vector<std::string>)> Handler) {
      OwnedCommands.push_back(TuiCommand{Name, Usage, std::move(Handler)});
    };
    Add("refresh", "refresh  (re-enumerate callbacks)",
        [this](std::vector<std::string>) { Query(true); });
    Add("filter", "filter [all|type]  (ObProcess, Registry, FltWrite, ...)",
        [this](std::vector<std::string> Args) {
          if (Args.empty()) {
            DetailDialog(*Dialogs, "Callback Type Filter",
                         FieldRows({{"Current", TypeFilter_}}));
            return;
          }
          TypeFilter_ = Args.front();
          Populate();
        });
    Add("remove", "remove  (remove the selected callback)",
        [this](std::vector<std::string>) { RemoveSelected(); });
  }

  void Query(bool ShowResult) {
    if (Refreshing_.exchange(true)) {
      Notify("Already refreshing.", NoticeKind::Info);
      return;
    }
    SetStatus("Enumerating callbacks...");
    TuiAsyncVoid(
        [this, ShowResult] {
          std::vector<CALLBACK_ENTRY> Rows;
          const auto Modules = AegisNT::KernelResearch::QueryAll(IOCTL_ENUM_KERNEL_MODULES);
          auto &Symbols = AegisNT::KernelResearch::SymbolService::Instance();
          Symbols.Initialize();
          Symbols.ReloadModules(Modules);
          DWORD BytesReturned = 0;
          ULONG Count = 0;
          bool Success =
              SendIoctlWithOutput(IOCTL_ENUM_CALLBACKS, nullptr, 0, &Count,
                                  sizeof(Count), &BytesReturned) != FALSE;
          DWORD ErrorCode = G_LastAegisCoreError;
          if (Success && Count) {
            const DWORD Size =
                sizeof(CALLBACK_ENUM_OUTPUT) + (Count - 1) * sizeof(CALLBACK_ENTRY);
            std::vector<BYTE> Buffer(Size);
            auto *Output = reinterpret_cast<PCALLBACK_ENUM_OUTPUT>(Buffer.data());
            ZeroMemory(Output, Size);
            Success = SendIoctlWithOutput(IOCTL_ENUM_CALLBACKS, nullptr, 0, Output,
                                          Size, &BytesReturned) != FALSE;
            ErrorCode = G_LastAegisCoreError;
            if (Success) {
              const size_t MaxEntries = Count;
              const size_t ReturnedEntries = static_cast<size_t>(Output->Count);
              const size_t RequiredBytes =
                  sizeof(CALLBACK_ENUM_OUTPUT) +
                  (ReturnedEntries ? (ReturnedEntries - 1) * sizeof(CALLBACK_ENTRY)
                                   : 0);
              if (ReturnedEntries > MaxEntries || BytesReturned < RequiredBytes) {
                Success = false;
                ErrorCode = ERROR_INVALID_DATA;
              } else {
                Rows.assign(Output->Entries, Output->Entries + ReturnedEntries);
              }
            }
          }
          TuiPost([this, Rows = std::move(Rows), Modules, Success, ErrorCode,
                   ShowResult]() mutable {
            Refreshing_ = false;
            if (!Success) {
              const QString Message =
                  QString("Enumeration failed (error %1)").arg(ErrorCode);
              SetStatus(Utf8(Message));
              if (ShowResult)
                Notify(Utf8(Message), NoticeKind::Error);
              Populate();
              return;
            }
            Rows_ = std::move(Rows);
            Modules_ = Modules;
            std::map<std::string, int> Counts;
            for (const CALLBACK_ENTRY &Entry : Rows_)
              ++Counts[CallbackTypeName(Entry.Type)];
            std::string Summary;
            for (const auto &[Name, Value] : Counts)
              Summary += (Summary.empty() ? "" : ", ") + Name + ":" +
                         std::to_string(Value);
            SetStatus(Summary.empty()
                          ? "0 callback(s)"
                          : std::to_string(Rows_.size()) + " callback(s) | " + Summary);
            if (ShowResult)
              Notify("Enumerated " + std::to_string(Rows_.size()) + " callback(s).",
                     NoticeKind::Success);
            Populate();
          });
        },
        [] {});
  }

  void Populate() {
    std::vector<TuiRow> TableRows;
    TableRows.reserve(Rows_.size());
    for (size_t Index = 0; Index < Rows_.size(); ++Index) {
      const CALLBACK_ENTRY &Entry = Rows_[Index];
      const std::string Type = CallbackTypeName(Entry.Type);
      if (LowerAscii(TypeFilter_) != "all" && !TypeFilter_.empty() &&
          Type != TypeFilter_)
        continue;
      const auto Owner = AegisNT::KernelResearch::ResolveAddress(Entry.Address, Modules_);
      const QString DriverModule =
          Entry.ModuleName[0] ? QString::fromWCharArray(Entry.ModuleName) : QString();
      const QString Module =
          Owner.Module.isEmpty()
              ? (DriverModule.isEmpty() ? QString("(unknown)") : DriverModule)
              : Owner.Module +
                    QString("+0x%1").arg(Owner.Rva, 0, 16).toUpper() +
                    (Owner.Symbol.isEmpty() ? QString() : " | " + Owner.Symbol);
      const QString Source = Entry.SourceName[0]
                                 ? QString::fromWCharArray(Entry.SourceName)
                                 : QString("(unknown)");
      TuiRow Row;
      Row.Cells = {Type, Utf8(FormatTaskPointer(Entry.Address)), Utf8(Module),
                   Utf8(Owner.Status), Utf8(Source)};
      Row.Detail = Type + " @ " + Utf8(FormatTaskPointer(Entry.Address));
      TableRows.push_back(std::move(Row));
    }
    Table_.Headers = {"Type", "Address", "Module / Symbol", "State", "Source"};
    Table_.RightAlign = {false, false, false, false, false};
    Table_.Filter = Filter;
    Table_.Rows = std::move(TableRows);
    Table_.Rebuild();
  }

  void RemoveSelected() {
    const TuiRow *Row = Table_.Current();
    if (!Row || Row->Cells.size() < 2) {
      Notify("Select a callback first.", NoticeKind::Warning);
      return;
    }
    // 用地址+类型在当前数据里定位原始条目（表格行可能被过滤）。
    uint64_t Address = 0;
    if (!ParseUInt64(Row->Cells[1], Address))
      return;
    const auto Match = std::find_if(
        Rows_.begin(), Rows_.end(),
        [Address](const CALLBACK_ENTRY &Entry) { return Entry.Address == Address; });
    if (Match == Rows_.end()) {
      Notify("The callback list changed. Refresh and try again.",
             NoticeKind::Warning);
      return;
    }
    const CALLBACK_ENTRY Entry = *Match;
    if ((Entry.Flags & CALLBACK_FLAG_CAN_REMOVE) == 0) {
      Notify("This callback is not marked as removable.", NoticeKind::Warning);
      return;
    }
    if (Removing_.exchange(true)) {
      Notify("A callback removal is already running.", NoticeKind::Warning);
      return;
    }
    const QString Text =
        QString("Remove callback at 0x%1?")
            .arg(static_cast<quint64>(Entry.Address),
                 static_cast<int>(sizeof(uintptr_t)) * 2, 16, QLatin1Char('0'))
            .toUpper();
    ConfirmDialog(*Dialogs, "Callback", Utf8(Text), [this, Entry] {
      TuiAsyncVoid(
          [this, Entry] {
            CALLBACK_REMOVE_INPUT Input = {};
            Input.Type = Entry.Type;
            Input.Address = Entry.Address;
            const bool Success =
                SendIoctl(IOCTL_REMOVE_CALLBACK_BY_ADDRESS, &Input, sizeof(Input)) !=
                FALSE;
            const DWORD ErrorCode = G_LastAegisCoreError;
            TuiPost([this, Success, ErrorCode] {
              Removing_ = false;
              if (Success && ErrorCode == ERROR_SUCCESS)
                Notify("Callback removed successfully.", NoticeKind::Success);
              else
                Notify(Utf8(QString("Operation failed (error %1)").arg(ErrorCode)),
                       NoticeKind::Error);
              Query(false);
            });
          },
          [] {});
    }, "Yes", "No");
  }

  int Index_ = 0;
  std::string TypeFilter_ = "All";
  std::vector<CALLBACK_ENTRY> Rows_;
  std::vector<INVENTORY_RECORD> Modules_;
  TuiTable Table_;
  std::atomic_bool Refreshing_{false};
  std::atomic_bool Removing_{false};
};

std::unique_ptr<TuiPage> MakeCallbackPage(int Index) {
  return std::make_unique<CallbackPage>(Index);
}

// ------------------------------------------------------------
// HotKeys 页
// ------------------------------------------------------------

class HotKeysPage final : public TuiPage {
public:
  explicit HotKeysPage(int Index) : Index_(Index) { RegisterCommands(); }

  std::string Title() const override { return "HotKeys"; }

  std::string Subtitle() const override {
    return "enumerate and unregister system-wide hotkeys";
  }

  void OnEnter() override {
    Table_.Headers = {"PID", "Process", "Hotkey", "Key", "Modifiers", "Flags",
                      "ID", "Object"};
    Table_.RightAlign = {true, false, false, false, false, false, true, false};
    Refresh();
  }

  void OnTick(int64_t NowMs) override {
    if (LastAutoRefreshMs_ == 0) {
      LastAutoRefreshMs_ = NowMs;
      return;
    }
    if (NowMs - LastAutoRefreshMs_ < 10000)
      return;
    LastAutoRefreshMs_ = NowMs;
    Refresh();
  }

  TuiTable *ActiveTable() override { return &Table_; }

  std::string RenderText() override {
    if (Table_.Headers.empty())
      OnEnter();
    Populate();
    std::string Text;
    if (!Filter.empty())
      Text += "filter: " + Filter + '\n';
    Text += TuiTableToText(Table_, 0);
    return Text;
  }

private:
  void RegisterCommands() {
    OwnedCommands.push_back(TuiCommand{
        "refresh", "refresh  (enumerate global hotkeys)",
        [this](std::vector<std::string>) { Refresh(); }});
    OwnedCommands.push_back(TuiCommand{
        "remove", "remove  (unregister the selected hotkey)",
        [this](std::vector<std::string>) { RemoveSelected(); }});
  }

  void Refresh() {
    if (Refreshing_.exchange(true)) {
      Notify("Already refreshing.", NoticeKind::Info);
      return;
    }
    SetStatus("Enumerating global hotkeys...");
    TuiAsyncVoid(
        [this] {
          auto Result = std::make_shared<HOTKEY_ENUM_OUTPUT>();
          const bool Success = EnumerateHotkeys(Result.get()) != FALSE;
          const DWORD ErrorCode = G_LastAegisCoreError;
          auto Names = std::make_shared<std::unordered_map<quint32, QString>>(
              HotKeySnapshotProcessNames());
          TuiPost([this, Result, Names, Success, ErrorCode] {
            Result_ = Result;
            Names_ = Names;
            Refreshing_ = false;
            if (!Success) {
              SetStatus(Utf8(QString("Enumeration failed (error %1)").arg(ErrorCode)));
              Populate();
              return;
            }
            if (Result_->Count == 0) {
              if (Result_->TableAddress == 0) {
                SetStatus(Utf8(
                    QString("Hotkey table not located (win32k base 0x%1, %2 "
                            "candidate(s) scanned)")
                        .arg(Result_->Win32kBase, 0, 16)
                        .arg(Result_->CandidateCount)
                        .toUpper()));
              } else {
                SetStatus(Utf8(QString("0 hotkeys registered (table at 0x%1)")
                                   .arg(Result_->TableAddress, 0, 16)
                                   .toUpper()));
              }
            } else {
              SetStatus(std::to_string(Result_->Count) + " hotkeys");
            }
            Populate();
          });
        },
        [] {});
  }

  void Populate() {
    std::vector<TuiRow> Rows;
    const auto &Names = *Names_;
    for (ULONG Index = 0; Index < Result_->Count && Index < HOTKEY_MAX_ENTRIES;
         ++Index) {
      const HOTKEY_ENUM_ENTRY &Entry = Result_->Entries[Index];
      const QString Key = HotKeyFormat::VirtualKeyName(Entry.VirtualKey);
      const QString Mods = HotKeyFormat::ModifierName(Entry.Modifiers);
      const QString Combo = Mods.isEmpty() ? Key : (Mods + " + " + Key);
      QString Process;
      if (Entry.ProcessId == 0) {
        Process = "-";
      } else if (Entry.ProcessId == 4) {
        Process = "System";
      } else {
        const auto It = Names.find(Entry.ProcessId);
        Process = It != Names.end() ? It->second
                                    : QString("<%1>").arg(Entry.ProcessId);
      }
      const QString Vk =
          QString("%1 (0x%2)")
              .arg(Key)
              .arg(QString::number(Entry.VirtualKey, 16)
                       .rightJustified(2, QLatin1Char('0'))
                       .toUpper());
      const QString Flags = HotKeyFormat::FlagsName(Entry.Flags);
      TuiRow Row;
      Row.Cells = {
          std::to_string(Entry.ProcessId),
          Utf8(Process),
          Utf8(Combo),
          Utf8(Vk),
          Utf8(QString("0x%1")
                   .arg(Entry.Modifiers, 4, 16, QLatin1Char('0'))
                   .toUpper()),
          Utf8(Flags.isEmpty() ? QString("-") : Flags),
          std::to_string(Entry.Id),
          Utf8(QString("0x%1")
                   .arg(static_cast<qulonglong>(Entry.HotKeyObject),
                        static_cast<int>(sizeof(ULONG_PTR)) * 2, 16,
                        QLatin1Char('0'))
                   .toUpper()),
      };
      Row.Detail = Utf8(Process + " | " + Combo);
      Rows.push_back(std::move(Row));
    }
    Table_.Headers = {"PID", "Process", "Hotkey", "Key", "Modifiers", "Flags",
                      "ID", "Object"};
    Table_.RightAlign = {true, false, false, false, false, false, true, false};
    Table_.Filter = Filter;
    Table_.Rows = std::move(Rows);
    Table_.Rebuild();
  }

  void RemoveSelected() {
    const TuiRow *Row = Table_.Current();
    if (!Row || Row->Cells.size() < 7) {
      Notify("Select a hotkey first.", NoticeKind::Warning);
      return;
    }
    // 用 PID + ID + VK 在原始结果里定位条目（表格可能被过滤）。
    DWORD Pid = 0;
    DWORD Id = 0;
    if (!ParseUInt32(Row->Cells[0], Pid) || !ParseUInt32(Row->Cells[6], Id))
      return;
    const auto Match = std::find_if(
        Result_->Entries, Result_->Entries + std::min<ULONG>(Result_->Count,
                                                             HOTKEY_MAX_ENTRIES),
        [Pid, Id](const HOTKEY_ENUM_ENTRY &Entry) {
          return Entry.ProcessId == Pid && static_cast<DWORD>(Entry.Id) == Id;
        });
    if (Match == Result_->Entries + std::min<ULONG>(Result_->Count,
                                                    HOTKEY_MAX_ENTRIES)) {
      Notify("The hotkey list changed. Refresh and try again.",
             NoticeKind::Warning);
      return;
    }
    const HOTKEY_ENUM_ENTRY Entry = *Match;
    if (Refreshing_.exchange(true)) {
      Notify("Already refreshing.", NoticeKind::Info);
      return;
    }
    SetStatus("Removing hotkey...");
    TuiAsyncVoid(
        [this, Entry] {
          NTSTATUS KernelStatus = 0;
          DWORD ErrorCode = 0;
          ULONG Detail = HOTKEY_REMOVE_DETAIL_NONE;
          HOTKEY_REMOVE_DIAGNOSTIC Diagnostic{};
          const bool Success = RemoveHotkey(Entry, &KernelStatus, &ErrorCode,
                                           &Detail, &Diagnostic) != FALSE;
          TuiPost([this, Success, KernelStatus, ErrorCode, Detail, Diagnostic,
                   Entry] {
            Refreshing_ = false;
            if (Success) {
              Notify("Hotkey removed.", NoticeKind::Success);
              Refresh();
              return;
            }
            QString Message;
            const ULONG Code = static_cast<ULONG>(KernelStatus);
            if (ErrorCode == ERROR_INVALID_FUNCTION ||
                ErrorCode == ERROR_REVISION_MISMATCH) {
              Message = "The loaded driver does not support hotkey removal. "
                        "Reload the updated driver.";
            } else if (!ErrorCode && Code == 0xC00000BBu) {
              Message = QString("Hotkey removal validation failed at %1 (stage %2).")
                            .arg(HotKeyFormat::RemovalStageName(Detail))
                            .arg(Detail);
            } else if (!ErrorCode &&
                       (Code == 0xC0000225u || Code == 0xC000022Du)) {
              Message = "The hotkey changed or was already removed. Refresh and "
                        "select it again.";
            } else {
              Message = QString("Hotkey removal failed (error %1, kernel status "
                                "0x%2).")
                            .arg(ErrorCode)
                            .arg(Code, 8, 16, QLatin1Char('0'));
            }
            Message += QString(" [PID %1, ID %2, VK 0x%3, flags 0x%4, status 0x%5, "
                               "stage %6]")
                           .arg(Entry.ProcessId)
                           .arg(Entry.Id)
                           .arg(Entry.VirtualKey, 2, 16, QLatin1Char('0'))
                           .arg(Entry.Flags, 4, 16, QLatin1Char('0'))
                           .arg(Code, 8, 16, QLatin1Char('0'))
                           .arg(Detail);
            if (Diagnostic.Actual) {
              Message += QString(" [target 0x%1, resolved 0x%2, expected 0x%3, "
                                 "alternate 0x%4, base 0x%5, full 0x%6, code %7]")
                             .arg(Diagnostic.Actual, 0, 16)
                             .arg(Diagnostic.Resolved, 0, 16)
                             .arg(Diagnostic.Expected, 0, 16)
                             .arg(Diagnostic.Alternate, 0, 16)
                             .arg(Diagnostic.BaseImage, 0, 16)
                             .arg(Diagnostic.FullImage, 0, 16)
                             .arg(QString::fromLatin1(
                                 QByteArray(reinterpret_cast<const char *>(
                                                Diagnostic.Code),
                                            int(qMin(Diagnostic.CodeSize,
                                                     ULONG(sizeof(Diagnostic.Code)))))
                                     .toHex()));
            }
            SetStatus(Utf8(Message));
            Notify(Utf8(Message), NoticeKind::Error);
            if (!ErrorCode && (Code == 0xC0000225u || Code == 0xC000022Du))
              Refresh();
          });
        },
        [] {});
  }

  int Index_ = 0;
  int64_t LastAutoRefreshMs_ = 0;
  std::shared_ptr<HOTKEY_ENUM_OUTPUT> Result_ = std::make_shared<HOTKEY_ENUM_OUTPUT>();
  std::shared_ptr<std::unordered_map<quint32, QString>> Names_ =
      std::make_shared<std::unordered_map<quint32, QString>>();
  TuiTable Table_;
  std::atomic_bool Refreshing_{false};
};

std::unique_ptr<TuiPage> MakeHotKeysPage(int Index) {
  return std::make_unique<HotKeysPage>(Index);
}

} // namespace AegisNT::Tui
