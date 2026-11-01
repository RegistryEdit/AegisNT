// Source/Tui/TuiPagesStorage.cpp
// ============================================================
// 索引 3/4/7/20：Registry / File / Memory / Disk。
// ------------------------------------------------------------
// 四个页面与 GUI 的 FileExplorerPage / RegistryManagerPage /
// MemoryPage / DiskProtectionPage 一一对应：同样的列、同样的
// 字面消息、同样的后端调用。
//
// 本文件由 AegisNT.cpp 在**全局作用域**unity 包含（匿名 namespace
// 关闭之后、main() 之前），因此：
//   - 绝不包含系统头/Qt 头：它们已在 AegisNT.cpp 顶部全局包含。
//   - 统一引用的 unity 助手（ConfigurationValue、AppendConsoleOutput、
//     MonitorTimestamp、AegisDisk*、ProtectFile …）不加 AegisNT:: 限定。
//   - 只有头文件里声明的名字（KernelResearch::*、PageDefinitions …）
//     才用 AegisNT:: 限定。
//
// 所有重活都走 TuiAsync：worker 线程只产出纯数据，TS 状态只在
// 完成回调（UI 线程）里改动。驱动缺失时页面照常渲染，只显示 GUI
// 的失败文案（"State: unavailable" / "… failed (error N)"）。
//
// 渲染是行式的：`show` 调用 RenderText() 打印 ASCII 表（TuiTableToText），
// 多视图页的第一行是页签条，用 `view` 命令切换；`detail <n>` 由 shell
// 负责，页面只保留 TuiRow::Detail 文本。
// ============================================================

#include "TuiAsync.h"
#include "TuiPages.h"
#include "TuiSync.h"
#include "TuiWidgets.h"
#include "TuiStyle.h"

namespace AegisNT::Tui {

// ------------------------------------------------------------
// 通用小工具（命名 namespace：unity TU 内避免与兄弟页面冲突）
// ------------------------------------------------------------

namespace StorageUtil {

inline std::string Utf8(const QString &Text) { return Text.toStdString(); }

inline QString Q(const std::string &Text) { return QString::fromStdString(Text); }

// 选中行：有标记用标记，否则用当前行。
std::vector<int> SelectedRows(const TuiTable &Table) {
  if (!Table.Marked.empty())
    return Table.Marked;
  const int Index = Table.CurrentRowIndex();
  return Index >= 0 ? std::vector<int>{Index} : std::vector<int>{};
}

// 单行提示：Notice 只渲染一行，把多行失败列表拼成逗号分隔。
std::string JoinLines(const QStringList &Lines) {
  return Utf8(Lines.join(", "));
}

// 显示用十六进制（大写、固定宽度）。
std::string Hex(uint64_t Value, int Width) {
  return Utf8(QString("%1").arg(static_cast<qulonglong>(Value), Width, 16,
                                QLatin1Char('0'))
                  .toUpper());
}

bool ParseU64(const std::string &Text, uint64_t *Value, int Base = 0) {
  if (!Value)
    return false;
  bool Ok = false;
  const qulonglong Parsed = Q(TrimAscii(Text)).toULongLong(&Ok, Base);
  if (!Ok)
    return false;
  *Value = static_cast<uint64_t>(Parsed);
  return true;
}

bool ParseUInt(const std::string &Text, uint32_t *Value, int Base = 0) {
  if (!Value)
    return false;
  bool Ok = false;
  const uint Parsed = Q(TrimAscii(Text)).toUInt(&Ok, Base);
  if (!Ok)
    return false;
  *Value = static_cast<uint32_t>(Parsed);
  return true;
}

} // namespace StorageUtil

// ------------------------------------------------------------
// FileOps：GUI FileExplorerPage 的私有文件操作原样搬过来
// ------------------------------------------------------------
// GUI 里的这些是 FileExplorerPage 的成员/文件级 static，TUI 不能
// 复用（会隐式依赖 Qt 控件），因此按原实现复制，逻辑一字不改。
// ------------------------------------------------------------

namespace FileOps {

#ifndef FileDispositionInfoEx
#define FileDispositionInfoEx ((FILE_INFO_BY_HANDLE_CLASS)21)
#endif
#ifndef FileRenameInfoEx
#define FileRenameInfoEx ((FILE_INFO_BY_HANDLE_CLASS)22)
#endif
#ifndef FILE_DISPOSITION_FLAG_DELETE
#define FILE_DISPOSITION_FLAG_DELETE 0x00000001
#endif
#ifndef FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
#define FILE_DISPOSITION_FLAG_POSIX_SEMANTICS 0x00000002
#endif
#ifndef FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE
#define FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE 0x00000010
#endif
#ifndef FILE_RENAME_FLAG_POSIX_SEMANTICS
#define FILE_RENAME_FLAG_POSIX_SEMANTICS 0x00000001
#endif

bool TryPosixRename(HANDLE FileHandle) {
  static const size_t NameChars = 32;
  std::vector<BYTE> Buffer(sizeof(FILE_RENAME_INFO) + NameChars * sizeof(WCHAR),
                           0);
  auto *RenameInfo = reinterpret_cast<PFILE_RENAME_INFO>(Buffer.data());
  RenameInfo->ReplaceIfExists = TRUE;
  RenameInfo->Flags = FILE_RENAME_FLAG_POSIX_SEMANTICS;
  swprintf_s(RenameInfo->FileName, NameChars, L"__del_%08x",
             static_cast<unsigned>(GetTickCount()));
  RenameInfo->FileNameLength =
      static_cast<DWORD>(wcsnlen_s(RenameInfo->FileName, NameChars));
  return SetFileInformationByHandle(FileHandle, FileRenameInfoEx, RenameInfo,
                                    static_cast<DWORD>(Buffer.size())) != 0;
}

// NTFS POSIX 语义删除（已锁定映像先改名再删除处置）。
bool ForceDeleteFileNtfs(const std::wstring &Path) {
  const DWORD Attributes = GetFileAttributesW(Path.c_str());
  if (Attributes != INVALID_FILE_ATTRIBUTES &&
      (Attributes & FILE_ATTRIBUTE_READONLY) != 0)
    SetFileAttributesW(Path.c_str(), Attributes & ~FILE_ATTRIBUTE_READONLY);

  HANDLE FileHandle = CreateFileW(
      Path.c_str(), DELETE | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
      OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
      nullptr);
  if (FileHandle == INVALID_HANDLE_VALUE)
    return false;

  FILE_DISPOSITION_INFO_EX Disposition{};
  Disposition.Flags = FILE_DISPOSITION_FLAG_DELETE |
                      FILE_DISPOSITION_FLAG_POSIX_SEMANTICS |
                      FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE;
  BOOL Ok = SetFileInformationByHandle(FileHandle, FileDispositionInfoEx,
                                       &Disposition, sizeof(Disposition));
  if (!Ok) {
    if (TryPosixRename(FileHandle))
      Ok = SetFileInformationByHandle(FileHandle, FileDispositionInfoEx,
                                      &Disposition, sizeof(Disposition));
  }
  CloseHandle(FileHandle);
  return Ok != 0;
}

// 经 AegisCore 驱动强制删除（目录递归）。
bool DeletePathR0(const QString &Path) {
  const QFileInfo Info(Path);
  if (Info.isDir()) {
    for (const QFileInfo &Child : QDir(Path).entryInfoList(
             QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden |
             QDir::System))
      if (!DeletePathR0(Child.absoluteFilePath()))
        return false;
  }
  const std::wstring WidePath = QDir::toNativeSeparators(Path).toStdWString();
  return ForceDeleteFile(WidePath.c_str()) == TRUE;
}

// NTFS POSIX 语义删除（目录递归）。
bool DeletePathNtfs(const QString &Path) {
  const QFileInfo Info(Path);
  if (Info.isDir()) {
    for (const QFileInfo &Child : QDir(Path).entryInfoList(
             QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden |
             QDir::System))
      if (!DeletePathNtfs(Child.absoluteFilePath()))
        return false;
  }
  return ForceDeleteFileNtfs(QDir::toNativeSeparators(Path).toStdWString());
}

bool CopyRecursively(const QString &SourcePath,
                     const QString &DestinationPath) {
  const QFileInfo SourceInformation(SourcePath);
  if (SourceInformation.isDir()) {
    QDir DestinationDirectory;
    if (!DestinationDirectory.mkpath(DestinationPath))
      return false;
    const QDir SourceDirectory(SourcePath);
    for (const QFileInfo &Child :
         SourceDirectory.entryInfoList(QDir::AllEntries |
                                       QDir::NoDotAndDotDot)) {
      if (!CopyRecursively(Child.absoluteFilePath(),
                           QDir(DestinationPath).filePath(Child.fileName())))
        return false;
    }
    return true;
  }
  if (QFileInfo::exists(DestinationPath))
    return false;
  return QFile::copy(SourcePath, DestinationPath);
}

// 显示路径 → NT 设备路径（与 GUI 的 ConvertToNtPath 相同）。
bool ConvertToNtPath(const QString &Path, QString &NtPath) {
  QString NativePath = QDir::toNativeSeparators(Path);
  if (NativePath.startsWith("\\Device\\", Qt::CaseInsensitive)) {
    NtPath = NativePath;
    return true;
  }
  if (NativePath.startsWith("\\\\")) {
    NtPath = "\\Device\\Mup" + NativePath.mid(1);
    return true;
  }
  if (NativePath.size() < 3 || NativePath.at(1) != ':')
    return false;

  const QString Drive = NativePath.left(2);
  std::vector<wchar_t> DeviceBuffer(32768, L'\0');
  if (QueryDosDeviceW(reinterpret_cast<LPCWSTR>(Drive.utf16()),
                      DeviceBuffer.data(),
                      static_cast<DWORD>(DeviceBuffer.size())) == 0)
    return false;
  NtPath = QString::fromWCharArray(DeviceBuffer.data()) + NativePath.mid(2);
  return NtPath.startsWith("\\Device\\", Qt::CaseInsensitive);
}

} // namespace FileOps

// ------------------------------------------------------------
// 索引 4：File
// ------------------------------------------------------------

class FilePage final : public TuiPage {
public:
  explicit FilePage(int Index) : Index_(Index) {
    Explorer_.Headers = {"Name", "Size", "Type", "Modified"};
    Explorer_.RightAlign = {false, true, false, false};
    Explorer_.MultiSelect = true;

    Protected_.Headers = {"Name", "Protected path"};
    Protected_.RightAlign = {false, false};
    Protected_.MultiSelect = true;

    Monitor_.Headers = {"Time", "Operation", "Process", "PID", "Path"};
    Monitor_.RightAlign = {false, false, false, true, false};

    RegisterCommands();
  }

  ~FilePage() override { StopFileMonitor(false); }

  std::string Title() const override { return "File"; }
  std::string PromptLocationPath() const override {
    return StorageUtil::Utf8(QDir::toNativeSeparators(CurrentPath_));
  }

  std::string Subtitle() const override {
    return "file browser, protected paths, file-monitor events";
  }

  void OnEnter() override {
    // `use` 与 `refresh` 都走这里：回到当前目录重新列一次，并刷新监控事件。
    if (!Entered_) {
      Entered_ = true;
      NavigateTo(HomePath(), true);
    } else if (CurrentPath_.isEmpty()) {
      NavigateTo(HomePath(), true);
    } else {
      RefreshExplorer();
    }
    RefreshMonitorRows();
  }

  void OnTick(int64_t NowMs) override {
    if (Tab_ == 2) {
      const uint64_t Version = MonitorVersion_.load(std::memory_order_relaxed);
      if (Version != DisplayedVersion_) {
        DisplayedVersion_ = Version;
        RefreshMonitorRows();
      }
    }
    if (LastStatusMs_ == 0 || NowMs - LastStatusMs_ >= 500) {
      LastStatusMs_ = NowMs;
      UpdateStatus();
    }
  }

  TuiTable *ActiveTable() override {
    switch (Tab_) {
    case 1:
      return &Protected_;
    case 2:
      return &Monitor_;
    default:
      return &Explorer_;
    }
  }

  std::string RenderText() override {
    // `show`：用页面自己的填充函数重放一遍（同步、读缓存），再打印 ASCII 表。
    switch (Tab_) {
    case 1:
      RefreshProtectedRows();
      break;
    case 2:
      RefreshMonitorRows();
      break;
    default:
      Explorer_.Filter = Filter;
      Explorer_.Rebuild();
      break;
    }
    const TuiTable &Table = *ActiveTable();
    std::string Text =
        TabStrip({"Explorer", "ProtectedFiles", "Monitor"}, Tab_) + "\n";
    switch (Tab_) {
    case 1:
      Text += "Protected paths: " + std::to_string(ProtectedFiles_.size()) +
              "\n";
      break;
    case 2:
      Text += "Watched: " +
              (WatchedDisplayPath_.isEmpty() ? std::string("-")
                                             : StorageUtil::Utf8(
                                                   WatchedDisplayPath_)) +
              "  (" + (FileMonitor_ ? "running" : "stopped") + ")\n";
      break;
    default:
      Text += "  Path: " +
              (CurrentPath_.isEmpty() ? std::string("-")
                                      : StorageUtil::Utf8(
                                            QDir::toNativeSeparators(
                                                CurrentPath_))) +
              "\n";
      break;
    }
    Text += TuiTableToText(Table, 200);
    return Text;
  }

private:
  struct DirListing {
    bool Ok = false;
    QString Path;
    std::vector<TuiRow> Rows;
    QString Error;
  };

  struct MonitorEntry {
    QString Time;
    QString Operation;
    QString Process;
    QString Path;
    QString Detail;
    DWORD ProcessId = 0;
  };

  struct ProtectedEntry {
    QString DisplayPath;
    QString NtPath;
  };

  // ---- 命令注册（与 GUI 按钮/右键菜单一一对应）----
  void RegisterCommands() {
    const auto Add = [this](std::string Name, std::string Usage,
                            std::function<void(std::vector<std::string>)> Fn) {
      OwnedCommands.push_back(TuiCommand{std::move(Name), std::move(Usage),
                                         std::move(Fn)});
    };

    Add("prev", "prev  (directory history back; back returns to home prompt)", [this](std::vector<std::string>) {
      NavigateHistory(-1);
    });
    Add("forward", "forward  (history forward)", [this](std::vector<std::string>) {
      NavigateHistory(1);
    });
    Add("up", "up  (parent folder)", [this](std::vector<std::string>) {
      const QDir Directory(CurrentPath_);
      const QString Parent = QFileInfo(Directory.absolutePath()).dir().absolutePath();
      if (Parent.isEmpty() || Parent == CurrentPath_)
        return;
      NavigateTo(Parent, true);
    });
    Add("home", "home  (user profile folder)", [this](std::vector<std::string>) {
      NavigateTo(HomePath(), true);
    });
    Add("cd", "cd <path>  (navigate to path)",
        [this](std::vector<std::string> Args) {
          if (Args.empty()) {
            Notify("Usage: cd <path>", NoticeKind::Warning);
            return;
          }
          std::string Joined;
          for (const std::string &Part : Args) {
            if (!Joined.empty())
              Joined += ' ';
            Joined += Part;
          }
          NavigateTo(StorageUtil::Q(Joined), true);
        });
    Add("pwd", "pwd  (show the current directory)",
        [this](std::vector<std::string>) {
          Notify(StorageUtil::Utf8(QDir::toNativeSeparators(CurrentPath_)),
                 NoticeKind::Info);
        });
    for (const char *Name : {"ls", "list", "dir"}) {
      Add(Name, std::string(Name) + " [path]  (reload and display directory contents)",
          [this](std::vector<std::string> Args) {
            Tab_ = 0;
            if (Args.empty()) {
              RefreshExplorer();
              return;
            }
            std::string Path;
            for (const auto &Part : Args) {
              if (!Path.empty())
                Path += ' ';
              Path += Part;
            }
            NavigateTo(StorageUtil::Q(Path), true);
          });
    }
    Add("refresh", "refresh  (reload the current folder)",
        [this](std::vector<std::string>) {
          RefreshExplorer();
          Notify("Folder refreshed.", NoticeKind::Success);
        });
    Add("mkdir", "mkdir <name>  (create a folder)",
        [this](std::vector<std::string> Args) {
          if (!Args.empty()) {
            CreateFolder(StorageUtil::Q(Args.front()));
            return;
          }
          PromptTextDialog(*Dialogs, "New folder", "Folder name:", "New folder",
                           [this](std::string Name) {
                             CreateFolder(StorageUtil::Q(TrimAscii(Name)));
                           });
        });
    Add("delete", "delete  (permanently delete selection)",
        [this](std::vector<std::string>) { DeleteSelection(); });
    Add("delete-ntfs", "delete-ntfs  (NTFS POSIX delete)",
        [this](std::vector<std::string>) { DeleteSelectionNtfs(); });
    Add("delete-r0", "delete-r0  (force delete through the kernel driver)",
        [this](std::vector<std::string>) { DeleteSelectionR0(); });
    Add("copy", "copy  (copy selection to a folder)",
        [this](std::vector<std::string>) { CopySelection(); });
    Add("copy-path", "copy-path  (copy the selected path)",
        [this](std::vector<std::string>) { CopySelectionPath(); });
    Add("rename", "rename  (rename the selected item)",
        [this](std::vector<std::string>) { RenameSelection(); });
    Add("protect", "protect  (protect selection via AegisCore)",
        [this](std::vector<std::string>) { ProtectSelection(); });
    Add("unprotect", "unprotect  (unprotect selection)",
        [this](std::vector<std::string>) { UnprotectSelection(); });
    Add("monitor-dir", "monitor-dir <path>  (watch a directory)",
        [this](std::vector<std::string> Args) {
          const QString Path = Args.empty()
                                   ? CurrentPath_
                                   : StorageUtil::Q(Args.front());
          StartMonitoringDirectory(Path, true, true);
        });
    Add("monitor-current", "monitor-current  (watch the current folder)",
        [this](std::vector<std::string>) {
          StartMonitoringDirectory(CurrentPath_, true, true);
        });
    Add("browse", "browse  (pick a directory to monitor)",
        [this](std::vector<std::string>) {
          PromptTextDialog(*Dialogs, "Monitor directory", "Directory:",
                           StorageUtil::Utf8(
                               WatchedDisplayPath_.isEmpty()
                                   ? CurrentPath_
                                   : WatchedDisplayPath_),
                           [this](std::string Path) {
                             StartMonitoringDirectory(
                                 StorageUtil::Q(TrimAscii(Path)), true, true);
                           });
        });
    Add("stop", "stop  (stop directory monitoring)",
        [this](std::vector<std::string>) { StopFileMonitor(true); });
    Add("clear", "clear  (clear monitor events)",
        [this](std::vector<std::string>) { ClearMonitorEvents(); });
    Add("details", "details [n]  (monitor event details)",
        [this](std::vector<std::string> Args) {
          ShowMonitorDetails(Args.empty() ? std::string() : Args.front());
        });
    Add("open", "open  (open the selected item)",
        [this](std::vector<std::string>) { ActivateExplorer(); });
    Add("view", "view [explorer|protected|monitor]  (switch view)",
        [this](std::vector<std::string> Args) {
          if (!Args.empty()) {
            const std::string Name = LowerAscii(Args.front());
            if (Name == "explorer" || Name == "0")
              Tab_ = 0;
            else if (Name == "protected" || Name == "protectedfiles" ||
                     Name == "1")
              Tab_ = 1;
            else if (Name == "monitor" || Name == "2")
              Tab_ = 2;
            else {
              Notify("Unknown view: " + Args.front(), NoticeKind::Warning);
              return;
            }
          } else {
            Tab_ = (Tab_ + 1) % 3;
          }
          UpdateStatus();
        });
  }

  static QString HomePath() {
    const QString Home =
        QStandardPaths::writableLocation(QStandardPaths::HomeLocation);
    return Home.isEmpty() ? QDir(QCoreApplication::applicationDirPath()).absolutePath()
                          : Home;
  }

  // ---- Explorer ----

  void UpdateStatus() {
    const int Items = static_cast<int>(Explorer_.Rows.size());
    const int Selected = static_cast<int>(Explorer_.Marked.size());
    if (Selected > 0)
      SetStatus(std::to_string(Items) + " items  |  " +
                std::to_string(Selected) + " selected");
    else
      SetStatus(std::to_string(Items) + " items");
  }

  void NavigateHistory(int Offset) {
    const int NextIndex = HistoryIndex_ + Offset;
    if (NextIndex < 0 || NextIndex >= static_cast<int>(History_.size()))
      return;
    HistoryIndex_ = NextIndex;
    NavigateTo(History_[static_cast<size_t>(HistoryIndex_)], false);
  }

  void RefreshExplorer() {
    if (CurrentPath_.isEmpty()) {
      NavigateTo(HomePath(), true);
      return;
    }
    NavigateTo(CurrentPath_, false);
  }

  void NavigateTo(const QString &Target, bool AddHistory) {
    if (!Dialogs)
      return;
    if (Listing_.exchange(true)) {
      Notify("Already loading the folder.", NoticeKind::Info);
      return;
    }
    const QString Input = Target.trimmed();
    const QString Requested =
        Input.isEmpty() ? QString()
        : QDir::isRelativePath(Input) && !CurrentPath_.isEmpty()
            ? QDir(CurrentPath_).absoluteFilePath(Input)
            : Input;
    TuiAsync<DirListing>(
        [Requested] {
          DirListing Result;
          const QFileInfo Information(Requested);
          if (Requested.isEmpty() || !Information.exists() ||
              !Information.isDir()) {
            Result.Ok = false;
            return Result;
          }
          Result.Ok = true;
          Result.Path = QDir::cleanPath(Information.absoluteFilePath());

          std::vector<TuiRow> Rows;
          const QDir Directory(Result.Path);
          // 根目录（例如 C:\）同时列出其他盘符，等价于 GUI 的 Drives 过滤。
          if (QFileInfo(Result.Path).dir().absolutePath() == Result.Path) {
            for (const QFileInfo &Drive : QDir::drives()) {
              if (!Drive.exists())
                continue;
              Rows.push_back(TuiRow{{StorageUtil::Utf8(
                                         QDir::toNativeSeparators(
                                             Drive.absoluteFilePath())),
                                     "-", "Drive", "-"},
                                    StorageUtil::Utf8(Drive.absoluteFilePath()), TuiRowKind::Directory});
            }
          }
          const QFileInfoList Entries = Directory.entryInfoList(
              QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden |
                  QDir::System,
              QDir::DirsFirst | QDir::Name | QDir::IgnoreCase);
          for (const QFileInfo &Entry : Entries) {
            const bool IsDirectory = Entry.isDir();
            const QString Type =
                IsDirectory ? QString("Folder")
                            : (Entry.suffix().isEmpty()
                                   ? QString("File")
                                   : Entry.suffix().toUpper());
            Rows.push_back(TuiRow{{StorageUtil::Utf8(Entry.fileName()),
                                   IsDirectory
                                       ? std::string("-")
                                       : StorageUtil::Utf8(
                                             FormatBytes(static_cast<quint64>(
                                                 Entry.size()))),
                                   StorageUtil::Utf8(Type),
                                   StorageUtil::Utf8(Entry.lastModified().toString(
                                       "yyyy-MM-dd HH:mm"))},
                                  StorageUtil::Utf8(Entry.absoluteFilePath()),
                                  IsDirectory ? TuiRowKind::Directory : TuiRowKind::Normal, Entry.isHidden()});
          }
          Result.Rows = std::move(Rows);
          return Result;
        },
        [this, AddHistory](DirListing Result) {
          Listing_ = false;
          if (!Result.Ok) {
            Notify("The folder does not exist or cannot be accessed.",
                   NoticeKind::Error);
            UpdateStatus();
            return;
          }
          if (AddHistory && Result.Path != CurrentPath_) {
            while (static_cast<int>(History_.size()) > HistoryIndex_ + 1)
              History_.pop_back();
            History_.push_back(Result.Path);
            HistoryIndex_ = static_cast<int>(History_.size()) - 1;
          }
          CurrentPath_ = Result.Path;
          Tab_ = 0;
          Explorer_.Rows = std::move(Result.Rows);
          Explorer_.Filter = Filter;
          Explorer_.Selected = 0;
          Explorer_.Marked.clear();
          Explorer_.Rebuild();
          UpdateStatus();
        });
  }

  void ActivateExplorer() {
    const int Index = Explorer_.CurrentRowIndex();
    if (Index < 0 || Index >= static_cast<int>(Explorer_.Rows.size()))
      return;
    const QString Path =
        StorageUtil::Q(Explorer_.Rows[static_cast<size_t>(Index)].Detail);
    const QFileInfo Information(Path);
    if (Information.isDir())
      NavigateTo(Information.absoluteFilePath(), true);
    else
      QDesktopServices::openUrl(QUrl::fromLocalFile(Information.absoluteFilePath()));
  }

  std::vector<QString> SelectedPaths() const {
    std::vector<QString> Paths;
    for (int Index : StorageUtil::SelectedRows(Explorer_)) {
      if (Index < 0 || Index >= static_cast<int>(Explorer_.Rows.size()))
        continue;
      const QString Path =
          StorageUtil::Q(Explorer_.Rows[static_cast<size_t>(Index)].Detail);
      if (!Path.isEmpty())
        Paths.push_back(Path);
    }
    return Paths;
  }

  void CreateFolder(const QString &Name) {
    if (Name.isEmpty())
      return;
    if (!QDir(CurrentPath_).mkdir(Name))
      Notify("Failed to create the folder.", NoticeKind::Error);
    else {
      Notify("Folder created successfully.", NoticeKind::Success);
      RefreshExplorer();
    }
  }

  void RenameSelection() {
    const std::vector<QString> Paths = SelectedPaths();
    if (Paths.size() != 1) {
      Notify("Select exactly one item to rename.", NoticeKind::Warning);
      return;
    }
    const QFileInfo Information(Paths.front());
    PromptTextDialog(*Dialogs, "Rename", "New name:",
                     StorageUtil::Utf8(Information.fileName()),
                     [this, Information](std::string NewName) {
                       const QString Name = StorageUtil::Q(TrimAscii(NewName));
                       if (Name.isEmpty() || Name == Information.fileName())
                         return;
                       const QString Destination =
                           Information.dir().absoluteFilePath(Name);
                       if (!QDir().rename(Information.absoluteFilePath(),
                                          Destination))
                         Notify("Failed to rename the selected item.",
                                NoticeKind::Error);
                       else {
                         Notify("Item renamed successfully.",
                                NoticeKind::Success);
                         RefreshExplorer();
                       }
                     });
  }

  void DeleteSelection() {
    const std::vector<QString> Paths = SelectedPaths();
    if (Paths.empty())
      return;
    ConfirmDialog(
        *Dialogs, "Delete",
        "Permanently delete " + std::to_string(Paths.size()) +
            " selected item(s)?",
        [this, Paths] {
          if (Deleting_.exchange(true))
            return;
          TuiAsync<QStringList>(
              [Paths] {
                QStringList Failures;
                for (const QString &Path : Paths) {
                  const QFileInfo Information(Path);
                  const bool Removed =
                      Information.isDir() ? QDir(Path).removeRecursively()
                                          : QFile::remove(Path);
                  if (!Removed)
                    Failures.append(Information.fileName());
                }
                return Failures;
              },
              [this, Count = Paths.size()](QStringList Failures) {
                Deleting_ = false;
                if (!Failures.isEmpty())
                  Notify("Failed to delete: " +
                             StorageUtil::JoinLines(Failures),
                         NoticeKind::Error);
                else
                  Notify("Deleted " + std::to_string(Count) + " item(s).",
                         NoticeKind::Success);
                MarkMutated();
                RefreshExplorer();
              });
        },
        "Yes", "No");
  }

  void DeleteSelectionNtfs() {
    const std::vector<QString> Paths = SelectedPaths();
    if (Paths.empty())
      return;
    ConfirmDialog(
        *Dialogs, "Delete (NTFS)",
        "Permanently delete " + std::to_string(Paths.size()) +
            " selected item(s) via NTFS POSIX semantics?",
        [this, Paths] {
          if (Deleting_.exchange(true))
            return;
          TuiAsync<QStringList>(
              [Paths] {
                QStringList Failures;
                for (const QString &Path : Paths) {
                  if (!FileOps::DeletePathNtfs(Path))
                    Failures.append(QString("%1 (error %2)")
                                        .arg(QFileInfo(Path).fileName())
                                        .arg(GetLastError()));
                }
                return Failures;
              },
              [this, Count = Paths.size()](QStringList Failures) {
                Deleting_ = false;
                if (!Failures.isEmpty())
                  Notify("Failed to delete: " +
                             StorageUtil::JoinLines(Failures),
                         NoticeKind::Error);
                else
                  Notify("Deleted " + std::to_string(Count) + " item(s).",
                         NoticeKind::Success);
                MarkMutated();
                RefreshExplorer();
              });
        },
        "Yes", "No");
  }

  void DeleteSelectionR0() {
    const std::vector<QString> Paths = SelectedPaths();
    if (Paths.empty())
      return;
    ConfirmDialog(
        *Dialogs, "Delete (R0)",
        "Force delete " + std::to_string(Paths.size()) +
            " selected item(s) through the kernel driver?",
        [this, Paths] {
          if (Deleting_.exchange(true))
            return;
          TuiAsync<QStringList>(
              [Paths] {
                QStringList Failures;
                for (const QString &Path : Paths) {
                  if (!FileOps::DeletePathR0(Path))
                    Failures.append(QString("%1 (error %2)")
                                        .arg(QFileInfo(Path).fileName())
                                        .arg(G_LastAegisCoreError));
                }
                return Failures;
              },
              [this, Count = Paths.size()](QStringList Failures) {
                Deleting_ = false;
                if (!Failures.isEmpty())
                  Notify("Failed to force delete: " +
                             StorageUtil::JoinLines(Failures),
                         NoticeKind::Error);
                else
                  Notify("Force deleted " + std::to_string(Count) + " item(s).",
                         NoticeKind::Success);
                MarkMutated();
                RefreshExplorer();
              });
        },
        "Yes", "No");
  }

  void CopySelection() {
    const std::vector<QString> Paths = SelectedPaths();
    if (Paths.empty())
      return;
    PromptTextDialog(*Dialogs, "Copy to", "Destination folder:",
                     StorageUtil::Utf8(CurrentPath_),
                     [this, Paths](std::string Destination) {
                       const QString Target =
                           QDir::cleanPath(StorageUtil::Q(TrimAscii(Destination)));
                       if (Target.isEmpty())
                         return;
                       if (Copying_.exchange(true))
                         return;
                       TuiAsync<QStringList>(
                           [Paths, Target] {
                             QStringList Failures;
                             for (const QString &Path : Paths) {
                               const QFileInfo Information(Path);
                               const QString DestinationPath =
                                   QDir(Target).filePath(Information.fileName());
                               if (!FileOps::CopyRecursively(
                                       Information.absoluteFilePath(),
                                       DestinationPath))
                                 Failures.append(Information.fileName());
                             }
                             return Failures;
                           },
                           [this, Count = Paths.size()](QStringList Failures) {
                             Copying_ = false;
                             if (!Failures.isEmpty())
                               Notify("Failed to copy: " +
                                          StorageUtil::JoinLines(Failures) +
                                          " (the destination item may already exist.)",
                                      NoticeKind::Error);
                             else
                               Notify("Copied " + std::to_string(Count) +
                                          " item(s).",
                                      NoticeKind::Success);
                           });
                     });
  }

  void CopySelectionPath() {
    const std::vector<QString> Paths = SelectedPaths();
    QString Text = QDir::toNativeSeparators(CurrentPath_);
    if (!Paths.empty()) {
      QStringList Joined;
      for (const QString &Path : Paths)
        Joined.append(Path);
      Text = Joined.join("\n");
    }
    TuiClipboard::Set(StorageUtil::Utf8(Text));
    Notify("Path copied to the clipboard.", NoticeKind::Success);
  }

  void ProtectSelection() {
    const std::vector<QString> Paths = SelectedPaths();
    if (Paths.empty())
      return;
    if (Protecting_.exchange(true))
      return;
    TuiAsync<QStringList>(
        [Paths] {
          QStringList Failures;
          for (const QString &Path : Paths) {
            const QString NormalizedPath =
                QDir::toNativeSeparators(QFileInfo(Path).absoluteFilePath());
            QString NtPath;
            if (!FileOps::ConvertToNtPath(NormalizedPath, NtPath)) {
              Failures.append(QFileInfo(Path).fileName());
              continue;
            }
            const std::wstring WidePath = NtPath.toStdWString();
            if (!ProtectFile(WidePath.c_str()))
              Failures.append(QFileInfo(Path).fileName());
          }
          return Failures;
        },
        [this, Paths](QStringList Failures) {
          Protecting_ = false;
          int ProtectedCount = 0;
          for (const QString &Path : Paths) {
            const QString NormalizedPath =
                QDir::toNativeSeparators(QFileInfo(Path).absoluteFilePath());
            QString NtPath;
            if (!FileOps::ConvertToNtPath(NormalizedPath, NtPath))
              continue;
            bool AlreadyListed = false;
            for (const ProtectedEntry &Entry : ProtectedFiles_) {
              if (Entry.DisplayPath.compare(NormalizedPath,
                                            Qt::CaseInsensitive) == 0) {
                AlreadyListed = true;
                break;
              }
            }
            if (!AlreadyListed) {
              ProtectedFiles_.push_back({NormalizedPath, NtPath});
              ++ProtectedCount;
            }
          }
          RefreshProtectedRows();
          if (Failures.isEmpty())
            Notify("Protected " + std::to_string(ProtectedCount) + " item(s).",
                   NoticeKind::Success);
          else
            Notify("Failed to protect: " + StorageUtil::JoinLines(Failures),
                   NoticeKind::Error);
          MarkMutated();
        });
  }

  void RefreshProtectedRows() {
    std::vector<TuiRow> Rows;
    Rows.reserve(ProtectedFiles_.size());
    for (const ProtectedEntry &Entry : ProtectedFiles_) {
      Rows.push_back(TuiRow{{StorageUtil::Utf8(QFileInfo(Entry.DisplayPath).fileName()),
                             StorageUtil::Utf8(Entry.DisplayPath)},
                            StorageUtil::Utf8(Entry.NtPath)});
    }
    Protected_.Rows = std::move(Rows);
    Protected_.Filter = Filter;
    Protected_.Rebuild();
  }

  void UnprotectSelection() {
    std::vector<ProtectedEntry> Entries;
    for (int Index : StorageUtil::SelectedRows(Protected_)) {
      if (Index < 0 || Index >= static_cast<int>(ProtectedFiles_.size()))
        continue;
      Entries.push_back(ProtectedFiles_[static_cast<size_t>(Index)]);
    }
    if (Entries.empty())
      return;
    if (Protecting_.exchange(true))
      return;
    TuiAsync<QStringList>(
        [Entries] {
          QStringList Failures;
          for (const ProtectedEntry &Entry : Entries) {
            const std::wstring WidePath = Entry.NtPath.toStdWString();
            if (!UnprotectFile(WidePath.c_str()))
              Failures.append(QFileInfo(Entry.DisplayPath).fileName());
          }
          return Failures;
        },
        [this, Entries](QStringList Failures) {
          Protecting_ = false;
          for (const ProtectedEntry &Entry : Entries) {
            const bool Failed =
                Failures.contains(QFileInfo(Entry.DisplayPath).fileName());
            if (Failed)
              continue;
            for (size_t Index = 0; Index < ProtectedFiles_.size(); ++Index) {
              if (ProtectedFiles_[Index].DisplayPath.compare(
                      Entry.DisplayPath, Qt::CaseInsensitive) == 0) {
                ProtectedFiles_.erase(ProtectedFiles_.begin() +
                                      static_cast<ptrdiff_t>(Index));
                break;
              }
            }
          }
          Protected_.Marked.clear();
          RefreshProtectedRows();
          if (Failures.isEmpty())
            Notify("Unprotected " + std::to_string(Entries.size()) + " item(s).",
                   NoticeKind::Success);
          else
            Notify("Failed to unprotect: " +
                       StorageUtil::JoinLines(Failures),
                   NoticeKind::Error);
          MarkMutated();
        });
  }

  // ---- 文件监控 ----

  static QString MajorOperationText(ULONG Major) {
    switch (Major) {
    case 0x00:
      return "IRP_MJ_CREATE";
    case 0x04:
      return "IRP_MJ_WRITE";
    case 0x06:
      return "IRP_MJ_SET_INFORMATION";
    default:
      return QString("Major 0x%1").arg(Major, 0, 16).toUpper();
    }
  }

  static MonitorEntry BuildMonitorEntry(const MonitorSimpleEvent &Event) {
    const QString Extra = QString::fromWCharArray(Event.Extra);
    const QString Operation =
        Extra.contains(" | ") ? Extra.section(" | ", 0, 0) : Extra;
    const QString ProcessImage =
        Extra.contains(" | ") ? Extra.section(" | ", 1) : QString();
    const std::wstring ProcessName = GetProcessNameFromPid(Event.ProcessId);
    const QString Process =
        ProcessImage.isEmpty()
            ? (ProcessName.empty()
                   ? QString("<unknown>")
                   : QString::fromStdWString(ProcessName))
            : QString("%1 | %2")
                  .arg(ProcessName.empty()
                           ? QString("<unknown>")
                           : QString::fromStdWString(ProcessName),
                       ProcessImage);
    MonitorEntry Entry;
    Entry.Time = MonitorTimestamp(Event.TimeStamp);
    Entry.Operation = Operation.isEmpty() ? "FileOp" : Operation;
    Entry.Process = Process;
    Entry.Path = QString::fromWCharArray(Event.Path);
    Entry.ProcessId = Event.ProcessId;
    Entry.Detail =
        QString("%1\n\nProcess: %2\nPID: %3\nTID: %4\nOperation: %5\nPath: "
                "%6\nExtra: %7\nMajor: %8\nMinor: %9 (0x%10)")
            .arg(Entry.Time, Entry.Process)
            .arg(Event.ProcessId)
            .arg(Event.ThreadId)
            .arg(Entry.Operation, Entry.Path,
                 Extra.isEmpty() ? QString("-") : Extra,
                 MajorOperationText(Event.Data1))
            .arg(Event.Data2)
            .arg(QString::number(Event.Data2, 16).toUpper());
    return Entry;
  }

  void EnsureFileMonitorWorker() {
    if (FileMonitor_)
      return;
    FileMonitor_ = std::make_unique<SimpleEventMonitor>(MonitorChannel::File);
    FileMonitor_->SetCallback([this](const MonitorSimpleEvent &Event) {
      MonitorEntry Entry = BuildMonitorEntry(Event);
      {
        std::lock_guard<std::mutex> Lock(MonitorMutex_);
        MonitorEvents_.insert(MonitorEvents_.begin(), std::move(Entry));
        if (MonitorEvents_.size() > 500)
          MonitorEvents_.resize(500);
      }
      MonitorVersion_.fetch_add(1, std::memory_order_relaxed);
    });
  }

  void StartMonitoringDirectory(const QString &DirectoryPath,
                               bool SwitchToMonitorTab, bool ShowNotice) {
    if (DirectoryPath.isEmpty())
      return;
    const QFileInfo Information(DirectoryPath);
    const QString AbsoluteDirectory =
        Information.isDir() ? Information.absoluteFilePath()
                            : Information.absolutePath();
    if (AbsoluteDirectory.isEmpty() ||
        !QFileInfo(AbsoluteDirectory).isDir()) {
      Notify("Select a valid directory first.", NoticeKind::Error);
      return;
    }

    QString NtPath;
    if (!FileOps::ConvertToNtPath(AbsoluteDirectory, NtPath)) {
      Notify("Unable to convert the directory to an NT path.",
             NoticeKind::Error);
      return;
    }

    try {
      EnsureFileMonitorWorker();
      if (!AegisSentinelSetWatchDirectory(NtPath.toStdWString().c_str())) {
        Notify(QString("Kernel watch setup failed (error %1).")
                   .arg(GetLastError())
                   .toStdString(),
               NoticeKind::Error);
        return;
      }
      if (FileMonitor_ && !FileMonitor_->IsRunning() &&
          !FileMonitor_->Start()) {
        Notify("Failed to start the file monitor worker.", NoticeKind::Error);
        return;
      }
    } catch (const std::exception &Error) {
      FileMonitor_.reset();
      Notify(QString::fromLocal8Bit(Error.what()).toStdString(),
             NoticeKind::Error);
      return;
    }

    WatchedDisplayPath_ = QDir::toNativeSeparators(AbsoluteDirectory);
    WatchedNtPath_ = NtPath;
    ClearMonitorEvents();
    if (SwitchToMonitorTab)
      Tab_ = 2;
    if (ShowNotice)
      Notify("Directory monitoring started.", NoticeKind::Success);
  }

  void StopFileMonitor(bool ShowNotice) {
    if (FileMonitor_) {
      FileMonitor_->Stop();
      FileMonitor_.reset();
    }
    AegisSentinelClearWatchDirectory();
    WatchedDisplayPath_.clear();
    WatchedNtPath_.clear();
    if (ShowNotice)
      Notify("Directory monitoring stopped.", NoticeKind::Success);
  }

  void ClearMonitorEvents() {
    {
      std::lock_guard<std::mutex> Lock(MonitorMutex_);
      MonitorEvents_.clear();
    }
    MonitorVersion_.fetch_add(1, std::memory_order_relaxed);
    DisplayedVersion_ = MonitorVersion_.load(std::memory_order_relaxed);
    RefreshMonitorRows();
  }

  void RefreshMonitorRows() {
    std::vector<MonitorEntry> Copy;
    {
      std::lock_guard<std::mutex> Lock(MonitorMutex_);
      Copy = MonitorEvents_;
    }
    std::vector<TuiRow> Rows;
    Rows.reserve(Copy.size());
    for (const MonitorEntry &Entry : Copy) {
      Rows.push_back(TuiRow{{StorageUtil::Utf8(Entry.Time),
                             StorageUtil::Utf8(Entry.Operation),
                             StorageUtil::Utf8(Entry.Process),
                             std::to_string(Entry.ProcessId),
                             StorageUtil::Utf8(Entry.Path)},
                            StorageUtil::Utf8(Entry.Detail)});
    }
    Monitor_.Rows = std::move(Rows);
    Monitor_.Filter = Filter;
    Monitor_.Rebuild();
  }

  void ShowMonitorDetails(const std::string &Argument = {}) {
    if (!Dialogs)
      return;
    const std::string Number = TrimAscii(Argument);
    if (!Number.empty()) {
      bool Ok = false;
      const long Position = StorageUtil::Q(Number).toLong(&Ok);
      if (!Ok || Position < 1 ||
          Position > static_cast<long>(Monitor_.Visible.size())) {
        Notify("details: 1.." + std::to_string(Monitor_.Visible.size()),
               NoticeKind::Warning);
        return;
      }
      Monitor_.Selected = static_cast<int>(Position) - 1;
    }
    const TuiRow *Row = Monitor_.Current();
    if (!Row) {
      Notify("No monitor event is selected.", NoticeKind::Info);
      return;
    }
    std::string Detail = Row->Detail;
    if (Detail.empty()) {
      for (size_t Index = 0; Index < Row->Cells.size(); ++Index) {
        if (Index)
          Detail += '\n';
        if (Index < Monitor_.Headers.size())
          Detail += Monitor_.Headers[Index] + ": ";
        Detail += Row->Cells[Index];
      }
    }
    // 详情对话框只显示一行行文本；超长时截断，避免撑爆窗口。
    const size_t Limit = 4000;
    if (Detail.size() > Limit)
      Detail = Detail.substr(0, Limit) + "\n…";
    TuiDialog Dialog;
    Dialog.Title = "File monitor details";
    Dialog.Body = Detail;
    Dialog.PrimaryLabel = "Close";
    Dialog.SecondaryLabel.clear();
    Dialog.OnSubmit = [](TuiDialog &) {};
    Dialogs->Push(std::move(Dialog));
  }

  int Index_ = 0;
  bool Entered_ = false;
  int Tab_ = 0;
  int64_t LastStatusMs_ = 0;

  QString CurrentPath_;
  std::vector<QString> History_;
  int HistoryIndex_ = -1;

  TuiTable Explorer_;
  TuiTable Protected_;
  TuiTable Monitor_;

  std::vector<ProtectedEntry> ProtectedFiles_;

  std::unique_ptr<SimpleEventMonitor> FileMonitor_;
  std::mutex MonitorMutex_;
  std::vector<MonitorEntry> MonitorEvents_;
  std::atomic<uint64_t> MonitorVersion_{0};
  uint64_t DisplayedVersion_ = 0;
  QString WatchedDisplayPath_;
  QString WatchedNtPath_;

  std::atomic_bool Listing_{false};
  std::atomic_bool Deleting_{false};
  std::atomic_bool Copying_{false};
  std::atomic_bool Protecting_{false};
};

std::unique_ptr<TuiPage> MakeFilePage(int Index) {
  return std::make_unique<FilePage>(Index);
}

// ------------------------------------------------------------
// Registry 编码/路径助手（GUI RegistryManagerPage 的私有 static 复制）
// ------------------------------------------------------------

namespace RegistryCodec {

struct Location {
  HKEY Root = nullptr;
  QString RootName;
  QString SubKey;
};

// 启动项 12 个位置（GUI RefreshValues 的默认列表）。
struct StartupEntry {
  HKEY Root;
  const char *RootName;
  const char *Path;
  const char *Location;
};

const StartupEntry kStartupEntries[] = {
    {HKEY_CURRENT_USER, "HKCU",
     "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Current user / Run"},
    {HKEY_CURRENT_USER, "HKCU",
     "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
     "Current user / RunOnce"},
    {HKEY_CURRENT_USER, "HKCU",
     "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
     "Current user / RunServices"},
    {HKEY_CURRENT_USER, "HKCU",
     "Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
     "Current user / RunServicesOnce"},
    {HKEY_LOCAL_MACHINE, "HKLM",
     "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "All users / Run"},
    {HKEY_LOCAL_MACHINE, "HKLM",
     "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
     "All users / RunOnce"},
    {HKEY_LOCAL_MACHINE, "HKLM",
     "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices",
     "All users / RunServices"},
    {HKEY_LOCAL_MACHINE, "HKLM",
     "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
     "All users / RunServicesOnce"},
    {HKEY_CURRENT_USER, "HKCU",
     "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
     "Current user / Explorer policy"},
    {HKEY_LOCAL_MACHINE, "HKLM",
     "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
     "All users / Explorer policy"},
    {HKEY_USERS, "HKU",
     ".DEFAULT\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
     "Default user / Run"},
    {HKEY_LOCAL_MACHINE, "HKLM",
     "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "Winlogon"},
};

// 五种根键的长名/短名表（GUI ParseLocation 的同序表）。
struct RootAlias {
  const char *LongName;
  const char *ShortName;
  HKEY Root;
};

const RootAlias kRoots[] = {
    {"HKEY_LOCAL_MACHINE", "HKLM", HKEY_LOCAL_MACHINE},
    {"HKLM", "HKLM", HKEY_LOCAL_MACHINE},
    {"HKEY_CURRENT_USER", "HKCU", HKEY_CURRENT_USER},
    {"HKCU", "HKCU", HKEY_CURRENT_USER},
    {"HKEY_USERS", "HKU", HKEY_USERS},
    {"HKU", "HKU", HKEY_USERS},
    {"HKEY_CLASSES_ROOT", "HKCR", HKEY_CLASSES_ROOT},
    {"HKCR", "HKCR", HKEY_CLASSES_ROOT},
    {"HKEY_CURRENT_CONFIG", "HKCC", HKEY_CURRENT_CONFIG},
    {"HKCC", "HKCC", HKEY_CURRENT_CONFIG},
};

bool Parse(const QString &Text, Location &Result) {
  QString Path = QDir::fromNativeSeparators(Text.trimmed()).replace('/', '\\');
  while (Path.startsWith('\\'))
    Path.remove(0, 1);
  for (const RootAlias &Alias : kRoots) {
    const QString Prefix = QString::fromLatin1(Alias.LongName);
    if (Path.compare(Prefix, Qt::CaseInsensitive) == 0 ||
        Path.startsWith(Prefix + "\\", Qt::CaseInsensitive)) {
      Result.Root = Alias.Root;
      Result.RootName = QString::fromLatin1(Alias.ShortName);
      Result.SubKey = Path.mid(Prefix.size());
      while (Result.SubKey.startsWith('\\'))
        Result.SubKey.remove(0, 1);
      return true;
    }
  }
  return false;
}

QString TypeName(DWORD Type) {
  switch (Type) {
  case REG_SZ:
    return "REG_SZ";
  case REG_EXPAND_SZ:
    return "REG_EXPAND_SZ";
  case REG_DWORD:
    return "REG_DWORD";
  case REG_QWORD:
    return "REG_QWORD";
  case REG_MULTI_SZ:
    return "REG_MULTI_SZ";
  case REG_BINARY:
    return "REG_BINARY";
  case REG_NONE:
    return "REG_NONE";
  default:
    return QString("REG_%1").arg(Type);
  }
}

QString ValueDataText(DWORD Type, const std::vector<BYTE> &Data) {
  if ((Type == REG_SZ || Type == REG_EXPAND_SZ) &&
      Data.size() >= sizeof(wchar_t)) {
    QString Value = QString::fromWCharArray(
        reinterpret_cast<const wchar_t *>(Data.data()),
        static_cast<qsizetype>(Data.size() / sizeof(wchar_t)));
    while (Value.endsWith(QChar::Null))
      Value.chop(1);
    return Value;
  }
  if (Type == REG_DWORD && Data.size() >= sizeof(DWORD)) {
    DWORD Value = 0;
    std::memcpy(&Value, Data.data(), sizeof(Value));
    return QString("%1 (0x%2)")
        .arg(Value)
        .arg(Value, 8, 16, QLatin1Char('0'))
        .toUpper();
  }
  if (Type == REG_QWORD && Data.size() >= sizeof(ULONGLONG)) {
    ULONGLONG Value = 0;
    std::memcpy(&Value, Data.data(), sizeof(Value));
    return QString("%1 (0x%2)")
        .arg(Value)
        .arg(Value, 16, 16, QLatin1Char('0'))
        .toUpper();
  }
  if (Type == REG_MULTI_SZ && Data.size() >= sizeof(wchar_t)) {
    QStringList Values;
    const wchar_t *Current = reinterpret_cast<const wchar_t *>(Data.data());
    const wchar_t *End = Current + Data.size() / sizeof(wchar_t);
    while (Current < End && *Current) {
      const size_t Length =
          wcsnlen_s(Current, static_cast<size_t>(End - Current));
      Values.append(
          QString::fromWCharArray(Current, static_cast<qsizetype>(Length)));
      Current += Length + 1;
    }
    return Values.join(" | ");
  }
  QStringList Bytes;
  for (BYTE Value : Data)
    Bytes.append(QString("%1").arg(Value, 2, 16, QLatin1Char('0')).toUpper());
  return Bytes.join(' ');
}

int TypeIndex(DWORD Type) {
  switch (Type) {
  case REG_SZ:
    return 0;
  case REG_EXPAND_SZ:
    return 1;
  case REG_DWORD:
    return 2;
  case REG_QWORD:
    return 3;
  case REG_MULTI_SZ:
    return 4;
  case REG_BINARY:
    return 5;
  default:
    return 0;
  }
}

DWORD TypeFromIndex(int Index) {
  static const std::array<DWORD, 6> Types{
      REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_QWORD, REG_MULTI_SZ, REG_BINARY};
  return Index >= 0 && Index < static_cast<int>(Types.size())
             ? Types[static_cast<size_t>(Index)]
             : REG_SZ;
}

// 对话框里显示的类型列表，与 GUI 的 ComboBox 完全一致。
const std::vector<std::string> &TypeChoices() {
  static const std::vector<std::string> Choices{
      "String (REG_SZ)",  "Expandable string", "DWORD",
      "QWORD",            "Multi-string",      "Binary"};
  return Choices;
}

bool EncodeValueData(DWORD Type, const QString &Text,
                     std::vector<BYTE> &Data) {
  if (Type == REG_SZ || Type == REG_EXPAND_SZ) {
    const std::wstring Value = Text.toStdWString();
    Data.resize((Value.size() + 1) * sizeof(wchar_t));
    std::memcpy(Data.data(), Value.c_str(), Data.size());
    return true;
  }
  if (Type == REG_DWORD || Type == REG_QWORD) {
    bool Ok = false;
    const qulonglong Value = Text.trimmed().toULongLong(&Ok, 0);
    if (!Ok)
      return false;
    if (Type == REG_DWORD) {
      const DWORD Number = static_cast<DWORD>(Value);
      Data.resize(sizeof(Number));
      std::memcpy(Data.data(), &Number, sizeof(Number));
    } else {
      const ULONGLONG Number = Value;
      Data.resize(sizeof(Number));
      std::memcpy(Data.data(), &Number, sizeof(Number));
    }
    return true;
  }
  if (Type == REG_MULTI_SZ) {
    const QStringList Values = Text.split('\n', Qt::SkipEmptyParts);
    std::vector<wchar_t> Buffer;
    for (const QString &Value : Values) {
      const std::wstring Wide = Value.trimmed().toStdWString();
      Buffer.insert(Buffer.end(), Wide.begin(), Wide.end());
      Buffer.push_back(L'\0');
    }
    Buffer.push_back(L'\0');
    Data.resize(Buffer.size() * sizeof(wchar_t));
    std::memcpy(Data.data(), Buffer.data(), Data.size());
    return true;
  }
  QString Hex = Text;
  Hex.remove(' ');
  Hex.remove(',');
  Hex.remove('-');
  Hex.replace("0x", "", Qt::CaseInsensitive);
  if (Hex.size() % 2 != 0)
    return false;
  Data.clear();
  for (qsizetype Index = 0; Index < Hex.size(); Index += 2) {
    bool Ok = false;
    const int Value = Hex.mid(Index, 2).toInt(&Ok, 16);
    if (!Ok)
      return false;
    Data.push_back(static_cast<BYTE>(Value));
  }
  return true;
}

QString CurrentUserSid() {
  HANDLE Token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token))
    return {};
  DWORD Size = 0;
  GetTokenInformation(Token, TokenUser, nullptr, 0, &Size);
  std::vector<BYTE> Buffer(Size);
  QString Sid;
  if (GetTokenInformation(Token, TokenUser, Buffer.data(), Size, &Size)) {
    LPWSTR Text = nullptr;
    if (ConvertSidToStringSidW(
            reinterpret_cast<TOKEN_USER *>(Buffer.data())->User.Sid, &Text)) {
      Sid = QString::fromWCharArray(Text);
      LocalFree(Text);
    }
  }
  CloseHandle(Token);
  return Sid;
}

bool ToKernelRegistryPath(const QString &Input, QString &KernelPath) {
  QString Path = Input.trimmed().replace('/', '\\');
  if (Path.startsWith("\\Registry\\", Qt::CaseInsensitive)) {
    KernelPath = Path;
    return true;
  }
  Location Parsed;
  if (!Parse(Path, Parsed))
    return false;
  if (Parsed.Root == HKEY_LOCAL_MACHINE) {
    KernelPath = "\\Registry\\Machine";
  } else if (Parsed.Root == HKEY_CURRENT_USER) {
    const QString Sid = CurrentUserSid();
    if (Sid.isEmpty())
      return false;
    KernelPath = "\\Registry\\User\\" + Sid;
  } else if (Parsed.Root == HKEY_USERS) {
    KernelPath = "\\Registry\\User";
  } else if (Parsed.Root == HKEY_CLASSES_ROOT) {
    KernelPath = "\\Registry\\Machine\\Software\\Classes";
  } else if (Parsed.Root == HKEY_CURRENT_CONFIG) {
    KernelPath = "\\Registry\\Machine\\System\\CurrentControlSet\\Hardware "
                 "Profiles\\Current";
  } else {
    return false;
  }
  if (!Parsed.SubKey.isEmpty())
    KernelPath += "\\" + Parsed.SubKey;
  return true;
}

} // namespace RegistryCodec

// ------------------------------------------------------------
// 索引 3：Registry
// ------------------------------------------------------------

class RegistryPage final : public TuiPage {
  struct ValueRow {
    QString RootName;
    QString KeyPath;
    QString Location;
    QString Name;
    QString Data;
    DWORD Type = REG_NONE;
  };

  struct ProtectedEntry {
    QString DisplayPath;
    QString KernelPath;
  };

  struct BrowseRow {
    QString Name;
    QString Path;   // "HKLM\SOFTWARE\..."
    HKEY Root = nullptr;
    QString RootName;
    QString SubKey;
    bool IsRoot = false;
  };

  struct QueryResult {
    bool Ok = false;
    std::vector<ValueRow> Rows;
    QString Error;
  };

public:
  explicit RegistryPage(int Index) : Index_(Index) {
    Values_.Headers = {"Location", "Registry path", "Value name", "Type",
                       "Data"};
    Values_.RightAlign = {false, false, false, false, false};

    Protected_.Headers = {"Registry path", "Kernel path"};
    Protected_.RightAlign = {false, false};
    Protected_.MultiSelect = true;

    Browse_.Headers = {"Name", "Path"};
    Browse_.RightAlign = {false, false};

    Address_ = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    RegisterCommands();
  }

  std::string Title() const override { return "Registry"; }

  std::string Subtitle() const override {
    return "registry values, protected keys, key browser";
  }

  void OnEnter() override {
    // `use` / `refresh` 都走这里：重新枚举一次并刷新保护列表。
    RefreshValues(false);
    RefreshProtectedRows();
  }

  void OnTick(int64_t NowMs) override {
    (void)NowMs;
  }

  TuiTable *ActiveTable() override {
    switch (Tab_) {
    case 1:
      return &Protected_;
    case 2:
      return &Browse_;
    default:
      return &Values_;
    }
  }

  std::string RenderText() override {
    // `show`：用页面自己的填充函数重放一遍（同步、读缓存），再打印 ASCII 表。
    switch (Tab_) {
    case 1:
      RefreshProtectedRows();
      break;
    case 2:
      PopulateBrowse();
      break;
    default:
      PopulateValues();
      break;
    }
    const TuiTable &Table = *ActiveTable();
    std::string Text =
        TabStrip({"Browser", "Protected", "Keys"}, Tab_) + "\n";
    switch (Tab_) {
    case 1:
      Text += "Protected: " + std::to_string(ProtectedFiles_.size()) +
              " path(s)\n";
      break;
    case 2:
      Text += "Browse: " +
              (BrowsePath_.isEmpty() ? std::string("\\")
                                     : StorageUtil::Utf8(BrowsePath_)) +
              "\n";
      break;
    default:
      Text += "Source: " + SourceName() + "\nKey: " +
              StorageUtil::Utf8(Address_) + "\n";
      break;
    }
    Text += TuiTableToText(Table, 200);
    return Text;
  }

private:
  std::string SourceName() const {
    switch (Source_) {
    case 0:
      return "Startup items";
    case 1:
      return "Image hijacks";
    default:
      return "Selected path";
    }
  }

  void RegisterCommands() {
    const auto Add = [this](std::string Name, std::string Usage,
                            std::function<void(std::vector<std::string>)> Fn) {
      OwnedCommands.push_back(TuiCommand{std::move(Name), std::move(Usage),
                                         std::move(Fn)});
    };

    Add("source", "source <startup|hijack|path>  (switch enumeration source)",
        [this](std::vector<std::string> Args) {
          if (Args.empty()) {
            Notify("Usage: source <startup|hijack|path>",
                   NoticeKind::Warning);
            return;
          }
          const std::string Name = LowerAscii(Args.front());
          if (Name == "startup" || Name == "startup-items" || Name == "0") {
            Source_ = 0;
            Address_ = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
          } else if (Name == "hijack" || Name == "hijacks" || Name == "1") {
            Source_ = 1;
            Address_ = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
                       "\\Image File Execution Options";
          } else if (Name == "path" || Name == "selected" || Name == "2") {
            Source_ = 2;
          } else {
            Notify("Unknown source: " + Args.front(), NoticeKind::Warning);
            return;
          }
          Tab_ = 0;
          RefreshValues(false);
        });
    Add("cd", "cd <registry path>  (select a path and enumerate it)",
        [this](std::vector<std::string> Args) {
          if (Args.empty()) {
            Notify("Usage: cd <HKLM\\Software\\...>", NoticeKind::Warning);
            return;
          }
          std::string Joined;
          for (const std::string &Part : Args) {
            if (!Joined.empty())
              Joined += ' ';
            Joined += Part;
          }
          RegistryCodec::Location Parsed;
          if (!RegistryCodec::Parse(StorageUtil::Q(Joined), Parsed)) {
            Notify("Enter a valid HKLM, HKCU, HKU, HKCR, or HKCC path.",
                   NoticeKind::Error);
            return;
          }
          Source_ = 2;
          Address_ = StorageUtil::Q(Joined);
          RefreshValues(false);
        });
    Add("browse", "browse  (open the key browser)",
        [this](std::vector<std::string>) {
          Tab_ = 2;
          LoadBrowseRoots();
        });
    Add("view", "view [browser|protected|keys]  (switch view)",
        [this](std::vector<std::string> Args) {
          if (!Args.empty()) {
            const std::string Name = LowerAscii(Args.front());
            if (Name == "browser" || Name == "values" || Name == "0")
              Tab_ = 0;
            else if (Name == "protected" || Name == "1")
              Tab_ = 1;
            else if (Name == "keys" || Name == "browse" || Name == "2")
              Tab_ = 2;
            else {
              Notify("Unknown view: " + Args.front(), NoticeKind::Warning);
              return;
            }
          } else {
            Tab_ = (Tab_ + 1) % 3;
          }
        });
    Add("descend", "descend  (open the selected key in the browser)",
        [this](std::vector<std::string>) { BrowseDescend(); });
    Add("use", "use  (use the selected browser key)",
        [this](std::vector<std::string>) { UseBrowseSelection(); });
    Add("refresh", "refresh  (reload registry values)",
        [this](std::vector<std::string>) {
          RefreshValues(true);
          RefreshProtectedRows();
          Notify("Registry values refreshed.", NoticeKind::Success);
        });
    Add("protect", "protect [path]  (protect a registry key)",
        [this](std::vector<std::string> Args) {
          if (!Args.empty()) {
            Address_ = StorageUtil::Q(Args.front());
            Source_ = 2;
          }
          ProtectAddress();
        });
    Add("new-key", "new-key [name]  (create a child key)",
        [this](std::vector<std::string> Args) {
          if (!Args.empty()) {
            CreateChildKey(StorageUtil::Q(Args.front()));
            return;
          }
          PromptTextDialog(*Dialogs, "New registry key", "Child key name:", {},
                           [this](std::string Name) {
                             CreateChildKey(StorageUtil::Q(TrimAscii(Name)));
                           });
        });
    Add("new-value", "new-value  (create a registry value)",
        [this](std::vector<std::string>) { ShowValueDialog(false); });
    Add("modify", "modify  (edit the selected value)",
        [this](std::vector<std::string>) { ShowModifyValue(); });
    Add("delete", "delete  (delete the selected value)",
        [this](std::vector<std::string>) { DeleteSelectedValue(); });
    Add("unprotect", "unprotect  (unprotect the selected path)",
        [this](std::vector<std::string>) { UnprotectSelection(); });
  }

  // ---- 枚举 ----

  void RefreshValues(bool Report) {
    if (Refreshing_.exchange(true)) {
      if (Report)
        Notify("Already refreshing registry values.", NoticeKind::Info);
      return;
    }
    const int Source = Source_;
    const QString Address = Address_;
    TuiAsync<QueryResult>(
        [Source, Address] {
          QueryResult Result;
          std::vector<ValueRow> Rows;

          const auto EnumerateKey = [&Rows](HKEY Root, const QString &RootName,
                                            const QString &KeyPath,
                                            const QString &Location) {
            HKEY Key = nullptr;
            if (RegOpenKeyExW(Root, reinterpret_cast<LPCWSTR>(KeyPath.utf16()),
                              0, KEY_READ | KEY_WOW64_64KEY,
                              &Key) != ERROR_SUCCESS)
              return;
            DWORD ValueCount = 0, MaximumNameLength = 0, MaximumDataLength = 0;
            RegQueryInfoKeyW(Key, nullptr, nullptr, nullptr, nullptr, nullptr,
                             nullptr, &ValueCount, &MaximumNameLength,
                             &MaximumDataLength, nullptr, nullptr);
            std::vector<wchar_t> Name(
                static_cast<size_t>(MaximumNameLength) + 2);
            std::vector<BYTE> Data(static_cast<size_t>(MaximumDataLength) +
                                   sizeof(wchar_t) * 2);
            for (DWORD Index = 0; Index < ValueCount; ++Index) {
              DWORD NameLength = static_cast<DWORD>(Name.size());
              DWORD DataLength = static_cast<DWORD>(Data.size());
              DWORD Type = REG_NONE;
              const LSTATUS Status = RegEnumValueW(
                  Key, Index, Name.data(), &NameLength, nullptr, &Type,
                  Data.data(), &DataLength);
              if (Status != ERROR_SUCCESS)
                continue;
              std::vector<BYTE> ValueData(Data.begin(),
                                          Data.begin() + DataLength);
              Rows.push_back({RootName, KeyPath, Location,
                              QString::fromWCharArray(Name.data(), NameLength),
                              RegistryCodec::ValueDataText(Type, ValueData),
                              Type});
            }
            RegCloseKey(Key);
          };

          if (Source == 0) {
            for (const RegistryCodec::StartupEntry &Entry :
                 RegistryCodec::kStartupEntries) {
              EnumerateKey(Entry.Root, QString::fromLatin1(Entry.RootName),
                           QString::fromLatin1(Entry.Path),
                           QString::fromLatin1(Entry.Location));
            }
          } else if (Source == 1) {
            const QString BasePath =
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File "
                "Execution Options";
            HKEY BaseKey = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                              reinterpret_cast<LPCWSTR>(BasePath.utf16()), 0,
                              KEY_READ | KEY_WOW64_64KEY,
                              &BaseKey) == ERROR_SUCCESS) {
              DWORD SubKeyCount = 0, MaximumNameLength = 0;
              RegQueryInfoKeyW(BaseKey, nullptr, nullptr, nullptr, &SubKeyCount,
                               &MaximumNameLength, nullptr, nullptr, nullptr,
                               nullptr, nullptr, nullptr);
              std::vector<wchar_t> Name(
                  static_cast<size_t>(MaximumNameLength) + 2);
              for (DWORD Index = 0; Index < SubKeyCount; ++Index) {
                DWORD NameLength = static_cast<DWORD>(Name.size());
                if (RegEnumKeyExW(BaseKey, Index, Name.data(), &NameLength,
                                  nullptr, nullptr, nullptr,
                                  nullptr) == ERROR_SUCCESS)
                  EnumerateKey(
                      HKEY_LOCAL_MACHINE, "HKLM",
                      BasePath + "\\" +
                          QString::fromWCharArray(Name.data(), NameLength),
                      "Image hijack");
              }
              RegCloseKey(BaseKey);
            }
          } else {
            RegistryCodec::Location Parsed;
            if (RegistryCodec::Parse(Address, Parsed))
              EnumerateKey(Parsed.Root, Parsed.RootName, Parsed.SubKey,
                           "Selected path");
          }

          std::sort(Rows.begin(), Rows.end(),
                    [](const ValueRow &Left, const ValueRow &Right) {
                      const int LocationCompare = Left.Location.compare(
                          Right.Location, Qt::CaseInsensitive);
                      if (LocationCompare != 0)
                        return LocationCompare < 0;
                      const int KeyCompare =
                          (Left.RootName + Left.KeyPath)
                              .compare(Right.RootName + Right.KeyPath,
                                       Qt::CaseInsensitive);
                      return KeyCompare == 0
                                 ? Left.Name.compare(Right.Name,
                                                     Qt::CaseInsensitive) < 0
                                 : KeyCompare < 0;
                    });

          Result.Ok = true;
          Result.Rows = std::move(Rows);
          return Result;
        },
        [this](QueryResult Result) {
          Refreshing_ = false;
          if (!Result.Ok) {
            Notify(Result.Error.isEmpty()
                       ? "Registry enumeration failed."
                       : Result.Error.toStdString(),
                   NoticeKind::Error);
            SetStatus("0 values");
            return;
          }
          Rows_ = std::move(Result.Rows);
          PopulateValues();
        });
  }

  void PopulateValues() {
    std::vector<TuiRow> Rows;
    Rows.reserve(Rows_.size());
    for (const ValueRow &Value : Rows_) {
      Rows.push_back(TuiRow{{StorageUtil::Utf8(Value.Location),
                             StorageUtil::Utf8(Value.RootName + "\\" +
                                               Value.KeyPath),
                             StorageUtil::Utf8(Value.Name.isEmpty()
                                                   ? QString("(Default)")
                                                   : Value.Name),
                             StorageUtil::Utf8(
                                 RegistryCodec::TypeName(Value.Type)),
                             StorageUtil::Utf8(Value.Data)},
                            StorageUtil::Utf8(Value.Data)});
    }
    Values_.Rows = std::move(Rows);
    Values_.Filter = Filter;
    Values_.Rebuild();
    const int Total = static_cast<int>(Rows_.size());
    const int Visible = static_cast<int>(Values_.Visible.size());
    SetStatus(Filter.empty()
                  ? std::to_string(Total) + " value" + (Total == 1 ? "" : "s")
                  : std::to_string(Visible) + " of " + std::to_string(Total));
  }

  const ValueRow *SelectedValue() const {
    const int Index = Values_.CurrentRowIndex();
    if (Index < 0 || Index >= static_cast<int>(Rows_.size()))
      return nullptr;
    return &Rows_[static_cast<size_t>(Index)];
  }

  // ---- 写操作 ----

  bool PrepareLocation(RegistryCodec::Location &Parsed,
                       const QString &FallbackError) {
    if (!RegistryCodec::Parse(Address_, Parsed)) {
      Notify(FallbackError.toStdString(), NoticeKind::Error);
      return false;
    }
    return true;
  }

  void CreateChildKey(const QString &ChildName) {
    if (ChildName.isEmpty()) {
      Notify("Enter a key name.", NoticeKind::Warning);
      return;
    }
    RegistryCodec::Location Parsed;
    if (!PrepareLocation(Parsed,
                         "Enter a valid HKLM, HKCU, HKU, HKCR, or HKCC path."))
      return;
    const QString TargetPath =
        Parsed.SubKey.isEmpty() ? ChildName : Parsed.SubKey + "\\" + ChildName;
    if (Write_.exchange(true))
      return;
    TuiAsync<std::pair<bool, DWORD>>(
        [Parsed, TargetPath] {
          DWORD Status = ERROR_GEN_FAILURE;
          QString KernelPath;
          bool Success = false;
          if (RegistryCodec::ToKernelRegistryPath(
                  Parsed.RootName + "\\" + TargetPath, KernelPath)) {
            const std::wstring WidePath = KernelPath.toStdWString();
            if (RegCreateKeyKernel(WidePath.c_str())) {
              Status = ERROR_SUCCESS;
              Success = true;
            } else {
              Status = G_LastAegisCoreError;
            }
          }
          if (!Success) {
            HKEY Key = nullptr;
            DWORD Disposition = 0;
            const LSTATUS UserStatus = RegCreateKeyExW(
                Parsed.Root, reinterpret_cast<LPCWSTR>(TargetPath.utf16()), 0,
                nullptr, 0, KEY_READ | KEY_WRITE | KEY_WOW64_64KEY, nullptr,
                &Key, &Disposition);
            if (Key)
              RegCloseKey(Key);
            Status = UserStatus;
            Success = UserStatus == ERROR_SUCCESS;
          }
          return std::pair<bool, DWORD>(Success, Status);
        },
        [this, Parsed, TargetPath](std::pair<bool, DWORD> Outcome) {
          Write_ = false;
          if (!Outcome.first) {
            Notify(QString("Unable to create key (error %1).")
                       .arg(Outcome.second)
                       .toStdString(),
                   NoticeKind::Error);
            return;
          }
          Address_ = Parsed.RootName + "\\" + TargetPath;
          Source_ = 2;
          Tab_ = 0;
          MarkMutated();
          RefreshValues(false);
          Notify("Registry key created.", NoticeKind::Success);
        });
  }

  void ShowModifyValue() {
    const ValueRow *Selected = SelectedValue();
    if (!Selected) {
      Notify("Select a registry value first.", NoticeKind::Warning);
      return;
    }
    ShowValueDialog(true);
  }

  void ShowValueDialog(bool Editing) {
    RegistryCodec::Location Parsed;
    QString InitialName;
    QString InitialData;
    DWORD InitialType = REG_SZ;
    if (Editing) {
      const ValueRow *Selected = SelectedValue();
      if (!Selected)
        return;
      if (!RegistryCodec::Parse(Selected->RootName + "\\" + Selected->KeyPath,
                                Parsed))
        return;
      InitialName = Selected->Name;
      InitialData = Selected->Data;
      InitialType = Selected->Type;
      if (InitialType == REG_DWORD || InitialType == REG_QWORD)
        InitialData = InitialData.section(' ', 0, 0);
    } else if (!RegistryCodec::Parse(Address_, Parsed)) {
      Notify("Enter a valid registry key path first.", NoticeKind::Error);
      return;
    }

    TuiDialog Dialog;
    Dialog.Title = Editing ? "Modify registry value" : "New registry value";
    Dialog.Body = StorageUtil::Utf8(Parsed.RootName + "\\" + Parsed.SubKey);

    TuiField Name;
    Name.Label = "Value name";
    // 修改已有值时名称不可编辑：ReadOnly 字段只回显，不读输入。
    Name.Kind = Editing ? TuiFieldKind::ReadOnly : TuiFieldKind::Text;
    Name.Value = StorageUtil::Utf8(InitialName);
    Name.Placeholder = "empty for Default";
    Dialog.Fields.push_back(Name);

    TuiField Type;
    Type.Label = "Type";
    Type.Kind = TuiFieldKind::Combo;
    Type.Choices = RegistryCodec::TypeChoices();
    Type.Choice = Editing ? RegistryCodec::TypeIndex(InitialType) : 0;
    Dialog.Fields.push_back(Type);

    TuiField Data;
    Data.Label = "Data";
    Data.Kind = TuiFieldKind::Multiline;
    Data.Value = StorageUtil::Utf8(InitialData);
    Data.Placeholder = "Value data";
    Data.Hint = "multi-string uses one entry per line; binary uses hex bytes";
    Dialog.Fields.push_back(Data);

    Dialog.PrimaryLabel = Editing ? "Save" : "Create";
    Dialog.SecondaryLabel = "Cancel";
    Dialog.Validate = [](const TuiDialog &Current) -> std::string {
      const DWORD Type = RegistryCodec::TypeFromIndex(
          Current.Fields.size() > 1 ? Current.Fields[1].Choice : 0);
      std::vector<BYTE> Buffer;
      if (!RegistryCodec::EncodeValueData(
              Type,
              Current.Fields.size() > 2
                  ? StorageUtil::Q(Current.Fields[2].Value)
                  : QString(),
              Buffer))
        return "The value data format is invalid.";
      return {};
    };
    Dialog.OnSubmit = [this, Parsed](TuiDialog &Submitted) {
      if (Submitted.Fields.size() < 3)
        return;
      const QString ValueName = StorageUtil::Q(Submitted.Fields[0].Value);
      const DWORD ValueType =
          RegistryCodec::TypeFromIndex(Submitted.Fields[1].Choice);
      std::vector<BYTE> Buffer;
      if (!RegistryCodec::EncodeValueData(
              ValueType, StorageUtil::Q(Submitted.Fields[2].Value), Buffer))
        return;
      ApplyValue(Parsed, ValueName, ValueType, std::move(Buffer));
    };
    Dialogs->Push(std::move(Dialog));
  }

  void ApplyValue(RegistryCodec::Location Parsed, const QString &ValueName,
                  DWORD ValueType, std::vector<BYTE> Buffer) {
    if (Write_.exchange(true))
      return;
    TuiAsync<std::pair<bool, DWORD>>(
        [Parsed, ValueName, ValueType, Buffer] {
          DWORD Status = ERROR_GEN_FAILURE;
          QString KernelPath;
          bool Success = false;
          if (RegistryCodec::ToKernelRegistryPath(
                  Parsed.RootName + "\\" + Parsed.SubKey, KernelPath)) {
            const std::wstring WidePath = KernelPath.toStdWString();
            const std::wstring WideName = ValueName.toStdWString();
            if (RegSetValueKernel(WidePath.c_str(), WideName.c_str(), ValueType,
                                  const_cast<BYTE *>(Buffer.data()),
                                  static_cast<ULONG>(Buffer.size()))) {
              Status = ERROR_SUCCESS;
              Success = true;
            } else {
              Status = G_LastAegisCoreError;
            }
          }
          if (!Success) {
            HKEY Key = nullptr;
            const LSTATUS OpenStatus = RegOpenKeyExW(
                Parsed.Root, reinterpret_cast<LPCWSTR>(Parsed.SubKey.utf16()),
                0, KEY_SET_VALUE | KEY_WOW64_64KEY, &Key);
            if (OpenStatus != ERROR_SUCCESS) {
              Status = OpenStatus;
            } else {
              const LSTATUS UserStatus = RegSetValueExW(
                  Key, reinterpret_cast<LPCWSTR>(ValueName.utf16()), 0,
                  ValueType, Buffer.data(),
                  static_cast<DWORD>(Buffer.size()));
              RegCloseKey(Key);
              Status = UserStatus;
              Success = UserStatus == ERROR_SUCCESS;
            }
          }
          return std::pair<bool, DWORD>(Success, Status);
        },
        [this](std::pair<bool, DWORD> Outcome) {
          Write_ = false;
          if (!Outcome.first) {
            Notify(QString("Unable to save value (error %1).")
                       .arg(Outcome.second)
                       .toStdString(),
                   NoticeKind::Error);
            return;
          }
          MarkMutated();
          RefreshValues(false);
          Notify("Registry value saved.", NoticeKind::Success);
        });
  }

  void DeleteSelectedValue() {
    const ValueRow *Selected = SelectedValue();
    if (!Selected)
      return;
    const ValueRow Value = *Selected;
    ConfirmDialog(*Dialogs, "Registry",
                  StorageUtil::Utf8(
                      QString("Delete value '%1' from %2\\%3?")
                          .arg(Value.Name.isEmpty() ? QString("(Default)")
                                                    : Value.Name,
                               Value.RootName, Value.KeyPath)),
                  [this, Value] {
                    RegistryCodec::Location Parsed;
                    if (!RegistryCodec::Parse(
                            Value.RootName + "\\" + Value.KeyPath, Parsed))
                      return;
                    if (Write_.exchange(true))
                      return;
                    TuiAsync<std::pair<bool, DWORD>>(
                        [Parsed, Name = Value.Name] {
                          DWORD Status = ERROR_GEN_FAILURE;
                          QString KernelPath;
                          bool Success = false;
                          if (RegistryCodec::ToKernelRegistryPath(
                                  Parsed.RootName + "\\" + Parsed.SubKey,
                                  KernelPath)) {
                            const std::wstring WidePath =
                                KernelPath.toStdWString();
                            const std::wstring WideName = Name.toStdWString();
                            if (RegDeleteValueKernel(WidePath.c_str(),
                                                     WideName.c_str())) {
                              Status = ERROR_SUCCESS;
                              Success = true;
                            } else {
                              Status = G_LastAegisCoreError;
                            }
                          }
                          if (!Success) {
                            HKEY Key = nullptr;
                            const LSTATUS OpenStatus = RegOpenKeyExW(
                                Parsed.Root,
                                reinterpret_cast<LPCWSTR>(
                                    Parsed.SubKey.utf16()),
                                0, KEY_SET_VALUE | KEY_WOW64_64KEY, &Key);
                            if (OpenStatus != ERROR_SUCCESS) {
                              Status = OpenStatus;
                            } else {
                              const LSTATUS UserStatus = RegDeleteValueW(
                                  Key,
                                  reinterpret_cast<LPCWSTR>(Name.utf16()));
                              RegCloseKey(Key);
                              Status = UserStatus;
                              Success = UserStatus == ERROR_SUCCESS;
                            }
                          }
                          return std::pair<bool, DWORD>(Success, Status);
                        },
                        [this](std::pair<bool, DWORD> Outcome) {
                          Write_ = false;
                          if (!Outcome.first) {
                            Notify(QString("Unable to delete value (error %1).")
                                       .arg(Outcome.second)
                                       .toStdString(),
                                   NoticeKind::Error);
                            return;
                          }
                          MarkMutated();
                          RefreshValues(false);
                          Notify("Registry value deleted.",
                                 NoticeKind::Success);
                        });
                  },
                  "Yes", "No");
  }

  // ---- 保护列表 ----

  void ProtectAddress() {
    const QString DisplayPath = Address_.trimmed();
    QString KernelPath;
    if (!RegistryCodec::ToKernelRegistryPath(DisplayPath, KernelPath)) {
      Notify("Unable to convert the registry address to a kernel path.",
             NoticeKind::Error);
      return;
    }
    if (Protecting_.exchange(true))
      return;
    TuiAsync<DWORD>(
        [KernelPath] {
          const std::wstring WidePath = KernelPath.toStdWString();
          ProtectRegistryKey(WidePath.c_str());
          return G_LastAegisCoreError;
        },
        [this, DisplayPath, KernelPath](DWORD Error) {
          Protecting_ = false;
          if (Error != ERROR_SUCCESS) {
            Notify(QString("Protection failed (error %1).").arg(Error)
                       .toStdString(),
                   NoticeKind::Error);
            return;
          }
          bool Found = false;
          for (const ProtectedEntry &Entry : ProtectedFiles_) {
            if (Entry.KernelPath.compare(KernelPath, Qt::CaseInsensitive) == 0) {
              Found = true;
              break;
            }
          }
          if (!Found)
            ProtectedFiles_.push_back({DisplayPath, KernelPath});
          RefreshProtectedRows();
          MarkMutated();
          Notify("Registry path protected.", NoticeKind::Success);
        });
  }

  void RefreshProtectedRows() {
    std::vector<TuiRow> Rows;
    Rows.reserve(ProtectedFiles_.size());
    for (const ProtectedEntry &Entry : ProtectedFiles_) {
      Rows.push_back(TuiRow{{StorageUtil::Utf8(Entry.DisplayPath),
                             StorageUtil::Utf8(Entry.KernelPath)},
                            StorageUtil::Utf8(Entry.KernelPath)});
    }
    Protected_.Rows = std::move(Rows);
    Protected_.Filter = Filter;
    Protected_.Rebuild();
  }

  void UnprotectSelection() {
    std::vector<QString> KernelPaths;
    for (int Index : StorageUtil::SelectedRows(Protected_)) {
      if (Index < 0 || Index >= static_cast<int>(ProtectedFiles_.size()))
        continue;
      KernelPaths.push_back(ProtectedFiles_[static_cast<size_t>(Index)].KernelPath);
    }
    if (KernelPaths.empty()) {
      Notify("Select a protected registry path first.", NoticeKind::Warning);
      return;
    }
    if (Protecting_.exchange(true))
      return;
    TuiAsync<QStringList>(
        [KernelPaths] {
          QStringList Failures;
          for (const QString &KernelPath : KernelPaths) {
            const std::wstring WidePath = KernelPath.toStdWString();
            UnprotectRegistryKey(WidePath.c_str());
            if (G_LastAegisCoreError != ERROR_SUCCESS)
              Failures.append(KernelPath);
          }
          return Failures;
        },
        [this, KernelPaths](QStringList Failures) {
          Protecting_ = false;
          for (const QString &KernelPath : KernelPaths) {
            if (Failures.contains(KernelPath))
              continue;
            for (size_t Index = 0; Index < ProtectedFiles_.size(); ++Index) {
              if (ProtectedFiles_[Index].KernelPath.compare(
                      KernelPath, Qt::CaseInsensitive) == 0) {
                ProtectedFiles_.erase(ProtectedFiles_.begin() +
                                      static_cast<ptrdiff_t>(Index));
                break;
              }
            }
          }
          Protected_.Marked.clear();
          RefreshProtectedRows();
          MarkMutated();
          if (Failures.isEmpty())
            Notify("Unprotected " + std::to_string(KernelPaths.size()) +
                       " registry path(s).",
                   NoticeKind::Success);
          else
            Notify("Failed to unprotect: " + StorageUtil::JoinLines(Failures),
                   NoticeKind::Error);
        });
  }

  // ---- 键浏览器（GUI 的 ShowRegistryPathDialog 等价物）----

  void LoadBrowseRoots() {
    std::vector<BrowseRow> Rows;
    const std::pair<const char *, HKEY> Roots[] = {
        {"HKCR", HKEY_CLASSES_ROOT}, {"HKCU", HKEY_CURRENT_USER},
        {"HKLM", HKEY_LOCAL_MACHINE}, {"HKU", HKEY_USERS},
        {"HKCC", HKEY_CURRENT_CONFIG}};
    for (const auto &[Name, Root] : Roots) {
      BrowseRow Row;
      Row.Name = QString::fromLatin1(Name);
      Row.Path = Row.Name;
      Row.Root = Root;
      Row.RootName = Row.Name;
      Row.SubKey.clear();
      Row.IsRoot = true;
      Rows.push_back(Row);
    }
    BrowsePath_ = "\\";
    BrowseRows_ = std::move(Rows);
    PopulateBrowse();
  }

  void BrowseInto(HKEY Root, const QString &RootName, const QString &SubKey) {
    std::vector<BrowseRow> Rows;
    HKEY Key = nullptr;
    const LSTATUS OpenStatus =
        RegOpenKeyExW(Root, reinterpret_cast<LPCWSTR>(SubKey.utf16()), 0,
                      KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_WOW64_64KEY,
                      &Key);
    if (OpenStatus == ERROR_SUCCESS) {
      DWORD SubKeyCount = 0;
      DWORD MaximumNameLength = 0;
      RegQueryInfoKeyW(Key, nullptr, nullptr, nullptr, &SubKeyCount,
                       &MaximumNameLength, nullptr, nullptr, nullptr, nullptr,
                       nullptr, nullptr);
      std::vector<wchar_t> Name(static_cast<size_t>(MaximumNameLength) + 2);
      for (DWORD Index = 0; Index < SubKeyCount; ++Index) {
        DWORD NameLength = static_cast<DWORD>(Name.size());
        if (RegEnumKeyExW(Key, Index, Name.data(), &NameLength, nullptr, nullptr,
                          nullptr, nullptr) != ERROR_SUCCESS)
          continue;
        BrowseRow Row;
        Row.Name = QString::fromWCharArray(Name.data(), NameLength);
        Row.SubKey = SubKey.isEmpty() ? Row.Name : SubKey + "\\" + Row.Name;
        Row.Root = Root;
        Row.RootName = RootName;
        Row.Path = RootName + "\\" + Row.SubKey;
        Rows.push_back(Row);
      }
      RegCloseKey(Key);
    } else {
      Notify(QString("Unable to open the key (error %1).").arg(OpenStatus)
                 .toStdString(),
             NoticeKind::Error);
      return;
    }
    BrowseRoot_ = Root;
    BrowseRootName_ = RootName;
    BrowseSubKey_ = SubKey;
    BrowsePath_ = RootName + (SubKey.isEmpty() ? QString() : "\\" + SubKey);
    BrowseRows_ = std::move(Rows);
    PopulateBrowse();
  }

  void PopulateBrowse() {
    std::vector<TuiRow> Rows;
    Rows.reserve(BrowseRows_.size());
    for (const BrowseRow &Row : BrowseRows_)
      Rows.push_back(TuiRow{{StorageUtil::Utf8(Row.Name),
                             StorageUtil::Utf8(Row.Path)},
                            StorageUtil::Utf8(Row.Path)});
    Browse_.Rows = std::move(Rows);
    Browse_.Filter = Filter;
    Browse_.Rebuild();
    SetStatus(std::to_string(BrowseRows_.size()) + " subkey(s)");
  }

  void BrowseDescend() {
    const int Index = Browse_.CurrentRowIndex();
    if (Index < 0 || Index >= static_cast<int>(BrowseRows_.size()))
      return;
    const BrowseRow &Row = BrowseRows_[static_cast<size_t>(Index)];
    BrowseInto(Row.Root, Row.RootName, Row.SubKey);
  }

  void UseBrowseSelection() {
    const int Index = Browse_.CurrentRowIndex();
    QString Selected;
    if (Index >= 0 && Index < static_cast<int>(BrowseRows_.size()))
      Selected = BrowseRows_[static_cast<size_t>(Index)].Path;
    else if (!BrowsePath_.isEmpty() && BrowsePath_ != "\\")
      Selected = BrowsePath_;
    if (Selected.isEmpty() || Selected == "\\") {
      Notify("Select a registry key first.", NoticeKind::Warning);
      return;
    }
    Address_ = Selected;
    Source_ = 2;
    Tab_ = 0;
    RefreshValues(false);
  }

  int Index_ = 0;
  int Tab_ = 0;
  int Source_ = 0;
  QString Address_;

  TuiTable Values_;
  TuiTable Protected_;
  TuiTable Browse_;
  std::vector<ValueRow> Rows_;
  std::vector<ProtectedEntry> ProtectedFiles_;

  std::vector<BrowseRow> BrowseRows_;
  QString BrowsePath_ = "\\";
  HKEY BrowseRoot_ = nullptr;
  QString BrowseRootName_;
  QString BrowseSubKey_;

  std::atomic_bool Refreshing_{false};
  std::atomic_bool Write_{false};
  std::atomic_bool Protecting_{false};
};

std::unique_ptr<TuiPage> MakeRegistryPage(int Index) {
  return std::make_unique<RegistryPage>(Index);
}

// ------------------------------------------------------------
// 索引 20：Disk
// ------------------------------------------------------------

class DiskPage final : public TuiPage {
  struct EventRow {
    AEGISDISK_EVENT Event{};
    std::string Time;
    std::string Type;
    std::string Process;
    std::string Detail;
  };

  struct DrainResult {
    bool Ok = false;
    std::vector<EventRow> Events;
    int Added = 0;
  };

  struct StateSnapshot {
    bool Ok = false;
    DWORD Error = ERROR_SUCCESS;
    AEGISDISK_STATE_OUTPUT State{};
  };

public:
  explicit DiskPage(int Index) : Index_(Index) {
    Events_.Headers = {"Time", "Type", "PID", "Process", "Disk",
                       "Offset", "Length", "Detail"};
    Events_.RightAlign = {false, false, true, false, true, true, true, false};
    RegisterCommands();
  }

  std::string Title() const override { return "Disk"; }

  std::string Subtitle() const override {
    return "disk write protection state and blocked write events";
  }

  void OnEnter() override {
    // `use` / `refresh` 都走这里：重读保护状态并排空事件队列。
    RefreshState(false, true);
    DrainEvents(false);
  }

  void OnTick(int64_t NowMs) override {
    if (LastPollMs_ != 0 && NowMs - LastPollMs_ < 1500)
      return;
    LastPollMs_ = NowMs;
    RefreshState(false, false);
    DrainEvents(false);
  }

  TuiTable *ActiveTable() override { return &Events_; }

  std::string RenderText() override {
    // `show` 只读缓存：状态与事件由 OnEnter / OnTick / 各命令推进。
    Events_.Filter = Filter;
    Events_.Rebuild();
    std::string Text = "Disk: " + DiskNumber_ + "  " + PartitionStyle_ +
                       "  " + (Enabled_ ? "enabled" : "disabled") + "  " +
                       (AuditOnly_ ? "audit only" : "enforcing") + "  " +
                       DetectedStyle_ + "\n";
    Text += StateLine_ + "\n";
    Text += RangeLine_ + "\n";
    Text += TuiTableToText(Events_, 200);
    if (!SectorLines_.empty()) {
      Text += "\nProtected sectors:\n";
      for (const std::string &Line : SectorLines_)
        Text += Line + "\n";
    }
    return Text;
  }

private:
  static ULONG PartitionStyleFromName(const std::string &Name) {
    const std::string Value = LowerAscii(TrimAscii(Name));
    if (Value == "gpt" || Value == "1")
      return PARTITION_STYLE_GPT;
    if (Value == "raw" || Value == "2")
      return PARTITION_STYLE_RAW;
    return PARTITION_STYLE_MBR;
  }

  static std::string PartitionStyleText(ULONG Value) {
    switch (Value) {
    case PARTITION_STYLE_GPT:
      return "GPT";
    case PARTITION_STYLE_RAW:
      return "RAW";
    default:
      return "MBR";
    }
  }

  static std::string EventTypeText(ULONG Value) {
    switch (Value) {
    case AegisDiskEventWriteBlocked:
      return "WriteBlocked";
    case AegisDiskEventLayoutBlocked:
      return "LayoutBlocked";
    default:
      return "Unknown";
    }
  }

  static std::string DetectedPartitionStyleText(ULONG Value) {
    switch (Value) {
    case PARTITION_STYLE_GPT:
      return "Detected: GPT";
    case PARTITION_STYLE_RAW:
      return "Detected: RAW";
    case PARTITION_STYLE_MBR:
      return "Detected: MBR";
    default:
      return "Detected: unknown";
    }
  }

  void RegisterCommands() {
    const auto Add = [this](std::string Name, std::string Usage,
                            std::function<void(std::vector<std::string>)> Fn) {
      OwnedCommands.push_back(TuiCommand{std::move(Name), std::move(Usage),
                                         std::move(Fn)});
    };

    Add("refresh", "refresh  (reload protection state)",
        [this](std::vector<std::string>) { RefreshState(true, true); });
    Add("apply", "apply [disk] [mbr|gpt|raw] [enabled|disabled] [audit|enforce]",
        [this](std::vector<std::string> Args) {
          if (!Args.empty()) {
            DiskNumber_ = Args[0];
            if (Args.size() > 1)
              PartitionStyle_ = PartitionStyleText(
                  PartitionStyleFromName(Args[1]));
            for (size_t Index = 2; Index < Args.size(); ++Index) {
              const std::string Value = LowerAscii(Args[Index]);
              if (Value == "enabled" || Value == "on" || Value == "true")
                Enabled_ = true;
              else if (Value == "disabled" || Value == "off" ||
                       Value == "false")
                Enabled_ = false;
              else if (Value == "audit" || Value == "auditonly")
                AuditOnly_ = true;
              else if (Value == "enforce" || Value == "enforcing")
                AuditOnly_ = false;
            }
            ApplyState();
            return;
          }
          ShowApplyDialog();
        });
    Add("drain", "drain  (read queued blocked events)",
        [this](std::vector<std::string>) { DrainEvents(true, true); });
    Add("allow-once", "allow-once  (one-shot token for the selected event)",
        [this](std::vector<std::string>) { AllowSelected(); });
    Add("allow", "allow  (allow the pending write request)",
        [this](std::vector<std::string>) { DecideSelected(true); });
    Add("deny", "deny  (deny the pending write request)",
        [this](std::vector<std::string>) { DecideSelected(false); });
    Add("clear", "clear  (clear the driver event queue)",
        [this](std::vector<std::string>) { ClearEvents(); });
    Add("range", "range [protected|custom] [head|tail] [start-lba] [count]",
        [this](std::vector<std::string> Args) {
          if (!Args.empty()) {
            const std::string Mode = LowerAscii(Args[0]);
            RangeMode_ = (Mode == "custom" || Mode == "1") ? 1 : 0;
            if (Args.size() > 1) {
              const std::string Region = LowerAscii(Args[1]);
              RegionTail_ = (Region == "tail" || Region == "1");
            }
            if (Args.size() > 2)
              StartLba_ = Args[2];
            if (Args.size() > 3)
              SectorCount_ = Args[3];
            RefreshRangePresentation();
            return;
          }
          ShowRangeDialog();
        });
    Add("read", "read  (read the active sector range as hex)",
        [this](std::vector<std::string>) { ReadSectors(true); });
    Add("use-event", "use-event  (move the custom range to the selected event)",
        [this](std::vector<std::string>) { ApplySelectedEventRange(); });
  }

  // ---- 状态 ----

  int CurrentDiskNumber() const {
    uint32_t Value = 0;
    if (!StorageUtil::ParseUInt(DiskNumber_, &Value))
      return 0;
    return static_cast<int>(Value);
  }

  bool IsProtectedRangeMode() const { return RangeMode_ == 0; }

  bool IsGptPartitionStyle() const {
    return PartitionStyleFromName(PartitionStyle_) == PARTITION_STYLE_GPT;
  }

  AEGISDISK_PROTECTED_REGION CurrentProtectedRegion() const {
    return RegionTail_ ? AegisDiskProtectedRegionTail
                       : AegisDiskProtectedRegionHead;
  }

  void RefreshDetectedPartitionStyle() {
    const ULONG Disk = static_cast<ULONG>(CurrentDiskNumber());
    if (Detecting_.exchange(true))
      return;
    TuiAsync<std::pair<bool, ULONG>>(
        [Disk] {
          ULONG Style = PARTITION_STYLE_RAW;
          const bool Ok = AegisDiskQueryPartitionStyleRobust(Disk, &Style);
          return std::pair<bool, ULONG>(Ok, Style);
        },
        [this](std::pair<bool, ULONG> Result) {
          Detecting_ = false;
          DetectedStyle_ = Result.first ? DetectedPartitionStyleText(Result.second)
                                        : "Detected: unavailable";
          RefreshRangePresentation();
        });
  }

  void RefreshState(bool Report, bool ReloadForm) {
    if (Refreshing_.exchange(true)) {
      if (Report)
        Notify("Already refreshing protection state.", NoticeKind::Info);
      return;
    }
    if (Report)
      SetStatus("Refreshing protection state...");
    TuiAsync<StateSnapshot>(
        [] {
          StateSnapshot Snapshot;
          Snapshot.Ok = AegisDiskQueryState(&Snapshot.State);
          Snapshot.Error = Snapshot.Ok ? ERROR_SUCCESS : GetLastError();
          return Snapshot;
        },
        [this, Report, ReloadForm](StateSnapshot Snapshot) {
          Refreshing_ = false;
          if (!Snapshot.Ok) {
            StateLine_ = "State: unavailable";
            RangeLine_ = "Range: unavailable";
            if (Report)
              Notify(QString("State query failed (error %1).")
                         .arg(Snapshot.Error)
                         .toStdString(),
                     NoticeKind::Error);
            return;
          }
          CachedState_ = Snapshot.State;
          StateLine_ =
              QString("State: disk %1 | %2 | enabled=%3 | audit=%4 | blocked "
                      "writes=%5 | blocked layouts=%6 | queued=%7")
                  .arg(Snapshot.State.DiskNumber)
                  .arg(QString::fromStdString(
                      PartitionStyleText(Snapshot.State.PartitionStyle)))
                  .arg(Snapshot.State.Enabled ? "yes" : "no")
                  .arg(Snapshot.State.AuditOnly ? "yes" : "no")
                  .arg(Snapshot.State.BlockedWriteCount)
                  .arg(Snapshot.State.BlockedLayoutIoctlCount)
                  .arg(Snapshot.State.PendingEventCount)
                  .toStdString();
          if (ReloadForm) {
            DiskNumber_ = std::to_string(Snapshot.State.DiskNumber);
            PartitionStyle_ =
                PartitionStyleText(Snapshot.State.PartitionStyle);
            Enabled_ = Snapshot.State.Enabled != FALSE;
            AuditOnly_ = Snapshot.State.AuditOnly != FALSE;
            RefreshDetectedPartitionStyle();
          }
          RefreshRangePresentation();
          if (Report)
            Notify("Protection state refreshed.", NoticeKind::Success);
          SetStatus(StateLine_);
        });
  }

  void ShowApplyDialog() {
    TuiDialog Dialog;
    Dialog.Title = "Apply disk protection";
    TuiField Disk;
    Disk.Label = "Disk";
    Disk.Kind = TuiFieldKind::Int;
    Disk.Value = DiskNumber_;
    Dialog.Fields.push_back(Disk);

    TuiField Style;
    Style.Label = "Style";
    Style.Kind = TuiFieldKind::Combo;
    Style.Choices = {"MBR", "GPT", "RAW"};
    Style.Choice = IsGptPartitionStyle() ? 1
                                         : (PartitionStyleFromName(
                                                PartitionStyle_) ==
                                                    PARTITION_STYLE_RAW
                                                ? 2
                                                : 0);
    Dialog.Fields.push_back(Style);

    TuiField Enabled;
    Enabled.Label = "Enabled";
    Enabled.Kind = TuiFieldKind::Check;
    Enabled.Checked = Enabled_;
    Dialog.Fields.push_back(Enabled);

    TuiField Audit;
    Audit.Label = "Audit only";
    Audit.Kind = TuiFieldKind::Check;
    Audit.Checked = AuditOnly_;
    Dialog.Fields.push_back(Audit);

    Dialog.PrimaryLabel = "Apply";
    Dialog.SecondaryLabel = "Cancel";
    Dialog.Validate = [](const TuiDialog &Current) -> std::string {
      if (Current.Fields.size() < 2)
        return {};
      uint32_t ParsedDisk = 0;
      if (!StorageUtil::ParseUInt(Current.Fields[0].Value, &ParsedDisk))
        return "Disk must be a non-negative number.";
      return {};
    };
    Dialog.OnSubmit = [this](TuiDialog &Submitted) {
      if (Submitted.Fields.size() < 4)
        return;
      DiskNumber_ = TrimAscii(Submitted.Fields[0].Value);
      PartitionStyle_ = PartitionStyleText(
          PartitionStyleFromName(std::to_string(Submitted.Fields[1].Choice)));
      Enabled_ = Submitted.Fields[2].Checked;
      AuditOnly_ = Submitted.Fields[3].Checked;
      ApplyState();
    };
    Dialogs->Push(std::move(Dialog));
  }

  void ApplyState() {
    AEGISDISK_SET_PROTECTION_INPUT Input{};
    Input.DiskNumber = static_cast<ULONG>(CurrentDiskNumber());
    Input.PartitionStyle = PartitionStyleFromName(
        PartitionStyle_ == "GPT" ? "gpt"
                                 : (PartitionStyle_ == "RAW" ? "raw" : "mbr"));
    Input.Enabled = Enabled_ ? TRUE : FALSE;
    Input.AuditOnly = AuditOnly_ ? TRUE : FALSE;
    if (Applying_.exchange(true))
      return;
    TuiAsync<std::pair<bool, DWORD>>(
        [Input] {
          const bool Ok = AegisDiskSetProtection(Input);
          return std::pair<bool, DWORD>(Ok, Ok ? ERROR_SUCCESS : GetLastError());
        },
        [this](std::pair<bool, DWORD> Result) {
          Applying_ = false;
          if (!Result.first) {
            Notify(QString("Apply failed (error %1).").arg(Result.second)
                       .toStdString(),
                   NoticeKind::Error);
            return;
          }
          MarkMutated();
          RefreshDetectedPartitionStyle();
          RefreshState(false, true);
          Notify("Protection configuration updated.", NoticeKind::Success);
        });
  }

  // ---- 事件 ----

  static EventRow BuildEventRow(const AEGISDISK_EVENT &Event) {
    FILETIME FileTime{Event.TimeStamp.LowPart,
                      static_cast<DWORD>(Event.TimeStamp.HighPart)};
    SYSTEMTIME SystemTime{};
    FileTimeToSystemTime(&FileTime, &SystemTime);
    EventRow Row;
    Row.Event = Event;
    Row.Time = QString("%1-%2-%3 %4:%5:%6")
                   .arg(SystemTime.wYear, 4, 10, QLatin1Char('0'))
                   .arg(SystemTime.wMonth, 2, 10, QLatin1Char('0'))
                   .arg(SystemTime.wDay, 2, 10, QLatin1Char('0'))
                   .arg(SystemTime.wHour, 2, 10, QLatin1Char('0'))
                   .arg(SystemTime.wMinute, 2, 10, QLatin1Char('0'))
                   .arg(SystemTime.wSecond, 2, 10, QLatin1Char('0'))
                   .toStdString();
    Row.Type = EventTypeText(Event.EventType);
    Row.Process = StorageUtil::Utf8(QString::fromWCharArray(
        Event.ProcessImage[0] ? Event.ProcessImage : L"<unknown>"));
    Row.Detail = StorageUtil::Utf8(QString::fromWCharArray(Event.Detail));
    return Row;
  }

  void DrainEvents(bool Report, bool Repopulate = false) {
    if (Draining_.exchange(true)) {
      if (Report)
        Notify("Already draining events.", NoticeKind::Info);
      return;
    }
    TuiAsync<DrainResult>(
        [] {
          DrainResult Result;
          Result.Ok = true;
          for (;;) {
            AEGISDISK_EVENT Event{};
            if (!AegisDiskReadEvent(&Event))
              break;
            Result.Events.push_back(BuildEventRow(Event));
          }
          Result.Added = static_cast<int>(Result.Events.size());
          return Result;
        },
        [this, Report, Repopulate](DrainResult Result) {
          Draining_ = false;
          if (Result.Added > 0) {
            // 事件按到达顺序返回，最新在前（与 GUI 的 insert(begin) 同序）。
            for (auto It = Result.Events.begin(); It != Result.Events.end(); ++It)
              Rows_.insert(Rows_.begin(), *It);
            if (Rows_.size() > 256)
              Rows_.resize(256);
            PopulateEvents();
          }
          if (Repopulate)
            RefreshState(false, false);
          if (Report)
            Notify("Read " + std::to_string(Result.Added) + " event(s).",
                   NoticeKind::Success);
        });
  }

  void PopulateEvents() {
    std::vector<TuiRow> Rows;
    Rows.reserve(Rows_.size());
    for (const EventRow &Row : Rows_) {
      Rows.push_back(TuiRow{{Row.Time, Row.Type,
                             std::to_string(Row.Event.ProcessId), Row.Process,
                             std::to_string(Row.Event.DiskNumber),
                             "0x" + StorageUtil::Hex(Row.Event.Offset, 1),
                             "0x" + StorageUtil::Hex(Row.Event.Length, 1),
                             Row.Detail},
                            Row.Detail});
    }
    Events_.Rows = std::move(Rows);
    Events_.Filter = Filter;
    Events_.Rebuild();
    SetStatus(std::to_string(Rows_.size()) + " blocked event(s)");
  }

  const EventRow *SelectedEvent() const {
    const int Index = Events_.CurrentRowIndex();
    if (Index < 0 || Index >= static_cast<int>(Rows_.size()))
      return nullptr;
    return &Rows_[static_cast<size_t>(Index)];
  }

  void AllowSelected() {
    const EventRow *Selected = SelectedEvent();
    if (!Selected) {
      Notify("Select a blocked event first.", NoticeKind::Warning);
      return;
    }
    AEGISDISK_ALLOW_ONCE_INPUT Input{};
    Input.DiskNumber = Selected->Event.DiskNumber;
    Input.OperationType = Selected->Event.Flags;
    Input.ProcessId = Selected->Event.ProcessId;
    Input.Offset = Selected->Event.Offset;
    Input.Length = Selected->Event.Length;
    Input.TimeoutMs = 10000;
    if (Allowing_.exchange(true))
      return;
    TuiAsync<std::pair<bool, DWORD>>(
        [Input] {
          const bool Ok = AegisDiskAllowOnce(Input);
          return std::pair<bool, DWORD>(Ok, Ok ? ERROR_SUCCESS : GetLastError());
        },
        [this](std::pair<bool, DWORD> Result) {
          Allowing_ = false;
          if (!Result.first) {
            Notify(QString("Allow-once failed (error %1).").arg(Result.second)
                       .toStdString(),
                   NoticeKind::Error);
            return;
          }
          Notify("One-shot token issued for the selected event.",
                 NoticeKind::Success);
        });
  }

  void DecideSelected(bool Allow) {
    const EventRow *Selected = SelectedEvent();
    if (!Selected) {
      Notify("Select a blocked event first.", NoticeKind::Warning);
      return;
    }
    const ULONGLONG RequestId = Selected->Event.RequestId;
    if (RequestId == 0) {
      Notify("The selected event has no pending write request.",
             NoticeKind::Error);
      return;
    }
    if (Allowing_.exchange(true))
      return;
    const int RowIndex = Events_.CurrentRowIndex();
    TuiAsync<std::pair<bool, DWORD>>(
        [RequestId, Allow] {
          const bool Ok = AegisDiskDecideRequest(RequestId, Allow);
          return std::pair<bool, DWORD>(Ok, Ok ? ERROR_SUCCESS : GetLastError());
        },
        [this, Allow, RowIndex](std::pair<bool, DWORD> Result) {
          Allowing_ = false;
          if (!Result.first) {
            Notify(QString("Decision failed (error %1).").arg(Result.second)
                       .toStdString(),
                   NoticeKind::Error);
            return;
          }
          if (RowIndex >= 0 && RowIndex < static_cast<int>(Rows_.size())) {
            Rows_.erase(Rows_.begin() + RowIndex);
            PopulateEvents();
          }
          MarkMutated();
          Notify(Allow ? "Current write allowed." : "Current write denied.",
                 NoticeKind::Success);
        });
  }

  void ClearEvents() {
    if (Clearing_.exchange(true))
      return;
    TuiAsync<std::pair<bool, DWORD>>(
        [] {
          const bool Ok = AegisDiskClearEvents();
          return std::pair<bool, DWORD>(Ok, Ok ? ERROR_SUCCESS : GetLastError());
        },
        [this](std::pair<bool, DWORD> Result) {
          Clearing_ = false;
          if (!Result.first) {
            Notify(QString("Clear failed (error %1).").arg(Result.second)
                       .toStdString(),
                 NoticeKind::Error);
            return;
          }
          Rows_.clear();
          PopulateEvents();
          RefreshState(false, false);
          Notify("Event queue cleared.", NoticeKind::Success);
        });
  }

  // ---- 扇区范围 ----
  // AEGISDISK_SECTOR_RANGE 的解析会打开 \\.\PhysicalDriveN（
  // BuildProtectedSectorRangeEx / AegisDiskQueryBytesPerSector 内部读扇区），
  // 因此一律放到 worker 线程；所有输入按值捕获，页面不跨线程读取成员。

  struct RangeInputs {
    ULONG Disk = 0;
    ULONG Style = PARTITION_STYLE_MBR;
    bool ProtectedMode = true;
    AEGISDISK_PROTECTED_REGION Region = AegisDiskProtectedRegionHead;
    AEGISDISK_STATE_OUTPUT State{};
    uint64_t StartLba = 0;
    uint64_t SectorCount = 0;
  };

  struct RangeOutcome {
    bool Ok = false;
    DWORD Error = ERROR_SUCCESS;
    AEGISDISK_SECTOR_RANGE Range{};
  };

  static RangeOutcome ResolveRange(const RangeInputs &Inputs) {
    RangeOutcome Outcome;
    Outcome.Range.DiskNumber = Inputs.Disk;
    Outcome.Range.PartitionStyle = Inputs.Style;
    if (Inputs.ProtectedMode) {
      AEGISDISK_STATE_OUTPUT State = Inputs.State;
      State.DiskNumber = Inputs.Disk;
      State.PartitionStyle = Inputs.Style;
      Outcome.Ok =
          BuildProtectedSectorRangeEx(State, Inputs.Region, &Outcome.Range) &&
          Outcome.Range.SectorCount != 0;
    } else if (Inputs.SectorCount == 0 || Inputs.SectorCount > 4096) {
      Outcome.Ok = false;
    } else {
      Outcome.Range.StartLba = Inputs.StartLba;
      Outcome.Range.SectorCount = static_cast<ULONG>(Inputs.SectorCount);
      Outcome.Range.BytesPerSector = 512;
      AegisDiskQueryBytesPerSector(Outcome.Range.DiskNumber,
                                   &Outcome.Range.BytesPerSector);
      Outcome.Ok = true;
    }
    Outcome.Error = Outcome.Ok ? ERROR_SUCCESS : GetLastError();
    return Outcome;
  }

  RangeInputs CurrentRangeInputs() const {
    RangeInputs Inputs;
    Inputs.Disk = static_cast<ULONG>(CurrentDiskNumber());
    Inputs.Style = PartitionStyleFromName(
        PartitionStyle_ == "GPT" ? "gpt"
                                 : (PartitionStyle_ == "RAW" ? "raw" : "mbr"));
    Inputs.ProtectedMode = IsProtectedRangeMode();
    Inputs.Region = CurrentProtectedRegion();
    Inputs.State = CachedState_;
    StorageUtil::ParseU64(StartLba_, &Inputs.StartLba);
    StorageUtil::ParseU64(SectorCount_, &Inputs.SectorCount);
    return Inputs;
  }

  std::string ModeText() const {
    if (!IsProtectedRangeMode())
      return "Custom";
    if (IsGptPartitionStyle())
      return RegionTail_ ? "Protected tail" : "Protected head";
    return "Protected";
  }

  void UpdateRangeLabel(const AEGISDISK_SECTOR_RANGE &Range) {
    RangeLine_ = QString("Range: %1 | disk %2 | %3 | LBA %4 | sectors %5 | "
                         "bytes/sector %6 | total %7 bytes")
                     .arg(QString::fromStdString(ModeText()))
                     .arg(Range.DiskNumber)
                     .arg(QString::fromStdString(
                         PartitionStyleText(Range.PartitionStyle)))
                     .arg(static_cast<qulonglong>(Range.StartLba))
                     .arg(Range.SectorCount)
                     .arg(Range.BytesPerSector)
                     .arg(static_cast<qulonglong>(Range.SectorCount) *
                          Range.BytesPerSector)
                     .toStdString();
  }

  void RefreshRangePresentation() {
    if (RangeBusy_.exchange(true))
      return;
    const RangeInputs Inputs = CurrentRangeInputs();
    TuiAsync<RangeOutcome>(
        [Inputs] { return ResolveRange(Inputs); },
        [this](RangeOutcome Outcome) {
          RangeBusy_ = false;
          if (!Outcome.Ok) {
            RangeLine_ = "Range: unavailable";
            return;
          }
          UpdateRangeLabel(Outcome.Range);
        });
  }

  void ShowRangeDialog() {
    TuiDialog Dialog;
    Dialog.Title = "Sector range";
    TuiField Mode;
    Mode.Label = "Mode";
    Mode.Kind = TuiFieldKind::Combo;
    Mode.Choices = {"Protected range", "Custom range"};
    Mode.Choice = RangeMode_;
    Dialog.Fields.push_back(Mode);

    TuiField Region;
    Region.Label = "Region";
    Region.Kind = TuiFieldKind::Combo;
    Region.Choices = {"Head", "Tail"};
    Region.Choice = RegionTail_ ? 1 : 0;
    Region.Hint = "tail only applies to GPT disks";
    Dialog.Fields.push_back(Region);

    TuiField Start;
    Start.Label = "Start LBA";
    Start.Kind = TuiFieldKind::Text;
    Start.Value = StartLba_;
    Dialog.Fields.push_back(Start);

    TuiField Count;
    Count.Label = "Sectors";
    Count.Kind = TuiFieldKind::Text;
    Count.Value = SectorCount_;
    Dialog.Fields.push_back(Count);

    Dialog.PrimaryLabel = "Apply";
    Dialog.SecondaryLabel = "Cancel";
    Dialog.Validate = [](const TuiDialog &Current) -> std::string {
      if (Current.Fields.size() < 4 || Current.Fields[0].Choice == 0)
        return {};
      uint64_t Start = 0;
      uint64_t Count = 0;
      if (!StorageUtil::ParseU64(Current.Fields[2].Value, &Start) ||
          !StorageUtil::ParseU64(Current.Fields[3].Value, &Count))
        return "Start LBA and sector count must be numbers.";
      if (Count == 0 || Count > 4096)
        return "Sector count must be between 1 and 4096.";
      return {};
    };
    Dialog.OnSubmit = [this](TuiDialog &Submitted) {
      if (Submitted.Fields.size() < 4)
        return;
      RangeMode_ = Submitted.Fields[0].Choice;
      RegionTail_ = Submitted.Fields[1].Choice == 1;
      StartLba_ = TrimAscii(Submitted.Fields[2].Value);
      SectorCount_ = TrimAscii(Submitted.Fields[3].Value);
      RefreshRangePresentation();
    };
    Dialogs->Push(std::move(Dialog));
  }

  struct EventRangeOutcome {
    bool Ok = false;
    DWORD Error = ERROR_SUCCESS;
    uint64_t BytesPerSector = 512;
  };

  void ApplySelectedEventRange() {
    const EventRow *Selected = SelectedEvent();
    if (!Selected) {
      Notify("Select a blocked event first.", NoticeKind::Warning);
      return;
    }
    if (RangeBusy_.exchange(true))
      return;
    const ULONGLONG Offset = Selected->Event.Offset;
    const ULONGLONG Length = Selected->Event.Length;
    RangeInputs Inputs = CurrentRangeInputs();
    Inputs.ProtectedMode = true;
    TuiAsync<EventRangeOutcome>(
        [Inputs] {
          EventRangeOutcome Outcome;
          const RangeOutcome Base = ResolveRange(Inputs);
          Outcome.Ok = Base.Ok && Base.Range.BytesPerSector != 0;
          Outcome.Error = Base.Error;
          Outcome.BytesPerSector = Base.Range.BytesPerSector;
          return Outcome;
        },
        [this, Offset, Length](EventRangeOutcome Outcome) {
          RangeBusy_ = false;
          if (!Outcome.Ok || Outcome.BytesPerSector == 0) {
            Notify(QString("Unable to query bytes per sector (error %1).")
                       .arg(Outcome.Error)
                       .toStdString(),
                   NoticeKind::Error);
            return;
          }
          const ULONGLONG BytesPerSector = Outcome.BytesPerSector;
          const ULONGLONG EffectiveLength =
              Length == 0 ? BytesPerSector : Length;
          const ULONGLONG StartLba = Offset / BytesPerSector;
          const ULONGLONG EndOffset =
              Offset + std::max<ULONGLONG>(EffectiveLength, 1) - 1;
          const ULONGLONG EndLba = EndOffset / BytesPerSector;
          const ULONGLONG SectorCount = (EndLba - StartLba) + 1;
          RangeMode_ = 1;
          StartLba_ = std::to_string(StartLba);
          SectorCount_ = std::to_string(SectorCount);
          RefreshRangePresentation();
          Notify("Custom range moved to the selected event offset.",
                 NoticeKind::Success);
        });
  }

  struct SectorReadOutcome {
    bool Ok = false;
    DWORD Error = ERROR_SUCCESS;
    AEGISDISK_SECTOR_RANGE Range{};
    std::vector<BYTE> Buffer;
  };

  void ReadSectors(bool Report) {
    if (Reading_.exchange(true))
      return;
    const RangeInputs Inputs = CurrentRangeInputs();
    TuiAsync<SectorReadOutcome>(
        [Inputs] {
          SectorReadOutcome Outcome;
          const RangeOutcome Base = ResolveRange(Inputs);
          Outcome.Range = Base.Range;
          if (!Base.Ok) {
            Outcome.Error = Base.Error;
            return Outcome;
          }
          Outcome.Ok = ReadPhysicalDiskSectors(Outcome.Range, &Outcome.Buffer);
          if (!Outcome.Ok)
            Outcome.Error = GetLastError();
          return Outcome;
        },
        [this, Report](SectorReadOutcome Outcome) {
          Reading_ = false;
          if (!Outcome.Ok) {
            if (Report)
              Notify(QString("Read failed (error %1).").arg(Outcome.Error)
                         .toStdString(),
                     NoticeKind::Error);
            return;
          }
          UpdateRangeLabel(Outcome.Range);
          // Tui::FormatHexAscii：16 字节/行，%012X 绝对偏移，第 8 字节后加间隔。
          const std::string Dump = FormatHexAscii(
              Outcome.Buffer, static_cast<uint64_t>(Outcome.Range.StartLba) *
                                  Outcome.Range.BytesPerSector);
          SectorLines_.clear();
          std::string Current;
          for (char C : Dump) {
            if (C == '\n') {
              SectorLines_.push_back(Current);
              Current.clear();
            } else {
              Current += C;
            }
          }
          if (!Current.empty())
            SectorLines_.push_back(Current);
          if (SectorLines_.empty())
            SectorLines_.push_back("(empty read)");
          if (Report)
            Notify("Read " + std::to_string(Outcome.Buffer.size()) +
                       " byte(s) from disk " +
                       std::to_string(Outcome.Range.DiskNumber) + ".",
                   NoticeKind::Success);
        });
  }

  int Index_ = 0;
  int64_t LastPollMs_ = 0;

  std::string DiskNumber_ = "0";
  std::string PartitionStyle_ = "MBR";
  bool Enabled_ = true;
  bool AuditOnly_ = false;
  std::string DetectedStyle_ = "Detected: unknown";

  int RangeMode_ = 0;
  bool RegionTail_ = false;
  std::string StartLba_;
  std::string SectorCount_;

  std::string StateLine_ = "State: unavailable";
  std::string RangeLine_ = "Range: unavailable";
  std::vector<std::string> SectorLines_;

  AEGISDISK_STATE_OUTPUT CachedState_{};
  std::vector<EventRow> Rows_;

  TuiTable Events_;

  std::atomic_bool Refreshing_{false};
  std::atomic_bool Draining_{false};
  std::atomic_bool Applying_{false};
  std::atomic_bool Allowing_{false};
  std::atomic_bool Clearing_{false};
  std::atomic_bool Reading_{false};
  std::atomic_bool Detecting_{false};
  std::atomic_bool RangeBusy_{false};
};

std::unique_ptr<TuiPage> MakeDiskPage(int Index) {
  return std::make_unique<DiskPage>(Index);
}

// ------------------------------------------------------------
// 索引 7：Memory
// ------------------------------------------------------------
// GUI MemoryPage 的私有 static（PatternByte / PatternScanHit /
// MemoryProtectReadable / MemoryPatternFind）在这里重建；写事务的
// 前置读/校验/回滚与审计日志与 GUI 完全一致。
// ------------------------------------------------------------

class MemoryPage final : public TuiPage {
  struct PatternByte {
    unsigned char Value = 0;
    bool Wildcard = false;
  };

  struct PatternScanHit {
    ULONG_PTR Address = 0;
    ULONG_PTR RegionBase = 0;
    ULONG Protect = 0;
    ULONG Type = 0;
    unsigned char Context[16] = {};
  };

  struct ScanOutcome {
    bool Ok = true;
    std::vector<PatternScanHit> Hits;
    uint64_t Scanned = 0;
    uint32_t Skipped = 0;
    bool InvalidPid = false;
  };

  struct ReadOutcome {
    bool Ok = false;
    std::vector<unsigned char> Bytes;
    DWORD Error = ERROR_SUCCESS;
  };

  enum class WriteState {
    Ok,
    ReadFailed,
    Identical,
    WriteFailed,
    VerifyFailedRestored,
    VerifyFailedRestoreFailed
  };

  struct WriteOutcome {
    WriteState State = WriteState::ReadFailed;
    DWORD Error = ERROR_SUCCESS;
    std::string OwnerName;
    std::string DiffSummary;
    std::string TransactionId;
    bool AuditFailed = false;
    std::string AuditError;
    std::shared_ptr<AegisNT::KernelResearch::WriteTransaction> Transaction;
  };

  struct RollbackOutcome {
    enum class State {
      Ok,
      NoTransaction,
      AddressMismatch,
      MemoryChanged,
      WriteFailed
    } State = State::NoTransaction;
  };

public:
  explicit MemoryPage(int Index) : Index_(Index) {
    Physical_.Headers = {"Range", "Base", "End", "Bytes", "Size"};
    Physical_.RightAlign = {true, false, false, true, true};

    Suspect_.Headers = {"Base", "Size", "Protect", "Type", "Flags"};
    Suspect_.RightAlign = {false, true, false, false, false};

    Scan_.Headers = {"Address", "Region Base", "Protect", "Type", "Context"};
    Scan_.RightAlign = {false, false, false, false, false};

    Modules_.Headers = {"Module", "Base", "Size"};
    Modules_.RightAlign = {false, false, true};

    Pte_.Headers = {"Level", "Entry Physical", "Entry Value", "Next Physical",
                    "Flags"};
    Pte_.RightAlign = {false, false, false, false, false};

    RegisterCommands();
  }

  std::string Title() const override { return "Memory"; }

  std::string Subtitle() const override {
    return "process/kernel memory editor, pattern scan, modules, page tables";
  }

  void OnEnter() override { SetStatus("Ready"); }

  void OnTick(int64_t NowMs) override { (void)NowMs; }

  TuiTable *ActiveTable() override {
    switch (Tab_) {
    case 1:
      return &Physical_;
    case 2:
      return &Suspect_;
    case 3:
      return &Scan_;
    case 4:
      return &Modules_;
    case 5:
      return &Pte_;
    default:
      return nullptr;
    }
  }

  std::string RenderText() override {
    // `show` 只读缓存：各表由对应的命令异步填充，这里只重放一遍筛选。
    std::string Text =
        TabStrip({"Editor", "Physical", "Suspect", "Scan", "Dump", "PTE",
                  "Regions"}, Tab_) +
        "\n";
    TuiTable *Table = ActiveTable();
    if (Table) {
      Table->Filter = Filter;
      Table->Rebuild();
    }
    switch (Tab_) {
    case 0:
      Text += "pid " + (Pid_.empty() ? std::string("-") : Pid_) +
              "  address " + (Address_.empty() ? std::string("-") : Address_) +
              "  size " + Size_ + "  method " + MethodName() + "\n";
      if (HexLines_.empty()) {
        Text += "(no data - run read)\n";
        break;
      }
      Text += "\nHEX\n";
      for (const std::string &Line : HexLines_)
        Text += Line + "\n";
      Text += "\nASCII\n";
      for (const std::string &Line : AsciiLines_)
        Text += Line + "\n";
      break;
    case 1:
      Text += "Physical memory ranges\n" + TuiTableToText(*Table, 200);
      break;
    case 2:
      Text += SuspectStatus_ + "\n" + TuiTableToText(*Table, 200);
      break;
    case 3:
      Text += ScanStatus_ + "\n" + TuiTableToText(*Table, 200);
      break;
    case 4:
      Text += DumpStatus_ + "\n" + TuiTableToText(*Table, 200);
      break;
    case 5:
      Text += PteStatus_ + "\n" + TuiTableToText(*Table, 200);
      break;
    default:
      Text += OpsStatus_ + "\n";
      Text += RollbackEnabled_ ? "rollback: last transaction available\n"
                               : "rollback: none\n";
      Text += "protect <address> <size> [0-4]   alloc <size> [0-2] [reserve]   "
              "free <base>\n";
      Text += "PAGE_NOACCESS / PAGE_READONLY / PAGE_READWRITE / "
              "PAGE_EXECUTE_READ / PAGE_EXECUTE_READWRITE\n";
      break;
    }
    return Text;
  }

private:
  // ---- 局部内存助手（GUI MemoryPage.cpp 匿名 namespace 的同序实现）----

  static bool MemoryProtectReadable(ULONG Protect) {
    if (Protect & PAGE_GUARD)
      return false;
    switch (Protect & 0xFF) {
    case PAGE_READONLY:
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
      return true;
    default:
      return false;
    }
  }

  static size_t PatternFind(const unsigned char *Data, size_t Size,
                            const std::vector<PatternByte> &Pattern) {
    if (Pattern.empty() || Size < Pattern.size())
      return static_cast<size_t>(-1);
    const size_t Last = Size - Pattern.size();
    for (size_t Offset = 0; Offset <= Last; ++Offset) {
      size_t Index = 0;
      for (; Index < Pattern.size(); ++Index) {
        if (!Pattern[Index].Wildcard &&
            Data[Offset + Index] != Pattern[Index].Value)
          break;
      }
      if (Index == Pattern.size())
        return Offset;
    }
    return static_cast<size_t>(-1);
  }

  std::string MethodName() const {
    static const char *Names[] = {"Auto", "MDL map", "CR0 WP-off", "Direct map"};
    return Names[std::clamp(Method_, 0, 3)];
  }

  KRNL_MEMRW_METHOD MethodValue() const {
    return static_cast<KRNL_MEMRW_METHOD>(std::clamp(Method_, 0, 3));
  }

  // ---- 命令 ----

  void RegisterCommands() {
    const auto Add = [this](std::string Name, std::string Usage,
                            std::function<void(std::vector<std::string>)> Fn) {
      OwnedCommands.push_back(TuiCommand{std::move(Name), std::move(Usage),
                                         std::move(Fn)});
    };

    Add("pid", "pid <n>  (target process id, 0 = kernel mode)",
        [this](std::vector<std::string> Args) {
          if (Args.empty()) {
            Notify("Usage: pid <n>", NoticeKind::Warning);
            return;
          }
          Pid_ = TrimAscii(Args.front());
        });
    Add("address", "address <hex>  (target address)",
        [this](std::vector<std::string> Args) {
          if (Args.empty()) {
            Notify("Usage: address 0x7FF612340000", NoticeKind::Warning);
            return;
          }
          Address_ = TrimAscii(Args.front());
        });
    Add("size", "size <n>  (read size, 1-4096)",
        [this](std::vector<std::string> Args) {
          if (Args.empty()) {
            Notify("Usage: size <bytes>", NoticeKind::Warning);
            return;
          }
          Size_ = TrimAscii(Args.front());
        });
    Add("method", "method <auto|mdl|cr0|direct>  (kernel access path)",
        [this](std::vector<std::string> Args) {
          if (Args.empty()) {
            Notify("Usage: method <auto|mdl|cr0|direct>", NoticeKind::Warning);
            return;
          }
          const std::string Value = LowerAscii(Args.front());
          if (Value == "auto" || Value == "0")
            Method_ = 0;
          else if (Value == "mdl" || Value == "1")
            Method_ = 1;
          else if (Value == "cr0" || Value == "2")
            Method_ = 2;
          else if (Value == "direct" || Value == "3")
            Method_ = 3;
          else
            Notify("Unknown method: " + Args.front(), NoticeKind::Warning);
        });

    Add("read", "read  (read 1-4096 bytes at the target address)",
        [this](std::vector<std::string>) { ReadTarget(true); });
    Add("write", "write  (stage hex bytes, then write and verify)",
        [this](std::vector<std::string> Args) {
          if (!Args.empty()) {
            std::string Joined;
            for (const std::string &Part : Args) {
              if (!Joined.empty())
                Joined += ' ';
              Joined += Part;
            }
            HexInput_ = Joined;
            WriteStaged();
            return;
          }
          ShowWriteDialog();
        });
    Add("rollback", "rollback  (restore the last write transaction)",
        [this](std::vector<std::string>) { RollbackLast(); });
    Add("physical", "physical  (reload physical memory ranges)",
        [this](std::vector<std::string>) { LoadPhysical(); });
    Add("suspect", "suspect  (scan for suspicious executable regions)",
        [this](std::vector<std::string>) { ScanSuspicious(); });
    Add("scan", "scan <pattern>  (pattern scan, ?? = wildcard)",
        [this](std::vector<std::string> Args) {
          if (!Args.empty()) {
            std::string Joined;
            for (const std::string &Part : Args) {
              if (!Joined.empty())
                Joined += ' ';
              Joined += Part;
            }
            PatternText_ = Joined;
            RunPatternScan();
            return;
          }
          PromptTextDialog(*Dialogs, "Pattern scan", "Pattern:", PatternText_,
                           [this](std::string Pattern) {
                             PatternText_ = TrimAscii(Pattern);
                             RunPatternScan();
                           },
                           "e.g. 48 8B ?? 05 ?? ?? ?? ??");
        });
    Add("dump-modules", "dump-modules  (enumerate modules of the target)",
        [this](std::vector<std::string>) { LoadModules(); });
    Add("dump", "dump <base> <size> [path]  (dump memory to a file)",
        [this](std::vector<std::string> Args) {
          if (Args.size() >= 2) {
            uint64_t Base = 0;
            uint64_t Length = 0;
            if (!StorageUtil::ParseU64(Args[0], &Base) ||
                !StorageUtil::ParseU64(Args[1], &Length)) {
              Notify("Base and size must be numbers.", NoticeKind::Warning);
              return;
            }
            const std::string Path = Args.size() > 2 ? Args[2] : std::string();
            RunDump(Base, Length, Path.empty() ? QString() : StorageUtil::Q(Path));
            return;
          }
          ShowDumpDialog();
        });
    Add("pte", "pte  (walk the page tables for the target address)",
        [this](std::vector<std::string>) { WalkPageTables(); });
    Add("protect", "protect <address> <size> [index]  (change protection)",
        [this](std::vector<std::string> Args) {
          if (Args.size() >= 2) {
            uint64_t Target = 0;
            uint64_t Length = 0;
            if (!StorageUtil::ParseU64(Args[0], &Target) ||
                !StorageUtil::ParseU64(Args[1], &Length)) {
              Notify("Address and size must be numbers.", NoticeKind::Warning);
              return;
            }
            int ProtectIndex = 2;
            if (Args.size() > 2) {
              uint32_t Parsed = 0;
              if (StorageUtil::ParseUInt(Args[2], &Parsed))
                ProtectIndex = static_cast<int>(Parsed);
            }
            ChangeProtect(Target, Length, ProtectIndex);
            return;
          }
          ShowProtectDialog();
        });
    Add("alloc", "alloc <size> [index] [reserve]  (allocate in the target)",
        [this](std::vector<std::string> Args) {
          if (!Args.empty()) {
            uint64_t Length = 0;
            if (!StorageUtil::ParseU64(Args[0], &Length)) {
              Notify("Size must be a number.", NoticeKind::Warning);
              return;
            }
            int ProtectIndex = 0;
            bool Reserve = false;
            if (Args.size() > 1) {
              uint32_t Parsed = 0;
              if (StorageUtil::ParseUInt(Args[1], &Parsed))
                ProtectIndex = static_cast<int>(Parsed);
            }
            if (Args.size() > 2)
              Reserve = LowerAscii(Args[2]) == "reserve";
            AllocateRegion(Length, ProtectIndex, Reserve);
            return;
          }
          ShowAllocDialog();
        });
    Add("free", "free <base>  (release a region in the target)",
        [this](std::vector<std::string> Args) {
          if (!Args.empty()) {
            uint64_t Base = 0;
            if (!StorageUtil::ParseU64(Args[0], &Base)) {
              Notify("Base must be a number.", NoticeKind::Warning);
              return;
            }
            FreeRegion(Base);
            return;
          }
          ShowFreeDialog();
        });
    Add("view", "view [editor|physical|suspect|scan|dump|pte|regions]  (switch view)",
        [this](std::vector<std::string> Args) {
          static const char *Names[] = {"editor",  "physical", "suspect",
                                        "scan",    "dump",     "pte",
                                        "regions"};
          constexpr int Count = 7;
          if (Args.empty()) {
            Tab_ = (Tab_ + 1) % Count;
            return;
          }
          const std::string Name = LowerAscii(Args.front());
          for (int Index = 0; Index < Count; ++Index) {
            if (Name == Names[Index] || Name == std::to_string(Index)) {
              Tab_ = Index;
              return;
            }
          }
          Notify("Unknown view: " + Args.front(), NoticeKind::Warning);
        });
  }

  // ---- 目标解析 ----

  bool ParseTarget(ULONG &ProcessId, ULONG_PTR &TargetAddress) {
    uint64_t PidValue = 0;
    uint64_t AddressValue = 0;
    if (!StorageUtil::ParseU64(Pid_, &PidValue) ||
        PidValue > std::numeric_limits<ULONG>::max() ||
        !StorageUtil::ParseU64(Address_, &AddressValue) || AddressValue == 0) {
      Notify("Enter a valid PID and address. PID 0 means kernel mode.",
             NoticeKind::Warning);
      return false;
    }
    ProcessId = static_cast<ULONG>(PidValue);
    TargetAddress = static_cast<ULONG_PTR>(AddressValue);
    return true;
  }

  bool ParsePidOnly(ULONG &ProcessId) {
    uint64_t PidValue = 0;
    if (!StorageUtil::ParseU64(Pid_, &PidValue) || PidValue == 0 ||
        PidValue > 0xFFFFFFFFull) {
      Notify("Enter a valid non-zero target process ID.", NoticeKind::Warning);
      return false;
    }
    ProcessId = static_cast<ULONG>(PidValue);
    return true;
  }

  // GUI 的 ReadTarget / WriteTarget 分派规则：PID 0 走内核专用 IOCTL。
  static bool ReadFrom(ULONG ProcessId, ULONG_PTR Address, void *Buffer,
                       ULONG Size, ULONG *BytesRead, KRNL_MEMRW_METHOD Method) {
    if (ProcessId == 0)
      return KernelReadMemory(Address, Buffer, Size, BytesRead, Method) != FALSE;
    return ReadMemory(ProcessId, Address, Buffer, Size, BytesRead) != FALSE;
  }

  static bool WriteTo(ULONG ProcessId, ULONG_PTR Address, void *Buffer,
                      ULONG Size, KRNL_MEMRW_METHOD Method) {
    if (ProcessId == 0)
      return KernelWriteMemory(Address, Buffer, Size, Method) != FALSE;
    return WriteMemory(ProcessId, Address, Buffer, Size) != FALSE;
  }

  // ---- 读取 ----

  void ReadTarget(bool Report) {
    ULONG ProcessId = 0;
    ULONG_PTR TargetAddress = 0;
    if (!ParseTarget(ProcessId, TargetAddress))
      return;
    uint32_t Requested = 0;
    if (!StorageUtil::ParseUInt(Size_, &Requested) || Requested == 0 ||
        Requested > 4096) {
      Notify("Read size must be between 1 and 4096.", NoticeKind::Warning);
      return;
    }
    if (Reading_.exchange(true))
      return;
    const KRNL_MEMRW_METHOD Method = MethodValue();
    TuiAsync<ReadOutcome>(
        [ProcessId, TargetAddress, Requested, Method] {
          ReadOutcome Outcome;
          std::vector<unsigned char> Buffer(Requested);
          ULONG BytesRead = 0;
          Outcome.Ok = ReadFrom(ProcessId, TargetAddress, Buffer.data(),
                                Requested, &BytesRead, Method);
          Outcome.Error = Outcome.Ok ? ERROR_SUCCESS : G_LastAegisCoreError;
          Buffer.resize(std::min<size_t>(BytesRead, Buffer.size()));
          Outcome.Bytes = std::move(Buffer);
          return Outcome;
        },
        [this, TargetAddress, Report](ReadOutcome Outcome) {
          Reading_ = false;
          if (!Outcome.Ok) {
            const std::string Message =
                "Read failed (error " + std::to_string(Outcome.Error) + ")";
            SetStatus(Message);
            Notify(Message, NoticeKind::Error);
            return;
          }
          BuildHexPanels(Outcome.Bytes, TargetAddress);
          const std::string Message =
              "Read " + std::to_string(Outcome.Bytes.size()) + " byte(s).";
          SetStatus(Message);
          if (Report)
            Notify(Message, NoticeKind::Success);
        });
  }

  void BuildHexPanels(const std::vector<unsigned char> &Bytes,
                      ULONG_PTR Base) {
    const std::string Dump = FormatHexAscii(Bytes, Base);
    HexLines_.clear();
    AsciiLines_.clear();
    std::string Current;
    for (char C : Dump) {
      if (C == '\n') {
        HexLines_.push_back(Current);
        Current.clear();
      } else {
        Current += C;
      }
    }
    if (!Current.empty())
      HexLines_.push_back(Current);
    if (HexLines_.empty())
      HexLines_.push_back("(no data)");

    for (size_t Offset = 0; Offset < Bytes.size(); Offset += 16) {
      char Line[64];
      std::snprintf(Line, sizeof(Line), "%016llX  ",
                    static_cast<unsigned long long>(Base + Offset));
      std::string Text = Line;
      for (size_t Index = 0; Index < 16 && Offset + Index < Bytes.size();
           ++Index) {
        const unsigned char Value = Bytes[Offset + Index];
        Text += std::isprint(static_cast<int>(Value))
                    ? static_cast<char>(Value)
                    : '.';
      }
      AsciiLines_.push_back(Text);
    }
  }

  // ---- 写事务 ----

  void ShowWriteDialog() {
    TuiDialog Dialog;
    Dialog.Title = "Write memory";
    Dialog.Body = "Hex bytes replace memory starting at the address above.";
    TuiField Field;
    Field.Label = "Bytes";
    Field.Kind = TuiFieldKind::Multiline;
    Field.Value = HexInput_;
    Field.Placeholder = "48 8B 05 00 FF";
    Dialog.Fields.push_back(Field);
    Dialog.PrimaryLabel = "Write";
    Dialog.SecondaryLabel = "Cancel";
    Dialog.OnSubmit = [this](TuiDialog &Submitted) {
      if (Submitted.Fields.empty())
        return;
      HexInput_ = Submitted.Fields.front().Value;
      WriteStaged();
    };
    Dialogs->Push(std::move(Dialog));
  }

  bool ParseStagedBytes(std::vector<unsigned char> &Bytes) {
    Bytes.clear();
    std::string Text = HexInput_;
    for (char &C : Text) {
      if (C == ',' || C == ';' || C == '\n' || C == '\t' || C == '\r')
        C = ' ';
    }
    std::vector<std::string> Tokens;
    std::string Current;
    for (char C : Text) {
      if (std::isspace(static_cast<unsigned char>(C)) != 0) {
        if (!Current.empty()) {
          Tokens.push_back(Current);
          Current.clear();
        }
      } else {
        Current += C;
      }
    }
    if (!Current.empty())
      Tokens.push_back(Current);
    if (Tokens.empty() || Tokens.size() > 4096) {
      Notify("Enter between 1 and 4096 hexadecimal bytes.",
             NoticeKind::Warning);
      return false;
    }
    for (std::string Token : Tokens) {
      if (StartsWithCi(Token, "0x"))
        Token.erase(0, 2);
      bool Ok = false;
      const QString Text = QString::fromStdString(Token);
      const uint Value = Text.toUInt(&Ok, 16);
      if (!Ok || Token.size() > 2 || Value > 0xFF) {
        Notify("Invalid hex byte: " + Token, NoticeKind::Warning);
        return false;
      }
      Bytes.push_back(static_cast<unsigned char>(Value));
    }
    return true;
  }

  void WriteStaged() {
    ULONG ProcessId = 0;
    ULONG_PTR TargetAddress = 0;
    if (!ParseTarget(ProcessId, TargetAddress))
      return;
    std::vector<unsigned char> Bytes;
    if (!ParseStagedBytes(Bytes))
      return;
    if (Writing_.exchange(true))
      return;

    const KRNL_MEMRW_METHOD Method = MethodValue();
    TuiAsync<WriteOutcome>(
        [ProcessId, TargetAddress, Bytes, Method] {
          WriteOutcome Outcome;
          std::vector<unsigned char> Before(Bytes.size());
          ULONG BeforeRead = 0;
          if (!ReadFrom(ProcessId, TargetAddress, Before.data(),
                        static_cast<ULONG>(Before.size()), &BeforeRead,
                        Method) ||
              BeforeRead != Before.size()) {
            Outcome.State = WriteState::ReadFailed;
            Outcome.Error = G_LastAegisCoreError;
            return Outcome;
          }
          Before.resize(BeforeRead);

          QStringList Diff;
          for (size_t Index = 0; Index < Bytes.size(); ++Index) {
            if (Before[Index] != Bytes[Index])
              Diff << QString("+0x%1: %2 -> %3")
                          .arg(Index, 0, 16)
                          .arg(Before[Index], 2, 16, QLatin1Char('0'))
                          .arg(Bytes[Index], 2, 16, QLatin1Char('0'))
                          .toUpper();
            if (Diff.size() == 16) {
              Diff << "...";
              break;
            }
          }
          if (Diff.isEmpty()) {
            Outcome.State = WriteState::Identical;
            return Outcome;
          }
          Outcome.DiffSummary = Diff.join(" | ").toStdString();

          const auto Modules =
              ProcessId == 0
                  ? AegisNT::KernelResearch::QueryAll(IOCTL_ENUM_KERNEL_MODULES)
                  : std::vector<INVENTORY_RECORD>{};
          const auto Owner =
              AegisNT::KernelResearch::ResolveAddress(TargetAddress, Modules);
          Outcome.OwnerName = Owner.Module.isEmpty()
                                  ? std::string("unresolved")
                                  : Owner.Module.toStdString();

          std::vector<unsigned char> Staged = Bytes;
          if (!WriteTo(ProcessId, TargetAddress, Staged.data(),
                       static_cast<ULONG>(Staged.size()), Method)) {
            Outcome.State = WriteState::WriteFailed;
            Outcome.Error = G_LastAegisCoreError;
            return Outcome;
          }

          std::vector<unsigned char> Verify(Bytes.size());
          ULONG VerifiedRead = 0;
          const bool Verified =
              ReadFrom(ProcessId, TargetAddress, Verify.data(),
                       static_cast<ULONG>(Verify.size()), &VerifiedRead,
                       Method) &&
              VerifiedRead == Bytes.size() && Verify == Bytes;
          if (!Verified) {
            const bool Restored =
                WriteTo(ProcessId, TargetAddress, Before.data(),
                        static_cast<ULONG>(Before.size()), Method);
            Outcome.State = Restored ? WriteState::VerifyFailedRestored
                                     : WriteState::VerifyFailedRestoreFailed;
            return Outcome;
          }

          auto Tx = std::make_shared<AegisNT::KernelResearch::WriteTransaction>();
          Tx->Id = QUuid::createUuid().toString(QUuid::WithoutBraces);
          Tx->CreatedUtc = QDateTime::currentDateTimeUtc();
          Tx->Address = TargetAddress;
          Tx->Before = QByteArray(reinterpret_cast<const char *>(Before.data()),
                                  static_cast<int>(Before.size()));
          Tx->After = QByteArray(reinterpret_cast<const char *>(Bytes.data()),
                                 static_cast<int>(Bytes.size()));
          Tx->Owner = Owner;
          Tx->Verified = true;
          Outcome.Transaction = Tx;
          Outcome.TransactionId = Tx->Id.toStdString();

          QDir AuditDir(QCoreApplication::applicationDirPath());
          AuditDir.mkpath("Data/Audit");
          QFile Audit(AuditDir.filePath(
              "Data/Audit/kernel-write-" +
              QDate::currentDate().toString("yyyyMMdd") + ".jsonl"));
          if (Audit.open(QIODevice::WriteOnly | QIODevice::Append)) {
            const QJsonObject Record{
                {"id", Tx->Id},
                {"createdUtc", Tx->CreatedUtc.toString(Qt::ISODate)},
                {"address", AegisNT::KernelResearch::Hex(Tx->Address)},
                {"size", static_cast<int>(Bytes.size())},
                {"verified", true},
                {"owner", AegisNT::KernelResearch::AddressJson(Tx->Owner)}};
            const QByteArray Line =
                QJsonDocument(Record).toJson(QJsonDocument::Compact) + '\n';
            if (Audit.write(Line) != Line.size()) {
              Outcome.AuditFailed = true;
              Outcome.AuditError = Audit.errorString().toStdString();
            }
          } else {
            Outcome.AuditFailed = true;
            Outcome.AuditError = Audit.errorString().toStdString();
          }
          Outcome.State = WriteState::Ok;
          return Outcome;
        },
        [this, Bytes](WriteOutcome Outcome) {
          Writing_ = false;
          switch (Outcome.State) {
          case WriteState::ReadFailed:
            Notify("Pre-write read failed; no write was attempted.",
                   NoticeKind::Error);
            return;
          case WriteState::Identical:
            Notify("The staged bytes are identical to memory.",
                   NoticeKind::Warning);
            return;
          case WriteState::WriteFailed: {
            const std::string Message =
                "Write failed (error " + std::to_string(Outcome.Error) + ")";
            SetStatus(Message);
            Notify(Message, NoticeKind::Error);
            return;
          }
          case WriteState::VerifyFailedRestored:
            SetStatus("Write verification failed; automatic restore succeeded.");
            Notify("Write verification failed; automatic restore succeeded.",
                   NoticeKind::Error);
            return;
          case WriteState::VerifyFailedRestoreFailed:
            SetStatus("Write verification failed; automatic restore failed.");
            Notify("Write verification failed; automatic restore failed.",
                   NoticeKind::Error);
            return;
          case WriteState::Ok:
          default:
            break;
          }

          if (Outcome.Transaction) {
            LastTransaction_ = Outcome.Transaction;
            RollbackEnabled_ = true;
          }
          if (Outcome.AuditFailed)
            AppendConsoleOutput(
                QString("[WARN] Memory: Kernel write succeeded, but the audit "
                        "record could not be written: %1\n")
                    .arg(QString::fromStdString(Outcome.AuditError)));
          const std::string Message =
              "Wrote and verified " + std::to_string(Bytes.size()) +
              " byte(s). Transaction " + Outcome.TransactionId.substr(0, 8);
          SetStatus(Message);
          Notify(Message, NoticeKind::Success);
          MarkMutated();
          ReadTarget(false);
        });
  }

  void RollbackLast() {
    if (!LastTransaction_) {
      Notify("No write transaction is available.", NoticeKind::Warning);
      return;
    }
    ULONG ProcessId = 0;
    ULONG_PTR TargetAddress = 0;
    if (!ParseTarget(ProcessId, TargetAddress))
      return;
    if (TargetAddress != LastTransaction_->Address) {
      Notify("Current address does not match the last transaction.",
             NoticeKind::Warning);
      return;
    }
    if (Writing_.exchange(true))
      return;
    const KRNL_MEMRW_METHOD Method = MethodValue();
    auto Tx = LastTransaction_;
    TuiAsync<RollbackOutcome>(
        [ProcessId, Tx, Method] {
          RollbackOutcome Outcome;
          std::vector<unsigned char> Current(
              static_cast<size_t>(Tx->After.size()));
          ULONG ReadBytes = 0;
          if (!ReadFrom(ProcessId, Tx->Address, Current.data(),
                        static_cast<ULONG>(Current.size()), &ReadBytes,
                        Method) ||
              QByteArray(reinterpret_cast<const char *>(Current.data()),
                         static_cast<int>(ReadBytes)) != Tx->After) {
            Outcome.State = RollbackOutcome::State::MemoryChanged;
            return Outcome;
          }
          QByteArray RestoreBytes = Tx->Before;
          if (!WriteTo(ProcessId, Tx->Address, RestoreBytes.data(),
                       static_cast<ULONG>(RestoreBytes.size()), Method)) {
            Outcome.State = RollbackOutcome::State::WriteFailed;
            return Outcome;
          }
          Outcome.State = RollbackOutcome::State::Ok;
          return Outcome;
        },
        [this](RollbackOutcome Outcome) {
          Writing_ = false;
          switch (Outcome.State) {
          case RollbackOutcome::State::MemoryChanged:
            Notify("Memory changed after the transaction; rollback refused.",
                   NoticeKind::Warning);
            return;
          case RollbackOutcome::State::WriteFailed:
            Notify("Rollback write failed.", NoticeKind::Error);
            return;
          case RollbackOutcome::State::AddressMismatch:
          case RollbackOutcome::State::NoTransaction:
            Notify("No write transaction is available.", NoticeKind::Warning);
            return;
          case RollbackOutcome::State::Ok:
          default:
            break;
          }
          if (LastTransaction_)
            LastTransaction_->RolledBack = true;
          RollbackEnabled_ = false;
          SetStatus(
              "Last transaction rolled back and verified on next read.");
          Notify("Last write transaction rolled back.", NoticeKind::Success);
          MarkMutated();
        });
  }

  // ---- Physical ranges ----

  void LoadPhysical() {
    if (LoadingPhysical_.exchange(true)) {
      Notify("Already loading physical ranges.", NoticeKind::Info);
      return;
    }
    TuiAsync<std::vector<INVENTORY_RECORD>>(
        [] { return AegisNT::KernelResearch::QueryAll(IOCTL_QUERY_MEMORY); },
        [this](std::vector<INVENTORY_RECORD> Records) {
          LoadingPhysical_ = false;
          std::vector<TuiRow> Rows;
          Rows.reserve(Records.size());
          for (const INVENTORY_RECORD &Record : Records) {
            const quint64 End = Record.Address + Record.SizeBytes;
            Rows.push_back(TuiRow{
                {std::to_string(Record.Value[0]),
                 AegisNT::KernelResearch::Hex(Record.Address).toStdString(),
                 AegisNT::KernelResearch::Hex(End).toStdString(),
                 std::to_string(Record.SizeBytes),
                 std::to_string(Record.SizeBytes / (1024ull * 1024ull)) +
                     " MiB"},
                {}});
          }
          Physical_.Rows = std::move(Rows);
          Physical_.Filter = Filter;
          Physical_.Rebuild();
          SetStatus(std::to_string(Physical_.Rows.size()) +
                    " physical range(s)");
          if (Physical_.Rows.empty())
            Notify("No physical memory ranges returned (driver unavailable?).",
                   NoticeKind::Warning);
        });
  }

  // ---- Suspicious memory ----

  void ScanSuspicious() {
    ULONG ProcessId = 0;
    if (!ParsePidOnly(ProcessId))
      return;
    if (Scanning_.exchange(true))
      return;
    SuspectStatus_ = "Scanning...";
    TuiAsync<std::pair<bool, SUSPECT_MEMORY_OUTPUT>>(
        [ProcessId] {
          SUSPECT_MEMORY_OUTPUT Output{};
          const bool Ok = SuspiciousMemoryScan(ProcessId, &Output) != FALSE;
          return std::pair<bool, SUSPECT_MEMORY_OUTPUT>(Ok, Output);
        },
        [this, ProcessId](std::pair<bool, SUSPECT_MEMORY_OUTPUT> Result) {
          Scanning_ = false;
          if (!Result.first) {
            const std::string Message =
                "Scan failed (error " + std::to_string(G_LastAegisCoreError) +
                ")";
            SuspectStatus_ = Message;
            Notify(Message, NoticeKind::Error);
            return;
          }
          const SUSPECT_MEMORY_OUTPUT &Output = Result.second;
          std::vector<TuiRow> Rows;
          const ULONG Count = std::min<ULONG>(Output.Count,
                                              SUSPICIOUS_MEMORY_MAX_REGIONS);
          Rows.reserve(Count);
          for (ULONG Index = 0; Index < Count; ++Index) {
            const SUSPECT_MEMORY_REGION &Region = Output.Regions[Index];
            Rows.push_back(TuiRow{
                {StorageUtil::Utf8(
                     QString("0x%1").arg(Region.Base, 16, 16, QLatin1Char('0'))
                         .toUpper()),
                 std::to_string(Region.Size) + " bytes",
                 StorageUtil::Utf8(QString("0x%1")
                                       .arg(Region.Protect, 8, 16,
                                            QLatin1Char('0'))
                                       .toUpper()),
                 Region.Type == 0x00020000
                     ? std::string("Private")
                     : StorageUtil::Utf8(QString("0x%1")
                                             .arg(Region.Type, 8, 16,
                                                  QLatin1Char('0'))),
                 (Region.Flags & SUSPECT_FLAG_UNBACKED_EXEC)
                     ? std::string("Unbacked executable")
                     : std::string("-")},
                {}});
          }
          Suspect_.Rows = std::move(Rows);
          Suspect_.Filter = Filter;
          Suspect_.Rebuild();
          SuspectStatus_ = std::to_string(Output.Count) +
                           " suspect region(s) in PID " +
                           std::to_string(ProcessId) + " (" +
                           std::to_string(Output.TotalCount) +
                           " total scanned)";
          SetStatus(SuspectStatus_);
        });
  }

  // ---- Pattern scan ----

  void RunPatternScan() {
    ULONG ProcessId = 0;
    if (!ParsePidOnly(ProcessId))
      return;

    std::vector<std::string> Tokens;
    {
      std::string Current;
      for (char C : PatternText_) {
        if (std::isspace(static_cast<unsigned char>(C)) != 0 || C == ',') {
          if (!Current.empty()) {
            Tokens.push_back(Current);
            Current.clear();
          }
        } else {
          Current += C;
        }
      }
      if (!Current.empty())
        Tokens.push_back(Current);
    }
    if (Tokens.empty() || Tokens.size() > 256) {
      Notify("Enter 1-256 pattern bytes.", NoticeKind::Warning);
      return;
    }
    std::vector<PatternByte> Pattern;
    for (const std::string &Token : Tokens) {
      if (Token == "??" || Token == "*" || Token == "?") {
        Pattern.push_back({0, true});
        continue;
      }
      std::string Hex = Token;
      if (StartsWithCi(Hex, "0x"))
        Hex.erase(0, 2);
      bool Ok = false;
      const uint Value = QString::fromStdString(Hex).toUInt(&Ok, 16);
      if (!Ok || Hex.size() > 2 || Value > 0xFF) {
        Notify("Invalid pattern byte: " + Token, NoticeKind::Warning);
        return;
      }
      Pattern.push_back({static_cast<unsigned char>(Value), false});
    }
    bool AnyByte = false;
    for (const PatternByte &Byte : Pattern)
      if (!Byte.Wildcard)
        AnyByte = true;
    if (!AnyByte) {
      Notify("Pattern must contain at least one concrete byte.",
             NoticeKind::Warning);
      return;
    }
    if (Scanning_.exchange(true))
      return;
    ScanStatus_ = "Scanning...";
    TuiAsync<ScanOutcome>(
        [ProcessId, Pattern] {
          ScanOutcome Outcome;
          constexpr ULONG64 ScanLimit = 512ull << 20;
          constexpr size_t MaxHits = 1000;
          const HANDLE Handle =
              OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE,
                          ProcessId);
          if (Handle == nullptr) {
            Outcome.Ok = false;
            return Outcome;
          }
          ULONG_PTR Region = 0;
          MEMORY_BASIC_INFORMATION Mbi{};
          while (VirtualQueryEx(Handle, reinterpret_cast<LPCVOID>(Region), &Mbi,
                               sizeof(Mbi)) &&
                 Outcome.Hits.size() < MaxHits && Outcome.Scanned < ScanLimit) {
            const ULONG_PTR RegionBase =
                reinterpret_cast<ULONG_PTR>(Mbi.BaseAddress);
            const ULONG_PTR RegionSize = Mbi.RegionSize;
            if (Mbi.State == MEM_COMMIT && RegionSize > 0 &&
                MemoryProtectReadable(Mbi.Protect)) {
              constexpr ULONG ChunkSize = 1u << 20;
              ULONG_PTR Offset = 0;
              std::vector<unsigned char> Tail;
              while (Offset < RegionSize && Outcome.Hits.size() < MaxHits &&
                     Outcome.Scanned < ScanLimit) {
                ULONG Take = ChunkSize;
                if (Offset + Take > RegionSize)
                  Take = static_cast<ULONG>(RegionSize - Offset);
                std::vector<unsigned char> Buffer(Tail.size() + Take);
                if (!Tail.empty())
                  memcpy(Buffer.data(), Tail.data(), Tail.size());
                SIZE_T ReadBytes = 0;
                if (!ReadProcessMemory(Handle,
                                       reinterpret_cast<LPCVOID>(RegionBase +
                                                                 Offset),
                                       Buffer.data() + Tail.size(), Take,
                                       &ReadBytes) ||
                    ReadBytes == 0) {
                  ++Outcome.Skipped;
                  break;
                }
                Buffer.resize(Tail.size() + ReadBytes);
                Outcome.Scanned += ReadBytes;
                const ULONG_PTR BufferBase =
                    RegionBase + Offset - Tail.size();
                size_t Position = 0;
                while (Outcome.Hits.size() < MaxHits) {
                  const size_t Found =
                      PatternFind(Buffer.data() + Position,
                                  Buffer.size() - Position, Pattern);
                  if (Found == static_cast<size_t>(-1))
                    break;
                  const size_t Match = Position + Found;
                  PatternScanHit Hit;
                  Hit.Address = BufferBase + Match;
                  Hit.RegionBase = RegionBase;
                  Hit.Protect = Mbi.Protect;
                  Hit.Type = Mbi.Type;
                  const size_t ContextStart = Match >= 8 ? Match - 8 : 0;
                  const size_t ContextLength =
                      std::min<size_t>(16, Buffer.size() - ContextStart);
                  ZeroMemory(Hit.Context, sizeof(Hit.Context));
                  memcpy(Hit.Context, Buffer.data() + ContextStart,
                         ContextLength);
                  Outcome.Hits.push_back(Hit);
                  Position = Match + 1;
                  if (Position >= Buffer.size())
                    break;
                }
                const size_t Keep =
                    std::min<size_t>(Buffer.size(), Pattern.size() - 1);
                Tail.assign(Buffer.end() - static_cast<ptrdiff_t>(Keep),
                            Buffer.end());
                Offset += ReadBytes;
              }
            }
            Region = RegionBase + RegionSize;
            if (Region < RegionBase)
              break;
          }
          CloseHandle(Handle);
          Outcome.Ok = true;
          return Outcome;
        },
        [this](ScanOutcome Outcome) {
          Scanning_ = false;
          if (!Outcome.Ok) {
            const std::string Message =
                "Scan failed (error " +
                std::to_string(G_LastAegisCoreError) + ")";
            ScanStatus_ = Message;
            Notify(Message, NoticeKind::Error);
            return;
          }
          std::vector<TuiRow> Rows;
          Rows.reserve(Outcome.Hits.size());
          for (const PatternScanHit &Hit : Outcome.Hits) {
            std::string Context;
            char Buffer[8];
            for (unsigned char Byte : Hit.Context) {
              std::snprintf(Buffer, sizeof(Buffer), "%02X ", Byte);
              Context += Buffer;
            }
            while (!Context.empty() && Context.back() == ' ')
              Context.pop_back();
            Rows.push_back(TuiRow{
                {AegisNT::KernelResearch::Hex(Hit.Address).toStdString(),
                 AegisNT::KernelResearch::Hex(Hit.RegionBase).toStdString(),
                 StorageUtil::Utf8(QString("0x%1")
                                       .arg(Hit.Protect, 8, 16,
                                            QLatin1Char('0'))
                                       .toUpper()),
                 Hit.Type == MEM_PRIVATE
                     ? std::string("Private")
                     : (Hit.Type == MEM_MAPPED
                            ? std::string("Mapped")
                            : (Hit.Type == MEM_IMAGE ? std::string("Image")
                                                     : std::string("-"))),
                 Context},
                {}});
          }
          Scan_.Rows = std::move(Rows);
          Scan_.Filter = Filter;
          Scan_.Rebuild();
          ScanStatus_ = std::to_string(Outcome.Hits.size()) + " hit(s), " +
                        std::to_string(Outcome.Scanned >> 20) +
                        " MiB scanned, " + std::to_string(Outcome.Skipped) +
                        " unreadable region(s).";
          SetStatus(ScanStatus_);
        });
  }

  // ---- Dump ----

  void LoadModules() {
    ULONG ProcessId = 0;
    if (!ParsePidOnly(ProcessId))
      return;
    if (LoadingModules_.exchange(true))
      return;
    DumpStatus_ = "Enumerating modules...";
    TuiAsync<std::vector<INVENTORY_RECORD>>(
        [ProcessId] {
          return AegisNT::KernelResearch::QueryAll(IOCTL_ENUM_MODULES, {},
                                                   ProcessId);
        },
        [this](std::vector<INVENTORY_RECORD> Modules) {
          LoadingModules_ = false;
          std::vector<TuiRow> Rows;
          Rows.reserve(Modules.size());
          for (const INVENTORY_RECORD &Record : Modules) {
            Rows.push_back(TuiRow{
                {QString::fromWCharArray(Record.Name).toStdString(),
                 AegisNT::KernelResearch::Hex(Record.Address).toStdString(),
                 std::to_string(Record.SizeBytes / 1024) + " KB"},
                {}});
          }
          Modules_.Rows = std::move(Rows);
          Modules_.Filter = Filter;
          Modules_.Rebuild();
          DumpStatus_ = Modules.empty()
                            ? "(no modules enumerated)"
                            : std::to_string(Modules.size()) + " module(s)";
          SetStatus(DumpStatus_);
        });
  }

  void ShowDumpDialog() {
    TuiDialog Dialog;
    Dialog.Title = "Dump memory";
    Dialog.Body = "Provide an explicit base and size, or use dump-modules.";
    TuiField Base;
    Base.Label = "Base";
    Base.Value = Address_;
    Base.Placeholder = "0x7FF612340000";
    Dialog.Fields.push_back(Base);

    TuiField Length;
    Length.Label = "Size";
    Length.Placeholder = "bytes";
    Dialog.Fields.push_back(Length);

    TuiField Path;
    Path.Label = "File";
    Path.Placeholder = "empty = Data/Dumps/<name>_<pid>.bin";
    Dialog.Fields.push_back(Path);

    Dialog.PrimaryLabel = "Dump";
    Dialog.SecondaryLabel = "Cancel";
    Dialog.Validate = [](const TuiDialog &Current) -> std::string {
      if (Current.Fields.size() < 2)
        return {};
      uint64_t Base = 0;
      uint64_t Size = 0;
      if (!StorageUtil::ParseU64(Current.Fields[0].Value, &Base))
        return "Enter a valid dump base address.";
      if (!StorageUtil::ParseU64(Current.Fields[1].Value, &Size) || Size == 0)
        return "Enter a size in bytes.";
      return {};
    };
    Dialog.OnSubmit = [this](TuiDialog &Submitted) {
      if (Submitted.Fields.size() < 3)
        return;
      uint64_t Base = 0;
      uint64_t Size = 0;
      StorageUtil::ParseU64(Submitted.Fields[0].Value, &Base);
      StorageUtil::ParseU64(Submitted.Fields[1].Value, &Size);
      DumpPathOverride_ = StorageUtil::Q(TrimAscii(Submitted.Fields[2].Value));
      RunDump(Base, Size, QString());
    };
    Dialogs->Push(std::move(Dialog));
  }

  struct DumpOutcome {
    ULONG64 Written = 0;
    ULONG64 Requested = 0;
    NTSTATUS LastError = 0;
    QString Path;
  };

  void RunDump(ULONG_PTR Base, ULONG64 Size, const QString &Name) {
    ULONG ProcessId = 0;
    if (!ParsePidOnly(ProcessId))
      return;
    if (Base == 0) {
      Notify("Enter a valid dump base address.", NoticeKind::Warning);
      return;
    }
    // 显式路径优先，其次 Data/Dumps/<name>_<pid>.bin。
    QString Target = DumpPathOverride_;
    DumpPathOverride_.clear();
    if (Target.isEmpty()) {
      QDir DumpDir(QCoreApplication::applicationDirPath());
      DumpDir.mkpath("Data/Dumps");
      Target = DumpDir.filePath(QString("Data/Dumps/%1_%2.bin")
                                    .arg(Name.isEmpty() ? "range" : Name)
                                    .arg(ProcessId));
    }
    if (Dumping_.exchange(true))
      return;
    DumpStatus_ = "Dumping " + std::to_string(Size) + " byte(s) from " +
                  AegisNT::KernelResearch::Hex(Base).toStdString() + " ...";
    TuiAsync<DumpOutcome>(
        [ProcessId, Base, Size, Target] {
          DumpOutcome Outcome;
          Outcome.Requested = Size;
          Outcome.Path = Target;
          QDir().mkpath(QFileInfo(Target).absolutePath());
          QFile Output(Target);
          if (!Output.open(QIODevice::WriteOnly | QIODevice::Truncate))
            return Outcome;
          unsigned char Buffer[4096];
          while (Outcome.Written < Size) {
            const ULONG Take = static_cast<ULONG>(
                std::min<ULONG64>(sizeof(Buffer), Size - Outcome.Written));
            ULONG Read = 0;
            if (!ReadMemory(ProcessId, Base + Outcome.Written, Buffer, Take,
                            &Read) ||
                Read == 0) {
              Outcome.LastError = static_cast<NTSTATUS>(G_LastAegisCoreError);
              break;
            }
            if (Output.write(reinterpret_cast<const char *>(Buffer), Read) !=
                Read) {
              Outcome.LastError = static_cast<NTSTATUS>(-1);
              break;
            }
            Outcome.Written += Read;
          }
          Output.close();
          return Outcome;
        },
        [this](DumpOutcome Outcome) {
          Dumping_ = false;
          DumpPathOverride_.clear();
          if (Outcome.Written == 0) {
            const std::string Message =
                "Dump failed (error " + std::to_string(Outcome.LastError) + ").";
            DumpStatus_ = Message;
            Notify(Message, NoticeKind::Error);
            return;
          }
          const QString Path = QDir::toNativeSeparators(Outcome.Path);
          if (Outcome.Written == Outcome.Requested) {
            const std::string Message =
                "Dumped " + std::to_string(Outcome.Written) + " byte(s) to " +
                Path.toStdString() + ".";
            DumpStatus_ = Message;
            Notify(Message, NoticeKind::Success);
          } else {
            const std::string Message =
                "Partial dump: " + std::to_string(Outcome.Written) + " of " +
                std::to_string(Outcome.Requested) + " byte(s) to " +
                Path.toStdString() + " (error " +
                std::to_string(Outcome.LastError) + ").";
            DumpStatus_ = Message;
            Notify(Message, NoticeKind::Warning);
          }
          SetStatus(DumpStatus_);
        });
  }

  // ---- PTE walk ----

  void WalkPageTables() {
    uint64_t PidValue = 0;
    uint64_t AddressValue = 0;
    if (!StorageUtil::ParseU64(Pid_, &PidValue) ||
        PidValue > 0xFFFFFFFFull ||
        !StorageUtil::ParseU64(Address_, &AddressValue) ||
        AddressValue == 0) {
      Notify("Enter a valid PID and address above.", NoticeKind::Warning);
      return;
    }
    if (Walking_.exchange(true))
      return;
    PteStatus_ = "Walking page tables...";
    const ULONG ProcessId = static_cast<ULONG>(PidValue);
    TuiAsync<std::pair<bool, std::vector<INVENTORY_RECORD>>>(
        [ProcessId, AddressValue] {
          std::vector<INVENTORY_RECORD> Records;
          INVENTORY_LIST_HEADER Header{};
          const bool Ok =
              QueryPteWalk(ProcessId, AddressValue, Records, &Header);
          return std::pair<bool, std::vector<INVENTORY_RECORD>>(Ok,
                                                                std::move(Records));
        },
        [this](std::pair<bool, std::vector<INVENTORY_RECORD>> Result) {
          Walking_ = false;
          std::vector<TuiRow> Rows;
          if (!Result.first || Result.second.empty()) {
            const std::string Message = "Page-table walk failed (error " +
                                        std::to_string(G_LastAegisCoreError) +
                                        ").";
            Pte_.Rows.clear();
            Pte_.Rebuild();
            PteStatus_ = Message;
            Notify(Message, NoticeKind::Error);
            return;
          }
          Rows.reserve(Result.second.size());
          for (const INVENTORY_RECORD &Record : Result.second) {
            Rows.push_back(TuiRow{
                {QString::fromWCharArray(Record.Name).toStdString(),
                 AegisNT::KernelResearch::Hex(Record.Address).toStdString(),
                 AegisNT::KernelResearch::Hex(Record.Value[0]).toStdString(),
                 Record.Value[1]
                     ? AegisNT::KernelResearch::Hex(Record.Value[1]).toStdString()
                     : std::string("-"),
                 QString::fromWCharArray(Record.Detail).toStdString()},
                {}});
          }
          Pte_.Rows = std::move(Rows);
          Pte_.Filter = Filter;
          Pte_.Rebuild();
          PteStatus_ = std::to_string(Result.second.size()) + " level(s) walked.";
          SetStatus(PteStatus_);
        });
  }

  // ---- Region ops ----

  static const ULONG *ProtectTable() {
    static const ULONG Table[] = {PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
                                 PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE};
    return Table;
  }

  static const ULONG *AllocProtectTable() {
    static const ULONG Table[] = {PAGE_READWRITE, PAGE_EXECUTE_READWRITE,
                                  PAGE_EXECUTE_READ};
    return Table;
  }

  void ShowProtectDialog() {
    TuiDialog Dialog;
    Dialog.Title = "Change protection";
    TuiField Address;
    Address.Label = "Address";
    Address.Value = Address_;
    Dialog.Fields.push_back(Address);
    TuiField Length;
    Length.Label = "Size";
    Length.Placeholder = "bytes";
    Dialog.Fields.push_back(Length);
    TuiField Protect;
    Protect.Label = "Protect";
    Protect.Kind = TuiFieldKind::Combo;
    Protect.Choices = {"PAGE_NOACCESS", "PAGE_READONLY", "PAGE_READWRITE",
                       "PAGE_EXECUTE_READ", "PAGE_EXECUTE_READWRITE"};
    Protect.Choice = 2;
    Dialog.Fields.push_back(Protect);
    Dialog.PrimaryLabel = "Apply";
    Dialog.SecondaryLabel = "Cancel";
    Dialog.Validate = [](const TuiDialog &Current) -> std::string {
      if (Current.Fields.size() < 3)
        return {};
      uint64_t Target = 0;
      uint64_t Size = 0;
      if (!StorageUtil::ParseU64(Current.Fields[0].Value, &Target) ||
          !StorageUtil::ParseU64(Current.Fields[1].Value, &Size) || Size == 0)
        return "Enter a valid address and size.";
      return {};
    };
    Dialog.OnSubmit = [this](TuiDialog &Submitted) {
      if (Submitted.Fields.size() < 3)
        return;
      uint64_t Target = 0;
      uint64_t Size = 0;
      StorageUtil::ParseU64(Submitted.Fields[0].Value, &Target);
      StorageUtil::ParseU64(Submitted.Fields[1].Value, &Size);
      ChangeProtect(Target, Size, Submitted.Fields[2].Choice);
    };
    Dialogs->Push(std::move(Dialog));
  }

  void ChangeProtect(uint64_t Target, uint64_t Size, int ProtectIndex) {
    ULONG ProcessId = 0;
    if (!ParsePidOnly(ProcessId))
      return;
    if (Target == 0 || Size == 0) {
      Notify("Enter a valid address and size.", NoticeKind::Warning);
      return;
    }
    const ULONG NewProtect = ProtectTable()[std::clamp(ProtectIndex, 0, 4)];
    if (OpsBusy_.exchange(true))
      return;
    TuiAsync<std::pair<bool, std::pair<DWORD, ULONG>>>(
        [ProcessId, Target, Size, NewProtect] {
          ULONG OldProtect = 0;
          const bool Ok =
              KernelProtectMemory(ProcessId, static_cast<ULONG_PTR>(Target),
                                  Size, NewProtect, &OldProtect) != FALSE;
          return std::pair<bool, std::pair<DWORD, ULONG>>(
              Ok, {Ok ? ERROR_SUCCESS : G_LastAegisCoreError, OldProtect});
        },
        [this](std::pair<bool, std::pair<DWORD, ULONG>> Result) {
          OpsBusy_ = false;
          if (!Result.first) {
            const std::string Message =
                "Change protect failed (error " +
                std::to_string(Result.second.first) + ").";
            OpsStatus_ = Message;
            Notify(Message, NoticeKind::Error);
            return;
          }
          const std::string Message =
              StorageUtil::Utf8(QString("Protection changed; old protect 0x%1.")
                                    .arg(Result.second.second, 8, 16,
                                         QLatin1Char('0'))
                                    .toUpper());
          OpsStatus_ = Message;
          Notify(Message, NoticeKind::Success);
          MarkMutated();
        });
  }

  void ShowAllocDialog() {
    TuiDialog Dialog;
    Dialog.Title = "Allocate memory";
    TuiField Length;
    Length.Label = "Size";
    Length.Placeholder = "bytes (max 256 MiB)";
    Dialog.Fields.push_back(Length);
    TuiField Protect;
    Protect.Label = "Protect";
    Protect.Kind = TuiFieldKind::Combo;
    Protect.Choices = {"PAGE_READWRITE", "PAGE_EXECUTE_READWRITE",
                       "PAGE_EXECUTE_READ"};
    Dialog.Fields.push_back(Protect);
    TuiField Reserve;
    Reserve.Label = "Reserve only";
    Reserve.Kind = TuiFieldKind::Check;
    Dialog.Fields.push_back(Reserve);
    Dialog.PrimaryLabel = "Allocate";
    Dialog.SecondaryLabel = "Cancel";
    Dialog.Validate = [](const TuiDialog &Current) -> std::string {
      if (Current.Fields.empty())
        return {};
      uint64_t Size = 0;
      if (!StorageUtil::ParseU64(Current.Fields[0].Value, &Size) || Size == 0)
        return "Alloc size must be 1 byte - 256 MiB.";
      return {};
    };
    Dialog.OnSubmit = [this](TuiDialog &Submitted) {
      if (Submitted.Fields.size() < 3)
        return;
      uint64_t Size = 0;
      StorageUtil::ParseU64(Submitted.Fields[0].Value, &Size);
      AllocateRegion(Size, Submitted.Fields[1].Choice,
                     Submitted.Fields[2].Checked);
    };
    Dialogs->Push(std::move(Dialog));
  }

  void AllocateRegion(uint64_t Size, int ProtectIndex, bool ReserveOnly) {
    ULONG ProcessId = 0;
    if (!ParsePidOnly(ProcessId))
      return;
    if (Size == 0 || Size > (256ull << 20)) {
      Notify("Alloc size must be 1 byte - 256 MiB.", NoticeKind::Warning);
      return;
    }
    const ULONG Protect = AllocProtectTable()[std::clamp(ProtectIndex, 0, 2)];
    if (OpsBusy_.exchange(true))
      return;
    TuiAsync<std::pair<bool, std::pair<DWORD, ULONG_PTR>>>(
        [ProcessId, Size, Protect, ReserveOnly] {
          ULONG_PTR Base = 0;
          const bool Ok =
              KernelAllocMemory(ProcessId, Size, Protect,
                                ReserveOnly ? TRUE : FALSE, &Base) != FALSE;
          return std::pair<bool, std::pair<DWORD, ULONG_PTR>>(
              Ok, {Ok ? ERROR_SUCCESS : G_LastAegisCoreError, Base});
        },
        [this](std::pair<bool, std::pair<DWORD, ULONG_PTR>> Result) {
          OpsBusy_ = false;
          if (!Result.first) {
            const std::string Message = "Allocate failed (error " +
                                        std::to_string(Result.second.first) +
                                        ").";
            OpsStatus_ = Message;
            Notify(Message, NoticeKind::Error);
            return;
          }
          const std::string Message =
              StorageUtil::Utf8(QString("Allocated at %1.")
                                    .arg(AegisNT::KernelResearch::Hex(
                                        Result.second.second)));
          OpsStatus_ = Message;
          Notify(Message, NoticeKind::Success);
          MarkMutated();
        });
  }

  void ShowFreeDialog() {
    TuiDialog Dialog;
    Dialog.Title = "Free memory";
    TuiField Base;
    Base.Label = "Base";
    Base.Value = Address_;
    Dialog.Fields.push_back(Base);
    Dialog.PrimaryLabel = "Free";
    Dialog.SecondaryLabel = "Cancel";
    Dialog.Validate = [](const TuiDialog &Current) -> std::string {
      if (Current.Fields.empty())
        return {};
      uint64_t Base = 0;
      if (!StorageUtil::ParseU64(Current.Fields[0].Value, &Base) || Base == 0)
        return "Enter a valid base address.";
      return {};
    };
    Dialog.OnSubmit = [this](TuiDialog &Submitted) {
      if (Submitted.Fields.empty())
        return;
      uint64_t Base = 0;
      StorageUtil::ParseU64(Submitted.Fields[0].Value, &Base);
      FreeRegion(Base);
    };
    Dialogs->Push(std::move(Dialog));
  }

  void FreeRegion(uint64_t Base) {
    ULONG ProcessId = 0;
    if (!ParsePidOnly(ProcessId))
      return;
    if (Base == 0) {
      Notify("Enter a valid base address.", NoticeKind::Warning);
      return;
    }
    if (OpsBusy_.exchange(true))
      return;
    TuiAsync<std::pair<bool, DWORD>>(
        [ProcessId, Base] {
          const bool Ok =
              KernelFreeMemory(ProcessId, static_cast<ULONG_PTR>(Base)) != FALSE;
          return std::pair<bool, DWORD>(
              Ok, Ok ? ERROR_SUCCESS : G_LastAegisCoreError);
        },
        [this, Base](std::pair<bool, DWORD> Result) {
          OpsBusy_ = false;
          if (!Result.first) {
            const std::string Message =
                "Free failed (error " + std::to_string(Result.second) + ").";
            OpsStatus_ = Message;
            Notify(Message, NoticeKind::Error);
            return;
          }
          const std::string Message =
              StorageUtil::Utf8(QString("Region at %1 released.")
                                    .arg(AegisNT::KernelResearch::Hex(Base)));
          OpsStatus_ = Message;
          Notify(Message, NoticeKind::Success);
          MarkMutated();
        });
  }

  int Index_ = 0;
  int Tab_ = 0;

  std::string Pid_;
  std::string Address_;
  std::string Size_ = "256";
  int Method_ = 0;

  std::string HexInput_;
  std::string PatternText_;
  QString DumpPathOverride_;

  std::vector<std::string> HexLines_;
  std::vector<std::string> AsciiLines_;

  std::string SuspectStatus_ =
      "Scans committed private executable regions (unbacked memory).";
  std::string ScanStatus_ =
      "Scans committed readable regions of the target process "
      "(max 1000 hits, 512 MiB).";
  std::string DumpStatus_ =
      "Dumps module memory through the kernel read path (max 64 MiB per dump).";
  std::string PteStatus_ =
      "Walks CR3 -> PML4E -> PDPTE -> PDE -> PTE for the address above "
      "(PID 0 = System).";
  std::string OpsStatus_ =
      "Kernel-mode region control: protection changes, allocation, and "
      "release in the target process (PID above).";

  TuiTable Physical_;
  TuiTable Suspect_;
  TuiTable Scan_;
  TuiTable Modules_;
  TuiTable Pte_;

  std::shared_ptr<AegisNT::KernelResearch::WriteTransaction> LastTransaction_;
  bool RollbackEnabled_ = false;

  std::atomic_bool Reading_{false};
  std::atomic_bool Writing_{false};
  std::atomic_bool Scanning_{false};
  std::atomic_bool LoadingPhysical_{false};
  std::atomic_bool LoadingModules_{false};
  std::atomic_bool Dumping_{false};
  std::atomic_bool Walking_{false};
  std::atomic_bool OpsBusy_{false};
};

std::unique_ptr<TuiPage> MakeMemoryPage(int Index) {
  return std::make_unique<MemoryPage>(Index);
}

} // namespace AegisNT::Tui
