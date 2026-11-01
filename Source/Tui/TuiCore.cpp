// ============================================================
// 控制台外壳：行式提示符、页面宿主、命令分派、退出与清理。
// ------------------------------------------------------------
// 两种入口共用同一套 shell：
//   - --console：进程内唯一的 Qt 对象是 QCoreApplication
//   - GUI 模式：作为第二前端运行在独立子进程里（自己的控制台窗口）
// 所有页面对象在首次访问时创建并常驻（与 GUI 的 StackedWidget 一致），
// 因此表格缓存与筛选都能保留。没有帧循环：只有输入线程与命令。
// ============================================================

#include "TuiCore.h"

#include "TuiAsync.h"
#include "TuiConsole.h"
#include "TuiPages.h"
#include "TuiSync.h"
#include "TuiText.h"
#include "TuiStyle.h"
#include "TuiSearch.h"
#include "TuiWidgets.h"

#include <QProcess>
#include <QProcessEnvironment>
#include <QSysInfo>
#include <algorithm>
#include <atomic>
#include <cctype>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>

namespace AegisNT::Tui {

std::function<void()> G_ConsoleVisibilityApplier;
std::function<void(bool)> G_ConsoleVisibleChanged;

namespace {

// Private inherited pipes carry session state; never passwords, argv tokens or
// files.
QByteArray SessionPacket() {
  QJsonObject Object{{"type", "session"},
                     {"version", 1},
                     {"loggedIn", Account.IsLoggedIn},
                     {"user", Account.UserName},
                     {"title", Account.Title},
                     {"userType", Account.UserType},
                     {"token", Account.IsLoggedIn ? Account.Token : QString()}};
  return QJsonDocument(Object).toJson(QJsonDocument::Compact) + '\n';
}

bool ApplySessionPacket(const QJsonObject &Object) {
  if (Object.value("type") != "session" ||
      Object.value("version").toInt() != 1 ||
      !Object.value("loggedIn").isBool() || !Object.value("user").isString() ||
      !Object.value("token").isString())
    return false;
  const bool LoggedIn = Object.value("loggedIn").toBool();
  const QString Token = Object.value("token").toString();
  if (LoggedIn &&
      (Token.isEmpty() || Object.value("user").toString().isEmpty()))
    return false;
  const QByteArray Before = SessionPacket();
  Account = {};
  Account.IsLoggedIn = LoggedIn;
  Account.UserName = Object.value("user").toString();
  Account.Title = Object.value("title").toString();
  Account.UserType = Object.value("userType").toInt();
  Account.Token = LoggedIn ? Token : QString();
  if (SessionPacket() != Before) {
    NotifyAccountSessionChanged();
    MarkMutated();
  }
  return true;
}

class ParentSessionPipe {
public:
  ~ParentSessionPipe() {
    if (Input_ != INVALID_HANDLE_VALUE)
      CloseHandle(Input_);
    if (Output_ != INVALID_HANDLE_VALUE)
      CloseHandle(Output_);
  }
  bool Attach() {
    const HANDLE Input = GetStdHandle(STD_INPUT_HANDLE);
    const HANDLE Output = GetStdHandle(STD_OUTPUT_HANDLE);
    if (GetFileType(Input) != FILE_TYPE_PIPE ||
        GetFileType(Output) != FILE_TYPE_PIPE)
      return false;
    const HANDLE Self = GetCurrentProcess();
    return DuplicateHandle(Self, Input, Self, &Input_, 0, FALSE,
                           DUPLICATE_SAME_ACCESS) &&
           DuplicateHandle(Self, Output, Self, &Output_, 0, FALSE,
                           DUPLICATE_SAME_ACCESS);
  }
  bool Poll() {
    DWORD Available = 0;
    if (!PeekNamedPipe(Input_, nullptr, 0, nullptr, &Available, nullptr))
      return false;
    if (Available) {
      if (Available + Buffer_.size() > 128 * 1024)
        return false;
      char Data[8192];
      DWORD Read = 0;
      if (!ReadFile(Input_, Data, std::min<DWORD>(Available, sizeof(Data)),
                    &Read, nullptr))
        return false;
      Buffer_.append(Data, Read);
    }
    while (Buffer_.contains('\n')) {
      const auto End = Buffer_.indexOf('\n');
      const auto Object = QJsonDocument::fromJson(Buffer_.left(End)).object();
      Buffer_.remove(0, End + 1);
      if (Object.value("type") == "close")
        return false;
      if (!ApplySessionPacket(Object))
        return false;
      Ready_ = true;
      LastSession_ = SessionPacket();
    }
    return true;
  }
  bool Ready() const { return Ready_; }
  void PublishChanges() {
    const auto Packet = SessionPacket();
    if (!Ready_ || Packet == LastSession_)
      return;
    LastSession_ = Packet;
    DWORD Written = 0;
    WriteFile(Output_, Packet.constData(), static_cast<DWORD>(Packet.size()),
              &Written, nullptr);
  }

private:
  HANDLE Input_ = INVALID_HANDLE_VALUE;
  HANDLE Output_ = INVALID_HANDLE_VALUE;
  QByteArray Buffer_, LastSession_;
  bool Ready_ = false;
};

bool ConsoleShuttingDown = false;

bool &IntegratedConsoleStopRequested() {
  static bool Requested = false;
  return Requested;
}

QProcess *IntegratedConsoleProcess() {
  static QProcess *Process = [] {
    auto *Created = new QProcess(qApp);
    Created->setProcessChannelMode(QProcess::SeparateChannels);
    QObject::connect(Created, &QProcess::started, Created,
                     [Created] { Created->write(SessionPacket()); });
    auto Buffer = std::make_shared<QByteArray>();
    QObject::connect(
        Created, &QProcess::readyReadStandardOutput, Created,
        [Created, Buffer] {
          Buffer->append(Created->readAllStandardOutput());
          if (Buffer->size() > 128 * 1024) {
            Buffer->clear();
            return;
          }
          while (Buffer->contains('\n')) {
            const auto End = Buffer->indexOf('\n');
            ApplySessionPacket(
                QJsonDocument::fromJson(Buffer->left(End)).object());
            Buffer->remove(0, End + 1);
          }
        });
    QObject::connect(Created, &QProcess::readyReadStandardError, Created,
                     [Created] {
                       Created->readAllStandardError(); // Drain without logging
                                                        // session payloads.
                     });
    const QPointer<QProcess> Guard(Created);
    AegisNT::ApplicationContext().AccountSessionListeners.push_back([Guard] {
      if (!Guard)
        return false;
      if (Guard->state() == QProcess::Running)
        Guard->write(SessionPacket());
      return true;
    });
    QObject::connect(qApp, &QCoreApplication::aboutToQuit, Created, [Created] {
      ConsoleShuttingDown = true;
      if (Created->state() != QProcess::NotRunning) {
        Created->kill();
        Created->waitForFinished(1500);
      }
    });
    QObject::connect(
        Created, qOverload<int, QProcess::ExitStatus>(&QProcess::finished),
        Created, [Created](int, QProcess::ExitStatus) {
          if (ConsoleShuttingDown)
            return;
          const bool WasRequested =
              std::exchange(IntegratedConsoleStopRequested(), false);
          const bool Wanted =
              ConfigurationValue("Application", "ConsoleVisible", false)
                  .toBool();
          if (WasRequested) {
            if (Wanted)
              QTimer::singleShot(0, qApp, [] { StartConsoleSurface(); });
            return;
          }
          if (!Wanted)
            return;
          // Closing the child console ends only this process. Keep
          // the GUI alive and mirror that close into Settings.
          SetConfigurationValue("Application", "ConsoleVisible", false);
          if (G_ConsoleVisibleChanged)
            G_ConsoleVisibleChanged(false);
          AppendConsoleOutput(
              "[*] Console window closed; GUI is still running.\n");
        });
    return Created;
  }();
  return Process;
}

bool StartIntegratedConsoleProcess() {
  QProcess *Process = IntegratedConsoleProcess();
  if (Process->state() != QProcess::NotRunning)
    return true;
  Process->setProgram(QCoreApplication::applicationFilePath());
  Process->setArguments(
      {QStringLiteral("--console"), QStringLiteral("--console-child")});
  Process->setCreateProcessArgumentsModifier(
      [](QProcess::CreateProcessArguments *Arguments) {
        Arguments->flags &= ~CREATE_NO_WINDOW;
        Arguments->flags |= CREATE_NEW_CONSOLE;
      });
  Process->start();
  if (!Process->waitForStarted(3000)) {
    SetConfigurationValue("Application", "ConsoleVisible", false);
    if (G_ConsoleVisibleChanged)
      G_ConsoleVisibleChanged(false);
    AppendConsoleOutput("[!] Failed to start the console front-end: " +
                        Process->errorString() + "\n");
    return false;
  }
  return true;
}

// ------------------------------------------------------------
// 输出助手（msfconsole 风格的 [+]/[-]/[!]/[*]）
// ------------------------------------------------------------

void Out(const std::string &Text) {
  WriteConsoleText(Text.data(), Text.size());
}

thread_local bool CommandFailed = false;
void Info(const std::string &Text) { WriteConsoleLine(NoticeText(Text, TuiTone::Accent)); }
void Good(const std::string &Text) { WriteConsoleLine(NoticeText(Text, TuiTone::Success)); }
void Warn(const std::string &Text) { WriteConsoleLine(NoticeText(Text, TuiTone::Warning)); }
void Bad(const std::string &Text) { CommandFailed = true; WriteConsoleLine(NoticeText(Text, TuiTone::Error)); }

// ------------------------------------------------------------
// 外壳状态
// ------------------------------------------------------------
struct ShellState {
  std::vector<std::string> NavEntries;
  std::vector<std::unique_ptr<TuiPage>> Pages;
  std::vector<bool> Created;
  TuiDialogStack Dialogs;
  std::string PageStatus;
  TuiTableView View;
  std::string ViewPrefix, ViewSuffix, ViewTitle;
  bool DisplayValid = false;
  bool LastOutputWasTable = false;
  bool QuitRequested = false;
  int Context = -1; // 当前 use 的页索引；-1 = 根提示符
};

ShellState &Shell() {
  static ShellState State;
  return State;
}

std::unique_ptr<TuiPage> &EnsurePage(int Index) {
  static std::unique_ptr<TuiPage> Fallback;
  ShellState &State = Shell();
  if (Index < 0 || Index >= static_cast<int>(State.Pages.size()))
    return Fallback;
  if (!State.Pages[static_cast<size_t>(Index)]) {
    if (PageFactory Factory = PageFactoryFor(Index)) {
      State.Pages[static_cast<size_t>(Index)] = Factory(Index);
      TuiPage *Page = State.Pages[static_cast<size_t>(Index)].get();
      Page->Dialogs = &State.Dialogs;
      Page->Commands = &Page->CommandsStorage();
      Page->Status = &State.PageStatus;
      Page->ReadOnlyMode =
          !Account.IsLoggedIn && PageRequiresAccountSession(Index);
      SetLastSeenGeneration(Index, SyncGeneration().load());
      State.Created[static_cast<size_t>(Index)] = true;
    }
  }
  return State.Pages[static_cast<size_t>(Index)];
}

// 当前页（必要时创建）。根提示符返回 nullptr。
TuiPage *CurrentPage() {
  ShellState &State = Shell();
  if (State.Context < 0)
    return nullptr;
  return EnsurePage(State.Context).get();
}

TerminalPromptContext CurrentPrompt() {
  TerminalPromptContext Context;
  Context.SignedIn = Account.IsLoggedIn;
  Context.Chinese = ActiveLanguage == "zh_CN";
  if (auto *Page = CurrentPage()) {
    Context.Page = Page->Title();
    Context.Path = Page->PromptLocationPath();
  }
  return Context;
}

void SwitchPage(int NewIndex) {
  ShellState &State = Shell();
  if (NewIndex < 0 || NewIndex >= static_cast<int>(State.NavEntries.size()))
    return;
  State.Context = NewIndex;
  State.PageStatus.clear();
  State.DisplayValid = false;
  if (TuiPage *Page = CurrentPage()) {
    Page->ReadOnlyMode =
        !Account.IsLoggedIn && PageRequiresAccountSession(NewIndex);
    Page->OnEnter(); // `use` 与 `refresh` 都靠它重新拉数据
    SetLastSeenGeneration(NewIndex, SyncGeneration().load());
  }
}

void InitializeShell() {
  ShellState &State = Shell();
  std::vector<std::string> Entries;
  for (const PageDefinition &Definition : AegisNT::PageDefinitions())
    Entries.push_back(
        TranslateText(QString::fromUtf8(Definition.Title)).toStdString());
  State.NavEntries = std::move(Entries);
  State.Pages.clear();
  State.Pages.resize(State.NavEntries.size());
  State.Created.assign(State.NavEntries.size(), false);
  State.QuitRequested = false;
  State.Context = -1;
  State.PageStatus.clear();
  State.DisplayValid = false;
  State.Dialogs = TuiDialogStack{};
}

void ShutdownShell() {
  ShellState &State = Shell();
  for (auto &Page : State.Pages)
    Page.reset();
}

// ------------------------------------------------------------
// 页面清单（根上下文 show / help / search / use 共用）
// ------------------------------------------------------------

TuiTable PageListTable(const std::vector<int> &Indices) {
  TuiTable Table;
  Table.Headers = {"#", "Page", "Access", "Description"};
  Table.RightAlign = {true, false, false};
  for (int Index : Indices) {
    const auto &Definition =
        AegisNT::PageDefinitions()[static_cast<size_t>(Index)];
    // Help must not instantiate pages: OnEnter can scan/load drivers or start
    // I/O.
    Table.Rows.push_back(TuiRow{
        {std::to_string(Index + 1), Definition.Title,
         PageRequiresAccountSession(Index) && !Account.IsLoggedIn ? "Sign in"
                                                                  : "Ready",
         TranslateText(QString::fromUtf8(Definition.Subtitle)).toStdString()},
        {}});
  }
  Table.Rebuild();
  return Table;
}

std::vector<int> AllPageIndices() {
  std::vector<int> Indices;
  for (int Index = 0; Index < static_cast<int>(Shell().NavEntries.size());
       ++Index)
    Indices.push_back(Index);
  return Indices;
}

// 按名称（不区分大小写）、前缀或 1 基序号解析页面。
int ResolvePageIndex(const std::string &Query) {
  const std::string Text = TrimAscii(Query);
  if (Text.empty())
    return -1;
  char *End = nullptr;
  const long Number = std::strtol(Text.c_str(), &End, 10);
  if (End != Text.c_str() && End != nullptr && *End == '\0') {
    return Number >= 1 && Number <= static_cast<long>(Shell().NavEntries.size())
               ? static_cast<int>(Number - 1)
               : -1;
  }
  const std::string Needle = LowerAscii(Text);
  const auto &Entries = Shell().NavEntries;
  for (size_t Index = 0; Index < Entries.size(); ++Index)
    if (LowerAscii(Entries[Index]) == Needle ||
        LowerAscii(AegisNT::PageDefinitions()[Index].Title) == Needle)
      return static_cast<int>(Index);
  int Match = -1;
  for (size_t Index = 0; Index < Entries.size(); ++Index) {
    if (LowerAscii(Entries[Index]).find(Needle) != std::string::npos ||
        LowerAscii(AegisNT::PageDefinitions()[Index].Title).find(Needle) !=
            std::string::npos) {
      if (Match >= 0)
        return -2; // Never silently enter a different page.
      Match = static_cast<int>(Index);
    }
  }
  return Match;
}

// ------------------------------------------------------------
// 内置命令
// ------------------------------------------------------------

struct BuiltinHelp {
  const char *Name;
  const char *Usage;
  const char *Chinese;
  int Group;
};
const BuiltinHelp kBuiltins[] = {
    {"pages", "pages                  browse available pages", "pages                  浏览全部页面", 0},
    {"use", "use <page>             enter by name or number", "use <page>             按名称或序号进入页面", 0},
    {"back", "back                   return home", "back                   返回主提示符", 0},
    {"search", "search <text>          search page names", "search <text>          搜索页面", 0},
    {"show", "show [n|all|first|last]  view snapshot / page / rows", "show [n|all|first|last]  显示快照、指定页、首末页或全部行", 1},
    {"ls", "ls [path]              display; File reloads directory", "ls [path]              显示；File 页重新列目录", 1},
    {"list", "list [path]            alias of ls", "list [path]            ls 的别名", 1},
    {"dir", "dir [path]             alias of ls", "dir [path]             ls 的别名", 1},
    {"next-page", "next-page | n          next 20 rows (PageUp)", "next-page | n          下一页（20 条，PageUp）", 1},
    {"prev-page", "prev-page | p          previous 20 rows (PageDown)", "prev-page | p          上一页（20 条，PageDown）", 1},
    {"detail", "detail <n>             full fields from snapshot row n", "detail <n>             查看快照中第 n 行完整字段", 1},
    {"filter", "filter [text]          filter; empty text clears", "filter [text]          筛选；无参数清除筛选", 1},
    {"find", "find [-n] <text>       find text; show row numbers and highlights", "find [-n] <text>       查找文本，显示行号与高亮", 1},
    {"grep", "grep [-n] <text>       alias of find (literal, ignores case)", "grep [-n] <text>       find 的别名（字面匹配，忽略大小写）", 1},
    {"findstr", "findstr [-n] <text>    alias of find", "findstr [-n] <text>    find 的别名", 1},
    {"|", "show | find \"text\"    search full snapshot; pipes can be chained", "show | find \"text\"    查找完整快照；可串联多个管道", 1},
    {"refresh", "refresh                reload data; return to page 1", "refresh                重新加载并回到第一页", 1},
    {"login", "login                  sign in", "login                  登录", 2},
    {"logout", "logout                 sign out and clear saved credentials", "logout                 注销并清除保存的凭证", 2},
    {"whoami", "whoami                 current session", "whoami                 查看当前身份", 2},
    {"clear", "clear                  clear screen (Ctrl+L also works)", "clear                  清屏（也可使用 Ctrl+L）", 2},
    {"history", "history                recent input lines", "history                最近的输入历史", 2},
    {"version", "version                application version", "version                版本信息", 2},
    {"exit", "exit | quit            close terminal", "exit | quit            退出终端", 2},
    {"help", "help [command|all]     focused / complete help", "help [command|all]     指定命令帮助或完整帮助", 2},
    {"run", "run <command> [args]   explicitly invoke page command", "run <command> [args]   显式执行页面命令", 3},
};
void PrintHelpLine(const std::string &Text) {
  for (const auto &Line : WrapText(Text, TerminalColumns() - 1, "  "))
    WriteConsoleLine(Paint(Line, TuiTone::Muted));
}
// Command column in accent, description in gray; continuation lines stay gray.
void PrintUsageLine(const std::string &Text) {
  const auto Lines = WrapText(Text, TerminalColumns() - 1, "  ");
  for (size_t I = 0; I < Lines.size(); ++I) {
    if (I || Lines[I].size() <= 2) {
      WriteConsoleLine(Paint(Lines[I], TuiTone::Muted));
      continue;
    }
    const std::string Body = Lines[I].substr(2);
    const size_t Split = Body.find("  ");
    if (Split == std::string::npos) {
      WriteConsoleLine(Paint(Lines[I], TuiTone::Muted));
      continue;
    }
    const auto Usage = Body.substr(0, Split);
    const auto Space = Usage.find(' ');
    WriteConsoleLine("  " + Paint(Usage.substr(0, Space), TuiTone::Accent) +
        (Space == std::string::npos ? std::string() : Paint(Usage.substr(Space), TuiTone::Parameter)) +
        Paint(Body.substr(Split), TuiTone::Muted));
  }
}
void PrintCommonHelp(bool All) {
  const char *En[] = {"Navigation", "Display", "Session", "Page actions"};
  const char *Zh[] = {"导航", "查看", "会话", "页面操作"};
  for (int Group = 0; Group < 4; ++Group) {
    Out(SectionHeading(UiText(En[Group], Zh[Group])));
    for (const auto &Entry : kBuiltins) {
      if (Entry.Group != Group) continue;
      const std::string Name = Entry.Name;
      if (!All && (Name == "list" || Name == "dir" || Name == "grep" || Name == "findstr" || Name == "version" ||
                   Name == "search" || Name == "whoami")) continue;
      PrintUsageLine(UiText(Entry.Usage, Entry.Chinese));
    }
  }
}
void PrintPageHelp(TuiPage &Page, bool All = false) {
  PrintCommonHelp(All);
  Out(SectionHeading(Page.Title() + UiText(" / commands", " / 页面命令")));
  const auto &Commands = Page.CommandsStorage();
  const size_t Count = All ? Commands.size() : std::min<size_t>(Commands.size(), 8);
  for (size_t I = 0; I < Count; ++I) PrintUsageLine(Commands[I].Usage);
  if (Count < Commands.size())
    PrintHelpLine(UiText("More page actions: help all; usage: help <command>.",
                        "更多页面操作：help all；指定命令用法：help <command>。"));
}
void PrintRootHelp(bool All = false) {
  PrintCommonHelp(All);
  PrintHelpLine(UiText("Use pages to browse tools; use File to start browsing files.",
                      "输入 pages 浏览工具；输入 use File 开始浏览文件。"));
  PrintHelpLine(UiText(
      "Copy: drag to select text, then Enter or Ctrl+Shift+C (right-click pastes); \"| copy\" sends output straight to the clipboard.",
      "复制：拖选文本后按 Enter 或 Ctrl+Shift+C（右键粘贴）；\"| copy\" 可把输出直接送入剪贴板。"));
}
void PrintPageFragment(const std::string &Text) {
  size_t Start = 0;
  while (Start < Text.size()) {
    const size_t End = Text.find('\n', Start);
    const auto Line = Text.substr(Start, End == std::string::npos ? End : End - Start);
    for (const auto &Wrapped : TerminalWrapStyled(Line, TerminalColumns() - 1))
      WriteConsoleLine(Wrapped);
    if (End == std::string::npos) break;
    Start = End + 1;
  }
}
void PrintSnapshot() {
  auto &State = Shell();
  State.LastOutputWasTable = State.View.Valid;
  Out(SectionHeading(State.ViewTitle));
  PrintPageFragment(State.ViewPrefix);
  if (State.View.Valid) Out(State.View.Render());
  PrintPageFragment(State.ViewSuffix);
}

void PrintPageText(TuiPage &Page) {
  auto &State = Shell();
  State.DisplayValid = false;
  State.View = {};
  TerminalChinese = ActiveLanguage == "zh_CN";
  QElapsedTimer Budget;
  Budget.start();
  QTimer Loading;
  Loading.setSingleShot(true);
  QObject::connect(&Loading, &QTimer::timeout, [&] {
    WriteConsoleFeedback(NoticeText(UiText("Loading data...", "正在加载数据…"), TuiTone::Muted));
  });
  Loading.start(300);
  const auto Wait = [&] {
    return WaitForTuiTasks(std::max(0, 10000 - static_cast<int>(Budget.elapsed())));
  };
  if (!Wait()) {
    ConsoleOutputCapture::MarkFailed();
    Warn(UiText("Still loading. Run show again later.", "仍在加载，请稍后再次执行 show。"));
    return;
  }
  std::string Text;
  const auto Render = [&] {
    TuiTableCapture Capture(Page.ActiveTable());
    Text = Page.RenderText();
    State.View = std::move(Capture.View);
  };
  Render();
  if (TuiBusy()) {
    if (!Wait()) {
      ConsoleOutputCapture::MarkFailed();
      Warn(UiText("Still loading. Run show again later.", "仍在加载，请稍后再次执行 show。"));
      return;
    }
    Render();
  }
  Loading.stop();
  State.ViewTitle = Page.Title();
  const auto Marker = Text.find(TuiTableCapture::Marker);
  State.ViewPrefix = Marker == std::string::npos ? Text : Text.substr(0, Marker);
  State.ViewSuffix = Marker == std::string::npos ? "" : Text.substr(Marker + std::strlen(TuiTableCapture::Marker));
  if (Marker == std::string::npos) State.View.Valid = false;
  State.DisplayValid = true;
  PrintSnapshot();
  if (Text.empty()) Info(UiText("No display data. Type help for commands.", "暂无展示内容，输入 help 查看命令。"));
  if (Budget.elapsed() >= 300)
    WriteConsoleFeedback(NoticeText(UiText("Loaded in ", "加载耗时 ") + std::to_string(Budget.elapsed()) + " ms", TuiTone::Muted));
  if (Page.ReadOnlyMode) Warn(UiText("Read-only: sign in to change this page.", "只读状态：登录后可修改此页。"));
}
void RunShow(const std::string &Argument = {}) {
  auto &State = Shell();
  if (State.Context < 0) {
    if (!Argument.empty()) Bad(UiText("Paging requires a page: use <page>.", "请先用 use <page> 进入页面再翻页。"));
    else Out(TuiTableToText(PageListTable(AllPageIndices()), 0));
    return;
  }
  const std::string Requested = LowerAscii(TrimAscii(Argument));
  if (!State.DisplayValid) {
    if (auto *Page = CurrentPage()) { Page->OnTick(NowMs()); PrintPageText(*Page); }
    if (Requested.empty() || !State.DisplayValid) return;
  }
  if (!Requested.empty()) {
    if (!State.View.Valid) {
      Bad(UiText("This view has no active table to paginate.", "此视图没有可分页的活动表格。"));
      return;
    }
    if (Requested == "all") State.View.All = true;
    else if (Requested == "first")
      State.View.SetPage(1);
    else if (Requested == "last")
      State.View.SetPage(State.View.PageCount());
    else {
      char *End = nullptr;
      const long Number = std::strtol(Requested.c_str(), &End, 10);
      if (End == Requested.c_str() || *End || Number < 1 || Number > State.View.PageCount() ||
          !State.View.SetPage(static_cast<int>(Number))) {
        Bad(UiText("Page must be in 1..", "页码范围：1..") + std::to_string(State.View.PageCount()));
        return;
      }
    }
  }
  PrintSnapshot();
}
void RunDetail(const std::string &Argument) {
  auto &State = Shell();
  if (!CurrentPage()) { Bad(UiText("Use a page before detail.", "请先进入页面再查看详情。")); return; }
  if (!State.DisplayValid) PrintPageText(*CurrentPage());
  if (!State.View.Valid) { Bad(UiText("This view has no active table.", "此视图没有活动表格。")); return; }
  const std::string Text = TrimAscii(Argument);
  char *End = nullptr;
  const long Number = std::strtol(Text.c_str(), &End, 10);
  if (End == Text.c_str() || *End || Number < 1 || Number > static_cast<long>(State.View.Snapshot.Visible.size())) {
    Bad(UiText("detail: valid rows 1..", "detail：有效行号 1..") + std::to_string(State.View.Snapshot.Visible.size()));
    return;
  }
  if (const auto *Row = State.View.RowAt(static_cast<int>(Number))) {
    Out(SectionHeading(UiText("Details #", "详情 #") + std::to_string(Number)));
    ShowSelectedRowDetails(State.View.Snapshot, *Row);
  }
}
void RunFilter(const std::string &Argument) {
  auto *Page = CurrentPage();
  if (!Page) { Bad(UiText("Use a page before filter.", "请先进入页面再筛选。")); return; }
  Page->Filter = TrimAscii(Argument);
  PrintPageText(*Page);
  if (!Page->ActiveTable()) Bad(UiText("This page has no table.", "此页没有表格。"));
}

std::vector<TerminalSearchLine> SnapshotSearchLines(const TuiTableView &View) {
  std::vector<TerminalSearchLine> Lines;
  for (size_t I = 0; I < View.Snapshot.Visible.size(); ++I) {
    const auto *Row = View.RowAt(static_cast<int>(I + 1));
    if (!Row) continue;
    TerminalSearchLine Line{I + 1, {}};
    const size_t Start = !View.Snapshot.Headers.empty() && View.Snapshot.Headers.front() == "#" ? 1 : 0;
    for (size_t C = Start; C < Row->Cells.size(); ++C) {
      if (C > Start) { Line.Text += "  |  "; Line.Spans.push_back({"  |  ", ToneInk(TuiTone::Muted)}); }
      const auto Text = TerminalClean(Row->Cells[C]);
      Line.Text += Text;
      Line.Spans.push_back({Text, TuiCellInk(View.Snapshot, *Row, C)});
    }
    Lines.push_back(std::move(Line));
  }
  return Lines;
}
bool ParseFindQuery(const std::vector<std::string> &Args, std::string &Query) {
  Query.clear();
  size_t Start = 1;
  bool Literal = false;
  for (; Start < Args.size(); ++Start) {
    if (!Literal && Args[Start] == "--") { Literal = true; ++Start; break; }
    if (Args[Start] == "-n" || Args[Start] == "-i" || Args[Start] == "/n" || Args[Start] == "/i") continue;
    if (!Literal && Args[Start].size() > 1 && Args[Start][0] == '-') {
      Bad(UiText("find supports -n/-i; use -- before text starting with '-'.", "find 支持 -n/-i；以 '-' 开头的文本请放在 -- 后。")); return false;
    }
    break;
  }
  for (size_t I = Start; I < Args.size(); ++I) { if (I > Start) Query += ' '; Query += Args[I]; }
  if (!Query.empty()) return true;
  Bad(UiText("Usage: find <text> or show | find \"text\" (literal, case-insensitive).",
             "用法：find <文本> 或 show | find \"文本\"（字面匹配，忽略大小写）。"));
  return false;
}
void PrintFindResults(const std::vector<TerminalSearchLine> &Lines,
                      const std::vector<std::string> &Queries, bool TableRows) {
  const auto Matches = TerminalFindLines(Lines, Queries);
  const int Columns = TerminalColumns();
  std::string Title = UiText("Find", "查找");
  for (const auto &Query : Queries) Title += " / " + TerminalClean(Query);
  Out(SectionHeading(Title));
  for (const auto &Match : Matches) {
    const auto Prefix = "  " + std::to_string(Match.Number) + ": ";
    const auto Wrapped = TerminalWrapStyled(HighlightSearchLine(Match, Queries), Columns - 1 - TerminalWidth(Prefix));
    for (size_t I = 0; I < Wrapped.size(); ++I)
      WriteConsoleLine((I == 0 ? Paint(Prefix, TuiTone::Accent) : std::string(TerminalWidth(Prefix), ' ')) +
                       Wrapped[I]);
  }
  if (Matches.empty()) PrintHelpLine(UiText("No matching text.", "没有匹配文本。"));
  PrintHelpLine(std::to_string(Matches.size()) + UiText(" matched / ", " 行匹配 / ") +
      std::to_string(Lines.size()) + UiText(" searched", " 行已搜索") +
      (TableRows ? UiText("  |  snapshot row numbers; detail <n>", "  |  快照行号；detail <n> 查看详情")
                 : UiText("  |  output line numbers", "  |  输出文本行号")));
}
void RunFind(const std::vector<std::string> &Args) {
  std::string Query;
  if (!ParseFindQuery(Args, Query)) return;
  auto &State = Shell();
  if (!State.DisplayValid) {
    if (auto *Page = CurrentPage()) {
      ConsoleOutputCapture Capture;
      PrintPageText(*Page);
    }
  }
  if (!State.DisplayValid || !CurrentPage()) {
    Bad(UiText("No page snapshot. Use a page, or try pages | find <text>.", "暂无页面快照。请先进入页面，或使用 pages | find <文本>。")); return;
  }
  PrintFindResults(State.View.Valid ? SnapshotSearchLines(State.View)
      : TerminalTextLines(State.ViewPrefix + State.ViewSuffix), {Query}, State.View.Valid);
}

void RunSearch(const std::string &Argument) {
  const std::string Needle = LowerAscii(TrimAscii(Argument));
  if (Needle.empty()) {
    Bad(UiText("Usage: search <text>", "用法：search <文本>"));
    return;
  }
  std::vector<int> Matches;
  for (int Index : AllPageIndices())
    if (LowerAscii(Shell().NavEntries[static_cast<size_t>(Index)])
                .find(Needle) != std::string::npos ||
        LowerAscii(AegisNT::PageDefinitions()[static_cast<size_t>(Index)].Title)
                .find(Needle) != std::string::npos)
      Matches.push_back(Index);
  if (Matches.empty()) {
    Bad(UiText("No page matches: ", "没有匹配页面：") + TrimAscii(Argument));
    return;
  }
  Out(TuiTableToText(PageListTable(Matches), 0));
}

void RunUse(const std::string &Argument) {
  const int Index = ResolvePageIndex(Argument);
  if (Index == -2) {
    Warn(UiText("Ambiguous page name. Choose a full name or number:", "页面名称不唯一，请输入完整名称或序号："));
    RunSearch(Argument);
    return;
  }
  if (Index < 0) {
    Bad(UiText("Unknown page: ", "未知页面：") + TrimAscii(Argument));
    return;
  }
  if (PageRequiresAccountSession(Index) && !Account.IsLoggedIn) {
    Warn(UiText("This page requires sign-in. Type 'login'; local tools remain available.", "此页需要登录，请输入 login；本地工具仍可使用。"));
    return;
  }
  SwitchPage(Index);
  TuiPage *Page = CurrentPage();
  if (Page) PrintPageText(*Page);
}

void RunLogin() {
  if (Account.IsLoggedIn) {
    Info(UiText("Already signed in as ", "当前已登录：") + Account.UserName.toStdString());
    return;
  }
  if (!RunConsoleLoginGate(false)) {
    Info(UiText("Sign-in cancelled; session unchanged.", "已取消登录，会话保持不变。"));
    return;
  }
  if (Account.IsLoggedIn)
    Good(UiText("Signed in as ", "已登录：") + Account.UserName.toStdString());
}

void RunLogout() {
  if (!Account.IsLoggedIn) {
    Info(UiText("Not signed in", "当前未登录"));
    return;
  }
  HandleLogout();
  MarkMutated();
  if (PageRequiresAccountSession(Shell().Context))
    Shell().Context = -1;
  Good(UiText("Logged out. Continuing as guest; saved sign-in credentials cleared.", "已注销并清除保存凭证，继续使用访客会话。"));
}

// 页面命令：只在页上下文中查找。
bool RunPageCommand(const std::string &Line, std::vector<std::string> &Args) {
  TuiPage *Page = CurrentPage();
  if (!Page)
    return false;
  if (PageRequiresAccountSession(Shell().Context) && !Account.IsLoggedIn) {
    Warn(UiText("Sign in with 'login' to use Account and Chat.", "输入 login 登录后可使用 Account 和 Chat。"));
    return true;
  }
  const std::string Name = LowerAscii(Args.front());
  for (const TuiCommand &Command : Page->CommandsStorage()) {
    if (LowerAscii(Command.Name) != Name)
      continue;
    // Copy before calling: handlers can rebuild the command registry.
    const auto Handler = Command.Handler;
    std::vector<std::string> Rest(Args.begin() + 1, Args.end());
    (void)Line;
    if (Handler) {
      Page->SetStatus("executed: " + Name);
      Handler(std::move(Rest));
      PrintPageText(*Page);
    }
    return true;
  }
  return false;
}

// Memory-only input history lives with the reader; defined below Reader().
std::vector<std::string> &InputHistory();

// Closest known command for a typo ("did you mean"); "" when nothing is close.
std::string SuggestCommand(const std::string &Name) {
  if (Name.size() < 3 || Name.size() > 24)
    return {};
  const auto Levenshtein = [](const std::string &A, const std::string &B) {
    std::vector<size_t> Row(B.size() + 1);
    for (size_t J = 0; J <= B.size(); ++J) Row[J] = J;
    for (size_t I = 1; I <= A.size(); ++I) {
      size_t Corner = Row[0];
      Row[0] = I;
      for (size_t J = 1; J <= B.size(); ++J) {
        const size_t Above = Row[J];
        Row[J] = std::min({Row[J] + 1, Row[J - 1] + 1,
                           Corner + (A[I - 1] == B[J - 1] ? 0 : 1)});
        Corner = Above;
      }
    }
    return Row[B.size()];
  };
  std::vector<std::string> Candidates;
  for (const auto &Entry : kBuiltins)
    if (std::string(Entry.Name) != "|")
      Candidates.push_back(Entry.Name);
  if (auto *Page = CurrentPage())
    for (const auto &Command : Page->CommandsStorage())
      Candidates.push_back(Command.Name);
  size_t Best = std::string::npos;
  std::string Suggestion;
  for (const auto &Candidate : Candidates) {
    const size_t Distance = Levenshtein(Name, Candidate);
    if (Distance < Best ||
        (Distance == Best && Candidate.size() < Suggestion.size())) {
      Best = Distance;
      Suggestion = Candidate;
    }
  }
  const size_t Limit = Name.size() <= 5 ? 1 : 2;
  return Best <= Limit ? Suggestion : std::string();
}

// ------------------------------------------------------------
// 行分派（仅主线程）
// ------------------------------------------------------------

void ExecuteSingleLine(const std::string &Line) {
  // A GUI logout can revoke the inherited session between commands.
  if (PageRequiresAccountSession(Shell().Context) && !Account.IsLoggedIn)
    Shell().Context = -1;
  const std::string Text = TrimAscii(Line);
  if (Text.empty())
    return;

  std::vector<std::string> Args;
  std::string Error;
  if (!ParseCommandLine(Text, Args, Error)) {
    Bad(Error);
    return;
  }
  if (Args.empty())
    return;

  const std::string Name = LowerAscii(Args.front());
  std::string Rest;
  for (size_t I = 1; I < Args.size(); ++I) {
    if (I > 1)
      Rest += ' ';
    Rest += Args[I];
  }

  if (Name == "help" || Name == "?") {
    const auto Query = LowerAscii(TrimAscii(Rest));
    auto *Page = CurrentPage();
    if (Query.empty() || Query == "all") {
      if (Page) PrintPageHelp(*Page, Query == "all"); else PrintRootHelp(Query == "all");
      return;
    }
    if (Page)
      for (const auto &Command : Page->CommandsStorage())
        if (LowerAscii(Command.Name) == Query) { PrintHelpLine(Command.Usage); return; }
    for (const auto &Entry : kBuiltins)
      if (Entry.Name == Query) { PrintHelpLine(UiText(Entry.Usage, Entry.Chinese)); return; }
    const int Index = ResolvePageIndex(Rest);
    if (Index >= 0) {
      if (PageRequiresAccountSession(Index) && !Account.IsLoggedIn)
        Warn(UiText("Sign in with login to use this page.", "此页需要登录，请使用 login。"));
      else if (auto &Slot = EnsurePage(Index)) PrintPageHelp(*Slot);
    } else Warn(UiText("Unknown command: ", "未知命令：") + Rest);
    return;
  }
  if (Name == "cd" && RunPageCommand(Text, Args))
    return;
  if (Name == "use" || Name == "cd") {
    RunUse(Rest);
    return;
  }
  if (Name == "back" || Name == "..") {
    if (Shell().Context < 0) {
      Info(UiText("Already at the root prompt", "当前已在主提示符"));
      return;
    }
    Shell().Context = -1;
    Shell().PageStatus.clear();
    Shell().DisplayValid = false;
    Info(UiText("Back to root", "已返回主提示符"));
    return;
  }
  if (Name == "pages") {
    Out(TuiTableToText(PageListTable(AllPageIndices()), 0));
    return;
  }
  if (Name == "whoami") {
    Info(Account.IsLoggedIn
             ? UiText("Signed in as ", "已登录：") + Account.UserName.toStdString()
             : UiText("Guest (local tools available; Account and Chat require login)", "访客（本地工具可用；Account 和 Chat 需要登录）"));
    return;
  }
  if (Name == "show" || Name == "ls" || Name == "list" || Name == "dir") {
    if (Name != "show" && RunPageCommand(Text, Args))
      return;
    RunShow(Rest);
    return;
  }
  if (Name == "next-page" || Name == "prev-page") {
    if (!Rest.empty()) { Bad(UiText("Paging commands take no arguments.", "翻页命令不接受参数。")); return; }
    if (!Shell().DisplayValid || !Shell().View.Valid) {
      Bad(UiText("No table snapshot. Use a page and show first.", "暂无表格快照，请先进入页面并执行 show。")); return;
    }
    RunShow(std::to_string(Shell().View.Page + (Name == "next-page" ? 1 : -1)));
    return;
  }
  if (Name == "detail") {
    RunDetail(Rest);
    return;
  }
  if (Name == "filter") {
    RunFilter(Rest);
    return;
  }
  if (Name == "find" || Name == "grep" || Name == "findstr") {
    RunFind(Args);
    return;
  }
  if (Name == "refresh") {
    if (RunPageCommand(Text, Args))
      return;
    TuiPage *Page = CurrentPage();
    if (!Page) {
      Bad(UiText("refresh is only available inside a page (use <page>)", "请先 use <page> 进入页面再执行 refresh。"));
      return;
    }
    Page->OnEnter();
    SetLastSeenGeneration(Shell().Context, SyncGeneration().load());
    PrintPageText(*Page);
    return;
  }
  if (Name == "search") {
    RunSearch(Rest);
    return;
  }
  if (Name == "login") {
    RunLogin();
    return;
  }
  if (Name == "logout") {
    RunLogout();
    return;
  }
  if (Name == "clear") {
    ClearConsoleScreen(); // Viewport only; scrollback stays selectable.
    return;
  }
  if (Name == "cls") {
    ClearConsoleBuffer(); // Explicit full wipe including scrollback.
    return;
  }
  if (Name == "history") {
    const auto &History = InputHistory();
    if (History.empty()) {
      Info(UiText("No input history yet.", "暂无输入历史。"));
      return;
    }
    const size_t Begin = History.size() > 20 ? History.size() - 20 : 0;
    for (size_t I = Begin; I < History.size(); ++I)
      WriteConsoleLine("  " + Paint(std::to_string(I + 1), TuiTone::Muted) +
                       "  " + TerminalClean(History[I]));
    return;
  }
  if (Name == "version") {
    WriteConsoleLine("AegisNT " + KApplicationVersion.toStdString());
    return;
  }
  if (Name == "exit" || Name == "quit") {
    Shell().QuitRequested = true;
    return;
  }
  if (Name == "run") {
    std::vector<std::string> PageArgs(Args.begin() + 1, Args.end());
    if (PageArgs.empty() || !RunPageCommand(Rest, PageArgs))
      Bad(UiText("Usage: run <page-command> [args] (type 'help' inside a page)", "用法：run <页面命令> [参数]，在页内输入 help 查看命令。"));
    return;
  }
  if (Shell().Context < 0 && Args.size() == 1 &&
      std::all_of(
          Name.begin(), Name.end(),
          [](unsigned char C) { return std::isdigit(C); })) {
    RunUse(Name);
    return;
  }
  if (RunPageCommand(Text, Args))
    return;
  // Single-key page turns inside a page ("n"ext / "p"revious); page commands
  // above win if a page ever registers those names.
  if (Shell().Context >= 0 && Rest.empty() && (Name == "n" || Name == "p")) {
    if (!Shell().DisplayValid || !Shell().View.Valid) {
      Bad(UiText("No table snapshot. Use a page and show first.",
                 "暂无表格快照，请先进入页面并执行 show。"));
      return;
    }
    RunShow(std::to_string(Shell().View.Page + (Name == "n" ? 1 : -1)));
    return;
  }
  if (Shell().Context < 0) {
    // Root prompt: a bare page name ("File", "kernel research") enters the
    // page directly; pages are tried after every builtin and page command.
    if (ResolvePageIndex(Text) >= 0) {
      RunUse(Text);
      return;
    }
  }
  const std::string Suggestion = SuggestCommand(Name);
  if (!Suggestion.empty() && Suggestion != Name)
    Bad(UiText("Unknown command: ", "未知命令：") + Name +
        UiText(" (did you mean '", "（你是想输入 '") + Suggestion +
        UiText("'?)", "'？）"));
  else
    Bad(UiText("Unknown command: ", "未知命令：") + Name +
        UiText(" (type help)", "（输入 help 查看帮助）"));
}

void ExecuteLineImpl(const std::string &Line) {
  if (TrimAscii(Line).empty()) return;
  std::vector<std::string> Parts;
  std::string Error;
  if (!SplitTerminalPipeline(Line, Parts, Error)) { Bad(Error); return; }
  if (Parts.size() == 1) { ExecuteSingleLine(Line); return; }
  std::vector<std::string> Source;
  if (!ParseCommandLine(Parts.front(), Source, Error) || Source.empty()) { Bad(Error); return; }
  const auto Name = LowerAscii(Source.front());
  const std::vector<std::string> Producers = {"show", "ls", "list", "dir", "pages", "detail", "help", "?", "search", "pwd", "version", "whoami"};
  if (std::find(Producers.begin(), Producers.end(), Name) == Producers.end()) {
    Bad(UiText("Pipe source: show, ls/list/dir, pages, detail, help, search, pwd, version, whoami.",
               "管道来源支持：show、ls/list/dir、pages、detail、help、search、pwd、version、whoami。")); return;
  }
  // Validate the entire pipeline before running even the first page command.
  std::vector<std::string> Queries;
  bool CopyStage = false;
  for (size_t I = 1; I < Parts.size(); ++I) {
    std::vector<std::string> Args;
    if (!ParseCommandLine(Parts[I], Args, Error) || Args.empty()) { Bad(Error); return; }
    const auto Filter = LowerAscii(Args.front());
    if (Filter == "copy") {
      if (I + 1 != Parts.size() || Args.size() > 1) {
        Bad(UiText("copy must be the last pipeline stage without arguments.", "copy 必须是管道最后一段且不带参数。")); return;
      }
      CopyStage = true;
      continue;
    }
    if (Filter != "find" && Filter != "grep" && Filter != "findstr") {
      Bad(UiText("After | use find, grep, findstr or copy.", "管道 | 后请使用 find、grep、findstr 或 copy。")); return;
    }
    std::string Query;
    if (!ParseFindQuery(Args, Query)) return;
    Queries.push_back(std::move(Query));
  }
  auto &State = Shell();
  State.LastOutputWasTable = false;
  CommandFailed = false;
  std::string Captured;
  bool Failed = false;
  {
    ConsoleOutputCapture Capture;
    ExecuteSingleLine(Parts.front());
    Failed = Capture.Failed;
    Captured = std::move(Capture.Text);
  }
  if (CommandFailed || Failed) { Out(Captured); return; }
  const bool TableRows = State.LastOutputWasTable && State.View.Valid &&
      (Name == "show" || Name == "ls" || Name == "list" || Name == "dir");
  if (CopyStage) {
    // Copy the pipeline result instead of printing it: the full output without
    // a filter, otherwise one original line per match (no row numbers).
    std::string Payload;
    if (Queries.empty()) {
      Payload = TerminalPlain(Captured);
    } else {
      const auto Matches = TerminalFindLines(
          TableRows ? SnapshotSearchLines(State.View) : TerminalTextLines(Captured), Queries);
      for (size_t I = 0; I < Matches.size(); ++I) {
        if (I) Payload += '\n';
        Payload += Matches[I].Text;
      }
    }
    while (!Payload.empty() && Payload.back() == '\n')
      Payload.pop_back();
    if (Payload.empty()) {
      Info(UiText("Nothing to copy.", "没有可复制的内容。"));
      return;
    }
    TuiClipboard::Set(Payload);
    Good(UiText("Copied ", "已复制 ") +
         std::to_string(1 + static_cast<int>(std::count(Payload.begin(), Payload.end(), '\n'))) +
         UiText(" lines to the clipboard (", " 行到剪贴板（") +
         std::to_string(Payload.size()) + UiText(" bytes).", " 字节）。"));
    return;
  }
  PrintFindResults(TableRows ? SnapshotSearchLines(State.View) : TerminalTextLines(Captured), Queries, TableRows);
}

// ------------------------------------------------------------
// 输入线程与提示协议
// ------------------------------------------------------------

// The input worker never touches Qt pages or account state. The main thread
// publishes a prompt/completion snapshot after each command. Commands are
// queued (not BlockingQueuedConnection), so quitting cannot strand a worker.
struct ConsoleReaderState {
  std::mutex Mutex;
  std::condition_variable Changed;
  bool Stop = false;
  bool Paused = false;
  bool Reading = false;
  bool Dispatching = false;
  TerminalPromptContext Prompt;
  std::vector<std::string> Completions;
  std::vector<std::string>
      History; // Memory-only; commands, never form/password input.
  std::thread Thread;
};

ConsoleReaderState &Reader() {
  static ConsoleReaderState State;
  return State;
}

std::vector<std::string> &InputHistory() { return Reader().History; }

std::atomic_bool &InputRunning() {
  static std::atomic_bool Running{false};
  return Running;
}

void UpdateConsolePrompt() {
  TerminalChinese = ActiveLanguage == "zh_CN";
  if (PageRequiresAccountSession(Shell().Context) && !Account.IsLoggedIn)
    Shell().Context = -1;
  for (size_t I = 0; I < Shell().Pages.size(); ++I)
    if (Shell().Pages[I])
      Shell().Pages[I]->ReadOnlyMode =
          !Account.IsLoggedIn &&
          PageRequiresAccountSession(static_cast<int>(I));
  std::vector<std::string> Completions;
  for (const auto &Entry : kBuiltins)
    if (std::string(Entry.Name) != "|") {
      Completions.emplace_back(Entry.Name);
      Completions.emplace_back(std::string("help ") + Entry.Name);
    }
  for (const auto &Page : AegisNT::PageDefinitions()) {
    Completions.emplace_back(std::string("use ") + Page.Title);
    Completions.emplace_back(std::string("help ") + Page.Title);
  }
  Completions.emplace_back("show all");
  Completions.emplace_back("help all");
  if (auto *Page = CurrentPage()) {
    for (const auto &Command : Page->CommandsStorage()) {
      Completions.push_back(Command.Name);
      Completions.push_back("help " + Command.Name);
    }
    Completions.emplace_back("n");
    Completions.emplace_back("p");
  }
  std::lock_guard<std::mutex> Lock(Reader().Mutex);
  Reader().Prompt = CurrentPrompt();
  Reader().Completions = std::move(Completions);
}

void InputLoop() {
  auto &State = Reader();
  for (;;) {
    TerminalPromptContext Prompt;
    ConsoleLineOptions Options;
    {
      std::unique_lock<std::mutex> Lock(State.Mutex);
      State.Changed.wait(Lock, [&] {
        return State.Stop || (!State.Paused && !State.Dispatching);
      });
      if (State.Stop)
        break;
      Prompt = State.Prompt;
      Options.History = &State.History;
      Options.Completions = State.Completions;
      Options.ControlPaging = true;
      State.Reading = true;
    }
    std::string Line;
    Options.PromptFactory = [Prompt] {
      return RenderTerminalPrompt(Prompt,
          QDateTime::currentDateTime().toString("HH:mm:ss").toStdString(), TerminalColumns());
    };
    const bool Accepted = ReadConsoleLine(nullptr, true, Line, Options);
    const bool Ended = ConsoleInputEnded();
    {
      std::lock_guard<std::mutex> Lock(State.Mutex);
      State.Reading = false;
      if (Ended)
        State.Stop = true;
      if (Accepted && !TrimAscii(Line).empty() && !State.Stop)
        State.Dispatching = true;
    }
    State.Changed.notify_all();
    if (Ended) {
      QMetaObject::invokeMethod(
          qApp, [] { QCoreApplication::quit(); }, Qt::QueuedConnection);
      break;
    }
    {
      std::lock_guard<std::mutex> Lock(State.Mutex);
      if (State.Stop)
        break;
    }
    if (!Accepted || TrimAscii(Line).empty())
      continue;
    const bool Queued = QMetaObject::invokeMethod(
        qApp,
        [Line] {
          ExecuteLineImpl(Line);
          UpdateConsolePrompt();
          {
            std::lock_guard<std::mutex> Lock(Reader().Mutex);
            Reader().Dispatching = false;
            if (Shell().QuitRequested)
              Reader().Stop = true;
          }
          Reader().Changed.notify_all();
          if (Shell().QuitRequested)
            QCoreApplication::quit();
        },
        Qt::QueuedConnection);
    if (!Queued)
      break;
  }
  {
    std::lock_guard<std::mutex> Lock(State.Mutex);
    State.Reading = false;
    State.Stop = true;
  }
  State.Changed.notify_all();
}

void PrintBannerLines() {
  TerminalChinese = ActiveLanguage == "zh_CN";
  WriteConsoleLine("");
  // Host/identity row for the banner: computer · user · Windows release.
  const QProcessEnvironment Env = QProcessEnvironment::systemEnvironment();
  std::string HostInfo = Env.value("COMPUTERNAME").toStdString();
  const QString User = Env.value("USERNAME");
  if (!User.isEmpty()) {
    if (!HostInfo.empty()) HostInfo += " · ";
    HostInfo += User.toStdString();
  }
  const QString Product = QSysInfo::prettyProductName();
  if (!Product.isEmpty()) {
    if (!HostInfo.empty()) HostInfo += " · ";
    HostInfo += Product.toStdString();
  }
  Out(RenderTerminalBanner(KApplicationVersion.toStdString(),
                           UiText("TERMINAL", "原生终端"), TerminalColumns(),
                           HostInfo));
  PrintHelpLine(UiText("pages  tools    help  commands    Tab  complete", "pages  工具    help  命令    Tab  补全"));
  PrintHelpLine(UiText("Up/Down  history (type to filter)    PgUp/PgDn  page tables    n/p  next/prev",
                       "↑/↓  历史（先输入过滤）    PgUp/PgDn  表格翻页    n/p  下/上一页"));
  PrintHelpLine(UiText("show | find \"text\" | copy    Ctrl+←/→  words    Esc  cancel",
                       "show | find \"文本\" | copy    Ctrl+←/→  词跳转    Esc  取消"));
  WriteConsoleLine("");
}

} // namespace

// ------------------------------------------------------------
// 提示符入口
// ------------------------------------------------------------

void PrintShellBanner() { PrintBannerLines(); }

void StartShell(bool ConsoleOnly) {
  (void)ConsoleOnly;
  InitializeShell();
  SetConsoleSurfaceActive(true);
  {
    std::lock_guard<std::mutex> Lock(Reader().Mutex);
    Reader().Stop = false;
    Reader().Paused = false;
    Reader().Reading = false;
    Reader().Dispatching = false;
    Reader().History.clear();
  }
  UpdateConsolePrompt();
  ResetConsoleReadInterrupt();
  Info(Account.IsLoggedIn ? UiText("Signed-in session. Type 'pages' to browse tools.", "已登录，输入 pages 浏览工具。")
                          : UiText("Guest session. Local tools ready; Account and Chat require 'login'.", "访客会话已就绪，输入 pages 浏览本地工具。"));
  InputRunning() = true;
  Reader().Thread = std::thread(InputLoop);
}

void StopShell() {
  {
    std::lock_guard<std::mutex> Lock(Reader().Mutex);
    Reader().Stop = true;
  }
  InputRunning() = false;
  InterruptConsoleRead();
  Reader().Changed.notify_all();
  if (Reader().Thread.joinable())
    Reader().Thread.join();
  SetConsoleSurfaceActive(false);
  WriteConsoleLine(AnsiColorize(UiText("Session closed. Goodbye.", "会话已关闭。"), AnsiColor::Gray));
}

bool AskLine(const std::string &Question, bool Password, std::string &Line) {
  Line.clear();
  if (!InputRunning())
    return ReadConsoleLine(Question.c_str(), !Password, Line);

  // Async page callbacks may open a form while the worker is at the prompt.
  // Transfer ownership of stdin explicitly; never let two threads read it.
  {
    std::unique_lock<std::mutex> Lock(Reader().Mutex);
    Reader().Paused = true;
    if (Reader().Reading)
      InterruptConsoleRead();
    Reader().Changed.wait(Lock, [] { return !Reader().Reading; });
    if (Reader().Stop) {
      Reader().Paused = false;
      return false;
    }
  }
  // The worker may have finished a line just as we requested interruption.
  // Clear that stale wakeup only after it relinquishes the input handle.
  ResetConsoleReadInterrupt();
  const bool Accepted = ReadConsoleLine(Question.c_str(), !Password, Line);
  const bool Ended = ConsoleInputEnded();
  {
    std::lock_guard<std::mutex> Lock(Reader().Mutex);
    Reader().Paused = false;
    if (Ended)
      Reader().Stop = true;
  }
  Reader().Changed.notify_all();
  if (Ended) {
    Shell().QuitRequested = true;
    QCoreApplication::quit();
  }
  return Accepted;
}

// ------------------------------------------------------------
// --console 独占模式
// ------------------------------------------------------------

int RunConsoleMode(int Argc, char *Argv[]) {
  const bool SkipLogin = HasCommandLineSwitch(Argc, Argv, "--skip-login");
  const bool Integrated = HasCommandLineSwitch(Argc, Argv, "--console-child");
  QCoreApplication Application(Argc, Argv);
  Application.setApplicationName("AegisNT");
  Application.setOrganizationName("AegisNT");

  LoadConfiguration();
  LoadLanguageResources();
  ActiveLanguage =
      ConfigurationValue("Application", "Language", "en_US").toString() ==
              "zh_CN"
          ? "zh_CN"
          : "en_US";

  TerminalChinese = ActiveLanguage == "zh_CN";
  Account = {}; // Persisted account state is never an authenticated session.
  ParentSessionPipe Parent;
  if (Integrated && !Parent.Attach())
    return 4;

  if (!AttachConsoleForConsoleOnly(
          HasCommandLineSwitch(Argc, Argv, "--reuse-console")))
    return 3;

  InitInjectLog();
  SetInjectLogSink([](const char *Data, size_t Len) {
    const QByteArray Bytes(Data, static_cast<int>(Len));
    QStringDecoder Decoder(QStringDecoder::Utf8,
                           QStringConverter::Flag::Stateless);
    QString Result = Decoder.decode(Bytes);
    if (Decoder.hasError())
      Result = QString::fromLocal8Bit(Bytes);
    AppendConsoleOutput(Result);
  });
  qInstallMessageHandler([](QtMsgType Type, const QMessageLogContext &Context,
                            const QString &Message) {
    QString Prefix = "[*]";
    switch (Type) {
    case QtDebugMsg:
      Prefix = "[DEBUG]";
      break;
    case QtInfoMsg:
      Prefix = "[*]";
      break;
    case QtWarningMsg:
      Prefix = "[WARN]";
      break;
    case QtCriticalMsg:
    case QtFatalMsg:
      Prefix = "[!]";
      break;
    }
    QString Source;
    if (Context.file && Context.line > 0)
      Source = QString(" (%1:%2)")
                   .arg(QFileInfo(QString::fromUtf8(Context.file)).fileName())
                   .arg(Context.line);
    AppendConsoleOutput(
        QString("%1 Qt%2: %3\n").arg(Prefix, Source, Message.trimmed()));
  });

  if (HasCommandLineSwitch(Argc, Argv, "--vmxon")) {
    QString LoadError;
    if (!EnsureRing0CoreLoaded(&LoadError)) {
      AppendConsoleOutput("[!] --vmxon: Ring0Core unavailable: " + LoadError +
                          "\n");
    } else {
      VT_STATUS_OUTPUT VtStatus{};
      if (EnableVt(&VtStatus)) {
        AppendConsoleOutput(
            QString("[*] --vmxon: virtualization enabled on %1/%2 CPUs "
                    "(EPTP=0x%3).\n")
                .arg(VtStatus.ActiveCpuCount)
                .arg(VtStatus.CpuCount)
                .arg(VtStatus.EptPointer, 0, 16));
      }
    }
  }

  AppendConsoleOutput("[*] AegisNT console front-end starting.\n");
  PrintShellBanner();

  QTimer ParentTick;
  if (Integrated) {
    QElapsedTimer Deadline;
    Deadline.start();
    while (!Parent.Ready() && Deadline.elapsed() < 5000) {
      if (!Parent.Poll()) {
        RestoreConsole();
        return 4;
      }
      if (!Parent.Ready())
        QThread::msleep(10);
    }
    if (!Parent.Ready()) {
      RestoreConsole();
      return 4;
    }
    // GUI's Skip state is also authoritative: never show a second login gate.
    QObject::connect(&ParentTick, &QTimer::timeout, [&] {
      if (!Parent.Poll()) {
        Shell().QuitRequested = true;
        QCoreApplication::quit();
        return;
      }
      Parent.PublishChanges();
    });
    ParentTick.start(50);
  } else if (SkipLogin) {
    Info(UiText("Guest session ready (--skip-login). Type 'login' to sign in later.", "已进入访客会话（--skip-login），可输入 login 登录。"));
  } else if (!RunConsoleLoginGate()) {
    ShutdownShell();
    RestoreConsole();
    return 0;
  }

  StartShell(true);
  QCoreApplication::exec();
  StopShell();
  ParentTick.stop();
  Parent.PublishChanges();
  ShutdownShell();

  if (ActiveConsoleProcess &&
      ActiveConsoleProcess->state() != QProcess::NotRunning) {
    ActiveConsoleProcess->kill();
    ActiveConsoleProcess->waitForFinished(1000);
  }
  if (ModuleRunning.load() && !RunningModulePath.isEmpty()) {
    if (auto *RunningModule = FindDllModule(RunningModulePath);
        RunningModule && RunningModule->Handle) {
      const auto StopModule = reinterpret_cast<void (*)()>(
          GetProcAddress(RunningModule->Handle, "StopModule"));
      if (StopModule)
        StopModule();
    }
  }
  UnprotectProcess(GetCurrentProcessId());
  CleanupManagedDriversOnExit();
  if (!ModuleRunning.load()) {
    for (auto &Module : DllModules)
      DestroyModuleInstance(Module);
  }
  RestoreConsole();
  return 0;
}

// ------------------------------------------------------------
// GUI 模式下的第二前端
// ------------------------------------------------------------

void ApplyConsoleVisibilityFromConfig() {
  const bool Show =
      ConfigurationValue("Application", "ConsoleVisible", false).toBool();
  if (Show) {
    StartIntegratedConsoleProcess();
  } else {
    StopConsoleSurface();
  }
}

void StartConsoleSurface() {
  if (ConfigurationValue("Application", "ConsoleVisible", false).toBool())
    StartIntegratedConsoleProcess();
}

void StopConsoleSurface() {
  QProcess *Process = IntegratedConsoleProcess();
  if (Process->state() != QProcess::NotRunning) {
    // A fast off/on toggle should start a fresh process after this one exits.
    IntegratedConsoleStopRequested() = true;
    Process->write("{\"type\":\"close\"}\n");
    const auto Pid = Process->processId();
    QTimer::singleShot(1500, Process, [Process, Pid] {
      if (Process->processId() == Pid &&
          Process->state() != QProcess::NotRunning)
        Process->kill();
    });
  }
}

// 页面索引与 PageDefinitions()/CreatePageBody 完全一致。
PageFactory PageFactoryFor(int Index) {
  switch (Index) {
  case 0:
    return &MakeInformationPage;
  case 1:
    return &MakeTaskPage;
  case 2:
    return &MakeMonitorPage;
  case 3:
    return &MakeRegistryPage;
  case 4:
    return &MakeFilePage;
  case 5:
    return &MakeWindowPage;
  case 6:
    return &MakeDriverPage;
  case 7:
    return &MakeMemoryPage;
  case 8:
    return &MakeTablePage;
  case 9:
    return &MakeCallbackPage;
  case 10:
    return &MakePayloadPage;
  case 11:
    return &MakeModuleRunPage;
  case 12:
    return &MakeModuleManagerPage;
  case 13:
    return &MakeConsolePage;
  case 14:
    return &MakeChatPage;
  case 15:
    return &MakeSettingsPage;
  case 16:
    return &MakeKernelInspectorPage;
  case 17:
    return &MakeServicePage;
  case 18:
    return &MakeNetworkPage;
  case 19:
    return &MakeSnapshotPage;
  case 20:
    return &MakeDiskPage;
  case 21:
    return &MakeKernelResearchPage;
  case 22:
    return &MakeHookPage;
  case 23:
    return &MakeAccountPage;
  case 24:
    return &MakeHotKeysPage;
  default:
    return nullptr;
  }
}

void ValidatePageRegistry() {
  const auto &Definitions = AegisNT::PageDefinitions();
  for (int Index = 0; Index < static_cast<int>(Definitions.size()); ++Index) {
    PageFactory Factory = PageFactoryFor(Index);
    if (!Factory) {
      AppendConsoleOutput(
          QString("[!] TUI page registry mismatch: no factory for %1\n")
              .arg(QString::fromUtf8(
                  Definitions[static_cast<size_t>(Index)].Title)));
      continue;
    }
    auto Probe = Factory(Index);
    if (!Probe ||
        Probe->Title() !=
            std::string(Definitions[static_cast<size_t>(Index)].Title)) {
      AppendConsoleOutput(
          QString("[!] TUI page registry mismatch: %1 != %2\n")
              .arg(QString::fromStdString(Probe ? Probe->Title() : "(null)"))
              .arg(QString::fromUtf8(
                  Definitions[static_cast<size_t>(Index)].Title)));
    }
  }
}

} // namespace AegisNT::Tui
