// ============================================================
// 控制台窗口生命周期与行式 I/O 实现（Win32）。
// （unity 包含进 AegisNT.cpp，全局作用域）
// ============================================================

#include "TuiConsole.h"

#include "TuiText.h"
#include "TuiWidgets.h"
#include "TuiSearch.h"

#include <clocale>
#include <atomic>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <mutex>
#include <string_view>
#include <unordered_map>

namespace AegisNT::Tui {

namespace {

HWND &ConsoleWindow() {
  static HWND Window = nullptr;
  return Window;
}

bool &ConsoleOwned() {
  static bool Owned = false;
  return Owned;
}

// The first GUI console is created before stdout capture is installed. A
// console created after the user closes the window must leave the capture
// pipes attached to stdout/stderr and only replace the interactive stdin.
bool &GuiConsoleInitialized() {
  static bool Initialized = false;
  return Initialized;
}

DWORD &OriginalOutputMode() {
  static DWORD Mode = 0;
  return Mode;
}

DWORD &OriginalInputMode() {
  static DWORD Mode = 0;
  return Mode;
}

// 我们自己设置的 CONOUT$/CONIN$ 句柄；退出时归还并关闭。
HANDLE &OwnedOutput() {
  static HANDLE Handle = INVALID_HANDLE_VALUE;
  return Handle;
}

HANDLE &OwnedInput() {
  static HANDLE Handle = INVALID_HANDLE_VALUE;
  return Handle;
}

// 原始标准句柄，供 RestoreConsole 还原。
HANDLE &SavedStdout() {
  static HANDLE Handle = INVALID_HANDLE_VALUE;
  return Handle;
}

HANDLE &SavedStdin() {
  static HANDLE Handle = INVALID_HANDLE_VALUE;
  return Handle;
}

HANDLE SavedStderr = INVALID_HANDLE_VALUE;
UINT SavedOutputCodePage = 0;
UINT SavedInputCodePage = 0;
std::wstring SavedConsoleTitle;

bool EnvironmentSet(const char *Name) {
  const auto *Value = std::getenv(Name);
  return Value != nullptr && *Value != '\0';
}

bool AdvertisesTrueColor() {
  const auto *Color = std::getenv("COLORTERM");
  const std::string Value = Color ? LowerAscii(Color) : "";
  const auto *ConEmu = std::getenv("ConEmuANSI");
  return Value == "truecolor" || Value == "24bit" ||
         EnvironmentSet("WT_SESSION") || EnvironmentSet("WEZTERM_EXECUTABLE") ||
         (ConEmu && LowerAscii(ConEmu) == "on");
}

thread_local ConsoleOutputCapture *ActiveOutputCapture = nullptr;
struct ConsoleWidthMetrics {
  HANDLE Buffer = INVALID_HANDLE_VALUE;
  std::mutex Mutex;
  std::unordered_map<char32_t, int> Cache;
};
ConsoleWidthMetrics &WidthMetrics() { static ConsoleWidthMetrics Metrics; return Metrics; }
int MeasureConsoleCell(char32_t C) {
  auto &Metrics = WidthMetrics();
  std::lock_guard<std::mutex> Lock(Metrics.Mutex);
  if (Metrics.Buffer == INVALID_HANDLE_VALUE) return -1;
  if (const auto It = Metrics.Cache.find(C); It != Metrics.Cache.end()) return It->second;
  // An inactive buffer inherits the host font. Never switch the visible buffer
  // or print probe characters into the user's scrollback.
  const auto Sample = QString::fromUcs4(&C, 1).toStdWString();
  const std::wstring Probe = L"x" + Sample + L"x";
  DWORD Written = 0;
  CONSOLE_SCREEN_BUFFER_INFO Info{};
  if (!SetConsoleCursorPosition(Metrics.Buffer, {0, 0}) ||
      !WriteConsoleW(Metrics.Buffer, Probe.data(), static_cast<DWORD>(Probe.size()), &Written, nullptr) ||
      !GetConsoleScreenBufferInfo(Metrics.Buffer, &Info)) return -1;
  const int Width = Info.dwCursorPosition.Y == 0 ? std::clamp<int>(Info.dwCursorPosition.X - 2, 0, 2) : -1;
  if (Metrics.Cache.size() < 4096) Metrics.Cache.emplace(C, Width);
  return Width;
}
void ResetConsoleMetrics() {
  auto &Metrics = WidthMetrics();
  std::lock_guard<std::mutex> Lock(Metrics.Mutex);
  if (Metrics.Buffer != INVALID_HANDLE_VALUE) CloseHandle(Metrics.Buffer);
  Metrics.Buffer = INVALID_HANDLE_VALUE;
  Metrics.Cache.clear();
}

HANDLE OpenConsoleDevice(const wchar_t *Name) {
  return CreateFileW(Name, GENERIC_READ | GENERIC_WRITE,
                     FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                     0, nullptr);
}

bool OpenConsoleHandles() {
  if (OwnedOutput() == INVALID_HANDLE_VALUE)
    OwnedOutput() = OpenConsoleDevice(L"CONOUT$");
  if (OwnedInput() == INVALID_HANDLE_VALUE)
    OwnedInput() = OpenConsoleDevice(L"CONIN$");
  return OwnedOutput() != INVALID_HANDLE_VALUE &&
         OwnedInput() != INVALID_HANDLE_VALUE;
}

// 把 CRT 标准流与 Win32 标准句柄都接到控制台。
// 顺序要求：先保存原始句柄，再覆盖。Explorer 启动时标准句柄可能是无效值。
void BindStandardStreams() {
  if (SavedStdout() == INVALID_HANDLE_VALUE)
    SavedStdout() = GetStdHandle(STD_OUTPUT_HANDLE);
  if (SavedStdin() == INVALID_HANDLE_VALUE)
    SavedStdin() = GetStdHandle(STD_INPUT_HANDLE);
  SavedStderr = GetStdHandle(STD_ERROR_HANDLE);

  // The prompt uses WriteConsoleW; shared CRT streams still need to accept
  // both printf and wprintf from local tools. Do not use Unicode-only modes.
  FILE *Stream = nullptr;
  freopen_s(&Stream, "CONOUT$", "wb", stdout);
  freopen_s(&Stream, "CONOUT$", "wb", stderr);
  freopen_s(&Stream, "CONIN$", "rb", stdin);
  std::setlocale(LC_CTYPE, ".UTF8");
  _setmode(_fileno(stdout), _O_TEXT);
  _setmode(_fileno(stderr), _O_TEXT);
  SetConsoleOutputCP(CP_UTF8);
  SetConsoleCP(CP_UTF8);
  std::setvbuf(stdout, nullptr, _IONBF, 0);
  std::setvbuf(stderr, nullptr, _IONBF, 0);

  if (OpenConsoleHandles()) {
    SetStdHandle(STD_OUTPUT_HANDLE, OwnedOutput());
    SetStdHandle(STD_ERROR_HANDLE, OwnedOutput());
    SetStdHandle(STD_INPUT_HANDLE, OwnedInput());
  }
}

// Used only after the initial GUI stdout/stderr capture is already active.
// Do not freopen stdout here: that would silently bypass the capture pipe.
bool BindConsoleInputForGuiReattach() {
  if (!OpenConsoleHandles())
    return false;
  SetStdHandle(STD_INPUT_HANDLE, OwnedInput());
  return true;
}

void CaptureOriginalModes() {
  SavedOutputCodePage = GetConsoleOutputCP();
  SavedInputCodePage = GetConsoleCP();
  wchar_t Title[1024]{};
  const DWORD Length = GetConsoleTitleW(Title, 1024);
  SavedConsoleTitle.assign(Title, Length);
  HANDLE Output = OwnedOutput();
  if (Output != nullptr && Output != INVALID_HANDLE_VALUE)
    GetConsoleMode(Output, &OriginalOutputMode());
  HANDLE Input = OwnedInput();
  if (Input != nullptr && Input != INVALID_HANDLE_VALUE)
    GetConsoleMode(Input, &OriginalInputMode());
}

void EnableVirtualTerminalOutput() {
  HANDLE Output = OwnedOutput();
  if (Output == INVALID_HANDLE_VALUE)
    return;
  DWORD Mode = 0;
  if (GetConsoleMode(Output, &Mode))
    SetConsoleMode(Output, Mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING |
                               ENABLE_PROCESSED_OUTPUT);
  ResetConsoleMetrics();
  WidthMetrics().Buffer = CreateConsoleScreenBuffer(GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, CONSOLE_TEXTMODE_BUFFER, nullptr);
  TerminalNativeCellWidth = MeasureConsoleCell;
}

// 提示符按行读取，所以必须关掉行输入、回显与 Ctrl+C 直通：
// 关闭 LINE 后 ReadConsoleW 逐字符返回；关闭 ECHO 由我们自己回显（密码
// 不回显）；关闭 PROCESSED 后 Ctrl+C 变成字符 0x03 而不是终止信号。
// MOUSE_INPUT 保持关闭、QUICK_EDIT_MODE 保留：conhost 接管左键拖选，
// 用户才能选中复制；Windows Terminal 的选择与该标志无关。
void ConfigureConsoleInputForLineReads() {
  const HANDLE Input = OwnedInput();
  if (Input == nullptr || Input == INVALID_HANDLE_VALUE)
    return;
  DWORD Mode = 0;
  if (!GetConsoleMode(Input, &Mode))
    return;
  Mode &= ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT |
            ENABLE_MOUSE_INPUT | ENABLE_WINDOW_INPUT |
            ENABLE_VIRTUAL_TERMINAL_INPUT);
  Mode |= ENABLE_EXTENDED_FLAGS | ENABLE_QUICK_EDIT_MODE;
  SetConsoleMode(Input, Mode);
}

} // namespace

bool TuiConsoleAttached() {
  return ConsoleWindow() != nullptr && IsWindow(ConsoleWindow()) != FALSE;
}

bool AttachConsoleForGui() {
  if (TuiConsoleAttached())
    return true;
  ReleaseDetachedGuiConsole();
  // 从 cmd/powershell 启动时 GetConsoleWindow() 非空：那是用户自己的窗口，
  // 既不能隐藏也不能复用（否则 cmd 无法返回提示符）。先断开再自建。
  if (GetConsoleWindow() != nullptr)
    FreeConsole();
  if (!AllocConsole())
    return false;
  ConsoleOwned() = true;
  ConsoleWindow() = GetConsoleWindow();
  if (!OpenConsoleHandles())
    return false;
  CaptureOriginalModes();
  const bool Bound = GuiConsoleInitialized() ? BindConsoleInputForGuiReattach()
                                             : (BindStandardStreams(), true);
  if (!Bound) {
    FreeConsole();
    ConsoleWindow() = nullptr;
    ConsoleOwned() = false;
    return false;
  }
  GuiConsoleInitialized() = true;
  EnableVirtualTerminalOutput();
  if (ConsoleWindow() != nullptr) {
    SetConsoleTitleW(L"AegisNT Console");
    ShowWindow(ConsoleWindow(), SW_HIDE); // 默认隐藏
  }
  return true;
}

bool AttachConsoleForConsoleOnly(bool ReuseParent) {
  if (GetConsoleWindow() == nullptr) {
    // A /SUBSYSTEM:WINDOWS executable does not inherit its invoking terminal.
    // Its parent shell can already be reading another command. Attaching to
    // that input buffer makes login/commands race cmd.exe (including More?).
    // Keep the default console independent; borrowing requires an explicit
    // flag and a caller which waits for this process.
    const bool Attached = ReuseParent && AttachConsole(ATTACH_PARENT_PROCESS);
    if (!Attached && !AllocConsole())
      return false;
    ConsoleOwned() = true; // We detach on exit; never close the host window.
  }
  if (!OpenConsoleHandles())
    return false;
  CaptureOriginalModes();
  // Capture host modes before enabling VT, UTF-8 or editing keys.
  BindStandardStreams();
  ConsoleWindow() = GetConsoleWindow();
  if (!ReuseParent) {
    // A newly allocated classic console otherwise falls back to a CJK raster
    // font. Consolas ships with Windows; this changes only our private window,
    // never a reused PowerShell/Windows Terminal font or global console defaults.
    CONSOLE_FONT_INFOEX Font{};
    Font.cbSize = sizeof(Font);
    if (GetCurrentConsoleFontEx(OwnedOutput(), FALSE, &Font)) {
      Font.dwFontSize = {0, 18};
      Font.FontFamily = FF_MODERN;
      Font.FontWeight = FW_NORMAL;
      wcscpy_s(Font.FaceName, L"Consolas");
      SetCurrentConsoleFontEx(OwnedOutput(), FALSE, &Font);
    }
  }
  EnableVirtualTerminalOutput();
  if (ConsoleWindow() != nullptr) {
    SetConsoleTitleW(L"AegisNT Console");
    ShowWindow(ConsoleWindow(), SW_SHOW);
  }
  return ConsoleWindow() != nullptr;
}

void ReleaseDetachedGuiConsole() {
  // Called on the GUI thread after CTRL_CLOSE_EVENT detached this process.
  // Preserve stdout/stderr: in GUI mode they belong to the log-capture pipes.
  if (GetConsoleWindow() != nullptr)
    return;
  ResetConsoleMetrics();
  if (OwnedOutput() != INVALID_HANDLE_VALUE) {
    CloseHandle(OwnedOutput());
    OwnedOutput() = INVALID_HANDLE_VALUE;
  }
  if (OwnedInput() != INVALID_HANDLE_VALUE) {
    CloseHandle(OwnedInput());
    OwnedInput() = INVALID_HANDLE_VALUE;
  }
  SavedStdout() = INVALID_HANDLE_VALUE;
  SavedStdin() = INVALID_HANDLE_VALUE;
  OriginalOutputMode() = 0;
  OriginalInputMode() = 0;
  ConsoleWindow() = nullptr;
  ConsoleOwned() = false;
}

HANDLE ConsoleWriteHandle() { return OwnedOutput(); }

HANDLE ConsoleReadHandle() { return OwnedInput(); }

namespace {
HANDLE &SavedStdoutBinding() {
  static HANDLE Handle = INVALID_HANDLE_VALUE;
  return Handle;
}

int &SavedStdoutFd() {
  static int Fd = -1;
  return Fd;
}
} // namespace

void BindStdoutToConsole() {
  // 提示符输出走 OwnedOutput()；这里同步接管 STD 句柄与 CRT stdout，
  // 让转发来的日志与提示符落在同一张屏幕上。
  if (OwnedOutput() == INVALID_HANDLE_VALUE)
    return;
  if (SavedStdoutBinding() == INVALID_HANDLE_VALUE) {
    SavedStdoutBinding() = GetStdHandle(STD_OUTPUT_HANDLE);
    SavedStdoutFd() = _dup(_fileno(stdout));
  }
  SetStdHandle(STD_OUTPUT_HANDLE, OwnedOutput());
  SetStdHandle(STD_ERROR_HANDLE, OwnedOutput());
  DWORD Mode = 0;
  if (GetConsoleMode(OwnedOutput(), &Mode))
    SetConsoleMode(OwnedOutput(), Mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING |
                                      ENABLE_PROCESSED_OUTPUT);
  FILE *Stream = nullptr;
  freopen_s(&Stream, "CONOUT$", "wb", stdout);
  _setmode(_fileno(stdout), _O_TEXT);
  std::setvbuf(stdout, nullptr, _IONBF, 0);
}

void RestoreStdoutBinding() {
  if (SavedStdoutBinding() == INVALID_HANDLE_VALUE)
    return;
  std::fflush(stdout);
  if (SavedStdoutFd() >= 0) {
    _dup2(SavedStdoutFd(), _fileno(stdout));
    _close(SavedStdoutFd());
    SavedStdoutFd() = -1;
  }
  SetStdHandle(STD_OUTPUT_HANDLE, SavedStdoutBinding());
  SetStdHandle(STD_ERROR_HANDLE, SavedStdoutBinding());
  SavedStdoutBinding() = INVALID_HANDLE_VALUE;
}

bool ConsoleWindowAlive() {
  return ConsoleWindow() != nullptr && IsWindow(ConsoleWindow()) != FALSE;
}

bool IsConsoleVisible() {
  return ConsoleWindowAlive() && IsWindowVisible(ConsoleWindow()) != FALSE;
}

void ShowConsoleWindow(bool Show) {
  if (!ConsoleWindowAlive())
    return;
  ShowWindow(ConsoleWindow(), Show ? SW_SHOW : SW_HIDE);
  if (Show)
    SetForegroundWindow(ConsoleWindow());
}

void WriteConsoleText(const char *Data, size_t Size) {
  // Interactive output uses CONOUT$ directly, independently of CRT capture.
  // ConPTY exposes a non-visible HWND. Visibility is not an output capability.
  if (Data == nullptr || Size == 0)
    return;
  if (ActiveOutputCapture) {
    ActiveOutputCapture->Text += StripTerminalStyles(std::string_view(Data, Size));
    return;
  }
  const HANDLE Out = OwnedOutput();
  if (Out == INVALID_HANDLE_VALUE)
    return;

  static std::mutex WriteMutex;
  std::lock_guard<std::mutex> Lock(WriteMutex);

  const auto Mode = GetTerminalColorMode();
  CONSOLE_SCREEN_BUFFER_INFOEX Info{};
  Info.cbSize = sizeof(Info);
  const bool HavePalette = GetConsoleScreenBufferInfoEx(Out, &Info) != FALSE;
  if (!HavePalette) {
    CONSOLE_SCREEN_BUFFER_INFO Basic{};
    if (!GetConsoleScreenBufferInfo(Out, &Basic)) return;
    Info.wAttributes = Basic.wAttributes;
  }
  TerminalSgrState State(Info.wAttributes);
  if (HavePalette)
    for (size_t I = 0; I < State.Palette.size(); ++I)
      State.Palette[I] = {GetRValue(Info.ColorTable[I]), GetGValue(Info.ColorTable[I]),
                          GetBValue(Info.ColorTable[I])};
  const auto Write = [&](std::string_view Text) {
    const auto Decoded = QString::fromUtf8(Text.data(),
        static_cast<qsizetype>(Text.size())).toStdWString();
    std::wstring Wide;
    Wide.reserve(Decoded.size());
    wchar_t Previous = 0;
    for (wchar_t C : Decoded) {
      if (C == L'\n' && Previous != L'\r') Wide += L'\r';
      Wide += C; Previous = C;
    }
    size_t Offset = 0;
    while (Offset < Wide.size()) {
      DWORD Count = static_cast<DWORD>(std::min<size_t>(Wide.size() - Offset, 8192));
      if (Offset + Count < Wide.size() && QChar::isHighSurrogate(Wide[Offset + Count - 1])) --Count;
      DWORD Written = 0;
      if (!Count || !WriteConsoleW(Out, Wide.data() + Offset, Count, &Written, nullptr) || !Written) break;
      Offset += Written;
    }
  };
  if (Mode == TerminalColorMode::TrueColor) {
    Write(std::string_view(Data, Size));
    // Every writer call is a self-contained fragment. Reset even if its caller
    // omitted a trailing reset; restore the host's original background/flags.
    if (std::string_view(Data, Size).find('\x1b') != std::string_view::npos) Write("\x1b[0m");
  } else {
    VisitTerminalStyles(std::string_view(Data, Size), [&](std::string_view Text) {
      if (Mode == TerminalColorMode::Ansi16) SetConsoleTextAttribute(Out, State.Attributes());
      Write(Text);
    }, [&](const std::vector<int> &Params) {
      if (Mode == TerminalColorMode::Ansi16) State.Apply(Params);
    });
  }
  SetConsoleTextAttribute(Out, Info.wAttributes);
}

ConsoleOutputCapture::ConsoleOutputCapture() : Previous(ActiveOutputCapture) { ActiveOutputCapture = this; }
ConsoleOutputCapture::~ConsoleOutputCapture() { ActiveOutputCapture = Previous; }
void ConsoleOutputCapture::MarkFailed() {
  if (ActiveOutputCapture) ActiveOutputCapture->Failed = true;
}

void WriteConsoleLine(const std::string &Text) {
  std::string Line = Text;
  Line += '\n';
  WriteConsoleText(Line.data(), Line.size());
}

void WriteConsoleFeedback(const std::string &Text) {
  auto *Capture = ActiveOutputCapture;
  ActiveOutputCapture = nullptr;
  try { WriteConsoleLine(Text); }
  catch (...) { ActiveOutputCapture = Capture; throw; }
  ActiveOutputCapture = Capture;
}

TerminalColorMode GetTerminalColorMode() {
  DWORD Mode = 0;
  const bool Console = OwnedOutput() != INVALID_HANDLE_VALUE &&
      GetConsoleMode(OwnedOutput(), &Mode) != FALSE;
  const bool NoColor = EnvironmentSet("NO_COLOR") || EnvironmentSet("AEGISNT_NO_COLOR");
  if (!Console || NoColor) return TerminalColorMode::None;
  wchar_t ClassName[64]{};
  GetClassNameW(GetConsoleWindow(), ClassName, 64);
  const bool Classic = std::wcscmp(ClassName, L"ConsoleWindowClass") == 0;
  const bool Pseudo = std::wcscmp(ClassName, L"PseudoConsoleWindow") == 0;
  // A new standalone conhost inherits WT_SESSION from its parent shell. Its
  // real window class wins over inherited environment hints. Hidden conhost
  // windows remain classic; visibility is never used as a capability test.
  return SelectTerminalColorMode(Console, (Mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0,
      Pseudo, !Classic && AdvertisesTrueColor(), NoColor);
}

bool TerminalTrueColorEnabled() { return GetTerminalColorMode() == TerminalColorMode::TrueColor; }

bool AnsiEnabled() { return GetTerminalColorMode() != TerminalColorMode::None; }

bool ConsoleVtEnabled() {
  const HANDLE Out = OwnedOutput();
  DWORD Mode = 0;
  return Out != INVALID_HANDLE_VALUE && GetConsoleMode(Out, &Mode) != FALSE &&
         (Mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0;
}

std::string AnsiColorize(const std::string &Text, AnsiColor Color, bool Bold) {
  if (!AnsiEnabled())
    return Text;
  const char *Code = "";
  switch (Color) {
  case AnsiColor::Red:
    Code = "31";
    break;
  case AnsiColor::Green:
    Code = "32";
    break;
  case AnsiColor::Yellow:
    Code = "33";
    break;
  case AnsiColor::Blue:
    Code = "94";
    break;
  case AnsiColor::Magenta:
    Code = "35";
    break;
  case AnsiColor::Cyan:
    Code = "96";
    break;
  case AnsiColor::White:
    Code = "37";
    break;
  case AnsiColor::Gray:
    Code = "90";
    break;
  case AnsiColor::Default:
  default:
    break;
  }
  std::string Out;
  if (Bold)
    Out += "\x1b[1m";
  if (*Code)
    Out += std::string("\x1b[") + Code + "m";
  if (Out.empty())
    return Text;
  return Out + Text + "\x1b[0m";
}

std::string RgbColorize(const std::string &Text, RgbColor Color, bool Bold,
                        bool Underline) {
  return FormatTerminalColor(Text, Color, Bold, Underline, GetTerminalColorMode());
}

namespace {
thread_local bool InputEnded = false;
std::atomic_bool IgnorePastedLf{false};

HANDLE ConsoleInterruptEvent() {
  static HANDLE Event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
  return Event;
}
} // namespace

bool ConsoleInputEnded() { return InputEnded; }

void InterruptConsoleRead() { SetEvent(ConsoleInterruptEvent()); }
void ResetConsoleReadInterrupt() { ResetEvent(ConsoleInterruptEvent()); }

void ClearConsoleScreen() {
  CONSOLE_SCREEN_BUFFER_INFO Info{};
  if (!GetConsoleScreenBufferInfo(OwnedOutput(), &Info))
    return;
  // Viewport-only wipe: `clear` and Ctrl+L keep scrollback so earlier output
  // stays selectable/copyable. Region fill instead of CSI 2J because conhost
  // does not implement that erase; FillConsoleOutput* works on every host.
  const SHORT Top = Info.srWindow.Top;
  const DWORD Cells =
      static_cast<DWORD>(Info.dwSize.X) * (Info.srWindow.Bottom - Top + 1);
  DWORD Written = 0;
  FillConsoleOutputCharacterW(OwnedOutput(), L' ', Cells, {0, Top}, &Written);
  FillConsoleOutputAttribute(OwnedOutput(), Info.wAttributes, Cells, {0, Top},
                             &Written);
  SetConsoleCursorPosition(OwnedOutput(), {0, Top});
}

void ClearConsoleBuffer() {
  CONSOLE_SCREEN_BUFFER_INFO Info{};
  if (!GetConsoleScreenBufferInfo(OwnedOutput(), &Info))
    return;
  const DWORD Cells = static_cast<DWORD>(Info.dwSize.X) * Info.dwSize.Y;
  DWORD Written = 0;
  FillConsoleOutputCharacterW(OwnedOutput(), L' ', Cells, {0, 0}, &Written);
  FillConsoleOutputAttribute(OwnedOutput(), Info.wAttributes, Cells, {0, 0},
                             &Written);
  SetConsoleCursorPosition(OwnedOutput(), {0, 0});
}

bool ReadConsoleLine(const char *Prompt, bool Echo, std::string &Line,
                     const ConsoleLineOptions &Options) {
  std::string LivePrompt;
  if (Options.PromptFactory) {
    LivePrompt = Options.PromptFactory();
    Prompt = LivePrompt.c_str();
  }
  Line.clear();
  InputEnded = false;
  const HANDLE Input = OwnedInput();
  const bool ConsoleInput =
      Input != INVALID_HANDLE_VALUE && GetFileType(Input) == FILE_TYPE_CHAR;

  if (Prompt != nullptr && *Prompt != '\0')
    WriteConsoleText(Prompt, std::strlen(Prompt));

  // stdin 被重定向（管道/文件）时没有控制台记录可读，退回 CRT 行读取；
  // 此时回显由管道对端决定，回显抑制无从实施。
  if (!ConsoleInput) {
    std::string Text;
    if (!std::getline(std::cin, Text)) {
      InputEnded = true;
      return false;
    }
    Line = Text;
    return true;
  }

  ConfigureConsoleInputForLineReads();
  TerminalEditor Editor;
  CONSOLE_SCREEN_BUFFER_INFO Info{};
  GetConsoleScreenBufferInfo(OwnedOutput(), &Info);
  COORD Origin = Info.dwCursorPosition;
  int LastWidth = 0;
  size_t ViewStart = 0;
  size_t HistoryIndex = Options.History ? Options.History->size() : 0;
  std::string Draft;
  std::vector<std::string> Matches;
  size_t MatchIndex = 0;
  bool Listed = false;      // Candidates shown; Tab/Shift+Tab now cycle them.
  bool HistorySearch = false; // ↑/↓ filter history by the typed prefix.
  std::string LastKill;       // Last Ctrl+W/U/K/Delete cut, yanked by Ctrl+Y.
  wchar_t HighSurrogate = 0;
  const auto Render = [&](bool Hints = true) {
    GetConsoleScreenBufferInfo(OwnedOutput(), &Info);
    Origin.X =
        std::clamp<SHORT>(Origin.X, 0, std::max<SHORT>(0, Info.dwSize.X - 2));
    Origin.Y =
        std::clamp<SHORT>(Origin.Y, 0, std::max<SHORT>(0, Info.dwSize.Y - 1));
    const int Available = std::max(1, static_cast<int>(
        std::min<SHORT>(Info.dwSize.X - 1, Info.srWindow.Right) - Origin.X));
    ViewStart = std::min(ViewStart, Editor.Cursor);
    const auto Width = [&](size_t Begin, size_t End) {
      return Echo ? TerminalWidth(Editor.Text.substr(Begin, End - Begin))
                  : static_cast<int>(End - Begin);
    };
    while (ViewStart < Editor.Cursor &&
           Width(ViewStart, Editor.Cursor) >= Available)
      ++ViewStart;
    std::u32string Visible;
    int Cells = 0;
    for (size_t I = ViewStart; I < Editor.Text.size(); ++I) {
      const char32_t C = Echo ? Editor.Text[I] : U'*';
      const int Advance = TerminalCellWidth(C);
      if (Cells + Advance > Available)
        break;
      Visible += C;
      Cells += Advance;
    }
    DWORD Written = 0;
    FillConsoleOutputCharacterW(
        OwnedOutput(), L' ', static_cast<DWORD>(std::min(LastWidth, Available)),
        Origin, &Written);
    SetConsoleCursorPosition(OwnedOutput(), Origin);
    const auto Text = TerminalUtf8(Visible);
    WriteConsoleText(Text.data(), Text.size());
    if (Hints && Echo && !Options.Completions.empty() && !Editor.Text.empty() &&
        Editor.Cursor == Editor.Text.size() && Cells == Width(ViewStart, Editor.Text.size())) {
      const auto Prefix = TerminalUtf8(Editor.Text);
      const auto Suggestions = TerminalCompletions(Prefix, Options.Completions);
      const auto It = std::find_if(Suggestions.begin(), Suggestions.end(), [&](const auto &S) { return S.size() > Prefix.size(); });
      if (It != Suggestions.end()) {
        const auto Hint = TerminalClip(AnsiEnabled() ? It->substr(Prefix.size()) + " [Tab]"
                                                   : " [Tab: " + *It + "]", Available - Cells);
        const auto Painted = Paint(Hint, TuiTone::Muted);
        WriteConsoleText(Painted.data(), Painted.size());
        Cells += TerminalWidth(Hint);
      }
    }
    const SHORT X =
        static_cast<SHORT>(Origin.X + Width(ViewStart, Editor.Cursor));
    SetConsoleCursorPosition(OwnedOutput(), {X, Origin.Y});
    LastWidth = Cells;
  };

  for (;;) {
    const HANDLE WaitHandles[] = {ConsoleInterruptEvent(), Input};
    const DWORD Wait = WaitForMultipleObjects(2, WaitHandles, FALSE, INFINITE);
    if (Wait == WAIT_OBJECT_0)
      return false;
    if (Wait != WAIT_OBJECT_0 + 1) {
      InputEnded = true;
      return false;
    }
    INPUT_RECORD Record{};
    DWORD Read = 0;
    // One record at a time keeps pasted lines queued for subsequent prompts.
    if (!ReadConsoleInputW(Input, &Record, 1, &Read) || !Read) {
      InputEnded = true;
      return false;
    }
    if (Record.EventType != KEY_EVENT || !Record.Event.KeyEvent.bKeyDown)
      continue;
    const auto &Key = Record.Event.KeyEvent;
    const wchar_t Char = Key.uChar.UnicodeChar;
    // Treat pasted CRLF as one Enter, including across prompt/thread changes.
    if (Char == L'\n' && IgnorePastedLf.exchange(false))
      continue;
    if (Char != L'\0')
      IgnorePastedLf = false;
    const bool Ctrl =
        (Key.dwControlKeyState & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED)) != 0;
    if (Key.wVirtualKeyCode == VK_ESCAPE || Char == 3) {
      Editor.Cursor = Editor.Text.size();
      Render(false);
      WriteConsoleLine(Char == 3 ? "^C" : UiText(" [cancelled]", " [已取消]"));
      return false;
    }
    if ((Char == 4 || Char == 26) && Editor.Text.empty()) {
      InputEnded = true;
      WriteConsoleLine("");
      return false;
    }
    if (Key.wVirtualKeyCode == VK_RETURN || Char == L'\r' || Char == L'\n') {
      IgnorePastedLf = Char == L'\r';
      Editor.Cursor = Editor.Text.size();
      Render(false);
      Line = TerminalUtf8(Editor.Text);
      WriteConsoleLine("");
      if (Echo && Options.History && !TrimAscii(Line).empty()) {
        auto &History = *Options.History;
        if (History.empty() || History.back() != Line)
          History.push_back(Line);
        if (History.size() > 100)
          History.erase(History.begin());
      }
      return true;
    }
    if (Key.wVirtualKeyCode != VK_TAB) {
      Matches.clear();
      Listed = false;
    }
    if (Key.wVirtualKeyCode != VK_UP && Key.wVirtualKeyCode != VK_DOWN)
      HistorySearch = false;
    for (WORD Repeat = 0; Repeat < std::max<WORD>(1, Key.wRepeatCount);
         ++Repeat) {
      if (Key.wVirtualKeyCode == VK_LEFT)
        Ctrl ? Editor.WordLeft() : Editor.Left();
      else if (Key.wVirtualKeyCode == VK_RIGHT)
        Ctrl ? Editor.WordRight() : Editor.Right();
      else if (Key.wVirtualKeyCode == VK_HOME || Char == 1)
        Editor.Cursor = 0;
      else if (Key.wVirtualKeyCode == VK_END || Char == 5)
        Editor.Cursor = Editor.Text.size();
      else if (Char == 2) // Ctrl+B / Ctrl+F: readline character motion.
        Editor.Left();
      else if (Char == 6)
        Editor.Right();
      else if (Key.wVirtualKeyCode == VK_BACK) {
        if (Ctrl)
          LastKill = TerminalUtf8(Editor.EraseWord());
        else
          Editor.Backspace();
      } else if (Key.wVirtualKeyCode == VK_DELETE) {
        if (Ctrl)
          LastKill = TerminalUtf8(Editor.DeleteWord());
        else
          Editor.Delete();
      } else if (Char == 21) {
        LastKill = TerminalUtf8(Editor.Text.substr(0, Editor.Cursor));
        Editor.Text.erase(0, Editor.Cursor);
        Editor.Cursor = 0;
      } else if (Char == 11) { // Ctrl+K: kill to end of line.
        LastKill = TerminalUtf8(Editor.Text.substr(Editor.Cursor));
        Editor.Text.erase(Editor.Cursor);
      } else if (Char == 25) { // Ctrl+Y: yank the last kill.
        Editor.InsertText(LastKill);
      } else if (Char == 22) { // Ctrl+V: paste clipboard text in place.
        if (OpenClipboard(nullptr)) {
          std::string Pasted;
          if (const HANDLE Data = GetClipboardData(CF_UNICODETEXT)) {
            if (const auto *Wide =
                    static_cast<const wchar_t *>(GlobalLock(Data))) {
              std::wstring Flat;
              Flat.reserve(std::min<size_t>(16384, wcslen(Wide)));
              for (const wchar_t *P = Wide;
                   *P && Flat.size() < 16384; ++P) {
                // Commands are single-line; flatten pasted newlines/tabs.
                Flat += (*P == L'\r' || *P == L'\n' || *P == L'\t') ? L' ' : *P;
              }
              GlobalUnlock(Data);
              Pasted = QString::fromStdWString(Flat).toUtf8().toStdString();
            }
          }
          CloseClipboard();
          if (!Pasted.empty())
            Editor.InsertText(Pasted);
        }
      } else if (Char == 23)
        LastKill = TerminalUtf8(Editor.EraseWord());
      else if (Char == 12) {
        ClearConsoleScreen();
        if (Options.PromptFactory) {
          LivePrompt = Options.PromptFactory();
          Prompt = LivePrompt.c_str();
        }
        if (Prompt)
          WriteConsoleText(Prompt, std::strlen(Prompt));
        GetConsoleScreenBufferInfo(OwnedOutput(), &Info);
        Origin = Info.dwCursorPosition;
        LastWidth = 0;
      } else if ((Key.wVirtualKeyCode == VK_NEXT ||
                  Key.wVirtualKeyCode == VK_PRIOR) &&
                 Echo && Options.ControlPaging && Editor.Text.empty()) {
        // Empty prompt: page keys dispatch prev-page/next-page directly.
        // Auto-submitted lines skip history, like shell control keys.
        const char *Command = Key.wVirtualKeyCode == VK_NEXT ? "next-page"
                                                            : "prev-page";
        Render(false);
        WriteConsoleLine("");
        WriteConsoleLine(Paint(std::string("  » ") + Command, TuiTone::Muted));
        Line = Command;
        return true;
      } else if ((Key.wVirtualKeyCode == VK_UP ||
                  Key.wVirtualKeyCode == VK_DOWN) &&
                 Echo && Options.History) {
        auto &History = *Options.History;
        if (HistoryIndex == History.size())
          Draft = TerminalUtf8(Editor.Text);
        // Typed text turns ↑/↓ into a prefix history search (PSReadLine
        // style); empty input keeps the classic full-history walk.
        if (HistoryIndex == History.size() && !Draft.empty())
          HistorySearch = true;
        if (HistorySearch && !Draft.empty()) {
          const std::string Needle = LowerAscii(Draft);
          if (Key.wVirtualKeyCode == VK_UP) {
            for (size_t Step = std::min<size_t>(HistoryIndex, History.size());
                 Step-- > 0;)
              if (LowerAscii(History[Step]).rfind(Needle, 0) == 0) {
                HistoryIndex = Step;
                Editor.Set(History[Step]);
                break;
              }
          } else {
            for (size_t Step = HistoryIndex + 1; Step <= History.size(); ++Step) {
              if (Step == History.size()) {
                HistoryIndex = Step;
                Editor.Set(Draft); // Past the newest match: restore the draft.
                break;
              }
              if (LowerAscii(History[Step]).rfind(Needle, 0) == 0) {
                HistoryIndex = Step;
                Editor.Set(History[Step]);
                break;
              }
            }
          }
        } else if (Key.wVirtualKeyCode == VK_UP && HistoryIndex) {
          --HistoryIndex;
          Editor.Set(History[HistoryIndex]);
        } else if (Key.wVirtualKeyCode == VK_DOWN && HistoryIndex < History.size()) {
          ++HistoryIndex;
          Editor.Set(HistoryIndex == History.size() ? Draft
                                                    : History[HistoryIndex]);
        }
      } else if (Key.wVirtualKeyCode == VK_TAB && Echo) {
        if (Options.Completions.empty()) continue;
        const bool Shift = (Key.dwControlKeyState & SHIFT_PRESSED) != 0;
        if (!Listed) {
          const auto Prefix = TerminalUtf8(Editor.Text);
          Matches = TerminalCompletions(Prefix, Options.Completions);
          MatchIndex = 0;
          if (Matches.empty()) continue;
          if (Matches.size() == 1) {
            Editor.Set(Matches.front() + " "); // Unique: complete plus space.
            Matches.clear();
            continue;
          }
          const auto Common = TerminalCommonPrefix(Matches);
          if (TerminalWidth(Common) > TerminalWidth(Prefix)) {
            Editor.Set(Common); // First Tab only extends to the common prefix.
            continue;
          }
          Listed = true;
          Editor.Cursor = Editor.Text.size();
          Render(false);
          WriteConsoleLine("");
          std::string Candidates;
          for (size_t I = 0; I < std::min<size_t>(Matches.size(), 8); ++I) {
            if (I) Candidates += Paint("  /  ", TuiTone::Muted);
            Candidates += Paint(TerminalClean(Matches[I]), TuiTone::Accent);
          }
          if (Matches.size() > 8) Candidates += "  (+" + std::to_string(Matches.size() - 8) + ")";
          for (const auto &Hint : TerminalWrapStyled(Paint("Tab  ", TuiTone::Muted) + Candidates, TerminalColumns() - 3))
            WriteConsoleLine("  " + Hint);
          if (Options.PromptFactory) { LivePrompt = Options.PromptFactory(); Prompt = LivePrompt.c_str(); }
          if (Prompt) WriteConsoleText(Prompt, std::strlen(Prompt));
          GetConsoleScreenBufferInfo(OwnedOutput(), &Info);
          Origin = Info.dwCursorPosition;
          LastWidth = 0;
        }
        if (Matches.empty()) continue;
        if (Shift) // Shift+Tab walks the candidates backwards.
          MatchIndex = MatchIndex ? MatchIndex - 1 : Matches.size() - 1;
        Editor.Set(Matches[(MatchIndex++) % Matches.size()]);
      } else if (QChar::isHighSurrogate(Char)) {
        HighSurrogate = Char;
      } else if (QChar::isLowSurrogate(Char)) {
        if (HighSurrogate)
          Editor.Insert(QChar::surrogateToUcs4(HighSurrogate, Char));
        HighSurrogate = 0;
      } else if (Char >= L' ' && Char != 0x7f) {
        HighSurrogate = 0;
        Editor.Insert(Char);
      }
    }
    Render();
  }
}

void RestoreConsole() {
  ResetConsoleMetrics();
  // Restore the actual console handles, not redirected/inherited std handles.
  if (OwnedOutput() != INVALID_HANDLE_VALUE)
    SetConsoleMode(OwnedOutput(), OriginalOutputMode());
  if (OwnedInput() != INVALID_HANDLE_VALUE)
    SetConsoleMode(OwnedInput(), OriginalInputMode());
  if (SavedOutputCodePage)
    SetConsoleOutputCP(SavedOutputCodePage);
  if (SavedInputCodePage)
    SetConsoleCP(SavedInputCodePage);
  SetConsoleTitleW(SavedConsoleTitle.c_str());
  // 还原标准句柄（否则 FreeConsole 之后仍指向已销毁的控制台）。
  if (SavedStdout() != INVALID_HANDLE_VALUE)
    SetStdHandle(STD_OUTPUT_HANDLE, SavedStdout());
  if (SavedStdin() != INVALID_HANDLE_VALUE)
    SetStdHandle(STD_INPUT_HANDLE, SavedStdin());
  SetStdHandle(STD_ERROR_HANDLE, SavedStderr);

  if (OwnedOutput() != INVALID_HANDLE_VALUE) {
    CloseHandle(OwnedOutput());
    OwnedOutput() = INVALID_HANDLE_VALUE;
  }
  if (OwnedInput() != INVALID_HANDLE_VALUE) {
    CloseHandle(OwnedInput());
    OwnedInput() = INVALID_HANDLE_VALUE;
  }
  SavedStdout() = INVALID_HANDLE_VALUE;
  SavedStdin() = INVALID_HANDLE_VALUE;

  if (ConsoleOwned() && GetConsoleWindow() != nullptr)
    FreeConsole();
  ConsoleWindow() = nullptr;
  ConsoleOwned() = false;
}

} // namespace AegisNT::Tui
