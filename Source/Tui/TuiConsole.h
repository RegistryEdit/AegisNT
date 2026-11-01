#pragma once
// ============================================================
// 控制台窗口生命周期与行式 I/O（两种模式共用）。
// ------------------------------------------------------------
// GUI 日志由管道捕获；交互式提示符由独立子进程持有控制台，
// 避免关闭终端窗口杀掉主 GUI。
// --console 模式：默认独占控制台输入；--reuse-console 显式复用等待中的宿主。
// 本文件不包含任何全屏 TUI 头：控制台前端是纯行式提示符。
// ============================================================

#include "TuiPlatform.h"
#include "TuiColor.h"
#include <windows.h>

#include <functional>
#include <vector>

namespace AegisNT::Tui {

// Legacy embedding helper; the GUI startup path no longer needs a console.
bool AttachConsoleForGui();

// 默认不 AttachConsole 到父 shell，GUI 子系统程序的父 shell 不一定等待，
// 会争抢 stdin。ReuseParent 仅供显式 --reuse-console + 宿主等待使用。
bool AttachConsoleForConsoleOnly(bool ReuseParent = false);

// GUI 控制台收到 CTRL_CLOSE_EVENT 并已 FreeConsole 后，释放旧控制台句柄；
// 下次设置开关重新启用时，AttachConsoleForGui 会创建新的控制台窗口。
void ReleaseDetachedGuiConsole();

// 是否为 GUI 模式建立了私有控制台。
bool TuiConsoleAttached();

// 显示/隐藏控制台窗口。隐藏只做窗口操作，stdout 重定向保持有效，
// 因此隐藏期间日志仍进入转录缓冲，显示时回放。
void ShowConsoleWindow(bool Show);
bool IsConsoleVisible();

// 控制台窗口句柄是否仍然有效（用户强行关闭后可能已销毁）。
bool ConsoleWindowAlive();

// 写入控制台（UTF-8 字节，内部转 UTF-16 走 CONOUT$，不碰 CRT stdout）。
// 支持传统控制台及 ConPTY；不以 HWND 是否可见判断输出能力。
void WriteConsoleText(const char *Data, size_t Size);

// 写入一行并按需换行（便捷重载）。
void WriteConsoleLine(const std::string &Text);
void WriteConsoleFeedback(const std::string &Text); // UI progress, never a pipe's search data.

// 我们持有的 CONOUT$ 写句柄（无效值表示未绑定）。
HANDLE ConsoleWriteHandle();

// Main-thread display capture for in-process `command | find text` pipelines.
// RAII restores the writer on every early return; never used for input forms.
class ConsoleOutputCapture {
public:
  ConsoleOutputCapture();
  ~ConsoleOutputCapture();
  ConsoleOutputCapture(const ConsoleOutputCapture &) = delete;
  ConsoleOutputCapture &operator=(const ConsoleOutputCapture &) = delete;
  std::string Text;
  bool Failed = false;
  static void MarkFailed();
private:
  ConsoleOutputCapture *Previous;
};

// 把 GetStdHandle(STD_OUTPUT_HANDLE) 临时指向控制台，停止前端时由
// RestoreStdoutBinding() 还原到捕获管道。
void BindStdoutToConsole();
void RestoreStdoutBinding();

// 还原控制台模式与标题（退出时调用一次）。
void RestoreConsole();

// ------------------------------------------------------------
// ANSI 上色
// ------------------------------------------------------------

enum class AnsiColor {
  Default,
  Red,
  Green,
  Yellow,
  Blue,
  Magenta,
  Cyan,
  White,
  Gray
};

// Runtime color capability selected once the console handles are attached.
// None keeps transcripts and NO_COLOR output plain; Ansi16 is also used by
// classic conhost when VT sequences are unavailable; TrueColor is used by
// Windows Terminal/ConPTY and other hosts advertising 24-bit color.
TerminalColorMode GetTerminalColorMode();
bool TerminalTrueColorEnabled();

// ANSI 是否可用：NO_COLOR 非空，或本进程输出句柄没有启用
// ENABLE_VIRTUAL_TERMINAL_PROCESSING 时返回 false。
bool AnsiEnabled();
bool ConsoleVtEnabled(); // Capability independent of NO_COLOR.

// 关闭颜色时原样返回 Text；否则包一层 SGR 序列。
std::string AnsiColorize(const std::string &Text, AnsiColor Color,
                         bool Bold = false);
std::string RgbColorize(const std::string &Text, RgbColor Color,
                        bool Bold = false, bool Underline = false);

// ------------------------------------------------------------
// 行读取
// ------------------------------------------------------------

// 读到换行为止（不走 CRT stdin，以便关闭回显）。Prompt 非空时先输出。
// Echo=false 时显示星号（密码），不记录历史。支持光标、补全与整字删除。
// 返回 false 表示 EOF / 终端关闭 / Esc / Ctrl+C / 读取中断。
struct ConsoleLineOptions {
  std::function<std::string()> PromptFactory;
  std::vector<std::string> *History = nullptr;
  std::vector<std::string> Completions;
  // PageUp/PageDown at an empty prompt submit prev-page/next-page (shell
  // only; form/password reads keep them inert).
  bool ControlPaging = false;
};

bool ReadConsoleLine(const char *Prompt, bool Echo, std::string &Line,
                     const ConsoleLineOptions &Options = {});
bool ConsoleInputEnded();
void InterruptConsoleRead();
void ResetConsoleReadInterrupt();
// Wipes only the visible viewport; scrollback stays for selection/copy.
void ClearConsoleScreen();
// Wipes the whole buffer including scrollback (explicit `cls`).
void ClearConsoleBuffer();

} // namespace AegisNT::Tui
