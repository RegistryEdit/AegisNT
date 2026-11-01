#pragma once
// ============================================================
// 控制台前端入口与行式提示符外壳。
// ------------------------------------------------------------
// RunConsoleMode  : --console 独占进程（无 Qt 窗口）。
// StartShell/StopShell : 启动/停止提示符输入线程。
// AskLine         : 暂停提示符读取，将 stdin 交给主线程的表单字段。
// G_ConsoleVisibilityApplier : 设置页触发显隐的钩子（与 G_HotkeyReapplier
// 同一模式）。
// ============================================================

#include "TuiPlatform.h"

#include <functional>

namespace AegisNT::Tui {

// --console：只跑控制台，完全不创建窗口。
int RunConsoleMode(int Argc, char *Argv[]);

// 启动提示符：打印 banner，启动输入线程；返回后由调用方跑 Qt 事件循环。
void StartShell(bool ConsoleOnly);

// 停止输入线程并打印 "Goodbye."。
void StopShell();

// 打印 banner（RunConsoleMode 在登录门控之前调用一次）。
void PrintShellBanner();

// 主线程调用：提问并读取一行。Password=true 时不回显。
// 返回 false 表示输入流结束 / Ctrl+C。
bool AskLine(const std::string &Question, bool Password, std::string &Line);

// GUI 模式：启动/停止独立控制台前端进程。
void StartConsoleSurface();
void StopConsoleSurface();

// 立即按配置 Application/ConsoleVisible 应用一次显隐。
void ApplyConsoleVisibilityFromConfig();

// 设置页写入配置后调用；窗口尚未创建时为空。
extern std::function<void()> G_ConsoleVisibilityApplier;

// 集成控制台子进程退出时通知设置页，让“Show console window”同步关闭；
// 未创建设置页时为空。
extern std::function<void(bool)> G_ConsoleVisibleChanged;

// 登录门控（TuiSession.cpp）：返回 true 表示可以进入 shell。
// 内部负责自动登录、账号密码登录、注册与会话落盘。
bool RunConsoleLoginGate(bool AllowAutoLogin = true);

} // namespace AegisNT::Tui
