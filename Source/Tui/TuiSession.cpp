// ============================================================
// 控制台登录门控：自动登录 / 账号密码登录 / 注册（纯文本提示）。
// ------------------------------------------------------------
// 与 GUI 的 RunLoginFlow 语义对齐：
//   - 端点 /Login、/Register，信封 {success, message, data}
//   - 成功后 HandleLoginSuccess 落盘会话，nullptr 父窗口表示不弹 GUI 提示
//   - Skip 清空内存会话（受限模式，账号/聊天页不可用）
//   - 退出返回 false，由调用方结束进程
// 没有帧循环：所有提问都走 AskLine，随时可再次调用（shell 的 login 命令）。
// ============================================================

#include "TuiCore.h"

#include "TuiAsync.h"
#include "TuiConsole.h"
#include "TuiSync.h"
#include "TuiWidgets.h"
#include "TuiStyle.h"
#include "TuiSearch.h"

#include <utility>

namespace AegisNT::Tui {

namespace {

void LoginInfo(const std::string &Text) {
  WriteConsoleLine(NoticeText(Text, TuiTone::Accent));
}

void LoginGood(const std::string &Text) {
  WriteConsoleLine(NoticeText(Text, TuiTone::Success));
}

void LoginBad(const std::string &Text) {
  WriteConsoleLine(NoticeText(Text, TuiTone::Error));
}

// 同步登录：在调用线程上跑一次带超时的 HTTP 请求（内部自带 QEventLoop）。
// 门控阶段事件循环还没启动，这里不能依赖 TuiAsync 的投递。
std::pair<bool, QString> LoginRequest(const QString &User,
                                      const QString &Password) {
  QJsonObject Body;
  Body["UserName"] = User;
  Body["Password"] = Sha256Hex(Password);
  QJsonObject Response;
  QString Error;
  if (!HttpPostJson("/Login", Body, 6000, &Response, &Error))
    return std::make_pair(false, QString::fromStdString(UiText("Network error: ", "网络错误：")) + Error);
  if (!Response["success"].toBool())
    return std::make_pair(false, Response["message"].toString());
  const bool RememberMe =
      ConfigurationValue("Account", "SaveCredentials", false).toBool();
  const bool AutoLogin =
      ConfigurationValue("Account", "AutoLogin", false).toBool();
  HandleLoginSuccess(nullptr, Response["data"].toObject(), User, Password,
                     RememberMe, AutoLogin);
  if (!Account.IsLoggedIn)
    return std::make_pair(false,
                          QString(QString::fromStdString(UiText("Server returned an invalid login session.", "服务器返回了无效的登录会话。"))));
  return std::make_pair(true, QString::fromStdString(UiText("Welcome, %1!", "欢迎，%1！")).arg(User));
}

// 自动登录：与 RunLoginFlow 的前置步骤一致。
bool TryConsoleAutoLogin() {
  if (!ConfigurationValue("Account", "AutoLogin", false).toBool())
    return false;
  if (!ConfigurationValue("Account", "SaveCredentials", false).toBool())
    return false;
  const QString User = ConfigurationValue("Account", "UserName", "").toString();
  const QString Encrypted =
      ConfigurationValue("Account", "Password", "").toString();
  if (User.isEmpty() || Encrypted.isEmpty())
    return false;
  const QString Password = DecryptPassword(Encrypted);
  if (Password.isEmpty())
    return false;
  LoginInfo(UiText("Auto login as ", "使用保存的凭证登录：") + User.toStdString() + " ...");
  const auto Result = LoginRequest(User, Password);
  if (!Result.first) {
    LoginBad(Result.second.toStdString());
    LoginInfo(UiText("Saved sign-in failed. Press Enter or S at the menu for local tools, or L to enter different credentials.", "保存凭证登录失败。按 Enter/S 使用本地工具，或按 L 输入其他账号。"));
  }
  return Result.first;
}

bool RegisterFlow() {
  std::string User;
  std::string Password;
  std::string Confirm;
  if (!AskLine(UiText("Register user name: ", "注册用户名："), false, User))
    return false;
  if (!AskLine(UiText("Register password (at least 6): ", "注册密码（至少 6 位）："), true, Password))
    return false;
  if (!AskLine(UiText("Repeat password: ", "确认密码："), true, Confirm))
    return false;
  if (User.empty() || Password.size() < 6) {
    LoginBad(UiText("User name is required and the password must be at least 6 characters", "用户名不能为空，密码至少 6 位。"));
    return false;
  }
  if (Password != Confirm) {
    LoginBad(UiText("Passwords do not match", "两次密码不一致"));
    return false;
  }
  QJsonObject Body;
  Body["UserName"] = QString::fromStdString(User);
  Body["Password"] = Sha256Hex(QString::fromStdString(Password));
  QJsonObject Response;
  QString Error;
  if (!HttpPostJson("/Register", Body, 6000, &Response, &Error)) {
    LoginBad(UiText("Network error: ", "网络错误：") + Error.toStdString());
    return false;
  }
  if (!Response["success"].toBool()) {
    LoginBad(Response["message"].toString().toStdString());
    return false;
  }
  LoginGood(UiText("Registered successfully: ", "注册成功：") + User);
  return true;
}

} // namespace

bool RunConsoleLoginGate(bool AllowAutoLogin) {
  // Never put a network request in front of the first usable input prompt.
  // Saved automatic credentials are offered explicitly; guest remains instant
  // even when the configured server is unavailable.
  const bool OfferSavedLogin =
      AllowAutoLogin &&
      ConfigurationValue("Account", "AutoLogin", false).toBool() &&
      ConfigurationValue("Account", "SaveCredentials", false).toBool() &&
      !ConfigurationValue("Account", "UserName", "").toString().isEmpty() &&
      !ConfigurationValue("Account", "Password", "").toString().isEmpty();

  for (;;) {
    WriteConsoleLine("");
    const auto Heading = SectionHeading(UiText("SESSION / Choose how to continue", "会话 / 选择进入方式"));
    WriteConsoleText(Heading.data(), Heading.size());
    // Wrap before painting: SGR bytes would otherwise consume layout cells.
    const auto MenuLine = [](const std::string &Text, TuiTone Tone) {
      for (const auto &Line : WrapText(Text, TerminalColumns() - 1, "  "))
        WriteConsoleLine(Paint(Line, Tone));
    };
    WriteConsoleLine("  " + Paint("[Enter / S]", TuiTone::Title) + "  " +
                     UiText("Guest / local tools", "访客 / 本地工具"));
    const std::string Options = Paint(UiText("[L] Sign in", "[L] ??"), TuiTone::Success) + "   " +
        Paint(UiText("[R] Register", "[R] ??"), TuiTone::Accent) + "   " +
        Paint(UiText("[Q] Exit", "[Q] ??"), TuiTone::Muted);
    for (const auto &Line : TerminalWrapStyled(Options, TerminalColumns() - 3)) WriteConsoleLine("  " + Line);
    if (OfferSavedLogin)
      MenuLine(UiText("[A] Use saved sign-in (network request)",
                      "[A] ?????????????"), TuiTone::Warning);
    MenuLine(UiText("Guest mode keeps local tools available. Account and Chat need sign-in.",
                    "访客可使用本地工具，Account 和 Chat 需要登录。"), TuiTone::Muted);
    std::string Choice;
    if (!AskLine(UiText("  Continue [guest]: ", "  继续 [默认访客]: "), false, Choice)) return false;
    const std::string Action = LowerAscii(TrimAscii(Choice));
    if (Action.empty() || Action == "s" || Action == "skip" || Action == "g" ||
        Action == "guest") {
      Account = {};
      NotifyAccountSessionChanged();
      MarkMutated();
      LoginInfo(
          UiText("Guest session ready. Type 'login' whenever you want to sign in.", "已进入访客会话，可随时输入 login 登录。"));
      return true;
    }
    if (Action == "q" || Action == "quit" || Action == "exit")
      return false;
    if (Action == "a" && OfferSavedLogin) {
      if (TryConsoleAutoLogin())
        return true;
      continue;
    }
    if (Action == "r" || Action == "register") {
      RegisterFlow();
      continue;
    }
    if (Action == "?" || Action == "h" || Action == "help")
      continue;
    if (Action != "l" && Action != "login") {
      LoginBad(UiText("Choose Enter/S for guest, L to sign in, R to register, or Q to exit.", "按 Enter/S 进入访客，L 登录，R 注册，Q 退出。"));
      continue;
    }
    std::string User;
    std::string Password;
    if (!AskLine(UiText("Login: ", "用户名："), false, User))
      continue;
    if (TrimAscii(User).empty()) {
      LoginBad(UiText("User name cannot be empty", "用户名不能为空"));
      continue;
    }
    if (!AskLine(UiText("Password: ", "密码："), true, Password))
      continue;
    if (Password.empty()) {
      LoginBad(UiText("Password cannot be empty", "密码不能为空"));
      continue;
    }

    LoginInfo(UiText("Signing in ...", "正在登录…"));
    const auto Result = LoginRequest(QString::fromStdString(TrimAscii(User)),
                                     QString::fromStdString(Password));
    if (Result.first) {
      LoginGood(Result.second.toStdString());
      return true;
    }
    LoginBad(Result.second.toStdString());
  }
}

} // namespace AegisNT::Tui
