// ============================================================
// 应用级共享上下文：配置、翻译表、账号会话、模块运行状态与
// 事件监听器。单例经 ApplicationContext() 访问，页面与 .inc
// 之间通过它解耦通信。
// ============================================================
#pragma once

#include <QJsonObject>
#include <QMap>
#include <QString>

#include <atomic>
#include <functional>
#include <vector>

namespace AegisNT {

struct AccountSession {
  bool IsLoggedIn = false;
  QString UserName;
  QString Title;
  int UserType = 0;
  QString Token;
};

struct AppContext {
  QJsonObject Configuration;
  // 多语言翻译表：按语言码索引（"en_US"/"zh_CN"），值对应当前语言文件
  // Data/<lang>.json 的 translations 对象（key 为英文原文）。
  QMap<QString, QJsonObject> LanguageResources;
  QString ActiveLanguage = QStringLiteral("en_US");
  AccountSession Account;
  std::vector<std::function<bool()>> AccountSessionListeners;
  std::vector<std::function<bool(const QString &, const QString &)>>
      UserTitleChangedListeners;

  bool ModulesScanned = false;
  std::atomic_bool ModuleRunning = false;
  std::atomic_bool DriverShutdownPerformed = false;
  QString RunningModulePath;
  QString HandleLabPresetSearch;
  quint64 HandleLabPresetPid = 0;
  QString ConsoleTranscript =
      QStringLiteral("[*] Console ready. Module output will appear here.\n");
  QString ModuleTranscript;
};

AppContext &ApplicationContext();
void NotifyAccountSessionChanged();
void NotifyUserTitleChanged(const QString &UserName, const QString &Title);

} // namespace AegisNT
