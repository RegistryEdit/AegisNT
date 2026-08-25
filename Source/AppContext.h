#pragma once

#include <QJsonObject>
#include <QString>

#include <atomic>
#include <functional>
#include <vector>

namespace AegisNT {

struct AccountSession {
  bool IsLoggedIn = false;
  QString UserName;
  int UserType = 0;
  QString Token;
};

struct AppContext {
  QJsonObject Configuration;
  QJsonObject ChineseTranslations;
  QString ActiveLanguage = QStringLiteral("en_US");
  AccountSession Account;
  std::vector<std::function<bool()>> AccountSessionListeners;

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

} // namespace AegisNT
