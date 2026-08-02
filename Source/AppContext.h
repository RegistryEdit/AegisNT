#pragma once

#include <QJsonObject>
#include <QString>

#include <atomic>

namespace AegisNT {

struct AppContext {
  QJsonObject Configuration;
  QJsonObject ChineseTranslations;
  QString ActiveLanguage = QStringLiteral("en_US");

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

} // namespace AegisNT
