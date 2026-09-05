#pragma once

#include "../Platform/AegisCoreCall.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QString>

#include <dbghelp.h>
#include <algorithm>
#include <mutex>
#include <vector>

namespace AegisNT::KernelResearch {

struct AddressInfo {
  quint64 Address = 0;
  quint64 ModuleBase = 0;
  quint64 Rva = 0;
  quint64 Displacement = 0;
  QString Module;
  QString Path;
  QString Symbol;
  QString Status = "OutsideModule";
};

struct WriteTransaction {
  QString Id;
  QDateTime CreatedUtc;
  quint64 Address = 0;
  QByteArray Before;
  QByteArray After;
  AddressInfo Owner;
  bool Verified = false;
  bool RolledBack = false;
};

inline std::vector<MDV2_RECORD> QueryAll(DWORD Ioctl,
                                         const QString &Path = {}) {
  std::vector<MDV2_RECORD> Result;
  MDV2_QUERY_INPUT Query{};
  Query.Size = sizeof(Query);
  Query.Version = 2;
  Query.MaxEntries = 512;
  if (!Path.isEmpty())
    wcsncpy_s(Query.Path, Path.toStdWString().c_str(), _TRUNCATE);
  for (int Page = 0; Page < 256; ++Page) {
    std::vector<MDV2_RECORD> Records;
    MDV2_LIST_HEADER Header{};
    if (!QueryAegisCoreRecordsV2(Ioctl, Query, Records, &Header))
      break;
    Result.insert(Result.end(), Records.begin(), Records.end());
    if (Header.NextCursor == 0)
      break;
    Query.Cursor = Header.NextCursor;
  }
  return Result;
}

class SymbolService {
public:
  static SymbolService &Instance() {
    static SymbolService Value;
    return Value;
  }

  bool Initialize(QString *Error = nullptr) {
    std::scoped_lock Lock(Mutex_);
    if (Initialized_)
      return true;
    CachePath_ = QDir(QCoreApplication::applicationDirPath())
                     .filePath("Data/SymbolCache");
    QDir().mkpath(CachePath_);
    const QString Search = QString("srv*%1*https://msdl.microsoft.com/download/symbols")
                               .arg(CachePath_);
    SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME | SYMOPT_FAIL_CRITICAL_ERRORS);
    Initialized_ = SymInitializeW(GetCurrentProcess(),
                                  reinterpret_cast<PCWSTR>(Search.utf16()),
                                  FALSE) != FALSE;
    if (!Initialized_ && Error)
      *Error = QString("SymInitialize failed (%1)").arg(GetLastError());
    return Initialized_;
  }

  QString CachePath() const { return CachePath_; }

  void ReloadModules(const std::vector<MDV2_RECORD> &Modules) {
    std::scoped_lock Lock(Mutex_);
    if (!Initialized_)
      return;
    SymRefreshModuleList(GetCurrentProcess());
    for (const auto &Record : Modules) {
      const QString Path = QString::fromWCharArray(Record.Path);
      const QString Name = QString::fromWCharArray(Record.Name);
      SymLoadModuleExW(GetCurrentProcess(), nullptr,
                       Path.isEmpty() ? nullptr : reinterpret_cast<PCWSTR>(Path.utf16()),
                       Name.isEmpty() ? nullptr : reinterpret_cast<PCWSTR>(Name.utf16()),
                       Record.Address, static_cast<DWORD>(Record.SizeBytes),
                       nullptr, 0);
    }
  }

  QString Resolve(quint64 Address, quint64 *Displacement = nullptr) {
    std::scoped_lock Lock(Mutex_);
    if (!Initialized_)
      return {};
    alignas(SYMBOL_INFO) char Storage[sizeof(SYMBOL_INFO) + MAX_SYM_NAME]{};
    auto *Info = reinterpret_cast<SYMBOL_INFO *>(Storage);
    Info->SizeOfStruct = sizeof(SYMBOL_INFO);
    Info->MaxNameLen = MAX_SYM_NAME;
    DWORD64 Delta = 0;
    if (!SymFromAddr(GetCurrentProcess(), Address, &Delta, Info))
      return {};
    if (Displacement)
      *Displacement = Delta;
    return QString::fromLatin1(Info->Name);
  }

private:
  SymbolService() = default;
  std::mutex Mutex_;
  bool Initialized_ = false;
  QString CachePath_;
};

inline AddressInfo ResolveAddress(quint64 Address,
                                  const std::vector<MDV2_RECORD> &Modules) {
  AddressInfo Info;
  Info.Address = Address;
  for (const auto &Module : Modules) {
    if (Address < Module.Address || Address >= Module.Address + Module.SizeBytes)
      continue;
    Info.ModuleBase = Module.Address;
    Info.Rva = Address - Module.Address;
    Info.Module = QString::fromWCharArray(Module.Name);
    Info.Path = QString::fromWCharArray(Module.Path);
    Info.Status = "Resolved";
    break;
  }
  Info.Symbol = SymbolService::Instance().Resolve(Address, &Info.Displacement);
  if (Info.Status == "Resolved" && Info.Symbol.isEmpty())
    Info.Status = "ModuleOnly";
  return Info;
}

inline QString Hex(quint64 Value) {
  return QString("0x%1").arg(Value, 16, 16, QLatin1Char('0')).toUpper();
}

inline QJsonObject AddressJson(const AddressInfo &Info) {
  return {{"address", Hex(Info.Address)}, {"module", Info.Module},
          {"moduleBase", Hex(Info.ModuleBase)}, {"rva", Hex(Info.Rva)},
          {"symbol", Info.Symbol}, {"displacement", Hex(Info.Displacement)},
          {"status", Info.Status}};
}

} // namespace AegisNT::KernelResearch
