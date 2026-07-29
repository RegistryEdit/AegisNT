#pragma once

#include <QByteArray>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QString>
#include <QStringList>
#include <bcrypt.h>
#include <map>
#include <mscat.h>
#include <mutex>
#include <sddl.h>
#include <softpub.h>
#include <vector>
#include <windows.h>
#include <wintrust.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

struct UserFileTrustInfo {
  QString Sha256;
  QString SignatureKind;
  QString Signer;
  LONG TrustStatus = TRUST_E_NOSIGNATURE;
  bool Trusted = false;
};

struct UserTokenEntry {
  QString Category;
  QString Name;
  QString Sid;
  QString Attributes;
};

struct UserTokenInfo {
  QString User;
  QString UserSid;
  QString Integrity;
  QString AppContainerSid;
  bool Elevated = false;
  bool AppContainer = false;
  DWORD Error = ERROR_SUCCESS;
  std::vector<UserTokenEntry> Entries;
};

inline QString UserSidString(PSID Sid) {
  if (!Sid || !IsValidSid(Sid))
    return {};
  PWSTR Text = nullptr;
  const QString Result = ConvertSidToStringSidW(Sid, &Text)
                             ? QString::fromWCharArray(Text)
                             : QString();
  if (Text)
    LocalFree(Text);
  return Result;
}

inline QString UserSidAccount(PSID Sid) {
  if (!Sid || !IsValidSid(Sid))
    return {};
  DWORD NameLength = 0, DomainLength = 0;
  SID_NAME_USE Use{};
  LookupAccountSidW(nullptr, Sid, nullptr, &NameLength, nullptr, &DomainLength,
                    &Use);
  std::vector<WCHAR> Name(NameLength + 1), Domain(DomainLength + 1);
  if (!LookupAccountSidW(nullptr, Sid, Name.data(), &NameLength, Domain.data(),
                         &DomainLength, &Use))
    return UserSidString(Sid);
  const QString Account = QString::fromWCharArray(Name.data());
  const QString DomainName = QString::fromWCharArray(Domain.data());
  return DomainName.isEmpty() ? Account : DomainName + "\\" + Account;
}

inline QString UserGroupAttributes(DWORD Attributes) {
  QStringList Values;
  if (Attributes & SE_GROUP_ENABLED)
    Values << "Enabled";
  if (Attributes & SE_GROUP_ENABLED_BY_DEFAULT)
    Values << "Default";
  if (Attributes & SE_GROUP_MANDATORY)
    Values << "Mandatory";
  if (Attributes & SE_GROUP_USE_FOR_DENY_ONLY)
    Values << "DenyOnly";
  if (Attributes & SE_GROUP_INTEGRITY)
    Values << "Integrity";
  if ((Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID)
    Values << "LogonId";
  if (Attributes & SE_GROUP_RESOURCE)
    Values << "Resource";
  return Values.isEmpty() ? "None" : Values.join(" | ");
}

inline QString UserPrivilegeAttributes(DWORD Attributes) {
  QStringList Values;
  if (Attributes & SE_PRIVILEGE_ENABLED)
    Values << "Enabled";
  if (Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT)
    Values << "DefaultEnabled";
  if (Attributes & SE_PRIVILEGE_REMOVED)
    Values << "Removed";
  return Values.isEmpty() ? "None" : Values.join(" | ");
}

inline bool QueryUserTokenInfo(DWORD ProcessId, UserTokenInfo &Result) {
  Result = {};
  HANDLE Process =
      OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);
  if (!Process) {
    Result.Error = GetLastError();
    return false;
  }
  HANDLE Token = nullptr;
  if (!OpenProcessToken(Process, TOKEN_QUERY, &Token)) {
    Result.Error = GetLastError();
    CloseHandle(Process);
    return false;
  }
  const auto Query = [Token](TOKEN_INFORMATION_CLASS Class,
                             std::vector<BYTE> &Buffer) {
    DWORD Size = 0;
    GetTokenInformation(Token, Class, nullptr, 0, &Size);
    if (!Size)
      return false;
    Buffer.resize(Size);
    return GetTokenInformation(Token, Class, Buffer.data(), Size, &Size) ==
           TRUE;
  };
  std::vector<BYTE> Buffer;
  if (Query(TokenUser, Buffer)) {
    auto User = reinterpret_cast<TOKEN_USER *>(Buffer.data());
    Result.UserSid = UserSidString(User->User.Sid);
    Result.User = UserSidAccount(User->User.Sid);
  }
  if (Query(TokenGroups, Buffer)) {
    auto Groups = reinterpret_cast<TOKEN_GROUPS *>(Buffer.data());
    for (DWORD Index = 0; Index < Groups->GroupCount; ++Index)
      Result.Entries.push_back(
          {"Group", UserSidAccount(Groups->Groups[Index].Sid),
           UserSidString(Groups->Groups[Index].Sid),
           UserGroupAttributes(Groups->Groups[Index].Attributes)});
  }
  if (Query(TokenPrivileges, Buffer)) {
    auto Privileges = reinterpret_cast<TOKEN_PRIVILEGES *>(Buffer.data());
    for (DWORD Index = 0; Index < Privileges->PrivilegeCount; ++Index) {
      DWORD Length = 0;
      LookupPrivilegeNameW(nullptr, &Privileges->Privileges[Index].Luid,
                           nullptr, &Length);
      std::vector<WCHAR> Name(Length + 1);
      if (!LookupPrivilegeNameW(nullptr, &Privileges->Privileges[Index].Luid,
                                Name.data(), &Length))
        Name[0] = L'\0';
      Result.Entries.push_back(
          {"Privilege",
           QString::fromWCharArray(Name.data()),
           {},
           UserPrivilegeAttributes(Privileges->Privileges[Index].Attributes)});
    }
  }
  if (Query(TokenIntegrityLevel, Buffer)) {
    auto Integrity = reinterpret_cast<TOKEN_MANDATORY_LABEL *>(Buffer.data());
    const DWORD Rid =
        *GetSidSubAuthority(Integrity->Label.Sid,
                            *GetSidSubAuthorityCount(Integrity->Label.Sid) - 1);
    Result.Integrity = Rid >= SECURITY_MANDATORY_PROTECTED_PROCESS_RID
                           ? "Protected"
                       : Rid >= SECURITY_MANDATORY_SYSTEM_RID ? "System"
                       : Rid >= SECURITY_MANDATORY_HIGH_RID   ? "High"
                       : Rid >= SECURITY_MANDATORY_MEDIUM_RID ? "Medium"
                       : Rid >= SECURITY_MANDATORY_LOW_RID    ? "Low"
                                                              : "Untrusted";
  }
  TOKEN_ELEVATION Elevation{};
  DWORD Returned = 0;
  if (GetTokenInformation(Token, TokenElevation, &Elevation, sizeof(Elevation),
                          &Returned))
    Result.Elevated = Elevation.TokenIsElevated != 0;
  DWORD IsAppContainer = 0;
  if (GetTokenInformation(Token, TokenIsAppContainer, &IsAppContainer,
                          sizeof(IsAppContainer), &Returned))
    Result.AppContainer = IsAppContainer != 0;
  if (Query(TokenAppContainerSid, Buffer)) {
    auto Information =
        reinterpret_cast<TOKEN_APPCONTAINER_INFORMATION *>(Buffer.data());
    Result.AppContainerSid = UserSidString(Information->TokenAppContainer);
  }
  if (Query(TokenCapabilities, Buffer)) {
    auto Capabilities = reinterpret_cast<TOKEN_GROUPS *>(Buffer.data());
    for (DWORD Index = 0; Index < Capabilities->GroupCount; ++Index)
      Result.Entries.push_back(
          {"Capability", UserSidAccount(Capabilities->Groups[Index].Sid),
           UserSidString(Capabilities->Groups[Index].Sid),
           UserGroupAttributes(Capabilities->Groups[Index].Attributes)});
  }
  CloseHandle(Token);
  CloseHandle(Process);
  Result.Error = ERROR_SUCCESS;
  return true;
}

inline LONG VerifyUserFileTrust(const QString &FilePath, QString *Signer,
                                bool Catalog) {
  const std::wstring Path = QDir::toNativeSeparators(FilePath).toStdWString();
  GUID Policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
  WINTRUST_DATA Data{};
  Data.cbStruct = sizeof(Data);
  Data.dwUIChoice = WTD_UI_NONE;
  Data.fdwRevocationChecks = WTD_REVOKE_NONE;
  Data.dwStateAction = WTD_STATEACTION_VERIFY;
  Data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
  WINTRUST_FILE_INFO FileInfo{};
  WINTRUST_CATALOG_INFO CatalogInfo{};
  HCATADMIN Admin = nullptr;
  HCATINFO CatalogContext = nullptr;
  HANDLE File = INVALID_HANDLE_VALUE;
  std::vector<BYTE> Hash;
  std::wstring MemberTag;
  QByteArray Hex;
  CATALOG_INFO CatalogPath{};
  if (!Catalog) {
    FileInfo.cbStruct = sizeof(FileInfo);
    FileInfo.pcwszFilePath = Path.c_str();
    Data.dwUnionChoice = WTD_CHOICE_FILE;
    Data.pFile = &FileInfo;
  } else {
    File = CreateFileW(Path.c_str(), GENERIC_READ,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (File == INVALID_HANDLE_VALUE)
      return TRUST_E_NOSIGNATURE;
    if (!CryptCATAdminAcquireContext2(&Admin, nullptr, BCRYPT_SHA256_ALGORITHM,
                                      nullptr, 0)) {
      CloseHandle(File);
      return TRUST_E_NOSIGNATURE;
    }
    DWORD HashSize = 0;
    CryptCATAdminCalcHashFromFileHandle2(Admin, File, &HashSize, nullptr, 0);
    Hash.resize(HashSize);
    if (!HashSize || !CryptCATAdminCalcHashFromFileHandle2(
                         Admin, File, &HashSize, Hash.data(), 0))
      goto CatalogCleanup;
    CatalogContext = CryptCATAdminEnumCatalogFromHash(Admin, Hash.data(),
                                                      HashSize, 0, nullptr);
    if (!CatalogContext)
      goto CatalogCleanup;
    CatalogPath.cbStruct = sizeof(CatalogPath);
    if (!CryptCATCatalogInfoFromContext(CatalogContext, &CatalogPath, 0))
      goto CatalogCleanup;
    Hex = QByteArray(reinterpret_cast<const char *>(Hash.data()), HashSize)
              .toHex()
              .toUpper();
    MemberTag = QString::fromLatin1(Hex).toStdWString();
    CatalogInfo.cbStruct = sizeof(CatalogInfo);
    CatalogInfo.pcwszCatalogFilePath = CatalogPath.wszCatalogFile;
    CatalogInfo.pcwszMemberFilePath = Path.c_str();
    CatalogInfo.pcwszMemberTag = MemberTag.c_str();
    CatalogInfo.hMemberFile = File;
    Data.dwUnionChoice = WTD_CHOICE_CATALOG;
    Data.pCatalog = &CatalogInfo;
  }
  {
    const LONG Status = WinVerifyTrust(nullptr, &Policy, &Data);
    if (Status == ERROR_SUCCESS && Signer) {
      auto Provider = WTHelperProvDataFromStateData(Data.hWVTStateData);
      auto Chain = Provider
                       ? WTHelperGetProvSignerFromChain(Provider, 0, FALSE, 0)
                       : nullptr;
      if (Chain && Chain->csCertChain && Chain->pasCertChain[0].pCert) {
        WCHAR Name[512]{};
        CertGetNameStringW(Chain->pasCertChain[0].pCert,
                           CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, Name,
                           512);
        *Signer = QString::fromWCharArray(Name);
      }
    }
    Data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &Policy, &Data);
    if (CatalogContext)
      CryptCATAdminReleaseCatalogContext(Admin, CatalogContext, 0);
    if (Admin)
      CryptCATAdminReleaseContext(Admin, 0);
    if (File != INVALID_HANDLE_VALUE)
      CloseHandle(File);
    return Status;
  }
CatalogCleanup:
  if (CatalogContext)
    CryptCATAdminReleaseCatalogContext(Admin, CatalogContext, 0);
  if (Admin)
    CryptCATAdminReleaseContext(Admin, 0);
  if (File != INVALID_HANDLE_VALUE)
    CloseHandle(File);
  return TRUST_E_NOSIGNATURE;
}

inline UserFileTrustInfo QueryUserFileTrust(const QString &FilePath) {
  UserFileTrustInfo Result;
  QFile File(FilePath);
  if (File.open(QIODevice::ReadOnly)) {
    QCryptographicHash Hash(QCryptographicHash::Sha256);
    while (!File.atEnd())
      Hash.addData(File.read(1024 * 1024));
    Result.Sha256 = QString::fromLatin1(Hash.result().toHex().toUpper());
  }
  Result.TrustStatus = VerifyUserFileTrust(FilePath, &Result.Signer, false);
  if (Result.TrustStatus == ERROR_SUCCESS) {
    Result.Trusted = true;
    Result.SignatureKind = "Embedded";
    return Result;
  }
  Result.TrustStatus = VerifyUserFileTrust(FilePath, &Result.Signer, true);
  Result.Trusted = Result.TrustStatus == ERROR_SUCCESS;
  Result.SignatureKind = Result.Trusted ? "Catalog" : "Unsigned/Untrusted";
  return Result;
}

inline UserFileTrustInfo QueryUserFileTrustCached(const QString &FilePath) {
  struct CacheEntry {
    qint64 Size = -1;
    qint64 Modified = -1;
    UserFileTrustInfo Trust;
  };
  static std::mutex Lock;
  static std::map<std::wstring, CacheEntry> Cache;
  const QFileInfo Info(FilePath);
  const std::wstring Key =
      QDir::toNativeSeparators(Info.absoluteFilePath()).toStdWString();
  const qint64 Size = Info.exists() ? Info.size() : -1;
  const qint64 Modified =
      Info.exists() ? Info.lastModified().toMSecsSinceEpoch() : -1;
  {
    std::lock_guard Guard(Lock);
    const auto Existing = Cache.find(Key);
    if (Existing != Cache.end() && Existing->second.Size == Size &&
        Existing->second.Modified == Modified)
      return Existing->second.Trust;
  }
  UserFileTrustInfo Trust = QueryUserFileTrust(FilePath);
  {
    std::lock_guard Guard(Lock);
    Cache[Key] = {Size, Modified, Trust};
  }
  return Trust;
}

inline QString NormalizeUserDriverPath(QString Path) {
  Path = QDir::fromNativeSeparators(Path.trimmed());
  if (Path.startsWith("\\??\\"))
    Path.remove(0, 4);
  if (Path.startsWith("/??/"))
    Path.remove(0, 4);
  const QString Windows = QDir::fromNativeSeparators(
      qEnvironmentVariable("SystemRoot", "C:/Windows"));
  if (Path.startsWith("\\SystemRoot\\", Qt::CaseInsensitive) ||
      Path.startsWith("/SystemRoot/", Qt::CaseInsensitive))
    Path = Windows + Path.mid(11);
  else if (Path.startsWith("System32/", Qt::CaseInsensitive))
    Path = Windows + "/" + Path;
  return QDir::toNativeSeparators(QDir::cleanPath(Path));
}
