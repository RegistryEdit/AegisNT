// ============================================================
// AegisNT 主程序入口（单翻译单元）
// ------------------------------------------------------------
// 本文件采用 unity build 方式组织：通过 #include 并入 Source/UI/Pages/
// 各页面实现、Source/Core 的配置/负载/模块运行时、Platform/ 的
// 驱动调用封装等，最终形成单一 main() 可执行文件。
// 全局共享状态集中在 AegisNT::ApplicationContext()（见
// Source/AppContext.h），页面之间通过该上下文与事件监听器解耦。
// ============================================================
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QCompleter>
#include <QCryptographicHash>
#include <QCloseEvent>
#include <QDateTime>
#include <QDesktopServices>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFileSystemModel>
#include <QFont>
#include <QFrame>
#include <QGridLayout>
#include <QHeaderView>
#include <QHostAddress>
#include <QImageReader>
#include <QInputDialog>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QListWidget>
#include <QLocale>
#include <QMessageBox>
#include <QMetaProperty>
#include <QMoveEvent>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QEventLoop>
#include <QMouseEvent>
#include <QWindow>
#include <QStringConverter>
#include <functional>
#include <QLineEdit>
#include <QLocalServer>
#include <QLocalSocket>
#include <QPaintEvent>
#include <QPainter>
#include <QPixmap>
#include <QPointer>
#include <QProcess>
#include <QProcessEnvironment>
#include <QProgressBar>
#include <QAbstractNativeEventFilter>
#include <QKeySequenceEdit>
#include <QRandomGenerator>
#include <QUuid>
#include <QRegularExpression>
#include <QSaveFile>
#include <QScreen>
#include <QSet>
#include <QSystemTrayIcon>
#include <QMessageAuthenticationCode>
#include <QShowEvent>
#include <QSignalBlocker>
#include <QSplitter>
#include <QStackedWidget>
#include <QStandardPaths>
#include <QStorageInfo>
#include <QStyle>
#include <QSysInfo>
#include <QTabWidget>
#include <QTableWidgetItem>
#include <QTcpSocket>
#include <QTextCharFormat>
#include <QTextCursor>
#include <QTextEdit>
#include <QTextStream>
#include <QThread>
#include <QTimer>
#include <QTreeView>
#include <QTreeWidget>
#include <QUrl>
#include <QMenu>
#include <QVBoxLayout>
#include <QVersionNumber>

#include <QFluent/CardWidget.h>
#include <QFluent/CheckBox.h>
#include <QFluent/ComboBox.h>
#include <QFluent/DateTime/DatePicker.h>
#include <QFluent/DateTime/TimePicker.h>
#include <QFluent/Dialog/ColorDialog.h>
#include <QFluent/Dialog/MessageBoxBase.h>
#include <QFluent/Dialog/MessageDialog.h>
#include <QFluent/Menu/RoundMenu.h>
#include <QFluent/FluentIcon.h>
#include <QFluent/IconWidget.h>
#include <QFluent/InfoBar.h>
#include <QFluent/Label.h>
#include <QFluent/LineEdit.h>
#include <QFluent/ListView.h>
#include <QFluent/Menu/RoundMenu.h>
#include <QFluent/MultiViewComboBox.h>
#include <QFluent/Navigation/NavigationPanel.h>
#include <QFluent/Progress/IndeterminateProgressRing.h>
#include <QFluent/PushButton.h>
#include <QFluent/ScrollArea.h>
#include <QFluent/ScrollBar.h>
#include <QFluent/Slider.h>
#include <QFluent/SpinBox.h>
#include <QFluent/Splitter.h>
#include <QFluent/StackedWidget.h>
#include <QFluent/SwitchButton.h>
#include <QFluent/TabBar.h>
#include <QFluent/TableView.h>
#include <QFluent/TextEdit.h>
#include <QFluent/Theme.h>
#include <QFluent/ToolButton.h>

#include <QWKWidgets/widgetwindowagent.h>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <format>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <dwmapi.h>
#include <winioctl.h>
#include <winternl.h>
#include <dbghelp.h>
#include <wtsapi32.h>
#include <netfw.h>
#include <sddl.h>
#include <tlhelp32.h>
#include <userenv.h>
#include <wincodec.h>
#ifdef ERROR
#undef ERROR
#endif

#include "Module/ModuleBase.h"
#include "Module/ModuleTypes.h"
#include "Module/OutputCapture.h"
#include "Platform/AegisDiskCall.h"
#include "Platform/DllInject.h"
#include "Platform/DllMonitor.h"
#include "Platform/DriverControl.h"
#include "Platform/ETWMonitor.h"
#include "Platform/GetPEB.h"
#include "Platform/HttpCapture.h"
#include "Platform/AegisSentinelCall.h"
#include "Platform/AegisCoreCall.h"
#include "Platform/NetMon.h"
#include "Platform/ProcessCtl.h"
#include "Platform/UserProcessCtl.h"
#include "Platform/UserSecurityInfo.h"
#include "Source/AppContext.h"
#include "Source/UI/Common/Base/PageBase.h"
#include "Source/UI/Common/Widgets/RefreshControl.h"
#include "Source/UI/Common/Widgets/DebouncedSearchEdit.h"
#include "Source/UI/Pages/KernelResearch.h"
#include "Source/UI/Pages/PageFactory.h"
#include "Source/UI/Pages/PageRegistry.h"
#include <openssl/applink.c>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <io.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Dwmapi.lib")
#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "Userenv.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Windowscodecs.lib")
#pragma comment(lib, "Dbghelp.lib")

namespace {

QImage LoadImageWithWic(const QString &Path) {
  IWICImagingFactory *Factory = nullptr;
  HRESULT Hr =
      CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
                       IID_PPV_ARGS(&Factory));
  if (FAILED(Hr) || !Factory)
    return {};

  IWICBitmapDecoder *Decoder = nullptr;
  Hr = Factory->CreateDecoderFromFilename(
      reinterpret_cast<LPCWSTR>(Path.utf16()), nullptr, GENERIC_READ,
      WICDecodeMetadataCacheOnLoad, &Decoder);
  if (FAILED(Hr) || !Decoder) {
    Factory->Release();
    return {};
  }

  IWICBitmapFrameDecode *Frame = nullptr;
  Hr = Decoder->GetFrame(0, &Frame);
  if (FAILED(Hr) || !Frame) {
    Decoder->Release();
    Factory->Release();
    return {};
  }

  IWICFormatConverter *Converter = nullptr;
  Hr = Factory->CreateFormatConverter(&Converter);
  if (FAILED(Hr) || !Converter) {
    Frame->Release();
    Decoder->Release();
    Factory->Release();
    return {};
  }

  Hr = Converter->Initialize(Frame, GUID_WICPixelFormat32bppPBGRA,
                             WICBitmapDitherTypeNone, nullptr, 0.0,
                             WICBitmapPaletteTypeCustom);
  UINT Width = 0;
  UINT Height = 0;
  if (SUCCEEDED(Hr))
    Hr = Converter->GetSize(&Width, &Height);

  QImage Image;
  if (SUCCEEDED(Hr) && Width > 0 && Height > 0) {
    Image = QImage(static_cast<int>(Width), static_cast<int>(Height),
                   QImage::Format_ARGB32_Premultiplied);
    if (Image.isNull() ||
        FAILED(Converter->CopyPixels(
            nullptr, static_cast<UINT>(Image.bytesPerLine()),
            static_cast<UINT>(Image.sizeInBytes()), Image.bits()))) {
      Image = QImage();
    }
  }

  Converter->Release();
  Frame->Release();
  Decoder->Release();
  Factory->Release();
  return Image;
}

#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY 0x0001
#endif

#ifndef STATUS_NO_MORE_ENTRIES
#define STATUS_NO_MORE_ENTRIES ((NTSTATUS)0x8000001AL)
#endif

struct PublicObjectDirectoryInformation {
  UNICODE_STRING Name;
  UNICODE_STRING TypeName;
};

using SystemCallNameMap = std::map<ULONG, QString>;

QString SessionStateText(ULONG State) {
  switch (static_cast<WTS_CONNECTSTATE_CLASS>(State)) {
  case WTSActive:
    return "Active";
  case WTSConnected:
    return "Connected";
  case WTSConnectQuery:
    return "ConnectQuery";
  case WTSShadow:
    return "Shadow";
  case WTSDisconnected:
    return "Disconnected";
  case WTSIdle:
    return "Idle";
  case WTSListen:
    return "Listen";
  case WTSReset:
    return "Reset";
  case WTSDown:
    return "Down";
  case WTSInit:
    return "Init";
  default:
    return QString("State %1").arg(State);
  }
}

ULONG ParsePortValue(const QString &Ports) {
  if (Ports.isEmpty())
    return 0;
  const QString FirstToken =
      Ports.split(',', Qt::SkipEmptyParts).value(0).trimmed();
  if (FirstToken.isEmpty() || FirstToken == "*" || FirstToken == "RPC" ||
      FirstToken == "IPHTTPS")
    return 0;
  const QString RangeStart =
      FirstToken.split('-', Qt::SkipEmptyParts).value(0).trimmed();
  bool Ok = false;
  const uint Port = RangeStart.toUInt(&Ok);
  return Ok ? static_cast<ULONG>(Port) : 0;
}

std::map<ULONG, ULONG> BuildSessionProcessCounts() {
  std::map<ULONG, ULONG> Counts;
  HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (Snapshot == INVALID_HANDLE_VALUE)
    return Counts;

  PROCESSENTRY32W Entry{};
  Entry.dwSize = sizeof(Entry);
  if (Process32FirstW(Snapshot, &Entry)) {
    do {
      DWORD SessionId = 0;
      if (ProcessIdToSessionId(Entry.th32ProcessID, &SessionId))
        ++Counts[static_cast<ULONG>(SessionId)];
    } while (Process32NextW(Snapshot, &Entry));
  }
  CloseHandle(Snapshot);
  return Counts;
}

bool EnumerateSessionsFallback(
    std::vector<std::tuple<ULONG, ULONG, ULONG, QString>> &Entries) {
  PWTS_SESSION_INFOW Sessions = nullptr;
  DWORD Count = 0;
  if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &Sessions,
                             &Count))
    return false;

  const std::map<ULONG, ULONG> ProcessCounts = BuildSessionProcessCounts();
  for (DWORD Index = 0; Index < Count; ++Index) {
    const WTS_SESSION_INFOW &Session = Sessions[Index];
    QString WinStation = Session.pWinStationName
                             ? QString::fromWCharArray(Session.pWinStationName)
                             : QString();
    if (WinStation.isEmpty()) {
      LPWSTR Buffer = nullptr;
      DWORD Bytes = 0;
      if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,
                                      Session.SessionId, WTSWinStationName,
                                      &Buffer, &Bytes) &&
          Buffer) {
        WinStation = QString::fromWCharArray(Buffer);
        WTSFreeMemory(Buffer);
      }
    }
    Entries.emplace_back(
        static_cast<ULONG>(Session.SessionId),
        static_cast<ULONG>(Session.State),
        ProcessCounts.contains(static_cast<ULONG>(Session.SessionId))
            ? ProcessCounts.at(static_cast<ULONG>(Session.SessionId))
            : 0,
        WinStation);
  }
  WTSFreeMemory(Sessions);
  return true;
}

bool DisconnectSessionFallback(ULONG SessionId, bool Wait = false) {
  return WTSDisconnectSession(WTS_CURRENT_SERVER_HANDLE, SessionId,
                              Wait ? TRUE : FALSE) != FALSE;
}

bool SendSessionMessageFallback(ULONG SessionId, const QString &Title,
                                const QString &Message, ULONG Style,
                                ULONG TimeoutSeconds, bool Wait,
                                DWORD *Response = nullptr) {
  DWORD LocalResponse = 0;
  const BOOL Success = WTSSendMessageW(
      WTS_CURRENT_SERVER_HANDLE, SessionId,
      const_cast<LPWSTR>(reinterpret_cast<LPCWSTR>(Title.utf16())),
      static_cast<DWORD>(Title.size() * sizeof(wchar_t)),
      const_cast<LPWSTR>(reinterpret_cast<LPCWSTR>(Message.utf16())),
      static_cast<DWORD>(Message.size() * sizeof(wchar_t)), Style,
      TimeoutSeconds, &LocalResponse, Wait ? TRUE : FALSE);
  if (Response)
    *Response = LocalResponse;
  return Success != FALSE;
}

bool LaunchProcessInSession(ULONG SessionId, const QString &ExecutablePath,
                            const QString &Arguments, bool ShowWindow,
                            DWORD *ProcessId = nullptr) {
  if (ProcessId)
    *ProcessId = 0;
  const QString Path = ExecutablePath.trimmed();
  if (Path.isEmpty() || !QFileInfo::exists(Path)) {
    SetLastError(ERROR_FILE_NOT_FOUND);
    return false;
  }

  HANDLE ImpersonationToken = nullptr;
  if (!WTSQueryUserToken(SessionId, &ImpersonationToken))
    return false;

  HANDLE PrimaryToken = nullptr;
  const BOOL DuplicateOk = DuplicateTokenEx(
      ImpersonationToken,
      TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY |
          TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
      nullptr, SecurityIdentification, TokenPrimary, &PrimaryToken);
  const DWORD DuplicateError = DuplicateOk ? ERROR_SUCCESS : GetLastError();
  CloseHandle(ImpersonationToken);
  if (!DuplicateOk) {
    SetLastError(DuplicateError);
    return false;
  }

  STARTUPINFOW StartupInfo{};
  StartupInfo.cb = sizeof(StartupInfo);
  StartupInfo.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");
  StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
  StartupInfo.wShowWindow = ShowWindow ? SW_SHOWNORMAL : SW_HIDE;

  PROCESS_INFORMATION ProcessInfo{};
  QString CommandLine = QDir::toNativeSeparators(Path);
  CommandLine = "\"" + CommandLine + "\"";
  if (!Arguments.trimmed().isEmpty())
    CommandLine += " " + Arguments.trimmed();
  std::wstring MutableCommandLine = CommandLine.toStdWString();
  std::wstring MutableApplication =
      QDir::toNativeSeparators(Path).toStdWString();

  const BOOL CreateOk = CreateProcessAsUserW(
      PrimaryToken, MutableApplication.c_str(), MutableCommandLine.data(),
      nullptr, nullptr, FALSE, CREATE_NEW_CONSOLE, nullptr, nullptr,
      &StartupInfo, &ProcessInfo);
  const DWORD CreateError = CreateOk ? ERROR_SUCCESS : GetLastError();
  CloseHandle(PrimaryToken);
  if (!CreateOk) {
    SetLastError(CreateError);
    return false;
  }

  if (ProcessId)
    *ProcessId = ProcessInfo.dwProcessId;
  CloseHandle(ProcessInfo.hThread);
  CloseHandle(ProcessInfo.hProcess);
  SetLastError(ERROR_SUCCESS);
  return true;
}

bool EnumerateFirewallRulesFallback(
    std::vector<std::tuple<QString, ULONG, ULONG, ULONG, QString>> &Entries) {
  const HRESULT InitHr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
  const bool CoInitialized = SUCCEEDED(InitHr);
  const bool ComReady = SUCCEEDED(InitHr) || InitHr == RPC_E_CHANGED_MODE;
  if (!ComReady)
    return false;

  INetFwPolicy2 *Policy = nullptr;
  HRESULT Hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr,
                                CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2),
                                reinterpret_cast<void **>(&Policy));
  if (FAILED(Hr)) {
    if (CoInitialized)
      CoUninitialize();
    return false;
  }

  INetFwRules *Rules = nullptr;
  Hr = Policy->get_Rules(&Rules);
  if (FAILED(Hr) || Rules == nullptr) {
    Policy->Release();
    if (CoInitialized)
      CoUninitialize();
    return false;
  }

  IUnknown *EnumUnknown = nullptr;
  Hr = Rules->get__NewEnum(&EnumUnknown);
  if (FAILED(Hr) || EnumUnknown == nullptr) {
    Rules->Release();
    Policy->Release();
    if (CoInitialized)
      CoUninitialize();
    return false;
  }

  IEnumVARIANT *Enum = nullptr;
  Hr = EnumUnknown->QueryInterface(IID_PPV_ARGS(&Enum));
  EnumUnknown->Release();
  if (FAILED(Hr) || Enum == nullptr) {
    Rules->Release();
    Policy->Release();
    if (CoInitialized)
      CoUninitialize();
    return false;
  }

  VARIANT Variant;
  VariantInit(&Variant);
  ULONG Added = 0;
  while (Enum->Next(1, &Variant, nullptr) == S_OK) {
    if (Variant.vt == VT_DISPATCH && Variant.pdispVal != nullptr) {
      INetFwRule *Rule = nullptr;
      if (SUCCEEDED(Variant.pdispVal->QueryInterface(
              __uuidof(INetFwRule), reinterpret_cast<void **>(&Rule))) &&
          Rule != nullptr) {
        BSTR Name = nullptr;
        BSTR LocalPorts = nullptr;
        NET_FW_ACTION Action = NET_FW_ACTION_BLOCK;
        long Protocol = 0;
        VARIANT_BOOL Enabled = VARIANT_FALSE;
        NET_FW_RULE_DIRECTION Direction = NET_FW_RULE_DIR_IN;

        Rule->get_Name(&Name);
        Rule->get_Action(&Action);
        Rule->get_Protocol(&Protocol);
        Rule->get_LocalPorts(&LocalPorts);
        Rule->get_Enabled(&Enabled);
        Rule->get_Direction(&Direction);

        const QString NameText =
            Name ? QString::fromWCharArray(Name) : QString();
        const QString PortsText =
            LocalPorts ? QString::fromWCharArray(LocalPorts) : QString();
        const QString StateText =
            QString("%1 / %2")
                .arg(Enabled == VARIANT_TRUE ? "Enabled" : "Disabled")
                .arg(Direction == NET_FW_RULE_DIR_OUT ? "Outbound" : "Inbound");
        Entries.emplace_back(
            NameText, static_cast<ULONG>(Action == NET_FW_ACTION_ALLOW ? 1 : 0),
            static_cast<ULONG>(Protocol), ParsePortValue(PortsText), StateText);
        ++Added;

        if (Name)
          SysFreeString(Name);
        if (LocalPorts)
          SysFreeString(LocalPorts);
        Rule->Release();
      }
    }
    VariantClear(&Variant);
  }

  Enum->Release();
  Rules->Release();
  Policy->Release();
  if (CoInitialized)
    CoUninitialize();
  return Added > 0;
}

bool WithFirewallPolicy(const std::function<bool(INetFwPolicy2 *)> &Callback) {
  const HRESULT InitHr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
  const bool CoInitialized = SUCCEEDED(InitHr);
  const bool ComReady = SUCCEEDED(InitHr) || InitHr == RPC_E_CHANGED_MODE;
  if (!ComReady)
    return false;
  INetFwPolicy2 *Policy = nullptr;
  const HRESULT Hr = CoCreateInstance(
      __uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
      __uuidof(INetFwPolicy2), reinterpret_cast<void **>(&Policy));
  if (FAILED(Hr) || Policy == nullptr) {
    if (CoInitialized)
      CoUninitialize();
    return false;
  }
  const bool Result = Callback(Policy);
  Policy->Release();
  if (CoInitialized)
    CoUninitialize();
  return Result;
}

bool AddFirewallRuleFallback(const QString &Name, ULONG Action, ULONG Protocol,
                             ULONG Port) {
  return WithFirewallPolicy([&](INetFwPolicy2 *Policy) {
    INetFwRules *Rules = nullptr;
    if (FAILED(Policy->get_Rules(&Rules)) || Rules == nullptr)
      return false;

    INetFwRule *Rule = nullptr;
    const HRESULT CreateHr = CoCreateInstance(
        __uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER,
        __uuidof(INetFwRule), reinterpret_cast<void **>(&Rule));
    if (FAILED(CreateHr) || Rule == nullptr) {
      Rules->Release();
      return false;
    }

    const std::wstring RuleName = Name.toStdWString();
    const std::wstring PortText = std::to_wstring(Port);
    BSTR NameBstr = SysAllocString(RuleName.c_str());
    BSTR PortBstr = SysAllocString(PortText.c_str());
    BSTR DescriptionBstr = SysAllocString(L"AegisNT firewall rule");
    Rule->put_Name(NameBstr);
    Rule->put_Description(DescriptionBstr);
    Rule->put_Protocol(static_cast<long>(Protocol));
    Rule->put_LocalPorts(PortBstr);
    Rule->put_Action(Action == 0 ? NET_FW_ACTION_BLOCK : NET_FW_ACTION_ALLOW);
    Rule->put_Direction(NET_FW_RULE_DIR_IN);
    Rule->put_Profiles(NET_FW_PROFILE2_ALL);
    Rule->put_Enabled(VARIANT_TRUE);
    const HRESULT AddHr = Rules->Add(Rule);

    SysFreeString(NameBstr);
    SysFreeString(PortBstr);
    SysFreeString(DescriptionBstr);
    Rule->Release();
    Rules->Release();
    return SUCCEEDED(AddHr);
  });
}

bool RemoveFirewallRuleFallback(const QString &Name) {
  return WithFirewallPolicy([&](INetFwPolicy2 *Policy) {
    INetFwRules *Rules = nullptr;
    if (FAILED(Policy->get_Rules(&Rules)) || Rules == nullptr)
      return false;
    const std::wstring RuleName = Name.toStdWString();
    BSTR NameBstr = SysAllocString(RuleName.c_str());
    const HRESULT Hr = Rules->Remove(NameBstr);
    SysFreeString(NameBstr);
    Rules->Release();
    return SUCCEEDED(Hr);
  });
}

bool SetFirewallRuleEnabledFallback(const QString &Name, bool Enabled) {
  return WithFirewallPolicy([&](INetFwPolicy2 *Policy) {
    INetFwRules *Rules = nullptr;
    if (FAILED(Policy->get_Rules(&Rules)) || Rules == nullptr)
      return false;
    const std::wstring RuleName = Name.toStdWString();
    BSTR NameBstr = SysAllocString(RuleName.c_str());
    INetFwRule *Rule = nullptr;
    const HRESULT ItemHr = Rules->Item(NameBstr, &Rule);
    SysFreeString(NameBstr);
    Rules->Release();
    if (FAILED(ItemHr) || Rule == nullptr)
      return false;
    const HRESULT Hr =
        Rule->put_Enabled(Enabled ? VARIANT_TRUE : VARIANT_FALSE);
    Rule->Release();
    return SUCCEEDED(Hr);
  });
}

bool QueryDirectorySyncObjects(
    const wchar_t *Path, ULONG DirectoryId,
    std::vector<std::tuple<QString, QString, ULONG>> &Entries) {
  using NtOpenDirectoryObjectFn =
      NTSTATUS(NTAPI *)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
  using NtQueryDirectoryObjectFn =
      NTSTATUS(NTAPI *)(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG);

  static const NtOpenDirectoryObjectFn NtOpenDirectoryObjectPtr =
      reinterpret_cast<NtOpenDirectoryObjectFn>(GetProcAddress(
          GetModuleHandleW(L"ntdll.dll"), "NtOpenDirectoryObject"));
  static const NtQueryDirectoryObjectFn NtQueryDirectoryObjectPtr =
      reinterpret_cast<NtQueryDirectoryObjectFn>(GetProcAddress(
          GetModuleHandleW(L"ntdll.dll"), "NtQueryDirectoryObject"));
  if (NtOpenDirectoryObjectPtr == nullptr ||
      NtQueryDirectoryObjectPtr == nullptr)
    return false;

  UNICODE_STRING DirName;
  DirName.Buffer = const_cast<PWSTR>(Path);
  DirName.Length = static_cast<USHORT>(wcslen(Path) * sizeof(wchar_t));
  DirName.MaximumLength = DirName.Length + sizeof(wchar_t);
  OBJECT_ATTRIBUTES Attributes;
  InitializeObjectAttributes(&Attributes, &DirName, OBJ_CASE_INSENSITIVE,
                             nullptr, nullptr);

  HANDLE Directory = nullptr;
  if (NtOpenDirectoryObjectPtr(&Directory, DIRECTORY_QUERY, &Attributes) < 0)
    return false;

  bool Added = false;
  ULONG Context = 0;
  BOOLEAN Restart = TRUE;
  BYTE Buffer[8192];
  for (;;) {
    ULONG Returned = 0;
    const NTSTATUS Status = NtQueryDirectoryObjectPtr(
        Directory, Buffer, sizeof(Buffer), TRUE, Restart, &Context, &Returned);
    if (Status == STATUS_NO_MORE_ENTRIES)
      break;
    if (Status < 0)
      break;
    Restart = FALSE;

    const auto *Info =
        reinterpret_cast<const PublicObjectDirectoryInformation *>(Buffer);
    if (Info->Name.Buffer == nullptr || Info->TypeName.Buffer == nullptr)
      continue;

    const QString Type = QString::fromWCharArray(
        Info->TypeName.Buffer, Info->TypeName.Length / sizeof(wchar_t));
    if (!Type.startsWith("Mutant", Qt::CaseInsensitive) &&
        !Type.startsWith("Event", Qt::CaseInsensitive) &&
        !Type.startsWith("Semaphore", Qt::CaseInsensitive))
      continue;

    const QString Name = QString::fromWCharArray(
        Info->Name.Buffer, Info->Name.Length / sizeof(wchar_t));
    Entries.emplace_back(Name, Type, DirectoryId);
    Added = true;
  }

  CloseHandle(Directory);
  return Added;
}

bool EnumerateSyncObjectsFallback(
    std::vector<std::tuple<QString, QString, ULONG>> &Entries) {
  bool Success = QueryDirectorySyncObjects(L"\\BaseNamedObjects", 0, Entries);
  DWORD SessionId = 0;
  if (ProcessIdToSessionId(GetCurrentProcessId(), &SessionId) &&
      SessionId != 0) {
    const std::wstring SessionPath =
        std::format(L"\\Sessions\\{}\\BaseNamedObjects", SessionId);
    Success =
        QueryDirectorySyncObjects(SessionPath.c_str(), 1, Entries) || Success;
  }
  return Success;
}

SystemCallNameMap ParseSystemCallNames(HMODULE Module, const char *Prefix,
                                       bool ShadowTable = false) {
  SystemCallNameMap Names;
  if (!Module)
    return Names;

  const auto *Base = reinterpret_cast<const BYTE *>(Module);
  const auto *DosHeader = reinterpret_cast<const IMAGE_DOS_HEADER *>(Base);
  if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    return Names;
  const auto *NtHeaders =
      reinterpret_cast<const IMAGE_NT_HEADERS *>(Base + DosHeader->e_lfanew);
  if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
    return Names;
  const IMAGE_DATA_DIRECTORY &Directory =
      NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  if (!Directory.VirtualAddress)
    return Names;

  const auto *Exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY *>(
      Base + Directory.VirtualAddress);
  const auto *NameRvas =
      reinterpret_cast<const DWORD *>(Base + Exports->AddressOfNames);
  const auto *Ordinals =
      reinterpret_cast<const WORD *>(Base + Exports->AddressOfNameOrdinals);
  const auto *FunctionRvas =
      reinterpret_cast<const DWORD *>(Base + Exports->AddressOfFunctions);
  const size_t PrefixLength = std::strlen(Prefix);
  for (DWORD ExportIndex = 0; ExportIndex < Exports->NumberOfNames;
       ++ExportIndex) {
    const char *Name =
        reinterpret_cast<const char *>(Base + NameRvas[ExportIndex]);
    if (std::strncmp(Name, Prefix, PrefixLength) != 0)
      continue;
    const DWORD FunctionRva = FunctionRvas[Ordinals[ExportIndex]];
    if (FunctionRva >= Directory.VirtualAddress &&
        FunctionRva < Directory.VirtualAddress + Directory.Size)
      continue;
    const BYTE *Stub = Base + FunctionRva;
    for (size_t Offset = 0; Offset + 5 <= 32; ++Offset) {
      if (Stub[Offset] != 0xB8)
        continue;
      ULONG ServiceIndex = 0;
      std::memcpy(&ServiceIndex, Stub + Offset + 1, sizeof(ServiceIndex));
      if (ShadowTable)
        ServiceIndex &= 0x0FFF;
      Names.emplace(ServiceIndex, QString::fromLatin1(Name));
      break;
    }
  }
  return Names;
}

const SystemCallNameMap &ServiceNamesForTable(int TableKind) {
  static const SystemCallNameMap SsdtNames =
      ParseSystemCallNames(GetModuleHandleW(L"ntdll.dll"), "Nt");
  static const HMODULE Win32uModule = LoadLibraryW(L"win32u.dll");
  static const SystemCallNameMap ShadowSsdtNames =
      ParseSystemCallNames(Win32uModule, "Nt", true);
  return TableKind == SYSTEM_TABLE_KIND_SSDT ? SsdtNames : ShadowSsdtNames;
}

QString IdtVectorName(ULONG Vector) {
  static const std::array<const char *, 22> ExceptionNames{
      "Divide Error",
      "Debug",
      "NMI Interrupt",
      "Breakpoint",
      "Overflow",
      "BOUND Range Exceeded",
      "Invalid Opcode",
      "Device Not Available",
      "Double Fault",
      "Coprocessor Segment Overrun",
      "Invalid TSS",
      "Segment Not Present",
      "Stack-Segment Fault",
      "General Protection Fault",
      "Page Fault",
      "Reserved",
      "x87 Floating-Point Exception",
      "Alignment Check",
      "Machine Check",
      "SIMD Floating-Point Exception",
      "Virtualization Exception",
      "Control Protection Exception"};
  if (Vector < ExceptionNames.size())
    return QString::fromLatin1(ExceptionNames[Vector]);
  if (Vector >= 0x20 && Vector <= 0x2F)
    return QString("Hardware IRQ %1").arg(Vector - 0x20);
  if (Vector == 0x80)
    return "Legacy System Call";
  return QString("Interrupt Gate 0x%1")
      .arg(Vector, 2, 16, QLatin1Char('0'))
      .toUpper();
}

QString GdtDescriptorName(ULONG Index) {
  switch (Index) {
  case 0:
    return "Null Descriptor";
  case 1:
    return "Kernel Code Segment";
  case 2:
    return "Kernel Data Segment";
  case 3:
    return "User Data Segment";
  case 4:
    return "User Code Segment";
  case 5:
    return "TSS Descriptor Low";
  case 6:
    return "TSS Descriptor High";
  default:
    return QString("GDT Selector 0x%1")
        .arg(Index * 8, 4, 16, QLatin1Char('0'))
        .toUpper();
  }
}

QString SystemTableEntryName(int TableKind, const SYSTEM_TABLE_ENTRY &Entry) {
  if (TableKind == SYSTEM_TABLE_KIND_IDT)
    return IdtVectorName(Entry.Index);
  if (TableKind == SYSTEM_TABLE_KIND_IO_TIMER) {
    static const std::array<const char *, 4> TimerNames{
        "KUSER_SHARED_DATA", "SystemTime", "InterruptTime", "TickCount"};
    return Entry.Index < TimerNames.size()
               ? QString::fromLatin1(TimerNames[Entry.Index])
               : QString("KUSER_SHARED_DATA field 0x%1")
                     .arg(Entry.Index, 0, 16)
                     .toUpper();
  }
  if (TableKind == SYSTEM_TABLE_KIND_SSDT ||
      TableKind == SYSTEM_TABLE_KIND_SHADOW_SSDT) {
    const SystemCallNameMap &Names = ServiceNamesForTable(TableKind);
    const auto Name = Names.find(Entry.Index);
    if (Name != Names.end())
      return Name->second;
    return QString("Unexported system service 0x%1")
        .arg(Entry.Index, 0, 16)
        .toUpper();
  }
  if (TableKind == SYSTEM_TABLE_KIND_GDT)
    return GdtDescriptorName(Entry.Index);
  return "Unknown table entry";
}

QString FormatPeTimeDateStamp(ULONG TimeDateStamp) {
  if (TimeDateStamp == 0)
    return "0";

  const QDateTime Time = QDateTime::fromSecsSinceEpoch(
      static_cast<qint64>(TimeDateStamp), Qt::UTC);
  if (!Time.isValid())
    return QString("0x%1")
        .arg(TimeDateStamp, 8, 16, QLatin1Char('0'))
        .toUpper();
  return QString("0x%1 | %2 UTC")
      .arg(TimeDateStamp, 8, 16, QLatin1Char('0'))
      .toUpper()
      .arg(Time.toString("yyyy-MM-dd HH:mm:ss"));
}

QString RandomInformationQuote() {
  static const std::array<const char *, 36> Quotes{
      "Stay curious. Small signals reveal the big picture.",
      "Good tools turn friction into momentum.",
      "Clarity first. Speed follows.",
      "Measure what changed before changing more.",
      "Quiet systems still leave useful traces.",
      "Precision is faster than repetition.",
      "A clean view makes hard problems smaller.",
      "Inspect deeply, act deliberately.",
      "Patterns appear when noise is given structure.",
      "Strong diagnostics are a form of leverage.",
      "Reliable workflows beat dramatic fixes.",
      "Every interface teaches a habit.",
      "Evidence reduces guesswork.",
      "Readable systems are easier to defend.",
      "Useful detail arrives before perfect detail.",
      "The fastest path is often the clearest one.",
      "Small observability wins compound quickly.",
      "Better defaults create calmer operations.",
      "Well-lit data leaves fewer blind corners.",
      "A stable baseline makes anomalies obvious.",
      "Context turns raw output into decisions.",
      "Good instrumentation shortens every investigation.",
      "Strong systems are legible under pressure.",
      "The right summary saves ten deeper clicks.",
      "Neat structure is a performance feature.",
      "Confidence comes from verifiable detail.",
      "Useful interfaces make important things visible.",
      "Diagnosis improves when the signal stays close.",
      "Simplicity scales better than cleverness.",
      "Healthy feedback loops keep systems honest.",
      "A clear trace is worth a fast guess.",
      "Consistency is a quiet kind of speed.",
      "The best tooling reduces hesitation.",
      "Tidy surfaces make complex internals approachable.",
      "Visibility is the first step toward control.",
      "Careful observation outperforms noisy reaction."};
  return QString::fromLatin1(Quotes[QRandomGenerator::global()->bounded(
      static_cast<int>(Quotes.size()))]);
}

constexpr int KSidebarWidth = 272;
const QColor KAccent("#40BEE6");
const QColor KAppBackground("#F5F5F9");
const QColor KSurfaceSoft("#EFEFF5");
const QColor KTextPrimary("#17171B");
const QColor KTextMuted("#626269");
const QString KApplicationVersion = "3.6.2";
auto &ApplicationState = AegisNT::ApplicationContext();
auto &Configuration = ApplicationState.Configuration;
auto &LanguageResources = ApplicationState.LanguageResources;
auto &ActiveLanguage = ApplicationState.ActiveLanguage;
auto &Account = ApplicationState.Account;
auto &ModulesScanned = ApplicationState.ModulesScanned;
auto &ModuleRunning = ApplicationState.ModuleRunning;
auto &RunningModulePath = ApplicationState.RunningModulePath;
auto &ConsoleTranscript = ApplicationState.ConsoleTranscript;
auto &ModuleTranscript = ApplicationState.ModuleTranscript;

QString MonitorTimestamp(const FILETIME &Timestamp);
QString MonitorTimestamp(const LARGE_INTEGER &Timestamp);

QString ConfigurationPath() {
  return QCoreApplication::applicationDirPath() + "/Data/Config.json";
}

void AppendConsoleOutput(const QString &Text);

#include "Source/Core/Runtime/Configuration.inc"

#include "Source/Core/Runtime/PayloadShell.inc"

#include "Source/Core/Runtime/ModuleRuntime.inc"

QIcon CreateFluentIcon(Fluent::IconType Icon) { return Fluent::icon(Icon); }

void ShowLaunchAsDialog(QWidget *Parent);

FluentLabelBase *MakeLabel(const QString &Text, int PixelSize,
                           const QColor &Color, QFont::Weight Weight) {
  auto *Label = new FluentLabelBase(Text, PixelSize, Weight);
  QColor EffectiveColor = Color;
  if (Color == KTextPrimary) {
    Label->setProperty("TextRole", "Primary");
    EffectiveColor = PrimaryTextColor();
  } else if (Color == KTextMuted) {
    Label->setProperty("TextRole", "Muted");
    EffectiveColor = MutedTextColor();
  } else if (Color == KAccent) {
    Label->setProperty("TextRole", "Accent");
    EffectiveColor = ConfiguredColor("AccentColor", KAccent);
  }
  Label->setProperty("ThemeBasePixelSize", PixelSize);
  Label->setTextColor(EffectiveColor, EffectiveColor);
  return Label;
}

IconWidget *MakeGlyph(Fluent::IconType Glyph, int IconSize) {
  auto *Icon = new IconWidget(Fluent::coloredIcon(Glyph, KAccent, KAccent));
  Icon->setFixedSize(IconSize, IconSize);
  return Icon;
}

QString ApplicationIconPath() {
  return QCoreApplication::applicationDirPath() + "/Data/ICON.png";
}

int ColorDistanceSquared(QRgb Left, QRgb Right) {
  const int DeltaRed = qRed(Left) - qRed(Right);
  const int DeltaGreen = qGreen(Left) - qGreen(Right);
  const int DeltaBlue = qBlue(Left) - qBlue(Right);
  return DeltaRed * DeltaRed + DeltaGreen * DeltaGreen + DeltaBlue * DeltaBlue;
}

QRect ApplicationIconVisibleBounds(const QImage &Image) {
  if (Image.isNull())
    return {};

  const QRgb BackgroundSamples[] = {
      Image.pixel(0, 0),
      Image.pixel(std::max(0, Image.width() - 1), 0),
      Image.pixel(0, std::max(0, Image.height() - 1)),
      Image.pixel(std::max(0, Image.width() - 1),
                  std::max(0, Image.height() - 1)),
  };

  int SumAlpha = 0;
  int SumRed = 0;
  int SumGreen = 0;
  int SumBlue = 0;
  for (QRgb Sample : BackgroundSamples) {
    SumAlpha += qAlpha(Sample);
    SumRed += qRed(Sample);
    SumGreen += qGreen(Sample);
    SumBlue += qBlue(Sample);
  }

  const QRgb Background =
      qRgba(SumRed / 4, SumGreen / 4, SumBlue / 4, SumAlpha / 4);
  constexpr int HardAlphaThreshold = 72;
  constexpr int SoftAlphaThreshold = 12;
  constexpr int BackgroundToleranceSquared = 18 * 18 * 3;

  const auto IsVisiblePixel = [Background](QRgb Pixel) {
    const int Alpha = qAlpha(Pixel);
    if (Alpha <= SoftAlphaThreshold)
      return false;
    if (Alpha >= HardAlphaThreshold)
      return true;
    return ColorDistanceSquared(Pixel, Background) > BackgroundToleranceSquared;
  };

  int Left = Image.width();
  int Top = Image.height();
  int Right = -1;
  int Bottom = -1;
  for (int Y = 0; Y < Image.height(); ++Y) {
    const QRgb *Line = reinterpret_cast<const QRgb *>(Image.constScanLine(Y));
    for (int X = 0; X < Image.width(); ++X) {
      if (!IsVisiblePixel(Line[X]))
        continue;
      Left = std::min(Left, X);
      Top = std::min(Top, Y);
      Right = std::max(Right, X);
      Bottom = std::max(Bottom, Y);
    }
  }
  if (Right < Left || Bottom < Top)
    return QRect(0, 0, Image.width(), Image.height());
  return QRect(QPoint(Left, Top), QPoint(Right, Bottom));
}

QRect ApplicationIconFocusBounds(const QImage &Image,
                                 const QRect &VisibleBounds) {
  if (Image.isNull() || !VisibleBounds.isValid())
    return {};

  const int VisibleWidth = VisibleBounds.width();
  const int VisibleHeight = VisibleBounds.height();
  int Side = std::min(VisibleWidth, VisibleHeight);
  if (Side <= 0)
    return VisibleBounds;

  if (VisibleHeight > VisibleWidth * 1.08)
    Side = std::max(1, qRound(Side * 0.86));
  else if (VisibleWidth > VisibleHeight * 1.08)
    Side = std::max(1, qRound(Side * 0.9));

  const QPoint Center = VisibleBounds.center();
  int Left = Center.x() - Side / 2;
  int Top = Center.y() - Side / 2;

  Left = qBound(0, Left, std::max(0, Image.width() - Side));
  Top = qBound(0, Top, std::max(0, Image.height() - Side));
  return QRect(Left, Top, Side, Side);
}

// 图标文件运行期不变：读盘 + 全图逐像素扫描只做一次。
struct ApplicationIconCacheData {
  QImage Image;
  QRect VisibleBounds;
};

const ApplicationIconCacheData &ApplicationIconCache() {
  static const ApplicationIconCacheData Cached = [] {
    ApplicationIconCacheData Result;
    const QString Path = ApplicationIconPath();
    if (QFileInfo::exists(Path)) {
      Result.Image = QImage(Path);
      if (!Result.Image.isNull())
        Result.Image =
            Result.Image.convertToFormat(QImage::Format_ARGB32_Premultiplied);
      Result.VisibleBounds = ApplicationIconVisibleBounds(Result.Image);
    }
    return Result;
  }();
  return Cached;
}

QImage ApplicationIconImage() { return ApplicationIconCache().Image; }

QPixmap ApplicationIconPixmap(const QSize &TargetSize) {
  const QImage &Source = ApplicationIconCache().Image;
  if (Source.isNull() || TargetSize.width() <= 0 || TargetSize.height() <= 0)
    return {};

  const QRect Bounds = ApplicationIconCache().VisibleBounds;
  const QRect FocusBounds = ApplicationIconFocusBounds(Source, Bounds);
  QImage Cropped = Source.copy(FocusBounds.isValid() ? FocusBounds : Bounds);
  if (Cropped.isNull())
    return {};

  const QImage Scaled = Cropped.scaled(
      TargetSize, Qt::KeepAspectRatioByExpanding, Qt::SmoothTransformation);
  if (Scaled.isNull())
    return {};

  const int Left = std::max(0, (Scaled.width() - TargetSize.width()) / 2);
  const int Top = std::max(0, (Scaled.height() - TargetSize.height()) / 2);
  return QPixmap::fromImage(
      Scaled.copy(Left, Top, TargetSize.width(), TargetSize.height()));
}

QPixmap ApplicationIconFitPixmap(const QSize &TargetSize) {
  const QImage &Source = ApplicationIconCache().Image;
  if (Source.isNull() || TargetSize.width() <= 0 || TargetSize.height() <= 0)
    return {};

  const QRect Bounds = ApplicationIconCache().VisibleBounds;
  QImage Cropped = Source.copy(
      Bounds.isValid() ? Bounds : QRect(0, 0, Source.width(), Source.height()));
  if (Cropped.isNull())
    return {};

  const QImage Scaled =
      Cropped.scaled(TargetSize, Qt::KeepAspectRatio, Qt::SmoothTransformation);
  if (Scaled.isNull())
    return {};

  QImage Canvas(TargetSize, QImage::Format_ARGB32_Premultiplied);
  Canvas.fill(Qt::transparent);

  QPainter Painter(&Canvas);
  const int Left = std::max(0, (TargetSize.width() - Scaled.width()) / 2);
  const int Top = std::max(0, (TargetSize.height() - Scaled.height()) / 2);
  Painter.drawImage(QPoint(Left, Top), Scaled);
  Painter.end();

  return QPixmap::fromImage(Canvas);
}

QPixmap ApplicationIconPixmap(int Size) {
  return ApplicationIconPixmap(QSize(Size, Size));
}

QIcon ApplicationIcon() {
  QIcon Icon;
  for (const int Size : {16, 20, 24, 32, 40, 48, 64, 128, 256}) {
    const QPixmap Pixmap = ApplicationIconPixmap(Size);
    if (!Pixmap.isNull())
      Icon.addPixmap(Pixmap);
  }
  return Icon;
}

QWidget *MakeApplicationIconWidget(const QSize &IconSize) {
  const QPixmap Pixmap = ApplicationIconPixmap(IconSize);
  if (Pixmap.isNull())
    return MakeGlyph(Fluent::IconType::APPLICATION,
                     std::max(IconSize.width(), IconSize.height()));

  auto *Label = new QLabel;
  Label->setFixedSize(IconSize);
  Label->setAlignment(Qt::AlignCenter);
  Label->setScaledContents(true);
  Label->setPixmap(Pixmap);
  return Label;
}

QWidget *MakeApplicationIconWidget(int IconSize) {
  return MakeApplicationIconWidget(QSize(IconSize, IconSize));
}

QWidget *MakeApplicationIconFitWidget(const QSize &IconSize) {
  const QPixmap Pixmap = ApplicationIconFitPixmap(IconSize);
  if (Pixmap.isNull())
    return MakeGlyph(Fluent::IconType::APPLICATION,
                     std::max(IconSize.width(), IconSize.height()));

  auto *Label = new QLabel;
  Label->setFixedSize(IconSize);
  Label->setAlignment(Qt::AlignCenter);
  Label->setPixmap(Pixmap);
  return Label;
}

void InstallFluentScrollBar(QAbstractScrollArea *Area,
                            Qt::Orientation Orientation) {
  QScrollBar *OriginalScrollBar = Orientation == Qt::Vertical
                                      ? Area->verticalScrollBar()
                                      : Area->horizontalScrollBar();
  auto *OverlayScrollBar = new ScrollBar(OriginalScrollBar, Area);
  OverlayScrollBar->setAnimationEnabled(true);
}

class InformationItem final : public SimpleCardWidget {
public:
  InformationItem(Fluent::IconType Glyph, const QString &Title,
                  const QString &Description, const QString &Value,
                  QWidget *Parent = nullptr)
      : SimpleCardWidget(Parent) {
    setBorderRadius(8);
    setMinimumHeight(88);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Minimum);

    auto *Layout = new QHBoxLayout(this);
    Layout->setContentsMargins(16, 14, 16, 14);
    Layout->setSpacing(14);

    auto *IconHost = new QWidget;
    IconHost->setFixedSize(44, 44);
    const bool DarkMode =
        ConfigurationValue("Theme", "DarkMode", KDefaultThemeDarkMode).toBool();
    QColor IconBackground = ConfiguredColor("AccentColor", KAccent);
    IconBackground.setAlpha(DarkMode ? 52 : 28);
    IconHost->setStyleSheet(
        QString("background: rgba(%1,%2,%3,%4); border-radius: 22px;")
            .arg(IconBackground.red())
            .arg(IconBackground.green())
            .arg(IconBackground.blue())
            .arg(IconBackground.alpha()));
    auto *IconHostLayout = new QVBoxLayout(IconHost);
    IconHostLayout->setContentsMargins(0, 0, 0, 0);
    IconHostLayout->addWidget(MakeGlyph(Glyph, 22), 0, Qt::AlignCenter);
    Layout->addWidget(IconHost, 0, Qt::AlignTop);

    auto *TextLayout = new QVBoxLayout;
    TextLayout->setContentsMargins(0, 0, 0, 0);
    TextLayout->setSpacing(4);
    auto *TitleLabel = MakeLabel(Title, 14, KTextPrimary, QFont::DemiBold);
    auto *DescriptionLabel = MakeLabel(Description, 12, KTextMuted);
    DescriptionLabel->setWordWrap(true);
    TextLayout->addWidget(TitleLabel);
    TextLayout->addWidget(DescriptionLabel);
    Layout->addLayout(TextLayout, 1);

    auto *ValueLabel = MakeLabel(Value, 14, KTextPrimary, QFont::Medium);
    ValueLabel->setAlignment(Qt::AlignRight | Qt::AlignTop);
    ValueLabel->setWordWrap(true);
    ValueLabel->setMinimumWidth(150);
    ValueLabel->setMaximumWidth(360);
    Layout->addWidget(ValueLabel);
  }
};

class InformationSectionHeader final : public QWidget {
public:
  InformationSectionHeader(const QString &Title, const QString &Description,
                           QWidget *Parent = nullptr)
      : QWidget(Parent) {
    auto *Layout = new QVBoxLayout(this);
    Layout->setContentsMargins(2, 8, 2, 2);
    Layout->setSpacing(6);

    Layout->addWidget(MakeLabel(Title, 17, KTextPrimary, QFont::DemiBold));
    if (!Description.trimmed().isEmpty()) {
      auto *DescriptionLabel = MakeLabel(Description, 12, KTextMuted);
      DescriptionLabel->setWordWrap(true);
      Layout->addWidget(DescriptionLabel);
    }

    auto *Divider = new QFrame;
    Divider->setFixedHeight(1);
    const bool DarkMode =
        ConfigurationValue("Theme", "DarkMode", KDefaultThemeDarkMode).toBool();
    const QColor DividerColor =
        DarkMode ? QColor(255, 255, 255, 24) : QColor(0, 0, 0, 18);
    Divider->setStyleSheet(
        QString("background: rgba(%1,%2,%3,%4); border: none;")
            .arg(DividerColor.red())
            .arg(DividerColor.green())
            .arg(DividerColor.blue())
            .arg(DividerColor.alpha()));
    Layout->addWidget(Divider);
  }
};

class InformationBadge final : public SimpleCardWidget {
public:
  InformationBadge(const QString &Caption, const QString &Value,
                   QWidget *Parent = nullptr)
      : SimpleCardWidget(Parent) {
    setBorderRadius(8);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    auto *Layout = new QVBoxLayout(this);
    Layout->setContentsMargins(14, 12, 14, 12);
    Layout->setSpacing(4);

    auto *CaptionLabel = MakeLabel(Caption, 11, KTextMuted, QFont::Medium);
    auto *ValueLabel = MakeLabel(Value, 14, KTextPrimary, QFont::DemiBold);
    ValueLabel->setWordWrap(true);
    Layout->addWidget(CaptionLabel);
    Layout->addWidget(ValueLabel);
  }
};

class InformationNoticeCard final : public SimpleCardWidget {
public:
  InformationNoticeCard(Fluent::IconType Glyph, const QString &Title,
                        const QString &Content, const QColor &Color,
                        QWidget *Parent = nullptr)
      : SimpleCardWidget(Parent) {
    setBorderRadius(8);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    auto *Layout = new QHBoxLayout(this);
    Layout->setContentsMargins(16, 14, 16, 14);
    Layout->setSpacing(12);

    auto *IconHost = new QWidget;
    IconHost->setFixedSize(40, 40);
    QColor Background = Color;
    Background.setAlpha(
        ConfigurationValue("Theme", "DarkMode", KDefaultThemeDarkMode).toBool()
            ? 54
            : 24);
    IconHost->setStyleSheet(
        QString("background: rgba(%1,%2,%3,%4); border-radius: 20px;")
            .arg(Background.red())
            .arg(Background.green())
            .arg(Background.blue())
            .arg(Background.alpha()));
    auto *IconHostLayout = new QVBoxLayout(IconHost);
    IconHostLayout->setContentsMargins(0, 0, 0, 0);
    IconHostLayout->addWidget(
        new IconWidget(Fluent::coloredIcon(Glyph, Color, Color)), 0,
        Qt::AlignCenter);
    Layout->addWidget(IconHost, 0, Qt::AlignTop);

    auto *TextLayout = new QVBoxLayout;
    TextLayout->setContentsMargins(0, 0, 0, 0);
    TextLayout->setSpacing(3);
    TextLayout->addWidget(MakeLabel(Title, 13, Color, QFont::DemiBold));
    auto *ContentLabel = MakeLabel(Content, 12, KTextMuted);
    ContentLabel->setWordWrap(true);
    TextLayout->addWidget(ContentLabel);
    Layout->addLayout(TextLayout, 1);
  }
};

QString QueryTestSigning() {
  using NtQuerySystemInformationFn =
      LONG(WINAPI *)(ULONG, PVOID, ULONG, PULONG);
  struct CodeIntegrityInformation {
    ULONG Length;
    ULONG Options;
  };
  CodeIntegrityInformation Information{sizeof(Information), 0};
  const HMODULE Ntdll = GetModuleHandleW(L"Ntdll.dll");
  if (!Ntdll)
    return "Unknown";
  const auto Query = reinterpret_cast<NtQuerySystemInformationFn>(
      GetProcAddress(Ntdll, "NtQuerySystemInformation"));
  if (!Query || Query(103, &Information, sizeof(Information), nullptr) != 0)
    return "Unknown";
  return (Information.Options & 0x2u) ? "Enabled" : "Disabled";
}

QString QueryNpcap() {
  SC_HANDLE Manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (!Manager)
    return "Unknown";
  SC_HANDLE Service = OpenServiceW(Manager, L"npcap", SERVICE_QUERY_STATUS);
  if (!Service) {
    CloseServiceHandle(Manager);
    return "Not installed";
  }
  SERVICE_STATUS_PROCESS Status{};
  DWORD BytesNeeded = 0;
  const bool Ok = QueryServiceStatusEx(Service, SC_STATUS_PROCESS_INFO,
                                       reinterpret_cast<LPBYTE>(&Status),
                                       sizeof(Status), &BytesNeeded) != FALSE;
  CloseServiceHandle(Service);
  CloseServiceHandle(Manager);
  if (!Ok)
    return "Unknown";
  if (Status.dwCurrentState == SERVICE_RUNNING)
    return "Running";
  if (Status.dwCurrentState == SERVICE_STOPPED)
    return "Stopped";
  return "Installed";
}

QString CertificateState() {
  const QString Path =
      QCoreApplication::applicationDirPath() + "/Data/CA_CERT.pem";
  return QFileInfo::exists(Path) ? "Certificate available"
                                 : "CA_CERT.pem not found";
}

QString FormatBytes(quint64 Bytes) {
  static const char *Units[] = {"B", "KB", "MB", "GB", "TB"};
  double Value = static_cast<double>(Bytes);
  int Index = 0;
  while (Value >= 1024.0 && Index < 4) {
    Value /= 1024.0;
    ++Index;
  }
  return QString::number(Value, Index == 0 ? 'f' : 'f', Index < 2 ? 0 : 1) +
         " " + Units[Index];
}

QString FormatRate(quint64 BytesPerSecond) {
  return FormatBytes(BytesPerSecond) + "/s";
}

QString RegistryStringValue(HKEY RootKey, const wchar_t *SubKey,
                            const wchar_t *ValueName) {
  HKEY Key = nullptr;
  if (RegOpenKeyExW(RootKey, SubKey, 0, KEY_READ, &Key) != ERROR_SUCCESS)
    return {};

  DWORD Type = 0;
  DWORD Size = 0;
  const LONG QueryStatus =
      RegQueryValueExW(Key, ValueName, nullptr, &Type, nullptr, &Size);
  if (QueryStatus != ERROR_SUCCESS ||
      (Type != REG_SZ && Type != REG_EXPAND_SZ && Type != REG_MULTI_SZ) ||
      Size == 0) {
    RegCloseKey(Key);
    return {};
  }

  std::wstring Buffer(static_cast<size_t>(Size / sizeof(wchar_t)) + 1, L'\0');
  if (RegQueryValueExW(Key, ValueName, nullptr, &Type,
                       reinterpret_cast<LPBYTE>(Buffer.data()),
                       &Size) != ERROR_SUCCESS) {
    RegCloseKey(Key);
    return {};
  }
  RegCloseKey(Key);
  while (!Buffer.empty() && Buffer.back() == L'\0')
    Buffer.pop_back();
  return QString::fromWCharArray(Buffer.c_str()).trimmed();
}

DWORD RegistryDwordValue(HKEY RootKey, const wchar_t *SubKey,
                         const wchar_t *ValueName, DWORD Fallback = 0) {
  HKEY Key = nullptr;
  if (RegOpenKeyExW(RootKey, SubKey, 0, KEY_READ, &Key) != ERROR_SUCCESS)
    return Fallback;
  DWORD Type = 0;
  DWORD Value = Fallback;
  DWORD Size = sizeof(Value);
  if (RegQueryValueExW(Key, ValueName, nullptr, &Type,
                       reinterpret_cast<LPBYTE>(&Value),
                       &Size) != ERROR_SUCCESS ||
      Type != REG_DWORD) {
    RegCloseKey(Key);
    return Fallback;
  }
  RegCloseKey(Key);
  return Value;
}

QString QueryWindowsVersionText() {
  const QString ProductName = RegistryStringValue(
      HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
      L"ProductName");
  const QString DisplayVersion = RegistryStringValue(
      HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
      L"DisplayVersion");
  const QString CurrentBuild = RegistryStringValue(
      HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
      L"CurrentBuild");
  const DWORD Ubr = RegistryDwordValue(
      HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
      L"UBR", 0);

  QString Version =
      ProductName.isEmpty() ? QSysInfo::prettyProductName() : ProductName;
  if (!DisplayVersion.isEmpty())
    Version += " " + DisplayVersion;
  if (!CurrentBuild.isEmpty())
    Version += QString(" (build %1.%2)").arg(CurrentBuild).arg(Ubr);
  return Version;
}

QString QueryCpuName() {
  return RegistryStringValue(
      HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
      L"ProcessorNameString");
}

QString QuerySystemManufacturer() {
  return RegistryStringValue(HKEY_LOCAL_MACHINE,
                             L"HARDWARE\\DESCRIPTION\\System\\BIOS",
                             L"SystemManufacturer");
}

QString QuerySystemModel() {
  return RegistryStringValue(HKEY_LOCAL_MACHINE,
                             L"HARDWARE\\DESCRIPTION\\System\\BIOS",
                             L"SystemProductName");
}

QString QueryBoardName() {
  const QString Manufacturer = RegistryStringValue(
      HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS",
      L"BaseBoardManufacturer");
  const QString Product = RegistryStringValue(
      HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS",
      L"BaseBoardProduct");
  return (Manufacturer + " " + Product).trimmed();
}

QString QueryBiosName() {
  const QString Vendor = RegistryStringValue(
      HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS",
      L"BIOSVendor");
  const QString Version = RegistryStringValue(
      HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS",
      L"BIOSVersion");
  return (Vendor + " " + Version).trimmed();
}

QString QueryGraphicsAdapters() {
  QStringList Adapters;
  DISPLAY_DEVICEW Device{};
  Device.cb = sizeof(Device);
  for (DWORD Index = 0;
       EnumDisplayDevicesW(nullptr, Index, &Device, 0) != FALSE; ++Index) {
    if ((Device.StateFlags & DISPLAY_DEVICE_ACTIVE) == 0 ||
        (Device.StateFlags & DISPLAY_DEVICE_MIRRORING_DRIVER) != 0) {
      Device = DISPLAY_DEVICEW{};
      Device.cb = sizeof(Device);
      continue;
    }
    const QString Name = QString::fromWCharArray(Device.DeviceString).trimmed();
    if (!Name.isEmpty() && !Adapters.contains(Name))
      Adapters.append(Name);
    Device = DISPLAY_DEVICEW{};
    Device.cb = sizeof(Device);
  }
  return Adapters.isEmpty() ? "Unknown" : Adapters.join(" | ");
}

QString QueryMemoryInstalled() {
  MEMORYSTATUSEX Memory{};
  Memory.dwLength = sizeof(Memory);
  if (!GlobalMemoryStatusEx(&Memory))
    return "Unknown";
  return FormatBytes(static_cast<quint64>(Memory.ullTotalPhys));
}

QString QuerySystemDriveSummary() {
  const QStorageInfo Storage(QCoreApplication::applicationDirPath());
  if (!Storage.isValid() || !Storage.isReady())
    return "Unknown";
  const quint64 Total = static_cast<quint64>(Storage.bytesTotal());
  const quint64 Free = static_cast<quint64>(Storage.bytesAvailable());
  const quint64 Used = Total > Free ? Total - Free : 0;
  return QString("%1  |  %2 used")
      .arg(QDir::toNativeSeparators(Storage.rootPath()), FormatBytes(Used));
}

QString FormatDuration(quint64 Milliseconds) {
  quint64 Seconds = Milliseconds / 1000;
  const quint64 Days = Seconds / 86400;
  Seconds %= 86400;
  const quint64 Hours = Seconds / 3600;
  Seconds %= 3600;
  const quint64 Minutes = Seconds / 60;
  Seconds %= 60;

  QStringList Parts;
  if (Days > 0)
    Parts.append(QString::number(Days) + "d");
  if (Hours > 0 || !Parts.isEmpty())
    Parts.append(QString::number(Hours) + "h");
  if (Minutes > 0 || !Parts.isEmpty())
    Parts.append(QString::number(Minutes) + "m");
  Parts.append(QString::number(Seconds) + "s");
  return Parts.join(' ');
}

struct NetworkTrafficSnapshot {
  quint64 InBytes = 0;
  quint64 OutBytes = 0;
};

NetworkTrafficSnapshot QueryNetworkTrafficSnapshot() {
  NetworkTrafficSnapshot Snapshot;
  PMIB_IF_TABLE2 Table = nullptr;
  if (GetIfTable2(&Table) != NO_ERROR || !Table)
    return Snapshot;

  for (ULONG Index = 0; Index < Table->NumEntries; ++Index) {
    const MIB_IF_ROW2 &Row = Table->Table[Index];
    if (Row.InterfaceAndOperStatusFlags.FilterInterface ||
        Row.Type == IF_TYPE_SOFTWARE_LOOPBACK ||
        Row.MediaConnectState != MediaConnectStateConnected)
      continue;
    Snapshot.InBytes += Row.InOctets;
    Snapshot.OutBytes += Row.OutOctets;
  }
  FreeMibTable(Table);
  return Snapshot;
}

struct PaintThemeSnapshot {
  bool DarkMode = false;
  QColor Accent;
};

// paintEvent 每帧查询主题配置的缓存：仅在配置代数变化时重读。
// 只在 GUI 线程调用，静态缓存无需加锁。
PaintThemeSnapshot QueryPaintTheme() {
  static PaintThemeSnapshot Cached;
  static int CachedGeneration = -1;
  const int Generation = CurrentConfigurationGeneration();
  if (Generation != CachedGeneration) {
    Cached.DarkMode = ConfigurationValue("Theme", "DarkMode",
                                         KDefaultThemeDarkMode).toBool();
    Cached.Accent = ConfiguredColor("AccentColor", KAccent);
    CachedGeneration = Generation;
  }
  return Cached;
}

class CircularGaugeWidget final : public QWidget {
public:
  explicit CircularGaugeWidget(QWidget *Parent = nullptr) : QWidget(Parent) {
    setFixedSize(118, 118);
  }

  void SetValue(int Value, const QString &Text) {
    Percent = std::clamp(Value, 0, 100);
    CenterText = Text;
    update();
  }

protected:
  void paintEvent(QPaintEvent *Event) override {
    Q_UNUSED(Event);
    QPainter Painter(this);
    Painter.setRenderHint(QPainter::Antialiasing, true);

    const QRectF RingRect(12.0, 12.0, width() - 24.0, height() - 24.0);
    const PaintThemeSnapshot Theme = QueryPaintTheme();
    QPen TrackPen(QColor(160, 160, 160, Theme.DarkMode ? 48 : 36), 10.0,
                  Qt::SolidLine, Qt::RoundCap);
    Painter.setPen(TrackPen);
    Painter.drawArc(RingRect, 225 * 16, -270 * 16);

    QColor Accent = Theme.Accent;
    if (Percent >= 85)
      Accent = QColor("#D13438");
    else if (Percent >= 65)
      Accent = QColor("#F0A10A");

    QPen ValuePen(Accent, 10.0, Qt::SolidLine, Qt::RoundCap);
    Painter.setPen(ValuePen);
    Painter.drawArc(RingRect, 225 * 16, -qRound(270.0 * Percent / 100.0) * 16);

    Painter.setPen(PrimaryTextColor());
    QFont PercentFont = font();
    PercentFont.setPixelSize(24);
    PercentFont.setWeight(QFont::DemiBold);
    Painter.setFont(PercentFont);
    Painter.drawText(rect().adjusted(0, 8, 0, -8), Qt::AlignCenter,
                     QString::number(Percent) + "%");

    Painter.setPen(MutedTextColor());
    QFont CaptionFont = font();
    CaptionFont.setPixelSize(10);
    Painter.setFont(CaptionFont);
    Painter.drawText(rect().adjusted(12, 68, -12, -8),
                     Qt::AlignHCenter | Qt::TextWordWrap, CenterText);
  }

private:
  int Percent = 0;
  QString CenterText;
};

class PerformanceDashboardCard final : public SimpleCardWidget {
public:
  PerformanceDashboardCard(Fluent::IconType Glyph, const QString &Title,
                           const QString &Description,
                           QWidget *Parent = nullptr)
      : SimpleCardWidget(Parent) {
    setBorderRadius(8);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

    auto *Layout = new QVBoxLayout(this);
    Layout->setContentsMargins(18, 16, 18, 16);
    Layout->setSpacing(12);

    auto *Header = new QHBoxLayout;
    Header->setContentsMargins(0, 0, 0, 0);
    Header->setSpacing(12);
    Header->addWidget(MakeGlyph(Glyph, 22), 0, Qt::AlignTop);

    auto *TitleLayout = new QVBoxLayout;
    TitleLayout->setContentsMargins(0, 0, 0, 0);
    TitleLayout->setSpacing(2);
    TitleLayout->addWidget(MakeLabel(Title, 14, KTextPrimary, QFont::DemiBold));
    auto *DescriptionLabel = MakeLabel(Description, 11, KTextMuted);
    DescriptionLabel->setWordWrap(true);
    TitleLayout->addWidget(DescriptionLabel);
    Header->addLayout(TitleLayout, 1);

    SummaryLabel = MakeLabel("0%", 16, KAccent, QFont::DemiBold);
    SummaryLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    SummaryLabel->setMinimumWidth(96);
    Header->addWidget(SummaryLabel);

    ToggleButton = new PushButton("Collapse");
    ToggleButton->setCursor(Qt::PointingHandCursor);
    ToggleButton->setMinimumHeight(30);
    ToggleButton->setMinimumWidth(88);
    Header->addWidget(ToggleButton);
    Layout->addLayout(Header);

    Body = new QWidget;
    auto *BodyLayout = new QHBoxLayout(Body);
    BodyLayout->setContentsMargins(0, 0, 0, 0);
    BodyLayout->setSpacing(18);

    Gauge = new CircularGaugeWidget;
    BodyLayout->addWidget(Gauge, 0, Qt::AlignTop);

    auto *DetailLayout = new QVBoxLayout;
    DetailLayout->setContentsMargins(0, 2, 0, 0);
    DetailLayout->setSpacing(8);
    DetailPrimary = MakeLabel("-", 12, KTextPrimary, QFont::Medium);
    DetailSecondary = MakeLabel("-", 11, KTextMuted);
    DetailTertiary = MakeLabel("-", 11, KTextMuted);
    DetailPrimary->setWordWrap(true);
    DetailSecondary->setWordWrap(true);
    DetailTertiary->setWordWrap(true);
    DetailLayout->addWidget(DetailPrimary);
    DetailLayout->addWidget(DetailSecondary);
    DetailLayout->addWidget(DetailTertiary);
    DetailLayout->addStretch();
    BodyLayout->addLayout(DetailLayout, 1);
    Layout->addWidget(Body);

    QObject::connect(ToggleButton, &QPushButton::clicked, this, [this] {
      if (ToggleHandler)
        ToggleHandler(!Expanded);
      else
        SetExpanded(!Expanded);
    });
  }

  void SetExpanded(bool Value) {
    Expanded = Value;
    Body->setVisible(Expanded);
    ToggleButton->setText(Expanded ? "Collapse" : "Expand");
  }

  bool IsExpanded() const { return Expanded; }

  void SetToggleHandler(std::function<void(bool)> Handler) {
    ToggleHandler = std::move(Handler);
  }

  void UpdateDashboard(int Percent, const QString &Summary,
                       const QString &Primary, const QString &Secondary,
                       const QString &Tertiary) {
    const int SafePercent = std::clamp(Percent, 0, 100);
    SummaryLabel->setText(Summary);
    Gauge->SetValue(SafePercent, Summary);
    DetailPrimary->setText(Primary);
    DetailSecondary->setText(Secondary);
    DetailTertiary->setText(Tertiary);
  }

private:
  bool Expanded = true;
  QWidget *Body = nullptr;
  PushButton *ToggleButton = nullptr;
  CircularGaugeWidget *Gauge = nullptr;
  FluentLabelBase *SummaryLabel = nullptr;
  FluentLabelBase *DetailPrimary = nullptr;
  FluentLabelBase *DetailSecondary = nullptr;
  FluentLabelBase *DetailTertiary = nullptr;
  std::function<void(bool)> ToggleHandler;
};

TableWidget *MakeTable(const QStringList &Headers) {
  auto *Table = new TableWidget;
  InstallFluentScrollBar(Table, Qt::Vertical);
  InstallFluentScrollBar(Table, Qt::Horizontal);
  Table->setColumnCount(Headers.size());
  Table->setRowCount(0);
  Table->setHorizontalHeaderLabels(Headers);
  Table->horizontalHeader()->setStretchLastSection(true);
  Table->horizontalHeader()->setMinimumSectionSize(80);
  Table->horizontalHeader()->setFixedHeight(34);
  Table->verticalHeader()->hide();
  Table->verticalHeader()->setDefaultSectionSize(KCompactTableRowHeight);
  Table->setAlternatingRowColors(false);
  Table->setSelectionBehavior(QAbstractItemView::SelectRows);
  Table->setEditTriggers(QAbstractItemView::NoEditTriggers);
  Table->setShowGrid(false);
  Table->setWordWrap(false);
  Table->setTextElideMode(Qt::ElideRight);
  Table->setProperty("UseGenericDetailDialog", true);
  QObject::connect(
      Table, &QTableWidget::cellDoubleClicked, Table, [Table](int Row, int) {
        if (!Table->property("UseGenericDetailDialog").toBool() || Row < 0 ||
            Row >= Table->rowCount())
          return;

        QStringList Lines;
        for (int Column = 0; Column < Table->columnCount(); ++Column) {
          const QString Header =
              Table->horizontalHeaderItem(Column)
                  ? Table->horizontalHeaderItem(Column)->text()
                  : QString("Column %1").arg(Column + 1);
          const QTableWidgetItem *Item = Table->item(Row, Column);
          const QString Value = Item ? Item->text() : QString();
          Lines.append(QString("%1: %2").arg(Header, Value.isEmpty() ? "(empty)"
                                                                     : Value));
        }

        auto *Dialog = new QDialog(Table->window());
        Dialog->setAttribute(Qt::WA_DeleteOnClose);
        Dialog->resize(900, 610);
        Dialog->setWindowTitle(
            Table->property("DetailDialogTitle").toString().isEmpty()
                ? QString("Details")
                : Table->property("DetailDialogTitle").toString());
        auto *Layout = new QVBoxLayout(Dialog);
        Layout->setContentsMargins(14, 14, 14, 14);
        Layout->setSpacing(8);
        auto *Text = new PlainTextEdit;
        Text->setReadOnly(true);
        Text->setFont(QFont("Cascadia Mono", 10));
        Text->setPlainText(Lines.join("\n\n"));
        InstallFluentScrollBar(Text, Qt::Vertical);
        auto *Close = MakeButton("Close", true);
        Layout->addWidget(Text, 1);
        Layout->addWidget(Close, 0, Qt::AlignRight);
        QObject::connect(Close, &QPushButton::clicked, Dialog,
                         &QDialog::accept);
        ApplyDialogTheme(Dialog);
        Dialog->show();
      });
  return Table;
}

void ConfigureToolbarLayout(QHBoxLayout *Layout, int Spacing) {
  if (!Layout)
    return;
  Layout->setContentsMargins(0, 0, 0, 0);
  Layout->setSpacing(Spacing);
}

void ConfigurePageLayout(QVBoxLayout *Layout,
                         int Spacing = KCompactPageSpacing) {
  if (!Layout)
    return;
  Layout->setContentsMargins(0, 0, 0, 0);
  Layout->setSpacing(Spacing);
}

void ConfigureSearchLineEdit(SearchLineEdit *Edit, const QString &Placeholder,
                             int MaximumWidth) {
  if (!Edit)
    return;
  Edit->setPlaceholderText(Placeholder);
  Edit->setClearButtonEnabled(true);
  Edit->setMaximumWidth(MaximumWidth > 0 ? MaximumWidth : KStandardSearchWidth);
}

void ConfigureLineEdit(LineEdit *Edit, const QString &Placeholder,
                       int MaximumWidth) {
  if (!Edit)
    return;
  Edit->setPlaceholderText(Placeholder);
  if (MaximumWidth > 0)
    Edit->setMaximumWidth(MaximumWidth);
}

PushButton *MakeButton(const QString &Text, bool Primary) {
  PushButton *Button =
      Primary ? static_cast<PushButton *>(new PrimaryPushButton(Text))
              : new PushButton(Text);
  Button->setCursor(Qt::PointingHandCursor);
  Button->setMinimumHeight(34);
  return Button;
}

void ConfigureActionButton(PushButton *Button, int Width, int Height) {
  if (!Button)
    return;
  Button->setMinimumWidth(Width);
  Button->setMaximumWidth(Width);
  Button->setFixedHeight(Height);
}

void SetTableRefreshEnabled(QTableWidget *Table, bool Enabled,
                            bool SortingEnabled) {
  if (!Table)
    return;
  if (!Enabled) {
    Table->setSortingEnabled(false);
    Table->setUpdatesEnabled(false);
    return;
  }
  Table->setUpdatesEnabled(true);
  Table->setSortingEnabled(SortingEnabled);
}

void SetRefreshUiState(PushButton *Button, IndeterminateProgressRing *Indicator,
                       BodyLabel *StatusLabel, bool Refreshing,
                       const QString &IdleText, const QString &RefreshingText,
                       const QString &IdleStatus,
                       const QString &RefreshingStatus) {
  if (Button) {
    Button->setEnabled(!Refreshing);
    Button->setText(Refreshing ? RefreshingText : IdleText);
  }
  if (Indicator) {
    if (Refreshing) {
      Indicator->show();
      Indicator->start();
    } else {
      Indicator->stop();
      Indicator->hide();
    }
  }
  if (StatusLabel) {
    if (Refreshing && !RefreshingStatus.isEmpty())
      StatusLabel->setText(RefreshingStatus);
    else if (!Refreshing && !IdleStatus.isEmpty())
      StatusLabel->setText(IdleStatus);
  }
}

void ConnectMenuAction(QAction *Action, QObject *Context,
                       std::function<void()> Handler) {
  QObject::connect(
      Action, &QAction::triggered, Context,
      [Context = QPointer<QObject>(Context), Handler = std::move(Handler)] {
        if (!Context)
          return;
        QTimer::singleShot(0, Context, [Context, Handler] {
          if (Context)
            Handler();
        });
      });
}

void ReleaseMenuAfterClose(RoundMenu *Menu) {
  QObject::connect(Menu, &RoundMenu::closed, Menu,
                   [Menu = QPointer<RoundMenu>(Menu)] {
                     QTimer::singleShot(0, qApp, [Menu] {
                       if (Menu)
                         Menu->deleteLater();
                     });
                   });
}

void ShowNotice(QWidget *Parent, InfoBar::Type Type, const QString &Title,
                const QString &Content, bool WriteToConsole = true) {
  if (WriteToConsole &&
      (Type == InfoBar::Type::ERROR || Type == InfoBar::Type::WARNING)) {
    QString Detail = Content.trimmed();
    Detail.replace('\n', "\n    ");
    const QString Prefix = Type == InfoBar::Type::ERROR ? "[!]" : "[WARN]";
    AppendConsoleOutput(QString("%1 %2: %3\n").arg(Prefix, Title, Detail));
  }
  QWidget *Target = Parent ? Parent->window() : QApplication::activeWindow();
  InfoBar::newInfoBar(Type, Title, Content, Qt::Horizontal, true, 3500,
                      InfoBar::Position::TOP_RIGHT, Target);
}

void ShowSuccessNotice(QWidget *Parent, const QString &Title,
                       const QString &Content) {
  ShowNotice(Parent, InfoBar::Type::SUCCESS, Title, Content);
}

void ShowErrorNotice(QWidget *Parent, const QString &Title,
                     const QString &Content, bool WriteToConsole = true) {
  ShowNotice(Parent, InfoBar::Type::ERROR, Title, Content, WriteToConsole);
}

void ShowWarningNotice(QWidget *Parent, const QString &Title,
                       const QString &Content, bool WriteToConsole = true) {
  ShowNotice(Parent, InfoBar::Type::WARNING, Title, Content, WriteToConsole);
}

// 页面(unity build 中先于主窗口定义)通过此钩子发托盘气泡,
// 主窗口 SetupTrayIcon 时注册实际实现。
static std::function<void(const QString &)> G_TrayNotifier;
void AegisNotifyTray(const QString &Message) {
  if (G_TrayNotifier)
    G_TrayNotifier(Message);
}

// 设置页改完热键配置后由此通知主窗口重新注册(页面先于主窗口定义,
// 无法直接引用窗口类型)。主窗口构造时注册实现。
static std::function<QString()> G_HotkeyReapplier;
QString ApplyRuntimeHotkeyConfiguration() {
  if (G_HotkeyReapplier)
    return G_HotkeyReapplier();
  return QStringLiteral("The main window is not ready to register a hotkey.");
}

bool IsToggleHotkeyEnabled() {
  // 兼容只有 HotkeyToggle 的旧配置；显式关闭的设置仍然优先。
  const bool HasShortcut =
      !ConfigurationValue("Application", "HotkeyToggle", "")
           .toString().trimmed().isEmpty();
  return ConfigurationValue("Application", "HotkeyToggleEnabled", HasShortcut)
      .toBool();
}

bool ShowConfirmDialog(QWidget *Parent, const QString &Title,
                       const QString &Content, const QString &ConfirmText,
                       const QString &CancelText) {
  auto *Dialog = new MessageBoxBase(Parent ? Parent->window()
                                           : QApplication::activeWindow());
  Dialog->viewLayout()->setContentsMargins(28, 26, 28, 32);
  Dialog->setAttribute(Qt::WA_DeleteOnClose);
  Dialog->setWindowTitle(Title);
  auto *TitleLabel = MakeLabel(Title, 16, KTextPrimary, QFont::DemiBold);
  auto *ContentLabel = MakeLabel(Content, 12, KTextMuted);
  ContentLabel->setWordWrap(true);
  Dialog->viewLayout()->addWidget(TitleLabel);
  Dialog->viewLayout()->addWidget(ContentLabel);
  Dialog->yesButton()->setText(ConfirmText);
  Dialog->cancelButton()->setText(CancelText);
  QObject::connect(Dialog->yesButton(), &QPushButton::clicked, Dialog,
                   &QDialog::accept);
  QObject::connect(Dialog->cancelButton(), &QPushButton::clicked, Dialog,
                   &QDialog::reject);
  return Dialog->exec() == QDialog::Accepted;
}

// 为独立 QDialog 应用全局主题(调色板 + 应用样式表 + FluentLabel 重着色)。
// 主窗口的样式表只作用于主窗口本身,独立对话框需要各自应用一次。
void ApplyDialogTheme(QWidget *Dialog) {
  ApplyConfiguredAppearance(Dialog);
  // 统一加大对话框内容边距：底部(按钮行)与右侧最多，避免控件/按钮贴边。
  if (QBoxLayout *Layout = qobject_cast<QBoxLayout *>(Dialog->layout())) {
    const QMargins Current = Layout->contentsMargins();
    Layout->setContentsMargins(Current.left() + 6, Current.top() + 4,
                               Current.right() + 6, Current.bottom() + 12);
  }
}

// 无边框对话框标题栏:复用主窗口标题栏的 QSS( QFrame#TitleBar /
// QPushButton#TitleBarClose ),支持按住拖动,右侧为关闭按钮。
class DialogTitleBarFrame : public QFrame {
public:
  explicit DialogTitleBarFrame(QWidget *Parent) : QFrame(Parent) {}

protected:
  void mousePressEvent(QMouseEvent *Event) override {
    if (Event->button() == Qt::LeftButton && windowHandle())
      windowHandle()->startSystemMove();
    QFrame::mousePressEvent(Event);
  }
};

QFrame *CreateDialogTitleBar(QDialog *Dialog, const QString &Title) {
  Dialog->setWindowFlag(Qt::FramelessWindowHint);
  auto *TitleBar = new DialogTitleBarFrame(Dialog);
  TitleBar->setObjectName("TitleBar");
  TitleBar->setFixedHeight(36);
  auto *Layout = new QHBoxLayout(TitleBar);
  Layout->setContentsMargins(14, 0, 0, 0);
  Layout->setSpacing(0);
  auto *TitleLabel = MakeLabel(Title, 11, KTextPrimary, QFont::Normal);
  TitleLabel->setContentsMargins(2, 0, 12, 0);
  TitleLabel->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
  Layout->addWidget(TitleLabel);
  Layout->addStretch();
  auto *CloseButton = new QPushButton(TitleBar);
  CloseButton->setObjectName("TitleBarClose");
  CloseButton->setFixedSize(40, 36);
  QFont CaptionFont;
  CaptionFont.setFamilies({"Segoe Fluent Icons", "Segoe MDL2 Assets"});
  CaptionFont.setPixelSize(10);
  CloseButton->setFont(CaptionFont);
  CloseButton->setText(QChar(0xE8BB));
  CloseButton->setToolTip("Close");
  CloseButton->setCursor(Qt::PointingHandCursor);
  Layout->addWidget(CloseButton);
  QObject::connect(CloseButton, &QPushButton::clicked, Dialog,
                   &QDialog::reject);
  return TitleBar;
}

QString DescribeWin32ErrorMessage(DWORD ErrorCode) {
  QString Message = QString("Win32 error: %1").arg(ErrorCode);
  LPWSTR Buffer = nullptr;
  const DWORD Length = FormatMessageW(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
          FORMAT_MESSAGE_IGNORE_INSERTS,
      nullptr, ErrorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
      reinterpret_cast<LPWSTR>(&Buffer), 0, nullptr);
  if (Length != 0 && Buffer != nullptr) {
    const QString Reason = QString::fromWCharArray(Buffer).trimmed();
    if (!Reason.isEmpty())
      Message += "\nReason: " + Reason;
  }
  if (Buffer != nullptr)
    LocalFree(Buffer);
  return Message;
}

QString DescribeSetTokenError(DWORD ErrorCode) {
  switch (ErrorCode) {
  case ERROR_NOT_FOUND:
    return "Token operation failed: the kernel driver could not locate the "
           "process token layout on this system build.";
  case ERROR_INVALID_PARAMETER:
    return "Token operation failed: the source or target process parameter was "
           "invalid.";
  default:
    return QString("Token operation failed (error %1).").arg(ErrorCode);
  }
}

QString DescribeLaunchAsError(ULONG AccountType, DWORD ErrorCode) {
  switch (ErrorCode) {
  case ERROR_NOT_FOUND:
    return AccountType == ACCOUNT_TYPE_TRUSTEDINSTALLER
               ? "Process launch failed: TrustedInstaller is not running or "
                 "its token source could not be resolved."
               : "Process launch failed: the source account process could not "
                 "be resolved by the driver.";
  case ERROR_INVALID_PARAMETER:
    return "Process launch failed: the executable path could not be converted "
           "to a Win32 launch path or the account type was invalid.";
  case ERROR_ACCESS_DENIED:
    return "Process launch failed: the driver rejected the token assignment "
           "for the suspended process.";
  default:
    return QString("Process launch failed (error %1).").arg(ErrorCode);
  }
}

bool ConvertExecutablePathToDevicePath(const QString &Path, QString &NtPath) {
  QString NativePath = QDir::toNativeSeparators(Path);
  if (NativePath.startsWith("\\Device\\", Qt::CaseInsensitive)) {
    NtPath = NativePath;
    return true;
  }
  if (NativePath.startsWith("\\\\")) {
    NtPath = "\\Device\\Mup" + NativePath.mid(1);
    return true;
  }
  if (NativePath.size() < 3 || NativePath.at(1) != ':')
    return false;

  const QString Drive = NativePath.left(2);
  std::vector<wchar_t> DeviceBuffer(32768, L'\0');
  if (QueryDosDeviceW(reinterpret_cast<LPCWSTR>(Drive.utf16()),
                      DeviceBuffer.data(),
                      static_cast<DWORD>(DeviceBuffer.size())) == 0)
    return false;
  NtPath = QString::fromWCharArray(DeviceBuffer.data()) + NativePath.mid(2);
  return NtPath.startsWith("\\Device\\", Qt::CaseInsensitive);
}

bool ConvertDriverServiceImagePath(const QString &Path, QString &KernelPath) {
  const QString NativePath = QDir::toNativeSeparators(Path.trimmed());
  if (NativePath.isEmpty())
    return false;

  if (NativePath.startsWith("\\??\\", Qt::CaseInsensitive) ||
      NativePath.startsWith("\\SystemRoot\\", Qt::CaseInsensitive)) {
    KernelPath = NativePath;
    return true;
  }

  if (NativePath.startsWith("\\Device\\", Qt::CaseInsensitive)) {
    KernelPath = NativePath;
    return true;
  }

  if (NativePath.startsWith("\\\\")) {
    KernelPath = "\\??\\UNC" + NativePath.mid(1);
    return true;
  }

  if (NativePath.size() >= 3 && NativePath.at(1) == ':' &&
      (NativePath.at(2) == '\\' || NativePath.at(2) == '/')) {
    KernelPath = "\\??\\" + NativePath;
    return true;
  }

  return false;
}

void ShowLaunchAsDialog(QWidget *Parent) {
  auto *Dialog = new MessageBoxBase(Parent ? Parent->window()
                                           : QApplication::activeWindow());
  Dialog->viewLayout()->setContentsMargins(28, 26, 28, 32);
  Dialog->setAttribute(Qt::WA_DeleteOnClose);
  Dialog->setWindowTitle("Run");

  auto *Title = MakeLabel("Run Process", 16, KTextPrimary, QFont::DemiBold);
  auto *Description = MakeLabel(
      "Launch an executable as SYSTEM or TrustedInstaller.", 12, KTextMuted);
  Description->setWordWrap(true);

  auto *Form = new QWidget;
  auto *Grid = new QGridLayout(Form);
  Grid->setContentsMargins(0, 0, 0, 0);
  Grid->setHorizontalSpacing(10);
  Grid->setVerticalSpacing(10);

  auto *Context = new ComboBox;
  Context->addItems({"SYSTEM", "TrustedInstaller"});
  Context->setCurrentIndex(0);
  auto *Executable = new LineEdit;
  Executable->setPlaceholderText("Select an executable");
  auto *Arguments = new LineEdit;
  Arguments->setPlaceholderText("Arguments (currently unsupported)");
  auto *FullPrivileges = new CheckBox("Enable Full Privileges");
  auto *Browse = MakeButton("Browse");

  Grid->addWidget(
      MakeLabel("Security context", 10, KTextPrimary, QFont::DemiBold), 0, 0);
  Grid->addWidget(Context, 0, 1, 1, 2);
  Grid->addWidget(MakeLabel("Executable", 10, KTextPrimary, QFont::DemiBold), 1,
                  0);
  Grid->addWidget(Executable, 1, 1);
  Grid->addWidget(Browse, 1, 2);
  Grid->addWidget(MakeLabel("Arguments", 10, KTextPrimary, QFont::DemiBold), 2,
                  0);
  Grid->addWidget(Arguments, 2, 1, 1, 2);
  Grid->addWidget(FullPrivileges, 3, 1, 1, 2);
  Grid->setColumnStretch(1, 1);

  Dialog->viewLayout()->addWidget(Title);
  Dialog->viewLayout()->addWidget(Description);
  Dialog->viewLayout()->addWidget(Form);
  Dialog->yesButton()->setText("Run");
  Dialog->cancelButton()->setText("Cancel");

  QObject::connect(Browse, &QPushButton::clicked, Dialog, [Dialog, Executable] {
    const QString Path = QFileDialog::getOpenFileName(
        Dialog, "Select executable", QString(),
        "Executable files (*.exe);;All files (*.*)");
    if (!Path.isEmpty())
      Executable->setText(QDir::toNativeSeparators(Path));
  });
  QObject::connect(
      Dialog->yesButton(), &QPushButton::clicked, Dialog,
      [Dialog, Parent, Context, Executable, Arguments, FullPrivileges] {
        const QString Path = Executable->text().trimmed();
        QString NtPath;
        ULONG ProcessId = 0;
        if (Path.isEmpty() || !QFileInfo::exists(Path)) {
          ShowWarningNotice(Parent, "Run",
                            "Select an existing executable file.");
          return;
        }
        if (!Arguments->text().trimmed().isEmpty()) {
          ShowWarningNotice(
              Parent, "Run",
              "The current LaunchAs backend supports executable paths only.");
          return;
        }
        if (!ConvertExecutablePathToDevicePath(Path, NtPath)) {
          ShowErrorNotice(
              Parent, "Run",
              "Unable to convert the executable path to a kernel device path.");
          return;
        }
        const ULONG AccountType = Context->currentIndex() == 0
                                      ? ACCOUNT_TYPE_SYSTEM
                                      : ACCOUNT_TYPE_TRUSTEDINSTALLER;
        if (!LaunchAs(AccountType, NtPath.toStdWString().c_str(), &ProcessId)) {
          ShowErrorNotice(
              Parent, "Run",
              DescribeLaunchAsError(AccountType, G_LastAegisCoreError));
          return;
        }
        ShowSuccessNotice(
            Parent, "Run",
            AccountType == ACCOUNT_TYPE_SYSTEM
                ? QString("Process launched as SYSTEM with pid %1.")
                      .arg(ProcessId)
                : QString("Process launched as TrustedInstaller with pid  %1.")
                      .arg(ProcessId));
        if (FullPrivileges->isChecked()) {
          SetProcessPreviousMode(ProcessId);
        }
        Dialog->accept();
      });
  QObject::connect(Dialog->cancelButton(), &QPushButton::clicked, Dialog,
                   &QDialog::reject);
  Dialog->show();
}

QWidget *WrapPage(QWidget *Body) {
  auto *Page = new QWidget;
  auto *Layout = new QVBoxLayout(Page);
  Layout->setContentsMargins(0, 0, 0, 0);
  Layout->addWidget(Body);
  return Page;
}

class InformationOverviewPage final : public QWidget {
public:
  InformationOverviewPage(QWidget *Parent = nullptr) : QWidget(Parent) {
    auto *RootLayout = new QVBoxLayout(this);
    RootLayout->setContentsMargins(0, 0, 0, 0);
    RootLayout->setSpacing(0);

    auto *Content = new QWidget;
    Content->setObjectName("InformationContent");
    Content->setAutoFillBackground(false);
    auto *Layout = new QVBoxLayout(Content);
    Layout->setContentsMargins(8, 18, 8, 24);
    Layout->setSpacing(16);

    const QString Computer = QProcessEnvironment::systemEnvironment().value(
        "COMPUTERNAME", "Unknown");
    const QString User =
        QProcessEnvironment::systemEnvironment().value("USERNAME", "Unknown");

    auto *Hero = new SimpleCardWidget;
    Hero->setBorderRadius(10);
    Hero->setMinimumHeight(150);
    auto *HeroLayout = new QHBoxLayout(Hero);
    HeroLayout->setContentsMargins(18, 16, 20, 16);
    HeroLayout->setSpacing(18);

    auto *Avatar =
        new QLabel(QString(User.isEmpty() ? "U" : User.left(1).toUpper()));
    Avatar->setFixedSize(82, 82);
    Avatar->setAlignment(Qt::AlignCenter);
    Avatar->setStyleSheet(
        QString("background:%1; color:white; border-radius:41px; "
                "font-size:28px; font-weight:700;")
            .arg(ConfiguredColor("AccentColor", KAccent).name()));
    HeroLayout->addWidget(Avatar, 0, Qt::AlignVCenter);

    auto *HeroText = new QVBoxLayout;
    HeroText->setContentsMargins(8, 4, 0, 4);
    HeroText->setSpacing(6);
    HeroText->addWidget(MakeLabel(QString("Hello, %1").arg(User), 19,
                                  KTextPrimary, QFont::DemiBold));
    HeroText->addWidget(
        MakeLabel(QString("Signed in on %1").arg(Computer), 12, KTextMuted));
    auto *QuoteLabel =
        MakeLabel(RandomInformationQuote(), 12, KTextPrimary, QFont::Medium);
    QuoteLabel->setWordWrap(true);
    HeroText->addWidget(QuoteLabel);
    HeroText->addStretch();
    HeroLayout->addLayout(HeroText, 1);

    auto *HeroPickerColumn = new QVBoxLayout;
    HeroPickerColumn->setContentsMargins(0, 0, 0, 0);
    HeroPickerColumn->setSpacing(8);
    HeroPickerColumn->addWidget(
        MakeLabel("Date", 11, KTextMuted, QFont::Medium), 0, Qt::AlignLeft);
    HeroDateEdit = new ZhDatePicker(this);
    HeroDateEdit->setMinimumWidth(170);
    HeroDateEdit->setDate(QDate::currentDate());
    HeroPickerColumn->addWidget(HeroDateEdit, 0, Qt::AlignLeft);
    HeroPickerColumn->addWidget(
        MakeLabel("Time", 11, KTextMuted, QFont::Medium), 0, Qt::AlignLeft);
    HeroTimeEdit = new TimePicker(this, true);
    HeroTimeEdit->setMinimumWidth(170);
    HeroPickerColumn->addWidget(HeroTimeEdit, 0, Qt::AlignLeft);
    HeroPickerColumn->addStretch();
    HeroLayout->addLayout(HeroPickerColumn, 0);

    auto *HeroHost = new QWidget;
    auto *HeroHostLayout = new QHBoxLayout(HeroHost);
    HeroHostLayout->setContentsMargins(-6, 0, -6, 0);
    HeroHostLayout->setSpacing(0);
    HeroHostLayout->addWidget(Hero);
    Layout->addWidget(HeroHost);

    auto *OverviewCard = new SimpleCardWidget;
    OverviewCard->setBorderRadius(10);
    OverviewCard->setMinimumHeight(248);
    auto *OverviewLayout = new QHBoxLayout(OverviewCard);
    OverviewLayout->setContentsMargins(24, 24, 28, 24);
    OverviewLayout->setSpacing(30);

    auto *OverviewArtworkHost = new QWidget;
    OverviewArtworkHost->setFixedSize(248, 248);
    auto *OverviewArtworkLayout = new QVBoxLayout(OverviewArtworkHost);
    OverviewArtworkLayout->setContentsMargins(0, 0, 0, 0);
    OverviewArtworkLayout->setSpacing(0);
    OverviewArtworkLayout->addWidget(
        MakeApplicationIconFitWidget(QSize(248, 248)), 0, Qt::AlignCenter);
    OverviewLayout->addWidget(OverviewArtworkHost, 0, Qt::AlignVCenter);

    auto *OverviewText = new QVBoxLayout;
    OverviewText->setContentsMargins(8, 6, 0, 6);
    OverviewText->setSpacing(8);
    OverviewText->addWidget(
        MakeLabel("Information", 20, KTextPrimary, QFont::DemiBold));
    auto *HeroDescription =
        MakeLabel("Kernel and user-mode inspection workspace with runtime "
                  "status, hardware telemetry, and environment summary.",
                  12, KTextMuted);
    HeroDescription->setWordWrap(true);
    OverviewText->addWidget(HeroDescription);
    OverviewText->addWidget(MakeLabel(
        QString("System management toolkit  |  v%1").arg(KApplicationVersion),
        12, KTextMuted));
    OverviewText->addStretch();
    OverviewLayout->addLayout(OverviewText, 1);
    Layout->addWidget(OverviewCard);

    const auto AddSection = [Layout](const QString &Title,
                                     const QString &Description) {
      Layout->addWidget(new InformationSectionHeader(Title, Description));
    };

    const QString TestSigning = QueryTestSigning();
    const QString Npcap = QueryNpcap();
    const QString Certificate = CertificateState();
    AddSection("Runtime environment",
               "Pre-flight items required by kernel-assisted features and "
               "traffic monitoring.");

    auto *RuntimeCard = new SimpleCardWidget;
    RuntimeCard->setBorderRadius(10);
    auto *RuntimeLayout = new QVBoxLayout(RuntimeCard);
    RuntimeLayout->setContentsMargins(16, 16, 16, 16);
    RuntimeLayout->setSpacing(10);
    RuntimeLayout->addWidget(new InformationItem(
        Fluent::IconType::ACCEPT, "TestSigning",
        "Windows test-signing mode required by kernel tools.", TestSigning));
    RuntimeLayout->addWidget(new InformationItem(
        Fluent::IconType::CONNECT, "Npcap Service",
        "Packet capture service used by network monitoring.", Npcap));
    RuntimeLayout->addWidget(new InformationItem(
        Fluent::IconType::CERTIFICATE, "HTTP Certificate",
        "Root certificate used for HTTP traffic inspection.", Certificate));
    if (TestSigning != "Enabled" || Npcap != "Running" ||
        Certificate != "Certificate available") {
      RuntimeLayout->addWidget(new InformationNoticeCard(
          Fluent::IconType::INFO, "Runtime requirements incomplete",
          "TestSigning, Npcap, and the HTTP certificate should all be "
          "available before using kernel and monitor features.",
          QColor("#B58A18")));
    }
    Layout->addWidget(RuntimeCard);

    const QString Manufacturer = QuerySystemManufacturer();
    const QString Model = QuerySystemModel();
    const QString Cpu = QueryCpuName();
    const QString Board = QueryBoardName();
    const QString Bios = QueryBiosName();
    const QString Graphics = QueryGraphicsAdapters();
    const QString MemoryInstalled = QueryMemoryInstalled();
    const QString SystemDrive = QuerySystemDriveSummary();
    const SYSTEM_INFO SystemInfo = [] {
      SYSTEM_INFO Value{};
      GetNativeSystemInfo(&Value);
      return Value;
    }();

    AddSection("Performance dashboards",
               "Live system load sampled every second. Collapse any card to "
               "fold all four together.");
    auto *DashboardSurface = new SimpleCardWidget;
    DashboardSurface->setBorderRadius(10);
    auto *DashboardSurfaceLayout = new QVBoxLayout(DashboardSurface);
    DashboardSurfaceLayout->setContentsMargins(16, 16, 16, 16);
    DashboardSurfaceLayout->setSpacing(0);

    auto *DashboardContainer = new QWidget;
    auto *DashboardLayout = new QGridLayout(DashboardContainer);
    DashboardLayout->setContentsMargins(0, 0, 0, 0);
    DashboardLayout->setHorizontalSpacing(12);
    DashboardLayout->setVerticalSpacing(12);

    CpuDashboard =
        new PerformanceDashboardCard(Fluent::IconType::DEVELOPER_TOOLS, "CPU",
                                     "Processor utilization and topology.");
    MemoryDashboard = new PerformanceDashboardCard(
        Fluent::IconType::TILES, "Memory",
        "Physical memory pressure and commit usage.");
    DiskDashboard = new PerformanceDashboardCard(
        Fluent::IconType::FOLDER, "Disk",
        "System drive occupancy and free capacity.");
    NetworkDashboard = new PerformanceDashboardCard(
        Fluent::IconType::GLOBE, "Network",
        "Aggregate receive and transmit throughput.");

    DashboardLayout->addWidget(CpuDashboard, 0, 0);
    DashboardLayout->addWidget(MemoryDashboard, 0, 1);
    DashboardLayout->addWidget(DiskDashboard, 1, 0);
    DashboardLayout->addWidget(NetworkDashboard, 1, 1);
    DashboardLayout->setColumnStretch(0, 1);
    DashboardLayout->setColumnStretch(1, 1);
    DashboardSurfaceLayout->addWidget(DashboardContainer);
    Layout->addWidget(DashboardSurface);

    const auto SyncDashboards = [this](bool Expanded) {
      if (CpuDashboard)
        CpuDashboard->SetExpanded(Expanded);
      if (MemoryDashboard)
        MemoryDashboard->SetExpanded(Expanded);
      if (DiskDashboard)
        DiskDashboard->SetExpanded(Expanded);
      if (NetworkDashboard)
        NetworkDashboard->SetExpanded(Expanded);
    };
    CpuDashboard->SetToggleHandler(SyncDashboards);
    MemoryDashboard->SetToggleHandler(SyncDashboards);
    DiskDashboard->SetToggleHandler(SyncDashboards);
    NetworkDashboard->SetToggleHandler(SyncDashboards);

    AddSection("Hardware profile",
               "Firmware, processor, graphics, and storage details detected "
               "from the current machine.");
    auto *HardwareCard = new SimpleCardWidget;
    HardwareCard->setBorderRadius(10);
    auto *HardwareLayout = new QGridLayout(HardwareCard);
    HardwareLayout->setContentsMargins(16, 16, 16, 16);
    HardwareLayout->setHorizontalSpacing(12);
    HardwareLayout->setVerticalSpacing(12);
    const QList<QWidget *> HardwareItems = {
        new InformationItem(Fluent::IconType::APPLICATION, "Computer",
                            "Current Windows device name.", Computer),
        new InformationItem(Fluent::IconType::PEOPLE, "Manufacturer",
                            "System vendor reported by firmware.",
                            Manufacturer.isEmpty() ? "Unknown" : Manufacturer),
        new InformationItem(Fluent::IconType::APPLICATION, "Model",
                            "System product model exposed by firmware.",
                            Model.isEmpty() ? "Unknown" : Model),
        new InformationItem(Fluent::IconType::DEVELOPER_TOOLS, "Processor",
                            "Primary CPU identification string.",
                            Cpu.isEmpty() ? "Unknown" : Cpu),
        new InformationItem(Fluent::IconType::LAYOUT, "Logical Processors",
                            "Online CPU execution contexts.",
                            QString::number(SystemInfo.dwNumberOfProcessors)),
        new InformationItem(Fluent::IconType::PHOTO, "Graphics",
                            "Active display adapters currently attached.",
                            Graphics.isEmpty() ? "Unknown" : Graphics),
        new InformationItem(Fluent::IconType::TILES, "Installed Memory",
                            "Total visible physical memory.", MemoryInstalled),
        new InformationItem(Fluent::IconType::LAYOUT, "Mainboard",
                            "Baseboard manufacturer and product.",
                            Board.isEmpty() ? "Unknown" : Board),
        new InformationItem(Fluent::IconType::INFO, "BIOS",
                            "Firmware vendor and exported version.",
                            Bios.isEmpty() ? "Unknown" : Bios),
        new InformationItem(Fluent::IconType::FOLDER, "System Drive",
                            "Application drive and current used capacity.",
                            SystemDrive)};
    for (int Index = 0; Index < HardwareItems.size(); ++Index)
      HardwareLayout->addWidget(HardwareItems[Index], Index / 2, Index % 2);
    HardwareLayout->setColumnStretch(0, 1);
    HardwareLayout->setColumnStretch(1, 1);
    Layout->addWidget(HardwareCard);

    const quint64 UptimeMs = GetTickCount64();
    const QDateTime BootTime =
        QDateTime::currentDateTime().addMSecs(-static_cast<qint64>(UptimeMs));
    AddSection("Software profile", "Operating system, boot state, and current "
                                   "process runtime information.");
    auto *SoftwareCard = new SimpleCardWidget;
    SoftwareCard->setBorderRadius(10);
    auto *SoftwareLayout = new QGridLayout(SoftwareCard);
    SoftwareLayout->setContentsMargins(16, 16, 16, 16);
    SoftwareLayout->setHorizontalSpacing(12);
    SoftwareLayout->setVerticalSpacing(12);
    const QList<QWidget *> SoftwareItems = {
        new InformationItem(Fluent::IconType::GLOBE, "Operating System",
                            "Edition, release channel, and build number.",
                            QueryWindowsVersionText()),
        new InformationItem(
            Fluent::IconType::COMMAND_PROMPT, "Kernel",
            "Kernel family and architecture used by the current process.",
            QString("%1  |  %2")
                .arg(QSysInfo::kernelVersion(),
                     QSysInfo::currentCpuArchitecture())),
        new InformationItem(Fluent::IconType::INFO, "Boot Time",
                            "Estimated local boot timestamp.",
                            BootTime.toString("yyyy-MM-dd HH:mm:ss")),
        new InformationItem(Fluent::IconType::STOP_WATCH, "Uptime",
                            "Elapsed time since the last system boot.",
                            FormatDuration(UptimeMs)),
        new InformationItem(
            Fluent::IconType::TILES, "Runtime",
            "Application framework and release version.",
            QString("Qt %1  |  v%2").arg(QT_VERSION_STR, KApplicationVersion)),
        new InformationItem(
            Fluent::IconType::COMMAND_PROMPT, "Process",
            "Current process ID and executable name.",
            QString("%1  |  PID %2")
                .arg(QFileInfo(QCoreApplication::applicationFilePath())
                         .fileName())
                .arg(QCoreApplication::applicationPid())),
        new InformationItem(
            Fluent::IconType::HOME, "Application Path",
            "Runtime directory used by configuration and modules.",
            QDir::toNativeSeparators(QCoreApplication::applicationDirPath()))};
    for (int Index = 0; Index < SoftwareItems.size(); ++Index)
      SoftwareLayout->addWidget(SoftwareItems[Index], Index / 2, Index % 2);
    SoftwareLayout->setColumnStretch(0, 1);
    SoftwareLayout->setColumnStretch(1, 1);
    Layout->addWidget(SoftwareCard);

    Layout->addStretch();

    auto *Scroll = new ScrollArea;
    InstallFluentScrollBar(Scroll, Qt::Vertical);
    Scroll->setObjectName("InformationScroll");
    Scroll->setWidgetResizable(true);
    Scroll->setFrameShape(QFrame::NoFrame);
    Scroll->viewport()->setAutoFillBackground(false);
    Scroll->setWidget(Content);
    RootLayout->addWidget(Scroll);

    const auto CurrentCpuTimes = QueryCpuTimes();
    PreviousIdle = CurrentCpuTimes.Idle;
    PreviousKernel = CurrentCpuTimes.Kernel;
    PreviousUser = CurrentCpuTimes.User;
    PreviousNetwork = QueryNetworkTrafficSnapshot();
    PreviousSampleTime = QDateTime::currentMSecsSinceEpoch();

    UpdateHeroClock();
    UpdatePerformance();
    RefreshTimer = new QTimer(this);
    RefreshTimer->setInterval(1000);
    QObject::connect(RefreshTimer, &QTimer::timeout, this, [this] {
      UpdateHeroClock();
      if (isVisible())
        UpdatePerformance();
    });
    RefreshTimer->start();
  }

private:
  struct CpuTimes {
    quint64 Idle = 0;
    quint64 Kernel = 0;
    quint64 User = 0;
  };

  static CpuTimes QueryCpuTimes() {
    FILETIME IdleTime{}, KernelTime{}, UserTime{};
    if (!GetSystemTimes(&IdleTime, &KernelTime, &UserTime))
      return {};
    const auto ToUInt64 = [](const FILETIME &Value) {
      ULARGE_INTEGER Integer{};
      Integer.LowPart = Value.dwLowDateTime;
      Integer.HighPart = Value.dwHighDateTime;
      return static_cast<quint64>(Integer.QuadPart);
    };
    return {ToUInt64(IdleTime), ToUInt64(KernelTime), ToUInt64(UserTime)};
  }

  void UpdateHeroClock() {
    if (!HeroDateEdit || !HeroTimeEdit)
      return;
    const QDateTime Current = QDateTime::currentDateTime();
    HeroDateEdit->setDate(Current.date());
    HeroTimeEdit->setTime(Current.time());
  }

  void UpdatePerformance() {
    UpdateCpu();
    UpdateMemory();
    UpdateDisk();
    UpdateNetwork();
  }

  void UpdateCpu() {
    const CpuTimes Current = QueryCpuTimes();
    const quint64 IdleDelta = Current.Idle - PreviousIdle;
    const quint64 KernelDelta = Current.Kernel - PreviousKernel;
    const quint64 UserDelta = Current.User - PreviousUser;
    const quint64 TotalDelta = KernelDelta + UserDelta;
    const int Usage =
        TotalDelta == 0
            ? 0
            : static_cast<int>(std::clamp(
                  qRound(((TotalDelta - IdleDelta) * 100.0) / TotalDelta), 0,
                  100));

    PreviousIdle = Current.Idle;
    PreviousKernel = Current.Kernel;
    PreviousUser = Current.User;

    SYSTEM_INFO Info{};
    GetNativeSystemInfo(&Info);
    CpuDashboard->UpdateDashboard(
        Usage, QString::number(Usage) + "%",
        QString("%1 logical processor(s)").arg(Info.dwNumberOfProcessors),
        QString("Architecture: %1").arg(QSysInfo::currentCpuArchitecture()),
        QueryCpuName().isEmpty() ? "CPU name unavailable" : QueryCpuName());
  }

  void UpdateMemory() {
    MEMORYSTATUSEX Memory{};
    Memory.dwLength = sizeof(Memory);
    if (!GlobalMemoryStatusEx(&Memory))
      return;
    const quint64 UsedPhysical = Memory.ullTotalPhys > Memory.ullAvailPhys
                                     ? Memory.ullTotalPhys - Memory.ullAvailPhys
                                     : 0;
    const quint64 UsedCommit =
        Memory.ullTotalPageFile > Memory.ullAvailPageFile
            ? Memory.ullTotalPageFile - Memory.ullAvailPageFile
            : 0;
    MemoryDashboard->UpdateDashboard(
        static_cast<int>(Memory.dwMemoryLoad),
        QString::number(Memory.dwMemoryLoad) + "%",
        QString("Physical: %1 / %2")
            .arg(FormatBytes(UsedPhysical), FormatBytes(Memory.ullTotalPhys)),
        QString("Available: %1").arg(FormatBytes(Memory.ullAvailPhys)),
        QString("Committed: %1 / %2")
            .arg(FormatBytes(UsedCommit),
                 FormatBytes(Memory.ullTotalPageFile)));
  }

  void UpdateDisk() {
    const QStorageInfo Storage(QCoreApplication::applicationDirPath());
    if (!Storage.isValid() || !Storage.isReady())
      return;
    const quint64 Total = static_cast<quint64>(Storage.bytesTotal());
    const quint64 Free = static_cast<quint64>(Storage.bytesAvailable());
    const quint64 Used = Total > Free ? Total - Free : 0;
    const int Usage = Total == 0 ? 0
                                 : static_cast<int>(std::clamp(
                                       qRound((Used * 100.0) / Total), 0, 100));
    DiskDashboard->UpdateDashboard(
        Usage, QString::number(Usage) + "%",
        QString("Drive: %1").arg(QDir::toNativeSeparators(Storage.rootPath())),
        QString("Used: %1 / %2").arg(FormatBytes(Used), FormatBytes(Total)),
        QString("Free: %1").arg(FormatBytes(Free)));
  }

  void UpdateNetwork() {
    const NetworkTrafficSnapshot Current = QueryNetworkTrafficSnapshot();
    const qint64 CurrentSampleTime = QDateTime::currentMSecsSinceEpoch();
    const qint64 ElapsedMs =
        std::max<qint64>(1, CurrentSampleTime - PreviousSampleTime);
    const quint64 DownloadRate =
        Current.InBytes >= PreviousNetwork.InBytes
            ? static_cast<quint64>((Current.InBytes - PreviousNetwork.InBytes) *
                                   1000ull / static_cast<quint64>(ElapsedMs))
            : 0;
    const quint64 UploadRate =
        Current.OutBytes >= PreviousNetwork.OutBytes
            ? static_cast<quint64>(
                  (Current.OutBytes - PreviousNetwork.OutBytes) * 1000ull /
                  static_cast<quint64>(ElapsedMs))
            : 0;
    const quint64 PeakRate = std::max<quint64>(DownloadRate, UploadRate);
    const int Usage =
        PeakRate == 0
            ? 0
            : std::min(100,
                       static_cast<int>(qRound(std::log2(PeakRate + 1) * 8.0)));

    PreviousNetwork = Current;
    PreviousSampleTime = CurrentSampleTime;

    NetworkDashboard->UpdateDashboard(
        Usage,
        QString("D %1 | U %2")
            .arg(FormatRate(DownloadRate), FormatRate(UploadRate)),
        QString("Received: %1").arg(FormatBytes(Current.InBytes)),
        QString("Sent: %1").arg(FormatBytes(Current.OutBytes)),
        QString("Sample interval: %1 ms").arg(ElapsedMs));
  }

  QTimer *RefreshTimer = nullptr;
  PerformanceDashboardCard *CpuDashboard = nullptr;
  PerformanceDashboardCard *MemoryDashboard = nullptr;
  PerformanceDashboardCard *DiskDashboard = nullptr;
  PerformanceDashboardCard *NetworkDashboard = nullptr;
  ZhDatePicker *HeroDateEdit = nullptr;
  TimePicker *HeroTimeEdit = nullptr;
  quint64 PreviousIdle = 0;
  quint64 PreviousKernel = 0;
  quint64 PreviousUser = 0;
  NetworkTrafficSnapshot PreviousNetwork;
  qint64 PreviousSampleTime = 0;
};

QWidget *CreateInformationPage() { return new InformationOverviewPage; }

#include "Source/UI/Pages/TaskManagerPage.cpp"

QWidget *CreateTaskPage() { return new TaskManagerPage; }

#include "Source/UI/Pages/MonitorPage.cpp"

QWidget *CreateMonitorPage() { return new MonitorManagerPage; }

#include "Source/UI/Pages/RegistryPage.cpp"

QWidget *CreateRegistryPage() { return new RegistryManagerPage; }

#include "Source/UI/Pages/FilePage.cpp"

QWidget *CreateFilePage() { return new FileExplorerPage; }

#include "Source/UI/Pages/WindowPage.cpp"

QWidget *CreateWindowPage() { return new WindowManagerPage; }

#include "Source/UI/Pages/DiskPage.cpp"

#include "Source/UI/Pages/MemoryPage.cpp"

#include "Source/UI/Pages/TablePage.cpp"

#include "Source/UI/Pages/CallbackPage.cpp"

#include "Source/UI/Pages/PayloadPage.cpp"

#include "Source/UI/Pages/ModuleRunPage.cpp"

#include "Source/UI/Pages/ConsolePage.cpp"

#include "Source/Core/Auth/AuthHelpers.inc"

#include "Source/Dialogs/RegisterDialog.cpp"

#include "Source/Dialogs/LoginDialog.cpp"

#include "Source/UI/Pages/ChatPage.cpp"

#include "Source/UI/Pages/AccountPage.cpp"

#include "Source/UI/Pages/ModuleManagerPage.cpp"

#include "Source/UI/Pages/KernelInspectorPage.cpp"

#include "Source/UI/Pages/KernelResearchPage.cpp"

#include "Source/UI/Pages/NetworkPage.cpp"

#include "Source/UI/Pages/HookLabPage.cpp"

#include "Source/UI/Pages/SnapshotLabPage.cpp"

#include "Source/UI/Pages/SettingsPage.cpp"

#include "Source/UI/Pages/HotKeysPage.cpp"

QWidget *CreatePageBody(int Index) {
  // 页面工厂：按侧边栏索引创建对应页面实例。
  // 页面定义（标题/副标题/图标）见 Source/UI/Pages/PageRegistry.cpp，
  // 实际的页面类声明集中在 Source/UI/Pages/PageFactory.h。
  switch (Index) {
  case 0:
    return CreateInformationPage();
  case 1:
    return CreateTaskPage();
  case 2:
    return CreateMonitorPage();
  case 3:
    return CreateRegistryPage();
  case 4:
    return CreateFilePage();
  case 5:
    return CreateWindowPage();
  case 6:
    return CreateDriverPage();
  case 7:
    return CreateMemoryPage();
  case 8:
    return CreateTablePage();
  case 9:
    return CreateCallbackPage();
  case 10:
    return CreatePayloadPage();
  case 11:
    return CreateModuleRunPage();
  case 12:
    return CreateModuleManagerPage();
  case 13:
    return CreateConsolePage();
  case 14:
    return CreateChatPage();
  case 15:
    return CreateSettingsPage();
  case 16:
    return CreateKernelInspectorPage();
  case 17:
    return CreateServiceManagerPage();
  case 18:
    return CreateNetworkControlPage();
  case 19:
    return CreateSnapshotLabPage();
  case 20:
    return CreateDiskPage();
  case 21:
    return CreateKernelResearchPage();
  case 22:
    return CreateHookLabPage();
  case 23:
    return CreateAccountPage();
  case 24:
    return CreateHotKeysPage();
  default:
    return new QWidget;
  }
}

// 全局热键的 WM_HOTKEY 接收器。RegisterHotKey 将消息投递到 GUI 线程，
// 由 Qt 原生事件过滤器截获，不依赖主窗口 HWND 的生命周期。
// AegisNTWindow 创建时登记自己的热键回调。
class AegisHotkeyFilter final : public QAbstractNativeEventFilter {
public:
  using Handler = std::function<bool(int HotkeyId)>;

  void SetHandler(Handler InHandler) { Callback = std::move(InHandler); }

  bool nativeEventFilter(const QByteArray &EventType, void *Message,
                         qintptr *Result) override {
    if (Message == nullptr ||
        (EventType != "windows_generic_MSG" &&
         EventType != "windows_dispatcher_MSG"))
      return false;
    MSG *NativeMessage = static_cast<MSG *>(Message);
    if (NativeMessage->message == WM_HOTKEY && Callback &&
        Callback(static_cast<int>(NativeMessage->wParam))) {
      if (Result != nullptr)
        *Result = 0;
      return true;
    }
    return false;
  }

private:
  Handler Callback;
};

static AegisHotkeyFilter G_HotkeyFilter;

// 把 Qt::Key 转成 Win32 虚拟键码（RegisterHotKey 需要 VK_*）。
// 不能直接拿 Qt 键码当 VK 用：ASCII 可见字符段两者恰好一致（Key_A=0x41=VK_A），
// 但 Qt 的功能键/导航键放在私有段 0x01000000+（Key_F1=0x01000030 而 VK_F1=0x70，
// Key_Escape=0x01000000 而 VK_ESCAPE=0x1B），必须查表转换。
// 返回 0 表示该键不支持做全局热键。
static UINT QtKeyToVirtualKey(int QtKey) {
  // ASCII 可见字符与数字/字母段：Qt 与 Win32 完全一致。
  if (QtKey >= Qt::Key_A && QtKey <= Qt::Key_Z)
    return static_cast<UINT>(QtKey); // VK_A..VK_Z == 'A'..'Z'
  if (QtKey >= Qt::Key_0 && QtKey <= Qt::Key_9)
    return static_cast<UINT>(QtKey); // VK_0..VK_9 == '0'..'9'

  switch (QtKey) {
  case Qt::Key_Space:      return VK_SPACE;
  case Qt::Key_Tab:        return VK_TAB;
  case Qt::Key_Backtab:    return VK_TAB;
  case Qt::Key_Return:     return VK_RETURN;
  case Qt::Key_Enter:      return VK_RETURN;
  case Qt::Key_Escape:     return VK_ESCAPE;
  case Qt::Key_Backspace:  return VK_BACK;
  case Qt::Key_Delete:     return VK_DELETE;
  case Qt::Key_Insert:     return VK_INSERT;
  case Qt::Key_Home:       return VK_HOME;
  case Qt::Key_End:        return VK_END;
  case Qt::Key_PageUp:     return VK_PRIOR;
  case Qt::Key_PageDown:   return VK_NEXT;
  case Qt::Key_Left:       return VK_LEFT;
  case Qt::Key_Right:      return VK_RIGHT;
  case Qt::Key_Up:         return VK_UP;
  case Qt::Key_Down:       return VK_DOWN;
  case Qt::Key_Print:      return VK_SNAPSHOT;
  case Qt::Key_Pause:      return VK_PAUSE;
  case Qt::Key_CapsLock:   return VK_CAPITAL;
  case Qt::Key_NumLock:    return VK_NUMLOCK;
  case Qt::Key_ScrollLock: return VK_SCROLL;
  default:
    break;
  }

  // 标点与符号段：Qt 用 ASCII 码，Win32 用 VK_OEM_*，需要显式对应。
  switch (QtKey) {
  case Qt::Key_QuoteLeft:  return VK_OEM_3;     // `
  case Qt::Key_Minus:      return VK_OEM_MINUS; // -
  case Qt::Key_Equal:      return VK_OEM_PLUS;  // =
  case Qt::Key_BracketLeft:  return VK_OEM_4;   // [
  case Qt::Key_BracketRight: return VK_OEM_6;   // ]
  case Qt::Key_Backslash:  return VK_OEM_5;     // backslash
  case Qt::Key_Semicolon:  return VK_OEM_1;     // ;
  case Qt::Key_Apostrophe: return VK_OEM_7;     // '
  case Qt::Key_Comma:      return VK_OEM_COMMA; // ,
  case Qt::Key_Period:     return VK_OEM_PERIOD;// .
  case Qt::Key_Slash:      return VK_OEM_2;     // /
  default:
    break;
  }

  // 功能键 F1..F24：Qt 0x01000030+n 对应 VK_F1+n。
  if (QtKey >= Qt::Key_F1 && QtKey <= Qt::Key_F24)
    return static_cast<UINT>(VK_F1 + (QtKey - Qt::Key_F1));

  // 小键盘数字与常见小键盘运算键。
  if (QtKey >= Qt::Key_0 && QtKey <= Qt::Key_9)
    return static_cast<UINT>(QtKey);

  return 0; // 不支持
}

class AegisNTWindow final : public QWidget {
public:
  AegisNTWindow() {
    setAttribute(Qt::WA_DontCreateNativeAncestors);
    // 无边框窗口：通过 QWK 窗口代理接管系统标题栏，自绘标题栏实现拖动/缩放。
    WindowAgent = new QWK::WidgetWindowAgent(this);
    WindowAgent->setup(this);
    setWindowTitle("AegisNT");
    setMinimumSize(900, 620);
    const QIcon Icon = ApplicationIcon();
    if (!Icon.isNull())
      qApp->setWindowIcon(Icon);
    setWindowIcon(Icon.isNull() ? style()->standardIcon(QStyle::SP_ComputerIcon)
                                : Icon);
    // 页面容器与加载标记：页面按需懒加载，切到对应标签时才首次实例化。
    PageContainers.resize(AegisNT::PageDefinitions().size());
    PageLoaded.resize(AegisNT::PageDefinitions().size(), false);

    // 整体布局：顶部自绘标题栏 + 中部（左侧边栏 + 右侧内容栈）。
    auto *Root = new QVBoxLayout(this);
    Root->setContentsMargins(0, 0, 0, 0);
    Root->setSpacing(0);
    Root->addWidget(CreateTitleBar());
    auto *Body = new QWidget;
    Body->setObjectName("WindowBody");
    auto *BodyLayout = new QHBoxLayout(Body);
    BodyLayout->setContentsMargins(0, 0, 0, 0);
    BodyLayout->setSpacing(0);
    BodyLayout->addWidget(CreateSidebar());
    BodyLayout->addWidget(CreateContent(), 1);
    Root->addWidget(Body, 1);

    ApplyStyleSheet();
    ApplyConfiguredAppearance(this);
    SetupTrayIcon();
    // 全局热键：注册 WM_HOTKEY 接收器，并按配置注册切换显隐的热键。
    G_HotkeyFilter.SetHandler([this](int HotkeyId) {
      if (HotkeyId != KToggleHotkeyId || !ToggleHotkeyRegistered)
        return false;
      ToggleWindowVisibility();
      return true;
    });
    qApp->installNativeEventFilter(&G_HotkeyFilter);
    const QString HotkeyError = ApplyToggleHotkey();
    if (!HotkeyError.isEmpty()) {
      AppendConsoleOutput("[!] Hotkey: " + HotkeyError + "\n");
      ShowTrayMessage(HotkeyError);
    }
    G_HotkeyReapplier = [this] { return ApplyToggleHotkey(); };
    QTimer::singleShot(0, this, [this] {
      SelectPage(0, false);
      PageStack->setAnimationEnabled(true);
      if (!ModulesScanned &&
          (ConfigurationValue("Drivers", "AutoLoad", true).toBool() ||
           ConfigurationValue("Modules", "AutoLoad", true).toBool()))
        ScanRuntimeModules();
		if (TryOpenDevice()) {
			ProtectProcess(GetCurrentProcessId());
		}
    });
  }

  ~AegisNTWindow() override {
    UnregisterToggleHotkey();
    G_HotkeyReapplier = nullptr;
    qApp->removeNativeEventFilter(&G_HotkeyFilter);
    G_HotkeyFilter.SetHandler(nullptr);
    if (TrayIcon) {
      TrayIcon->hide();
      TrayIcon->deleteLater();
      TrayIcon = nullptr;
    }
  }

  // 隐藏到托盘（关闭按钮、托盘菜单 Hide、全局热键共用）。
  void HideToTray() {
    hide();
    ShowTrayMessage("AegisNT is still running in the tray.");
  }

  // 从托盘/最小化状态唤起窗口（托盘菜单、双击托盘、第二实例、全局热键共用）。
  void RestoreFromTray() {
    AllowWindowClose = false;
    showNormal();
    raise();
    activateWindow();
  }

  // 全局热键的显隐切换：已显示则隐藏到托盘，否则唤起。
  void ToggleWindowVisibility() {
    if (isVisible() && !isMinimized())
      HideToTray();
    else
      RestoreFromTray();
  }

protected:
  void showEvent(QShowEvent *Event) override {
    QWidget::showEvent(Event);
    ScheduleBackdropRefresh(this);
  }

  void closeEvent(QCloseEvent *Event) override {
    // 关闭按钮 = 隐藏到托盘（托盘不可用时才真正退出）。
    if (TrayIcon && TrayIcon->isVisible() && !AllowWindowClose) {
      Event->ignore();
      HideToTray();
      return;
    }
    QWidget::closeEvent(Event);
  }

  void paintEvent(QPaintEvent *Event) override {
    QWidget::paintEvent(Event);
    // WA_NoSystemBackground 禁用了 backing store 的自动擦除。先替换旧像素，
    // 再绘制壁纸与子控件；SourceOver 的透明填充无法清除上一帧的文字/页面。
    QPainter Painter(this);
    Painter.setCompositionMode(QPainter::CompositionMode_Source);
    Painter.fillRect(rect(),
                     property("ThemeBackdropEffectiveMaterial").toInt() != 0
                         ? QColor(Qt::transparent)
                         : palette().color(QPalette::Window));
    Painter.setCompositionMode(QPainter::CompositionMode_SourceOver);
    // 壁纸参数按配置代数缓存，避免每次 paint 走 QJson 查找。
    const int Generation = CurrentConfigurationGeneration();
    if (Generation != CachedWallpaperGeneration) {
      CachedWallpaperGeneration = Generation;
      CachedWallpaperPathValue =
          ConfigurationValue("Theme", "WallpaperPath", "").toString();
      CachedWallpaperModeValue = std::clamp(
          ConfigurationValue("Theme", "WallpaperMode", 0).toInt(), 0, 3);
      CachedWallpaperOpacityValue =
          std::clamp(ConfigurationValue("Theme", "WallpaperOpacity",
                                        KDefaultThemeWallpaperOpacity)
                         .toInt(),
                     5, 100) /
          100.0;
    }
    if (CachedWallpaperPathValue.isEmpty())
      return;
    if (CachedWallpaperPath != CachedWallpaperPathValue ||
        CachedWallpaperMode != CachedWallpaperModeValue ||
        CachedWallpaperSize != size())
      RebuildWallpaperCache(CachedWallpaperPathValue, CachedWallpaperModeValue);
    if (WallpaperSource.isNull())
      return;

    Painter.setOpacity(CachedWallpaperOpacityValue);
    if (CachedWallpaperModeValue == 3)
      Painter.drawTiledPixmap(rect(), WallpaperSource);
    else if (!CachedWallpaper.isNull())
      Painter.drawPixmap(0, 0, CachedWallpaper);
  }

  void resizeEvent(QResizeEvent *Event) override {
    QWidget::resizeEvent(Event);
    CachedWallpaperSize = QSize();
  }

  void moveEvent(QMoveEvent *Event) override {
    QWidget::moveEvent(Event);
    // BackgroundMaterial 按配置代数缓存：移动窗口时每个 moveEvent
    // 都会到达这里，逐次 QJson 查找开销可观。
    const int Generation = CurrentConfigurationGeneration();
    if (Generation != CachedBackdropGeneration || CachedBackdropMaterial < 0) {
      CachedBackdropGeneration = Generation;
      CachedBackdropMaterial = std::clamp(
          ConfigurationValue("Theme", "BackgroundMaterial",
                             KDefaultThemeBackgroundMaterial).toInt(),
          0, 2);
    }
    if (CachedBackdropMaterial != 0)
      ScheduleBackdropRefresh(this);
  }

  void changeEvent(QEvent *Event) override {
    QWidget::changeEvent(Event);
    if (Event->type() == QEvent::WindowStateChange) {
      UpdateMaximizeButton();
      ScheduleBackdropRefresh(this);
      // 最小化保持普通最小化，不再自动隐藏到托盘；只有标题栏/系统菜单的
      // 关闭按钮（closeEvent）才隐藏到托盘。
    }
  }

private:
  QWidget *CreateTitleBar() {
    auto *TitleBar = new QFrame;
    TitleBar->setObjectName("TitleBar");
    const int NativeTitleBarHeight =
        std::max(32, WindowAgent->windowAttribute("title-bar-height").toInt());
    TitleBar->setFixedHeight(NativeTitleBarHeight);
    auto *Layout = new QHBoxLayout(TitleBar);
    Layout->setContentsMargins(0, 0, 0, 0);
    Layout->setSpacing(0);

    auto *IconButton = new QPushButton;
    IconButton->setObjectName("TitleBarIcon");
    IconButton->setFixedSize(40, NativeTitleBarHeight);
    IconButton->setIcon(windowIcon());
    IconButton->setIconSize(QSize(16, 16));
    IconButton->setToolTip("System menu");
    IconButton->setCursor(Qt::PointingHandCursor);
    auto *WindowTitle =
        MakeLabel(windowTitle(), 11, KTextPrimary, QFont::Normal);
    WindowTitle->setContentsMargins(2, 0, 12, 0);
    WindowTitle->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);

    const auto CreateSystemButton =
        [NativeTitleBarHeight](const QString &ObjectName, const wchar_t *Glyph,
                               const QString &ToolTip) {
          auto *Button = new QPushButton;
          Button->setObjectName(ObjectName);
          Button->setFixedSize(40, NativeTitleBarHeight);
          QFont CaptionFont;
          CaptionFont.setFamilies({"Segoe Fluent Icons", "Segoe MDL2 Assets"});
          CaptionFont.setPixelSize(10);
          Button->setFont(CaptionFont);
          Button->setText(QString::fromWCharArray(Glyph));
          Button->setToolTip(ToolTip);
          return Button;
        };
    auto *MinimizeButton =
        CreateSystemButton("TitleBarMinimize", L"\xE921", "Minimize");
    MaximizeButton =
        CreateSystemButton("TitleBarMaximize", L"\xE922", "Maximize");
    auto *CloseButton = CreateSystemButton("TitleBarClose", L"\xE8BB", "Close");

    Layout->addWidget(IconButton);
    Layout->addWidget(WindowTitle);
    Layout->addStretch();
    Layout->addWidget(MinimizeButton);
    Layout->addWidget(MaximizeButton);
    Layout->addWidget(CloseButton);

    WindowAgent->setTitleBar(TitleBar);
    WindowAgent->setSystemButton(QWK::WindowAgentBase::WindowIcon, IconButton);
    WindowAgent->setSystemButton(QWK::WindowAgentBase::Minimize,
                                 MinimizeButton);
    WindowAgent->setSystemButton(QWK::WindowAgentBase::Maximize,
                                 MaximizeButton);
    WindowAgent->setSystemButton(QWK::WindowAgentBase::Close, CloseButton);

    QObject::connect(
        IconButton, &QPushButton::clicked, this, [this, IconButton] {
          WindowAgent->showSystemMenu(
              IconButton->mapToGlobal(QPoint(0, IconButton->height())));
        });
    QObject::connect(MinimizeButton, &QPushButton::clicked, this,
                     &QWidget::showMinimized);
    QObject::connect(MaximizeButton, &QPushButton::clicked, this, [this] {
      isMaximized() ? showNormal() : showMaximized();
    });
    QObject::connect(CloseButton, &QPushButton::clicked, this, &QWidget::close);
    UpdateMaximizeButton();
    return TitleBar;
  }

  void UpdateMaximizeButton() {
    if (!MaximizeButton)
      return;
    const bool Maximized = isMaximized();
    MaximizeButton->setText(
        QString::fromWCharArray(Maximized ? L"\xE923" : L"\xE922"));
    MaximizeButton->setToolTip(Maximized ? "Restore" : "Maximize");
  }

  void RebuildWallpaperCache(const QString &Path, int Mode) {
    if (CachedWallpaperPath != Path || WallpaperSource.isNull()) {
      QImageReader Reader(Path);
      Reader.setAutoTransform(true);
      Reader.setDecideFormatFromContent(true);
      QImage Image = Reader.read();
      if (Image.isNull())
        Image = LoadImageWithWic(Path);
      WallpaperSource =
          Image.isNull() ? QPixmap() : QPixmap::fromImage(Image);
    }
    CachedWallpaperPath = Path;
    CachedWallpaperMode = Mode;
    CachedWallpaperSize = size();
    CachedWallpaper = QPixmap();
    if (WallpaperSource.isNull() || Mode == 3 || size().isEmpty())
      return;
    if (Mode == 2)
      CachedWallpaper = WallpaperSource.scaled(size(), Qt::IgnoreAspectRatio,
                                               Qt::SmoothTransformation);
    else {
      const Qt::AspectRatioMode RatioMode =
          Mode == 1 ? Qt::KeepAspectRatio : Qt::KeepAspectRatioByExpanding;
      const QPixmap Scaled =
          WallpaperSource.scaled(size(), RatioMode, Qt::SmoothTransformation);
      CachedWallpaper = QPixmap(size());
      CachedWallpaper.fill(Qt::transparent);
      QPainter Painter(&CachedWallpaper);
      Painter.drawPixmap((width() - Scaled.width()) / 2,
                         (height() - Scaled.height()) / 2, Scaled);
    }
  }

  QWidget *CreateSidebar() {
    auto *Sidebar = new QFrame;
    Sidebar->setObjectName("Sidebar");
    Sidebar->setFixedWidth(KSidebarWidth);
    auto *Layout = new QVBoxLayout(Sidebar);
    Layout->setContentsMargins(0, 0, 0, 0);
    Layout->setSpacing(0);

    NavigationPanelWidget = new NavigationPanel(Sidebar);
    NavigationPanelWidget->setFixedWidth(KSidebarWidth);
    NavigationPanelWidget->setExpandWidth(KSidebarWidth);
    NavigationPanelWidget->setMenuButtonVisible(false);
    NavigationPanelWidget->setReturnButtonVisible(false);
    NavigationPanelWidget->setCollapsible(false);
    NavigationPanelWidget->setAcrylicEnabled(false);
    const auto AddPageItem = [this](int Index, const QString &ParentRoute = {}) {
      const auto &Page = AegisNT::PageDefinitions()[Index];
      const QString Route = QString::number(Index);
      NavigationPanelWidget->addItem(
          Route, CreateFluentIcon(Page.Icon), Page.Title,
          [this, Index] { SelectPage(Index); }, true,
          NavigationPanel::ItemPosition::SCROLL, Page.Title, ParentRoute);
    };

    for (int Index : {0, 1, 2, 3, 4, 5})
      AddPageItem(Index);

    NavigationPanelWidget->addItem(
        "kernel", CreateFluentIcon(Fluent::IconType::DEVELOPER_TOOLS),
        "Kernel", nullptr, false, NavigationPanel::ItemPosition::SCROLL,
        "Kernel");
    NavigationPanelWidget->addItem(
        "kernel-overview", CreateFluentIcon(Fluent::IconType::SEARCH),
        "Overview", nullptr, false, NavigationPanel::ItemPosition::SCROLL,
        "Overview", "kernel");
    for (int Index : {16, 21, 24})
      AddPageItem(Index, "kernel-overview");

    NavigationPanelWidget->addItem(
        "kernel-execution",
        CreateFluentIcon(Fluent::IconType::DEVELOPER_TOOLS), "Execution",
        nullptr, false, NavigationPanel::ItemPosition::SCROLL, "Execution",
        "kernel");
    for (int Index : {6, 17, 18, 22, 7, 8, 9})
      AddPageItem(Index, "kernel-execution");

    NavigationPanelWidget->addItem(
        "kernel-storage", CreateFluentIcon(Fluent::IconType::SAVE), "Storage",
        nullptr, false, NavigationPanel::ItemPosition::SCROLL, "Storage",
        "kernel");
    for (int Index : {19, 20})
      AddPageItem(Index, "kernel-storage");

    NavigationPanelWidget->addItem(
        "module", CreateFluentIcon(Fluent::IconType::LIBRARY), "Module",
        nullptr, false, NavigationPanel::ItemPosition::SCROLL, "Module");
    for (int Index : {10, 11, 12})
      AddPageItem(Index, "module");

    for (int Index : {13, 14, 23, 15})
      AddPageItem(Index);
    Layout->addWidget(NavigationPanelWidget, 1);
    NavigationPanelWidget->expand(false);
    return Sidebar;
  }

  QWidget *CreateContent() {
    auto *Content = new QWidget;
    Content->setObjectName("Content");
    auto *Layout = new QVBoxLayout(Content);
    Layout->setContentsMargins(24, 20, 24, 24);
    Layout->setSpacing(0);

    TitleLabelWidget = MakeLabel("", 22, KAccent, QFont::DemiBold);
    TitleLabelWidget->setFixedHeight(40);
    SubtitleLabelWidget = MakeLabel("", 11, KTextMuted);
    SubtitleLabelWidget->setFixedHeight(24);
    Layout->addWidget(TitleLabelWidget);
    Layout->addSpacing(4);
    Layout->addWidget(SubtitleLabelWidget);
    Layout->addSpacing(14);

    PageStack = new StackedWidget(nullptr, AnimationType::PopUp);
    PageStack->setAnimationEnabled(false);
    for (int Index = 0;
         Index < static_cast<int>(AegisNT::PageDefinitions().size()); ++Index) {
      auto *Container = new QWidget;
      auto *ContainerLayout = new QVBoxLayout(Container);
      ContainerLayout->setContentsMargins(0, 0, 0, 0);
      ContainerLayout->setSpacing(0);
      PageContainers[Index] = Container;
      PageStack->addWidget(Container, 0, 12);
    }
    PageStack->setCurrentIndex(0, false, 0, false);
    Layout->addWidget(PageStack, 1);
    return Content;
  }

  void SelectPage(int Index, bool Animate = true) {
    // 切换侧边栏页面：懒加载目标页、同步标题/副标题并做运行时翻译，
    // 最后切换 QStackedWidget（首次加载不做动画，避免闪跳）。
    if (Index < 0 ||
        Index >= static_cast<int>(AegisNT::PageDefinitions().size()))
      return;
    const bool WasLoaded = PageLoaded[Index];
    EnsurePageLoaded(Index);
    NavigationPanelWidget->setCurrentItem(QString::number(Index));
    TitleLabelWidget->setProperty("LanguageOriginal_text",
                                  AegisNT::PageDefinitions()[Index].Title);
    SubtitleLabelWidget->setProperty(
        "LanguageOriginal_text", AegisNT::PageDefinitions()[Index].Subtitle);
    TitleLabelWidget->setText(AegisNT::PageDefinitions()[Index].Title);
    SubtitleLabelWidget->setText(AegisNT::PageDefinitions()[Index].Subtitle);
    TranslateObject(TitleLabelWidget);
    TranslateObject(SubtitleLabelWidget);
    PageStack->setCurrentIndex(Index, Animate && WasLoaded, 120, false);
    // 页面切换只更新内容，不重新设置窗口级 DWM 材质。
  }

  void EnsurePageLoaded(int Index) {
    // 页面懒加载：首次访问时经 CreatePageBody 创建实例并挂入容器。
    if (PageLoaded[Index])
      return;
    QWidget *Body = CreatePageBody(Index);
    PageContainers[Index]->layout()->addWidget(Body);
    PageLoaded[Index] = true;
  }

  void SetupTrayIcon() {
    // 托盘图标：注册页面发通知的全局钩子，提供 还原/隐藏/退出 菜单；
    // 关闭主窗口时若托盘可见则最小化到托盘而非退出。
    G_TrayNotifier = [this](const QString &Message) {
      ShowTrayMessage(Message);
    };
    if (!QSystemTrayIcon::isSystemTrayAvailable())
      return;

    TrayIcon = new QSystemTrayIcon(this);
    const QIcon Icon = windowIcon().isNull()
                           ? style()->standardIcon(QStyle::SP_ComputerIcon)
                           : windowIcon();
    TrayIcon->setIcon(Icon);
    TrayIcon->setToolTip("AegisNT");

    auto *TrayMenu = new QMenu(this);
    TrayMenu->setTitle("AegisNT");
    auto *RestoreAction = new QAction("Restore", TrayMenu);
    auto *HideAction = new QAction("Hide", TrayMenu);
    auto *ExitAction = new QAction("Exit", TrayMenu);
    TrayMenu->addAction(RestoreAction);
    TrayMenu->addAction(HideAction);
    TrayMenu->addSeparator();
    TrayMenu->addAction(ExitAction);

    ConnectMenuAction(RestoreAction, this, [this] { RestoreFromTray(); });
    ConnectMenuAction(HideAction, this, [this] { HideToTray(); });
    ConnectMenuAction(ExitAction, this, [this] {
      AllowWindowClose = true;
      qApp->quit();
    });
    connect(TrayIcon, &QSystemTrayIcon::activated, this,
            [this](QSystemTrayIcon::ActivationReason Reason) {
              if (Reason == QSystemTrayIcon::Trigger ||
                  Reason == QSystemTrayIcon::DoubleClick)
                RestoreFromTray();
            });

    TrayIcon->setContextMenu(TrayMenu);
    TrayIcon->show();
  }

  void ShowTrayMessage(const QString &Message) {
    if (TrayIcon && TrayIcon->isVisible())
      TrayIcon->showMessage("AegisNT", Message, TrayIcon->icon(), 2000);
  }

  // ---- 全局热键（RegisterHotKey + WM_HOTKEY 原生事件过滤） ----
  // 通过 RegisterHotKey 注册一个系统级热键，触发时切换窗口显隐。
  // 配置项 Application/HotkeyToggle（空字符串表示不注册），
  // Application/HotkeyToggleEnabled 为总开关。
  QString ApplyToggleHotkey() {
    UnregisterToggleHotkey();

    if (!IsToggleHotkeyEnabled())
      return {};

    const QString Sequence = ConfigurationValue("Application", "HotkeyToggle", "")
                                 .toString()
                                 .trimmed();
    if (Sequence.isEmpty())
      return {};

    const QKeySequence Key(Sequence, QKeySequence::PortableText);
    if (Key.isEmpty() || Key.count() != 1)
      return QStringLiteral("Global hotkey must contain exactly one key combination.");

    // Qt 功能键包含 0x01000000，不能用 0x00FFFFFF 截取键码。
    const QKeyCombination Combination = Key[0];
    const UINT Vk = QtKeyToVirtualKey(static_cast<int>(Combination.key()));
    if (Vk == 0)
      return QString("Hotkey %1 cannot be used as a global shortcut.")
          .arg(Sequence);

    const Qt::KeyboardModifiers KeyModifiers = Combination.keyboardModifiers();
    UINT Modifiers = 0;
    if (KeyModifiers.testFlag(Qt::ControlModifier))
      Modifiers |= MOD_CONTROL;
    if (KeyModifiers.testFlag(Qt::AltModifier))
      Modifiers |= MOD_ALT;
    if (KeyModifiers.testFlag(Qt::ShiftModifier))
      Modifiers |= MOD_SHIFT;
    if (KeyModifiers.testFlag(Qt::MetaModifier))
      Modifiers |= MOD_WIN;
    if (Modifiers == 0) {
      // 无修饰键的单键做全局热键会抢占正常输入，拒绝并告知。
      return QStringLiteral("Global hotkey needs at least one modifier "
                            "(Ctrl / Alt / Shift / Win).");
    }

    // 绑定 GUI 线程，窗口隐藏或原生句柄重建后仍能收到 WM_HOTKEY。
    if (::RegisterHotKey(nullptr, KToggleHotkeyId, Modifiers | MOD_NOREPEAT, Vk)) {
      ToggleHotkeyRegistered = true;
      qInfo("AegisNT: toggle hotkey registered: %s",
            Sequence.toUtf8().constData());
      return {};
    }

    const DWORD Error = ::GetLastError();
    if (Error == ERROR_HOTKEY_ALREADY_REGISTERED)
      return QString("Toggle hotkey %1 is already in use by another program.")
          .arg(Sequence);
    return QString("Failed to register toggle hotkey %1 (Windows error %2).")
        .arg(Sequence).arg(Error);
  }

  void UnregisterToggleHotkey() {
    if (!ToggleHotkeyRegistered)
      return;
    ::UnregisterHotKey(nullptr, KToggleHotkeyId);
    ToggleHotkeyRegistered = false;
  }

  static constexpr int KToggleHotkeyId = 0xA17E;

  void ApplyStyleSheet() { setStyleSheet(ApplicationStyleSheet()); }

  NavigationPanel *NavigationPanelWidget = nullptr;
  QWK::WidgetWindowAgent *WindowAgent = nullptr;
  QPushButton *MaximizeButton = nullptr;
  FluentLabelBase *TitleLabelWidget = nullptr;
  FluentLabelBase *SubtitleLabelWidget = nullptr;
  StackedWidget *PageStack = nullptr;
  std::vector<QWidget *> PageContainers;
  std::vector<bool> PageLoaded;
  QString CachedWallpaperPath;
  int CachedWallpaperMode = -1;
  QSize CachedWallpaperSize;
  QPixmap WallpaperSource;
  QPixmap CachedWallpaper;
  int CachedWallpaperGeneration = -1;
  QString CachedWallpaperPathValue;
  int CachedWallpaperModeValue = 0;
  double CachedWallpaperOpacityValue =
      KDefaultThemeWallpaperOpacity / 100.0;
  int CachedBackdropGeneration = -1;
  int CachedBackdropMaterial = -1;
  QSystemTrayIcon *TrayIcon = nullptr;
  bool AllowWindowClose = false;
  bool ToggleHotkeyRegistered = false;
};

} // namespace

// 单实例 IPC 通道名。第二个实例通过它把「唤起窗口」请求静默发给已运行实例，
// 不再弹「already running」提示框。
static const char *KSingleInstanceChannel = "AegisNT_SingleInstance_IPC";

int main(int Argc, char *Argv[]) {
  // 单实例：已在运行则静默唤起它（含双击关联文件等场景），本进程直接退出。
  // 不再弹「already running」提示框。
  {
    QLocalSocket Probe;
    Probe.connectToServer(QLatin1String(KSingleInstanceChannel));
    if (Probe.waitForConnected(300)) {
      Probe.write("restore\n");
      Probe.flush();
      Probe.waitForBytesWritten(300);
      Probe.disconnectFromServer();
      return 0;
    }
  }

  QGuiApplication::setAttribute(Qt::AA_DontCreateNativeWidgetSiblings);
  QApplication Application(Argc, Argv);
  Application.setApplicationName("AegisNT");
  Application.setApplicationDisplayName("AegisNT");
  Application.setOrganizationName("AegisNT");
  InitInjectLog();
  // 将受注入目标(模块)的 stdout/stderr 转发到控制台页。
  SetInjectLogSink([](const char *Data, size_t Len) {
    const QByteArray Bytes(Data, static_cast<int>(Len));
    QStringDecoder Decoder(QStringDecoder::Utf8, QStringConverter::Flag::Stateless);
    QString Result = Decoder.decode(Bytes);
    if (Decoder.hasError())
      Result = QString::fromLocal8Bit(Bytes);
    AppendConsoleOutput(Result);
  });
  StartStandardIoCapture();
  InstallQtMessageCapture();
  // 加载磁盘配置(Data/Config.json)，用于语言、窗口尺寸、主题等初始化。
  LoadConfiguration();
  // 启动不再信任持久化的登录态:主窗口创建必须先通过登录对话框 / 自动登录。
  // 仅回填用户名供登录框预填。
  Account = {};
  Account.UserName =
      ConfigurationValue("Account", "UserName", "").toString().trimmed();
  LoadLanguageResources();
  ActiveLanguage =
      ConfigurationValue("Application", "Language", "en_US").toString() ==
              "zh_CN"
          ? "zh_CN"
          : "en_US";
  LanguageFilter = new RuntimeLanguageFilter(&Application);
  Application.installEventFilter(LanguageFilter);
  QObject::connect(&Application, &QCoreApplication::aboutToQuit,
                   [] { CleanupManagedDriversOnExit(); });
EnsureThemeConfiguration();
  ApplyConfiguredAppearance(nullptr);

  int Result = 0;
  {
    if (!RunLoginFlow(nullptr)) {
      // 用户关闭登录对话框:退出程序。
      StopStandardIoCapture();
      return 0;
    }
    AegisNTWindow Window;
    // 单实例服务端：第二实例（如双击关联文件）连上来即唤起本窗口，
    // 静默处理，不弹任何提示。
    QLocalServer::removeServer(QLatin1String(KSingleInstanceChannel));
    QLocalServer InstanceServer;
    QObject::connect(&InstanceServer, &QLocalServer::newConnection, &Window,
                     [&InstanceServer, &Window] {
                       while (QLocalSocket *Client =
                                  InstanceServer.nextPendingConnection()) {
                         QObject::connect(Client, &QLocalSocket::disconnected,
                                          Client, &QLocalSocket::deleteLater);
                         Window.RestoreFromTray();
                         Client->disconnectFromServer();
                       }
                     });
    InstanceServer.listen(QLatin1String(KSingleInstanceChannel));
    const QRect Available = Window.screen()->availableGeometry();
    const int ConfiguredWidth =
        ConfigurationValue("Application", "Width", 1600).toInt();
    const int ConfiguredHeight =
        ConfigurationValue("Application", "Height", 1000).toInt();
    const int Width =
        std::min(ConfiguredWidth, std::max(900, Available.width() - 40));
    const int Height =
        std::min(ConfiguredHeight, std::max(620, Available.height() - 40));
    Window.resize(Width, Height);
    Window.show();
    Result = Application.exec();
  }

  if (ActiveConsoleProcess &&
      ActiveConsoleProcess->state() != QProcess::NotRunning) {
    ActiveConsoleProcess->kill();
    ActiveConsoleProcess->waitForFinished(1000);
  }
  if (ModuleRunning.load() && !RunningModulePath.isEmpty()) {
    if (ModuleEntry *RunningModule = FindDllModule(RunningModulePath);
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
    for (ModuleEntry &Module : DllModules)
      DestroyModuleInstance(Module);
  }
  StopStandardIoCapture();
  return Result;
}
