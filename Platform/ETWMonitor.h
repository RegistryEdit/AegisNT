#pragma once

#include <evntcons.h>
#include <evntrace.h>
#include <functional>
#include <guiddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <mutex>
#include <string>
#include <tdh.h>
#include <unordered_map>
#include <vector>
#include <windows.h>

#ifndef MAX_SESSION_NAME_LEN
#define MAX_SESSION_NAME_LEN 1024
#endif

enum class EventCategory : int {
  Unknown = 0,
  ProcessCreate,
  ProcessExit,
  ThreadCreate,
  ThreadExit,
  ImageLoad,
  ImageUnload,
  FileCreate,
  FileRead,
  FileWrite,
  FileDelete,
  FileRename,
  FileClose,
  FileFlush,
  FileQueryInfo,
  FileSetInfo,
  RegOpenKey,
  RegCreateKey,
  RegDeleteKey,
  RegDeleteValue,
  RegQueryValue,
  RegQueryKey,
  RegSetValue,
  RegCloseKey,
  RegEnumerateKey,
  RegEnumerateValueKey,
  RegFlush,
  TcpConnect,
  TcpAccept,
  TcpSend,
  TcpRecv,
  TcpDisconnect,
  UdpSend,
  UdpRecv,
  VirtualAlloc,
  VirtualFree,
  MemoryHardFault,
};

struct ParsedEvent {
  EventCategory Category;
  DWORD ProcessId;
  DWORD ThreadId;
  DWORD ParentPid;
  USHORT EventId;
  std::wstring ProcessName;
  std::wstring ProviderName;
  GUID ProviderGuid;
  ULONGLONG StartAddr;
  std::wstring ImageName;
  std::wstring FileName;
  std::wstring RegistryPath;
  std::wstring ValueName;
  std::wstring LocalAddress;
  USHORT LocalPort = 0;
  std::wstring RemoteAddress;
  USHORT RemotePort = 0;
  ULONG InterfaceIndex = 0;
  DWORD DataSize;
  FILETIME TimeStamp;
};

struct EtwProvider {
  std::wstring Name;
  GUID Guid;
  ULONGLONG MatchAnyKeyword;
  UCHAR Level;
};

static const EtwProvider KProviders[] = {
    {L"Kernel-Process",
     {0x22fb2cd6,
      0x0e7b,
      0x422b,
      {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}},
     0,
     TRACE_LEVEL_VERBOSE},
    {L"Kernel-File",
     {0xedd08927,
      0x9cc4,
      0x4e65,
      {0xb9, 0x70, 0xc2, 0x56, 0x0f, 0xb5, 0xc2, 0x61}},
     0,
     TRACE_LEVEL_VERBOSE},
    {L"Kernel-Registry",
     {0x70eb4f03,
      0xc1de,
      0x4f73,
      {0xa0, 0x51, 0x33, 0xd1, 0x3d, 0x54, 0x13, 0xbd}},
     0,
     TRACE_LEVEL_VERBOSE},
    {L"Kernel-Network",
     {0x7dd42a49,
      0x5329,
      0x4832,
      {0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88}},
     0,
     TRACE_LEVEL_VERBOSE},
    {L"Kernel-Memory",
     {0xd1d93ef7,
      0xe1f2,
      0x4f45,
      {0x99, 0x43, 0x03, 0xd2, 0x45, 0xfe, 0x6c, 0x00}},
     0,
     TRACE_LEVEL_VERBOSE},
};
static constexpr int KProviderCount =
    sizeof(KProviders) / sizeof(KProviders[0]);

// 内核之外精选的知名系统(manifest)提供程序。
// manifest 提供程序需要非零 keyword 掩码才会产出事件。
static const EtwProvider KSystemProviders[] = {
    {L"Microsoft-Windows-DNS-Client",
     {0x1c95126e,
      0x7eea,
      0x49a9,
      {0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d}},
     ~0ull,
     TRACE_LEVEL_VERBOSE},
    {L"Microsoft-Windows-Winsock-AFD",
     {0xe53c6823,
      0x7bb8,
      0x44bb,
      {0x90, 0xdc, 0x3f, 0x52, 0x9c, 0x4a, 0x06, 0xe2}},
     ~0ull,
     TRACE_LEVEL_VERBOSE},
    {L"Microsoft-Windows-Kernel-Audit-API-Calls",
     {0xe02a841c,
      0x75a3,
      0x4fa7,
      {0xaf, 0xc8, 0xae, 0x09, 0xcf, 0x9b, 0x7f, 0x23}},
     ~0ull,
     TRACE_LEVEL_VERBOSE},
    {L"Security",
     {0x54849625,
      0x5478,
      0x4994,
      {0xa5, 0xba, 0x3e, 0x3b, 0x03, 0x28, 0xc3, 0x0d}},
     ~0ull,
     TRACE_LEVEL_VERBOSE},
    {L"Microsoft-Windows-DotNETRuntime",
     {0xe13c0d23,
      0xccbc,
      0x4e12,
      {0x93, 0x1b, 0xd9, 0xcc, 0x2e, 0xee, 0x27, 0xe4}},
     ~0ull,
     TRACE_LEVEL_VERBOSE},
    {L"Microsoft-Windows-PowerShell",
     {0xa0c1853b,
      0x5c40,
      0x4b5d,
      {0x8b, 0x00, 0xf5, 0x33, 0x99, 0x95, 0xea, 0x11}},
     ~0ull,
     TRACE_LEVEL_VERBOSE},
    {L"Microsoft-Windows-Win32k",
     {0x8c416c79,
      0xd49b,
      0x4f01,
      {0xa4, 0x67, 0xe5, 0x6d, 0x3a, 0xa8, 0x23, 0x4c}},
     ~0ull,
     TRACE_LEVEL_VERBOSE},
    {L"Microsoft-Windows-SMBClient",
     {0x9502e570,
      0xe1dd,
      0x4f2b,
      {0x84, 0x51, 0xd3, 0xb2, 0xe3, 0x9c, 0xdb, 0xdc}},
     ~0ull,
     TRACE_LEVEL_VERBOSE},
    {L"Microsoft-Windows-Windows-Defender",
     {0x11cd958a,
      0xc507,
      0x4ef3,
      {0xb3, 0xf2, 0x5f, 0xd9, 0xdf, 0xbd, 0x2c, 0x78}},
     ~0ull,
     TRACE_LEVEL_VERBOSE},
};
static constexpr int KSystemProviderCount =
    sizeof(KSystemProviders) / sizeof(KSystemProviders[0]);

static const GUID GuidKernelProcess = {
    0x22fb2cd6,
    0x0e7b,
    0x422b,
    {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}};
static const GUID GuidKernelFile = {
    0xedd08927,
    0x9cc4,
    0x4e65,
    {0xb9, 0x70, 0xc2, 0x56, 0x0f, 0xb5, 0xc2, 0x61}};
static const GUID GuidKernelRegistry = {
    0x70eb4f03,
    0xc1de,
    0x4f73,
    {0xa0, 0x51, 0x33, 0xd1, 0x3d, 0x54, 0x13, 0xbd}};
static const GUID GuidKernelNetwork = {
    0x7dd42a49,
    0x5329,
    0x4832,
    {0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88}};
static const GUID GuidKernelMemory = {
    0xd1d93ef7,
    0xe1f2,
    0x4f45,
    {0x99, 0x43, 0x03, 0xd2, 0x45, 0xfe, 0x6c, 0x00}};
static const GUID GuidSystemTraceControl = {
    0x9e814aad,
    0x3204,
    0x11d2,
    {0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39}};
static const GUID GuidWindowsToolEtw = {
    0x7d5b8a1c,
    0x1f54,
    0x4f25,
    {0x9d, 0x3c, 0x71, 0x9d, 0x3e, 0x4b, 0x2a, 0x10}};

static TRACEHANDLE G_SessionHandle = INVALID_PROCESSTRACE_HANDLE;
static TRACEHANDLE G_TraceHandle = INVALID_PROCESSTRACE_HANDLE;
static BOOL G_Running = FALSE;
static BOOL G_Verbose = FALSE;
static ULONG G_LastStartTraceStatus = ERROR_SUCCESS;
static std::function<void(const ParsedEvent &)> G_EtwEventCallback;

static const WCHAR *G_SessionName = L"WindowsToolETW";

// 当前会话启用的提供程序集合（由 StartKernelTrace 设定）。
static std::vector<EtwProvider> G_SelectedProviders;

static const std::wstring *FindProviderName(const GUID &Guid) {
  for (const EtwProvider &P : G_SelectedProviders)
    if (P.Guid == Guid)
      return &P.Name;
  return nullptr;
}

static bool IsProviderSelected(const GUID &Guid) {
  return FindProviderName(Guid) != nullptr;
}

static std::wstring FormatTimestamp(const FILETIME &Ft) {
  SYSTEMTIME St;
  FileTimeToSystemTime(&Ft, &St);
  WCHAR Buf[64];
  swprintf_s(Buf, L"%04d-%02d-%02d %02d:%02d:%02d.%03d", St.wYear, St.wMonth,
             St.wDay, St.wHour, St.wMinute, St.wSecond, St.wMilliseconds);
  return Buf;
}

// GUI 模式下默认关闭逐事件控制台回显：wprintf + SetConsoleTextAttribute
// 在高事件量下是显著的 CPU 与分配热点，且 GUI 进程本就看不到输出。
static bool G_EtwConsoleEcho = false;

static void EnableEtwConsoleEcho(bool Enable) { G_EtwConsoleEcho = Enable; }

// PID->进程名缓存：ETW 每事件都要解析进程名，OpenProcess + 文件名查询
// 在 VERBOSE 级别下是每秒数千次的重复系统调用。缓存上限触发时整体清空。
static std::wstring GetProcessNameFromPid(DWORD Pid) {
  if (Pid == 4)
    return L"System";
  if (Pid == 0)
    return L"Idle";

  static std::mutex CacheMutex;
  static std::unordered_map<DWORD, std::wstring> NameCache;
  {
    std::lock_guard<std::mutex> Lock(CacheMutex);
    auto It = NameCache.find(Pid);
    if (It != NameCache.end())
      return It->second;
  }

  std::wstring Name = L"<unknown>";
  HANDLE HProcess =
      OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, Pid);
  if (HProcess) {
    WCHAR Path[MAX_PATH] = {0};
    DWORD Size = MAX_PATH;
    if (QueryFullProcessImageNameW(HProcess, 0, Path, &Size)) {
      WCHAR *P = wcsrchr(Path, L'\\');
      Name = P ? (P + 1) : Path;
    }
    CloseHandle(HProcess);
  }

  {
    std::lock_guard<std::mutex> Lock(CacheMutex);
    if (NameCache.size() >= 4096)
      NameCache.clear();
    NameCache.emplace(Pid, Name);
  }
  return Name;
}

static void PrintHeader(const WCHAR *Category, WORD Color) {
  HANDLE HConsole = GetStdHandle(STD_OUTPUT_HANDLE);
  SetConsoleTextAttribute(HConsole, Color);
  wprintf(L"\n========================================\n");
  wprintf(L"  %s\n", Category);
  wprintf(L"========================================\n");
  SetConsoleTextAttribute(HConsole, 7);
}

static DWORD GetPropertyU32(PEVENT_RECORD Rec, const WCHAR *Name) {
  PROPERTY_DATA_DESCRIPTOR Desc;
  DWORD Val = 0, SZ = sizeof(Val);
  Desc.PropertyName = (ULONGLONG)Name;
  Desc.ArrayIndex = ULONG_MAX;
  TdhGetPropertySize(Rec, 0, NULL, 1, &Desc, &SZ);
  TdhGetProperty(Rec, 0, NULL, 1, &Desc, SZ, (PBYTE)&Val);
  return Val;
}

static ULONGLONG GetPropertyU64(PEVENT_RECORD Rec, const WCHAR *Name) {
  PROPERTY_DATA_DESCRIPTOR Desc;
  ULONGLONG Val = 0;
  DWORD SZ = sizeof(Val);
  Desc.PropertyName = (ULONGLONG)Name;
  Desc.ArrayIndex = ULONG_MAX;
  TdhGetPropertySize(Rec, 0, NULL, 1, &Desc, &SZ);
  TdhGetProperty(Rec, 0, NULL, 1, &Desc, SZ, (PBYTE)&Val);
  return Val;
}

static std::wstring GetPropertyString(PEVENT_RECORD Rec, const WCHAR *Name) {
  PROPERTY_DATA_DESCRIPTOR Desc;
  Desc.PropertyName = (ULONGLONG)Name;
  Desc.ArrayIndex = ULONG_MAX;
  DWORD SZ = 0;
  if (TdhGetPropertySize(Rec, 0, NULL, 1, &Desc, &SZ) != ERROR_SUCCESS)
    return L"";
  WCHAR *Buf = (WCHAR *)malloc(SZ);
  if (!Buf)
    return L"";
  if (TdhGetProperty(Rec, 0, NULL, 1, &Desc, SZ, (PBYTE)Buf) != ERROR_SUCCESS) {
    free(Buf);
    return L"";
  }
  std::wstring Result(Buf);
  free(Buf);
  return Result;
}

static std::vector<BYTE> GetPropertyBlob(PEVENT_RECORD Rec,
                                         const WCHAR *Name) {
  PROPERTY_DATA_DESCRIPTOR Desc;
  Desc.PropertyName = (ULONGLONG)Name;
  Desc.ArrayIndex = ULONG_MAX;
  DWORD SZ = 0;
  if (TdhGetPropertySize(Rec, 0, NULL, 1, &Desc, &SZ) != ERROR_SUCCESS ||
      SZ == 0)
    return {};
  std::vector<BYTE> Buf(SZ);
  if (TdhGetProperty(Rec, 0, NULL, 1, &Desc, SZ, Buf.data()) != ERROR_SUCCESS)
    return {};
  return Buf;
}

static std::wstring DecodeSockaddr(const std::vector<BYTE> &Blob,
                                   USHORT &Port) {
  Port = 0;
  if (Blob.size() < 4)
    return L"";
  const USHORT Family = (USHORT)(Blob[0] | (Blob[1] << 8));
  Port = (USHORT)((Blob[2] << 8) | Blob[3]);
  WCHAR Text[64] = {0};
  if (Family == 2 /* AF_INET */ && Blob.size() >= 8) {
    swprintf_s(Text, L"%u.%u.%u.%u", Blob[4], Blob[5], Blob[6], Blob[7]);
    return Text;
  }
  if (Family == 23 /* AF_INET6 */ && Blob.size() >= 24) {
    const BYTE *A = &Blob[8];
    // 完整 8 组十六进制形式（不做压缩），保持解码零依赖。
    swprintf_s(Text, L"[%x:%x:%x:%x:%x:%x:%x:%x]", (A[0] << 8) | A[1],
               (A[2] << 8) | A[3], (A[4] << 8) | A[5], (A[6] << 8) | A[7],
               (A[8] << 8) | A[9], (A[10] << 8) | A[11], (A[12] << 8) | A[13],
               (A[14] << 8) | A[15]);
    return Text;
  }
  Port = 0;
  return L"";
}

static EventCategory ClassifyEvent(const GUID &ProviderGuid, USHORT EventId) {
  if (ProviderGuid == GuidKernelProcess) {
    switch (EventId) {
    case 1:
      return EventCategory::ProcessCreate;
    case 2:
      return EventCategory::ProcessExit;
    case 3:
      return EventCategory::ThreadCreate;
    case 4:
      return EventCategory::ThreadExit;
    case 5:
      return EventCategory::ImageLoad;
    case 6:
      return EventCategory::ImageUnload;
    }
  } else if (ProviderGuid == GuidKernelFile) {
    switch (EventId) {
    case 30:
      return EventCategory::FileCreate;
    case 32:
      return EventCategory::FileCreate;
    case 35:
      return EventCategory::FileDelete;
    case 36:
      return EventCategory::FileRename;
    case 40:
      return EventCategory::FileWrite;
    case 41:
      return EventCategory::FileWrite;
    case 42:
      return EventCategory::FileRead;
    case 43:
      return EventCategory::FileRead;
    case 44:
      return EventCategory::FileClose;
    }
  } else if (ProviderGuid == GuidKernelRegistry) {
    switch (EventId) {
    case 1:
      return EventCategory::RegCreateKey;
    case 2:
      return EventCategory::RegOpenKey;
    case 3:
      return EventCategory::RegDeleteKey;
    case 4:
      return EventCategory::RegQueryKey;
    case 6:
      return EventCategory::RegSetValue;
    case 7:
      return EventCategory::RegDeleteValue;
    case 8:
      return EventCategory::RegQueryValue;
    case 9:
      return EventCategory::RegEnumerateKey;
    case 10:
      return EventCategory::RegEnumerateValueKey;
    case 13:
      return EventCategory::RegCloseKey;
    }
  } else if (ProviderGuid == GuidKernelNetwork) {
    switch (EventId) {
    case 10:
      return EventCategory::TcpSend;
    case 11:
      return EventCategory::TcpRecv;
    case 12:
      return EventCategory::TcpConnect;
    case 13:
      return EventCategory::TcpAccept;
    case 15:
      return EventCategory::TcpDisconnect;
    case 26:
      return EventCategory::UdpSend;
    case 27:
      return EventCategory::UdpRecv;
    }
  } else if (ProviderGuid == GuidKernelMemory) {
    switch (EventId) {
    case 1:
      return EventCategory::VirtualAlloc;
    case 2:
      return EventCategory::VirtualFree;
    case 5:
      return EventCategory::MemoryHardFault;
    }
  }
  return EventCategory::Unknown;
}

static ParsedEvent ParseEvent(PEVENT_RECORD Rec) {
  ParsedEvent Evt = {};
  Evt.ProcessId = Rec->EventHeader.ProcessId;
  Evt.ThreadId = Rec->EventHeader.ThreadId;
  Evt.EventId = Rec->EventHeader.EventDescriptor.Id;
  Evt.ProviderGuid = Rec->EventHeader.ProviderId;
  Evt.ProcessName = GetProcessNameFromPid(Evt.ProcessId);
  Evt.TimeStamp = *(FILETIME *)&Rec->EventHeader.TimeStamp;
  Evt.Category = ClassifyEvent(Rec->EventHeader.ProviderId,
                               Rec->EventHeader.EventDescriptor.Id);
  if (Rec->EventHeader.ProviderId == GuidKernelNetwork) {
    Evt.LocalAddress = DecodeSockaddr(GetPropertyBlob(Rec, L"saddr"),
                                      Evt.LocalPort);
    Evt.RemoteAddress = DecodeSockaddr(GetPropertyBlob(Rec, L"daddr"),
                                       Evt.RemotePort);
    Evt.InterfaceIndex = GetPropertyU32(Rec, L"nid");
    Evt.DataSize = GetPropertyU32(Rec, L"size");
  }
  switch (Evt.Category) {
  case EventCategory::ProcessCreate:
    Evt.ParentPid = GetPropertyU32(Rec, L"ParentId");
    Evt.ImageName = GetPropertyString(Rec, L"ImageName");
    break;
  case EventCategory::ThreadCreate:
    Evt.StartAddr = GetPropertyU64(Rec, L"StartAddr");
    break;
  case EventCategory::ImageLoad:
    Evt.ImageName = GetPropertyString(Rec, L"ImageName");
    break;
  case EventCategory::FileCreate:
  case EventCategory::FileWrite:
  case EventCategory::FileRead:
  case EventCategory::FileDelete:
  case EventCategory::FileRename:
    Evt.FileName = GetPropertyString(Rec, L"FileName");
    Evt.DataSize = GetPropertyU32(Rec, L"IoSize");
    break;
  case EventCategory::RegCreateKey:
  case EventCategory::RegOpenKey:
  case EventCategory::RegDeleteKey:
  case EventCategory::RegQueryKey:
  case EventCategory::RegSetValue:
  case EventCategory::RegDeleteValue:
  case EventCategory::RegQueryValue:
  case EventCategory::RegCloseKey:
    Evt.RegistryPath = GetPropertyString(Rec, L"KeyName");
    Evt.ValueName = GetPropertyString(Rec, L"ValueName");
    break;
  default:
    break;
  }
  return Evt;
}

static const WCHAR *CategoryToString(EventCategory Cat) {
  switch (Cat) {
  case EventCategory::ProcessCreate:
    return L"Process Create";
  case EventCategory::ProcessExit:
    return L"Process Exit";
  case EventCategory::ThreadCreate:
    return L"Thread Create";
  case EventCategory::ThreadExit:
    return L"Thread Exit";
  case EventCategory::ImageLoad:
    return L"DLL Load";
  case EventCategory::ImageUnload:
    return L"DLL Unload";
  case EventCategory::FileCreate:
    return L"File Create";
  case EventCategory::FileRead:
    return L"File Read";
  case EventCategory::FileWrite:
    return L"File Write";
  case EventCategory::FileDelete:
    return L"File Delete";
  case EventCategory::FileRename:
    return L"File Rename";
  case EventCategory::FileClose:
    return L"File Close";
  case EventCategory::RegOpenKey:
    return L"Reg OpenKey";
  case EventCategory::RegCreateKey:
    return L"Reg CreateKey";
  case EventCategory::RegDeleteKey:
    return L"Reg DeleteKey";
  case EventCategory::RegDeleteValue:
    return L"Reg DeleteValue";
  case EventCategory::RegQueryValue:
    return L"Reg QueryValue";
  case EventCategory::RegQueryKey:
    return L"Reg QueryKey";
  case EventCategory::RegSetValue:
    return L"Reg SetValue";
  case EventCategory::RegCloseKey:
    return L"Reg CloseKey";
  case EventCategory::RegEnumerateKey:
    return L"Reg EnumKey";
  case EventCategory::RegEnumerateValueKey:
    return L"Reg EnumValue";
  case EventCategory::TcpConnect:
    return L"TCP Connect";
  case EventCategory::TcpAccept:
    return L"TCP Accept";
  case EventCategory::TcpSend:
    return L"TCP Send";
  case EventCategory::TcpRecv:
    return L"TCP Recv";
  case EventCategory::TcpDisconnect:
    return L"TCP Disconnect";
  case EventCategory::UdpSend:
    return L"UDP Send";
  case EventCategory::UdpRecv:
    return L"UDP Recv";
  case EventCategory::VirtualAlloc:
    return L"VirtualAlloc";
  case EventCategory::VirtualFree:
    return L"VirtualFree";
  case EventCategory::MemoryHardFault:
    return L"Memory Fault";
  default:
    return L"Unknown Event";
  }
}

static WORD CategoryToColor(EventCategory Cat) {
  switch (Cat) {
  case EventCategory::ProcessCreate:
  case EventCategory::ProcessExit:
  case EventCategory::ThreadCreate:
  case EventCategory::ThreadExit:
    return 10;
  case EventCategory::FileCreate:
  case EventCategory::FileWrite:
  case EventCategory::FileRead:
  case EventCategory::FileDelete:
  case EventCategory::FileRename:
  case EventCategory::FileClose:
    return 11;
  case EventCategory::RegOpenKey:
  case EventCategory::RegCreateKey:
  case EventCategory::RegDeleteKey:
  case EventCategory::RegDeleteValue:
  case EventCategory::RegQueryValue:
  case EventCategory::RegQueryKey:
  case EventCategory::RegSetValue:
  case EventCategory::RegCloseKey:
  case EventCategory::RegEnumerateKey:
  case EventCategory::RegEnumerateValueKey:
    return 13;
  case EventCategory::TcpConnect:
  case EventCategory::TcpAccept:
  case EventCategory::TcpSend:
  case EventCategory::TcpRecv:
  case EventCategory::TcpDisconnect:
  case EventCategory::UdpSend:
  case EventCategory::UdpRecv:
    return 9;
  case EventCategory::VirtualAlloc:
  case EventCategory::VirtualFree:
  case EventCategory::MemoryHardFault:
    return 14;
  default:
    return 7;
  }
}

static void PrintParsedEvent(const ParsedEvent &Evt) {
  HANDLE HConsole = GetStdHandle(STD_OUTPUT_HANDLE);
  std::wstring Ts = FormatTimestamp(Evt.TimeStamp);
  const std::wstring &ProcName = Evt.ProcessName;
  WORD Color = CategoryToColor(Evt.Category);

  SetConsoleTextAttribute(HConsole, Color);
  wprintf(L"[%s] ", Ts.c_str());
  wprintf(L"PID:%-6lu ", Evt.ProcessId);
  wprintf(L"%-16s %s", ProcName.c_str(), CategoryToString(Evt.Category));

  switch (Evt.Category) {
  case EventCategory::ProcessCreate:
    wprintf(L" PPID:%-6lu Name:%s", Evt.ParentPid, Evt.ImageName.c_str());
    break;
  case EventCategory::ThreadCreate:
    wprintf(L" TID:%-6lu StartAddr:0x%llX", Evt.ThreadId, Evt.StartAddr);
    break;
  case EventCategory::ImageLoad:
    wprintf(L" Image:%s", Evt.ImageName.c_str());
    break;
  case EventCategory::FileCreate:
  case EventCategory::FileWrite:
  case EventCategory::FileRead:
  case EventCategory::FileDelete:
  case EventCategory::FileRename:
    wprintf(L" File:%s Size:%lu", Evt.FileName.c_str(), Evt.DataSize);
    break;
  case EventCategory::RegSetValue:
  case EventCategory::RegQueryValue:
  case EventCategory::RegDeleteValue:
    wprintf(L" Key:%s Value:%s", Evt.RegistryPath.c_str(),
            Evt.ValueName.c_str());
    break;
  case EventCategory::RegOpenKey:
  case EventCategory::RegCreateKey:
  case EventCategory::RegDeleteKey:
  case EventCategory::RegEnumerateKey:
  case EventCategory::RegEnumerateValueKey:
    wprintf(L" Key:%s", Evt.RegistryPath.c_str());
    break;
  default:
    break;
  }
  wprintf(L"\n");
  SetConsoleTextAttribute(HConsole, 7);
}

static void
SetEtwEventCallback(std::function<void(const ParsedEvent &)> Callback) {
  G_EtwEventCallback = std::move(Callback);
}

static ULONG GetLastStartTraceStatus() { return G_LastStartTraceStatus; }

static BOOL WINAPI CtrlHandler(DWORD CtrlType) {
  (void)CtrlType;
  G_Running = FALSE;
  return TRUE;
}

static void WINAPI EventRecordCallback(PEVENT_RECORD Rec) {
  EventCategory Cat = ClassifyEvent(Rec->EventHeader.ProviderId,
                                    Rec->EventHeader.EventDescriptor.Id);
  const bool Selected = IsProviderSelected(Rec->EventHeader.ProviderId);
  if (Cat == EventCategory::Unknown && !G_Verbose && !Selected)
    return;
  ParsedEvent Evt = ParseEvent(Rec);
  if (Cat == EventCategory::Unknown && Selected) {
    if (const std::wstring *Name =
            FindProviderName(Rec->EventHeader.ProviderId))
      Evt.ProviderName = *Name;
  }
  if (G_EtwEventCallback) {
    G_EtwEventCallback(Evt);
  }
  if (G_EtwConsoleEcho)
    PrintParsedEvent(Evt);
}

static ULONG WINAPI BufferCallback(PEVENT_TRACE_LOGFILEW LogFile) {
  (void)LogFile;
  return TRUE;
}

static BOOL
StartKernelTrace(const std::vector<EtwProvider> *Providers = nullptr) {
  G_LastStartTraceStatus = ERROR_SUCCESS;
  G_SelectedProviders =
      Providers ? *Providers
                : std::vector<EtwProvider>(KProviders,
                                           KProviders + KProviderCount);
  ULONG BufSize = sizeof(EVENT_TRACE_PROPERTIES) +
                  ((MAX_SESSION_NAME_LEN + 1) * sizeof(WCHAR));

  EVENT_TRACE_PROPERTIES *Props = (EVENT_TRACE_PROPERTIES *)malloc(BufSize);
  if (!Props) {
    wprintf(L"[ERROR] Memory allocation failed\n");
    G_LastStartTraceStatus = ERROR_NOT_ENOUGH_MEMORY;
    return FALSE;
  }
  ZeroMemory(Props, BufSize);

  Props->Wnode.BufferSize = BufSize;
  Props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
  Props->Wnode.ClientContext = 1;
  Props->Wnode.Guid = GuidWindowsToolEtw;
  Props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
  Props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
  Props->LogFileNameOffset = 0;
  Props->BufferSize = 256;
  Props->MinimumBuffers = 64;
  Props->MaximumBuffers = 256;

  wcscpy_s((WCHAR *)((BYTE *)Props + Props->LoggerNameOffset),
           MAX_SESSION_NAME_LEN + 1, G_SessionName);
  ULONG Status = StartTraceW(&G_SessionHandle, G_SessionName, Props);
  if (Status == ERROR_ALREADY_EXISTS) {
    Status = ControlTraceW(0, G_SessionName, Props, EVENT_TRACE_CONTROL_STOP);
    if (Status != ERROR_SUCCESS) {
      wprintf(L"[ERROR] Failed to stop existing session: %lu\n", Status);
      G_LastStartTraceStatus = Status;
      free(Props);
      return FALSE;
    }
    Status = StartTraceW(&G_SessionHandle, G_SessionName, Props);
  }

  if (Status != ERROR_SUCCESS) {
    wprintf(L"[ERROR] StartTraceW failed: %lu\n", Status);
    G_LastStartTraceStatus = Status;
    free(Props);
    return FALSE;
  }

  int EnabledProviders = 0;
  for (const EtwProvider &Provider : G_SelectedProviders) {
    Status = EnableTraceEx2(G_SessionHandle, &Provider.Guid,
                            EVENT_CONTROL_CODE_ENABLE_PROVIDER, Provider.Level,
                            Provider.MatchAnyKeyword, 0, 0, NULL);
    if (Status == ERROR_SUCCESS) {
      ++EnabledProviders;
      wprintf(L"[OK] Provider enabled: %s\n", Provider.Name.c_str());
    } else {
      wprintf(L"[WARN] Failed to enable provider %s: %lu\n",
              Provider.Name.c_str(), Status);
    }
  }

  if (EnabledProviders == 0) {
    G_LastStartTraceStatus = ERROR_INVALID_PARAMETER;
    ControlTraceW(G_SessionHandle, G_SessionName, Props,
                  EVENT_TRACE_CONTROL_STOP);
    G_SessionHandle = INVALID_PROCESSTRACE_HANDLE;
    free(Props);
    return FALSE;
  }

  free(Props);
  return TRUE;
}

static bool
EnumerateSystemProviders(std::vector<EtwProvider> &Out) {
  ULONG Size = 0;
  ULONG Status = TdhEnumerateProviders(NULL, &Size);
  if (Status != ERROR_INSUFFICIENT_BUFFER || Size == 0)
    return false;
  std::vector<BYTE> Buffer(Size);
  PPROVIDER_ENUMERATION_INFO Info =
      (PPROVIDER_ENUMERATION_INFO)Buffer.data();
  Status = TdhEnumerateProviders(Info, &Size);
  if (Status != ERROR_SUCCESS)
    return false;
  // PROVIDER_ENUMERATION_INFO = { ULONG NumberOfProviders; ULONG Reserved;
  // TRACE_PROVIDER_INFO TraceProviderInfoArray[ANYSIZE_ARRAY]; } — 内联
  // 数组成员名在不同 SDK 版本间有改动，但内存布局未变。
  struct RawProviderInfo {
    GUID ProviderGuid;
    ULONG SchemaSource;
    ULONG ProviderNameOffset;
  };
  static_assert(sizeof(RawProviderInfo) == 24, "unexpected TDH ABI");
  const RawProviderInfo *Raw =
      (const RawProviderInfo *)((const BYTE *)Info + 2 * sizeof(ULONG));
  for (ULONG I = 0; I < Info->NumberOfProviders; ++I) {
    if (Raw[I].ProviderNameOffset == 0)
      continue;
    EtwProvider Provider;
    Provider.Name = (LPCWSTR)((BYTE *)Info + Raw[I].ProviderNameOffset);
    Provider.Guid = Raw[I].ProviderGuid;
    // manifest 提供程序在空 keyword 掩码下不会产出任何事件。
    Provider.MatchAnyKeyword = ~0ull;
    Provider.Level = TRACE_LEVEL_VERBOSE;
    Out.push_back(std::move(Provider));
  }
  return true;
}

static BOOL
OpenAndProcessTrace() {
  EVENT_TRACE_LOGFILEW LogFile = {};
  LogFile.LoggerName = (LPWSTR)G_SessionName;
  LogFile.ProcessTraceMode =
      PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
  LogFile.EventRecordCallback = EventRecordCallback;
  LogFile.BufferCallback = BufferCallback;

  G_TraceHandle = OpenTraceW(&LogFile);
  if (G_TraceHandle == INVALID_PROCESSTRACE_HANDLE) {
    wprintf(L"[ERROR] OpenTraceW failed: %lu\n", GetLastError());
    return FALSE;
  }

  wprintf(L"[INFO] Monitor started, press Ctrl+C to exit...\n\n");

  G_Running = TRUE;
  TRACEHANDLE Handles[] = {G_TraceHandle};
  ULONG Err = ProcessTrace(Handles, 1, NULL, NULL);

  if (Err != ERROR_SUCCESS && Err != ERROR_CANCELLED) {
    wprintf(L"[ERROR] ProcessTrace failed: %lu\n", Err);
    return FALSE;
  }
  return TRUE;
}

static void StopTrace() {
  if (G_SessionHandle != INVALID_PROCESSTRACE_HANDLE) {
    ULONG BufSize = sizeof(EVENT_TRACE_PROPERTIES) +
                    ((MAX_SESSION_NAME_LEN + 1) * sizeof(WCHAR));
    EVENT_TRACE_PROPERTIES *Props = (EVENT_TRACE_PROPERTIES *)malloc(BufSize);
    if (Props) {
      ZeroMemory(Props, BufSize);
      Props->Wnode.BufferSize = BufSize;
      Props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
      Props->LogFileNameOffset = 0;
      wcscpy_s((WCHAR *)((BYTE *)Props + Props->LoggerNameOffset),
               MAX_SESSION_NAME_LEN + 1, G_SessionName);
      ControlTraceW(G_SessionHandle, G_SessionName, Props,
                    EVENT_TRACE_CONTROL_STOP);
      free(Props);
    }
    G_SessionHandle = INVALID_PROCESSTRACE_HANDLE;
  }

  if (G_TraceHandle != INVALID_PROCESSTRACE_HANDLE) {
    CloseTrace(G_TraceHandle);
    G_TraceHandle = INVALID_PROCESSTRACE_HANDLE;
  }

  wprintf(L"\n[INFO] Monitor stopped\n");
}
