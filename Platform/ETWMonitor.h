#pragma once

#include <evntcons.h>
#include <evntrace.h>
#include <functional>
#include <guiddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <tdh.h>
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
  std::wstring ProcessName;
  ULONGLONG StartAddr;
  std::wstring ImageName;
  std::wstring FileName;
  std::wstring RegistryPath;
  std::wstring ValueName;
  DWORD DataSize;
  FILETIME TimeStamp;
};

struct EtwProvider {
  const WCHAR *Name;
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

static std::wstring FormatTimestamp(const FILETIME &Ft) {
  SYSTEMTIME St;
  FileTimeToSystemTime(&Ft, &St);
  WCHAR Buf[64];
  swprintf_s(Buf, L"%04d-%02d-%02d %02d:%02d:%02d.%03d", St.wYear, St.wMonth,
             St.wDay, St.wHour, St.wMinute, St.wSecond, St.wMilliseconds);
  return Buf;
}

static std::wstring GetProcessNameFromPid(DWORD Pid) {
  HANDLE HProcess =
      OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, Pid);
  if (!HProcess) {
    if (Pid == 4)
      return L"System";
    if (Pid == 0)
      return L"Idle";
    return L"<unknown>";
  }
  WCHAR Path[MAX_PATH] = {0};
  DWORD Size = MAX_PATH;
  std::wstring Name;
  if (QueryFullProcessImageNameW(HProcess, 0, Path, &Size)) {
    WCHAR *P = wcsrchr(Path, L'\\');
    Name = P ? (P + 1) : Path;
  } else {
    Name = L"<unknown>";
  }
  CloseHandle(HProcess);
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
  Evt.ProcessName = GetProcessNameFromPid(Evt.ProcessId);
  Evt.TimeStamp = *(FILETIME *)&Rec->EventHeader.TimeStamp;
  Evt.Category = ClassifyEvent(Rec->EventHeader.ProviderId,
                               Rec->EventHeader.EventDescriptor.Id);
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
  if (Cat == EventCategory::Unknown && !G_Verbose)
    return;
  ParsedEvent Evt = ParseEvent(Rec);
  if (G_EtwEventCallback) {
    G_EtwEventCallback(Evt);
  }
  PrintParsedEvent(Evt);
}

static ULONG WINAPI BufferCallback(PEVENT_TRACE_LOGFILEW LogFile) {
  (void)LogFile;
  return TRUE;
}

static BOOL StartKernelTrace() {
  G_LastStartTraceStatus = ERROR_SUCCESS;
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
  for (int I = 0; I < KProviderCount; I++) {
    Status =
        EnableTraceEx2(G_SessionHandle, &KProviders[I].Guid,
                       EVENT_CONTROL_CODE_ENABLE_PROVIDER, KProviders[I].Level,
                       KProviders[I].MatchAnyKeyword, 0, 0, NULL);
    if (Status == ERROR_SUCCESS) {
      ++EnabledProviders;
      wprintf(L"[OK] Provider enabled: %s\n", KProviders[I].Name);
    } else {
      wprintf(L"[WARN] Failed to enable provider %s: %lu\n", KProviders[I].Name,
              Status);
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

static BOOL OpenAndProcessTrace() {
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
