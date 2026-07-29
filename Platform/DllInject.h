#pragma once

#define WIN32_LEAN_AND_MEAN

#include <iostream>
#include <string>
#include <thread>
#include <tlhelp32.h>
#include <vector>
#include <windows.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

typedef NTSTATUS(NTAPI *pNtCreateThreadEx)(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, LPVOID ObjectAttributes,
    HANDLE ProcessHandle, LPTHREAD_START_ROUTINE StartAddress, LPVOID Parameter,
    ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize,
    SIZE_T MaximumStackSize, LPVOID AttributeList);

typedef BOOL(WINAPI *pQueueUserAPC2)(PAPCFUNC ApcRoutine, HANDLE Thread,
                                     ULONG_PTR Data, ULONG Flags);

constexpr ULONG QueueUserApcFlagsSpecialUserApc = 0x00000001;

DWORD GetProcessIdByName(const std::wstring &name) {
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE)
    return 0;

  PROCESSENTRY32W pe = {sizeof(PROCESSENTRY32W)};
  DWORD pid = 0;

  if (Process32FirstW(snapshot, &pe)) {
    do {
      if (_wcsicmp(pe.szExeFile, name.c_str()) == 0) {
        pid = pe.th32ProcessID;
        break;
      }
    } while (Process32NextW(snapshot, &pe));
  }
  CloseHandle(snapshot);
  return pid;
}

BOOL EnableDebugPrivilege() {
  HANDLE token;
  if (!OpenProcessToken(GetCurrentProcess(),
                        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
    return FALSE;

  TOKEN_PRIVILEGES tp;
  LUID luid;
  if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
    CloseHandle(token);
    return FALSE;
  }

  tp.PrivilegeCount = 1;
  tp.Privileges[0].Luid = luid;
  tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

  BOOL ret = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL);
  CloseHandle(token);
  return ret;
}

void PrintError(const char *msg) {
  DWORD err = GetLastError();
  std::cerr << "[-] " << msg << " (Error: " << err << ")" << std::endl;
}

BOOL Inject_RemoteThread(DWORD pid, const std::wstring &dllPath) {
  HANDLE hProcess =
      OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                      PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                  FALSE, pid);
  if (!hProcess) {
    PrintError("OpenProcess failed");
    return FALSE;
  }

  size_t pathSize = (dllPath.size() + 1) * sizeof(wchar_t);
  LPVOID pRemoteMem = VirtualAllocEx(hProcess, NULL, pathSize,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!pRemoteMem) {
    PrintError("VirtualAllocEx failed");
    CloseHandle(hProcess);
    return FALSE;
  }

  if (!WriteProcessMemory(hProcess, pRemoteMem, dllPath.c_str(), pathSize,
                          NULL)) {
    PrintError("WriteProcessMemory failed");
    VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return FALSE;
  }

  LPVOID pLoadLibrary =
      (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
  if (!pLoadLibrary) {
    PrintError("GetProcAddress(LoadLibraryW) failed");
    VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return FALSE;
  }

  HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                      (LPTHREAD_START_ROUTINE)pLoadLibrary,
                                      pRemoteMem, 0, NULL);
  if (!hThread) {
    PrintError("CreateRemoteThread failed");
    VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return FALSE;
  }

  std::thread([hProcess, hThread, pRemoteMem] {
    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
  }).detach();

  std::cout << "[+] CreateRemoteThread injection started (cleanup deferred)."
            << std::endl;
  return TRUE;
}

BOOL Inject_NtCreateThreadEx(DWORD pid, const std::wstring &dllPath) {
  HANDLE hProcess =
      OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                      PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                  FALSE, pid);
  if (!hProcess) {
    PrintError("OpenProcess failed");
    return FALSE;
  }

  size_t pathSize = (dllPath.size() + 1) * sizeof(wchar_t);
  LPVOID pRemoteMem = VirtualAllocEx(hProcess, NULL, pathSize,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!pRemoteMem) {
    PrintError("VirtualAllocEx failed");
    CloseHandle(hProcess);
    return FALSE;
  }

  if (!WriteProcessMemory(hProcess, pRemoteMem, dllPath.c_str(), pathSize,
                          NULL)) {
    PrintError("WriteProcessMemory failed");
    VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return FALSE;
  }

  LPVOID pLoadLibrary =
      (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
  if (!pLoadLibrary) {
    PrintError("GetProcAddress(LoadLibraryW) failed");
    VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return FALSE;
  }

  pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(
      GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx");
  if (!NtCreateThreadEx) {
    PrintError("GetProcAddress(NtCreateThreadEx) failed");
    VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return FALSE;
  }

  HANDLE hThread = NULL;
  NTSTATUS status = NtCreateThreadEx(
      &hThread, THREAD_ALL_ACCESS, NULL, hProcess,
      (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemoteMem, 0, 0, 0, 0, NULL);

  if (status != 0 || !hThread) {
    PrintError("NtCreateThreadEx failed");
    VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return FALSE;
  }

  std::thread([hProcess, hThread, pRemoteMem] {
    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
  }).detach();

  std::cout << "[+] NtCreateThreadEx injection started (cleanup deferred)."
            << std::endl;
  return TRUE;
}

BOOL Inject_QueueUserAPC(DWORD pid, const std::wstring &dllPath) {
  std::cout << "[*] QueueUserAPC injection targeting PID=" << pid << std::endl;

  HANDLE hProcess = OpenProcess(
      PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
          PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_SUSPEND_RESUME,
      FALSE, pid);
  if (!hProcess) {
    PrintError("OpenProcess failed");
    return FALSE;
  }

  size_t pathSize = (dllPath.size() + 1) * sizeof(wchar_t);
  LPVOID pRemoteMem = VirtualAllocEx(hProcess, NULL, pathSize,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!pRemoteMem) {
    PrintError("VirtualAllocEx failed");
    CloseHandle(hProcess);
    return FALSE;
  }

  if (!WriteProcessMemory(hProcess, pRemoteMem, dllPath.c_str(), pathSize,
                          NULL)) {
    PrintError("WriteProcessMemory failed");
    VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return FALSE;
  }

  LPVOID pLoadLibrary =
      (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
  if (!pLoadLibrary) {
    PrintError("GetProcAddress(LoadLibraryW) failed");
    VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return FALSE;
  }

  auto IsDllLoaded = [&]() -> BOOL {
    HANDLE hModSnap =
        CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hModSnap == INVALID_HANDLE_VALUE)
      return FALSE;

    MODULEENTRY32W me = {sizeof(me)};
    BOOL found = FALSE;
    if (Module32FirstW(hModSnap, &me)) {
      do {
        if (_wcsicmp(me.szExePath, dllPath.c_str()) == 0 ||
            _wcsicmp(
                me.szModule,
                dllPath.substr(dllPath.find_last_of(L"\\/") + 1).c_str()) ==
                0) {
          found = TRUE;
          break;
        }
      } while (Module32NextW(hModSnap, &me));
    }
    CloseHandle(hModSnap);
    return found;
  };

  pQueueUserAPC2 QueueUserAPC2Fn = nullptr;
  {
    HMODULE hKernelBase = GetModuleHandleW(L"kernelbase.dll");
    if (hKernelBase)
      QueueUserAPC2Fn =
          (pQueueUserAPC2)GetProcAddress(hKernelBase, "QueueUserAPC2");
  }
  if (!QueueUserAPC2Fn) {
    QueueUserAPC2Fn = (pQueueUserAPC2)GetProcAddress(
        GetModuleHandleW(L"kernel32.dll"), "QueueUserAPC2");
  }

  HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (hSnapshot == INVALID_HANDLE_VALUE) {
    PrintError("CreateToolhelp32Snapshot(thread) failed");
    VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return FALSE;
  }

  THREADENTRY32 te = {sizeof(THREADENTRY32)};
  int specialQueued = 0;
  int normalQueued = 0;
  int openFailed = 0;
  int queueFailed = 0;
  HANDLE hFallbackThread = NULL;
  DWORD fallbackTid = 0;

  if (Thread32First(hSnapshot, &te)) {
    do {
      if (te.th32OwnerProcessID == pid) {
        HANDLE hThread =
            OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME |
                           THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                       FALSE, te.th32ThreadID);
        if (hThread) {
          BOOL queued = FALSE;
          if (QueueUserAPC2Fn) {
            queued = QueueUserAPC2Fn((PAPCFUNC)pLoadLibrary, hThread,
                                     (ULONG_PTR)pRemoteMem,
                                     QueueUserApcFlagsSpecialUserApc);
            if (queued)
              specialQueued++;
          }
          if (!queued) {
            queued = QueueUserAPC((PAPCFUNC)pLoadLibrary, hThread,
                                  (ULONG_PTR)pRemoteMem);
            if (queued)
              normalQueued++;
          }
          if (!queued) {
            queueFailed++;
          }

          if (!hFallbackThread) {
            hFallbackThread = hThread;
            fallbackTid = te.th32ThreadID;
          } else {
            CloseHandle(hThread);
          }
        } else {
          openFailed++;
        }
      }
    } while (Thread32Next(hSnapshot, &te));
  }
  CloseHandle(hSnapshot);

  std::cout << "[*] APC injection: SpecialUserAPC=" << specialQueued
            << ", normal=" << normalQueued
            << ", OpenThread failed=" << openFailed
            << ", queue failed=" << queueFailed << std::endl;

  if (specialQueued > 0 || normalQueued > 0) {
    std::cout << "[*] Waiting up to 4 seconds for APC delivery ..."
              << std::endl;
    for (int i = 0; i < 40; i++) {
      if (IsDllLoaded()) {
        std::cout << "[+] APC injection succeeded: DLL loaded after "
                  << (i * 100) << " ms." << std::endl;
        if (hFallbackThread)
          CloseHandle(hFallbackThread);
        CloseHandle(hProcess);
        return TRUE;
      }
      Sleep(100);
    }

    std::cout << "[!] APC delivery timed out — APC queued but DLL not loaded "
                 "within 4s."
              << std::endl;
    if (!QueueUserAPC2Fn) {
      std::cout << "[!] QueueUserAPC2 not available. Normal APC requires "
                   "thread in alertable wait."
                << std::endl;
    }
  }

  if (!hFallbackThread) {
    std::cout << "[!] No usable threads found in target — falling back to "
                 "CreateRemoteThread."
              << std::endl;
    CloseHandle(hProcess);
    return Inject_RemoteThread(pid, dllPath);
  }

  std::cout << "[*] APC delivery not observed — falling back to thread-hijack "
               "injection on TID="
            << fallbackTid << " ..." << std::endl;

  auto SuspendGuard = [&](BOOL doSuspend) -> DWORD {
    if (doSuspend) {
      DWORD prev = SuspendThread(hFallbackThread);
      if (prev == (DWORD)-1) {
        PrintError("SuspendThread failed");
      }
      return prev;
    } else {
      ResumeThread(hFallbackThread);
      return 0;
    }
  };

  DWORD suspended = SuspendGuard(true);
  if (suspended == (DWORD)-1) {
    CloseHandle(hFallbackThread);
    VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    std::cout << "[!] Thread-hijack fallback failed (cannot suspend). Try "
                 "another injection method."
              << std::endl;
    return FALSE;
  }

  CONTEXT ctx = {};
  ctx.ContextFlags = CONTEXT_CONTROL;
  if (!GetThreadContext(hFallbackThread, &ctx)) {
    SuspendGuard(false);
    CloseHandle(hFallbackThread);
    VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    std::cout << "[!] GetThreadContext failed. Try another injection method."
              << std::endl;
    return FALSE;
  }

  unsigned char stub[] = {
#ifdef _M_X64
      0x48, 0x83, 0xEC, 0x28, 0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x28, 0xEB, 0xFE,
#else
      0x68, 0x00, 0x00, 0x00, 0x00, 0xB8, 0x00,
      0x00, 0x00, 0x00, 0xFF, 0xD0, 0xEB, 0xFE,
#endif
  };

#ifdef _M_X64
  memcpy(stub + 4, &pRemoteMem, sizeof(pRemoteMem));
  memcpy(stub + 14, &pLoadLibrary, sizeof(pLoadLibrary));
#else
  memcpy(stub + 1, &pRemoteMem, sizeof(DWORD));
  memcpy(stub + 6, &pLoadLibrary, sizeof(DWORD));
#endif

  LPVOID pStub =
      VirtualAllocEx(hProcess, NULL, sizeof(stub), MEM_COMMIT | MEM_RESERVE,
                     PAGE_EXECUTE_READWRITE);
  if (!pStub) {
    PrintError("VirtualAllocEx(stub) failed");
    SuspendGuard(false);
    CloseHandle(hFallbackThread);
    VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return FALSE;
  }

  SIZE_T written = 0;
  if (!WriteProcessMemory(hProcess, pStub, stub, sizeof(stub), &written) ||
      written != sizeof(stub)) {
    PrintError("WriteProcessMemory(stub) failed");
    VirtualFreeEx(hProcess, pStub, 0, MEM_RELEASE);
    SuspendGuard(false);
    CloseHandle(hFallbackThread);
    VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return FALSE;
  }

#ifdef _M_X64
  DWORD64 oldRip = ctx.Rip;
  ctx.Rip = (DWORD64)pStub;
#else
  DWORD oldEip = ctx.Eip;
  ctx.Eip = (DWORD)pStub;
#endif

  ctx.ContextFlags = CONTEXT_CONTROL;
  if (!SetThreadContext(hFallbackThread, &ctx)) {
    PrintError("SetThreadContext failed");
    VirtualFreeEx(hProcess, pStub, 0, MEM_RELEASE);
    SuspendGuard(false);
    CloseHandle(hFallbackThread);
    VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return FALSE;
  }

  ResumeThread(hFallbackThread);

  std::cout << "[*] Thread hijacked — waiting for DLL load ..." << std::endl;
  BOOL hijackSuccess = FALSE;
  for (int i = 0; i < 50; i++) {
    if (IsDllLoaded()) {
      std::cout << "[+] Thread-hijack injection succeeded after " << (i * 100)
                << " ms." << std::endl;
      hijackSuccess = TRUE;
      break;
    }
    Sleep(100);
  }

  SuspendThread(hFallbackThread);

#ifdef _M_X64
  ctx.Rip = oldRip;
#else
  ctx.Eip = oldEip;
#endif
  ctx.ContextFlags = CONTEXT_CONTROL;
  SetThreadContext(hFallbackThread, &ctx);
  ResumeThread(hFallbackThread);

  CloseHandle(hFallbackThread);
  VirtualFreeEx(hProcess, pStub, 0, MEM_RELEASE);
  CloseHandle(hProcess);

  if (hijackSuccess)
    return TRUE;

  std::cout << "[!] Thread-hijack fallback did not load DLL within timeout."
            << std::endl;
  return Inject_RemoteThread(pid, dllPath);
}

BOOL Inject_SetWindowsHookEx(DWORD pid, const std::wstring &dllPath) {
  HMODULE hDll = LoadLibraryW(dllPath.c_str());
  if (!hDll) {
    PrintError("LoadLibrary failed (cannot load DLL in current process)");
    return FALSE;
  }

  HOOKPROC hkProc = (HOOKPROC)GetProcAddress(hDll, "HookProc");
  if (!hkProc) {
    PrintError(
        "GetProcAddress(HookProc) failed - DLL needs to export HookProc");
    FreeLibrary(hDll);
    return FALSE;
  }

  HHOOK hook = SetWindowsHookExW(WH_KEYBOARD, hkProc, hDll, 0);
  if (!hook) {
    PrintError("SetWindowsHookEx failed");
    FreeLibrary(hDll);
    return FALSE;
  }

  PostThreadMessageW(GetWindowThreadProcessId(GetForegroundWindow(), NULL),
                     WM_NULL, 0, 0);

  std::cout << "[+] SetWindowsHookEx hook set. DLL will inject into processes"
            << " that process keyboard messages." << std::endl;

  UnhookWindowsHookEx(hook);
  FreeLibrary(hDll);

  return TRUE;
}
