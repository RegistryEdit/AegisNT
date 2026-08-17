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

#ifndef LOAD_LIBRARY_AS_DATAFILE
#define LOAD_LIBRARY_AS_DATAFILE 0x00000002
#endif
#ifndef LOAD_LIBRARY_AS_IMAGE
#define LOAD_LIBRARY_AS_IMAGE 0x00000020
#endif

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

BOOL Inject_Reflective(DWORD pid, const std::wstring &dllPath) {
  HANDLE hFile = CreateFileW(dllPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                             NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile == INVALID_HANDLE_VALUE) {
    PrintError("CreateFileW failed");
    return FALSE;
  }
  LARGE_INTEGER fileSize{};
  if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart <= 0) {
    PrintError("GetFileSizeEx failed");
    CloseHandle(hFile);
    return FALSE;
  }
  std::vector<BYTE> fileBytes(static_cast<size_t>(fileSize.QuadPart));
  DWORD bytesRead = 0;
  if (!ReadFile(hFile, fileBytes.data(), static_cast<DWORD>(fileBytes.size()),
                &bytesRead, NULL) ||
      bytesRead != fileBytes.size()) {
    PrintError("ReadFile failed");
    CloseHandle(hFile);
    return FALSE;
  }
  CloseHandle(hFile);

  if (fileBytes.size() < sizeof(IMAGE_DOS_HEADER)) {
    std::cout << "[-] Invalid DLL: too small for DOS header." << std::endl;
    return FALSE;
  }
  const auto *dosHeader =
      reinterpret_cast<const IMAGE_DOS_HEADER *>(fileBytes.data());
  if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
    std::cout << "[-] Invalid DLL: bad DOS signature." << std::endl;
    return FALSE;
  }
  if (dosHeader->e_lfanew <= 0 ||
      static_cast<size_t>(dosHeader->e_lfanew) + sizeof(IMAGE_NT_HEADERS) >
          fileBytes.size()) {
    std::cout << "[-] Invalid DLL: bad NT header offset." << std::endl;
    return FALSE;
  }
  const auto *ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS *>(
      fileBytes.data() + dosHeader->e_lfanew);
  if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
    std::cout << "[-] Invalid DLL: bad NT signature." << std::endl;
    return FALSE;
  }
#ifdef _M_X64
  if (ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
    std::cout << "[-] Architecture mismatch: x64 build requires an x64 DLL."
              << std::endl;
    return FALSE;
  }
#else
  if (ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
    std::cout << "[-] Architecture mismatch: x86 build requires an x86 DLL."
              << std::endl;
    return FALSE;
  }
#endif

  const DWORD imageSize = ntHeaders->OptionalHeader.SizeOfImage;
  const DWORD sectionCount = ntHeaders->FileHeader.NumberOfSections;
  const auto *sections = IMAGE_FIRST_SECTION(ntHeaders);

  // Translates an RVA into the file buffer. LoadLibraryEx(AS_IMAGE) may
  // return a handle offset from the real image base on some systems, so the
  // PE is read deterministically from the raw file bytes instead.
  const auto FileData = [&](DWORD Rva) -> const BYTE * {
    if (Rva < ntHeaders->OptionalHeader.SizeOfHeaders)
      return fileBytes.data() + Rva;
    for (DWORD I = 0; I < sectionCount; ++I) {
      const IMAGE_SECTION_HEADER &S = sections[I];
      if (!S.SizeOfRawData || Rva < S.VirtualAddress)
        continue;
      const DWORD Offset = Rva - S.VirtualAddress;
      if (Offset < S.SizeOfRawData)
        return fileBytes.data() + S.PointerToRawData + Offset;
    }
    return nullptr;
  };

  HANDLE hProcess = OpenProcess(
      PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
          PROCESS_VM_WRITE | PROCESS_VM_READ,
      FALSE, pid);
  if (!hProcess) {
    PrintError("OpenProcess failed");
    return FALSE;
  }

  LPVOID pRemote = VirtualAllocEx(
      hProcess, reinterpret_cast<LPVOID>(ntHeaders->OptionalHeader.ImageBase),
      imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!pRemote)
    pRemote = VirtualAllocEx(hProcess, NULL, imageSize,
                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!pRemote) {
    PrintError("VirtualAllocEx failed");
    CloseHandle(hProcess);
    return FALSE;
  }

  const ULONGLONG delta =
      reinterpret_cast<ULONGLONG>(pRemote) -
      static_cast<ULONGLONG>(ntHeaders->OptionalHeader.ImageBase);

  SIZE_T written = 0;
  auto WriteRemote = [&](const void *src, void *dst, SIZE_T size) -> BOOL {
    return WriteProcessMemory(hProcess, dst, src, size, &written) &&
           written == size;
  };
  auto Abort = [&]() -> BOOL {
    VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    std::cout << "[-] Reflective injection aborted." << std::endl;
    return FALSE;
  };

  if (!WriteRemote(fileBytes.data(), pRemote,
                   ntHeaders->OptionalHeader.SizeOfHeaders)) {
    PrintError("WriteProcessMemory(headers) failed");
    return Abort();
  }
  for (DWORD i = 0; i < sectionCount; ++i) {
    const IMAGE_SECTION_HEADER &section = sections[i];
    DWORD copySize = section.SizeOfRawData ? section.SizeOfRawData
                                           : section.Misc.VirtualSize;
    if (!copySize)
      continue;
    const DWORD endBound = i + 1 < sectionCount
                               ? sections[i + 1].VirtualAddress
                               : imageSize;
    if (section.VirtualAddress + copySize > endBound)
      copySize = endBound - section.VirtualAddress;
    if (!WriteRemote(fileBytes.data() + section.PointerToRawData,
                     static_cast<BYTE *>(pRemote) + section.VirtualAddress,
                     copySize)) {
      PrintError("WriteProcessMemory(section) failed");
      return Abort();
    }
  }

  const DWORD relocRva =
      ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
          .VirtualAddress;
  const DWORD relocSize =
      ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
          .Size;
  if (delta != 0 && relocRva && relocSize) {
    const auto *relocBase = FileData(relocRva);
    const auto *relocEnd = FileData(relocRva) + relocSize;
    if (relocBase && relocEnd) {
      const auto *block = reinterpret_cast<const IMAGE_BASE_RELOCATION *>(relocBase);
      while (reinterpret_cast<const BYTE *>(block) + sizeof(IMAGE_BASE_RELOCATION) <=
                 relocEnd &&
             block->VirtualAddress) {
        if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION))
          break;
        const DWORD entryCount =
            (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        const auto *entries = reinterpret_cast<const WORD *>(block + 1);
        const auto *pageData = FileData(block->VirtualAddress);
        for (DWORD i = 0; i < entryCount; ++i) {
          const WORD type = entries[i] >> 12;
          const WORD offset = entries[i] & 0xFFF;
          if (!pageData || block->VirtualAddress + offset >= imageSize)
            continue;
          const auto *shadowSlot = pageData + offset;
          auto *remoteSlot = static_cast<BYTE *>(pRemote) +
                             block->VirtualAddress + offset;
#ifdef _M_X64
          if (type == IMAGE_REL_BASED_DIR64) {
            ULONGLONG value = 0;
            memcpy(&value, shadowSlot, sizeof(value));
            value += delta;
            if (!WriteRemote(&value, remoteSlot, sizeof(value))) {
              PrintError("WriteProcessMemory(reloc) failed");
              return Abort();
            }
          }
#else
          if (type == IMAGE_REL_BASED_HIGHLOW) {
            ULONG value = 0;
            memcpy(&value, shadowSlot, sizeof(value));
            value += static_cast<ULONG>(delta);
            if (!WriteRemote(&value, remoteSlot, sizeof(value))) {
              PrintError("WriteProcessMemory(reloc) failed");
              return Abort();
            }
          }
#endif
        }
        block = reinterpret_cast<const IMAGE_BASE_RELOCATION *>(
            reinterpret_cast<const BYTE *>(block) + block->SizeOfBlock);
      }
    }
  }

  const DWORD importRva =
      ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
          .VirtualAddress;
  const DWORD importSize =
      ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
          .Size;
  if (importRva && importSize) {
    const auto *importData = FileData(importRva);
    if (importData) {
      const auto *importEnd = importData + importSize;
      const auto *desc =
          reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR *>(importData);
      while (reinterpret_cast<const BYTE *>(desc) + sizeof(IMAGE_IMPORT_DESCRIPTOR) <=
                 importEnd &&
             desc->Name != 0) {
        const auto *moduleNameData = FileData(desc->Name);
        if (!moduleNameData) {
          std::cout << "[-] Invalid import module RVA: 0x" << std::hex
                    << desc->Name << std::dec << std::endl;
          return Abort();
        }
        const auto *moduleName =
            reinterpret_cast<const char *>(moduleNameData);
        HMODULE hImport = GetModuleHandleA(moduleName);
        if (!hImport)
          hImport = LoadLibraryA(moduleName);
        if (!hImport) {
          std::cout << "[-] Failed to resolve import module: " << moduleName
                    << std::endl;
          return Abort();
        }
        const DWORD thunkRva = desc->FirstThunk;
        const DWORD origThunkRva = desc->OriginalFirstThunk
                                       ? desc->OriginalFirstThunk
                                       : thunkRva;
        const auto *thunk =
            reinterpret_cast<const IMAGE_THUNK_DATA *>(FileData(thunkRva));
        const auto *origThunk = reinterpret_cast<const IMAGE_THUNK_DATA *>(
            FileData(origThunkRva));
        if (!thunk || !origThunk) {
          std::cout << "[-] Invalid import thunk RVA: 0x" << std::hex
                    << thunkRva << std::dec << std::endl;
          return Abort();
        }
        DWORD iatIndex = 0;
        while (origThunk->u1.AddressOfData != 0) {
          LPVOID function = nullptr;
#ifdef _M_X64
          const bool byOrdinal =
              (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) != 0;
#else
          const bool byOrdinal =
              IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal) != 0;
#endif
          if (byOrdinal) {
            function = GetProcAddress(
                hImport, reinterpret_cast<LPCSTR>(origThunk->u1.Ordinal & 0xFFFF));
          } else {
            const auto *importByNameData = FileData(origThunk->u1.AddressOfData);
            if (!importByNameData) {
              std::cout << "[-] Invalid import name RVA: 0x" << std::hex
                        << origThunk->u1.AddressOfData << std::dec << std::endl;
              return Abort();
            }
            const auto *importByName =
                reinterpret_cast<const IMAGE_IMPORT_BY_NAME *>(importByNameData);
            function = GetProcAddress(hImport, importByName->Name);
          }
          if (!function) {
            std::cout << "[-] Failed to resolve import: " << moduleName
                      << std::endl;
            return Abort();
          }
          const ULONGLONG remoteFunction = reinterpret_cast<ULONGLONG>(function);
          auto *remoteIatSlot =
              static_cast<BYTE *>(pRemote) + thunkRva +
              iatIndex * sizeof(IMAGE_THUNK_DATA);
          if (!WriteRemote(&remoteFunction, remoteIatSlot,
                           sizeof(remoteFunction))) {
            PrintError("WriteProcessMemory(import) failed");
            return Abort();
          }
          ++thunk;
          ++origThunk;
          ++iatIndex;
        }
        ++desc;
      }
    }
  }

  for (DWORD i = 0; i < sectionCount; ++i) {
    const IMAGE_SECTION_HEADER &section = sections[i];
    const DWORD characteristics = section.Characteristics;
    const bool executable = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    const bool readable = (characteristics & IMAGE_SCN_MEM_READ) != 0;
    const bool writable = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    DWORD protection = PAGE_READONLY;
    if (executable)
      protection = writable ? PAGE_EXECUTE_READWRITE
                            : (readable ? PAGE_EXECUTE_READ : PAGE_EXECUTE);
    else if (writable)
      protection = PAGE_READWRITE;
    else if (!readable)
      protection = PAGE_NOACCESS;
    DWORD oldProtection = 0;
    if (!VirtualProtectEx(hProcess,
                          static_cast<BYTE *>(pRemote) + section.VirtualAddress,
                          section.Misc.VirtualSize, protection,
                          &oldProtection)) {
      PrintError("VirtualProtectEx(section) failed");
      return Abort();
    }
  }

  if (!ntHeaders->OptionalHeader.AddressOfEntryPoint) {
    PrintError("Module has no entry point");
    return Abort();
  }

  // MSVC CRTs abort at startup if the module's __security_cookie still holds
  // the file's default sentinel (meaning the image was not loaded by the OS
  // loader). Randomize the sentinel in the remote image beforehand, as
  // reflective loaders do, so DllMain actually runs.
  const ULONGLONG CookieSentinel64 = 0x2B992DDFA232ULL;
  const ULONGLONG CookieSentinel32 = 0xBB40E64EULL;
  for (DWORD i = 0; i < sectionCount; ++i) {
    const IMAGE_SECTION_HEADER &section = sections[i];
    if (!(section.Characteristics & IMAGE_SCN_MEM_WRITE) ||
        !(section.Characteristics & IMAGE_SCN_MEM_READ) ||
        section.Characteristics & IMAGE_SCN_MEM_EXECUTE ||
        !section.SizeOfRawData)
      continue;
    const DWORD RawSize =
        section.SizeOfRawData <
                static_cast<DWORD>(fileBytes.size()) - section.PointerToRawData
            ? section.SizeOfRawData
            : static_cast<DWORD>(fileBytes.size()) - section.PointerToRawData;
    if (RawSize < sizeof(ULONGLONG))
      continue;
    const auto *Raw = fileBytes.data() + section.PointerToRawData;
    for (DWORD Off = 0; Off + sizeof(ULONGLONG) <= RawSize; ++Off) {
      ULONGLONG Value = 0;
      memcpy(&Value, Raw + Off, sizeof(Value));
      if (Value != CookieSentinel64 && Value != CookieSentinel32)
        continue;
      const ULONGLONG RandomCookie =
          (static_cast<ULONGLONG>(GetTickCount64()) << 32) ^
          (static_cast<ULONGLONG>(GetCurrentProcessId()) << 16) ^
          (static_cast<ULONGLONG>(GetCurrentThreadId())) ^
          static_cast<ULONGLONG>(reinterpret_cast<ULONG_PTR>(pRemote));
      if (!WriteRemote(&RandomCookie,
                       static_cast<BYTE *>(pRemote) + section.VirtualAddress +
                           Off,
                       sizeof(RandomCookie))) {
        PrintError("WriteProcessMemory(security cookie) failed");
        return Abort();
      }
      break;
    }
  }
  auto *pEntry = static_cast<BYTE *>(pRemote) +
                 ntHeaders->OptionalHeader.AddressOfEntryPoint;

  // DllMain expects (hModule, fdwReason, lpReserved), but CreateRemoteThread
  // only supplies one argument. Run a small stub in the target that calls the
  // entry point with fdwReason = DLL_PROCESS_ATTACH.
  const BYTE Stub32[] = {0x68, 0, 0, 0, 0, // push lpReserved (NULL)
                         0x6A, 0x01,       // push fdwReason (1)
                         0x68, 0, 0, 0, 0, // push hModule
                         0xB8, 0, 0, 0, 0, // mov eax, entry
                         0xFF, 0xD0,       // call eax
                         0xC2, 0x0C, 0x00};// ret 0xC
  const BYTE Stub64[] = {
      0x48, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0, // mov rcx, hModule
      0xBA, 0x01, 0x00, 0x00, 0x00,       // mov edx, 1 (DLL_PROCESS_ATTACH)
      0x4C, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00, // lea r8, [rip+0] (NULL)
      0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, // mov rax, entry
      0x48, 0x83, 0xEC, 0x28,             // sub rsp, 28h
      0xFF, 0xD0,                         // call rax
      0x48, 0x83, 0xC4, 0x28,             // add rsp, 28h
      0xC3};                              // ret
#ifdef _M_X64
  BYTE Stub[sizeof(Stub64)];
  memcpy(Stub, Stub64, sizeof(Stub64));
  const SIZE_T StubSize = sizeof(Stub64);
  *reinterpret_cast<ULONGLONG *>(&Stub[2]) =
      reinterpret_cast<ULONGLONG>(pRemote);
  *reinterpret_cast<ULONGLONG *>(&Stub[24]) =
      reinterpret_cast<ULONGLONG>(pEntry);
#else
  BYTE Stub[sizeof(Stub32)];
  memcpy(Stub, Stub32, sizeof(Stub32));
  const SIZE_T StubSize = sizeof(Stub32);
  *reinterpret_cast<ULONG *>(&Stub[1]) = 0;
  *reinterpret_cast<ULONG *>(&Stub[8]) =
      reinterpret_cast<ULONG>(pRemote);
  *reinterpret_cast<ULONG *>(&Stub[13]) =
      reinterpret_cast<ULONG>(pEntry);
#endif
  LPVOID pStub = VirtualAllocEx(hProcess, NULL, StubSize, MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE);
  if (!pStub || !WriteRemote(Stub, pStub, StubSize)) {
    PrintError("VirtualAllocEx(stub) failed");
    return Abort();
  }
  HANDLE hThread = CreateRemoteThread(
      hProcess, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pStub), NULL,
      0, NULL);
  if (!hThread) {
    PrintError("CreateRemoteThread(entry) failed");
    return Abort();
  }
  WaitForSingleObject(hThread, INFINITE);
  CloseHandle(hThread);
  CloseHandle(hProcess);
  std::cout << "[+] Reflective injection succeeded: image at 0x" << std::hex
            << pRemote << std::dec << " in PID " << pid << std::endl;
  return TRUE;
}
