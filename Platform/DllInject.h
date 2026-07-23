#pragma once

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>

#pragma comment(lib, "ntdll.lib")

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    LPVOID ObjectAttributes,
    HANDLE ProcessHandle,
    LPTHREAD_START_ROUTINE StartAddress,
    LPVOID Parameter,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    LPVOID AttributeList
    );

typedef BOOL(WINAPI* pQueueUserAPC2)(
    PAPCFUNC ApcRoutine,
    HANDLE Thread,
    ULONG_PTR Data,
    ULONG Flags
    );

constexpr ULONG QueueUserApcFlagsSpecialUserApc = 0x00000001;

DWORD GetProcessIdByName(const std::wstring& name) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
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
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
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

void PrintError(const char* msg) {
    DWORD err = GetLastError();
    std::cerr << "[-] " << msg << " (Error: " << err << ")" << std::endl;
}

BOOL Inject_RemoteThread(DWORD pid, const std::wstring& dllPath) {
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
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

    if (!WriteProcessMemory(hProcess, pRemoteMem, dllPath.c_str(), pathSize, NULL)) {
        PrintError("WriteProcessMemory failed");
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
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

    std::cout << "[+] CreateRemoteThread injection started (cleanup deferred)." << std::endl;
    return TRUE;
}

BOOL Inject_NtCreateThreadEx(DWORD pid, const std::wstring& dllPath) {
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
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

    if (!WriteProcessMemory(hProcess, pRemoteMem, dllPath.c_str(), pathSize, NULL)) {
        PrintError("WriteProcessMemory failed");
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    if (!pLoadLibrary) {
        PrintError("GetProcAddress(LoadLibraryW) failed");
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    pNtCreateThreadEx NtCreateThreadEx =
        (pNtCreateThreadEx)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx");
    if (!NtCreateThreadEx) {
        PrintError("GetProcAddress(NtCreateThreadEx) failed");
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    HANDLE hThread = NULL;
    NTSTATUS status = NtCreateThreadEx(
        &hThread, THREAD_ALL_ACCESS, NULL, hProcess,
        (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemoteMem,
        0, 0, 0, 0, NULL
    );

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

    std::cout << "[+] NtCreateThreadEx injection started (cleanup deferred)." << std::endl;
    return TRUE;
}

BOOL Inject_QueueUserAPC(DWORD pid, const std::wstring& dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
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

    if (!WriteProcessMemory(hProcess, pRemoteMem, dllPath.c_str(), pathSize, NULL)) {
        PrintError("WriteProcessMemory failed");
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    if (!pLoadLibrary) {
        PrintError("GetProcAddress(LoadLibraryW) failed");
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    pQueueUserAPC2 QueueUserAPC2Fn = nullptr;
    if (HMODULE hKernelBase = GetModuleHandleW(L"kernelbase.dll")) {
        QueueUserAPC2Fn = (pQueueUserAPC2)GetProcAddress(hKernelBase, "QueueUserAPC2");
    }
    if (!QueueUserAPC2Fn) {
        QueueUserAPC2Fn = (pQueueUserAPC2)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "QueueUserAPC2");
    }

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        PrintError("CreateToolhelp32Snapshot failed");
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    THREADENTRY32 te = { sizeof(THREADENTRY32) };
    int specialQueued = 0;
    int normalQueued = 0;
    int openFailed = 0;
    int queueFailed = 0;
    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                if (hThread) {
                    BOOL queued = FALSE;
                    if (QueueUserAPC2Fn) {
                        queued = QueueUserAPC2Fn((PAPCFUNC)pLoadLibrary, hThread, (ULONG_PTR)pRemoteMem, QueueUserApcFlagsSpecialUserApc);
                        if (queued) {
                            specialQueued++;
                        }
                    }
                    if (!queued) {
                        queued = QueueUserAPC((PAPCFUNC)pLoadLibrary, hThread, (ULONG_PTR)pRemoteMem);
                        if (queued) {
                            normalQueued++;
                        }
                    }
                    if (!queued) {
                        queueFailed++;
                    }
                    CloseHandle(hThread);
                } else {
                    openFailed++;
                }
            }
        } while (Thread32Next(hSnapshot, &te));
    }
    CloseHandle(hSnapshot);

    if (specialQueued == 0 && normalQueued == 0) {
        PrintError("QueueUserAPC failed on all threads");
        std::cout << "    OpenThread failed: " << openFailed
            << ", queue failed: " << queueFailed << std::endl;
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    std::cout << "[+] APC injection queued. SpecialUserAPC: " << specialQueued
        << ", normal APC: " << normalQueued
        << ", OpenThread failed: " << openFailed
        << ", queue failed: " << queueFailed << std::endl;
    if (specialQueued == 0) {
        std::cout << "[!] QueueUserAPC2 is unavailable or failed. Normal APC only runs when a target thread enters alertable state." << std::endl;
    }
    CloseHandle(hProcess);
    return TRUE;
}

BOOL Inject_SetWindowsHookEx(DWORD pid, const std::wstring& dllPath) {
    HMODULE hDll = LoadLibraryW(dllPath.c_str());
    if (!hDll) {
        PrintError("LoadLibrary failed (cannot load DLL in current process)");
        return FALSE;
    }

    HOOKPROC hkProc = (HOOKPROC)GetProcAddress(hDll, "HookProc");
    if (!hkProc) {
        PrintError("GetProcAddress(HookProc) failed - DLL needs to export HookProc");
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

