#include <windows.h>
#include <detours/detours.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wininet.h>
#include <stdio.h>
#include <string.h>

#define PIPE_NAME        L"\\\\.\\pipe\\ApiMonitorPipe"
#define PIPE_BUFFER_SIZE 4096

static HANDLE G_Pipe = INVALID_HANDLE_VALUE;

static BOOL PipeConnect() {
    G_Pipe = CreateFileW(PIPE_NAME, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (G_Pipe == INVALID_HANDLE_VALUE) {
        G_Pipe = CreateFileW(PIPE_NAME, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (G_Pipe == INVALID_HANDLE_VALUE) return FALSE;
    }
    return TRUE;
}

static void PipeDisconnect() {
    if (G_Pipe != INVALID_HANDLE_VALUE) { CloseHandle(G_Pipe); G_Pipe = INVALID_HANDLE_VALUE; }
}

static BOOL PipeSend(const char* Json) {
    if (G_Pipe != INVALID_HANDLE_VALUE) {
        DWORD Written;
        if (WriteFile(G_Pipe, Json, (DWORD)strlen(Json), &Written, NULL)) return TRUE;
    }
    return FALSE;
}

struct JsonBuilder {
    char Buf[4096];
    int  Pos;
    int  Count;
    JsonBuilder(const char* Category) : Pos(0), Count(0) {
        Pos += sprintf_s(Buf + Pos, sizeof(Buf) - Pos,
            "{\"cat\":\"%s\",\"ts\":%llu",
            Category, (unsigned long long)GetTickCount64());
    }
    void Add(const char* Key, unsigned long long Val) {
        Pos += sprintf_s(Buf + Pos, sizeof(Buf) - Pos, ",\"%s\":%llu", Key, Val);
    }
    void Finish() {
        Pos += sprintf_s(Buf + Pos, sizeof(Buf) - Pos, "}");
    }
    const char* CStr() const { return Buf; }
};

static thread_local int G_FileRecursionGuard = 0;

#define DEFINE_HOOK_BASE(Prefix, Display, Ret, Func, Params, Args) \
    static Ret (WINAPI *True_##Func) Params = Func; \
    Ret WINAPI Hook_##Func Params { \
        JsonBuilder Jb(Display); \
        Jb.Add("pid", GetCurrentProcessId()); \
        Jb.Finish(); \
        PipeSend(Jb.CStr()); \
        return True_##Func Args; \
    } \
    void Attach_##Prefix##_##Func(BOOL Attach) { \
        if (Attach) DetourAttach(&(PVOID&)True_##Func, Hook_##Func); \
        else        DetourDetach(&(PVOID&)True_##Func, Hook_##Func); \
    }

#define DEFINE_HOOK_NO_LOG(Prefix, Ret, Func, Params, Args) \
    static Ret (WINAPI *True_##Func) Params = Func; \
    Ret WINAPI Hook_##Func Params { return True_##Func Args; } \
    void Attach_##Prefix##_##Func(BOOL Attach) { \
        if (Attach) DetourAttach(&(PVOID&)True_##Func, Hook_##Func); \
        else        DetourDetach(&(PVOID&)True_##Func, Hook_##Func); \
    }

#define DEFINE_HOOK_FILE(Display, Ret, Func, Params, Args) \
    static Ret (WINAPI *True_##Func) Params = Func; \
    Ret WINAPI Hook_##Func Params { \
        if (G_FileRecursionGuard > 0) return True_##Func Args; \
        G_FileRecursionGuard++; \
        JsonBuilder Jb(Display); \
        Jb.Add("pid", GetCurrentProcessId()); \
        Jb.Finish(); \
        PipeSend(Jb.CStr()); \
        G_FileRecursionGuard--; \
        return True_##Func Args; \
    } \
    void Attach_file_##Func(BOOL Attach) { \
        if (Attach) DetourAttach(&(PVOID&)True_##Func, Hook_##Func); \
        else        DetourDetach(&(PVOID&)True_##Func, Hook_##Func); \
    }

/* ──── Process / Thread hooks ──── */
DEFINE_HOOK_BASE(process, "CreateProcessW", BOOL, CreateProcessW, (LPCWSTR lpAppName, LPWSTR lpCmdLine, LPSECURITY_ATTRIBUTES lpProcAttr, LPSECURITY_ATTRIBUTES lpThreadAttr, BOOL bInherit, DWORD dwFlags, LPVOID lpEnv, LPCWSTR lpCurDir, LPSTARTUPINFOW lpSI, LPPROCESS_INFORMATION lpPI), (lpAppName, lpCmdLine, lpProcAttr, lpThreadAttr, bInherit, dwFlags, lpEnv, lpCurDir, lpSI, lpPI))
    DEFINE_HOOK_BASE(process, "CreateProcessA", BOOL, CreateProcessA, (LPCSTR lpAppName, LPSTR lpCmdLine, LPSECURITY_ATTRIBUTES lpProcAttr, LPSECURITY_ATTRIBUTES lpThreadAttr, BOOL bInherit, DWORD dwFlags, LPVOID lpEnv, LPCSTR lpCurDir, LPSTARTUPINFOA lpSI, LPPROCESS_INFORMATION lpPI), (lpAppName, lpCmdLine, lpProcAttr, lpThreadAttr, bInherit, dwFlags, lpEnv, lpCurDir, lpSI, lpPI))
    DEFINE_HOOK_BASE(process, "CreateThread", HANDLE, CreateThread, (LPSECURITY_ATTRIBUTES lpAttr, SIZE_T dwStack, LPTHREAD_START_ROUTINE lpStart, LPVOID lpParam, DWORD dwFlags, LPDWORD lpThreadId), (lpAttr, dwStack, lpStart, lpParam, dwFlags, lpThreadId))
    DEFINE_HOOK_BASE(process, "CreateRemoteThread", HANDLE, CreateRemoteThread, (HANDLE hProcess, LPSECURITY_ATTRIBUTES lpAttr, SIZE_T dwStack, LPTHREAD_START_ROUTINE lpStart, LPVOID lpParam, DWORD dwFlags, LPDWORD lpThreadId), (hProcess, lpAttr, dwStack, lpStart, lpParam, dwFlags, lpThreadId))
    DEFINE_HOOK_BASE(process, "CreateRemoteThreadEx", HANDLE, CreateRemoteThreadEx, (HANDLE hProcess, LPSECURITY_ATTRIBUTES lpAttr, SIZE_T dwStack, LPTHREAD_START_ROUTINE lpStart, LPVOID lpParam, DWORD dwFlags, LPPROC_THREAD_ATTRIBUTE_LIST lpAttrList, LPDWORD lpThreadId), (hProcess, lpAttr, dwStack, lpStart, lpParam, dwFlags, lpAttrList, lpThreadId))
    DEFINE_HOOK_BASE(process, "OpenProcess", HANDLE, OpenProcess, (DWORD dwDesiredAccess, BOOL bInherit, DWORD dwProcessId), (dwDesiredAccess, bInherit, dwProcessId))
    DEFINE_HOOK_BASE(process, "TerminateProcess", BOOL, TerminateProcess, (HANDLE hProcess, UINT uExitCode), (hProcess, uExitCode))
    DEFINE_HOOK_NO_LOG(process, VOID, ExitProcess, (UINT uExitCode), (uExitCode))

    /* ──── File I/O hooks ──── */
    DEFINE_HOOK_FILE("CreateFileW", HANDLE, CreateFileW, (LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecAttr, DWORD dwCreationDisp, DWORD dwFlagsAndAttr, HANDLE hTemplateFile), (lpFileName, dwDesiredAccess, dwShareMode, lpSecAttr, dwCreationDisp, dwFlagsAndAttr, hTemplateFile))
    DEFINE_HOOK_FILE("CreateFileA", HANDLE, CreateFileA, (LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecAttr, DWORD dwCreationDisp, DWORD dwFlagsAndAttr, HANDLE hTemplateFile), (lpFileName, dwDesiredAccess, dwShareMode, lpSecAttr, dwCreationDisp, dwFlagsAndAttr, hTemplateFile))
    DEFINE_HOOK_FILE("ReadFile", BOOL, ReadFile, (HANDLE hFile, LPVOID lpBuf, DWORD nToRead, LPDWORD lpRead, LPOVERLAPPED lpOverlapped), (hFile, lpBuf, nToRead, lpRead, lpOverlapped))
    DEFINE_HOOK_FILE("WriteFile", BOOL, WriteFile, (HANDLE hFile, LPCVOID lpBuf, DWORD nToWrite, LPDWORD lpWritten, LPOVERLAPPED lpOverlapped), (hFile, lpBuf, nToWrite, lpWritten, lpOverlapped))
    DEFINE_HOOK_FILE("DeleteFileW", BOOL, DeleteFileW, (LPCWSTR lpFileName), (lpFileName))
    DEFINE_HOOK_FILE("DeleteFileA", BOOL, DeleteFileA, (LPCSTR lpFileName), (lpFileName))
    DEFINE_HOOK_FILE("MoveFileW", BOOL, MoveFileW, (LPCWSTR lpExisting, LPCWSTR lpNew), (lpExisting, lpNew))
    DEFINE_HOOK_FILE("CopyFileW", BOOL, CopyFileW, (LPCWSTR lpExisting, LPCWSTR lpNew, BOOL bFailIfExists), (lpExisting, lpNew, bFailIfExists))

    /* ──── Registry hooks ──── */
    DEFINE_HOOK_BASE(registry, "RegOpenKeyExW", LSTATUS, RegOpenKeyExW, (HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult), (hKey, lpSubKey, ulOptions, samDesired, phkResult))
    DEFINE_HOOK_BASE(registry, "RegOpenKeyExA", LSTATUS, RegOpenKeyExA, (HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult), (hKey, lpSubKey, ulOptions, samDesired, phkResult))
    DEFINE_HOOK_BASE(registry, "RegCreateKeyExW", LSTATUS, RegCreateKeyExW, (HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecAttr, PHKEY phkResult, LPDWORD lpdwDisposition), (hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecAttr, phkResult, lpdwDisposition))
    DEFINE_HOOK_BASE(registry, "RegCreateKeyExA", LSTATUS, RegCreateKeyExA, (HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecAttr, PHKEY phkResult, LPDWORD lpdwDisposition), (hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecAttr, phkResult, lpdwDisposition))
    DEFINE_HOOK_BASE(registry, "RegSetValueExW", LSTATUS, RegSetValueExW, (HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData), (hKey, lpValueName, Reserved, dwType, lpData, cbData))
    DEFINE_HOOK_BASE(registry, "RegSetValueExA", LSTATUS, RegSetValueExA, (HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData), (hKey, lpValueName, Reserved, dwType, lpData, cbData))
    DEFINE_HOOK_BASE(registry, "RegQueryValueExW", LSTATUS, RegQueryValueExW, (HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData), (hKey, lpValueName, lpReserved, lpType, lpData, lpcbData))
    DEFINE_HOOK_BASE(registry, "RegDeleteKeyExW", LSTATUS, RegDeleteKeyExW, (HKEY hKey, LPCWSTR lpSubKey, REGSAM samDesired, DWORD Reserved), (hKey, lpSubKey, samDesired, Reserved))
    DEFINE_HOOK_BASE(registry, "RegDeleteValueW", LSTATUS, RegDeleteValueW, (HKEY hKey, LPCWSTR lpValueName), (hKey, lpValueName))
    DEFINE_HOOK_BASE(registry, "RegCloseKey", LSTATUS, RegCloseKey, (HKEY hKey), (hKey))

    /* ──── Network hooks ──── */
    DEFINE_HOOK_BASE(network, "socket", SOCKET, socket, (int af, int type, int protocol), (af, type, protocol))
    DEFINE_HOOK_BASE(network, "connect", int, connect, (SOCKET s, const struct sockaddr* name, int namelen), (s, name, namelen))
    DEFINE_HOOK_BASE(network, "send", int, send, (SOCKET s, const char* buf, int len, int flags), (s, buf, len, flags))
    DEFINE_HOOK_BASE(network, "recv", int, recv, (SOCKET s, char* buf, int len, int flags), (s, buf, len, flags))
    DEFINE_HOOK_BASE(network, "WSASend", int, WSASend, (SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine), (s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine))
    DEFINE_HOOK_BASE(network, "WSARecv", int, WSARecv, (SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine), (s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine))
    DEFINE_HOOK_BASE(network, "bind", int, bind, (SOCKET s, const struct sockaddr* addr, int namelen), (s, addr, namelen))
    DEFINE_HOOK_BASE(network, "listen", int, listen, (SOCKET s, int backlog), (s, backlog))
    DEFINE_HOOK_BASE(network, "accept", SOCKET, accept, (SOCKET s, struct sockaddr* addr, int* addrlen), (s, addr, addrlen))
    DEFINE_HOOK_BASE(network, "closesocket", int, closesocket, (SOCKET s), (s))
    DEFINE_HOOK_BASE(network, "URLDownloadToFileW", HRESULT, URLDownloadToFileW, (LPUNKNOWN pCaller, LPCWSTR szURL, LPCWSTR szFileName, DWORD dwReserved, LPBINDSTATUSCALLBACK lpfnCB), (pCaller, szURL, szFileName, dwReserved, lpfnCB))

    static int (WSAAPI* True_getaddrinfo)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*) = getaddrinfo;
int WSAAPI Hook_getaddrinfo(PCSTR NName, PCSTR SName, const ADDRINFOA* Hints, PADDRINFOA* Result) {
    JsonBuilder Jb("getaddrinfo");
    Jb.Add("pid", GetCurrentProcessId());
    Jb.Finish();
    PipeSend(Jb.CStr());
    return True_getaddrinfo(NName, SName, Hints, Result);
}
void Attach_network_getaddrinfo(BOOL Attach) {
    if (Attach) DetourAttach(&(PVOID&)True_getaddrinfo, Hook_getaddrinfo);
    else        DetourDetach(&(PVOID&)True_getaddrinfo, Hook_getaddrinfo);
}

/* ──── Memory hooks ──── */
DEFINE_HOOK_BASE(memory, "VirtualAlloc", LPVOID, VirtualAlloc, (LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect), (lpAddress, dwSize, flAllocationType, flProtect))
    DEFINE_HOOK_BASE(memory, "VirtualAllocEx", LPVOID, VirtualAllocEx, (HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect), (hProcess, lpAddress, dwSize, flAllocationType, flProtect))
    DEFINE_HOOK_BASE(memory, "VirtualFree", BOOL, VirtualFree, (LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType), (lpAddress, dwSize, dwFreeType))
    DEFINE_HOOK_BASE(memory, "VirtualFreeEx", BOOL, VirtualFreeEx, (HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType), (hProcess, lpAddress, dwSize, dwFreeType))
    DEFINE_HOOK_BASE(memory, "VirtualProtect", BOOL, VirtualProtect, (LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect), (lpAddress, dwSize, flNewProtect, lpflOldProtect))
    DEFINE_HOOK_BASE(memory, "VirtualProtectEx", BOOL, VirtualProtectEx, (HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect), (hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect))
    DEFINE_HOOK_BASE(memory, "WriteProcessMemory", BOOL, WriteProcessMemory, (HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten), (hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten))
    DEFINE_HOOK_BASE(memory, "ReadProcessMemory", BOOL, ReadProcessMemory, (HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead), (hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead))

    /* ──── DLL hooks ──── */
    DEFINE_HOOK_BASE(dll, "LoadLibraryW", HMODULE, LoadLibraryW, (LPCWSTR lpLibFileName), (lpLibFileName))
    DEFINE_HOOK_BASE(dll, "LoadLibraryA", HMODULE, LoadLibraryA, (LPCSTR lpLibFileName), (lpLibFileName))
    DEFINE_HOOK_BASE(dll, "LoadLibraryExW", HMODULE, LoadLibraryExW, (LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags), (lpLibFileName, hFile, dwFlags))
    DEFINE_HOOK_BASE(dll, "FreeLibrary", BOOL, FreeLibrary, (HMODULE hLibModule), (hLibModule))
    DEFINE_HOOK_BASE(dll, "GetProcAddress", FARPROC, GetProcAddress, (HMODULE hModule, LPCSTR lpProcName), (hModule, lpProcName))

    /* ──── Sync hooks ──── */
    DEFINE_HOOK_BASE(sync, "CreateMutexW", HANDLE, CreateMutexW, (LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName), (lpMutexAttributes, bInitialOwner, lpName))
    DEFINE_HOOK_BASE(sync, "CreateMutexA", HANDLE, CreateMutexA, (LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName), (lpMutexAttributes, bInitialOwner, lpName))
    DEFINE_HOOK_BASE(sync, "CreateEventW", HANDLE, CreateEventW, (LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCWSTR lpName), (lpEventAttributes, bManualReset, bInitialState, lpName))
    DEFINE_HOOK_BASE(sync, "CreateEventA", HANDLE, CreateEventA, (LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName), (lpEventAttributes, bManualReset, bInitialState, lpName))
    DEFINE_HOOK_BASE(sync, "CreateSemaphoreW", HANDLE, CreateSemaphoreW, (LPSECURITY_ATTRIBUTES lpSemaphoreAttributes, LONG lInitialCount, LONG lMaximumCount, LPCWSTR lpName), (lpSemaphoreAttributes, lInitialCount, lMaximumCount, lpName))
    DEFINE_HOOK_BASE(sync, "WaitForSingleObject", DWORD, WaitForSingleObject, (HANDLE hHandle, DWORD dwMilliseconds), (hHandle, dwMilliseconds))
    DEFINE_HOOK_BASE(sync, "SetEvent", BOOL, SetEvent, (HANDLE hEvent), (hEvent))

    /* ──── Window hooks ──── */
    DEFINE_HOOK_BASE(win, "CreateWindowExW", HWND, CreateWindowExW, (DWORD dwExStyle, LPCWSTR lpClassName, LPCWSTR lpWindowName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam), (dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam))
    DEFINE_HOOK_BASE(win, "CreateWindowExA", HWND, CreateWindowExA, (DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam), (dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam))
    DEFINE_HOOK_BASE(win, "SetWindowsHookExW", HHOOK, SetWindowsHookExW, (int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId), (idHook, lpfn, hmod, dwThreadId))
    DEFINE_HOOK_BASE(win, "SetWindowsHookExA", HHOOK, SetWindowsHookExA, (int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId), (idHook, lpfn, hmod, dwThreadId))
    DEFINE_HOOK_BASE(win, "SendMessageW", LRESULT, SendMessageW, (HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam), (hWnd, Msg, wParam, lParam))
    DEFINE_HOOK_BASE(win, "PostMessageW", BOOL, PostMessageW, (HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam), (hWnd, Msg, wParam, lParam))

    static BOOL(WINAPI* True_GetMessageW)(LPMSG, HWND, UINT, UINT) = GetMessageW;
BOOL WINAPI Hook_GetMessageW(LPMSG Msg, HWND Wnd, UINT Min, UINT Max) {
    return True_GetMessageW(Msg, Wnd, Min, Max);
}
void Attach_win_GetMessageW(BOOL Attach) {
    if (Attach) DetourAttach(&(PVOID&)True_GetMessageW, Hook_GetMessageW);
    else        DetourDetach(&(PVOID&)True_GetMessageW, Hook_GetMessageW);
}

DEFINE_HOOK_BASE(win, "SetWindowLongPtrW", LONG_PTR, SetWindowLongPtrW, (HWND hWnd, int nIndex, LONG_PTR dwNewLong), (hWnd, nIndex, dwNewLong))

    /* ──── Service hooks ──── */
    DEFINE_HOOK_BASE(service, "OpenSCManagerW", SC_HANDLE, OpenSCManagerW, (LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess), (lpMachineName, lpDatabaseName, dwDesiredAccess))
    DEFINE_HOOK_BASE(service, "OpenSCManagerA", SC_HANDLE, OpenSCManagerA, (LPCSTR lpMachineName, LPCSTR lpDatabaseName, DWORD dwDesiredAccess), (lpMachineName, lpDatabaseName, dwDesiredAccess))
    DEFINE_HOOK_BASE(service, "CreateServiceW", SC_HANDLE, CreateServiceW, (SC_HANDLE hSCManager, LPCWSTR lpServiceName, LPCWSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCWSTR lpBinaryPathName, LPCWSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCWSTR lpDependencies, LPCWSTR lpServiceStartName, LPCWSTR lpPassword), (hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword))
    DEFINE_HOOK_BASE(service, "StartServiceW", BOOL, StartServiceW, (SC_HANDLE hService, DWORD dwNumServiceArgs, LPCWSTR* lpServiceArgVectors), (hService, dwNumServiceArgs, lpServiceArgVectors))
    DEFINE_HOOK_BASE(service, "ControlService", BOOL, ControlService, (SC_HANDLE hService, DWORD dwControl, LPSERVICE_STATUS lpServiceStatus), (hService, dwControl, lpServiceStatus))
    DEFINE_HOOK_BASE(service, "DeleteService", BOOL, DeleteService, (SC_HANDLE hService), (hService))

    /* ──── External declarations needed by AttachAll/DetachAll ──── */
    extern void Attach_process_CreateProcessW(BOOL);
extern void Attach_process_CreateProcessA(BOOL);
extern void Attach_process_CreateThread(BOOL);
extern void Attach_process_CreateRemoteThread(BOOL);
extern void Attach_process_CreateRemoteThreadEx(BOOL);
extern void Attach_process_OpenProcess(BOOL);
extern void Attach_process_TerminateProcess(BOOL);
extern void Attach_process_ExitProcess(BOOL);

extern void Attach_file_CreateFileW(BOOL);
extern void Attach_file_CreateFileA(BOOL);
extern void Attach_file_ReadFile(BOOL);
extern void Attach_file_WriteFile(BOOL);
extern void Attach_file_DeleteFileW(BOOL);
extern void Attach_file_DeleteFileA(BOOL);
extern void Attach_file_MoveFileW(BOOL);
extern void Attach_file_CopyFileW(BOOL);

extern void Attach_registry_RegOpenKeyExW(BOOL);
extern void Attach_registry_RegOpenKeyExA(BOOL);
extern void Attach_registry_RegCreateKeyExW(BOOL);
extern void Attach_registry_RegCreateKeyExA(BOOL);
extern void Attach_registry_RegSetValueExW(BOOL);
extern void Attach_registry_RegSetValueExA(BOOL);
extern void Attach_registry_RegQueryValueExW(BOOL);
extern void Attach_registry_RegDeleteKeyExW(BOOL);
extern void Attach_registry_RegDeleteValueW(BOOL);
extern void Attach_registry_RegCloseKey(BOOL);

extern void Attach_network_socket(BOOL);
extern void Attach_network_connect(BOOL);
extern void Attach_network_send(BOOL);
extern void Attach_network_recv(BOOL);
extern void Attach_network_WSASend(BOOL);
extern void Attach_network_WSARecv(BOOL);
extern void Attach_network_bind(BOOL);
extern void Attach_network_listen(BOOL);
extern void Attach_network_accept(BOOL);
extern void Attach_network_closesocket(BOOL);
extern void Attach_network_getaddrinfo(BOOL);
extern void Attach_network_URLDownloadToFileW(BOOL);

extern void Attach_memory_VirtualAlloc(BOOL);
extern void Attach_memory_VirtualAllocEx(BOOL);
extern void Attach_memory_VirtualFree(BOOL);
extern void Attach_memory_VirtualFreeEx(BOOL);
extern void Attach_memory_VirtualProtect(BOOL);
extern void Attach_memory_VirtualProtectEx(BOOL);
extern void Attach_memory_WriteProcessMemory(BOOL);
extern void Attach_memory_ReadProcessMemory(BOOL);

extern void Attach_dll_LoadLibraryW(BOOL);
extern void Attach_dll_LoadLibraryA(BOOL);
extern void Attach_dll_LoadLibraryExW(BOOL);
extern void Attach_dll_FreeLibrary(BOOL);
extern void Attach_dll_GetProcAddress(BOOL);

extern void Attach_sync_CreateMutexW(BOOL);
extern void Attach_sync_CreateMutexA(BOOL);
extern void Attach_sync_CreateEventW(BOOL);
extern void Attach_sync_CreateEventA(BOOL);
extern void Attach_sync_CreateSemaphoreW(BOOL);
extern void Attach_sync_WaitForSingleObject(BOOL);
extern void Attach_sync_SetEvent(BOOL);

extern void Attach_win_CreateWindowExW(BOOL);
extern void Attach_win_CreateWindowExA(BOOL);
extern void Attach_win_SetWindowsHookExW(BOOL);
extern void Attach_win_SetWindowsHookExA(BOOL);
extern void Attach_win_SendMessageW(BOOL);
extern void Attach_win_PostMessageW(BOOL);
extern void Attach_win_GetMessageW(BOOL);
extern void Attach_win_SetWindowLongPtrW(BOOL);

extern void Attach_service_OpenSCManagerW(BOOL);
extern void Attach_service_OpenSCManagerA(BOOL);
extern void Attach_service_CreateServiceW(BOOL);
extern void Attach_service_StartServiceW(BOOL);
extern void Attach_service_ControlService(BOOL);
extern void Attach_service_DeleteService(BOOL);

/* ──── Hook manager ──── */
static BOOL HookManager_AttachAll() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    Attach_process_CreateProcessW(TRUE);   Attach_process_CreateProcessA(TRUE);
    Attach_process_CreateThread(TRUE);     Attach_process_CreateRemoteThread(TRUE);
    Attach_process_CreateRemoteThreadEx(TRUE); Attach_process_OpenProcess(TRUE);
    Attach_process_TerminateProcess(TRUE); Attach_process_ExitProcess(TRUE);

    Attach_file_CreateFileW(TRUE);  Attach_file_CreateFileA(TRUE);
    Attach_file_ReadFile(TRUE);     Attach_file_WriteFile(TRUE);
    Attach_file_DeleteFileW(TRUE);  Attach_file_DeleteFileA(TRUE);
    Attach_file_MoveFileW(TRUE);    Attach_file_CopyFileW(TRUE);

    Attach_registry_RegOpenKeyExW(TRUE);   Attach_registry_RegOpenKeyExA(TRUE);
    Attach_registry_RegCreateKeyExW(TRUE);  Attach_registry_RegCreateKeyExA(TRUE);
    Attach_registry_RegSetValueExW(TRUE);   Attach_registry_RegSetValueExA(TRUE);
    Attach_registry_RegQueryValueExW(TRUE); Attach_registry_RegDeleteKeyExW(TRUE);
    Attach_registry_RegDeleteValueW(TRUE);  Attach_registry_RegCloseKey(TRUE);

    Attach_network_socket(TRUE);        Attach_network_connect(TRUE);
    Attach_network_send(TRUE);          Attach_network_recv(TRUE);
    Attach_network_WSASend(TRUE);       Attach_network_WSARecv(TRUE);
    Attach_network_bind(TRUE);          Attach_network_listen(TRUE);
    Attach_network_accept(TRUE);        Attach_network_closesocket(TRUE);
    Attach_network_getaddrinfo(TRUE);   Attach_network_URLDownloadToFileW(TRUE);

    Attach_memory_VirtualAlloc(TRUE);       Attach_memory_VirtualAllocEx(TRUE);
    Attach_memory_VirtualFree(TRUE);        Attach_memory_VirtualFreeEx(TRUE);
    Attach_memory_VirtualProtect(TRUE);     Attach_memory_VirtualProtectEx(TRUE);
    Attach_memory_WriteProcessMemory(TRUE); Attach_memory_ReadProcessMemory(TRUE);

    Attach_dll_LoadLibraryW(TRUE);  Attach_dll_LoadLibraryA(TRUE);
    Attach_dll_LoadLibraryExW(TRUE); Attach_dll_FreeLibrary(TRUE);
    Attach_dll_GetProcAddress(TRUE);

    Attach_sync_CreateMutexW(TRUE); Attach_sync_CreateMutexA(TRUE);
    Attach_sync_CreateEventW(TRUE); Attach_sync_CreateEventA(TRUE);
    Attach_sync_CreateSemaphoreW(TRUE); Attach_sync_WaitForSingleObject(TRUE);
    Attach_sync_SetEvent(TRUE);

    Attach_win_CreateWindowExW(TRUE);   Attach_win_CreateWindowExA(TRUE);
    Attach_win_SetWindowsHookExW(TRUE); Attach_win_SetWindowsHookExA(TRUE);
    Attach_win_SendMessageW(TRUE);      Attach_win_PostMessageW(TRUE);
    Attach_win_GetMessageW(TRUE);       Attach_win_SetWindowLongPtrW(TRUE);

    Attach_service_OpenSCManagerW(TRUE); Attach_service_OpenSCManagerA(TRUE);
    Attach_service_CreateServiceW(TRUE); Attach_service_StartServiceW(TRUE);
    Attach_service_ControlService(TRUE); Attach_service_DeleteService(TRUE);

    LONG Err = DetourTransactionCommit();
    return Err == NO_ERROR;
}

static BOOL HookManager_DetachAll() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    Attach_process_CreateProcessW(FALSE);    Attach_process_CreateProcessA(FALSE);
    Attach_process_CreateThread(FALSE);      Attach_process_CreateRemoteThread(FALSE);
    Attach_process_CreateRemoteThreadEx(FALSE); Attach_process_OpenProcess(FALSE);
    Attach_process_TerminateProcess(FALSE);  Attach_process_ExitProcess(FALSE);

    Attach_file_CreateFileW(FALSE);  Attach_file_CreateFileA(FALSE);
    Attach_file_ReadFile(FALSE);     Attach_file_WriteFile(FALSE);
    Attach_file_DeleteFileW(FALSE);  Attach_file_DeleteFileA(FALSE);
    Attach_file_MoveFileW(FALSE);    Attach_file_CopyFileW(FALSE);

    Attach_registry_RegOpenKeyExW(FALSE);    Attach_registry_RegOpenKeyExA(FALSE);
    Attach_registry_RegCreateKeyExW(FALSE);   Attach_registry_RegCreateKeyExA(FALSE);
    Attach_registry_RegSetValueExW(FALSE);    Attach_registry_RegSetValueExA(FALSE);
    Attach_registry_RegQueryValueExW(FALSE);  Attach_registry_RegDeleteKeyExW(FALSE);
    Attach_registry_RegDeleteValueW(FALSE);   Attach_registry_RegCloseKey(FALSE);

    Attach_network_socket(FALSE);        Attach_network_connect(FALSE);
    Attach_network_send(FALSE);          Attach_network_recv(FALSE);
    Attach_network_WSASend(FALSE);       Attach_network_WSARecv(FALSE);
    Attach_network_bind(FALSE);          Attach_network_listen(FALSE);
    Attach_network_accept(FALSE);        Attach_network_closesocket(FALSE);
    Attach_network_getaddrinfo(FALSE);   Attach_network_URLDownloadToFileW(FALSE);

    Attach_memory_VirtualAlloc(FALSE);        Attach_memory_VirtualAllocEx(FALSE);
    Attach_memory_VirtualFree(FALSE);         Attach_memory_VirtualFreeEx(FALSE);
    Attach_memory_VirtualProtect(FALSE);      Attach_memory_VirtualProtectEx(FALSE);
    Attach_memory_WriteProcessMemory(FALSE);  Attach_memory_ReadProcessMemory(FALSE);

    Attach_dll_LoadLibraryW(FALSE);  Attach_dll_LoadLibraryA(FALSE);
    Attach_dll_LoadLibraryExW(FALSE); Attach_dll_FreeLibrary(FALSE);
    Attach_dll_GetProcAddress(FALSE);

    Attach_sync_CreateMutexW(FALSE);  Attach_sync_CreateMutexA(FALSE);
    Attach_sync_CreateEventW(FALSE);  Attach_sync_CreateEventA(FALSE);
    Attach_sync_CreateSemaphoreW(FALSE); Attach_sync_WaitForSingleObject(FALSE);
    Attach_sync_SetEvent(FALSE);

    Attach_win_CreateWindowExW(FALSE);    Attach_win_CreateWindowExA(FALSE);
    Attach_win_SetWindowsHookExW(FALSE);  Attach_win_SetWindowsHookExA(FALSE);
    Attach_win_SendMessageW(FALSE);       Attach_win_PostMessageW(FALSE);
    Attach_win_GetMessageW(FALSE);        Attach_win_SetWindowLongPtrW(FALSE);

    Attach_service_OpenSCManagerW(FALSE);  Attach_service_OpenSCManagerA(FALSE);
    Attach_service_CreateServiceW(FALSE);  Attach_service_StartServiceW(FALSE);
    Attach_service_ControlService(FALSE);  Attach_service_DeleteService(FALSE);

    LONG Err = DetourTransactionCommit();
    return Err == NO_ERROR;
}

/* ──── DLL Entry Point ──── */
BOOL WINAPI DllMain(HINSTANCE HinstDll, DWORD Reason, LPVOID Reserved) {
    (void)HinstDll;
    (void)Reserved;
    if (Reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(HinstDll);
        PipeConnect();
        HookManager_AttachAll();
        char Buf[256];
        sprintf_s(Buf, "{\"cat\":\"DLL_LOADED\",\"ts\":%llu,\"pid\":%lu}",
            (unsigned long long)GetTickCount64(), GetCurrentProcessId());
        PipeSend(Buf);
    }
    else if (Reason == DLL_PROCESS_DETACH) {
        HookManager_DetachAll();
        PipeDisconnect();
    }
    return TRUE;
}
