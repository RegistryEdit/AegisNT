#include <windows.h>
#include <cstdio>
#include <tlhelp32.h>
#include <winternl.h>
#include <vector>
#include <iostream>
#include <string>
#include <sstream>

#pragma warning(disable: 4700)

typedef NTSTATUS(NTAPI* PNtTerminateProcess)(HANDLE, NTSTATUS);
typedef struct _PACKAGE_SUICIDE {
	intptr_t adExitProcess;
}PACKAGE_SUICIDE, * PPACKAGE_SUICIDE;
typedef BOOL(WINAPI* T_EndTask)
(
	HWND hWnd,
	BOOL fShutDown,
	BOOL fForce
	);

T_EndTask pfnEndTask = nullptr;


void PatchThread(DWORD Ptid)
{
	static auto exitAddr = (DWORDLONG)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "ExitProcess");

	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, Ptid);
	SuspendThread(hThread);

	CONTEXT Context;
	Context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER; 

	BOOL bRet = GetThreadContext(hThread, &Context);
	if (!bRet) {
		printf("Thread %d GetThreadContext failed: %ld\n", Ptid, GetLastError());
		ResumeThread(hThread);
		CloseHandle(hThread);
		return;
	}

	Context.Rcx = 0U;
	Context.Rip = exitAddr;
	bRet = SetThreadContext(hThread, &Context);
	if (!bRet) {
		printf("Thread %d SetThreadContext failed: %ld\n", Ptid, GetLastError());
		ResumeThread(hThread);
		CloseHandle(hThread);
		return;
	}
	ResumeThread(hThread);
	CloseHandle(hThread);

	printf("Thread %d done\n", Ptid);
}
BOOL HaveProcess(DWORD Pid) {
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, Pid);
	if (hProcess == NULL) {
		DWORD Error = GetLastError();
		if (Error == ERROR_INVALID_PARAMETER) {
			return FALSE;
		}
		return TRUE;
	}
	CloseHandle(hProcess);
	return TRUE;
}
void PatchThreadRun(DWORD Pid) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, Pid);
	if (hSnapshot != INVALID_HANDLE_VALUE) {
		THREADENTRY32 Te = { sizeof(Te) };
		BOOL fOk = Thread32First(hSnapshot, &Te);
		for (; fOk; fOk = Thread32Next(hSnapshot, &Te)) {
			if (Te.th32OwnerProcessID == Pid) {
				PatchThread(Te.th32ThreadID);
			}
			if (!HaveProcess(Pid)) {
				break;
			}
		}
		CloseHandle(hSnapshot);
		printf("[*]Operation done!\n");
	}
}

bool NtTerminate(DWORD Pid) {
	HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, Pid);
	bool bRes = false;
	if (hProcess) {
		PNtTerminateProcess NtTerminateProcess =
			(PNtTerminateProcess)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtTerminateProcess");
		if (NtTerminateProcess) {
			bRes = NT_SUCCESS(NtTerminateProcess(hProcess, 0));
		}
		CloseHandle(hProcess);
	}
	return bRes;
}

bool KillProcessForce(DWORD dwProcessID)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwProcessID);
	if (hSnapshot != INVALID_HANDLE_VALUE) {
		bool Return = true;
		THREADENTRY32 Te = { sizeof(Te) };
		BOOL fOk = Thread32First(hSnapshot, &Te);
		for (; fOk; fOk = Thread32Next(hSnapshot, &Te)) {
			if (Te.th32OwnerProcessID == dwProcessID) {
				HANDLE hThread = OpenThread(THREAD_TERMINATE, FALSE, Te.th32ThreadID);
				if (!TerminateThread(hThread, 0)) Return = false;
				CloseHandle(hThread);
			}
		}
		CloseHandle(hSnapshot);
		return Return;
	}
}

DWORD WINAPI RemoteThreadProc_Suicide(LPVOID lpParam)
{
	PPACKAGE_SUICIDE pack = (PPACKAGE_SUICIDE)lpParam;
	typedef VOID(__stdcall* T_ExitProcess)(UINT);
	T_ExitProcess _ExitProcess = (T_ExitProcess)pack->adExitProcess;
	_ExitProcess(0);
	return 0;
}
bool InjectSuicide(HANDLE hProc)
{
	if (!hProc)
	{
		printf("Invalid handle\n");
		return false;
	}
	PACKAGE_SUICIDE pack{ 0 };
	pack.adExitProcess = (intptr_t)GetProcAddress(GetModuleHandle(L"KERNEL32.dll"), "ExitProcess");
	if (!pack.adExitProcess)
	{
		printf("GetProcAddress Failed\n");
		return false;
	}
	LPVOID lpData = VirtualAllocEx(hProc, NULL, sizeof pack, MEM_COMMIT, PAGE_READWRITE);
	if (!lpData)
	{
		printf("VirtualAllocEx 1 Failed\n");
		return false;
	}
	SIZE_T useless = 0;
	BOOL ret = WriteProcessMemory(hProc, lpData, &pack, sizeof pack, &useless);
	if (!ret)
	{
		printf("WriteProcessMemory 1 Failed\n");
		return false;
	}
	DWORD dwFunSize = 0x1000;
	LPVOID lpCode = VirtualAllocEx(hProc, NULL, dwFunSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!lpCode)
	{
		printf("VirtualAllocEx 2 Failed\n");
		return false;
	}
	ret = WriteProcessMemory(hProc, lpCode, (LPVOID)&RemoteThreadProc_Suicide, dwFunSize, &useless);
	if (!ret)
	{
		printf("WriteProcessMemory 2 Failed\n");
		return false;
	}
	HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)lpCode, lpData, 0, NULL);
	if (!hThread)
	{
		printf("CreateRemoteThread Failed\n");
		return false;
	}
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	CloseHandle(hProc);
	return true;
}
bool RunInjectProc(DWORD Pid) {
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);
	return InjectSuicide(hProc);
}