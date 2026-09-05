#include <iostream>
#include <sddl.h>
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS(NTAPI *pNtSuspendProcess)(HANDLE);
typedef NTSTATUS(NTAPI *pNtResumeProcess)(HANDLE);

inline pNtSuspendProcess NtSuspendProcess = nullptr;
inline pNtResumeProcess NtResumeProcess = nullptr;

inline bool InitNtFunctions() {
  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  if (!ntdll)
    return false;
  NtSuspendProcess =
      (pNtSuspendProcess)GetProcAddress(ntdll, "NtSuspendProcess");
  NtResumeProcess = (pNtResumeProcess)GetProcAddress(ntdll, "NtResumeProcess");
  return NtSuspendProcess && NtResumeProcess;
}

inline bool Suspend(DWORD Pid) {
  if (!InitNtFunctions())
    return false;
  HANDLE HProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, Pid);
  if (!HProcess)
    return false;
  NTSTATUS Status = NtSuspendProcess(HProcess);
  CloseHandle(HProcess);
  return NT_SUCCESS(Status);
}

inline bool Resume(DWORD Pid) {
  if (!InitNtFunctions())
    return false;
  HANDLE HProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, Pid);
  if (!HProcess)
    return false;
  NTSTATUS Status = NtResumeProcess(HProcess);
  CloseHandle(HProcess);
  return NT_SUCCESS(Status);
}

inline bool SetIntegrity(LPCTSTR Level) {
  HANDLE HToken;
  OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_DEFAULT | TOKEN_QUERY,
                   &HToken);

  PSID SID;
  ConvertStringSidToSidW(Level, &SID);

  TOKEN_MANDATORY_LABEL TML = {};
  TML.Label.Attributes = SE_GROUP_INTEGRITY;
  TML.Label.Sid = SID;

  BOOL OK = SetTokenInformation(HToken, TokenIntegrityLevel, &TML,
                                sizeof(TML) + GetLengthSid(SID));
  LocalFree(SID);
  CloseHandle(HToken);
  return OK;
}

inline bool SetIntegrity(DWORD Pid, LPCWSTR Level) {
  if (!Level)
    return false;
  HANDLE Process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
  if (!Process)
    return false;

  HANDLE Token = nullptr;
  const BOOL TokenOpened =
      OpenProcessToken(Process, TOKEN_ADJUST_DEFAULT | TOKEN_QUERY, &Token);
  CloseHandle(Process);
  if (!TokenOpened)
    return false;

  PSID Sid = nullptr;
  if (!ConvertStringSidToSidW(Level, &Sid)) {
    CloseHandle(Token);
    return false;
  }

  TOKEN_MANDATORY_LABEL Label{};
  Label.Label.Attributes = SE_GROUP_INTEGRITY;
  Label.Label.Sid = Sid;
  const BOOL Result =
      SetTokenInformation(Token, TokenIntegrityLevel, &Label,
                          sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(Sid));
  LocalFree(Sid);
  CloseHandle(Token);
  return Result == TRUE;
}

inline DWORD GetIntegrityLevel(HANDLE hToken) {
  DWORD dwLen = 0;
  GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &dwLen);
  if (dwLen == 0)
    return 0;
  auto *pTML = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, dwLen);
  if (!pTML ||
      !GetTokenInformation(hToken, TokenIntegrityLevel, pTML, dwLen, &dwLen)) {
    if (pTML)
      LocalFree(pTML);
    return 0;
  }

  DWORD RID = *GetSidSubAuthority(
      pTML->Label.Sid,
      (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTML->Label.Sid) - 1));
  LocalFree(pTML);
  return RID;
}
