#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

class ScHandleGuard {
public:
  explicit ScHandleGuard(SC_HANDLE Handle = nullptr) : M_Handle(Handle) {}
  ~ScHandleGuard() {
    if (M_Handle) {
      CloseServiceHandle(M_Handle);
    }
  }
  ScHandleGuard(const ScHandleGuard &) = delete;
  ScHandleGuard &operator=(const ScHandleGuard &) = delete;
  ScHandleGuard(ScHandleGuard &&Other) noexcept : M_Handle(Other.M_Handle) {
    Other.M_Handle = nullptr;
  }
  ScHandleGuard &operator=(ScHandleGuard &&Other) noexcept {
    if (this != &Other) {
      if (M_Handle)
        CloseServiceHandle(M_Handle);
      M_Handle = Other.M_Handle;
      Other.M_Handle = nullptr;
    }
    return *this;
  }
  SC_HANDLE Get() const { return M_Handle; }
  SC_HANDLE *Address() { return &M_Handle; }
  SC_HANDLE Release() {
    SC_HANDLE Handle = M_Handle;
    M_Handle = nullptr;
    return Handle;
  }
  bool Valid() const { return M_Handle != nullptr; }
  void Reset(SC_HANDLE Handle = nullptr) {
    if (M_Handle)
      CloseServiceHandle(M_Handle);
    M_Handle = Handle;
  }

private:
  SC_HANDLE M_Handle;
};

void PrintLastErrorMessage(const wchar_t *Context) {
  DWORD Error = GetLastError();
  wchar_t *MsgBuf = nullptr;
  FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                     FORMAT_MESSAGE_IGNORE_INSERTS,
                 nullptr, Error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                 (LPWSTR)&MsgBuf, 0, nullptr);
  wprintf(L"[Error] %s (Error Code: %lu)\n", Context, Error);
  if (MsgBuf) {
    wprintf(L"       Reason: %s\n", MsgBuf);
    LocalFree(MsgBuf);
  }
}

bool GetFullDriverPathValue(const wchar_t *InputPath, wchar_t *OutPath,
                            DWORD Size) {
  DWORD Result = GetFullPathNameW(InputPath, Size, OutPath, nullptr);
  if (Result == 0 || Result > Size) {
    return false;
  }
  DWORD Attr = GetFileAttributesW(OutPath);
  if (Attr == INVALID_FILE_ATTRIBUTES || (Attr & FILE_ATTRIBUTE_DIRECTORY)) {
    return false;
  }
  return true;
}

bool QueryServiceStatusValue(SC_HANDLE Service,
                             SERVICE_STATUS_PROCESS *Status) {
  DWORD BytesNeeded = 0;
  ZeroMemory(Status, sizeof(*Status));
  return QueryServiceStatusEx(Service, SC_STATUS_PROCESS_INFO,
                              reinterpret_cast<LPBYTE>(Status), sizeof(*Status),
                              &BytesNeeded) != FALSE;
}

bool QueryDriverServiceState(const wchar_t *ServiceName, DWORD *State) {
  if (State) {
    *State = SERVICE_STOPPED;
  }
  if (!ServiceName || !*ServiceName) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return false;
  }

  ScHandleGuard Scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
  if (!Scm.Valid()) {
    return false;
  }

  ScHandleGuard Service(
      OpenServiceW(Scm.Get(), ServiceName, SERVICE_QUERY_STATUS));
  if (!Service.Valid()) {
    const DWORD Error = GetLastError();
    if (Error == ERROR_SERVICE_DOES_NOT_EXIST) {
      if (State) {
        *State = SERVICE_STOPPED;
      }
      return true;
    }
    SetLastError(Error);
    return false;
  }

  SERVICE_STATUS_PROCESS Status{};
  if (!QueryServiceStatusValue(Service.Get(), &Status)) {
    return false;
  }
  if (State) {
    *State = Status.dwCurrentState;
  }
  return true;
}

bool IsDriverServiceRunning(const wchar_t *ServiceName) {
  DWORD State = SERVICE_STOPPED;
  return QueryDriverServiceState(ServiceName, &State) &&
         State == SERVICE_RUNNING;
}

bool WaitForServiceState(SC_HANDLE Service, DWORD DesiredState,
                         DWORD TimeoutMs) {
  const ULONGLONG Deadline = GetTickCount64() + TimeoutMs;
  SERVICE_STATUS_PROCESS Status{};
  do {
    if (!QueryServiceStatusValue(Service, &Status)) {
      return false;
    }
    if (Status.dwCurrentState == DesiredState) {
      return true;
    }
    Sleep(50);
  } while (GetTickCount64() < Deadline);
  SetLastError(ERROR_TIMEOUT);
  return false;
}

bool WaitForServiceDeletion(SC_HANDLE Scm, const wchar_t *ServiceName,
                            DWORD TimeoutMs) {
  const ULONGLONG Deadline = GetTickCount64() + TimeoutMs;
  do {
    ScHandleGuard Existing(
        OpenServiceW(Scm, ServiceName, SERVICE_QUERY_STATUS));
    if (!Existing.Valid()) {
      DWORD Error = GetLastError();
      if (Error == ERROR_SERVICE_DOES_NOT_EXIST) {
        return true;
      }
      SetLastError(Error);
      return false;
    }
    Sleep(50);
  } while (GetTickCount64() < Deadline);
  SetLastError(ERROR_SERVICE_MARKED_FOR_DELETE);
  return false;
}

const wchar_t *DriverDevicePathForService(const wchar_t *ServiceName) {
  if (!ServiceName || !*ServiceName) {
    return nullptr;
  }
  if (lstrcmpiW(ServiceName, L"Ring0Core") == 0 ||
      lstrcmpiW(ServiceName, L"AegisCore") == 0) {
    return L"\\\\.\\AegisCore";
  }
  if (lstrcmpiW(ServiceName, L"AegisSentinel") == 0) {
    return L"\\\\.\\AegisSentinel";
  }
  if (lstrcmpiW(ServiceName, L"DiskDrv") == 0) {
    return L"\\\\.\\DiskDrv";
  }
  return nullptr;
}

bool ShouldRetryDeviceOpenError(DWORD Error) {
  switch (Error) {
  case ERROR_FILE_NOT_FOUND:
  case ERROR_PATH_NOT_FOUND:
  case ERROR_GEN_FAILURE:
  case ERROR_DEVICE_NOT_CONNECTED:
  case ERROR_NOT_READY:
    return true;
  default:
    return false;
  }
}

bool WaitForDriverDeviceReady(const wchar_t *ServiceName, DWORD TimeoutMs) {
  const wchar_t *DevicePath = DriverDevicePathForService(ServiceName);
  if (!DevicePath) {
    return true;
  }

  const ULONGLONG Deadline = GetTickCount64() + TimeoutMs;
  DWORD LastError = ERROR_FILE_NOT_FOUND;
  do {
    HANDLE Device =
        CreateFileW(DevicePath, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (Device != INVALID_HANDLE_VALUE) {
      CloseHandle(Device);
      return true;
    }

    LastError = GetLastError();
    if (!ShouldRetryDeviceOpenError(LastError)) {
      break;
    }
    Sleep(50);
  } while (GetTickCount64() < Deadline);

  SetLastError(LastError);
  return false;
}

DWORD StopAndDeleteDriverService(SC_HANDLE Scm, const wchar_t *ServiceName) {
  ScHandleGuard Existing(OpenServiceW(Scm, ServiceName, SERVICE_ALL_ACCESS));
  if (!Existing.Valid()) {
    DWORD Error = GetLastError();
    if (Error == ERROR_SERVICE_DOES_NOT_EXIST) {
      return 0;
    }
    PrintLastErrorMessage(L"Failed to open existing driver service");
    return 1;
  }

  SERVICE_STATUS_PROCESS Status{};
  if (QueryServiceStatusValue(Existing.Get(), &Status)) {
    if (Status.dwCurrentState != SERVICE_STOPPED &&
        Status.dwCurrentState != SERVICE_STOP_PENDING) {
      SERVICE_STATUS ServiceStatus{};
      if (!ControlService(Existing.Get(), SERVICE_CONTROL_STOP,
                          &ServiceStatus)) {
        DWORD Error = GetLastError();
        if (Error != ERROR_SERVICE_NOT_ACTIVE) {
          PrintLastErrorMessage(L"Failed to stop existing driver service");
          return 1;
        }
      }
    }

    if (Status.dwCurrentState != SERVICE_STOPPED &&
        !WaitForServiceState(Existing.Get(), SERVICE_STOPPED, 5000)) {
      PrintLastErrorMessage(L"Timed out waiting for driver service to stop");
      return 1;
    }
  }

  if (!DeleteService(Existing.Get())) {
    DWORD Error = GetLastError();
    if (Error != ERROR_SERVICE_MARKED_FOR_DELETE) {
      PrintLastErrorMessage(L"Failed to delete existing driver service");
      return 1;
    }
  }

  Existing.Reset();

  if (!WaitForServiceDeletion(Scm, ServiceName, 5000)) {
    PrintLastErrorMessage(L"Timed out waiting for driver service deletion");
    return 1;
  }

  return 0;
}

DWORD OpenOrCreateDriverService(SC_HANDLE Scm, const wchar_t *ServiceName,
                                const wchar_t *FullPath,
                                ScHandleGuard *Service) {
  if (!Scm || !ServiceName || !*ServiceName || !FullPath || !*FullPath ||
      !Service) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return 1;
  }

  for (;;) {
    ScHandleGuard Existing(OpenServiceW(Scm, ServiceName, SERVICE_ALL_ACCESS));
    if (Existing.Valid()) {
      if (!ChangeServiceConfigW(Existing.Get(), SERVICE_NO_CHANGE,
                                SERVICE_DEMAND_START, SERVICE_NO_CHANGE,
                                FullPath, nullptr, nullptr, nullptr, nullptr,
                                nullptr, ServiceName)) {
        PrintLastErrorMessage(L"Failed to update existing driver service");
        return 1;
      }
      Service->Reset(Existing.Release());
      return 0;
    }

    const DWORD OpenError = GetLastError();
    if (OpenError != ERROR_SERVICE_DOES_NOT_EXIST &&
        OpenError != ERROR_SERVICE_MARKED_FOR_DELETE) {
      SetLastError(OpenError);
      PrintLastErrorMessage(L"Failed to open existing driver service");
      return 1;
    }

    if (OpenError == ERROR_SERVICE_MARKED_FOR_DELETE) {
      if (!WaitForServiceDeletion(Scm, ServiceName, 10000)) {
        PrintLastErrorMessage(L"Timed out waiting for driver service deletion");
        return 1;
      }
      continue;
    }

    ScHandleGuard Created(CreateServiceW(
        Scm, ServiceName, ServiceName, SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        FullPath, nullptr, nullptr, nullptr, nullptr, nullptr));
    if (Created.Valid()) {
      Service->Reset(Created.Release());
      return 0;
    }

    const DWORD CreateError = GetLastError();
    if (CreateError == ERROR_SERVICE_EXISTS || CreateError == ERROR_DUP_NAME ||
        CreateError == ERROR_SERVICE_MARKED_FOR_DELETE) {
      if (CreateError == ERROR_SERVICE_MARKED_FOR_DELETE &&
          !WaitForServiceDeletion(Scm, ServiceName, 10000)) {
        PrintLastErrorMessage(L"Timed out waiting for driver service deletion");
        return 1;
      }
      continue;
    }

    SetLastError(CreateError);
    PrintLastErrorMessage(L"Failed to create driver service");
    return 1;
  }
}

DWORD LoadDriverService(const wchar_t *DriverPath, const wchar_t *ServiceName) {
  wchar_t FullPath[MAX_PATH];
  if (!GetFullDriverPathValue(DriverPath, FullPath, MAX_PATH)) {
    wprintf(L"[!] Invalid driver path: %s\n", DriverPath);
    return 1;
  }

  ScHandleGuard Scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
  if (!Scm.Valid()) {
    PrintLastErrorMessage(L"Failed to open Service Control Manager");
    return 1;
  }

  ScHandleGuard Service;
  if (OpenOrCreateDriverService(Scm.Get(), ServiceName, FullPath, &Service) !=
      0) {
    return 1;
  }

  SERVICE_STATUS_PROCESS Status{};
  if (QueryServiceStatusValue(Service.Get(), &Status)) {
    if (Status.dwCurrentState == SERVICE_STOP_PENDING) {
      if (!WaitForServiceState(Service.Get(), SERVICE_STOPPED, 10000)) {
        PrintLastErrorMessage(L"Timed out waiting for driver service to stop");
        return 1;
      }
    } else if (Status.dwCurrentState == SERVICE_START_PENDING) {
      if (!WaitForServiceState(Service.Get(), SERVICE_RUNNING, 15000)) {
        PrintLastErrorMessage(L"Timed out waiting for driver service to start");
        return 1;
      }
    }
  }

  if (!QueryServiceStatusValue(Service.Get(), &Status) ||
      Status.dwCurrentState != SERVICE_RUNNING) {
    if (!StartServiceW(Service.Get(), 0, nullptr)) {
      const DWORD Error = GetLastError();
      if (Error != ERROR_SERVICE_ALREADY_RUNNING) {
        SetLastError(Error);
        PrintLastErrorMessage(L"Failed to start driver");
        return 1;
      }
    }
    if (!WaitForServiceState(Service.Get(), SERVICE_RUNNING, 15000)) {
      PrintLastErrorMessage(L"Timed out waiting for driver service to start");
      return 1;
    }
  }

  if (!WaitForDriverDeviceReady(ServiceName, 15000)) {
    DWORD State = SERVICE_STOPPED;
    if (!QueryDriverServiceState(ServiceName, &State) ||
        State != SERVICE_RUNNING) {
      PrintLastErrorMessage(
          L"Timed out waiting for driver device to become ready");
      return 1;
    }
  }

  wprintf(L"[Success] Driver \"%s\" loaded\n", ServiceName);
  return 0;
}

DWORD UnloadDriverService(const wchar_t *ServiceName) {
  ScHandleGuard Scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
  if (!Scm.Valid()) {
    PrintLastErrorMessage(L"Failed to open Service Control Manager");
    return 1;
  }

  const DWORD Result = StopAndDeleteDriverService(Scm.Get(), ServiceName);
  if (Result == 0) {
    wprintf(L"[Success] Service \"%s\" deleted\n", ServiceName);
  }
  return Result;
}
