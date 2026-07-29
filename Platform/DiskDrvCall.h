#pragma once

#include <algorithm>
#include <string>
#include <vector>
#include <windows.h>
#include <winioctl.h>

#include "..\\Drivers\\DiskDrv\\DiskDrvShared.h"

static constexpr const wchar_t *DISKDRV_USER_DEVICE_NAME = L"\\\\.\\DiskDrv";

struct DISKDRV_SECTOR_RANGE {
  ULONG DiskNumber = 0;
  ULONGLONG StartLba = 0;
  ULONG SectorCount = 0;
  ULONG BytesPerSector = 512;
  ULONG PartitionStyle = PARTITION_STYLE_RAW;
};

enum DISKDRV_PROTECTED_REGION : ULONG {
  DiskDrvProtectedRegionHead = 0,
  DiskDrvProtectedRegionTail = 1,
};

static inline bool ReadPhysicalDiskSectors(const DISKDRV_SECTOR_RANGE &Range,
                                           std::vector<BYTE> *Buffer);

static inline std::wstring DiskDrvPhysicalDrivePath(ULONG DiskNumber) {
  return L"\\\\.\\PhysicalDrive" + std::to_wstring(DiskNumber);
}

static inline HANDLE OpenDiskPhysicalDrive(ULONG DiskNumber) {
  const std::wstring Path = DiskDrvPhysicalDrivePath(DiskNumber);
  return CreateFileW(Path.c_str(), GENERIC_READ,
                     FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                     FILE_ATTRIBUTE_NORMAL, nullptr);
}

static inline bool DiskDrvQueryBytesPerSector(ULONG DiskNumber,
                                              ULONG *BytesPerSector) {
  if (!BytesPerSector) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return false;
  }

  *BytesPerSector = 512;
  HANDLE Device = OpenDiskPhysicalDrive(DiskNumber);
  if (Device == INVALID_HANDLE_VALUE)
    return false;

  DISK_GEOMETRY_EX Geometry{};
  DWORD Bytes = 0;
  const BOOL Ok =
      DeviceIoControl(Device, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, nullptr, 0,
                      &Geometry, sizeof(Geometry), &Bytes, nullptr);
  const DWORD Error = Ok ? ERROR_SUCCESS : GetLastError();
  CloseHandle(Device);
  if (!Ok) {
    SetLastError(Error);
    return false;
  }

  if (Geometry.Geometry.BytesPerSector != 0)
    *BytesPerSector = Geometry.Geometry.BytesPerSector;
  SetLastError(ERROR_SUCCESS);
  return true;
}

static inline bool DiskDrvQueryDiskLengthBytes(ULONG DiskNumber,
                                               ULONGLONG *DiskLengthBytes) {
  if (!DiskLengthBytes) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return false;
  }

  HANDLE Device = OpenDiskPhysicalDrive(DiskNumber);
  if (Device == INVALID_HANDLE_VALUE)
    return false;

  GET_LENGTH_INFORMATION LengthInfo{};
  DWORD Bytes = 0;
  const BOOL Ok =
      DeviceIoControl(Device, IOCTL_DISK_GET_LENGTH_INFO, nullptr, 0,
                      &LengthInfo, sizeof(LengthInfo), &Bytes, nullptr);
  const DWORD Error = Ok ? ERROR_SUCCESS : GetLastError();
  CloseHandle(Device);
  if (!Ok) {
    SetLastError(Error);
    return false;
  }

  *DiskLengthBytes = static_cast<ULONGLONG>(LengthInfo.Length.QuadPart);
  SetLastError(ERROR_SUCCESS);
  return true;
}

static inline bool DiskDrvQueryPartitionStyle(ULONG DiskNumber,
                                              ULONG *PartitionStyle) {
  if (!PartitionStyle) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return false;
  }

  HANDLE Device = OpenDiskPhysicalDrive(DiskNumber);
  if (Device == INVALID_HANDLE_VALUE)
    return false;

  std::vector<BYTE> Buffer(sizeof(DRIVE_LAYOUT_INFORMATION_EX) +
                               sizeof(PARTITION_INFORMATION_EX) * 128,
                           0);
  DWORD Bytes = 0;
  const BOOL Ok = DeviceIoControl(
      Device, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, nullptr, 0, Buffer.data(),
      static_cast<DWORD>(Buffer.size()), &Bytes, nullptr);
  const DWORD Error = Ok ? ERROR_SUCCESS : GetLastError();
  CloseHandle(Device);
  if (!Ok || Bytes < sizeof(DRIVE_LAYOUT_INFORMATION_EX)) {
    SetLastError(Ok ? ERROR_INSUFFICIENT_BUFFER : Error);
    return false;
  }

  const auto *Layout =
      reinterpret_cast<const DRIVE_LAYOUT_INFORMATION_EX *>(Buffer.data());
  *PartitionStyle = Layout->PartitionStyle;
  SetLastError(ERROR_SUCCESS);
  return true;
}

static inline bool DiskDrvReadSectorLba0(ULONG DiskNumber, ULONG BytesPerSector,
                                         std::vector<BYTE> *Buffer) {
  if (!Buffer || BytesPerSector == 0) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return false;
  }

  DISKDRV_SECTOR_RANGE Range{};
  Range.DiskNumber = DiskNumber;
  Range.StartLba = 0;
  Range.SectorCount = 1;
  Range.BytesPerSector = BytesPerSector;
  Range.PartitionStyle = PARTITION_STYLE_RAW;
  return ReadPhysicalDiskSectors(Range, Buffer);
}

static inline bool DiskDrvReadSectorLba1(ULONG DiskNumber, ULONG BytesPerSector,
                                         std::vector<BYTE> *Buffer) {
  if (!Buffer || BytesPerSector == 0) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return false;
  }

  DISKDRV_SECTOR_RANGE Range{};
  Range.DiskNumber = DiskNumber;
  Range.StartLba = 1;
  Range.SectorCount = 1;
  Range.BytesPerSector = BytesPerSector;
  Range.PartitionStyle = PARTITION_STYLE_RAW;
  return ReadPhysicalDiskSectors(Range, Buffer);
}

static inline bool DiskDrvHasProtectiveMbr(const std::vector<BYTE> &Sector0) {
  if (Sector0.size() < 512)
    return false;
  if (Sector0[510] != 0x55 || Sector0[511] != 0xAA)
    return false;

  for (size_t Offset = 446; Offset + 16 <= 510; Offset += 16) {
    if (Sector0[Offset + 4] == 0xEE)
      return true;
  }
  return false;
}

static inline bool DiskDrvHasGptHeaderSignature(const std::vector<BYTE> &Sector1) {
  static constexpr char KGptSignature[8] = {'E', 'F', 'I', ' ', 'P', 'A', 'R', 'T'};
  return Sector1.size() >= sizeof(KGptSignature) &&
         std::equal(std::begin(KGptSignature), std::end(KGptSignature), Sector1.begin());
}

static inline bool DiskDrvQueryPartitionStyleRobust(ULONG DiskNumber,
                                                    ULONG *PartitionStyle) {
  if (!PartitionStyle) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return false;
  }

  ULONG LayoutStyle = PARTITION_STYLE_RAW;
  const bool HasLayoutStyle = DiskDrvQueryPartitionStyle(DiskNumber, &LayoutStyle);
  const DWORD LayoutError = HasLayoutStyle ? ERROR_SUCCESS : GetLastError();

  ULONG BytesPerSector = 512;
  DiskDrvQueryBytesPerSector(DiskNumber, &BytesPerSector);

  std::vector<BYTE> Sector0;
  std::vector<BYTE> Sector1;
  const bool HasSector0 = DiskDrvReadSectorLba0(DiskNumber, BytesPerSector, &Sector0);
  const bool HasSector1 = DiskDrvReadSectorLba1(DiskNumber, BytesPerSector, &Sector1);

  const bool HasProtectiveMbr = HasSector0 && DiskDrvHasProtectiveMbr(Sector0);
  const bool HasGptHeader = HasSector1 && DiskDrvHasGptHeaderSignature(Sector1);

  if (HasGptHeader || (HasProtectiveMbr && LayoutStyle == PARTITION_STYLE_GPT)) {
    *PartitionStyle = PARTITION_STYLE_GPT;
    SetLastError(ERROR_SUCCESS);
    return true;
  }

  if (HasLayoutStyle) {
    *PartitionStyle = LayoutStyle;
    SetLastError(ERROR_SUCCESS);
    return true;
  }

  SetLastError(LayoutError);
  return false;
}

static inline bool BuildProtectedSectorRange(const DISKDRV_STATE_OUTPUT &State,
                                             DISKDRV_SECTOR_RANGE *Range) {
  if (!Range) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return false;
  }

  Range->DiskNumber = State.DiskNumber;
  Range->PartitionStyle = State.PartitionStyle;
  Range->StartLba = 0;
  Range->SectorCount = 1;
  Range->BytesPerSector = 512;
  DiskDrvQueryBytesPerSector(State.DiskNumber, &Range->BytesPerSector);

  switch (State.PartitionStyle) {
  case PARTITION_STYLE_GPT:
    Range->SectorCount = 34;
    break;
  case PARTITION_STYLE_MBR:
    Range->SectorCount = 1;
    break;
  default:
    Range->SectorCount = 1;
    break;
  }

  SetLastError(ERROR_SUCCESS);
  return true;
}

static inline bool
BuildTailProtectedSectorRange(const DISKDRV_STATE_OUTPUT &State,
                              DISKDRV_SECTOR_RANGE *Range) {
  if (!Range) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return false;
  }

  if (State.PartitionStyle != PARTITION_STYLE_GPT)
    return BuildProtectedSectorRange(State, Range);

  ULONG BytesPerSector = 512;
  if (!DiskDrvQueryBytesPerSector(State.DiskNumber, &BytesPerSector))
    return false;

  ULONGLONG DiskLengthBytes = 0;
  if (!DiskDrvQueryDiskLengthBytes(State.DiskNumber, &DiskLengthBytes))
    return false;

  if (DiskLengthBytes < BytesPerSector) {
    SetLastError(ERROR_INVALID_DATA);
    return false;
  }

  const ULONGLONG TotalSectors = DiskLengthBytes / BytesPerSector;
  if (TotalSectors < 33) {
    SetLastError(ERROR_INVALID_DATA);
    return false;
  }

  Range->DiskNumber = State.DiskNumber;
  Range->PartitionStyle = State.PartitionStyle;
  Range->BytesPerSector = BytesPerSector;
  Range->SectorCount = 33;
  Range->StartLba = TotalSectors - Range->SectorCount;
  SetLastError(ERROR_SUCCESS);
  return true;
}

static inline bool
BuildProtectedSectorRangeEx(const DISKDRV_STATE_OUTPUT &State,
                            DISKDRV_PROTECTED_REGION Region,
                            DISKDRV_SECTOR_RANGE *Range) {
  if (Region == DiskDrvProtectedRegionTail)
    return BuildTailProtectedSectorRange(State, Range);
  return BuildProtectedSectorRange(State, Range);
}

static inline bool ReadPhysicalDiskSectors(const DISKDRV_SECTOR_RANGE &Range,
                                           std::vector<BYTE> *Buffer) {
  if (!Buffer || Range.SectorCount == 0 || Range.BytesPerSector == 0) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return false;
  }

  const ULONGLONG TotalBytes64 =
      static_cast<ULONGLONG>(Range.SectorCount) * Range.BytesPerSector;
  if (TotalBytes64 == 0 || TotalBytes64 > MAXDWORD * 16ull) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return false;
  }

  HANDLE Device = OpenDiskPhysicalDrive(Range.DiskNumber);
  if (Device == INVALID_HANDLE_VALUE)
    return false;

  LARGE_INTEGER Offset{};
  Offset.QuadPart =
      static_cast<LONGLONG>(Range.StartLba * Range.BytesPerSector);
  if (!SetFilePointerEx(Device, Offset, nullptr, FILE_BEGIN)) {
    const DWORD Error = GetLastError();
    CloseHandle(Device);
    SetLastError(Error);
    return false;
  }

  Buffer->assign(static_cast<size_t>(TotalBytes64), 0);
  DWORD BytesRead = 0;
  const BOOL Ok =
      ReadFile(Device, Buffer->data(), static_cast<DWORD>(Buffer->size()),
               &BytesRead, nullptr);
  const DWORD Error = Ok ? ERROR_SUCCESS : GetLastError();
  CloseHandle(Device);
  if (!Ok) {
    Buffer->clear();
    SetLastError(Error);
    return false;
  }

  Buffer->resize(BytesRead);
  SetLastError(ERROR_SUCCESS);
  return true;
}

static inline HANDLE OpenDiskDrvDevice() {
  return CreateFileW(DISKDRV_USER_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0,
                     nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
}

static inline bool DiskDrvReadEvent(DISKDRV_EVENT *Event) {
  if (!Event) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return false;
  }

  HANDLE Device = OpenDiskDrvDevice();
  if (Device == INVALID_HANDLE_VALUE)
    return false;

  DWORD Bytes = 0;
  ZeroMemory(Event, sizeof(*Event));
  const BOOL Ok = DeviceIoControl(Device, IOCTL_DISKDRV_GET_EVENT, nullptr, 0,
                                  Event, sizeof(*Event), &Bytes, nullptr);
  const DWORD Error = Ok ? ERROR_SUCCESS : GetLastError();
  CloseHandle(Device);
  if (!Ok || Bytes < sizeof(*Event)) {
    SetLastError(Ok ? ERROR_INSUFFICIENT_BUFFER : Error);
    return false;
  }

  SetLastError(ERROR_SUCCESS);
  return true;
}

static inline bool DiskDrvQueryState(DISKDRV_STATE_OUTPUT *State) {
  if (!State) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return false;
  }

  HANDLE Device = OpenDiskDrvDevice();
  if (Device == INVALID_HANDLE_VALUE)
    return false;

  DWORD Bytes = 0;
  ZeroMemory(State, sizeof(*State));
  const BOOL Ok = DeviceIoControl(Device, IOCTL_DISKDRV_QUERY_STATE, nullptr, 0,
                                  State, sizeof(*State), &Bytes, nullptr);
  const DWORD Error = Ok ? ERROR_SUCCESS : GetLastError();
  CloseHandle(Device);
  if (!Ok || Bytes < sizeof(*State)) {
    SetLastError(Ok ? ERROR_INSUFFICIENT_BUFFER : Error);
    return false;
  }

  SetLastError(ERROR_SUCCESS);
  return true;
}

static inline bool
DiskDrvSetProtection(const DISKDRV_SET_PROTECTION_INPUT &Input) {
  HANDLE Device = OpenDiskDrvDevice();
  if (Device == INVALID_HANDLE_VALUE)
    return false;

  DWORD Bytes = 0;
  const BOOL Ok =
      DeviceIoControl(Device, IOCTL_DISKDRV_SET_PROTECTION,
                      const_cast<DISKDRV_SET_PROTECTION_INPUT *>(&Input),
                      sizeof(Input), nullptr, 0, &Bytes, nullptr);
  const DWORD Error = Ok ? ERROR_SUCCESS : GetLastError();
  CloseHandle(Device);
  SetLastError(Error);
  return Ok == TRUE;
}

static inline bool DiskDrvAllowOnce(const DISKDRV_ALLOW_ONCE_INPUT &Input) {
  HANDLE Device = OpenDiskDrvDevice();
  if (Device == INVALID_HANDLE_VALUE)
    return false;

  DWORD Bytes = 0;
  const BOOL Ok =
      DeviceIoControl(Device, IOCTL_DISKDRV_ALLOW_ONCE,
                      const_cast<DISKDRV_ALLOW_ONCE_INPUT *>(&Input),
                      sizeof(Input), nullptr, 0, &Bytes, nullptr);
  const DWORD Error = Ok ? ERROR_SUCCESS : GetLastError();
  CloseHandle(Device);
  SetLastError(Error);
  return Ok == TRUE;
}

static inline bool DiskDrvClearEvents() {
  HANDLE Device = OpenDiskDrvDevice();
  if (Device == INVALID_HANDLE_VALUE)
    return false;

  DWORD Bytes = 0;
  const BOOL Ok = DeviceIoControl(Device, IOCTL_DISKDRV_CLEAR_EVENTS, nullptr,
                                  0, nullptr, 0, &Bytes, nullptr);
  const DWORD Error = Ok ? ERROR_SUCCESS : GetLastError();
  CloseHandle(Device);
  SetLastError(Error);
  return Ok == TRUE;
}
