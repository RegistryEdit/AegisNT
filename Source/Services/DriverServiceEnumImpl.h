#pragma once

#include "../Models/CoreModels.h"
#include <cstddef>

namespace AegisNT::DriverServiceEnum {

// These parsers consume the byte counts returned by AegisCoreClient. They do
// not rely on the caller's buffer being aligned or zero-terminated.
Result<QVector<ProcessInfo>> ParseProcesses(const void *Buffer, size_t Bytes);
Result<QVector<ThreadInfo>> ParseThreadInventoryPage(
    const void *Buffer, size_t Bytes, DWORD ExpectedProcessId,
    ULONG64 RequestedCursor, ULONG64 *NextCursor);
Result<QVector<DriverInfo>> ParseDrivers(const void *Buffer, size_t Bytes);
Result<QVector<WindowInfo>> ParseKernelWindows(const void *Buffer, size_t Bytes);
Result<QVector<CallbackInfo>> ParseCallbacks(const void *Buffer, size_t Bytes);

} // namespace AegisNT::DriverServiceEnum
