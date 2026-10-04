#pragma once

#include <Windows.h>
#include <QString>
#include <algorithm>
#include <cstring>
#include <limits>
#include <tuple>
#include <vector>

namespace KernelInspectorData {
using SyncEntries = std::vector<std::tuple<QString, QString, ULONG>>;
using SessionEntries = std::vector<std::tuple<ULONG, ULONG, ULONG, QString>>;
constexpr size_t SessionRecordBytes = sizeof(ULONG) * 3 + 64;
constexpr size_t SessionBufferBytes = sizeof(ULONG) + 64 * SessionRecordBytes;

class Reader {
public:
  Reader(const void *Data, size_t Size)
      : Data(static_cast<const unsigned char *>(Data)), Size(Data ? Size : 0) {}

  template <typename T> bool Read(T &Value) {
    if (sizeof(T) > Remaining()) return false;
    std::memcpy(&Value, Data + Offset, sizeof(T));
    Offset += sizeof(T);
    return true;
  }

  bool ReadString(size_t Bytes, QString &Value) {
    if ((Bytes % sizeof(WCHAR)) != 0 || Bytes > Remaining()) return false;
    Value.resize(static_cast<qsizetype>(Bytes / sizeof(WCHAR)));
    if (Bytes) std::memcpy(Value.data(), Data + Offset, Bytes);
    Offset += Bytes;
    return true;
  }

  bool Align4() {
    const size_t Padding = (4 - Offset % 4) % 4;
    if (Padding > Remaining()) return false;
    Offset += Padding;
    return true;
  }

  size_t Remaining() const { return Size - Offset; }

private:
  const unsigned char *Data;
  size_t Size;
  size_t Offset = 0;
};

inline bool ParseSyncObjects(const void *Data, size_t Size, SyncEntries &Entries) {
  Reader Input(Data, Size);
  ULONG Count = 0;
  if (!Input.Read(Count) || Count > Input.Remaining() / 8) return false;
  SyncEntries Parsed;
  for (ULONG Index = 0; Index < Count; ++Index) {
    ULONG Directory = 0;
    USHORT NameBytes = 0, TypeBytes = 0;
    QString Name, Type;
    if (!Input.Read(Directory) || !Input.Read(NameBytes) ||
        !Input.ReadString(NameBytes, Name) || !Input.Read(TypeBytes) ||
        !Input.ReadString(TypeBytes, Type) || !Input.Align4()) return false;
    Parsed.emplace_back(std::move(Name), std::move(Type), Directory);
  }
  Entries = std::move(Parsed);
  return true;
}

inline bool ParseProcessSessions(const void *Data, size_t Size,
                                 SessionEntries &Entries) {
  Reader Input(Data, Size);
  ULONG Count = 0;
  if (!Input.Read(Count) || Count > Input.Remaining() / SessionRecordBytes)
    return false;
  SessionEntries Parsed;
  for (ULONG Index = 0; Index < Count; ++Index) {
    ULONG Id = 0, State = 0, Processes = 0;
    QString Name;
    if (!Input.Read(Id) || !Input.Read(State) || !Input.Read(Processes) ||
        !Input.ReadString(64, Name)) return false;
    const auto Terminator = Name.indexOf(QChar(0));
    if (Terminator >= 0) Name.truncate(Terminator);
    // A process snapshot cannot supply a WTS connection state. Older drivers
    // guessed it from the session ID; do not present that guess as live state.
    Parsed.emplace_back(Id, (std::numeric_limits<ULONG>::max)(), Processes,
                        std::move(Name));
  }
  Entries = std::move(Parsed);
  return true;
}

inline void DeduplicateSyncObjects(SyncEntries &Entries) {
  std::sort(Entries.begin(), Entries.end());
  Entries.erase(std::unique(Entries.begin(), Entries.end()), Entries.end());
}
} // namespace KernelInspectorData
