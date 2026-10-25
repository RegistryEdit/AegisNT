#include "../Source/Services/DriverServiceEnumImpl.h"
#include "../Platform/AegisCoreCall.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

static unsigned Checks = 0;
static void Check(bool Passed, const char *Message) {
    ++Checks;
    if (!Passed) { std::fprintf(stderr, "FAIL: %s\n", Message); std::exit(1); }
}

static void TestEnumerationParsers() {
    using namespace AegisNT;
    using namespace AegisNT::DriverServiceEnum;

    PROCESS_ENUM_OUTPUT Processes = {};
    Processes.Count = 1;
    Processes.Entries[0].ProcessId = 23;
    Processes.Entries[0].ParentPid = 4;
    Processes.Entries[0].ThreadCount = 7;
    Processes.Entries[0].IsCritical = TRUE;
    wcscpy_s(Processes.Entries[0].ImageName, L"worker.exe");
    const size_t ProcessBytes = offsetof(PROCESS_ENUM_OUTPUT, Entries) + sizeof(PROCESS_ENUM_ENTRY);
    auto ParsedProcesses = ParseProcesses(&Processes, ProcessBytes);
    Check(ParsedProcesses && ParsedProcesses.Value().size() == 1 &&
          ParsedProcesses.Value()[0].Pid == 23 && ParsedProcesses.Value()[0].Critical,
          "process parser maps ABI fields");
    wmemset(Processes.Entries[0].ImageName, L'x', 16);
    Check(ParseProcesses(&Processes, ProcessBytes).Value()[0].Name == QString(16, 'x'),
          "process parser bounds unterminated name");
    Check(ParseProcesses(&Processes, ProcessBytes - 1).IsError(), "process parser rejects partial record");
    Processes.Count = 2;
    Check(ParseProcesses(&Processes, ProcessBytes).IsError(), "process parser rejects truncated count");
    Processes.Count = 0;
    Check(ParseProcesses(&Processes, offsetof(PROCESS_ENUM_OUTPUT, Entries)),
          "process parser accepts empty list");
    Check(ParseProcesses(&Processes, sizeof(ULONG)).IsSuccess(), "process count-only empty list");
    Check(ParseProcesses(nullptr, ProcessBytes).IsError(), "process null buffer rejected");

    INVENTORY_LIST_OUTPUT Threads = {};
    Threads.Header.Size = sizeof(INVENTORY_LIST_HEADER);
    Threads.Header.Version = INVENTORY_PROTOCOL_VERSION;
    Threads.Header.ReturnedCount = 1;
    Threads.Header.NextCursor = 12;
    Threads.Records[0].Size = sizeof(INVENTORY_RECORD);
    Threads.Records[0].Kind = 2;
    Threads.Records[0].ProcessId = 77;
    Threads.Records[0].ThreadId = 301;
    Threads.Records[0].Address = 0x123456;
    Threads.Records[0].Value[0] = 9;
    Threads.Records[0].Value[2] = 5;
    ULONG64 NextCursor = 0;
    const size_t ThreadBytes = sizeof(INVENTORY_LIST_HEADER) + sizeof(INVENTORY_RECORD);
    auto ParsedThreads = ParseThreadInventoryPage(&Threads, ThreadBytes, 77, 10, &NextCursor);
    Check(ParsedThreads && ParsedThreads.Value().size() == 1 && NextCursor == 12 &&
          ParsedThreads.Value()[0].Tid == 301 && ParsedThreads.Value()[0].Priority == 9,
          "thread parser maps page and advances cursor");
    NextCursor = 99;
    Check(ParseThreadInventoryPage(&Threads, ThreadBytes, 77, 12, &NextCursor).IsError() &&
          NextCursor == 0, "thread parser rejects non-advancing cursor");
    Threads.Records[0].ProcessId = 78;
    Check(ParseThreadInventoryPage(&Threads, ThreadBytes, 77, 10, &NextCursor).IsError(),
          "thread parser rejects mismatched PID");
    Threads.Records[0].ProcessId = 77;
    Threads.Header.NextCursor = 0;
    auto LastPage = ParseThreadInventoryPage(&Threads, ThreadBytes, 77, 12, &NextCursor);
    Check(LastPage && NextCursor == 0 && LastPage.Value()[0].State == 5,
          "thread terminal page resets cursor and maps state");
    for (int Fault = 0; Fault < 6; ++Fault) {
        auto Bad = Threads;
        if (Fault == 0) Bad.Header.Version = 99;
        if (Fault == 1) Bad.Header.ReturnedCount = 257;
        if (Fault == 2) Bad.Records[0].Kind = 99;
        if (Fault == 3) Bad.Records[0].Size = 1;
        if (Fault == 4) Bad.Header.Status = static_cast<LONG>(0xC0000022);
        if (Fault == 5) Bad.Records[0].Status = static_cast<LONG>(0xC0000022);
        NextCursor = 99;
        auto Result = ParseThreadInventoryPage(&Bad, ThreadBytes, 77, 12, &NextCursor);
        Check(Result.IsError() && Result.Value().isEmpty() && NextCursor == 0,
              "invalid thread page publishes neither records nor cursor");
    }
    Check(ParseThreadInventoryPage(&Threads, ThreadBytes - 1, 77, 12, &NextCursor).IsError(),
          "thread partial record rejected");
    Check(ParseThreadInventoryPage(&Threads, ThreadBytes, 77, 12, nullptr).IsError(),
          "thread missing cursor output rejected");

    DRIVER_ENUM_OUTPUT Drivers = {};
    Drivers.Header.NtStatus = 0;
    Drivers.Header.Count = 1;
    Drivers.Entries[0].State = SERVICE_RUNNING;
    Drivers.Entries[0].ImageBase = 0x100000;
    Drivers.Entries[0].ImageSize = 4096;
    wcscpy_s(Drivers.Entries[0].ServiceName, L"Example");
    const size_t DriverBytes = offsetof(DRIVER_ENUM_OUTPUT, Entries) + sizeof(DRIVER_ENUM_ENTRY);
    auto ParsedDrivers = ParseDrivers(&Drivers, DriverBytes);
    Check(ParsedDrivers && ParsedDrivers.Value().size() == 1 &&
          ParsedDrivers.Value()[0].Name == "Example" && ParsedDrivers.Value()[0].Loaded,
          "driver parser maps ABI fields");
    Drivers.Header.NtStatus = static_cast<LONG>(0xC0000022);
    Drivers.Header.Count = 0;
    Check(ParseDrivers(&Drivers, offsetof(DRIVER_ENUM_OUTPUT, Entries)).GetErrorCode() == ERROR_ACCESS_DENIED,
          "driver parser propagates NTSTATUS");
    Drivers.Header.NtStatus = 0;
    Drivers.Header.Count = 1;
    Check(ParseDrivers(&Drivers, offsetof(DRIVER_ENUM_OUTPUT, Entries)).IsError(),
          "driver parser rejects truncated entry");

    CALLBACK_ENUM_OUTPUT Callbacks = {};
    Callbacks.Count = 0;
    Check(ParseCallbacks(&Callbacks, sizeof(ULONG)) &&
          ParseCallbacks(&Callbacks, sizeof(ULONG)).Value().isEmpty(),
          "callback parser accepts count-only empty list");
    Callbacks.Count = 1;
    Check(ParseCallbacks(&Callbacks, sizeof(ULONG)).IsError(),
          "callback parser rejects truncated entry");
    Callbacks.Entries[0].Type = CALLBACK_TYPE_PS_PROCESS_NOTIFY;
    Callbacks.Entries[0].Address = 0x123456;
    wmemset(Callbacks.Entries[0].ModuleName, L'm', 64);
    auto ParsedCallbacks = ParseCallbacks(&Callbacks, sizeof(Callbacks));
    Check(ParsedCallbacks && ParsedCallbacks.Value().size() == 1 &&
          ParsedCallbacks.Value()[0].Module == QString(64, 'm') &&
          ParsedCallbacks.Value()[0].Address == 0x123456 && ParsedCallbacks.Value()[0].Index == 0 &&
          ParsedCallbacks.Value()[0].Type == QString::number(CALLBACK_TYPE_PS_PROCESS_NOTIFY),
          "callback maps fields and bounds unterminated module");
    Check(ParseCallbacks(&Callbacks, sizeof(Callbacks) - 1).IsError(), "callback partial record rejected");

    const size_t WindowHeader = sizeof(ULONG);
    const size_t WindowEntry = sizeof(KERNEL_WINDOW_ENUM_ENTRY);
    const USHORT TitleBytes = static_cast<USHORT>(5 * sizeof(WCHAR));
    const size_t WindowBytes = WindowHeader + WindowEntry + WindowEntry + TitleBytes;
    std::vector<BYTE> WindowBuffer(WindowBytes);
    const ULONG WindowCount = 2;
    std::memcpy(WindowBuffer.data(), &WindowCount, sizeof(WindowCount));
    KERNEL_WINDOW_ENUM_ENTRY EmptyTitle = {};
    EmptyTitle.Hwnd = 0x100;
    std::memcpy(WindowBuffer.data() + WindowHeader, &EmptyTitle, sizeof(EmptyTitle));
    KERNEL_WINDOW_ENUM_ENTRY Titled = {};
    Titled.Hwnd = 0x200;
    Titled.ProcessId = 45;
    Titled.TitleLength = TitleBytes;
    Titled.Flags = WINDOW_FLAG_VISIBLE;
    const size_t TitledOffset = WindowHeader + WindowEntry;
    std::memcpy(WindowBuffer.data() + TitledOffset, &Titled, sizeof(Titled));
    const WCHAR Title[] = L"Title";
    std::memcpy(WindowBuffer.data() + TitledOffset + WindowEntry, Title, TitleBytes);
    auto ParsedWindows = ParseKernelWindows(WindowBuffer.data(), WindowBuffer.size());
    Check(ParsedWindows && ParsedWindows.Value().size() == 2 &&
          ParsedWindows.Value()[0].Title.isEmpty() &&
          ParsedWindows.Value()[1].Title == "Title" && ParsedWindows.Value()[1].Visible,
          "window parser handles empty and variable titles");
    std::vector<BYTE> Unaligned(WindowBuffer.size() + 1);
    std::memcpy(Unaligned.data() + 1, WindowBuffer.data(), WindowBuffer.size());
    auto UnalignedWindows = ParseKernelWindows(Unaligned.data() + 1, WindowBuffer.size());
    Check(UnalignedWindows && UnalignedWindows.Value()[1].Title == "Title",
          "window parser accepts unaligned headers and UTF-16 text");
    Titled.TitleLength = 1;
    std::memcpy(WindowBuffer.data() + TitledOffset, &Titled, sizeof(Titled));
    Check(ParseKernelWindows(WindowBuffer.data(), WindowBuffer.size()).IsError(),
          "window parser rejects odd title length");
    Titled.TitleLength = 4;
    std::memcpy(WindowBuffer.data() + TitledOffset, &Titled, sizeof(Titled));
    auto Truncated = ParseKernelWindows(WindowBuffer.data(), TitledOffset + WindowEntry + sizeof(WCHAR));
    Check(Truncated.IsError() && Truncated.Value().isEmpty(),
          "window parser rejects truncated title");
    Titled.TitleLength = 512;
    std::memcpy(WindowBuffer.data() + TitledOffset, &Titled, sizeof(Titled));
    Check(ParseKernelWindows(WindowBuffer.data(), WindowBuffer.size()).IsError(), "oversized window title rejected");
    ULONG Empty = 0;
    Check(ParseKernelWindows(&Empty, sizeof(Empty)).IsSuccess(), "empty window snapshot accepted");
}

int main() {
    TestEnumerationParsers();
    std::printf("PASS: %u enumeration parser assertions; no live driver used.\n", Checks);
}
