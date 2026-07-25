#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <stdio.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <algorithm>

using std::min;

struct ToolLdrDataTableEntry {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
};

struct ToolPeb {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE BitField;
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PVOID Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
};

struct ToolUnicodeString32 {
    USHORT Length;
    USHORT MaximumLength;
    ULONG Buffer;
};

struct ToolListEntry32 {
    ULONG Flink;
    ULONG Blink;
};

struct ToolPeb32 {
    BYTE BeingDebuggedReserved[2];
    BYTE BeingDebugged;
    BYTE BitField;
    ULONG Mutant;
    ULONG ImageBaseAddress;
    ULONG Ldr;
    ULONG ProcessParameters;
};

struct ToolPebLdrData32 {
    ULONG Length;
    BOOLEAN Initialized;
    BYTE Reserved1[3];
    ULONG SsHandle;
    ToolListEntry32 InLoadOrderModuleList;
    ToolListEntry32 InMemoryOrderModuleList;
    ToolListEntry32 InInitializationOrderModuleList;
};

struct ToolLdrDataTableEntry32 {
    ToolListEntry32 InLoadOrderLinks;
    ToolListEntry32 InMemoryOrderLinks;
    ToolListEntry32 InInitializationOrderLinks;
    ULONG DllBase;
    ULONG EntryPoint;
    ULONG SizeOfImage;
    ToolUnicodeString32 FullDllName;
    ToolUnicodeString32 BaseDllName;
};

struct ToolPebLdrData {
    ULONG Length;
    BOOLEAN Initialized;
    BYTE Reserved1[3];
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
};

struct ToolCurDir {
    UNICODE_STRING DosPath;
    HANDLE Handle;
};

struct ToolProcessParameters {
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;
    ToolCurDir CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;
};

#pragma pack(push, 4)
struct ToolCurDir32 {
    ToolUnicodeString32 DosPath;
    ULONG Handle;
};

struct ToolProcessParameters32 {
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    ULONG ConsoleHandle;
    ULONG ConsoleFlags;
    ULONG StandardInput;
    ULONG StandardOutput;
    ULONG StandardError;
    ToolCurDir32 CurrentDirectory;
    ToolUnicodeString32 DllPath;
    ToolUnicodeString32 ImagePathName;
    ToolUnicodeString32 CommandLine;
    ULONG Environment;
};
#pragma pack(pop)

#pragma comment(lib, "ntdll.lib")

typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

struct ToolModuleInfo {
    std::string Name;
    std::string FullPath;
    uintptr_t BaseAddress = 0;
    DWORD SizeOfImage = 0;
};

class ProcessPeb {
public:
    static BOOL ReadModuleList(DWORD Pid, std::vector<ToolModuleInfo>& Modules) {
        Modules.clear();
        HANDLE Snapshot = CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, Pid);
        if (Snapshot == INVALID_HANDLE_VALUE) return FALSE;

        auto WideToUtf8 = [](const wchar_t* Text) {
            if (!Text || !*Text) return std::string{};
            const int Size = WideCharToMultiByte(CP_UTF8, 0, Text, -1,
                nullptr, 0, nullptr, nullptr);
            std::string Result(Size > 0 ? static_cast<size_t>(Size) : 0, '\0');
            if (Size > 0) WideCharToMultiByte(CP_UTF8, 0, Text, -1,
                Result.data(), Size, nullptr, nullptr);
            while (!Result.empty() && Result.back() == '\0') Result.pop_back();
            return Result;
        };

        MODULEENTRY32W Entry{};
        Entry.dwSize = sizeof(Entry);
        if (!Module32FirstW(Snapshot, &Entry)) {
            const DWORD Error = GetLastError();
            CloseHandle(Snapshot);
            SetLastError(Error);
            return FALSE;
        }
        do {
            ToolModuleInfo Module;
            Module.Name = WideToUtf8(Entry.szModule);
            Module.FullPath = WideToUtf8(Entry.szExePath);
            Module.BaseAddress = reinterpret_cast<uintptr_t>(Entry.modBaseAddr);
            Module.SizeOfImage = Entry.modBaseSize;
            Modules.push_back(std::move(Module));
        } while (Module32NextW(Snapshot, &Entry));

        CloseHandle(Snapshot);
        return !Modules.empty();
    }

    static BOOL ReadPebInfoText(DWORD Pid, std::string& Output) {
        Output.clear();
        HANDLE HProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, Pid);
        if (!HProcess) return FALSE;
        PROCESS_BASIC_INFORMATION Pbi{};
        HMODULE HNtdll = GetModuleHandleW(L"ntdll.dll");
        auto Query = HNtdll ? reinterpret_cast<pfnNtQueryInformationProcess>(GetProcAddress(HNtdll, "NtQueryInformationProcess")) : nullptr;
        if (!Query || !NT_SUCCESS(Query(HProcess, ProcessBasicInformation, &Pbi, sizeof(Pbi), nullptr))) {
            CloseHandle(HProcess);
            return FALSE;
        }

        ULONG_PTR Wow64PebAddress = 0;
        Query(HProcess, static_cast<PROCESSINFOCLASS>(26),
            &Wow64PebAddress, sizeof(Wow64PebAddress), nullptr);
        if (Wow64PebAddress != 0) {
            ToolPeb32 Peb32{};
            if (!ReadProcessMemory(HProcess, reinterpret_cast<LPCVOID>(Wow64PebAddress),
                &Peb32, sizeof(Peb32), nullptr)) {
                CloseHandle(HProcess);
                return FALSE;
            }
            auto ReadUnicode32 = [&](const ToolUnicodeString32& Value) {
                if (Value.Buffer == 0 || Value.Length == 0 ||
                    (Value.Length % sizeof(WCHAR)) != 0) return std::wstring{};
                std::wstring Text(Value.Length / sizeof(WCHAR), L'\0');
                SIZE_T Read = 0;
                if (!ReadProcessMemory(HProcess,
                    reinterpret_cast<LPCVOID>(static_cast<ULONG_PTR>(Value.Buffer)),
                    Text.data(), Value.Length, &Read) || Read != Value.Length)
                    return std::wstring{};
                return Text;
            };
            auto WideToUtf8 = [](const std::wstring& Text) {
                if (Text.empty()) return std::string{};
                const int Size = WideCharToMultiByte(CP_UTF8, 0, Text.data(),
                    static_cast<int>(Text.size()), nullptr, 0, nullptr, nullptr);
                std::string Result(Size > 0 ? static_cast<size_t>(Size) : 0, '\0');
                if (Size > 0) WideCharToMultiByte(CP_UTF8, 0, Text.data(),
                    static_cast<int>(Text.size()), Result.data(), Size, nullptr, nullptr);
                return Result;
            };

            DWORD SessionId = 0;
            ProcessIdToSessionId(Pid, &SessionId);
            std::ostringstream Stream;
            Stream << "PEB / Process Information\n"
                   << "=========================\n"
                   << "PID: " << Pid << "\n"
                   << "Parent PID: " << reinterpret_cast<ULONG_PTR>(Pbi.Reserved3) << "\n"
                   << "Session ID: " << SessionId << "\n"
                   << "Architecture: x86 (WOW64)\n\n"
                   << "Native PEB Address: " << Pbi.PebBaseAddress << "\n"
                   << "WOW64 PEB Address: 0x" << std::hex << Wow64PebAddress << std::dec << "\n"
                   << "ImageBaseAddress: 0x" << std::hex << Peb32.ImageBaseAddress << std::dec << "\n"
                   << "Ldr: 0x" << std::hex << Peb32.Ldr << std::dec << "\n"
                   << "ProcessParameters: 0x" << std::hex << Peb32.ProcessParameters << std::dec << "\n"
                   << "BeingDebugged: " << (Peb32.BeingDebugged ? "Yes" : "No") << "\n"
                   << "BitField: 0x" << std::hex << static_cast<unsigned>(Peb32.BitField) << std::dec << "\n"
                   << "  ImageUsesLargePages: " << ((Peb32.BitField & 0x01) ? "Yes" : "No") << "\n"
                   << "  IsProtectedProcess: " << ((Peb32.BitField & 0x02) ? "Yes" : "No") << "\n"
                   << "  IsImageDynamicallyRelocated: " << ((Peb32.BitField & 0x04) ? "Yes" : "No") << "\n"
                   << "  IsPackagedProcess: " << ((Peb32.BitField & 0x10) ? "Yes" : "No") << "\n"
                   << "  IsAppContainer: " << ((Peb32.BitField & 0x20) ? "Yes" : "No") << "\n"
                   << "  IsProtectedProcessLight: " << ((Peb32.BitField & 0x40) ? "Yes" : "No") << "\n"
                   << "  IsLongPathAware: " << ((Peb32.BitField & 0x80) ? "Yes" : "No") << "\n";

            ToolProcessParameters32 Params32{};
            if (Peb32.ProcessParameters != 0 && ReadProcessMemory(HProcess,
                reinterpret_cast<LPCVOID>(static_cast<ULONG_PTR>(Peb32.ProcessParameters)),
                &Params32, sizeof(Params32), nullptr)) {
                Stream << "\nProcess Parameters (32-bit)\n"
                       << "---------------------------\n"
                       << "Length: " << Params32.Length << " / " << Params32.MaximumLength << " bytes\n"
                       << "Flags: 0x" << std::hex << Params32.Flags << std::dec << "\n"
                       << "ConsoleHandle: 0x" << std::hex << Params32.ConsoleHandle << std::dec << "\n"
                       << "StandardInput: 0x" << std::hex << Params32.StandardInput << std::dec << "\n"
                       << "StandardOutput: 0x" << std::hex << Params32.StandardOutput << std::dec << "\n"
                       << "StandardError: 0x" << std::hex << Params32.StandardError << std::dec << "\n"
                       << "Environment: 0x" << std::hex << Params32.Environment << std::dec << "\n"
                       << "ImagePath: " << WideToUtf8(ReadUnicode32(Params32.ImagePathName)) << "\n"
                       << "CommandLine: " << WideToUtf8(ReadUnicode32(Params32.CommandLine)) << "\n"
                       << "CurrentDirectory: " << WideToUtf8(ReadUnicode32(Params32.CurrentDirectory.DosPath)) << "\n"
                       << "DllPath: " << WideToUtf8(ReadUnicode32(Params32.DllPath)) << "\n";
            } else {
                Stream << "\n32-bit Process Parameters: unavailable (Error " << GetLastError() << ")\n";
            }
            CloseHandle(HProcess);
            Output = Stream.str();
            return TRUE;
        }
        ToolPeb Peb{};
        if (!ReadProcessMemory(HProcess, Pbi.PebBaseAddress, &Peb, sizeof(Peb), nullptr)) {
            CloseHandle(HProcess);
            return FALSE;
        }
        auto WideToUtf8 = [](const std::wstring& Text) {
            if (Text.empty()) return std::string{};
            const int Size = WideCharToMultiByte(CP_UTF8, 0, Text.data(),
                static_cast<int>(Text.size()), nullptr, 0, nullptr, nullptr);
            std::string Result(Size > 0 ? static_cast<size_t>(Size) : 0, '\0');
            if (Size > 0) WideCharToMultiByte(CP_UTF8, 0, Text.data(),
                static_cast<int>(Text.size()), Result.data(), Size, nullptr, nullptr);
            return Result;
        };
        auto ReadUnicode = [&](const UNICODE_STRING& Value) {
            if (!Value.Buffer || Value.Length == 0 || (Value.Length % sizeof(WCHAR)) != 0)
                return std::wstring{};
            std::wstring Text(Value.Length / sizeof(WCHAR), L'\0');
            SIZE_T Read = 0;
            if (!ReadProcessMemory(HProcess, Value.Buffer, Text.data(), Value.Length, &Read) ||
                Read != Value.Length) return std::wstring{};
            return Text;
        };

        DWORD SessionId = 0;
        ProcessIdToSessionId(Pid, &SessionId);
        USHORT ProcessMachine = IMAGE_FILE_MACHINE_UNKNOWN;
        USHORT NativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
        IsWow64Process2(HProcess, &ProcessMachine, &NativeMachine);
        const char* Architecture = ProcessMachine == IMAGE_FILE_MACHINE_I386 ? "x86 (WOW64)" :
            NativeMachine == IMAGE_FILE_MACHINE_AMD64 ? "x64" :
            NativeMachine == IMAGE_FILE_MACHINE_ARM64 ? "ARM64" : "Unknown";

        FILETIME CreateTime{}, ExitTime{}, KernelTime{}, UserTime{};
        GetProcessTimes(HProcess, &CreateTime, &ExitTime, &KernelTime, &UserTime);
        ULARGE_INTEGER Kernel{}, User{};
        Kernel.LowPart = KernelTime.dwLowDateTime; Kernel.HighPart = KernelTime.dwHighDateTime;
        User.LowPart = UserTime.dwLowDateTime; User.HighPart = UserTime.dwHighDateTime;

        std::ostringstream Stream;
        Stream << "PEB / Process Information\n"
               << "=========================\n"
               << "PID: " << Pid << "\n"
               << "Parent PID: " << reinterpret_cast<ULONG_PTR>(Pbi.Reserved3) << "\n"
               << "Session ID: " << SessionId << "\n"
               << "Architecture: " << Architecture << "\n"
               << "Priority Class: 0x" << std::hex << GetPriorityClass(HProcess) << std::dec << "\n"
               << "Kernel Time: " << (Kernel.QuadPart / 10000) << " ms\n"
               << "User Time: " << (User.QuadPart / 10000) << " ms\n\n"
               << "PEB Address: " << Pbi.PebBaseAddress << "\n"
               << "ImageBaseAddress: " << Peb.ImageBaseAddress << "\n"
               << "Ldr: " << Peb.Ldr << "\n"
               << "ProcessParameters: " << Peb.ProcessParameters << "\n"
               << "BeingDebugged: " << (Peb.BeingDebugged ? "Yes" : "No") << "\n"
               << "BitField: 0x" << std::hex << static_cast<unsigned int>(Peb.BitField) << std::dec << "\n"
               << "  ImageUsesLargePages: " << ((Peb.BitField & 0x01) ? "Yes" : "No") << "\n"
               << "  IsProtectedProcess: " << ((Peb.BitField & 0x02) ? "Yes" : "No") << "\n"
               << "  IsImageDynamicallyRelocated: " << ((Peb.BitField & 0x04) ? "Yes" : "No") << "\n"
               << "  SkipPatchingUser32Forwarders: " << ((Peb.BitField & 0x08) ? "Yes" : "No") << "\n"
               << "  IsPackagedProcess: " << ((Peb.BitField & 0x10) ? "Yes" : "No") << "\n"
               << "  IsAppContainer: " << ((Peb.BitField & 0x20) ? "Yes" : "No") << "\n"
               << "  IsProtectedProcessLight: " << ((Peb.BitField & 0x40) ? "Yes" : "No") << "\n"
               << "  IsLongPathAware: " << ((Peb.BitField & 0x80) ? "Yes" : "No") << "\n";

        ToolProcessParameters Params{};
        if (Peb.ProcessParameters && ReadProcessMemory(HProcess, Peb.ProcessParameters, &Params, sizeof(Params), nullptr)) {
            const std::wstring CommandLine = ReadUnicode(Params.CommandLine);
            const std::wstring ImagePath = ReadUnicode(Params.ImagePathName);
            const std::wstring CurrentDirectory = ReadUnicode(Params.CurrentDirectory.DosPath);
            const std::wstring DllPath = ReadUnicode(Params.DllPath);
            Stream << "\nProcess Parameters\n"
                   << "------------------\n"
                   << "Length: " << Params.Length << " / " << Params.MaximumLength << " bytes\n"
                   << "Flags: 0x" << std::hex << Params.Flags << std::dec << "\n"
                   << "ConsoleHandle: " << Params.ConsoleHandle << "\n"
                   << "StandardInput: " << Params.StandardInput << "\n"
                   << "StandardOutput: " << Params.StandardOutput << "\n"
                   << "StandardError: " << Params.StandardError << "\n"
                   << "Environment: " << Params.Environment << "\n"
                   << "ImagePath: " << WideToUtf8(ImagePath) << "\n"
                   << "CommandLine: " << WideToUtf8(CommandLine) << "\n"
                   << "CurrentDirectory: " << WideToUtf8(CurrentDirectory) << "\n"
                   << "DllPath: " << WideToUtf8(DllPath) << "\n";
        } else {
            Stream << "\nProcess Parameters: unavailable (Error " << GetLastError() << ")\n";
        }
        CloseHandle(HProcess);
        Output = Stream.str();
        return TRUE;
    }

    static BOOL ReadModuleListText(DWORD Pid, std::string& Output) {
        Output.clear();
        HANDLE HProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, Pid);
        if (!HProcess) return FALSE;
        PROCESS_BASIC_INFORMATION Pbi{};
        HMODULE HNtdll = GetModuleHandleW(L"ntdll.dll");
        auto Query = HNtdll ? reinterpret_cast<pfnNtQueryInformationProcess>(GetProcAddress(HNtdll, "NtQueryInformationProcess")) : nullptr;
        ULONG_PTR Wow64PebAddress = 0;
        if (Query) Query(HProcess, static_cast<PROCESSINFOCLASS>(26),
            &Wow64PebAddress, sizeof(Wow64PebAddress), nullptr);
        if (Query && Wow64PebAddress != 0) {
            ToolPeb32 Peb32{};
            ToolPebLdrData32 Ldr32{};
            if (!ReadProcessMemory(HProcess, reinterpret_cast<LPCVOID>(Wow64PebAddress),
                    &Peb32, sizeof(Peb32), nullptr) || Peb32.Ldr == 0 ||
                !ReadProcessMemory(HProcess,
                    reinterpret_cast<LPCVOID>(static_cast<ULONG_PTR>(Peb32.Ldr)),
                    &Ldr32, sizeof(Ldr32), nullptr)) {
                CloseHandle(HProcess);
                return FALSE;
            }
            auto ReadUnicode32 = [&](const ToolUnicodeString32& Value) {
                if (Value.Buffer == 0 || Value.Length == 0 ||
                    (Value.Length % sizeof(WCHAR)) != 0) return std::wstring{};
                std::wstring Text(Value.Length / sizeof(WCHAR), L'\0');
                SIZE_T Read = 0;
                if (!ReadProcessMemory(HProcess,
                    reinterpret_cast<LPCVOID>(static_cast<ULONG_PTR>(Value.Buffer)),
                    Text.data(), Value.Length, &Read) || Read != Value.Length)
                    return std::wstring{};
                return Text;
            };
            auto WideToUtf8 = [](const std::wstring& Text) {
                if (Text.empty()) return std::string{};
                const int Size = WideCharToMultiByte(CP_UTF8, 0, Text.data(),
                    static_cast<int>(Text.size()), nullptr, 0, nullptr, nullptr);
                std::string Result(Size > 0 ? static_cast<size_t>(Size) : 0, '\0');
                if (Size > 0) WideCharToMultiByte(CP_UTF8, 0, Text.data(),
                    static_cast<int>(Text.size()), Result.data(), Size, nullptr, nullptr);
                return Result;
            };
            std::ostringstream Stream;
            Stream << "ModuleList (PID=" << Pid << ", WOW64/x86)\n"
                   << "==================================\n";
            const ULONG RemoteHead = Peb32.Ldr +
                static_cast<ULONG>(offsetof(ToolPebLdrData32, InLoadOrderModuleList));
            ULONG Current = Ldr32.InLoadOrderModuleList.Flink;
            int Count = 0;
            while (Current != 0 && Current != RemoteHead && Count < 4096) {
                ToolLdrDataTableEntry32 Entry{};
                SIZE_T Read = 0;
                if (!ReadProcessMemory(HProcess,
                    reinterpret_cast<LPCVOID>(static_cast<ULONG_PTR>(Current)),
                    &Entry, sizeof(Entry), &Read) || Read != sizeof(Entry)) {
                    Stream << "Traversal stopped at 0x" << std::hex << Current << std::dec
                           << " (Error " << GetLastError() << ")\n";
                    break;
                }
                const std::string Name = WideToUtf8(ReadUnicode32(Entry.BaseDllName));
                const std::string FullPath = WideToUtf8(ReadUnicode32(Entry.FullDllName));
                Stream << "[" << Count << "] " << (Name.empty() ? "(unnamed)" : Name) << "\n"
                       << "  Full Path: " << (FullPath.empty() ? "(unavailable)" : FullPath) << "\n"
                       << "  Base: 0x" << std::hex << Entry.DllBase << "\n"
                       << "  Entry Point: 0x" << Entry.EntryPoint << "\n"
                       << "  Size: 0x" << Entry.SizeOfImage << std::dec
                       << " (" << Entry.SizeOfImage << " bytes)\n\n";
                Current = Entry.InLoadOrderLinks.Flink;
                ++Count;
            }
            Stream << "Total Modules: " << Count << "\n";
            CloseHandle(HProcess);
            Output = Stream.str();
            return TRUE;
        }
        ToolPeb Peb{};
        if (!Query || !NT_SUCCESS(Query(HProcess, ProcessBasicInformation, &Pbi, sizeof(Pbi), nullptr)) ||
            !ReadProcessMemory(HProcess, Pbi.PebBaseAddress, &Peb, sizeof(Peb), nullptr) || !Peb.Ldr) {
            CloseHandle(HProcess);
            return FALSE;
        }
        ToolPebLdrData Ldr{};
        if (!ReadProcessMemory(HProcess, Peb.Ldr, &Ldr, sizeof(Ldr), nullptr)) {
            CloseHandle(HProcess);
            return FALSE;
        }
        std::ostringstream Stream;
        Stream << "ModuleList (PID=" << Pid << ")\n"
               << "========================\n";
        const auto RemoteHead = reinterpret_cast<LIST_ENTRY*>(
            reinterpret_cast<BYTE*>(Peb.Ldr) + offsetof(ToolPebLdrData, InLoadOrderModuleList));
        LIST_ENTRY* Current = Ldr.InLoadOrderModuleList.Flink;
        int Count = 0;
        auto ReadRemoteUnicode = [&](const UNICODE_STRING& Value) {
            if (!Value.Buffer || Value.Length == 0 || (Value.Length % sizeof(WCHAR)) != 0)
                return std::wstring{};
            std::wstring Text(Value.Length / sizeof(WCHAR), L'\0');
            SIZE_T Read = 0;
            if (!ReadProcessMemory(HProcess, Value.Buffer, Text.data(), Value.Length, &Read) ||
                Read != Value.Length) return std::wstring{};
            return Text;
        };
        auto WideToUtf8 = [](const std::wstring& Text) {
            if (Text.empty()) return std::string{};
            const int Size = WideCharToMultiByte(CP_UTF8, 0, Text.data(),
                static_cast<int>(Text.size()), nullptr, 0, nullptr, nullptr);
            std::string Result(Size > 0 ? static_cast<size_t>(Size) : 0, '\0');
            if (Size > 0) WideCharToMultiByte(CP_UTF8, 0, Text.data(),
                static_cast<int>(Text.size()), Result.data(), Size, nullptr, nullptr);
            return Result;
        };
        while (Current && Current != RemoteHead && Count < 4096) {
            ToolLdrDataTableEntry Entry{};
            SIZE_T BytesRead = 0;
            if (!ReadProcessMemory(HProcess, Current, &Entry, sizeof(Entry), &BytesRead) ||
                BytesRead != sizeof(Entry)) {
                Stream << "\nTraversal stopped at " << Current
                       << " (Error " << GetLastError() << ")\n";
                break;
            }
            const std::string Name = WideToUtf8(ReadRemoteUnicode(Entry.BaseDllName));
            const std::string FullPath = WideToUtf8(ReadRemoteUnicode(Entry.FullDllName));
            Stream << "[" << Count << "] " << (Name.empty() ? "(unnamed)" : Name) << "\n"
                   << "  Full Path: " << (FullPath.empty() ? "(unavailable)" : FullPath) << "\n"
                   << "  Base: " << Entry.DllBase << "\n"
                   << "  Entry Point: " << Entry.EntryPoint << "\n"
                   << "  Size: 0x" << std::hex << Entry.SizeOfImage << std::dec
                   << " (" << Entry.SizeOfImage << " bytes)\n\n";
            Current = Entry.InLoadOrderLinks.Flink;
            ++Count;
        }
        if (Count == 0) {
            Stream << "PEB loader list returned no entries; using Toolhelp fallback.\n\n";
            HANDLE Snapshot = CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, Pid);
            if (Snapshot != INVALID_HANDLE_VALUE) {
                MODULEENTRY32W Module{};
                Module.dwSize = sizeof(Module);
                if (Module32FirstW(Snapshot, &Module)) {
                    do {
                        const std::string Name = WideToUtf8(Module.szModule);
                        const std::string FullPath = WideToUtf8(Module.szExePath);
                        Stream << "[" << Count << "] " << (Name.empty() ? "(unnamed)" : Name) << "\n"
                               << "  Full Path: " << (FullPath.empty() ? "(unavailable)" : FullPath) << "\n"
                               << "  Base: " << static_cast<void*>(Module.modBaseAddr) << "\n"
                               << "  Size: 0x" << std::hex << Module.modBaseSize << std::dec
                               << " (" << Module.modBaseSize << " bytes)\n\n";
                        ++Count;
                    } while (Module32NextW(Snapshot, &Module) && Count < 4096);
                } else {
                    Stream << "Toolhelp Module32First failed (Error " << GetLastError() << ")\n";
                }
                CloseHandle(Snapshot);
            } else {
                Stream << "CreateToolhelp32Snapshot failed (Error " << GetLastError() << ")\n";
            }
        }
        Stream << "Total Modules: " << Count << "\n";
        CloseHandle(HProcess);
        Output = Stream.str();
        return TRUE;
    }

    static PEB* GetPebAddress(DWORD Pid) {
        HMODULE HNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!HNtdll) return nullptr;

        auto NtQueryInformationProcess =
            (pfnNtQueryInformationProcess)GetProcAddress(HNtdll, "NtQueryInformationProcess");
        if (!NtQueryInformationProcess) return nullptr;

        HANDLE HProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE, Pid);
        if (!HProcess) return nullptr;

        PROCESS_BASIC_INFORMATION Pbi{};
        NTSTATUS Status = NtQueryInformationProcess(HProcess, ProcessBasicInformation,
            &Pbi, sizeof(Pbi), nullptr);
        CloseHandle(HProcess);

        return NT_SUCCESS(Status) ? Pbi.PebBaseAddress : nullptr;
    }

    static BOOL ReadBeingDebugged(DWORD Pid) {
        HANDLE HProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE, Pid);
        if (!HProcess) return FALSE;

        PROCESS_BASIC_INFORMATION Pbi{};
        HMODULE HNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!HNtdll) { CloseHandle(HProcess); return FALSE; }
        auto NtQueryInformationProcess =
            (pfnNtQueryInformationProcess)GetProcAddress(HNtdll, "NtQueryInformationProcess");
        if (!NtQueryInformationProcess) { CloseHandle(HProcess); return FALSE; }
        if (!NT_SUCCESS(NtQueryInformationProcess(HProcess, ProcessBasicInformation,
            &Pbi, sizeof(Pbi), nullptr))) {
            CloseHandle(HProcess);
            return FALSE;
        }

        BYTE BeingDebugged = 0;
        ReadProcessMemory(HProcess, &Pbi.PebBaseAddress->BeingDebugged,
            &BeingDebugged, sizeof(BeingDebugged), nullptr);
        CloseHandle(HProcess);
        return BeingDebugged != 0;
    }

    static BOOL ReadProcessParameters(DWORD Pid,
        RTL_USER_PROCESS_PARAMETERS& Params) {
        ZeroMemory(&Params, sizeof(Params));
        HANDLE HProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE, Pid);
        if (!HProcess) return FALSE;
        BOOL Result = ReadProcessParameters(HProcess, Params);
        CloseHandle(HProcess);
        return Result;
    }

    static BOOL ReadProcessParameters(HANDLE HProcess,
        RTL_USER_PROCESS_PARAMETERS& Params) {
        PROCESS_BASIC_INFORMATION Pbi{};
        HMODULE HNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!HNtdll) return FALSE;
        auto NtQueryInformationProcess =
            (pfnNtQueryInformationProcess)GetProcAddress(HNtdll, "NtQueryInformationProcess");
        if (!NtQueryInformationProcess) return FALSE;
        if (!NT_SUCCESS(NtQueryInformationProcess(HProcess, ProcessBasicInformation,
            &Pbi, sizeof(Pbi), nullptr)))
            return FALSE;

        ToolPeb Peb{};
        if (!ReadProcessMemory(HProcess, Pbi.PebBaseAddress, &Peb, sizeof(Peb), nullptr))
            return FALSE;

        return ReadProcessMemory(HProcess, Peb.ProcessParameters,
            &Params, sizeof(Params), nullptr) != FALSE;
    }

    static BOOL ReadCommandLine(DWORD Pid, WCHAR* Buffer, DWORD BufferSize) {
        if (!Buffer || BufferSize < 2) return FALSE;
        Buffer[0] = L'\0';

        RTL_USER_PROCESS_PARAMETERS Params{};
        if (!ReadProcessParameters(Pid, Params)) return FALSE;

        HANDLE HProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE, Pid);
        if (!HProcess) return FALSE;

        SIZE_T ReadSize = min(Params.CommandLine.Length, (USHORT)(BufferSize - 2));
        BOOL Result = ReadProcessMemory(HProcess, Params.CommandLine.Buffer,
            Buffer, ReadSize, nullptr);
        if (Result) Buffer[ReadSize / sizeof(WCHAR)] = L'\0';
        CloseHandle(HProcess);
        return Result;
    }

    static BOOL ReadImagePath(DWORD Pid, WCHAR* Buffer, DWORD BufferSize) {
        if (!Buffer || BufferSize < 2) return FALSE;
        Buffer[0] = L'\0';

        RTL_USER_PROCESS_PARAMETERS Params{};
        if (!ReadProcessParameters(Pid, Params)) return FALSE;

        HANDLE HProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE, Pid);
        if (!HProcess) return FALSE;

        SIZE_T ReadSize = min(Params.ImagePathName.Length, (USHORT)(BufferSize - 2));
        BOOL Result = ReadProcessMemory(HProcess, Params.ImagePathName.Buffer,
            Buffer, ReadSize, nullptr);
        if (Result) Buffer[ReadSize / sizeof(WCHAR)] = L'\0';
        CloseHandle(HProcess);
        return Result;
    }

    static BOOL PrintPebInfo(DWORD Pid) {
        HANDLE HProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE, Pid);
        if (!HProcess) return FALSE;

        
        PROCESS_BASIC_INFORMATION Pbi{};
        HMODULE HNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!HNtdll) { CloseHandle(HProcess); return FALSE; }
        auto NtQueryInformationProcess =
            (pfnNtQueryInformationProcess)GetProcAddress(HNtdll, "NtQueryInformationProcess");
        if (!NtQueryInformationProcess) { CloseHandle(HProcess); return FALSE; }
        if (!NT_SUCCESS(NtQueryInformationProcess(HProcess, ProcessBasicInformation,
            &Pbi, sizeof(Pbi), nullptr))) {
            CloseHandle(HProcess);
            return FALSE;
        }

        
        ToolPeb Peb{};
        if (!ReadProcessMemory(HProcess, Pbi.PebBaseAddress, &Peb, sizeof(Peb), nullptr)) {
            CloseHandle(HProcess);
            return FALSE;
        }

        printf("=== PEB (PID=%u) ===\n", Pid);
        printf("BeingDebugged:      %d\n", Peb.BeingDebugged);
        printf("ImageBaseAddress:   %p\n", Peb.ImageBaseAddress);
        printf("Ldr:                %p\n", Peb.Ldr);
        printf("ProcessParameters:  %p\n", Peb.ProcessParameters);

        
        RTL_USER_PROCESS_PARAMETERS Params{};
        if (ReadProcessMemory(HProcess, Peb.ProcessParameters, &Params, sizeof(Params), nullptr)) {
            WCHAR Buffer[1024];
            SIZE_T ReadSize;

            
            ReadSize = min(Params.CommandLine.Length, (USHORT)(sizeof(Buffer) - 2));
            if (ReadProcessMemory(HProcess, Params.CommandLine.Buffer, Buffer, ReadSize, nullptr)) {
                Buffer[ReadSize / sizeof(WCHAR)] = L'\0';
                printf("CommandLine:        %ws\n", Buffer);
            }

            
            ReadSize = min(Params.ImagePathName.Length, (USHORT)(sizeof(Buffer) - 2));
            if (ReadProcessMemory(HProcess, Params.ImagePathName.Buffer, Buffer, ReadSize, nullptr)) {
                Buffer[ReadSize / sizeof(WCHAR)] = L'\0';
                printf("ImagePath:          %ws\n", Buffer);
            }
        }

        
        ToolPebLdrData Ldr{};
        if (ReadProcessMemory(HProcess, Peb.Ldr, &Ldr, sizeof(Ldr), nullptr)) {
            printf("\n--- Loaded Modules ---\n");

            LIST_ENTRY* Head = &Ldr.InLoadOrderModuleList;
            LIST_ENTRY* Current = Head->Flink;

            while (Current != Head) {
                ToolLdrDataTableEntry Entry{};
                if (!ReadProcessMemory(HProcess, Current, &Entry, sizeof(Entry), nullptr))
                    break;

                WCHAR DllName[256] = { 0 };
                if (Entry.DllBase && Entry.BaseDllName.Buffer) {
                    SIZE_T NameSize = min(Entry.BaseDllName.Length, (USHORT)(sizeof(DllName) - 2));
                    ReadProcessMemory(HProcess, Entry.BaseDllName.Buffer, DllName, NameSize, nullptr);
                    DllName[NameSize / sizeof(WCHAR)] = L'\0';
                }

                printf("  %-30ws base=%p size=0x%X\n",
                    DllName[0] ? DllName : L"(unknown)",
                    Entry.DllBase, Entry.SizeOfImage);

                Current = Entry.InLoadOrderLinks.Flink;
            }
        }

        CloseHandle(HProcess);
        return TRUE;
    }
};
