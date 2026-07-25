#include "../../Module/ModuleBase.h"
#include "../../Utils/Color.h"
#include <iostream>
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <iphlpapi.h>
#include <windows.h>
#include <iomanip>
#include <string>
#include <map>
#include <sstream>
#include <vector>
#include <cstring>
#include <csignal>
#include <chrono>
#include <thread>
#include <conio.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

static volatile bool GRunning = true;

std::string MacToString(const BYTE* Mac, UINT Len)
{
    if (Len == 0) return "00:00:00:00:00:00";
    std::ostringstream Oss;
    for (UINT i = 0; i < Len; i++) {
        if (i > 0) Oss << ":";
        Oss << std::uppercase << std::hex
            << std::setw(2) << std::setfill('0') << static_cast<int>(Mac[i]);
    }
    return Oss.str();
}

std::string IpToString(DWORD Addr)
{
    const BYTE* B = reinterpret_cast<const BYTE*>(&Addr);
    std::ostringstream Oss;
    Oss << static_cast<int>(B[0]) << "."
        << static_cast<int>(B[1]) << "."
        << static_cast<int>(B[2]) << "."
        << static_cast<int>(B[3]);
    return Oss.str();
}

std::string GetTimestamp()
{
    auto Now = std::chrono::system_clock::now();
    auto Tt = std::chrono::system_clock::to_time_t(Now);
    std::tm Tm;
    localtime_s(&Tm, &Tt);
    std::ostringstream Oss;
    Oss << std::setfill('0')
        << std::setw(2) << Tm.tm_hour << ":"
        << std::setw(2) << Tm.tm_min << ":"
        << std::setw(2) << Tm.tm_sec;
    return Oss.str();
}

class ArpDefender
{
public:
    ArpDefender(DWORD GatewayIp, bool GatewaySpecified, DWORD IntervalSec)
        : M_GatewayIp(GatewayIp)
        , M_IfIndex(0)
        , M_GatewaySpecified(GatewaySpecified)
        , M_IntervalSec(IntervalSec)
        , M_ScanCount(0)
        , M_AttackCount(0)
    {
    }

    bool Initialize()
    {
        if (M_GatewayIp == 0 || M_GatewayIp == INADDR_NONE) {
            if (!AutoDetectGateway()) {
                std::cerr << "[ERROR] Failed to auto-detect default gateway!\n"
                    << "[HINT]  Use --gateway to specify the gateway IP manually\n";
                return false;
            }
            std::cout << "[*] Auto-detected gateway: " << IpToString(M_GatewayIp)
                << " (interface index: " << M_IfIndex << ")\n";
        }
        else {
            std::cout << "[*] Specified gateway: " << IpToString(M_GatewayIp) << "\n";
        }

        std::string FirstMac;
        DWORD FirstIfIndex = 0;
        if (!ScanArpTable(FirstMac, FirstIfIndex)) {
            std::cerr << "[ERROR] Failed to obtain gateway MAC address!\n"
                << "[HINT]  Check network connectivity and ensure the gateway is reachable\n";
            return false;
        }

        M_TrustedMac = FirstMac;
        if (M_IfIndex == 0) {
            M_IfIndex = FirstIfIndex;
        }
        std::cout << "[*] Gateway MAC: " << M_TrustedMac << " [recorded as trusted]\n";
        return true;
    }

    void Run()
    {
        std::cout << "[*] Scan interval: " << M_IntervalSec << " seconds\n"
            << "[*] Monitoring for ARP spoofing... (press Ctrl+C to exit)\n"
            << std::string(55, '-') << "\n";

        while (GRunning) {
            std::this_thread::sleep_for(
                std::chrono::seconds(M_IntervalSec));

            if (!GRunning) break;

            M_ScanCount++;

            std::string CurrentMac;
            DWORD IfIndex = 0;
            if (!ScanArpTable(CurrentMac, IfIndex)) {
                std::cout << "[" << GetTimestamp() << "] [WARN] Scan #"
                    << M_ScanCount << " failed, skipping\n";
                continue;
            }

            if (CurrentMac.empty()) {
                continue;
            }

            if (IfIndex != 0) {
                M_IfIndex = IfIndex;
            }

            if (CurrentMac != M_TrustedMac) {
                HandleSpoofingDetection(CurrentMac);
            }
        }

        std::cout << "\n[STATS] Total scans: " << M_ScanCount
            << ", attacks detected: " << M_AttackCount << "\n";
    }

private:
    bool AutoDetectGateway()
    {
        ULONG BufLen = sizeof(IP_ADAPTER_INFO);
        std::vector<BYTE> Buffer(BufLen);
        auto* PInfo = reinterpret_cast<PIP_ADAPTER_INFO>(Buffer.data());

        DWORD Ret = GetAdaptersInfo(PInfo, &BufLen);
        if (Ret == ERROR_BUFFER_OVERFLOW) {
            Buffer.resize(BufLen);
            PInfo = reinterpret_cast<PIP_ADAPTER_INFO>(Buffer.data());
            Ret = GetAdaptersInfo(PInfo, &BufLen);
        }
        if (Ret != NO_ERROR) return false;

        for (auto* P = PInfo; P != nullptr; P = P->Next) {
            const char* Gw = P->GatewayList.IpAddress.String;
            if (Gw[0] != '\0' && Gw[0] != '0') {
                M_GatewayIp = inet_addr(Gw);
                M_IfIndex = P->Index;
                return true;
            }
        }
        return false;
    }

    bool ScanArpTable(std::string& OutMac, DWORD& OutIfIndex) const
    {
        OutMac.clear();
        OutIfIndex = 0;

        ULONG BufLen = 0;
        GetIpNetTable(nullptr, &BufLen, FALSE);

        std::vector<BYTE> Buffer(BufLen);
        auto* PTable = reinterpret_cast<PMIB_IPNETTABLE>(Buffer.data());

        if (GetIpNetTable(PTable, &BufLen, FALSE) != NO_ERROR) {
            return false;
        }

        for (DWORD i = 0; i < PTable->dwNumEntries; i++) {
            const MIB_IPNETROW& Row = PTable->table[i];
            if (Row.dwAddr == M_GatewayIp
                && Row.dwPhysAddrLen > 0
                && Row.dwType != MIB_IPNET_TYPE_INVALID) {
                OutMac = MacToString(Row.bPhysAddr, Row.dwPhysAddrLen);
                OutIfIndex = Row.dwIndex;
                return true;
            }
        }

        for (DWORD i = 0; i < PTable->dwNumEntries; i++) {
            const MIB_IPNETROW& Row = PTable->table[i];
            if (Row.dwAddr == M_GatewayIp
                && Row.dwType != MIB_IPNET_TYPE_INVALID) {
                OutMac = MacToString(Row.bPhysAddr, Row.dwPhysAddrLen);
                OutIfIndex = Row.dwIndex;
                return true;
            }
        }

        return true;
    }

    std::string TraceAttackerIp(const std::string& AttackerMac) const
    {
        ULONG BufLen = 0;
        GetIpNetTable(nullptr, &BufLen, FALSE);

        std::vector<BYTE> Buffer(BufLen);
        auto* PTable = reinterpret_cast<PMIB_IPNETTABLE>(Buffer.data());

        if (GetIpNetTable(PTable, &BufLen, FALSE) != NO_ERROR) {
            return "Query failed";
        }

        std::vector<std::string> Candidates;

        for (DWORD i = 0; i < PTable->dwNumEntries; i++) {
            const MIB_IPNETROW& Row = PTable->table[i];
            if (Row.dwAddr == M_GatewayIp) continue;
            if (Row.dwType == MIB_IPNET_TYPE_INVALID) continue;
            if (Row.dwPhysAddrLen == 0) continue;

            std::string Mac = MacToString(Row.bPhysAddr, Row.dwPhysAddrLen);
            if (Mac == AttackerMac) {
                Candidates.push_back(IpToString(Row.dwAddr));
            }
        }

        if (Candidates.empty()) return "Not found (attacker may have spoofed source MAC)";
        if (Candidates.size() == 1) return Candidates[0];

        std::ostringstream Oss;
        for (size_t i = 0; i < Candidates.size(); i++) {
            if (i > 0) Oss << ", ";
            Oss << Candidates[i];
        }
        return Oss.str();
    }

    void HandleSpoofingDetection(const std::string& AttackerMac)
    {
        M_AttackCount++;

        std::string AttackerIp = TraceAttackerIp(AttackerMac);

        std::cout << "\n"
            << std::string(55, '=') << "\n"
            << "[!] [ARP SPOOFING ALERT]  Time: " << GetTimestamp() << "\n"
            << "[!] Scan #: " << M_ScanCount << "\n"
            << "[!] Gateway_IP:    " << IpToString(M_GatewayIp) << "\n"
            << "[!] Trusted MAC:   " << M_TrustedMac << "\n"
            << "[!] Current MAC:   " << AttackerMac << "  <-- ANOMALY!\n"
            << "[!] Attacker MAC:  " << AttackerMac << "\n"
            << "[!] Attacker IP:   " << AttackerIp << "\n"
            << std::string(55, '=') << "\n\n";

        const std::string GatewayIpText = IpToString(M_GatewayIp);
        const std::wstring GatewayIp(GatewayIpText.begin(), GatewayIpText.end());
        const std::wstring TrustedMac(M_TrustedMac.begin(), M_TrustedMac.end());
        const std::wstring CurrentMac(AttackerMac.begin(), AttackerMac.end());
        const std::wstring AttackerIpText(AttackerIp.begin(), AttackerIp.end());

        std::wostringstream Message;
        Message << L"A change in the gateway ARP mapping was detected.\n\n"
            << L"Gateway IP: " << GatewayIp << L"\n"
            << L"Trusted MAC: " << TrustedMac << L"\n"
            << L"Current MAC: " << CurrentMac << L"\n"
            << L"Associated IP: " << AttackerIpText << L"\n\n"
            << L"Do you trust the current MAC address?\n\n"
            << L"Yes: Trust the current MAC address\n"
            << L"No: Repair the ARP table and restore the gateway mapping\n"
            << L"Cancel: Ignore this alert and continue monitoring";

        const int Choice = MessageBoxW(
            nullptr,
            Message.str().c_str(),
            L"Windows Tool - ARP Defence Alert",
            MB_YESNOCANCEL | MB_ICONWARNING | MB_DEFBUTTON3 | MB_TOPMOST | MB_SETFOREGROUND);

        if (Choice == IDYES) {
            M_TrustedMac = AttackerMac;
            std::cout << "[*] " << AttackerMac << " recorded as new trusted MAC\n\n";
        }
        else if (Choice == IDNO) {
            RepairArpTable();
        }
        else {
            std::cout << "[*] Alert ignored, continuing to monitor\n\n";
        }
    }

    void RepairArpTable()
    {
        std::cout << "[+] Repairing ARP table...\n";

        MIB_IPNETROW DelEntry = {};
        DelEntry.dwIndex = M_IfIndex;
        DelEntry.dwAddr = M_GatewayIp;
        DWORD Ret = DeleteIpNetEntry(&DelEntry);
        if (Ret == NO_ERROR) {
            std::cout << "[+] Deleted poisoned ARP entry\n";
        }
        else if (Ret == ERROR_FILE_NOT_FOUND || Ret == ERROR_NOT_FOUND) {
            std::cout << "[*] No ARP entry to delete\n";
        }
        else {
            std::cout << "[WARN] Failed to delete ARP entry (error code: " << Ret << ")\n";
        }

        ULONG MacBuf[2] = { 0 };
        ULONG MacLen = 6;
        Ret = SendARP(M_GatewayIp, 0, MacBuf, &MacLen);
        if (Ret != NO_ERROR) {
            std::cerr << "[ERROR] SendARP failed (error code: " << Ret << ")\n"
                << "[HINT]  Check network connection and retry\n";
            return;
        }

        BYTE* ResolvedMac = reinterpret_cast<BYTE*>(MacBuf);
        std::string ResolvedStr = MacToString(ResolvedMac, MacLen);
        std::cout << "[+] Re-resolved gateway MAC: " << ResolvedStr << "\n";

        MIB_IPNETROW NewEntry = {};
        NewEntry.dwIndex = M_IfIndex;
        NewEntry.dwPhysAddrLen = MacLen;
        memcpy(NewEntry.bPhysAddr, ResolvedMac, MacLen);
        NewEntry.dwAddr = M_GatewayIp;
        NewEntry.dwType = MIB_IPNET_TYPE_STATIC;

        Ret = CreateIpNetEntry(&NewEntry);
        if (Ret == NO_ERROR) {
            std::cout << "[+] Static ARP entry created\n";
        }
        else if (Ret == ERROR_OBJECT_ALREADY_EXISTS) {
            Ret = SetIpNetEntry(&NewEntry);
            if (Ret == NO_ERROR) {
                std::cout << "[+] ARP entry updated to static\n";
            }
            else {
                std::cerr << "[ERROR] Failed to update ARP entry (error code: " << Ret << ")\n";
                return;
            }
        }
        else {
            std::cerr << "[ERROR] Failed to create ARP entry (error code: " << Ret << ")\n";
            return;
        }

        M_TrustedMac = ResolvedStr;
        std::cout << "[OK] ARP table repair complete\n\n";
    }

    DWORD       M_GatewayIp;
    DWORD       M_IfIndex;
    std::string M_TrustedMac;
    bool        M_GatewaySpecified;
    DWORD       M_IntervalSec;
    int         M_ScanCount;
    int         M_AttackCount;
};

class ARPDefenceB : public ModuleBase
{
public:
    ARPDefenceB()
    {
        RegisterOption("Gateway_IP", std::make_unique<OptString>(
            "", OptionRequired::Required,
            "The Gateway_IP (can be none)"));
        RegisterOption("Interval", std::make_unique<OptInt>(
            "", OptionRequired::Required,
            "Scan interval in second"));
    }

    ModuleInfo Info() const override
    {
        ModuleInfo Info;
        Info.Name = "LocalNetwork/ARPDefence";
        Info.Description = "ARPDefence Tool";
        Info.Author = "RegistryEdit";
        Info.License = "DLL_LICENSE";
        Info.Type = ModuleType::Auxiliary;
        Info.Targets = { "Windows 10 x64", "Windows 11 x64" };
        Info.DefaultTarget = "Windows 10 x64";
        Info.Platform = { "Windows" };
        Info.Arch = "x64";
        Info.DisclosureDate = "NULL";
        Info.References = { "NULL", "NULL" };
        Info.Rank = 300;
        return Info;
    }

    bool Check() override
    {
        Color::PrintInfo() << "Checking if the module is compatible with the current system..." << std::endl;
        return true;
    }

    bool Run() override
    {
        SetConsoleOutputCP(CP_UTF8);

        DWORD GatewayIp = 0;
        bool  GatewaySpecified = false;
        if (!GetOption("Gateway_IP").empty()) {
            GatewayIp = inet_addr(GetOption("Gateway_IP").c_str());
            if (GatewayIp == INADDR_NONE) {
                std::cerr << "[ERROR] Invalid IP address: " << GetOption("Gateway_IP") << "\n";
                return 1;
            }
            GatewaySpecified = true;
        }

        ArpDefender Defender(stoul(GetOption("Gateway_IP")), GatewaySpecified, stoul(GetOption("Interval")));

        if (!Defender.Initialize()) {
            std::cout << "\nPress any key to exit...";
            _getch();
            return 1;
        }

        Defender.Run();
        return true;
    }
};

extern "C" __declspec(dllexport) void StopModule() {
    GRunning = false;
}

BOOL APIENTRY DllMain(HMODULE, DWORD Reason, LPVOID)
{
    if (Reason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(GetModuleHandle(nullptr));
    return TRUE;
}

extern "C" __declspec(dllexport) ModuleBase* CreateModule()
{
    return new ARPDefenceB();
}

extern "C" __declspec(dllexport) void DestroyModule(ModuleBase* Module)
{
    delete Module;
}
