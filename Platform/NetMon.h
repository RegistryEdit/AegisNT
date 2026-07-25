#pragma once
































#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <mutex>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>




#define WINDIVERTEXPORT extern
#if __has_include("windivert.h")
#include "windivert.h"
#else




typedef enum {
    WINDIVERT_LAYER_NETWORK = 0
} WINDIVERT_LAYER;
constexpr UINT64 WINDIVERT_FLAG_SNIFF = 0x1;
constexpr UINT64 WINDIVERT_FLAG_NO_INSTALL = 0x2;
typedef struct {
    INT64 Timestamp;
    UINT32 Layer : 8;
    UINT32 Event : 8;
    UINT32 Sniffed : 1;
    UINT32 Outbound : 1;
    UINT32 Loopback : 1;
    UINT32 Impostor : 1;
    UINT32 IPv6 : 1;
    UINT32 IPChecksum : 1;
    UINT32 TCPChecksum : 1;
    UINT32 UDPChecksum : 1;
    UINT32 Reserved : 8;
    UINT32 Reserved2;
    UINT32 Reserved3;
} WINDIVERT_ADDRESS;
extern "C" {
WINDIVERTEXPORT HANDLE WINAPI WinDivertOpen(const char* Filter,
    WINDIVERT_LAYER Layer, INT16 Priority, UINT64 Flags);
WINDIVERTEXPORT BOOL WINAPI WinDivertRecv(HANDLE Handle, PVOID Packet,
    UINT PacketLen, UINT* ReadLen, WINDIVERT_ADDRESS* Address);
WINDIVERTEXPORT BOOL WINAPI WinDivertClose(HANDLE Handle);
}
#endif


constexpr uint16_t NETMON_MAX_PACKET_SIZE = 0xFFFF;
constexpr uint32_t NETMON_CACHE_TTL_MS    = 2000;  


#pragma pack(push, 1)

typedef struct {
    uint8_t  VersionIhl;
    uint8_t  Tos;
    uint16_t TotalLength;
    uint16_t Identification;
    uint16_t FlagsFragment;
    uint8_t  Ttl;
    uint8_t  Protocol;
    uint16_t Checksum;
    uint32_t SrcAddr;
    uint32_t DstAddr;
} NetMon_Ipv4Header;

typedef struct {
    uint16_t SrcPort;
    uint16_t DstPort;
    uint32_t SeqNum;
    uint32_t AckNum;
    uint16_t DataOffsetResFlags;
    uint16_t Window;
    uint16_t Checksum;
    uint16_t UrgentPtr;
} NetMon_TcpHeader;

typedef struct {
    uint16_t SrcPort;
    uint16_t DstPort;
    uint16_t Length;
    uint16_t Checksum;
} NetMon_UdpHeader;

typedef struct {
    uint8_t  VersionTcFlow[4];
    uint16_t PayloadLength;
    uint8_t  NextHeader;
    uint8_t  HopLimit;
    uint32_t SrcAddr[4];
    uint32_t DstAddr[4];
} NetMon_Ipv6Header;

#pragma pack(pop)


typedef struct {
    uint8_t  Protocol;
    bool     Outbound;
    bool     IsIpv6;
    uint32_t SrcAddr[4];
    uint32_t DstAddr[4];
    uint16_t SrcPort;
    uint16_t DstPort;

    
    
    
    uint32_t LocalAddr[4];
    uint32_t RemoteAddr[4];
    uint16_t LocalPort;
    uint16_t RemotePort;

    uint32_t Pid;
    char     ProcessName[64];

    uint32_t TotalLength;
    std::vector<uint8_t> Payload;
} NetMon_ParsedPacket;


typedef void (*NetMon_Callback)(const NetMon_ParsedPacket* Pkt);




namespace NetMon_Detail {





struct PidKey {
    uint16_t LocalPort;
    uint16_t RemotePort;
    uint8_t  Protocol;
    bool     IsIpv6;

    bool operator==(const PidKey& Other) const
    {
        return LocalPort  == Other.LocalPort &&
               RemotePort == Other.RemotePort &&
               Protocol   == Other.Protocol &&
               IsIpv6     == Other.IsIpv6;
    }
};

struct PidKeyHash {
    size_t operator()(const PidKey& Key) const
    {
        size_t H = (size_t)Key.Protocol ^ (size_t)Key.IsIpv6;
        H ^= (size_t)Key.LocalPort  << 16;
        H ^= (size_t)Key.RemotePort;
        return H;
    }
};




class PidCache {
public:
    
    
    
    uint32_t Lookup(uint32_t* InOutLocal,  uint32_t* InOutRemote,
                    uint16_t* InOutLocalPort, uint16_t* InOutRemotePort,
                    uint8_t Protocol, bool IsIpv6)
    {
        PidKey K = {};
        K.LocalPort   = *InOutLocalPort;
        K.RemotePort  = *InOutRemotePort;
        K.Protocol    = Protocol;
        K.IsIpv6      = IsIpv6;

        uint64_t Now = GetTickCount64();

        
        {
            std::lock_guard<std::mutex> Lock(Mutex_);
            auto It = Cache_.find(K);
            if (It != Cache_.end() && (Now - It->second.Timestamp) < NETMON_CACHE_TTL_MS)
            {
                
                std::memcpy(InOutLocal,  It->second.CorrectedLocal,
                           IsIpv6 ? 16 : 4);
                std::memcpy(InOutRemote, It->second.CorrectedRemote,
                           IsIpv6 ? 16 : 4);
                *InOutLocalPort  = It->second.CorrectedLocalPort;
                *InOutRemotePort = It->second.CorrectedRemotePort;
                return It->second.Pid;
            }
        }

        
        if (Protocol == IPPROTO_TCP)
        {
            
            
            uint32_t Pid = QueryTcpTable(
                InOutLocal, InOutRemote,
                *InOutLocalPort, *InOutRemotePort, IsIpv6,
                InOutLocal, InOutRemote,
                InOutLocalPort, InOutRemotePort);
            return Pid;
        }

        Entry E = {};
        E.Timestamp = Now;
        std::memcpy(E.CorrectedLocal,  InOutLocal,  IsIpv6 ? 16 : 4);
        std::memcpy(E.CorrectedRemote, InOutRemote, IsIpv6 ? 16 : 4);
        E.CorrectedLocalPort  = *InOutLocalPort;
        E.CorrectedRemotePort = *InOutRemotePort;

        if (Protocol == IPPROTO_UDP)
        {
            E.Pid = QueryUdpTable(
                InOutLocal, *InOutLocalPort, IsIpv6);
        }

        
        {
            std::lock_guard<std::mutex> Lock(Mutex_);
            Cache_[K] = E;
        }

        return E.Pid;
    }

private:
    struct Entry {
        uint32_t Pid;
        uint32_t CorrectedLocal[4];
        uint32_t CorrectedRemote[4];
        uint16_t CorrectedLocalPort;
        uint16_t CorrectedRemotePort;
        uint64_t Timestamp;
    };

    std::unordered_map<PidKey, Entry, PidKeyHash> Cache_;
    std::mutex Mutex_;

    
    
    static uint32_t QueryTcpTable(
        const uint32_t* PktLocal, const uint32_t* PktRemote,
        uint16_t PktLocalPort, uint16_t PktRemotePort, bool IsIpv6,
        uint32_t* OutLocal, uint32_t* OutRemote,
        uint16_t* OutLocalPort, uint16_t* OutRemotePort)
    {
        
        if (!IsIpv6)
        {
            DWORD Size = 0;
            ::GetExtendedTcpTable(nullptr, &Size, FALSE, AF_INET,
                                  TCP_TABLE_OWNER_PID_ALL, 0);
            if (Size > 0)
            {
                std::vector<uint8_t> Buf(Size);
                auto* Table = (PMIB_TCPTABLE_OWNER_PID)Buf.data();
                if (::GetExtendedTcpTable(Table, &Size, FALSE, AF_INET,
                                          TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
                {
                    
                    
                    
                    uint16_t LocalNbo  = htons(PktLocalPort);
                    uint16_t RemoteNbo = htons(PktRemotePort);

                    for (DWORD I = 0; I < Table->dwNumEntries; I++)
                    {
                        auto& Row = Table->table[I];
                        if (Row.dwLocalPort == LocalNbo &&
                            Row.dwRemotePort == RemoteNbo)
                        {
                            
                            
                            
                            OutLocal[0]  = Row.dwLocalAddr;
                            OutRemote[0] = Row.dwRemoteAddr;
                            *OutLocalPort  = PktLocalPort;
                            *OutRemotePort = PktRemotePort;
                            return Row.dwOwningPid;
                        }
                    }

                    
                    
                    for (DWORD I = 0; I < Table->dwNumEntries; I++)
                    {
                        auto& Row = Table->table[I];
                        if (Row.dwLocalPort == LocalNbo &&
                            Row.dwRemotePort == 0 &&
                            Row.dwLocalAddr == PktLocal[0])
                        {
                            OutLocal[0]  = Row.dwLocalAddr;
                            OutRemote[0] = Row.dwRemoteAddr;
                            *OutLocalPort  = PktLocalPort;
                            *OutRemotePort = PktRemotePort;
                            return Row.dwOwningPid;
                        }
                    }
                }
            }
        }

        
        if (!IsIpv6)
            return 0;

        {
            DWORD Size = 0;
            ::GetExtendedTcpTable(nullptr, &Size, FALSE, AF_INET6,
                                  TCP_TABLE_OWNER_PID_ALL, 0);
            if (Size == 0)
                return 0;

            std::vector<uint8_t> Buf(Size);
            auto* Table = (PMIB_TCP6TABLE_OWNER_PID)Buf.data();
            if (::GetExtendedTcpTable(Table, &Size, FALSE, AF_INET6,
                                      TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
                return 0;

            
            uint16_t LocalNbo  = htons(PktLocalPort);
            uint16_t RemoteNbo = htons(PktRemotePort);

            for (DWORD I = 0; I < Table->dwNumEntries; I++)
            {
                auto& Row = Table->table[I];
                if (Row.dwLocalPort == LocalNbo &&
                    Row.dwRemotePort == RemoteNbo)
                {
                    std::memcpy(OutLocal, Row.ucLocalAddr, 16);
                    std::memcpy(OutRemote, Row.ucRemoteAddr, 16);
                    *OutLocalPort  = PktLocalPort;
                    *OutRemotePort = PktRemotePort;
                    return Row.dwOwningPid;
                }
            }
        }

        return 0;
    }

    
    static uint32_t QueryUdpTable(const uint32_t* PktLocal,
                                   uint16_t PktLocalPort, bool IsIpv6)
    {
        
        if (!IsIpv6)
        {
            DWORD Size = 0;
            ::GetExtendedUdpTable(nullptr, &Size, FALSE, AF_INET,
                                  UDP_TABLE_OWNER_PID, 0);
            if (Size > 0)
            {
                std::vector<uint8_t> Buf(Size);
                auto* Table = (PMIB_UDPTABLE_OWNER_PID)Buf.data();
                if (::GetExtendedUdpTable(Table, &Size, FALSE, AF_INET,
                                          UDP_TABLE_OWNER_PID, 0) == NO_ERROR)
                {
                    uint16_t LocalNbo = htons(PktLocalPort);

                    for (DWORD I = 0; I < Table->dwNumEntries; I++)
                    {
                        auto& Row = Table->table[I];
                        if ((Row.dwLocalAddr == PktLocal[0] || Row.dwLocalAddr == 0) &&
                            Row.dwLocalPort == LocalNbo)
                        {
                            return Row.dwOwningPid;
                        }
                    }
                }
            }
        }

        if (!IsIpv6)
            return 0;

        DWORD Size = 0;
        ::GetExtendedUdpTable(nullptr, &Size, FALSE, AF_INET6,
                              UDP_TABLE_OWNER_PID, 0);
        if (Size == 0)
            return 0;

        std::vector<uint8_t> Buf(Size);
        auto* Table = (PMIB_UDP6TABLE_OWNER_PID)Buf.data();
        if (::GetExtendedUdpTable(Table, &Size, FALSE, AF_INET6,
                                  UDP_TABLE_OWNER_PID, 0) != NO_ERROR)
            return 0;

        uint16_t LocalNbo = htons(PktLocalPort);
        for (DWORD I = 0; I < Table->dwNumEntries; I++)
        {
            auto& Row = Table->table[I];
            if (Row.dwLocalPort == LocalNbo &&
                (std::memcmp(Row.ucLocalAddr, PktLocal, 16) == 0 ||
                 IN6_IS_ADDR_UNSPECIFIED((const IN6_ADDR*)Row.ucLocalAddr)))
            {
                return Row.dwOwningPid;
            }
        }

        return 0;
    }
};




inline bool ParsePacket(const uint8_t* Data, unsigned int Len,
                        NetMon_ParsedPacket* Pkt)
{
    if (!Data || !Pkt || Len < 20)
        return false;

    Pkt->Payload.clear();

    uint8_t Version = (Data[0] >> 4) & 0x0F;

    if (Version == 4)
    {
        Pkt->IsIpv6 = false;
        if (Len < sizeof(NetMon_Ipv4Header))
            return false;

        const auto* Ip = (const NetMon_Ipv4Header*)Data;
        Pkt->Protocol    = Ip->Protocol;
        Pkt->TotalLength = ntohs(Ip->TotalLength);
        Pkt->SrcAddr[0]  = Ip->SrcAddr;
        Pkt->DstAddr[0]  = Ip->DstAddr;

        uint8_t Ihl = (Ip->VersionIhl & 0x0F) * 4;
        if (Ihl < 20 || Ihl > Len)
            return false;

        const uint8_t* Next   = Data + Ihl;
        unsigned int Remaining = Len - Ihl;

        if (Pkt->Protocol == IPPROTO_TCP)
        {
            if (Remaining < sizeof(NetMon_TcpHeader))
                return false;
            const auto* Tcp = (const NetMon_TcpHeader*)Next;
            Pkt->SrcPort = ntohs(Tcp->SrcPort);
            Pkt->DstPort = ntohs(Tcp->DstPort);
            const uint16_t DataOffsetFlags = ntohs(Tcp->DataOffsetResFlags);
            uint8_t DataOff = static_cast<uint8_t>(((DataOffsetFlags >> 12) & 0x0F) * 4);
            if (DataOff < 20 || DataOff > Remaining)
                return false;
            if (Pkt->TotalLength < Ihl + DataOff)
                return false;
            unsigned int RawLen = Pkt->TotalLength - Ihl - DataOff;
            if (RawLen > Remaining - DataOff)
                RawLen = Remaining - DataOff;
            if (RawLen > 0)
                Pkt->Payload.assign(Next + DataOff, Next + DataOff + RawLen);
        }
        else if (Pkt->Protocol == IPPROTO_UDP)
        {
            if (Remaining < sizeof(NetMon_UdpHeader))
                return false;
            const auto* Udp = (const NetMon_UdpHeader*)Next;
            Pkt->SrcPort = ntohs(Udp->SrcPort);
            Pkt->DstPort = ntohs(Udp->DstPort);
            uint16_t UdpLen = ntohs(Udp->Length);
            if (UdpLen < sizeof(NetMon_UdpHeader) || UdpLen > Remaining)
                return false;
            unsigned int RawLen = UdpLen - sizeof(NetMon_UdpHeader);
            if (RawLen > 0)
                Pkt->Payload.assign(Next + sizeof(NetMon_UdpHeader),
                                     Next + sizeof(NetMon_UdpHeader) + RawLen);
            Pkt->TotalLength = UdpLen + Ihl;
        }
        else
        {
            Pkt->SrcPort = Pkt->DstPort = 0;
            unsigned int RawLen = Pkt->TotalLength - Ihl;
            if (RawLen > 0 && RawLen <= Remaining)
                Pkt->Payload.assign(Next, Next + RawLen);
        }
    }
    else if (Version == 6)
    {
        Pkt->IsIpv6 = true;
        if (Len < sizeof(NetMon_Ipv6Header))
            return false;

        const auto* Ip6 = (const NetMon_Ipv6Header*)Data;
        Pkt->Protocol    = Ip6->NextHeader;
        Pkt->TotalLength = ntohs(Ip6->PayloadLength) + 40;
        std::memcpy(Pkt->SrcAddr, Ip6->SrcAddr, 16);
        std::memcpy(Pkt->DstAddr, Ip6->DstAddr, 16);

        const uint8_t* Next  = Data + 40;
        unsigned int Remaining = ntohs(Ip6->PayloadLength);

        if (Pkt->Protocol == IPPROTO_TCP)
        {
            if (Remaining < sizeof(NetMon_TcpHeader))
                return false;
            const auto* Tcp = (const NetMon_TcpHeader*)Next;
            Pkt->SrcPort = ntohs(Tcp->SrcPort);
            Pkt->DstPort = ntohs(Tcp->DstPort);
            const uint16_t DataOffsetFlags = ntohs(Tcp->DataOffsetResFlags);
            uint8_t DataOff = static_cast<uint8_t>(((DataOffsetFlags >> 12) & 0x0F) * 4);
            if (DataOff < 20 || DataOff > Remaining)
                return false;
            if (ntohs(Ip6->PayloadLength) < DataOff)
                return false;
            unsigned int RawLen = ntohs(Ip6->PayloadLength) - DataOff;
            if (RawLen > Remaining - DataOff)
                RawLen = Remaining - DataOff;
            if (RawLen > 0)
                Pkt->Payload.assign(Next + DataOff, Next + DataOff + RawLen);
        }
        else if (Pkt->Protocol == IPPROTO_UDP)
        {
            if (Remaining < sizeof(NetMon_UdpHeader))
                return false;
            const auto* Udp = (const NetMon_UdpHeader*)Next;
            Pkt->SrcPort = ntohs(Udp->SrcPort);
            Pkt->DstPort = ntohs(Udp->DstPort);
            uint16_t UdpLen = ntohs(Udp->Length);
            if (UdpLen < sizeof(NetMon_UdpHeader) || UdpLen > Remaining)
                return false;
            unsigned int RawLen = UdpLen - sizeof(NetMon_UdpHeader);
            if (RawLen > 0)
                Pkt->Payload.assign(Next + sizeof(NetMon_UdpHeader),
                                     Next + sizeof(NetMon_UdpHeader) + RawLen);
        }
        else
        {
            Pkt->SrcPort = Pkt->DstPort = 0;
            unsigned int RawLen = ntohs(Ip6->PayloadLength);
            if (RawLen > 0 && RawLen <= Remaining)
                Pkt->Payload.assign(Next, Next + RawLen);
        }
    }
    else
    {
        return false;
    }

    return true;
}





inline void NormaliseEndpoints(NetMon_ParsedPacket* Pkt)
{
    if (Pkt->Outbound)
    {
        std::memcpy(Pkt->LocalAddr,  Pkt->SrcAddr, Pkt->IsIpv6 ? 16 : 4);
        std::memcpy(Pkt->RemoteAddr, Pkt->DstAddr, Pkt->IsIpv6 ? 16 : 4);
        Pkt->LocalPort  = Pkt->SrcPort;
        Pkt->RemotePort = Pkt->DstPort;
    }
    else
    {
        std::memcpy(Pkt->LocalAddr,  Pkt->DstAddr, Pkt->IsIpv6 ? 16 : 4);
        std::memcpy(Pkt->RemoteAddr, Pkt->SrcAddr, Pkt->IsIpv6 ? 16 : 4);
        Pkt->LocalPort  = Pkt->DstPort;
        Pkt->RemotePort = Pkt->SrcPort;
    }
}




inline void GetProcessName(uint32_t Pid, char* OutBuf, size_t OutSize)
{
    OutBuf[0] = '\0';
    if (Pid == 0) { std::strcpy(OutBuf, "Idle");   return; }
    if (Pid == 4) { std::strcpy(OutBuf, "System"); return; }

    HANDLE H = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
    if (!H) { std::strcpy(OutBuf, "???"); return; }

    WCHAR Path[MAX_PATH];
    DWORD PathLen = MAX_PATH;
    if (::QueryFullProcessImageNameW(H, 0, Path, &PathLen))
    {
        WCHAR* P = wcsrchr(Path, L'\\');
        if (P) ++P; else P = Path;

        int Len = ::WideCharToMultiByte(CP_UTF8, 0, P, -1, nullptr, 0, nullptr, nullptr);
        if (Len > 0 && (size_t)Len < OutSize)
            ::WideCharToMultiByte(CP_UTF8, 0, P, -1, OutBuf, (int)OutSize, nullptr, nullptr);
    }
    ::CloseHandle(H);

    if (OutBuf[0] == '\0')
        std::strcpy(OutBuf, "???");
}




inline std::string IpToString(const uint32_t* Addr, bool IsIpv6)
{
    char Buf[64] = {};
    int Family = IsIpv6 ? AF_INET6 : AF_INET;
    return ::InetNtopA(Family, Addr, Buf, (DWORD)sizeof(Buf))
        ? std::string(Buf) : std::string("?");
}

inline std::string PayloadToHex(const uint8_t* Data, size_t Len)
{
    if (Len == 0) return "(empty)";
    std::ostringstream Oss;
    Oss << std::hex << std::setfill('0');
    for (size_t I = 0; I < Len; I++)
    {
        Oss << std::setw(2) << (int)Data[I] << ' ';
        if ((I + 1) % 16 == 0 && I + 1 < Len)
            Oss << "\n             ";
    }
    return Oss.str();
}

inline std::string PayloadToAscii(const uint8_t* Data, size_t Len)
{
    if (Len == 0) return "";
    std::string Result;
    Result.reserve(Len);
    for (size_t I = 0; I < Len; I++)
        Result += (Data[I] >= 32 && Data[I] < 127) ? (char)Data[I] : '.';
    return Result;
}

inline const char* ProtoToString(uint8_t Protocol)
{
    switch (Protocol)
    {
        case IPPROTO_TCP:   return "TCP";
        case IPPROTO_UDP:   return "UDP";
        case IPPROTO_ICMP:  return "ICMP";
        case IPPROTO_ICMPV6: return "ICMPv6";
        default:
        {
            static char Buf[8];
            std::snprintf(Buf, sizeof(Buf), "%u", Protocol);
            return Buf;
        }
    }
}

} 





namespace {

inline NetMon_Detail::PidCache& GetPidCache()
{
    static NetMon_Detail::PidCache Cache;
    return Cache;
}

inline HANDLE& GetNetThread()
{
    static HANDLE H = nullptr;
    return H;
}

inline volatile bool& GetRunningFlag()
{
    static volatile bool Flag = false;
    return Flag;
}

inline NetMon_Callback& GetUserCallback()
{
    static NetMon_Callback Cb = nullptr;
    return Cb;
}

using NetMon_WinDivertOpenProc = decltype(&::WinDivertOpen);
using NetMon_WinDivertRecvProc = decltype(&::WinDivertRecv);
using NetMon_WinDivertCloseProc = decltype(&::WinDivertClose);

struct NetMon_WinDivertApi {
    NetMon_WinDivertOpenProc Open = nullptr;
    NetMon_WinDivertRecvProc Recv = nullptr;
    NetMon_WinDivertCloseProc Close = nullptr;
};

inline NetMon_WinDivertApi& GetWinDivertApi()
{
    static NetMon_WinDivertApi Api;
    return Api;
}

inline HMODULE& GetWinDivertModule()
{
    static HMODULE Module = nullptr;
    return Module;
}

inline bool& GetWinDivertApiReserved()
{
    static bool Reserved = false;
    return Reserved;
}

} 




inline bool NetMon_LoadWinDivertDllFromDirectory(const wchar_t* Directory)
{
    if (!Directory || !*Directory || GetWinDivertApiReserved())
    {
        ::SetLastError(ERROR_INVALID_STATE);
        return false;
    }

    std::wstring DllPath(Directory);
    if (DllPath.back() != L'\\' && DllPath.back() != L'/')
        DllPath += L'\\';
    DllPath += L"WinDivert.dll";

    DWORD Attributes = ::GetFileAttributesW(DllPath.c_str());
    if (Attributes == INVALID_FILE_ATTRIBUTES ||
        (Attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
    {
        ::SetLastError(ERROR_FILE_NOT_FOUND);
        return false;
    }

    HMODULE Module = ::LoadLibraryW(DllPath.c_str());
    if (!Module)
        return false;

    NetMon_WinDivertApi Api = {};
    Api.Open = reinterpret_cast<NetMon_WinDivertOpenProc>(
        ::GetProcAddress(Module, "WinDivertOpen"));
    Api.Recv = reinterpret_cast<NetMon_WinDivertRecvProc>(
        ::GetProcAddress(Module, "WinDivertRecv"));
    Api.Close = reinterpret_cast<NetMon_WinDivertCloseProc>(
        ::GetProcAddress(Module, "WinDivertClose"));
    if (!Api.Open || !Api.Recv || !Api.Close)
    {
        ::FreeLibrary(Module);
        ::SetLastError(ERROR_PROC_NOT_FOUND);
        return false;
    }

    GetWinDivertModule() = Module;
    GetWinDivertApi() = Api;
    return true;
}

inline bool NetMon_IsWinDivertDriverRunning()
{
    SC_HANDLE Scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!Scm)
        return false;

    
    
    const wchar_t* Names[] = { L"WinDivert", L"WinDivert64" };
    DWORD LastError = ERROR_SERVICE_DOES_NOT_EXIST;
    for (const wchar_t* Name : Names)
    {
        SC_HANDLE Service = ::OpenServiceW(Scm, Name, SERVICE_QUERY_STATUS);
        if (!Service)
        {
            LastError = ::GetLastError();
            continue;
        }

        SERVICE_STATUS_PROCESS Status = {};
        DWORD BytesNeeded = 0;
        BOOL Queried = ::QueryServiceStatusEx(
            Service, SC_STATUS_PROCESS_INFO,
            reinterpret_cast<BYTE*>(&Status), sizeof(Status), &BytesNeeded);
        DWORD Error = Queried && Status.dwCurrentState == SERVICE_RUNNING
            ? ERROR_SUCCESS : (Queried ? ERROR_SERVICE_NOT_ACTIVE : ::GetLastError());
        ::CloseServiceHandle(Service);
        if (Error == ERROR_SUCCESS)
        {
            ::CloseServiceHandle(Scm);
            return true;
        }
        LastError = Error;
    }

    ::CloseServiceHandle(Scm);
    ::SetLastError(LastError);
    return false;
}


inline DWORD WINAPI NetMon_NetworkThread(LPVOID)
{
    if (!NetMon_IsWinDivertDriverRunning())
    {
        ::fprintf(stderr, "[NetMon] WinDivert driver service is not running (error=%u)\n",
                  ::GetLastError());
        GetRunningFlag() = false;
        return 1;
    }

    auto& Divert = GetWinDivertApi();
    HANDLE Handle = Divert.Open(
        "ip and (tcp or udp)", WINDIVERT_LAYER_NETWORK, 0,
        WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_NO_INSTALL);

    if (Handle == INVALID_HANDLE_VALUE)
    {
        ::fprintf(stderr, "[NetMon] WinDivertOpen(NETWORK) failed (error=%u)\n",
                  ::GetLastError());
        GetRunningFlag() = false;
        return 1;
    }

    uint8_t Packet[NETMON_MAX_PACKET_SIZE];
    WINDIVERT_ADDRESS Addr = {};
    UINT RecvLen;
    NetMon_ParsedPacket Pkt = {};

    while (GetRunningFlag())
    {
        if (!Divert.Recv(Handle, Packet, sizeof(Packet), &RecvLen, &Addr))
        {
            if (!GetRunningFlag()) break;
            continue;
        }

        if (!NetMon_Detail::ParsePacket(Packet, RecvLen, &Pkt))
            continue;

        Pkt.Outbound = Addr.Outbound ? true : false;
        NetMon_Detail::NormaliseEndpoints(&Pkt);

        
        
        Pkt.Pid = GetPidCache().Lookup(
            Pkt.LocalAddr, Pkt.RemoteAddr,
            &Pkt.LocalPort, &Pkt.RemotePort,
            Pkt.Protocol, Pkt.IsIpv6);

        NetMon_Detail::GetProcessName(Pkt.Pid, Pkt.ProcessName,
                                       sizeof(Pkt.ProcessName));

        auto Cb = GetUserCallback();
        if (Cb)
            Cb(&Pkt);
    }

    Divert.Close(Handle);
    return 0;
}


inline bool NetMon_Start(NetMon_Callback Callback)
{
    auto& Running = GetRunningFlag();
    if (Running || !GetWinDivertModule())
    {
        ::SetLastError(ERROR_INVALID_STATE);
        return false;
    }

    Running           = true;
    GetUserCallback() = Callback;
    GetWinDivertApiReserved() = true;

    HANDLE HNet = ::CreateThread(nullptr, 0, NetMon_NetworkThread,
                                  nullptr, 0, nullptr);
    if (!HNet)
    {
        Running = false;
        GetWinDivertApiReserved() = false;
        return false;
    }
    GetNetThread() = HNet;

    return true;
}


inline void NetMon_Stop()
{
    auto& Running = GetRunningFlag();
    if (!Running && !GetNetThread())
        return;

    Running = false;

    HANDLE HNet = GetNetThread();
    if (HNet)
    {
        ::WaitForSingleObject(HNet, 3000);
        ::CloseHandle(HNet);
        GetNetThread() = nullptr;
    }

    GetUserCallback() = nullptr;
    GetWinDivertApiReserved() = false;
}


inline bool NetMon_IsRunning()
{
    return GetRunningFlag();
}
