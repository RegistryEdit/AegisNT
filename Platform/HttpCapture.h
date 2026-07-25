#pragma once
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace http_capture {



struct HttpHeader {
    std::string Name;
    std::string Value;
};

struct HttpRequest {
    std::string             Method;
    std::string             Url;
    std::string             Host;
    int                     Port;
    std::vector<HttpHeader> Headers;
    std::vector<uint8_t>    Body;

    std::string HeaderValue(const std::string& name) const {
        for (auto& h : Headers)
            if (_stricmp(h.Name.c_str(), name.c_str()) == 0)
                return h.Value;
        return {};
    }
};

struct HttpResponse {
    int                     StatusCode;
    std::string             Reason;
    std::vector<HttpHeader> Headers;
    std::vector<uint8_t>    Body;

    std::string HeaderValue(const std::string& name) const {
        for (auto& h : Headers)
            if (_stricmp(h.Name.c_str(), name.c_str()) == 0)
                return h.Value;
        return {};
    }
};

struct TlsSniInfo {
    std::string         ServerName;
    uint8_t             TlsVersion;
    std::vector<uint8_t> RawClientHello;
};

enum class Protocol { Unknown, HTTP, HTTPS };

struct FlowInfo {
    uint32_t    SrcIp;
    uint16_t    SrcPort;
    uint32_t    DstIp;
    uint16_t    DstPort;
    Protocol    Protocol;
    std::string Sni;
    bool        IsOutbound;
};



using OnHttpRequestCallback  = std::function<void(const FlowInfo&, const HttpRequest&)>;
using OnHttpResponseCallback = std::function<void(const FlowInfo&, const HttpResponse&)>;
using OnTlsSniCallback       = std::function<void(const FlowInfo&, const TlsSniInfo&)>;
using OnRawPayloadCallback   = std::function<void(const FlowInfo&, const uint8_t* data, size_t len)>;



struct Config {
    bool        CaptureHttp        = true;
    bool        CaptureHttps       = true;
    bool        HttpsMitm          = true;
    bool        EnableRawCallback  = false;
    uint16_t    ProxyPort          = 8443;
    std::string CaCertPath         = "ca_cert.pem";
    std::string CaKeyPath          = "ca_key.pem";
    std::string WinDivertDllPath   = "WinDivert.dll";
};



struct RawPacket {
    std::vector<uint8_t> Data;
    uint32_t             SrcIp;
    uint32_t             DstIp;
    uint16_t             SrcPort;
    uint16_t             DstPort;
    const uint8_t*       Payload;
    size_t               PayloadLen;
    uint32_t             TcpSeq;
    uint32_t             TcpAck;
    bool                 IsSyn;
    bool                 IsFin;
    bool                 IsRst;
    bool                 IsOutbound;
};

using OnPacketCallback = std::function<void(RawPacket&)>;



struct FlowKey {
    uint32_t SrcIp;
    uint32_t DstIp;
    uint16_t SrcPort;
    uint16_t DstPort;

    bool operator<(const FlowKey& o) const {
        if (SrcIp  != o.SrcIp)  return SrcIp  < o.SrcIp;
        if (DstIp  != o.DstIp)  return DstIp  < o.DstIp;
        if (SrcPort != o.SrcPort) return SrcPort < o.SrcPort;
        return DstPort < o.DstPort;
    }
};

struct FlowKeyHash {
    size_t operator()(const FlowKey& k) const {
        return ((size_t)k.SrcIp << 16) ^ k.DstIp ^
               ((size_t)k.SrcPort << 8) ^ k.DstPort;
    }
};

enum class FlowDir { ClientToServer, ServerToClient };

struct ReassembledData {
    FlowKey              Key;
    FlowDir              Dir;
    std::vector<uint8_t> Data;
    bool                 IsFin;
};

using OnReassembledData = std::function<void(const ReassembledData&)>;



enum class ParseState {
    MethodOrStatus,
    Headers,
    Body,
    Complete,
    Error,
};



class HttpParser {
public:
    HttpParser();

    bool Feed(const uint8_t* data, size_t len);
    bool IsRequest()  const { return IsRequest_; }
    bool IsComplete() const { return State_ == ParseState::Complete; }

    HttpRequest  TakeRequest();
    HttpResponse TakeResponse();
    void Reset();

    static bool ParseRequestLine(const std::string& line, std::string& method, std::string& url);
    static void ParseUrl(const std::string& url, std::string& host, int& port);

private:
    ParseState  State_          = ParseState::MethodOrStatus;
    bool        IsRequest_      = true;
    std::string LineBuffer_;

    std::string Method_;
    std::string Url_;
    int         StatusCode_     = 0;
    std::string Reason_;

    std::vector<HttpHeader> Headers_;
    std::vector<uint8_t>    Body_;
    size_t                  BodyBytesRead_    = 0;
    size_t                  ExpectedBodySize_ = 0;
};



class PacketCapture {
public:
    PacketCapture();
    ~PacketCapture();

    bool Start(const std::string& filter, OnPacketCallback cb,
               const Config& cfg = {});
    void Stop();
    bool IsRunning() const;
    std::string LastError() const;

private:
    void CaptureLoop(const std::string& filter, OnPacketCallback cb,
                     const Config& cfg);

    
    struct WinDivertFuncs {
        void* (*Open)(const char*, int, int, int) = nullptr;
        bool  (*Close)(void*) = nullptr;
        bool  (*Recv)(void*, void*, unsigned int, unsigned int*, void*) = nullptr;
        bool  (*HelperParsePacket)(const void*, unsigned int,
                                   void**, void**, unsigned char*,
                                   void**, void**, void**, void**,
                                   void**, unsigned int*, void**, unsigned int*) = nullptr;
    } Funcs_;

    std::atomic<bool> Running_{false};
    mutable std::mutex ErrorMutex_;
    std::string LastErrorText_;
    std::thread       Thread_;
    void*             Module_{nullptr};  
    void*             Handle_{nullptr};  

    void SetError(std::string text);
};



class TcpReassembler {
public:
    explicit TcpReassembler(OnReassembledData cb);

    void OnPacket(uint32_t src_ip, uint32_t dst_ip,
                  uint16_t src_port, uint16_t dst_port,
                  uint32_t seq, uint32_t ack,
                  const uint8_t* payload, size_t payload_len,
                  bool is_syn, bool is_fin, bool is_rst,
                  bool is_outbound);

    void CleanupIdle(uint32_t timeout_ms = 30000);

private:
    struct StreamBuffer {
        std::vector<uint8_t> RecvBuf;
        uint32_t             NextSeq;
        uint32_t             SynSeq;
        bool                 SynReceived = false;
        bool                 FinReceived = false;
        bool                 RstReceived = false;
        uint64_t             LastActivityMs;
    };

    std::unordered_map<uint64_t, StreamBuffer> Streams_;
    OnReassembledData Callback_;

    uint64_t MakeKey(const FlowKey& k) const;
    uint64_t MakeKeyNormalized(uint32_t ip1, uint32_t ip2,
                               uint16_t port1, uint16_t port2) const;
};



bool ExtractSniFromClienthello(const uint8_t* data, size_t len,
                               std::string& sni_out,
                               uint8_t& tls_version_out);

class MitmProxy {
public:
    MitmProxy(const Config& cfg,
              OnHttpRequestCallback  req_cb,
              OnHttpResponseCallback resp_cb);
    ~MitmProxy();

    bool Start();
    void Stop();
    bool IsRunning() const;
    std::string LastError() const;

    void OnIncomingSyn(uint32_t src_ip, uint16_t src_port,
                       uint32_t dst_ip, uint16_t dst_port);

private:
    struct Impl;
    std::unique_ptr<Impl> Impl_;
};



class HttpCapture {
public:
    HttpCapture(const Config& cfg = {});
    ~HttpCapture();

    bool Start();
    void Stop();
    bool IsRunning() const;

    void OnHttpRequest(OnHttpRequestCallback cb);
    void OnHttpResponse(OnHttpResponseCallback cb);
    void OnTlsSni(OnTlsSniCallback cb);
    void OnRawPayload(OnRawPayloadCallback cb);
    std::string LastError() const;

    void Wait();

private:
    struct Impl;
    std::unique_ptr<Impl> Impl_;
};

} 




#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <thread>
#include <vector>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")

namespace http_capture {



struct WdAddress {
    int64_t  Timestamp;
    uint32_t Flags;
    uint32_t DataLen;
    uint32_t Impostor;
    uint8_t  Direction;
    uint8_t  Loopback;
    uint8_t  Protocol;
    uint8_t  Reserved[1];
};

struct WdIpHdr {
    uint8_t  HdrLen : 4;
    uint8_t  Version : 4;
    uint8_t  Tos;
    uint16_t TotLen;
    uint16_t Id;
    uint16_t FragOff0;
    uint8_t  Ttl;
    uint8_t  Protocol;
    uint16_t Checksum;
    uint32_t SrcAddr;
    uint32_t DstAddr;
};

struct WdTcpHdr {
    uint16_t SrcPort;
    uint16_t DstPort;
    uint32_t SeqNum;
    uint32_t AckNum;
    uint16_t Reserved1 : 4;
    uint16_t HdrLen : 4;
    uint16_t Fin : 1;
    uint16_t Syn : 1;
    uint16_t Rst : 1;
    uint16_t Psh : 1;
    uint16_t Ack : 1;
    uint16_t Urg : 1;
    uint16_t Reserved2 : 2;
    uint16_t Window;
    uint16_t Checksum;
    uint16_t UrgPtr;
};



static bool IsWinDivertDriverLoaded()
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr,
                                   SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return false;

    bool loaded = false;
    const wchar_t* names[] = { L"WinDivert", L"WinDivert64" };
    for (const wchar_t* name : names) {
        SC_HANDLE svc = OpenServiceW(scm, name, SERVICE_QUERY_STATUS);
        if (!svc) continue;
        SERVICE_STATUS status{};
        loaded = QueryServiceStatus(svc, &status) &&
                 status.dwCurrentState == SERVICE_RUNNING;
        CloseServiceHandle(svc);
        if (loaded) break;
    }
    CloseServiceHandle(scm);
    return loaded;
}



PacketCapture::PacketCapture()  = default;
PacketCapture::~PacketCapture() { Stop(); }

void PacketCapture::SetError(std::string text)
{
    std::lock_guard<std::mutex> lock(ErrorMutex_);
    LastErrorText_ = std::move(text);
}

std::string PacketCapture::LastError() const
{
    std::lock_guard<std::mutex> lock(ErrorMutex_);
    return LastErrorText_;
}

bool PacketCapture::Start(const std::string& filter, OnPacketCallback cb,
                          const Config& cfg)
{
    if (Running_) return false;
    SetError({});

    
    Module_ = LoadLibraryA(cfg.WinDivertDllPath.c_str());
    if (!Module_) {
        DWORD err = GetLastError();
        std::cerr << "[PacketCapture] Failed to load " << cfg.WinDivertDllPath
                  << " (error " << err << ")\n";
        SetError("Failed to load WinDivert.dll from: " + cfg.WinDivertDllPath +
                 " (Win32 error " + std::to_string(err) + ")");
        return false;
    }

    auto get = [&](const char* name) -> void* {
        return GetProcAddress((HMODULE)Module_, name);
    };

    Funcs_.Open               = (void* (*)(const char*, int, int, int))get("WinDivertOpen");
    Funcs_.Close              = (bool (*)(void*))get("WinDivertClose");
    Funcs_.Recv               = (bool (*)(void*, void*, unsigned int, unsigned int*, void*))get("WinDivertRecv");
    Funcs_.HelperParsePacket  = (bool (*)(const void*, unsigned int,
                                          void**, void**, unsigned char*,
                                          void**, void**, void**, void**,
                                          void**, unsigned int*, void**, unsigned int*))get("WinDivertHelperParsePacket");

    if (!Funcs_.Open || !Funcs_.Close || !Funcs_.Recv || !Funcs_.HelperParsePacket) {
        std::cerr << "[PacketCapture] WinDivert.dll missing required exports\n";
        SetError("WinDivert.dll is missing required exports.");
        FreeLibrary((HMODULE)Module_);
        Module_ = nullptr;
        return false;
    }

    
    if (!IsWinDivertDriverLoaded()) {
        std::cerr << "[PacketCapture] WinDivert driver is not running.\n"
                  << "  Start it manually: \"sc start WinDivert\"\n"
                  << "  or install it first: \"windivertctl.exe install\"\n";
        SetError("WinDivert driver is not running.");
        FreeLibrary((HMODULE)Module_);
        Module_ = nullptr;
        return false;
    }

    HANDLE handle = (HANDLE)Funcs_.Open(
        filter.c_str(),
        0,          
        0,          
        0x0001      
    );
    if (!handle || handle == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        std::cerr << "[PacketCapture] WinDivertOpen failed: " << err << "\n"
                  << "  Make sure WinDivert64.sys is installed (run as Administrator)\n";
        SetError("WinDivertOpen failed with error " + std::to_string(err) +
                 ". Run as Administrator and verify WinDivert64.sys is installed.");
        FreeLibrary((HMODULE)Module_);
        Module_ = nullptr;
        return false;
    }
    Handle_ = handle;
    Running_ = true;
    Thread_  = std::thread(&PacketCapture::CaptureLoop, this, filter,
                           std::move(cb), std::ref(cfg));
    return true;
}

void PacketCapture::Stop()
{
    if (!Running_) return;
    Running_ = false;

    HANDLE handle = (HANDLE)Handle_;
    if (handle && handle != INVALID_HANDLE_VALUE) {
        if (Funcs_.Close) Funcs_.Close(handle);
        Handle_ = nullptr;
    }
    if (Thread_.joinable())
        Thread_.join();
    if (Module_) {
        FreeLibrary((HMODULE)Module_);
        Module_ = nullptr;
    }
}

bool PacketCapture::IsRunning() const
{
    return Running_.load();
}

void PacketCapture::CaptureLoop(const std::string& filter, OnPacketCallback cb,
                                const Config& cfg)
{
    HANDLE handle = (HANDLE)Handle_;
    if (!handle || handle == INVALID_HANDLE_VALUE) return;

    std::vector<uint8_t> buf(8192);

    while (Running_) {
        UINT recv_len = 0;
        WdAddress addr;
        ZeroMemory(&addr, sizeof(addr));

        BOOL ok = Funcs_.Recv(handle, buf.data(), (UINT)buf.size(),
                              &recv_len, &addr);
        if (!ok) {
            DWORD err = GetLastError();
            if (err == ERROR_NO_DATA) continue;
            if (err == ERROR_INVALID_HANDLE || err == ERROR_OPERATION_ABORTED)
                break;
            continue;
        }
        if (recv_len == 0) continue;

        WdIpHdr*   ip_hdr   = nullptr;
        WdTcpHdr*  tcp_hdr  = nullptr;
        UINT8      protocol = 0;
        PVOID      payload_ptr = nullptr;
        UINT       payload_len = 0;
        PVOID      next_ptr = nullptr;
        UINT       next_len = 0;

        Funcs_.HelperParsePacket(
            buf.data(), recv_len,
            (void**)&ip_hdr, nullptr, &protocol, nullptr, nullptr,
            (void**)&tcp_hdr, nullptr,
            &payload_ptr, &payload_len,
            &next_ptr, &next_len);

        if (!ip_hdr || !tcp_hdr) continue;

        RawPacket pkt;
        pkt.Data       = std::vector<uint8_t>(buf.begin(), buf.begin() + recv_len);
        pkt.Payload    = (const uint8_t*)payload_ptr;
        pkt.PayloadLen = payload_len;
        pkt.SrcIp      = ntohl(ip_hdr->SrcAddr);
        pkt.DstIp      = ntohl(ip_hdr->DstAddr);
        pkt.SrcPort    = ntohs(tcp_hdr->SrcPort);
        pkt.DstPort    = ntohs(tcp_hdr->DstPort);
        pkt.TcpSeq     = ntohl(tcp_hdr->SeqNum);
        pkt.TcpAck     = ntohl(tcp_hdr->AckNum);
        pkt.IsSyn      = (tcp_hdr->Syn != 0);
        pkt.IsFin      = (tcp_hdr->Fin != 0);
        pkt.IsRst      = (tcp_hdr->Rst != 0);
        pkt.IsOutbound = (addr.Direction != 0);

        cb(pkt);
    }
}





TcpReassembler::TcpReassembler(OnReassembledData cb)
    : Callback_(std::move(cb))
{
}

uint64_t TcpReassembler::MakeKey(const FlowKey& k) const
{
    return MakeKeyNormalized(k.SrcIp, k.DstIp, k.SrcPort, k.DstPort);
}

uint64_t TcpReassembler::MakeKeyNormalized(
    uint32_t ip1, uint32_t ip2,
    uint16_t port1, uint16_t port2) const
{
    uint64_t key;
    if (ip1 < ip2 || (ip1 == ip2 && port1 < port2)) {
        key = ((uint64_t)ip1 << 32) | ip2;
        key ^= ((uint64_t)port1 << 16) | port2;
    } else {
        key = ((uint64_t)ip2 << 32) | ip1;
        key ^= ((uint64_t)port2 << 16) | port1;
    }
    return key;
}

void TcpReassembler::OnPacket(
    uint32_t src_ip, uint32_t dst_ip,
    uint16_t src_port, uint16_t dst_port,
    uint32_t seq, uint32_t ack,
    const uint8_t* payload, size_t payload_len,
    bool is_syn, bool is_fin, bool is_rst,
    bool is_outbound)
{
    if (is_rst) {
        FlowKey k{src_ip, dst_ip, src_port, dst_port};
        uint64_t key = MakeKey(k);
        Streams_.erase(key);

        k = {dst_ip, src_ip, dst_port, src_port};
        key = MakeKey(k);
        Streams_.erase(key);
        return;
    }

    uint64_t key = MakeKeyNormalized(src_ip, dst_ip, src_port, dst_port);

    FlowDir dir;
    if (is_syn) {
        dir = FlowDir::ClientToServer;
    } else {
        if (dst_port == 80 || dst_port == 443)
            dir = FlowDir::ClientToServer;
        else if (src_port == 80 || src_port == 443)
            dir = FlowDir::ServerToClient;
        else
            dir = is_outbound ? FlowDir::ClientToServer : FlowDir::ServerToClient;
    }

    auto& stream = Streams_[key];
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now().time_since_epoch()).count();
    stream.LastActivityMs = now;

    if (is_syn) {
        stream.SynSeq      = seq;
        stream.NextSeq     = seq + 1;
        stream.SynReceived = true;
        return;
    }

    if (!stream.SynReceived) return;

    uint32_t rel_seq = seq - stream.SynSeq;

    if (payload_len > 0) {
        uint32_t expected_rel = stream.NextSeq - stream.SynSeq;

        if (rel_seq == expected_rel) {
            stream.RecvBuf.insert(stream.RecvBuf.end(), payload, payload + payload_len);
            stream.NextSeq = seq + (uint32_t)payload_len;

            ReassembledData rd;
            rd.Key  = {src_ip, dst_ip, src_port, dst_port};
            rd.Dir  = dir;
            rd.Data.assign(payload, payload + payload_len);
            rd.IsFin = is_fin;
            Callback_(rd);
        } else if (rel_seq > expected_rel) {
            ReassembledData rd;
            rd.Key  = {src_ip, dst_ip, src_port, dst_port};
            rd.Dir  = dir;
            rd.Data.assign(payload, payload + payload_len);
            rd.IsFin = false;
            Callback_(rd);
        }
    }

    if (is_fin) {
        stream.FinReceived = true;
        ReassembledData rd;
        rd.Key  = {src_ip, dst_ip, src_port, dst_port};
        rd.Dir  = dir;
        rd.IsFin = true;
        Callback_(rd);

        Streams_.erase(key);
    }
}

void TcpReassembler::CleanupIdle(uint32_t timeout_ms)
{
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now().time_since_epoch()).count();
    for (auto it = Streams_.begin(); it != Streams_.end(); ) {
        if (now - it->second.LastActivityMs > timeout_ms) {
            it = Streams_.erase(it);
        } else {
            ++it;
        }
    }
}





HttpParser::HttpParser() = default;

void HttpParser::Reset()
{
    State_             = ParseState::MethodOrStatus;
    IsRequest_         = true;
    LineBuffer_.clear();
    Method_.clear();
    Url_.clear();
    StatusCode_ = 0;
    Reason_.clear();
    Headers_.clear();
    Body_.clear();
    BodyBytesRead_    = 0;
    ExpectedBodySize_ = 0;
}

bool HttpParser::Feed(const uint8_t* data, size_t len)
{
    const char* ptr = reinterpret_cast<const char*>(data);
    size_t remaining = len;

    while (remaining > 0 && State_ != ParseState::Complete && State_ != ParseState::Error) {
        switch (State_) {
            case ParseState::MethodOrStatus: {
                size_t consumed = 0;
                for (size_t i = 0; i < remaining; i++) {
                    consumed = i + 1;
                    if (ptr[i] == '\r') continue;
                    if (ptr[i] == '\n') {
                        if (!LineBuffer_.empty()) {
                            IsRequest_ = !(LineBuffer_.compare(0, 4, "HTTP") == 0);
                            if (IsRequest_) {
                                ParseRequestLine(LineBuffer_, Method_, Url_);
                            } else {
                                auto space1 = LineBuffer_.find(' ');
                                auto space2 = LineBuffer_.find(' ', space1 + 1);
                                if (space1 != std::string::npos && space2 != std::string::npos) {
                                    StatusCode_ = std::stoi(LineBuffer_.substr(space1 + 1, space2 - space1 - 1));
                                    Reason_     = LineBuffer_.substr(space2 + 1);
                                }
                            }
                            LineBuffer_.clear();
                            State_ = ParseState::Headers;
                        }
                        break;
                    } else {
                        LineBuffer_ += ptr[i];
                    }
                }
                ptr += consumed;
                remaining -= consumed;
                break;
            }

            case ParseState::Headers: {
                size_t consumed = 0;
                for (size_t i = 0; i < remaining; i++) {
                    consumed = i + 1;
                    if (ptr[i] == '\r') continue;
                    if (ptr[i] == '\n') {
                        if (LineBuffer_.empty()) {
                            std::string cl;
                            for (auto& h : Headers_) {
                                if (_stricmp(h.Name.c_str(), "Content-Length") == 0) {
                                    cl = h.Value;
                                    break;
                                }
                            }
                            if (!cl.empty()) {
                                ExpectedBodySize_ = (size_t)std::stoll(cl);
                            }
                            State_ = ExpectedBodySize_ == 0
                                ? ParseState::Complete
                                : ParseState::Body;
                        } else {
                            auto colon = LineBuffer_.find(':');
                            if (colon != std::string::npos) {
                                HttpHeader h;
                                h.Name  = LineBuffer_.substr(0, colon);
                                h.Value = LineBuffer_.substr(colon + 1);
                                while (!h.Value.empty() && (h.Value[0] == ' ' || h.Value[0] == '\t'))
                                    h.Value.erase(0, 1);
                                Headers_.push_back(std::move(h));
                            }
                            LineBuffer_.clear();
                        }
                        break;
                    } else {
                        LineBuffer_ += ptr[i];
                    }
                }
                ptr += consumed;
                remaining -= consumed;
                break;
            }

            case ParseState::Body: {
                size_t to_read = (std::min)(remaining, ExpectedBodySize_ - BodyBytesRead_);
                Body_.insert(Body_.end(), ptr, ptr + to_read);
                BodyBytesRead_ += to_read;
                ptr += to_read;
                remaining -= to_read;

                if (BodyBytesRead_ >= ExpectedBodySize_) {
                    State_ = ParseState::Complete;
                }
                break;
            }

            default:
                remaining = 0;
                break;
        }
    }
    return State_ != ParseState::Error;
}

HttpRequest HttpParser::TakeRequest()
{
    HttpRequest req;
    req.Method  = std::move(Method_);
    req.Url     = std::move(Url_);
    req.Headers = std::move(Headers_);
    req.Body    = std::move(Body_);
    req.Host    = req.HeaderValue("Host");
    ParseUrl(req.Url, req.Host, req.Port);
    return req;
}

HttpResponse HttpParser::TakeResponse()
{
    HttpResponse resp;
    resp.StatusCode = StatusCode_;
    resp.Reason     = std::move(Reason_);
    resp.Headers    = std::move(Headers_);
    resp.Body       = std::move(Body_);
    return resp;
}

bool HttpParser::ParseRequestLine(const std::string& line,
                                  std::string& method, std::string& url)
{
    auto pos1 = line.find(' ');
    if (pos1 == std::string::npos) return false;
    auto pos2 = line.find(' ', pos1 + 1);
    if (pos2 == std::string::npos) return false;

    method = line.substr(0, pos1);
    url    = line.substr(pos1 + 1, pos2 - pos1 - 1);
    return true;
}

void HttpParser::ParseUrl(const std::string& url, std::string& host, int& port)
{
    port = 0;
    std::string tmp;

    size_t start = url.find("://");
    start = (start != std::string::npos) ? start + 3 : 0;

    auto slash = url.find('/', start);
    auto end = (slash != std::string::npos) ? slash : url.size();
    tmp = url.substr(start, end - start);

    auto colon = tmp.find(':');
    if (colon != std::string::npos) {
        host = tmp.substr(0, colon);
        port = std::stoi(tmp.substr(colon + 1));
    } else {
        host = tmp;
    }
}





bool ExtractSniFromClienthello(const uint8_t* data, size_t len,
                               std::string& sni_out,
                               uint8_t& tls_version_out)
{
    if (len < 5) return false;
    if (data[0] != 0x16) return false;

    tls_version_out = data[2];

    uint16_t record_len = ((uint16_t)data[3] << 8) | data[4];
    if (record_len + 5 > len) return false;

    size_t offset = 5;
    if (offset + 4 > len) return false;
    if (data[offset] != 0x01) return false;

    uint32_t handshake_len = ((uint32_t)data[offset+1] << 16) |
                             ((uint32_t)data[offset+2] << 8)  |
                             data[offset+3];
    offset += 4;

    if (offset + 34 > len) return false;
    offset += 34;

    if (offset + 1 > len) return false;
    uint8_t session_id_len = data[offset++];
    offset += session_id_len;

    if (offset + 2 > len) return false;
    uint16_t cipher_len = ((uint16_t)data[offset] << 8) | data[offset+1];
    offset += 2 + cipher_len;

    if (offset + 1 > len) return false;
    uint8_t comp_len = data[offset++];
    offset += comp_len;

    if (offset + 2 > len) return false;
    uint16_t ext_len = ((uint16_t)data[offset] << 8) | data[offset+1];
    offset += 2;

    while (offset + 4 <= len) {
        uint16_t ext_type = ((uint16_t)data[offset] << 8) | data[offset+1];
        uint16_t ext_data_len = ((uint16_t)data[offset+2] << 8) | data[offset+3];
        offset += 4;

        if (ext_type == 0x0000) {
            if (offset + 2 > len) return false;
            uint16_t sni_list_len = ((uint16_t)data[offset] << 8) | data[offset+1];
            offset += 2;

            if (offset + 1 > len) return false;
            uint8_t sni_type = data[offset];
            offset += 1;

            if (sni_type == 0x00) {
                if (offset + 2 > len) return false;
                uint16_t sni_name_len = ((uint16_t)data[offset] << 8) | data[offset+1];
                offset += 2;

                if (offset + sni_name_len <= len) {
                    sni_out.assign((const char*)data + offset, sni_name_len);
                    return true;
                }
            }
        }
        offset += ext_data_len;
    }
    return false;
}



static X509_NAME* MakeName(const std::string& cn,
                           const std::string& o,
                           const std::string& ou)
{
    X509_NAME* name = X509_NAME_new();
    if (!name) return nullptr;

    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char*)cn.c_str(), -1, -1, 0);
    if (!o.empty()) {
        X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                                   (const unsigned char*)o.c_str(), -1, -1, 0);
    }
    if (!ou.empty()) {
        X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC,
                                   (const unsigned char*)ou.c_str(), -1, -1, 0);
    }
    return name;
}

static bool InstallCaToCurrentUserRootStore(X509* cert)
{
    if (!cert) return false;

    int der_len = i2d_X509(cert, nullptr);
    if (der_len <= 0) return false;

    std::vector<unsigned char> der((size_t)der_len);
    unsigned char* der_ptr = der.data();
    if (i2d_X509(cert, &der_ptr) != der_len)
        return false;

    HCERTSTORE store = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_A,
        0,
        0,
        CERT_SYSTEM_STORE_CURRENT_USER,
        "ROOT");
    if (!store)
        return false;

    PCCERT_CONTEXT existing = CertFindCertificateInStore(
        store,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_EXISTING,
        der.data(),
        nullptr);
    if (existing) {
        CertFreeCertificateContext(existing);
        CertCloseStore(store, 0);
        return true;
    }

    const BOOL added = CertAddEncodedCertificateToStore(
        store,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        der.data(),
        (DWORD)der.size(),
        CERT_STORE_ADD_REPLACE_EXISTING,
        nullptr);
    CertCloseStore(store, 0);
    return added == TRUE;
}

static bool LoadCaCert(const std::string& cert_path,
                       const std::string& key_path,
                       X509*& ca_cert, EVP_PKEY*& ca_key)
{
    FILE* f = nullptr;
    if (fopen_s(&f, cert_path.c_str(), "rb") == 0 && f) {
        ca_cert = PEM_read_X509(f, nullptr, nullptr, nullptr);
        fclose(f);
    }
    if (!ca_cert) {
        std::cerr << "[TLS] Failed to load CA cert: " << cert_path << "\n";
        return false;
    }
    if (fopen_s(&f, key_path.c_str(), "rb") == 0 && f) {
        ca_key = PEM_read_PrivateKey(f, nullptr, nullptr, nullptr);
        fclose(f);
    }
    if (!ca_key) {
        std::cerr << "[TLS] Failed to load CA key: " << key_path << "\n";
        return false;
    }
    return true;
}

static bool GenerateCertForDomain(X509* ca_cert, EVP_PKEY* ca_key,
                                  const std::string& domain,
                                  X509*& out_cert, EVP_PKEY*& out_key)
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) return false;
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);
    if (!pkey) return false;

    X509* cert = X509_new();
    if (!cert) { EVP_PKEY_free(pkey); return false; }

    ASN1_INTEGER_set(X509_get_serialNumber(cert), (long)time(nullptr));
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 365 * 24 * 3600);
    X509_set_pubkey(cert, pkey);

    X509_NAME* name = MakeName(domain, "HttpCapture MITM", "Generated");
    if (!name) { X509_free(cert); EVP_PKEY_free(pkey); return false; }
    X509_set_subject_name(cert, name);
    X509_NAME_free(name);

    X509_set_issuer_name(cert, X509_get_subject_name(ca_cert));

    std::string san_str = "DNS:" + domain;
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, nullptr,
                                               NID_subject_alt_name,
                                               (char*)san_str.c_str());
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    if (!X509_sign(cert, ca_key, EVP_sha256())) {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return false;
    }

    out_cert = cert;
    out_key  = pkey;
    return true;
}



struct ProxyConnection {
    SOCKET       ClientSock = INVALID_SOCKET;
    SOCKET       ServerSock = INVALID_SOCKET;
    SSL*         ClientSsl  = nullptr;
    SSL*         ServerSsl  = nullptr;
    SSL_CTX*     ClientCtx  = nullptr;
    std::string  Sni;
    uint16_t     TargetPort = 443;
    uint32_t     ClientIp;
    uint16_t     ClientPort;

    HttpParser   ClientParser;
    HttpParser   ServerParser;

    std::vector<uint8_t> ClientBuf;
    std::vector<uint8_t> ServerBuf;
};

static bool SendAll(SOCKET sock, const void* data, size_t len)
{
    const char* ptr = static_cast<const char*>(data);
    size_t sent = 0;
    while (sent < len) {
        int n = send(sock, ptr + sent, (int)(len - sent), 0);
        if (n <= 0) return false;
        sent += (size_t)n;
    }
    return true;
}

static bool LooksLikeHttpProxyRequest(const uint8_t* data, size_t len)
{
    if (!data || len < 3) return false;
    static const char* methods[] = {
        "GET ", "POST ", "HEAD ", "PUT ", "DELETE ",
        "OPTIONS ", "PATCH ", "TRACE "
    };
    for (const char* method : methods) {
        const size_t method_len = strlen(method);
        if (len >= method_len && _memicmp(data, method, method_len) == 0)
            return true;
    }
    return false;
}

static std::string BuildOriginFormPath(const std::string& url)
{
    const size_t scheme = url.find("://");
    if (scheme == std::string::npos)
        return url.empty() ? "/" : url;

    const size_t host_start = scheme + 3;
    const size_t path_start = url.find('/', host_start);
    if (path_start == std::string::npos)
        return "/";
    return url.substr(path_start);
}

static bool G_WsInited = false;
static std::mutex G_SslMutex;

struct MitmProxy::Impl {
    Config               Cfg;
    OnHttpRequestCallback  ReqCb;
    OnHttpResponseCallback RespCb;
    mutable std::mutex    ErrorMutex;
    std::string           LastErrorText;

    SOCKET              ListenSock  = INVALID_SOCKET;
    std::atomic<bool>   Running{false};
    std::thread         AcceptThread;
    std::mutex          WorkerMutex;
    std::vector<std::thread> WorkerThreads;

    X509*               CaCert   = nullptr;
    EVP_PKEY*           CaKey    = nullptr;

    std::mutex          ConnMutex;
    std::map<SOCKET, std::unique_ptr<ProxyConnection>> Connections;

    Impl(const Config& cfg,
         OnHttpRequestCallback req,
         OnHttpResponseCallback resp)
        : Cfg(cfg), ReqCb(std::move(req)), RespCb(std::move(resp))
    {
        if (!G_WsInited) {
            WSADATA ws;
            WSAStartup(MAKEWORD(2, 2), &ws);
            G_WsInited = true;
        }

        std::lock_guard<std::mutex> lock(G_SslMutex);
        static bool ssl_inited = false;
        if (!ssl_inited) {
            SSL_library_init();
            SSL_load_error_strings();
            OpenSSL_add_all_algorithms();
            ssl_inited = true;
        }
    }

    ~Impl()
    {
        Stop();
        if (CaCert) X509_free(CaCert);
        if (CaKey)  EVP_PKEY_free(CaKey);
    }

    void SetError(std::string text)
    {
        std::lock_guard<std::mutex> lock(ErrorMutex);
        LastErrorText = std::move(text);
    }

    std::string GetError() const
    {
        std::lock_guard<std::mutex> lock(ErrorMutex);
        return LastErrorText;
    }

    bool LoadCa()
    {
        if (!LoadCaCert(Cfg.CaCertPath, Cfg.CaKeyPath, CaCert, CaKey)) {
            std::cerr << "[TLS] CA not found, generating self-signed CA...\n";
            return GenerateSelfSignedCa();
        }
        if (InstallCaToCurrentUserRootStore(CaCert)) {
            std::cout << "[TLS] CA installed in CurrentUser Root store\n";
        } else {
            std::cerr << "[TLS] Failed to install CA into CurrentUser Root store\n";
        }
        return true;
    }

    bool GenerateSelfSignedCa()
    {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!ctx) return false;
        EVP_PKEY_keygen_init(ctx);
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
        EVP_PKEY* pkey = nullptr;
        EVP_PKEY_keygen(ctx, &pkey);
        EVP_PKEY_CTX_free(ctx);
        if (!pkey) return false;

        X509* cert = X509_new();
        if (!cert) { EVP_PKEY_free(pkey); return false; }

        ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
        X509_gmtime_adj(X509_getm_notBefore(cert), 0);
        X509_gmtime_adj(X509_getm_notAfter(cert), 3650 * 24 * 3600);
        X509_set_pubkey(cert, pkey);

        X509_NAME* name = MakeName("HttpCapture Root CA", "HttpCapture", "");
        if (!name) { X509_free(cert); EVP_PKEY_free(pkey); return false; }
        X509_set_subject_name(cert, name);
        X509_set_issuer_name(cert, name);
        X509_NAME_free(name);

        std::string ca_str = "critical,CA:TRUE";
        X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, nullptr,
                                                    NID_basic_constraints,
                                                    (char*)ca_str.c_str());
        if (ext) {
            X509_add_ext(cert, ext, -1);
            X509_EXTENSION_free(ext);
        }

        if (!X509_sign(cert, pkey, EVP_sha256())) {
            X509_free(cert);
            EVP_PKEY_free(pkey);
            return false;
        }

        CaCert = cert;
        CaKey  = pkey;

        FILE* f = nullptr;
        if (fopen_s(&f, Cfg.CaCertPath.c_str(), "wb") == 0 && f) {
            PEM_write_X509(f, CaCert);
            fclose(f);
        }
        if (fopen_s(&f, Cfg.CaKeyPath.c_str(), "wb") == 0 && f) {
            PEM_write_PrivateKey(f, CaKey, nullptr, nullptr, 0, nullptr, nullptr);
            fclose(f);
        }

        std::cout << "[TLS] Self-signed CA generated: " << Cfg.CaCertPath << "\n";
        if (InstallCaToCurrentUserRootStore(CaCert)) {
            std::cout << "[TLS] CA installed in CurrentUser Root store\n";
        } else {
            std::cerr << "[TLS] Failed to install CA into CurrentUser Root store\n";
        }
        return true;
    }

    bool Start()
    {
        if (Running) return false;
        SetError({});

        if (Cfg.HttpsMitm) {
            if (!LoadCa()) {
                std::cerr << "[TLS] Failed to load/generate CA\n";
                if (GetError().empty())
                    SetError("Failed to load or generate MITM CA certificate.");
                return false;
            }
        }

        ListenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (ListenSock == INVALID_SOCKET) {
            SetError("Failed to create proxy socket (WSA " + std::to_string(WSAGetLastError()) + ").");
            return false;
        }

        int opt = 1;
        setsockopt(ListenSock, SOL_SOCKET, SO_REUSEADDR,
                   (const char*)&opt, sizeof(opt));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(Cfg.ProxyPort);

        if (bind(ListenSock, (sockaddr*)&addr, sizeof(addr)) != 0) {
            const int err = WSAGetLastError();
            std::cerr << "[MITM] bind to port " << Cfg.ProxyPort << " failed\n";
            SetError("Failed to bind 127.0.0.1:" + std::to_string(Cfg.ProxyPort) +
                     " (WSA " + std::to_string(err) + "). Port may already be in use.");
            closesocket(ListenSock);
            ListenSock = INVALID_SOCKET;
            return false;
        }

        if (listen(ListenSock, SOMAXCONN) != 0) {
            const int err = WSAGetLastError();
            SetError("listen() failed on 127.0.0.1:" + std::to_string(Cfg.ProxyPort) +
                     " (WSA " + std::to_string(err) + ").");
            closesocket(ListenSock);
            ListenSock = INVALID_SOCKET;
            return false;
        }
        Running = true;
        AcceptThread = std::thread(&Impl::AcceptLoop, this);

        std::cout << "[MITM] Proxy listening on 127.0.0.1:" << Cfg.ProxyPort << "\n";
        return true;
    }

    void Stop()
    {
        if (!Running) return;
        Running = false;

        if (ListenSock != INVALID_SOCKET) {
            closesocket(ListenSock);
            ListenSock = INVALID_SOCKET;
        }

        if (AcceptThread.joinable())
            AcceptThread.join();

        {
            std::lock_guard<std::mutex> lock(ConnMutex);
            for (auto& kv : Connections) {
                auto& conn = kv.second;
                if (conn->ClientSock != INVALID_SOCKET) {
                    shutdown(conn->ClientSock, SD_BOTH);
                    closesocket(conn->ClientSock);
                    conn->ClientSock = INVALID_SOCKET;
                }
                if (conn->ServerSock != INVALID_SOCKET) {
                    shutdown(conn->ServerSock, SD_BOTH);
                    closesocket(conn->ServerSock);
                    conn->ServerSock = INVALID_SOCKET;
                }
            }
        }

        {
            std::lock_guard<std::mutex> lock(WorkerMutex);
            for (auto& worker : WorkerThreads) {
                if (worker.joinable())
                    worker.join();
            }
            WorkerThreads.clear();
        }

        std::lock_guard<std::mutex> lock(ConnMutex);
        for (auto& kv : Connections) {
            auto& conn = kv.second;
            if (conn->ClientSsl) SSL_free(conn->ClientSsl);
            if (conn->ClientCtx) SSL_CTX_free(conn->ClientCtx);
            if (conn->ServerSsl) SSL_free(conn->ServerSsl);
        }
        Connections.clear();
    }

    bool IsRunning() const { return Running.load(); }

    void AcceptLoop()
    {
        while (Running) {
            SOCKET client = accept(ListenSock, nullptr, nullptr);
            if (client == INVALID_SOCKET) {
                if (!Running) break;
                continue;
            }
            sockaddr_in peer{};
            int peer_len = sizeof(peer);
            getpeername(client, (sockaddr*)&peer, &peer_len);

            auto conn = std::make_unique<ProxyConnection>();
            conn->ClientSock = client;
            conn->ClientIp   = ntohl(peer.sin_addr.s_addr);
            conn->ClientPort = ntohs(peer.sin_port);

            {
                std::lock_guard<std::mutex> lock(ConnMutex);
                Connections[client] = std::move(conn);
            }

            std::lock_guard<std::mutex> lock(WorkerMutex);
            WorkerThreads.emplace_back(&Impl::HandleConnection, this, client);
        }
    }

    bool ConnectUpstream(const std::string& host, uint16_t port,
                         SOCKET& server_sock, sockaddr_in& server_addr)
    {
        server_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (server_sock == INVALID_SOCKET)
            return false;

        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        addrinfo* result = nullptr;
        const std::string port_str = std::to_string(port);
        const int gai = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result);
        if (gai != 0 || !result) {
            std::cerr << "[MITM] DNS resolution failed for: " << host << "\n";
            closesocket(server_sock);
            server_sock = INVALID_SOCKET;
            return false;
        }

        ZeroMemory(&server_addr, sizeof(server_addr));
        memcpy(&server_addr, result->ai_addr, sizeof(server_addr));
        freeaddrinfo(result);

        if (connect(server_sock, (sockaddr*)&server_addr, sizeof(server_addr)) != 0) {
            std::cerr << "[MITM] connect to " << host << ":" << port
                      << " failed (error=" << WSAGetLastError() << ")\n";
            closesocket(server_sock);
            server_sock = INVALID_SOCKET;
            return false;
        }
        return true;
    }

    void HandlePlainHttpProxy(ProxyConnection* conn, SOCKET client_sock)
    {
        uint8_t buf[16384];
        sockaddr_in server_addr{};

        while (Running) {
            int n = recv(client_sock, (char*)buf, (int)sizeof(buf), 0);
            if (n <= 0)
                break;

            if (!conn->ClientParser.Feed(buf, (size_t)n)) {
                conn->ClientParser.Reset();
                if (conn->ServerSock != INVALID_SOCKET) {
                    closesocket(conn->ServerSock);
                    conn->ServerSock = INVALID_SOCKET;
                }
                break;
            }
            if (!conn->ClientParser.IsComplete())
                continue;

            HttpRequest req = conn->ClientParser.TakeRequest();
            conn->ClientParser.Reset();

            if (req.Host.empty()) {
                const char response[] =
                    "HTTP/1.1 400 Bad Request\r\n"
                    "Connection: close\r\n\r\n";
                SendAll(client_sock, response, strlen(response));
                break;
            }

            const uint16_t target_port = req.Port > 0 ? (uint16_t)req.Port : 80;
            const bool need_reconnect =
                conn->ServerSock == INVALID_SOCKET ||
                _stricmp(conn->Sni.c_str(), req.Host.c_str()) != 0 ||
                conn->TargetPort != target_port;
            if (need_reconnect) {
                if (conn->ServerSock != INVALID_SOCKET)
                    closesocket(conn->ServerSock);
                conn->ServerSock = INVALID_SOCKET;
                conn->Sni = req.Host;
                conn->TargetPort = target_port;
                if (!ConnectUpstream(conn->Sni, conn->TargetPort, conn->ServerSock, server_addr)) {
                    const char response[] =
                        "HTTP/1.1 502 Bad Gateway\r\n"
                        "Connection: close\r\n\r\n";
                    SendAll(client_sock, response, strlen(response));
                    break;
                }
            }

            std::ostringstream request_stream;
            request_stream << req.Method << " " << BuildOriginFormPath(req.Url) << " HTTP/1.1\r\n";
            for (const auto& header : req.Headers) {
                if (_stricmp(header.Name.c_str(), "Proxy-Connection") == 0)
                    continue;
                request_stream << header.Name << ": " << header.Value << "\r\n";
            }
            request_stream << "\r\n";
            std::string request_bytes = request_stream.str();
            if (!SendAll(conn->ServerSock, request_bytes.data(), request_bytes.size()) ||
                (!req.Body.empty() && !SendAll(conn->ServerSock, req.Body.data(), req.Body.size()))) {
                break;
            }

            FlowInfo req_flow;
            req_flow.SrcIp = conn->ClientIp;
            req_flow.SrcPort = conn->ClientPort;
            req_flow.DstIp = ntohl(server_addr.sin_addr.s_addr);
            req_flow.DstPort = conn->TargetPort;
            req_flow.Protocol = Protocol::HTTP;
            req_flow.Sni = conn->Sni;
            req_flow.IsOutbound = true;
            if (ReqCb) ReqCb(req_flow, req);

            bool response_complete = false;
            while (Running && !response_complete) {
                n = recv(conn->ServerSock, (char*)buf, (int)sizeof(buf), 0);
                if (n <= 0)
                    return;

                if (!SendAll(client_sock, buf, (size_t)n))
                    return;

                if (!conn->ServerParser.Feed(buf, (size_t)n)) {
                    conn->ServerParser.Reset();
                    response_complete = true;
                    continue;
                }
                if (conn->ServerParser.IsComplete()) {
                    HttpResponse resp = conn->ServerParser.TakeResponse();
                    conn->ServerParser.Reset();

                    FlowInfo resp_flow;
                    resp_flow.SrcIp = conn->ClientIp;
                    resp_flow.SrcPort = conn->ClientPort;
                    resp_flow.DstIp = ntohl(server_addr.sin_addr.s_addr);
                    resp_flow.DstPort = conn->TargetPort;
                    resp_flow.Protocol = Protocol::HTTP;
                    resp_flow.Sni = conn->Sni;
                    resp_flow.IsOutbound = false;
                    if (RespCb) RespCb(resp_flow, resp);
                    response_complete = true;
                }
            }
        }
    }

    void HandleConnection(SOCKET client_sock)
    {
        ProxyConnection* conn = nullptr;
        {
            std::lock_guard<std::mutex> lock(ConnMutex);
            auto it = Connections.find(client_sock);
            if (it == Connections.end()) return;
            conn = it->second.get();
        }

        uint8_t buf[16384];
        int n = 0;

        
        
        
        
        
        
        uint8_t preface[16]{};
        int preface_n = recv(client_sock, (char*)preface, (int)sizeof(preface), MSG_PEEK);
        if (preface_n <= 0) {
            CleanupConnection(client_sock);
            return;
        }

        if (LooksLikeHttpProxyRequest(preface, (size_t)preface_n)) {
            HandlePlainHttpProxy(conn, client_sock);
            CleanupConnection(client_sock);
            return;
        }

        const char first = (char)preface[0];
        if (first == 'C' || first == 'c') {
            std::string proxy_header;
            proxy_header.reserve(1024);
            const uint64_t header_deadline =
                GetTickCount64() + 10000ULL;
            char ch = 0;
            while (proxy_header.size() < 16384 &&
                   GetTickCount64() < header_deadline) {
                int got = recv(client_sock, &ch, 1, 0);
                if (got <= 0) {
                    CleanupConnection(client_sock);
                    return;
                }
                proxy_header.push_back(ch);
                if (proxy_header.size() >= 4 &&
                    proxy_header.compare(proxy_header.size() - 4, 4,
                                         "\r\n\r\n") == 0)
                    break;
            }

            std::istringstream header_stream(proxy_header);
            std::string method, target, version;
            header_stream >> method >> target >> version;
            if (_stricmp(method.c_str(), "CONNECT") != 0 || target.empty()) {
                const char response[] =
                    "HTTP/1.1 400 Bad Request\r\n"
                    "Connection: close\r\n\r\n";
                send(client_sock, response, (int)strlen(response), 0);
                CleanupConnection(client_sock);
                return;
            }

            size_t colon = target.rfind(':');
            if (colon != std::string::npos && colon + 1 < target.size()) {
                int parsed_port = atoi(target.c_str() + colon + 1);
                if (parsed_port > 0 && parsed_port <= 65535) {
                    conn->TargetPort = (uint16_t)parsed_port;
                    target.resize(colon);
                }
            }
            conn->Sni = target;

            const char response[] =
                "HTTP/1.1 200 Connection Established\r\n"
                "Proxy-Agent: WindowsTool\r\n\r\n";
            if (send(client_sock, response, (int)strlen(response), 0) <= 0) {
                CleanupConnection(client_sock);
                return;
            }
        }

        
        
        uint8_t tls_peek[65536]{};
        int tls_len = 0;
        uint8_t tls_ver = 0;
        bool got_sni = false;
        const uint64_t tls_deadline = GetTickCount64() + 15000ULL;
        while (GetTickCount64() < tls_deadline) {
            int available = recv(client_sock, (char*)tls_peek,
                                 (int)sizeof(tls_peek), MSG_PEEK);
            if (available <= 0) break;
            tls_len = available;
            if (ExtractSniFromClienthello(tls_peek, (size_t)tls_len,
                                          conn->Sni, tls_ver)) {
                got_sni = true;
                break;
            }
            fd_set wait_fds;
            FD_ZERO(&wait_fds);
            FD_SET(client_sock, &wait_fds);
            timeval wait_time{0, 200000};
            if (select(0, &wait_fds, nullptr, nullptr, &wait_time) <= 0)
                continue;
        }
        if (!got_sni && conn->Sni.empty()) {
            std::cerr << "[MITM] Failed to extract SNI from ClientHello\n";
            CleanupConnection(client_sock);
            return;
        }

        std::cout << "[MITM] HTTPS connection to: " << conn->Sni << "\n";

        conn->ClientCtx = SSL_CTX_new(TLS_server_method());
        if (!conn->ClientCtx) { CleanupConnection(client_sock); return; }
        SSL_CTX_set_verify(conn->ClientCtx, SSL_VERIFY_NONE, nullptr);

        X509* cert = nullptr;
        EVP_PKEY* key = nullptr;
        if (!GenerateCertForDomain(CaCert, CaKey, conn->Sni, cert, key)) {
            std::cerr << "[MITM] Failed to generate cert for: " << conn->Sni << "\n";
            CleanupConnection(client_sock);
            return;
        }

        SSL_CTX_use_certificate(conn->ClientCtx, cert);
        SSL_CTX_use_PrivateKey(conn->ClientCtx, key);
        
        
        
        SSL_CTX_set_alpn_select_cb(conn->ClientCtx,
            [](SSL*, const unsigned char** out, unsigned char* out_len,
               const unsigned char* in, unsigned int in_len, void*) -> int {
                static const unsigned char http11[] = "http/1.1";
                unsigned int pos = 0;
                while (pos < in_len) {
                    unsigned int len = in[pos++];
                    if (pos + len > in_len) break;
                    if (len == sizeof(http11) - 1 &&
                        memcmp(in + pos, http11, sizeof(http11) - 1) == 0) {
                        *out = http11;
                        *out_len = (unsigned char)(sizeof(http11) - 1);
                        return SSL_TLSEXT_ERR_OK;
                    }
                    pos += len;
                }
                return SSL_TLSEXT_ERR_NOACK;
            }, nullptr);

        conn->ClientSsl = SSL_new(conn->ClientCtx);
        SSL_set_fd(conn->ClientSsl, client_sock);

        int ret = SSL_accept(conn->ClientSsl);
        if (ret <= 0) {
            char err_buf[256];
            ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
            std::cerr << "[MITM] SSL_accept failed: " << err_buf << "\n";
            X509_free(cert); EVP_PKEY_free(key);
            CleanupConnection(client_sock);
            return;
        }

        sockaddr_in server_addr{};
        if (!ConnectUpstream(conn->Sni, conn->TargetPort, conn->ServerSock, server_addr)) {
            X509_free(cert); EVP_PKEY_free(key);
            CleanupConnection(client_sock);
            return;
        }

        SSL_CTX* server_ctx = SSL_CTX_new(TLS_client_method());
        if (!server_ctx) {
            X509_free(cert); EVP_PKEY_free(key);
            CleanupConnection(client_sock);
            return;
        }
        SSL_CTX_set_verify(server_ctx, SSL_VERIFY_NONE, nullptr);

        conn->ServerSsl = SSL_new(server_ctx);
        SSL_set_fd(conn->ServerSsl, (int)conn->ServerSock);
        SSL_set_tlsext_host_name(conn->ServerSsl, conn->Sni.c_str());

        ret = SSL_connect(conn->ServerSsl);
        if (ret <= 0) {
            char err_buf[256];
            ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
            std::cerr << "[MITM] SSL_connect to " << conn->Sni
                      << " failed: " << err_buf << "\n";
            SSL_CTX_free(server_ctx);
            X509_free(cert); EVP_PKEY_free(key);
            CleanupConnection(client_sock);
            return;
        }

        X509_free(cert);
        EVP_PKEY_free(key);

        {
            fd_set read_fds;

            while (Running) {
                FD_ZERO(&read_fds);
                FD_SET(client_sock, &read_fds);
                if (conn->ServerSock != INVALID_SOCKET)
                    FD_SET(conn->ServerSock, &read_fds);

                int max_fd = (int)(std::max)((int)client_sock, (int)conn->ServerSock);
                
                
                
                struct timeval tv{1, 0};
                int sel = select(max_fd + 1, &read_fds, nullptr, nullptr, &tv);
                const bool client_pending = SSL_pending(conn->ClientSsl) > 0;
                const bool server_pending = conn->ServerSsl &&
                                            SSL_pending(conn->ServerSsl) > 0;
                if (sel <= 0 && !client_pending && !server_pending)
                    continue;

                if (SSL_pending(conn->ClientSsl) > 0 ||
                    FD_ISSET(client_sock, &read_fds)) {
                    n = SSL_read(conn->ClientSsl, (char*)buf, (int)sizeof(buf));
                    if (n > 0) {
                        conn->ClientParser.Feed(buf, n);
                        if (conn->ClientParser.IsComplete()) {
                            HttpRequest req = conn->ClientParser.TakeRequest();
                            req.Host = conn->Sni;
                             req.Port = conn->TargetPort;
                            FlowInfo fi;
                            fi.SrcIp      = conn->ClientIp;
                            fi.SrcPort    = conn->ClientPort;
                            fi.DstIp      = ntohl(server_addr.sin_addr.s_addr);
                             fi.DstPort    = conn->TargetPort;
                            fi.Protocol   = Protocol::HTTPS;
                            fi.Sni        = conn->Sni;
                            fi.IsOutbound = true;
                            if (ReqCb) ReqCb(fi, req);
                            
                            
                            conn->ClientParser.Reset();
                        }
                        SSL_write(conn->ServerSsl, buf, n);
                    } else {
                        break;
                    }
                }

                if (conn->ServerSock != INVALID_SOCKET &&
                    (SSL_pending(conn->ServerSsl) > 0 ||
                     FD_ISSET(conn->ServerSock, &read_fds))) {
                    n = SSL_read(conn->ServerSsl, (char*)buf, (int)sizeof(buf));
                    if (n > 0) {
                        conn->ServerParser.Feed(buf, n);
                        if (conn->ServerParser.IsComplete()) {
                            HttpResponse resp = conn->ServerParser.TakeResponse();
                            FlowInfo fi;
                            fi.SrcIp      = conn->ClientIp;
                            fi.SrcPort    = conn->ClientPort;
                            fi.DstIp      = ntohl(server_addr.sin_addr.s_addr);
                             fi.DstPort    = conn->TargetPort;
                            fi.Protocol   = Protocol::HTTPS;
                            fi.Sni        = conn->Sni;
                            fi.IsOutbound = false;
                            if (RespCb) RespCb(fi, resp);
                            conn->ServerParser.Reset();
                        }
                        SSL_write(conn->ClientSsl, buf, n);
                    } else {
                        break;
                    }
                }
            }
        }

        SSL_CTX_free(server_ctx);
        CleanupConnection(client_sock);
    }

    void CleanupConnection(SOCKET client_sock)
    {
        std::lock_guard<std::mutex> lock(ConnMutex);
        auto it = Connections.find(client_sock);
        if (it != Connections.end()) {
            auto& conn = it->second;
            if (conn->ClientSsl) SSL_free(conn->ClientSsl);
            if (conn->ClientCtx) SSL_CTX_free(conn->ClientCtx);
            if (conn->ServerSsl) SSL_free(conn->ServerSsl);
            if (conn->ClientSock != INVALID_SOCKET) closesocket(conn->ClientSock);
            if (conn->ServerSock != INVALID_SOCKET) closesocket(conn->ServerSock);
            Connections.erase(it);
        }
    }
};

MitmProxy::MitmProxy(const Config& cfg,
                     OnHttpRequestCallback req_cb,
                     OnHttpResponseCallback resp_cb)
    : Impl_(std::make_unique<Impl>(cfg, std::move(req_cb), std::move(resp_cb)))
{
}

MitmProxy::~MitmProxy() = default;
bool MitmProxy::Start()              { return Impl_->Start(); }
void MitmProxy::Stop()               { Impl_->Stop(); }
bool MitmProxy::IsRunning() const   { return Impl_->IsRunning(); }
std::string MitmProxy::LastError() const { return Impl_->GetError(); }
void MitmProxy::OnIncomingSyn(uint32_t, uint16_t, uint32_t, uint16_t) {}





static std::string IpToString(uint32_t ip)
{
    return std::to_string((ip >> 24) & 0xFF) + "." +
           std::to_string((ip >> 16) & 0xFF) + "." +
           std::to_string((ip >> 8)  & 0xFF) + "." +
           std::to_string(ip  & 0xFF);
}

struct HttpCapture::Impl {
    Config Cfg;

    PacketCapture       Capture;
    TcpReassembler*     Reassembler = nullptr;
    MitmProxy*          Mitm        = nullptr;

    OnHttpRequestCallback  OnReq;
    OnHttpResponseCallback OnResp;
    OnTlsSniCallback       OnSni;
    OnRawPayloadCallback   OnRaw;

    std::map<uint64_t, HttpParser> HttpParsers;

    static uint64_t ParserKey(const FlowKey& key, FlowDir dir)
    {
        const uint32_t ip1 = (std::min)(key.SrcIp, key.DstIp);
        const uint32_t ip2 = (std::max)(key.SrcIp, key.DstIp);
        const uint16_t port1 = (key.SrcIp < key.DstIp) ? key.SrcPort : key.DstPort;
        const uint16_t port2 = (key.SrcIp < key.DstIp) ? key.DstPort : key.SrcPort;
        uint64_t value = (static_cast<uint64_t>(ip1) << 32) | ip2;
        value ^= (static_cast<uint64_t>(port1) << 16) | port2;
        return (value << 1) | (dir == FlowDir::ServerToClient ? 1ULL : 0ULL);
    }

    Impl(const Config& cfg) : Cfg(cfg)
    {
        Reassembler = new TcpReassembler(
            [this](const ReassembledData& rd) { OnReassembled(rd); });

        if (Cfg.HttpsMitm) {
            Mitm = new MitmProxy(Cfg,
                [this](const FlowInfo& fi, const HttpRequest& req) {
                    if (OnReq) OnReq(fi, req);
                },
                [this](const FlowInfo& fi, const HttpResponse& resp) {
                    if (OnResp) OnResp(fi, resp);
                });
        }
    }

    ~Impl()
    {
        delete Reassembler;
        delete Mitm;
    }

    void OnRawPacket(RawPacket& pkt)
    {
        
        
        
        
        if ((pkt.SrcPort == 443 || pkt.DstPort == 443) &&
            pkt.Payload && pkt.PayloadLen > 0 && pkt.Payload[0] == 0x16 &&
            pkt.IsOutbound) {
            std::string Sni;
            uint8_t TlsVersion = 0;
            if (ExtractSniFromClienthello(pkt.Payload, pkt.PayloadLen, Sni, TlsVersion) && OnSni) {
                FlowInfo Flow;
                Flow.SrcIp = pkt.SrcIp;
                Flow.SrcPort = pkt.SrcPort;
                Flow.DstIp = pkt.DstIp;
                Flow.DstPort = pkt.DstPort;
                Flow.Protocol = Protocol::HTTPS;
                Flow.Sni = Sni;
                Flow.IsOutbound = true;
                TlsSniInfo Info;
                Info.ServerName = Sni;
                Info.TlsVersion = TlsVersion;
                Info.RawClientHello.assign(pkt.Payload, pkt.Payload + pkt.PayloadLen);
                OnSni(Flow, Info);
            }
        }
        if (Cfg.EnableRawCallback && OnRaw) {
            FlowInfo fi;
            fi.SrcIp      = pkt.SrcIp;
            fi.SrcPort    = pkt.SrcPort;
            fi.DstIp      = pkt.DstIp;
            fi.DstPort    = pkt.DstPort;
            fi.IsOutbound = pkt.IsOutbound;
            fi.Protocol   = (pkt.DstPort == 443 || pkt.SrcPort == 443)
                                ? Protocol::HTTPS : Protocol::HTTP;
            OnRaw(fi, pkt.Payload, pkt.PayloadLen);
        }

        Reassembler->OnPacket(
            pkt.SrcIp, pkt.DstIp,
            pkt.SrcPort, pkt.DstPort,
            pkt.TcpSeq, pkt.TcpAck,
            pkt.Payload, pkt.PayloadLen,
            pkt.IsSyn, pkt.IsFin, pkt.IsRst,
            pkt.IsOutbound);
    }

    void OnReassembled(const ReassembledData& rd)
    {
        FlowInfo fi;
        fi.SrcIp      = rd.Key.SrcIp;
        fi.SrcPort    = rd.Key.SrcPort;
        fi.DstIp      = rd.Key.DstIp;
        fi.DstPort    = rd.Key.DstPort;
        fi.IsOutbound = (rd.Dir == FlowDir::ClientToServer);
        fi.Protocol   = (rd.Key.DstPort == 443 || rd.Key.SrcPort == 443)
                            ? Protocol::HTTPS : Protocol::HTTP;

        if (fi.Protocol == Protocol::HTTPS) {
            if (rd.Dir == FlowDir::ClientToServer && !rd.Data.empty()) {
                std::string sni;
                uint8_t tls_ver = 0;
                if (rd.Data[0] == 0x16 && ExtractSniFromClienthello(
                        rd.Data.data(), rd.Data.size(), sni, tls_ver)) {
                    fi.Sni = sni;
                    TlsSniInfo sni_info;
                    sni_info.ServerName = sni;
                    sni_info.TlsVersion = tls_ver;
                    sni_info.RawClientHello = rd.Data;
                    if (OnSni) OnSni(fi, sni_info);
                    std::cout << "[SNI] " << IpToString(fi.SrcIp) << ":"
                              << fi.SrcPort << " -> " << sni << "\n";
                }
            }
            if (!Cfg.HttpsMitm)
                return;
            
            
            return;
        }

        if (fi.Protocol == Protocol::HTTP || Cfg.HttpsMitm) {
            const uint64_t parser_key = ParserKey(rd.Key, rd.Dir);
            auto& parser = HttpParsers[parser_key];
            const bool valid = parser.Feed(rd.Data.data(), rd.Data.size());
            if (!valid) {
                parser.Reset();
                return;
            }
            if (rd.Dir == FlowDir::ClientToServer) {
                if (parser.IsComplete()) {
                    HttpRequest req = parser.TakeRequest();
                    if (OnReq) OnReq(fi, req);
                    HttpParsers.erase(parser_key);
                }
            } else {
                if (parser.IsComplete()) {
                    HttpResponse resp = parser.TakeResponse();
                    if (OnResp) OnResp(fi, resp);
                    HttpParsers.erase(parser_key);
                }
            }
        }
    }

    std::string BuildFilter()
    {
        std::string filter;
        if (Cfg.CaptureHttp && Cfg.CaptureHttps) {
            filter = "tcp";
        } else if (Cfg.CaptureHttp) {
            filter = "tcp";
        } else if (Cfg.CaptureHttps) {
            filter = "tcp";
        } else {
            filter = "false";
        }
        return filter;
    }
};

HttpCapture::HttpCapture(const Config& cfg)
    : Impl_(std::make_unique<Impl>(cfg))
{
}

HttpCapture::~HttpCapture() { Stop(); }

void HttpCapture::OnHttpRequest(OnHttpRequestCallback cb)
{
    Impl_->OnReq = std::move(cb);
}

void HttpCapture::OnHttpResponse(OnHttpResponseCallback cb)
{
    Impl_->OnResp = std::move(cb);
}

void HttpCapture::OnTlsSni(OnTlsSniCallback cb)
{
    Impl_->OnSni = std::move(cb);
}

void HttpCapture::OnRawPayload(OnRawPayloadCallback cb)
{
    Impl_->OnRaw = std::move(cb);
}

bool HttpCapture::Start()
{
    if (Impl_->Cfg.HttpsMitm && Impl_->Mitm) {
        if (!Impl_->Mitm->Start()) {
            std::cerr << "[HttpCapture] Failed to start MITM proxy\n";
            return false;
        }
    }

    auto filter = Impl_->BuildFilter();
    auto self = Impl_.get();
    bool ok = Impl_->Capture.Start(filter,
        [self](RawPacket& pkt) { self->OnRawPacket(pkt); },
        Impl_->Cfg);

    if (!ok) {
        std::cerr << "[HttpCapture] Failed to start WinDivert capture\n";
        if (Impl_->Mitm) Impl_->Mitm->Stop();
        return false;
    }

    std::cout << "[HttpCapture] Started (filter: " << filter << ")\n";
    return true;
}

void HttpCapture::Stop()
{
    Impl_->Capture.Stop();
    if (Impl_->Mitm) Impl_->Mitm->Stop();
}

bool HttpCapture::IsRunning() const
{
    return Impl_->Capture.IsRunning();
}

std::string HttpCapture::LastError() const
{
    if (Impl_->Mitm && !Impl_->Mitm->IsRunning()) {
        std::string mitm_error = Impl_->Mitm->LastError();
        if (!mitm_error.empty())
            return mitm_error;
    }
    std::string capture_error = Impl_->Capture.LastError();
    if (!capture_error.empty())
        return capture_error;
    return {};
}

void HttpCapture::Wait()
{
    while (IsRunning()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

} 





#ifdef CAPTURE_DEMO

static volatile bool G_Running = true;

void SignalHandler(int)
{
    G_Running = false;
}

std::string IpToStr(uint32_t ip)
{
    return std::to_string((ip >> 24) & 0xFF) + "." +
           std::to_string((ip >> 16) & 0xFF) + "." +
           std::to_string((ip >> 8)  & 0xFF) + "." +
           std::to_string(ip  & 0xFF);
}

int main()
{
    signal(SIGINT, SignalHandler);

    std::cout << "=== HttpCapture Demo ===\n";
    std::cout << "Capturing HTTP (port 80) and HTTPS (port 443, MITM decrypt)\n";
    std::cout << "Press Ctrl+C to stop.\n\n";

    http_capture::Config cfg;
    cfg.CaptureHttp  = true;
    cfg.CaptureHttps = true;
    cfg.HttpsMitm    = true;
    cfg.ProxyPort    = 8443;
    cfg.CaCertPath   = "CA_CERT.pem";
    cfg.CaKeyPath    = "CA_KEY.pem";

    http_capture::HttpCapture capture(cfg);

    capture.OnHttpRequest([](const http_capture::FlowInfo& fi,
                             const http_capture::HttpRequest& req) {
        std::cout << "\n[>>] " << IpToStr(fi.SrcIp) << ":" << fi.SrcPort
                  << "  " << req.Method << " " << req.Url;
        if (!fi.Sni.empty())
            std::cout << "  [SNI: " << fi.Sni << "]";
        std::cout << "\n";
        for (auto& h : req.Headers)
            std::cout << "  H: " << h.Name << ": " << h.Value << "\n";
        if (!req.Body.empty())
            std::cout << "  Body: " << req.Body.size() << " bytes\n";
    });

    capture.OnHttpResponse([](const http_capture::FlowInfo& fi,
                              const http_capture::HttpResponse& resp) {
        std::cout << "[<<] " << IpToStr(fi.DstIp) << ":" << fi.DstPort
                  << "  " << resp.StatusCode << " " << resp.Reason;
        if (!fi.Sni.empty())
            std::cout << "  [SNI: " << fi.Sni << "]";
        std::cout << "\n";
        for (auto& h : resp.Headers)
            std::cout << "  H: " << h.Name << ": " << h.Value << "\n";
        if (!resp.Body.empty())
            std::cout << "  Body: " << resp.Body.size() << " bytes\n";
    });

    capture.OnTlsSni([](const http_capture::FlowInfo& fi,
                        const http_capture::TlsSniInfo& sni) {
        std::cout << "[SNI] " << IpToStr(fi.SrcIp) << ":" << fi.SrcPort
                  << " -> " << sni.ServerName
                  << " (TLS v" << (int)sni.TlsVersion << ")\n";
    });

    if (!capture.Start()) {
        std::cerr << "Failed to start capture!\n";
        std::cerr << "Make sure WinDivert64.sys is installed (run as Administrator)\n";
        return 1;
    }

    while (G_Running && capture.IsRunning()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    capture.Stop();
    std::cout << "\n=== Capture stopped ===\n";
    return 0;
}
#endif 

