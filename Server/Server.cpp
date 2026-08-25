#include "Server.h"

#include <cstring>
#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <fstream>
#include <mutex>
#include <sstream>
#include <filesystem>

using std::cout;
using std::endl;

std::map<SocketHandle, ClientInfo> ClientNames;
std::mutex ClientNamesMutex;
std::mutex LogMutex;
std::ofstream LogFile(
    (std::filesystem::current_path() / "Server.log").string(),
    std::ios::app);

void Log(const char *Level, const std::string &Message) {
  const auto Now = std::chrono::system_clock::now();
  const std::time_t Time = std::chrono::system_clock::to_time_t(Now);
  std::tm LocalTime{};
#ifdef _WIN32
  localtime_s(&LocalTime, &Time);
#else
  localtime_r(&Time, &LocalTime);
#endif
  std::lock_guard<std::mutex> Lock(LogMutex);
  cout << '[' << std::put_time(&LocalTime, "%Y-%m-%d %H:%M:%S") << "] ["
       << Level << "] " << Message << endl;
  if (LogFile.is_open()) {
    LogFile << '[' << std::put_time(&LocalTime, "%Y-%m-%d %H:%M:%S") << "] ["
            << Level << "] " << Message << std::endl;
  }
}

bool ReceiveAll(SocketHandle Socket, char *Data, std::size_t Size) {
  std::size_t Received = 0;
  while (Received < Size) {
    const int Count = recv(Socket, Data + Received,
                           static_cast<int>(Size - Received), 0);
    if (Count <= 0)
      return false;
    Received += static_cast<std::size_t>(Count);
  }
  return true;
}

bool SendAll(SocketHandle Socket, const char *Data, std::size_t Size) {
  std::size_t Sent = 0;
  while (Sent < Size) {
    const int Count = send(Socket, Data + Sent,
                           static_cast<int>(Size - Sent), 0);
    if (Count <= 0)
      return false;
    Sent += static_cast<std::size_t>(Count);
  }
  return true;
}

template <typename T>
bool SendPacket(SocketHandle Socket, ChatPacketType Type, const T &Payload) {
  const ChatPacketHeader Header{static_cast<std::uint32_t>(Type),
                                static_cast<std::uint32_t>(sizeof(T))};
  return SendAll(Socket, reinterpret_cast<const char *>(&Header), sizeof(Header)) &&
         SendAll(Socket, reinterpret_cast<const char *>(&Payload), sizeof(T));
}

bool SendNotice(SocketHandle Socket, const std::string &Text) {
  const ChatPacketHeader Header{static_cast<std::uint32_t>(ChatPacketType::Notice),
                                static_cast<std::uint32_t>(Text.size())};
  return SendAll(Socket, reinterpret_cast<const char *>(&Header), sizeof(Header)) &&
         SendAll(Socket, Text.data(), Text.size());
}

void BroadcastOnlineUsers() {
  EnumMsg OnlineUsers{};
  OnlineUsers.OnlineNumber = static_cast<std::int32_t>(
      (std::min)(ClientNames.size(), ChatMaxOnlineUsers));
  int UserIndex = 0;
  for (const auto &[Socket, Info] : ClientNames) {
    if (UserIndex >= static_cast<int>(ChatMaxOnlineUsers))
      break;
    std::strncpy(OnlineUsers.OnlineUsers[UserIndex], Info.ClientName,
                 sizeof(OnlineUsers.OnlineUsers[UserIndex]) - 1);
    ++UserIndex;
  }
  for (const auto &[Socket, Info] : ClientNames)
    SendPacket(Socket, ChatPacketType::OnlineUsers, OnlineUsers);
}

void RevcMsg(SocketHandle ClientSocket) {
  {
    std::lock_guard<std::mutex> Lock(ClientNamesMutex);
    for (const auto &[Socket, Info] : ClientNames) {
      if (Socket == ClientSocket)
        continue;
      const std::string SendMsg =
          std::string(ClientNames[ClientSocket].ClientName) + " joined";
      SendNotice(Socket, SendMsg);
    }

    BroadcastOnlineUsers();
    Log("INFO", std::string(ClientNames[ClientSocket].ClientName) +
                    " joined; online users: " +
                    std::to_string(ClientNames.size()));
  }

  Msg ForwardMsg{};
  while (true) {
    ChatPacketHeader Header{};
    if (!ReceiveAll(ClientSocket, reinterpret_cast<char *>(&Header), sizeof(Header)))
      break;
    Log("DEBUG", "Received packet type " + std::to_string(Header.Type) +
                     ", payload bytes: " + std::to_string(Header.Size));
    if (Header.Type == static_cast<std::uint32_t>(ChatPacketType::QueryOnlineUsers) &&
        Header.Size == 0) {
      std::lock_guard<std::mutex> Lock(ClientNamesMutex);
      EnumMsg OnlineUsers{};
      OnlineUsers.OnlineNumber = static_cast<std::int32_t>(
          (std::min)(ClientNames.size(), ChatMaxOnlineUsers));
      int UserIndex = 0;
      for (const auto &[Socket, Info] : ClientNames) {
        if (UserIndex >= static_cast<int>(ChatMaxOnlineUsers))
          break;
        std::strncpy(OnlineUsers.OnlineUsers[UserIndex], Info.ClientName,
                     sizeof(OnlineUsers.OnlineUsers[UserIndex]) - 1);
        ++UserIndex;
      }
      SendPacket(ClientSocket, ChatPacketType::OnlineUsers, OnlineUsers);
      continue;
    }
    if (Header.Type != static_cast<std::uint32_t>(ChatPacketType::Message) ||
        Header.Size != sizeof(Msg)) {
      if (Header.Size > 1024 * 1024)
        break;
      std::vector<char> Discard(Header.Size);
      if (Header.Size && !ReceiveAll(ClientSocket, Discard.data(), Header.Size))
        break;
      continue;
    }
    if (!ReceiveAll(ClientSocket, reinterpret_cast<char *>(&ForwardMsg), sizeof(ForwardMsg)))
      break;

    std::lock_guard<std::mutex> Lock(ClientNamesMutex);
    ForwardMsg.From[sizeof(ForwardMsg.From) - 1] = '\0';
    ForwardMsg.To[sizeof(ForwardMsg.To) - 1] = '\0';
    ForwardMsg.Content[sizeof(ForwardMsg.Content) - 1] = '\0';
    const auto Sender = ClientNames.find(ClientSocket);
    if (Sender == ClientNames.end())
      break;
    Log("DEBUG", std::string("Processing message from ") +
                     Sender->second.ClientName);
    std::strncpy(ForwardMsg.From, Sender->second.ClientName,
                 sizeof(ForwardMsg.From) - 1);
    ForwardMsg.From[sizeof(ForwardMsg.From) - 1] = '\0';
    if (std::strcmp(ForwardMsg.To, "0") == 0) {
      for (const auto &[Socket, Info] : ClientNames) {
        SendPacket(Socket, ChatPacketType::Message, ForwardMsg);
      }
      Log("CHAT", std::string(ForwardMsg.From) + " -> all: " +
                      ForwardMsg.Content);
    } else {
      for (const auto &[Socket, Info] : ClientNames) {
        if (std::strcmp(Info.ClientName, ForwardMsg.To) == 0)
          SendPacket(Socket, ChatPacketType::Message, ForwardMsg);
      }
      Log("CHAT", std::string(ForwardMsg.From) + " -> " + ForwardMsg.To +
                      ": " + ForwardMsg.Content);
    }
  }

  std::lock_guard<std::mutex> Lock(ClientNamesMutex);
  const auto It = ClientNames.find(ClientSocket);
  if (It != ClientNames.end()) {
    const std::string UserName = It->second.ClientName;
    const std::string SendMsg = UserName + " left";
    for (const auto &[Socket, Info] : ClientNames) {
      if (Socket != ClientSocket)
        SendNotice(Socket, SendMsg);
    }
    ClientNames.erase(It);
    BroadcastOnlineUsers();
    Log("INFO", UserName + " left; online users: " +
                    std::to_string(ClientNames.size()));
  }
  CloseSocket(ClientSocket);
}

int main() {
#ifdef _WIN32
  SetConsoleOutputCP(CP_UTF8);
  SetConsoleCP(CP_UTF8);
  WSADATA WSAData;
  if (WSAStartup(MAKEWORD(2, 2), &WSAData) != 0) {
    Log("ERROR", "Failed to initialize the socket stack");
    return 1;
  }
#endif

  const SocketHandle ServerSocket = socket(AF_INET, SOCK_STREAM, 0);
  if (ServerSocket == InvalidSocket)
    return 1;

  sockaddr_in ServerAddr{};
  ServerAddr.sin_family = AF_INET;
  ServerAddr.sin_port = htons(1145);
  ServerAddr.sin_addr.s_addr = htonl(INADDR_ANY);
  if (bind(ServerSocket, reinterpret_cast<sockaddr *>(&ServerAddr),
           sizeof(ServerAddr)) < 0 ||
      listen(ServerSocket, 5) < 0) {
    CloseSocket(ServerSocket);
    return 1;
  }

  Log("INFO", "Chat server listening on 0.0.0.0:1145");
  while (true) {
    sockaddr_in ClientAddr{};
#ifdef _WIN32
    int Length = sizeof(ClientAddr);
#else
    socklen_t Length = sizeof(ClientAddr);
#endif
    const SocketHandle ClientSocket = accept(
        ServerSocket, reinterpret_cast<sockaddr *>(&ClientAddr), &Length);
    if (ClientSocket == InvalidSocket)
      continue;
    Log("DEBUG", "Accepted TCP connection");

    ClientInfo Info{};
    ChatPacketHeader Header{};
    if (!ReceiveAll(ClientSocket, reinterpret_cast<char *>(&Header), sizeof(Header)) ||
        Header.Type != static_cast<std::uint32_t>(ChatPacketType::ClientInfo) ||
        Header.Size != sizeof(ClientInfo) ||
        !ReceiveAll(ClientSocket, reinterpret_cast<char *>(&Info), sizeof(Info))) {
      CloseSocket(ClientSocket);
      continue;
    }
    Log("DEBUG", "Received client handshake");
    Info.ClientName[sizeof(Info.ClientName) - 1] = '\0';
    const std::string UserName = Info.ClientName;
    if (UserName.empty()) {
      Log("WARN", "Rejected connection with an empty user name");
      CloseSocket(ClientSocket);
      continue;
    }
    {
      std::lock_guard<std::mutex> Lock(ClientNamesMutex);
      const bool DuplicateName = std::any_of(
          ClientNames.begin(), ClientNames.end(), [&](const auto &Entry) {
            return UserName == Entry.second.ClientName;
          });
      if (DuplicateName) {
        Log("WARN", "Rejected duplicate user session: " + UserName);
        SendNotice(ClientSocket, "This user is already connected");
        CloseSocket(ClientSocket);
        continue;
      }
      ClientNames.emplace(ClientSocket, Info);
    }
    Log("DEBUG", "Registered chat client: " + UserName);
    std::thread(RevcMsg, ClientSocket).detach();
  }
}
