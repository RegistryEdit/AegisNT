#pragma once
#ifdef _WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <WinSock2.h>
#include <WS2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif
#include <string>
#include <iostream>
#include <vector>
#include <map>
#include <thread>
#include <memory>
#include "ChatProtocol.h"

#ifdef _WIN32
using SocketHandle = SOCKET;
constexpr SocketHandle InvalidSocket = INVALID_SOCKET;
inline void CloseSocket(SocketHandle Socket) { closesocket(Socket); }
#else
using SocketHandle = int;
constexpr SocketHandle InvalidSocket = -1;
inline void CloseSocket(SocketHandle Socket) { close(Socket); }
#endif
