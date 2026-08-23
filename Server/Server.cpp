#include "Server.h"
#pragma comment(lib, "ws2_32.lib")

#include <cstring>

using std::cout;
using std::endl;

std::map <SOCKET*, ClientInfo> ClientNames;

unsigned __stdcall RevcMsg(void* Args) {

	SOCKET* ClientSocket = (SOCKET*)Args;
	for (auto i : ClientNames) {
		if (i.first == ClientSocket) continue;
		std::string SendMsg =
			std::string(ClientNames[ClientSocket].ClientName) + "Joined";
		cout << SendMsg << endl;
		send(*i.first, SendMsg.data(), SendMsg.size(), 0);
	}

	EnumMsg BroadcastMsg = { 0 };
	BroadcastMsg.OnlineNumber = ClientNames.size();
	int UserIndex = 0;
	for (auto i : ClientNames) {
		if (UserIndex >= static_cast<int>(ChatMaxOnlineUsers))
			break;
		std::strncpy(BroadcastMsg.OnlineUsers[UserIndex],
					i.second.ClientName,
					sizeof(BroadcastMsg.OnlineUsers[UserIndex]) - 1);
		++UserIndex;
	}
	cout << "Broadcasting online users: " << BroadcastMsg.OnlineNumber << endl;
	send(*ClientSocket, (char*)&BroadcastMsg, sizeof(BroadcastMsg), 0);

	Msg ForawrdMsg = { 0 };
	while (true) {
		int BytesReceived = recv(*ClientSocket, (char*)&ForawrdMsg, sizeof(ForawrdMsg), 0);
		if (BytesReceived >= 0) {
			if (std::strcmp(ForawrdMsg.To, "0") == 0) {
				for (auto i : ClientNames) {
					if (i.first == ClientSocket) continue;
					cout << "Forwarding message from " << ForawrdMsg.From << " to all users" << endl;
					send(*i.first, (char*)&ForawrdMsg, sizeof(ForawrdMsg), 0);
				}
				continue;
			}
			else {
				for (auto i : ClientNames) {
					if (std::strcmp(i.second.ClientName, ForawrdMsg.To) == 0) {
						cout << "Forwarding message from " << ForawrdMsg.From << " to " << ForawrdMsg.To << endl;
						send(*i.first, (char*)&ForawrdMsg, sizeof(ForawrdMsg), 0);
					}
				}
				continue;
			}
			
		}

		for (auto i : ClientNames) {
			if (i.first == ClientSocket) continue;
			std::string SendMsg =
				std::string(ClientNames[ClientSocket].ClientName) + "Left";
			cout << SendMsg << endl;
			send(*i.first, SendMsg.data(), SendMsg.size(), 0);
		}
		cout << ClientNames[ClientSocket].ClientName << " Left" << endl;
		ClientNames.erase(ClientSocket);
		closesocket(*ClientSocket);
		delete[] ClientSocket;
		break;
	}
	return 0;
}

auto main() -> int {
	WSADATA WSAData;
	int STA = WSAStartup(MAKEWORD(2, 2), &WSAData);
	if (STA != 0) {
		cout << "Create protocol stack failed" << endl;
		return 1;
	}
	SOCKET ServerSocket = socket(AF_INET, SOCK_STREAM, 0);

	SOCKADDR_IN ServerAddr;
	ServerAddr.sin_family = AF_INET;
	ServerAddr.sin_port = htons(1145);
	ServerAddr.sin_addr.S_un.S_addr = INADDR_ANY;
	bind(ServerSocket, (sockaddr*)&ServerAddr, sizeof(ServerAddr));

	listen(ServerSocket, 5);
	cout << "Server started, waiting for clients..." << endl;
	while (true)
	{
		SOCKADDR_IN ClientAddr;
		int Length = sizeof(ClientAddr);
		auto ClientSocket = std::make_unique<SOCKET>(accept(ServerSocket, (sockaddr*)&ClientAddr, &Length));
		if (*ClientSocket == INVALID_SOCKET) {
			cout << inet_ntoa(ClientAddr.sin_addr) << "Accept failed" << endl;
			continue;
		}
		ClientInfo Info = { 0 };
		int RecvLength = recv(*ClientSocket, (char*)&Info, sizeof(Info), 0);
		if (RecvLength <= 0) {
			cout << inet_ntoa(ClientAddr.sin_addr) << "Receive failed" << endl;
			closesocket(*ClientSocket);
		}
		ClientNames.insert(std::pair<SOCKET*, ClientInfo>(ClientSocket.get(), Info));

		cout << inet_ntoa(ClientAddr.sin_addr) << " Connected, Client Name: " << Info.ClientName << endl;
		_beginthreadex(0, 0, RevcMsg, (SOCKET*)ClientSocket.get(), 0, 0);
	}
}
