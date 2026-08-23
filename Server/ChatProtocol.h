#pragma once

#include <cstddef>

// These structures are sent as raw bytes over the chat socket. Keep them POD
// types with fixed-size fields so both sides use the same wire representation.
constexpr std::size_t ChatNameCapacity = 64;
constexpr std::size_t ChatContentCapacity = 1024;
constexpr std::size_t ChatMaxOnlineUsers = 64;

struct Msg {
  int FromType = 0;
  char From[ChatNameCapacity]{};
  char To[ChatNameCapacity]{};
  char Content[ChatContentCapacity]{};
};

struct EnumMsg {
  int OnlineNumber = 0;
  char OnlineUsers[ChatMaxOnlineUsers][ChatNameCapacity]{};
};

struct ClientInfo {
  int Type = 0;
  char ClientName[ChatNameCapacity]{};
};
