#pragma once

#include <cstddef>
#include <cstdint>

// These structures are sent as raw bytes over the chat socket. Keep them POD
// types with fixed-size fields so both sides use the same wire representation.
constexpr std::size_t ChatNameCapacity = 64;
constexpr std::size_t ChatContentCapacity = 1024;
constexpr std::size_t ChatMaxOnlineUsers = 64;

enum class ChatPacketType : std::uint32_t {
  ClientInfo = 1,
  OnlineUsers = 2,
  Message = 3,
  Notice = 4,
  QueryOnlineUsers = 5,
  UpdateUserTitle = 6,
};

struct ChatPacketHeader {
  std::uint32_t Type = 0;
  std::uint32_t Size = 0;
};

struct Msg {
  std::int32_t FromType = 0;
  char From[ChatNameCapacity]{};
  char To[ChatNameCapacity]{};
  char Content[ChatContentCapacity]{};
};

struct EnumMsg {
  std::int32_t OnlineNumber = 0;
  char OnlineUsers[ChatMaxOnlineUsers][ChatNameCapacity]{};
};

struct ClientInfo {
  std::int32_t Type = 0;
  char ClientName[ChatNameCapacity]{};
  char Title[ChatNameCapacity]{};
};

struct UserTitleUpdate {
  char UserName[ChatNameCapacity]{};
  char Title[ChatNameCapacity]{};
};
