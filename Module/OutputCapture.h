#pragma once

#define WIN32_LEAN_AND_MEAN
#include <fcntl.h>
#include <io.h>
#include <windows.h>

#include <chrono>
#include <cstdio>
#include <functional>
#include <iostream>
#include <sstream>
#include <streambuf>
#include <string>
#include <thread>

namespace Module {

struct OutputNormalizer {
  enum class State {
    Normal,
    Esc,
    Csi,
  };

  State CurrentState = State::Normal;
  bool PendingCr = false;

  std::string Feed(const char *Data, size_t Len) {
    std::string Output;
    Output.reserve(Len);

    for (size_t Index = 0; Index < Len; ++Index) {
      const unsigned char Ch = static_cast<unsigned char>(Data[Index]);

      if (PendingCr) {
        PendingCr = false;
        if (Ch == '\n') {
          Output.push_back('\n');
          continue;
        }
        Output.push_back('\n');
      }

      if (CurrentState == State::Normal) {
        if (Ch == 0x1B) {
          CurrentState = State::Esc;
          continue;
        }
        if (Ch == '\r') {
          PendingCr = true;
          continue;
        }
        Output.push_back(static_cast<char>(Ch));
        continue;
      }

      if (CurrentState == State::Esc) {
        if (Ch == '[') {
          CurrentState = State::Csi;
        } else {
          CurrentState = State::Normal;
        }
        continue;
      }

      if (Ch >= 0x40 && Ch <= 0x7E) {
        CurrentState = State::Normal;
      }
    }

    return Output;
  }

  std::string Flush() {
    if (PendingCr) {
      PendingCr = false;
      return "\n";
    }
    return "";
  }
};

inline std::string NormalizeCapturedOutput(const std::string &Input) {
  std::string Output;
  Output.reserve(Input.size());

  OutputNormalizer N;
  Output = N.Feed(Input.data(), Input.size());

  return Output;
}

inline std::string CaptureOutputStreaming(
    const std::function<void()> &Func,
    const std::function<void(const std::string &)> &OnChunk) {
  struct IostreamCaptureBuf final : std::streambuf {
    OutputNormalizer Normalizer;
    std::ostringstream Full;
    std::function<void(const std::string &)> OnChunkCallback;
    std::string Raw;

    explicit IostreamCaptureBuf(
        std::function<void(const std::string &)> Callback)
        : OnChunkCallback(std::move(Callback)) {}

    void Emit(const char *Data, std::size_t Len) {
      if (Len == 0)
        return;
      std::string Chunk = Normalizer.Feed(Data, Len);
      if (!Chunk.empty()) {
        Full << Chunk;
        if (OnChunkCallback)
          OnChunkCallback(Chunk);
      }
    }

    int overflow(int ch) override {
      if (ch == traits_type::eof()) {
        return traits_type::not_eof(ch);
      }
      const char C = static_cast<char>(ch);
      Emit(&C, 1);
      return ch;
    }

    std::streamsize xsputn(const char *s, std::streamsize n) override {
      if (n > 0 && s) {
        Emit(s, static_cast<std::size_t>(n));
      }
      return n;
    }
  };

  auto FallbackIostream = [&](const char *Reason) -> std::string {
    if (OnChunk) {
      OnChunk(std::string("[!] OutputCapture fallback: ") + Reason + "\n");
    }

    IostreamCaptureBuf buf(OnChunk);
    std::streambuf *oldCout = std::cout.rdbuf(&buf);
    std::streambuf *oldCerr = std::cerr.rdbuf(&buf);
    const std::ios::fmtflags oldCoutFlags = std::cout.flags();
    const std::ios::fmtflags oldCerrFlags = std::cerr.flags();
    std::cout.setf(std::ios::unitbuf);
    std::cerr.setf(std::ios::unitbuf);

    Func();

    std::cout.rdbuf(oldCout);
    std::cerr.rdbuf(oldCerr);
    std::cout.flags(oldCoutFlags);
    std::cerr.flags(oldCerrFlags);

    std::string Tail = buf.Normalizer.Flush();
    if (!Tail.empty()) {
      buf.Full << Tail;
      if (OnChunk)
        OnChunk(Tail);
    }
    return buf.Full.str();
  };

  HANDLE ReadPipe = nullptr;
  HANDLE WritePipe = nullptr;
  SECURITY_ATTRIBUTES Sa = {sizeof(Sa), nullptr, TRUE};

  auto EnsureCrtStream = [&](FILE *Stream, const char *Name) -> bool {
    const int Fd = _fileno(Stream);
    if (Fd >= 0)
      return true;

    if (freopen("NUL", "w", Stream) != nullptr) {
      return _fileno(Stream) >= 0;
    }

    if (OnChunk) {
      OnChunk(std::string("[!] OutputCapture: failed to init ") + Name +
              " (fileno=" + std::to_string(Fd) + ")\n");
    }
    return false;
  };

  if (!CreatePipe(&ReadPipe, &WritePipe, &Sa, 0)) {
    return FallbackIostream("CreatePipe failed");
  }

  if (!EnsureCrtStream(stdout, "stdout") ||
      !EnsureCrtStream(stderr, "stderr")) {
    CloseHandle(ReadPipe);
    CloseHandle(WritePipe);
    return FallbackIostream("CRT stdout/stderr not available");
  }

  HANDLE OldStdout = GetStdHandle(STD_OUTPUT_HANDLE);
  HANDLE OldStderr = GetStdHandle(STD_ERROR_HANDLE);
  const int StdoutFd = _fileno(stdout);
  const int StderrFd = _fileno(stderr);
  int OldStdoutFd = _dup(StdoutFd);
  int OldStderrFd = _dup(StderrFd);
  if (OldStdoutFd == -1 || OldStderrFd == -1) {
    CloseHandle(ReadPipe);
    CloseHandle(WritePipe);
    return FallbackIostream("dup(stdout/stderr) failed");
  }

  int WriteFd = _open_osfhandle(reinterpret_cast<intptr_t>(WritePipe), _O_TEXT);
  if (WriteFd == -1) {
    _close(OldStdoutFd);
    _close(OldStderrFd);
    CloseHandle(ReadPipe);
    CloseHandle(WritePipe);
    return FallbackIostream("open_osfhandle(WritePipe) failed");
  }

  fflush(stdout);
  fflush(stderr);
  SetStdHandle(STD_OUTPUT_HANDLE, WritePipe);
  SetStdHandle(STD_ERROR_HANDLE, WritePipe);
  if (_dup2(WriteFd, StdoutFd) != 0 || _dup2(WriteFd, StderrFd) != 0) {

    SetStdHandle(STD_OUTPUT_HANDLE, OldStdout);
    SetStdHandle(STD_ERROR_HANDLE, OldStderr);
    _close(WriteFd);
    _dup2(OldStdoutFd, StdoutFd);
    _dup2(OldStderrFd, StderrFd);
    _close(OldStdoutFd);
    _close(OldStderrFd);
    CloseHandle(ReadPipe);
    return FallbackIostream("dup2(stdout/stderr) failed");
  }

  setvbuf(stdout, nullptr, _IONBF, 0);
  setvbuf(stderr, nullptr, _IONBF, 0);
  std::cout.setf(std::ios::unitbuf);
  std::cerr.setf(std::ios::unitbuf);

  OutputNormalizer Normalizer;
  std::ostringstream FullOutput;
  bool ReaderDone = false;
  std::thread Reader([&] {
    char Buffer[4096];
    DWORD Read = 0;
    while (ReadFile(ReadPipe, Buffer, sizeof(Buffer), &Read, nullptr) &&
           Read > 0) {
      std::string Chunk = Normalizer.Feed(Buffer, static_cast<size_t>(Read));
      if (!Chunk.empty()) {
        FullOutput << Chunk;
        if (OnChunk) {
          OnChunk(Chunk);
        }
      }
    }
    std::string Tail = Normalizer.Flush();
    if (!Tail.empty()) {
      FullOutput << Tail;
      if (OnChunk) {
        OnChunk(Tail);
      }
    }
    ReaderDone = true;
  });

  Func();

  fflush(stdout);
  fflush(stderr);
  _dup2(OldStdoutFd, StdoutFd);
  _dup2(OldStderrFd, StderrFd);
  _close(OldStdoutFd);
  _close(OldStderrFd);
  SetStdHandle(STD_OUTPUT_HANDLE, OldStdout);
  SetStdHandle(STD_ERROR_HANDLE, OldStderr);
  _close(WriteFd);

  if (Reader.joinable()) {
    Reader.join();
  }
  CloseHandle(ReadPipe);

  (void)ReaderDone;
  return FullOutput.str();
}

inline std::string CaptureOutput(const std::function<void()> &Func) {
  return CaptureOutputStreaming(Func, {});
}

} // namespace Module
