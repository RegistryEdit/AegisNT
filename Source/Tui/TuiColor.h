#pragma once
// Shared production color logic. No console handle or Qt dependency: the same
// encoder/parser is exercised by unit tests and the real Win32 writer.
#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

namespace AegisNT::Tui {
enum class TerminalColorMode { None, Ansi16, TrueColor };
struct RgbColor {
  unsigned char Red = 255, Green = 255, Blue = 255;
  // ANSI palette index, not Win32 attribute bits. 255 = nearest palette color.
  unsigned char Ansi = 255;
};
inline TerminalColorMode SelectTerminalColorMode(bool Console, bool Vt,
    bool PseudoConsole, bool Advertised, bool NoColor) {
  if (!Console || NoColor) return TerminalColorMode::None;
  return Vt && (PseudoConsole || Advertised) ? TerminalColorMode::TrueColor
                                            : TerminalColorMode::Ansi16;
}
constexpr unsigned char AnsiToWin32(unsigned char Index) {
  return (Index & 10) | ((Index & 1) << 2) | ((Index & 4) >> 2);
}
inline constexpr std::array<RgbColor, 16> AnsiPalette{{
    {0,0,0}, {128,0,0}, {0,128,0}, {128,128,0},
    {0,0,128}, {128,0,128}, {0,128,128}, {192,192,192},
    {128,128,128}, {255,0,0}, {0,255,0}, {255,255,0},
    {0,0,255}, {255,0,255}, {0,255,255}, {255,255,255}}};
inline unsigned char NearestColor(RgbColor Color,
                                  const std::array<RgbColor,16> &Palette) {
  int Best = std::numeric_limits<int>::max();
  unsigned char Index = 0;
  for (unsigned char I = 0; I < 16; ++I) {
    const int R = int(Color.Red) - Palette[I].Red;
    const int G = int(Color.Green) - Palette[I].Green;
    const int B = int(Color.Blue) - Palette[I].Blue;
    const int Distance = R*R + G*G + B*B;
    if (Distance < Best) { Best = Distance; Index = I; }
  }
  return Index;
}
inline RgbColor IndexedColor(int Index) {
  if (Index < 16) return AnsiPalette[static_cast<size_t>(Index)];
  if (Index >= 232) {
    const auto V = static_cast<unsigned char>(8 + (Index - 232) * 10);
    return {V,V,V};
  }
  const auto Channel = [](int V) { return static_cast<unsigned char>(V ? 55 + V*40 : 0); };
  Index -= 16;
  return {Channel(Index/36), Channel((Index/6)%6), Channel(Index%6)};
}
inline std::string FormatTerminalColor(const std::string &Text, RgbColor Color,
    bool Bold, bool Underline, TerminalColorMode Mode) {
  if (Mode == TerminalColorMode::None || Text.empty()) return Text;
  std::string Prefix = "\x1b[";
  if (Bold) Prefix += "1;";
  if (Underline) Prefix += "4;";
  if (Mode == TerminalColorMode::TrueColor)
    Prefix += "38;2;" + std::to_string(Color.Red) + ";" +
              std::to_string(Color.Green) + ";" + std::to_string(Color.Blue);
  else {
    const int Index = Color.Ansi < 16 ? Color.Ansi : NearestColor(Color, AnsiPalette);
    Prefix += std::to_string(Index < 8 ? 30 + Index : 90 + Index - 8);
  }
  return Prefix + "m" + Text + "\x1b[0m";
}

// Consume only bounded, well-formed SGR parameters. Unsupported CSI/OSC and
// incomplete sequences are discarded, never interpreted as console commands.
template<class TextFn, class SgrFn>
inline void VisitTerminalStyles(std::string_view Text, TextFn Emit, SgrFn Sgr) {
  size_t I = 0, Start = 0;
  while (I < Text.size()) {
    if (Text[I] != '\x1b') { ++I; continue; }
    if (I > Start) Emit(Text.substr(Start, I - Start));
    ++I;
    if (I < Text.size() && Text[I] == '[') {
      const size_t Begin = ++I;
      while (I < Text.size() && !(Text[I] >= '@' && Text[I] <= '~') && Text[I] != '\x1b') ++I;
      if (I < Text.size() && Text[I] != '\x1b') {
        if (Text[I] == 'm' && I - Begin <= 256) {
          std::vector<int> Params;
          int Value = 0;
          bool Valid = true;
          for (size_t P = Begin; P < I; ++P) {
            if (Text[P] == ';') { Params.push_back(Value); Value = 0; }
            else if (Text[P] >= '0' && Text[P] <= '9')
              Value = std::min(65535, Value * 10 + Text[P] - '0');
            else { Valid = false; break; }
          }
          Params.push_back(Value);
          if (Valid && Params.size() <= 64) Sgr(Params);
        }
        ++I;
      }
    } else if (I < Text.size() && (Text[I] == ']' || Text[I] == 'P' || Text[I] == '^' || Text[I] == '_')) {
      ++I;
      while (I < Text.size() && Text[I] != '\a' &&
             !(Text[I] == '\x1b' && I + 1 < Text.size() && Text[I+1] == '\\')) ++I;
      if (I < Text.size()) I += Text[I] == '\a' ? 1 : 2;
    } else if (I < Text.size() && Text[I] != '\x1b') ++I;
    Start = I;
  }
  if (Start < Text.size()) Emit(Text.substr(Start));
}
inline std::string StripTerminalStyles(std::string_view Text) {
  std::string Out;
  VisitTerminalStyles(Text, [&](std::string_view Part) { Out.append(Part); },
                      [](const std::vector<int>&) {});
  return Out;
}

struct TerminalSgrState {
  uint16_t Base, Foreground, Background;
  bool Bold = false, Underline = false, Reverse = false;
  std::array<RgbColor,16> Palette; // Win32 order; initialized from host palette.
  explicit TerminalSgrState(uint16_t Default) : Base(Default),
      Foreground(Default & 15), Background((Default >> 4) & 15) {
    for (unsigned char I = 0; I < 16; ++I) Palette[AnsiToWin32(I)] = AnsiPalette[I];
  }
  uint16_t Attributes() const {
    uint16_t Fg = Foreground | (Bold ? 8 : 0), Bg = Background;
    if (Reverse) std::swap(Fg, Bg);
    return static_cast<uint16_t>((Base & ~0x80ff) | Fg | (Bg << 4) |
                                (Underline ? 0x8000 : 0));
  }
  void Apply(const std::vector<int> &Params) {
    for (size_t I = 0; I < Params.size(); ++I) {
      const int Code = Params[I];
      if (Code == 0) { Foreground = Base & 15; Background = (Base >> 4) & 15;
        Bold = Reverse = false; Underline = (Base & 0x8000) != 0; }
      else if (Code == 1) Bold = true;
      else if (Code == 22) Bold = false;
      else if (Code == 4) Underline = true;
      else if (Code == 24) Underline = false;
      else if (Code == 7) Reverse = true;
      else if (Code == 27) Reverse = false;
      else if (Code == 39) Foreground = Base & 15;
      else if (Code == 49) Background = (Base >> 4) & 15;
      else if (Code >= 30 && Code <= 37) Foreground = AnsiToWin32(Code - 30);
      else if (Code >= 90 && Code <= 97) Foreground = AnsiToWin32(Code - 90 + 8);
      else if (Code >= 40 && Code <= 47) Background = AnsiToWin32(Code - 40);
      else if (Code >= 100 && Code <= 107) Background = AnsiToWin32(Code - 100 + 8);
      else if (Code == 38 || Code == 48) {
        if (I + 1 >= Params.size()) return;
        int Index = -1;
        if (Params[I+1] == 2) {
          if (I + 4 >= Params.size()) return;
          if (Params[I+2] <= 255 && Params[I+3] <= 255 && Params[I+4] <= 255)
            Index = NearestColor({static_cast<unsigned char>(Params[I+2]),
                static_cast<unsigned char>(Params[I+3]), static_cast<unsigned char>(Params[I+4])}, Palette);
          I += 4;
        } else if (Params[I+1] == 5) {
          if (I + 2 >= Params.size()) return;
          const int N = Params[I+2];
          if (N < 16) Index = AnsiToWin32(N);
          else if (N <= 255) Index = NearestColor(IndexedColor(N), Palette);
          I += 2;
        } else return;
        if (Index >= 0) { if (Code == 38) Foreground = Index; else Background = Index; }
      }
    }
  }
};
} // namespace AegisNT::Tui
