#pragma once
#include "TuiConsole.h"
#include "TuiText.h"
#include <atomic>
#include <cctype>

namespace AegisNT::Tui {
// Common presentation; never changes the host palette or GUI.
inline std::atomic_bool TerminalChinese{false};
inline std::string UiText(const char *English, const char *Chinese) {
  return TerminalChinese.load() ? Chinese : English;
}
enum class TuiTone { Title, Accent, Muted, Success, Warning, Error, Active,
                     Plain, Path, Header, Type, Size, Time, Parameter, Match };
struct TuiInk { RgbColor Color; bool Bold = false, Underline = false; };
inline RgbColor ToneColor(TuiTone Tone) {
  switch (Tone) {
  case TuiTone::Title: return {92,226,255,14};
  case TuiTone::Accent: return {105,155,255,12};
  case TuiTone::Muted: return {142,157,177,8};
  case TuiTone::Success: return {86,220,143,10};
  case TuiTone::Warning: return {255,198,88,11};
  case TuiTone::Error: return {255,103,125,9};
  case TuiTone::Active: return {106,242,255,14};
  case TuiTone::Path: return {174,195,219,7};
  case TuiTone::Header: return {167,182,255,13};
  case TuiTone::Type: return {195,169,235,13};
  case TuiTone::Size: return {140,194,196,3};
  case TuiTone::Time: return {152,172,194,8};
  case TuiTone::Parameter: return {188,169,239,13};
  case TuiTone::Match: return {255,224,102,11};
  default: return {232,238,246,15};
  }
}
inline TuiInk ToneInk(TuiTone Tone) {
  return {ToneColor(Tone), Tone == TuiTone::Title || Tone == TuiTone::Accent ||
      Tone == TuiTone::Header || Tone == TuiTone::Error || Tone == TuiTone::Match,
      Tone == TuiTone::Active};
}
inline std::string Paint(const std::string &Text, TuiInk Ink) {
  return RgbColorize(Text, Ink.Color, Ink.Bold, Ink.Underline);
}
inline std::string Paint(const std::string &Text, TuiTone Tone) {
  return Paint(Text, ToneInk(Tone));
}

inline int TerminalColumns() {
  CONSOLE_SCREEN_BUFFER_INFO Info{};
  if (GetConsoleScreenBufferInfo(ConsoleWriteHandle(), &Info))
    return std::max(12, static_cast<int>(Info.srWindow.Right - Info.srWindow.Left + 1));
  return 80;
}
inline std::string TerminalClean(const std::string &Text) {
  auto Points = TerminalCodepoints(Text);
  for (auto &C : Points)
    if (C < 32 || (C >= 0x7f && C < 0xa0)) C = U' ';
  return TerminalUtf8(Points);
}

inline TuiInk FileNameInk(const std::string &Name, bool Directory, bool Hidden = false) {
  if (Hidden) return {{120,132,150,8}};
  if (Directory) return {{105,220,255,14}, true};
  const auto Dot = Name.find_last_of('.');
  std::string Extension = Dot == std::string::npos ? "" : Name.substr(Dot);
  for (char &C : Extension) C = static_cast<char>(std::tolower(static_cast<unsigned char>(C)));
  if (Extension == ".exe" || Extension == ".dll" || Extension == ".sys") return {{255,177,92,11}};
  if (Extension == ".cpp" || Extension == ".h" || Extension == ".c" || Extension == ".py" || Extension == ".rs") return {{142,193,255,12}};
  if (Extension == ".json" || Extension == ".xml" || Extension == ".yaml" || Extension == ".yml") return {{215,151,255,13}};
  if (Extension == ".log" || Extension == ".txt" || Extension == ".md") return {{214,224,235,7}};
  if (Extension == ".png" || Extension == ".jpg" || Extension == ".jpeg" || Extension == ".gif") return {{93,225,179,10}};
  if (Extension == ".zip" || Extension == ".7z" || Extension == ".rar" || Extension == ".gz") return {{240,207,111,3}};
  return ToneInk(TuiTone::Plain);
}
inline std::string PaintFileName(const std::string &Name, bool Directory, bool Hidden = false) {
  return Paint(TerminalClean(Name), FileNameInk(Name, Directory, Hidden));
}
// No padding; middle ellipsis retains drive and final path component.
inline std::string TerminalClip(const std::string &Text, int Width, bool Middle = false) {
  const auto Points = TerminalCodepoints(TerminalClean(Text));
  if (Width <= 0) return {};
  if (TerminalWidth(Points) <= Width) return TerminalUtf8(Points);
  const std::u32string Mark = ConsoleVtEnabled() ? U"…" : U"...";
  const auto Ellipsis = TerminalWidth(Mark) <= Width ? Mark : std::u32string(Width, U'.');
  const int MarkWidth = TerminalWidth(Ellipsis);
  const int HeadBudget = Middle ? (Width - MarkWidth) / 3 : Width - MarkWidth;
  std::u32string Head, Tail;
  int Used = 0;
  for (const auto C : Points) {
    if (Used + TerminalCellWidth(C) > HeadBudget) break;
    Head += C;
    Used += TerminalCellWidth(C);
  }
  if (Middle) {
    const int Budget = Width - MarkWidth - Used;
    int UsedTail = 0;
    size_t Start = Points.size();
    while (Start && UsedTail + TerminalCellWidth(Points[Start - 1]) <= Budget)
      UsedTail += TerminalCellWidth(Points[--Start]);
    while (Start < Points.size() && TerminalCellWidth(Points[Start]) == 0) ++Start;
    Tail = Points.substr(Start);
  }
  return TerminalUtf8(Head + Ellipsis + Tail);
}
// Horizontal rule in console cells; ASCII when the host cannot render VT.
inline std::string TerminalRule(int Cells) {
  if (Cells <= 0) return {};
  const std::string Unit = ConsoleVtEnabled() ? "─" : "-";
  std::string Out;
  Out.reserve(Unit.size() * static_cast<size_t>(Cells));
  for (int I = 0; I < Cells; ++I) Out += Unit;
  return Out;
}
// 80 columns: "  ▌ SESSION ─────…────" (ASCII hosts keep "-- SESSION").
inline std::string SectionHeading(const std::string &Title, int Columns = 0) {
  const int Width = (Columns > 0 ? Columns : TerminalColumns()) - 1;
  const std::string Text = TerminalClip(Title, std::max(1, Width - 6));
  const bool Unicode = ConsoleVtEnabled();
  const int Used = 2 + (Unicode ? 2 : 3) + TerminalWidth(Text) + 1;
  const int Fill = std::max(0, Width - Used);
  if (!Unicode)
    return Paint("  -- ", TuiTone::Muted) + Paint(Text, TuiTone::Title) +
           Paint(" " + TerminalRule(Fill), TuiTone::Muted) + "\n";
  return "  " + Paint("▌ ", TuiTone::Title) + Paint(Text, TuiTone::Title) +
         Paint(" " + TerminalRule(Fill), TuiTone::Muted) + "\n";
}
inline std::string NoticeText(const std::string &Text, TuiTone Tone) {
  const std::string Label = Tone == TuiTone::Error ? UiText("ERROR", "错误")
      : Tone == TuiTone::Warning ? UiText("WARN", "注意")
      : Tone == TuiTone::Success ? UiText("OK", "完成") : UiText("INFO", "提示");
  // Classic msfconsole tags: [+]-success, [*]-info, [!]-warning, [-]-error;
  // bracket ASCII renders on every host, color comes from Tone.
  const std::string Tag = Tone == TuiTone::Error ? "[-] "
      : Tone == TuiTone::Warning ? "[!] "
      : Tone == TuiTone::Success ? "[+] " : "[*] ";
  const std::string Pad(static_cast<size_t>(std::max(0, 8 - TerminalWidth(Label))), ' ');
  return "  " + Paint(Tag + Label, Tone) +
         Paint(Pad + (ConsoleVtEnabled() ? " │ " : " | "), TuiTone::Muted) + Text;
}
// Shared view selector: "  File  [Protected]  Monitor", clipped when too wide.
inline std::string TabStrip(const std::vector<std::string> &Names, int Active,
                            int Columns = 0) {
  const int Width = (Columns > 0 ? Columns : TerminalColumns()) - 1;
  std::string Plain;
  for (size_t I = 0; I < Names.size(); ++I) {
    if (I) Plain += "  ";
    Plain += Names[I];
  }
  if (2 + TerminalWidth(Plain) > Width)
    return "  " + Paint(TerminalClip(Plain, Width - 2), TuiTone::Muted);
  std::string Out = "  ";
  for (size_t I = 0; I < Names.size(); ++I) {
    if (I) Out += "  ";
    const bool Current = static_cast<int>(I) == Active;
    Out += Paint(Current ? "[" + Names[I] + "]" : Names[I],
                 Current ? TuiTone::Active : TuiTone::Muted);
  }
  return Out;
}
// Framed brand banner with an optional host/identity row; falls back to one
// plain line on very narrow terminals.
inline std::string RenderTerminalBanner(const std::string &Version,
                                        const std::string &Mode, int Columns,
                                        const std::string &Info = {}) {
  const std::string Brand = "AegisNT";
  const std::string Plain = Brand + "  v" + Version + "  /  " + Mode;
  if (Columns - 1 < 30)
    return Paint("  " + TerminalClip(Plain, Columns - 3), TuiTone::Title) + "\n";
  const int Width = std::max(24, std::min(Columns - 1, 64));
  const int Inner = Width - 6;
  const bool Unicode = ConsoleVtEnabled();
  const std::string Mark = Unicode ? "◆ " : "";
  std::string Rest = TerminalClip("  v" + Version + "  /  " + Mode,
                                  std::max(0, Inner - TerminalWidth(Brand) -
                                                   TerminalWidth(Mark)));
  const int Left = TerminalWidth(Mark) + TerminalWidth(Brand) + TerminalWidth(Rest);
  const std::string Pad(static_cast<size_t>(std::max(0, Inner - Left)), ' ');
  const std::string Rule = Paint(TerminalRule(Inner + 2), TuiTone::Muted);
  const auto Corner = [&](const char *UnicodeChar, const char *Ascii) {
    return Paint(Unicode ? UnicodeChar : Ascii, TuiTone::Muted);
  };
  std::string Out = "  " + Corner("╭", "+") + Rule + Corner("╮", "+") + "\n";
  Out += "  " + Corner("│", "|") + " " +
         (Unicode ? Paint(Mark, TuiTone::Title) : std::string()) +
         Paint(Brand, TuiTone::Title) + Paint(Rest, TuiTone::Muted) + Pad + " " +
         Corner("│", "|") + "\n";
  if (!Info.empty()) {
    const auto Clipped = TerminalClip(Info, std::max(0, Inner - 3));
    // Interior must match the brand row: 3 + info + pad + 1 == Inner + 2.
    const std::string InfoPad(static_cast<size_t>(
        std::max(0, Inner - 2 - TerminalWidth(Clipped))), ' ');
    Out += "  " + Corner("│", "|") + "   " + Paint(Clipped, TuiTone::Muted) +
           InfoPad + " " + Corner("│", "|") + "\n";
  }
  Out += "  " + Corner("╰", "+") + Rule + Corner("╯", "+") + "\n";
  return Out;
}
struct TerminalPromptContext {
  std::string Page = "home";
  std::string Path;
  bool SignedIn = false;
  bool Chinese = false;
};
inline std::string RenderTerminalPrompt(const TerminalPromptContext &Context,
                                        const std::string &Time, int Columns) {
  const int Width = std::max(10, Columns - 1);
  const bool Unicode = ConsoleVtEnabled();
  const std::string Sep = Columns < 60 ? " " : Unicode ? " › " : " > ";
  const std::string State = Context.SignedIn
      ? (Context.Chinese ? "已登录" : "signed-in")
      : (Context.Chinese ? "访客" : "guest");
  const std::string Fixed = "[" + Time + "] AegisNT";
  const std::string Page = TerminalClean(Context.Page);
  const std::string Info = Page + Sep + State;
  std::string Out = Paint("[" + Time + "] ", TuiTone::Muted) + Paint("AegisNT", TuiTone::Title);
  int Available = Width - TerminalWidth(Fixed) - TerminalWidth(Sep);
  if (Available > 0) {
    // Reserve cells for the status dot so a tight fit never overflows.
    const int DotCells = Unicode ? 2 : 0;
    const auto Fitted = TerminalClip(Info, std::max(0, Available - DotCells));
    if (!Fitted.empty()) {
      Out += Paint(Sep, TuiTone::Muted);
      const TuiTone StateTone = Context.SignedIn ? TuiTone::Success : TuiTone::Warning;
      const size_t Split = Fitted.find(Sep);
      if (Split == std::string::npos)
        Out += Paint(Fitted, TuiTone::Accent);
      else
        Out += Paint(Fitted.substr(0, Split), TuiTone::Accent) +
               Paint(Sep, TuiTone::Muted) +
               Paint(std::string(Unicode ? (Context.SignedIn ? "● " : "○ ") : "") +
                         Fitted.substr(Split + Sep.size()), StateTone);
      Available -= TerminalWidth(Fitted) + TerminalWidth(Sep) + DotCells;
      if (!Context.Path.empty() && Available >= 5)
        Out += Paint(Sep, TuiTone::Muted) +
               Paint(TerminalClip(Context.Path, Available, true), TuiTone::Path);
    }
  }
  if (TerminalWidth(Fixed) > Width) Out = Paint(TerminalClip(Fixed, Width), TuiTone::Title);
  return Out + "\n" + Paint(Unicode ? "╰─❯ " : "+- > ", TuiTone::Title);
}
} // namespace AegisNT::Tui
