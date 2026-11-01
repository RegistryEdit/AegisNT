#pragma once

#include "TuiColor.h"
#include <QChar>
#include <QList>
#include <QString>
#include <algorithm>
#include <string>
#include <vector>

namespace AegisNT::Tui {

// The Win32 host can use different widths for ambiguous/combining glyphs.
// Installed once before the reader starts; pure layout tests use wcwidth below.
inline int (*TerminalNativeCellWidth)(char32_t) = nullptr;

// Terminal cells, not UTF-8 bytes or UTF-16 units. Combining marks have no
// advance; CJK/full-width characters and common emoji occupy two cells.
inline int TerminalCellWidth(char32_t C) {
  if (C >= 0xa0 && TerminalNativeCellWidth) {
    const int Measured = TerminalNativeCellWidth(C);
    if (Measured >= 0) return Measured;
  }
  const auto Category = QChar::category(C);
  if (C < 32 || (C >= 0x7f && C < 0xa0) || Category == QChar::Mark_NonSpacing ||
      Category == QChar::Mark_Enclosing || Category == QChar::Other_Format)
    return 0;
  return C >= 0x1100 && (C <= 0x115f || C == 0x2329 || C == 0x232a ||
                         (C >= 0x2e80 && C <= 0xa4cf && C != 0x303f) ||
                         (C >= 0xac00 && C <= 0xd7a3) ||
                         (C >= 0xf900 && C <= 0xfaff) ||
                         (C >= 0xfe10 && C <= 0xfe19) ||
                         (C >= 0xfe30 && C <= 0xfe6f) ||
                         (C >= 0xff00 && C <= 0xff60) ||
                         (C >= 0xffe0 && C <= 0xffe6) ||
                         (C >= 0x1f300 && C <= 0x1faff) ||
                         (C >= 0x20000 && C <= 0x3fffd))
             ? 2
             : 1;
}

inline std::u32string TerminalCodepoints(const std::string &Text) {
  const auto Points =
      QString::fromUtf8(Text.data(), static_cast<qsizetype>(Text.size()))
          .toUcs4();
  return {Points.begin(), Points.end()};
}

inline std::string TerminalUtf8(const std::u32string &Text) {
  return QString::fromUcs4(Text.data(), static_cast<qsizetype>(Text.size()))
      .toUtf8()
      .toStdString();
}

inline int TerminalWidth(const std::u32string &Text) {
  int Width = 0;
  for (char32_t C : Text)
    Width += TerminalCellWidth(C);
  return Width;
}

inline int TerminalWidth(const std::string &Text) {
  return TerminalWidth(TerminalCodepoints(StripTerminalStyles(Text)));
}

inline std::string TerminalFit(const std::string &Text, int Width,
                               bool Right = false) {
  if (Width <= 0)
    return {};
  auto Points = TerminalCodepoints(Text);
  for (char32_t &C : Points)
    if (C < 32 || (C >= 0x7f && C < 0xa0))
      C = U' '; // Never let table data inject terminal control sequences.
  const bool Truncate = TerminalWidth(Points) > Width;
  const std::u32string Ellipsis = TerminalCellWidth(U'\u2026') <= Width ? U"\u2026" : U".";
  const int Budget = Width - (Truncate ? TerminalWidth(Ellipsis) : 0);
  std::u32string Out;
  int Used = 0;
  for (char32_t C : Points) {
    const int Cells = TerminalCellWidth(C);
    if (Used + Cells > Budget)
      break;
    Out += C;
    Used += Cells;
  }
  if (Truncate) {
    Out += Ellipsis;
    Used += TerminalWidth(Ellipsis);
  }
  const std::string Padding(static_cast<size_t>(Width - Used), ' ');
  return Right ? Padding + TerminalUtf8(Out) : TerminalUtf8(Out) + Padding;
}

// Pure line-editing state, shared by the Win32 reader and regression tests.
// Only the shell passes command history; password/form fields never do.
inline bool TerminalContinuation(char32_t C) {
  const auto Category = QChar::category(C);
  return Category == QChar::Mark_NonSpacing || Category == QChar::Mark_Enclosing || Category == QChar::Other_Format;
}
struct TerminalEditor {
  std::u32string Text;
  size_t Cursor = 0;
  static constexpr size_t MaxLength = 8192;

  void Set(const std::string &Value) {
    Text = TerminalCodepoints(Value);
    if (Text.size() > MaxLength)
      Text.resize(MaxLength);
    Cursor = Text.size();
  }
  void Insert(char32_t C) {
    if (C >= 32 && C != 0x7f && Text.size() < MaxLength) {
      Text.insert(Text.begin() + static_cast<ptrdiff_t>(Cursor), C);
      ++Cursor;
    }
  }
  void Left() {
    if (!Cursor)
      return;
    --Cursor;
    while (Cursor && TerminalContinuation(Text[Cursor]))
      --Cursor;
  }
  void Right() {
    if (Cursor >= Text.size())
      return;
    ++Cursor;
    while (Cursor < Text.size() && TerminalContinuation(Text[Cursor]))
      ++Cursor;
  }
  void Backspace() {
    const size_t End = Cursor;
    Left();
    Text.erase(Cursor, End - Cursor);
  }
  void Delete() {
    const size_t Begin = Cursor;
    Right();
    Text.erase(Begin, Cursor - Begin);
    Cursor = Begin;
  }
  // Ctrl+W / Ctrl+Backspace: erase the previous word and report the cut so
  // Ctrl+Y can yank it back.
  std::u32string EraseWord() {
    const size_t End = Cursor;
    while (Cursor && Text[Cursor - 1] == U' ')
      --Cursor;
    while (Cursor && Text[Cursor - 1] != U' ')
      --Cursor;
    const std::u32string Killed = Text.substr(Cursor, End - Cursor);
    Text.erase(Cursor, End - Cursor);
    return Killed;
  }
  // Ctrl+Left: jump to the start of the current/previous word.
  void WordLeft() {
    while (Cursor && Text[Cursor - 1] == U' ')
      --Cursor;
    while (Cursor && Text[Cursor - 1] != U' ')
      --Cursor;
  }
  // Ctrl+Right: jump to the start of the next word.
  void WordRight() {
    while (Cursor < Text.size() && Text[Cursor] != U' ')
      ++Cursor;
    while (Cursor < Text.size() && Text[Cursor] == U' ')
      ++Cursor;
  }
  // Ctrl+Delete: erase the word in front of the cursor (including its
  // trailing separator) and report it for yank.
  std::u32string DeleteWord() {
    const size_t Begin = Cursor;
    while (Cursor < Text.size() && Text[Cursor] != U' ')
      ++Cursor;
    while (Cursor < Text.size() && Text[Cursor] == U' ')
      ++Cursor;
    const std::u32string Killed = Text.substr(Begin, Cursor - Begin);
    Text.erase(Begin, Cursor - Begin);
    Cursor = Begin;
    return Killed;
  }
  // Ctrl+V / yank: insert a UTF-8 run honoring MaxLength.
  void InsertText(const std::string &Value) {
    for (const char32_t C : TerminalCodepoints(Value))
      Insert(C);
  }
};

// Longest common prefix over candidates (ASCII case-insensitive), used by Tab
// so "use fi" extends to "use File" before candidates are listed.
inline std::string TerminalCommonPrefix(const std::vector<std::string> &Texts) {
  if (Texts.empty())
    return {};
  std::u32string Common = TerminalCodepoints(Texts.front());
  const auto Lower = [](char32_t C) {
    return C >= U'A' && C <= U'Z' ? C + (U'a' - U'A') : C;
  };
  for (size_t I = 1; I < Texts.size() && !Common.empty(); ++I) {
    const auto Points = TerminalCodepoints(Texts[I]);
    size_t J = 0;
    while (J < Common.size() && J < Points.size() &&
           Lower(Common[J]) == Lower(Points[J]))
      ++J;
    Common.resize(J);
  }
  return TerminalUtf8(Common);
}

} // namespace AegisNT::Tui
