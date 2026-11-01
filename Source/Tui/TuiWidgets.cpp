// ============================================================
// 控制台通用控件实现：表格文本渲染、同步对话框、剪贴板、格式化工具。
// （unity 包含进 AegisNT.cpp，全局作用域）
// ============================================================

#include "TuiWidgets.h"

#include "TuiConsole.h"
#include "TuiCore.h"
#include "TuiText.h"
#include "TuiStyle.h"
#include "TuiSearch.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace AegisNT::Tui {

// ------------------------------------------------------------
// 小工具
// ------------------------------------------------------------

std::string LowerAscii(std::string Text) {
  for (char &C : Text)
    C = static_cast<char>(std::tolower(static_cast<unsigned char>(C)));
  return Text;
}

std::string UpperAscii(std::string Text) {
  for (char &C : Text)
    C = static_cast<char>(std::toupper(static_cast<unsigned char>(C)));
  return Text;
}

std::string TrimAscii(const std::string &Text) {
  size_t Begin = 0;
  size_t End = Text.size();
  while (Begin < End &&
         std::isspace(static_cast<unsigned char>(Text[Begin])) != 0)
    ++Begin;
  while (End > Begin &&
         std::isspace(static_cast<unsigned char>(Text[End - 1])) != 0)
    --End;
  return Text.substr(Begin, End - Begin);
}

bool StartsWithCi(const std::string &Text, const std::string &Prefix) {
  if (Prefix.size() > Text.size())
    return false;
  return LowerAscii(Text.substr(0, Prefix.size())) == LowerAscii(Prefix);
}

namespace {

// Console display cells (CJK, surrogate pairs and combining marks included).
int GlyphCount(const std::string &Text) { return TerminalWidth(Text); }

// 按 codepoint 切分，保证多字节字符不被截断。
std::vector<std::string> SplitGlyphs(const std::string &Text) {
  std::vector<std::string> Glyphs;
  for (size_t Index = 0; Index < Text.size();) {
    const unsigned char Lead = static_cast<unsigned char>(Text[Index]);
    size_t Length = 1;
    if ((Lead & 0xE0) == 0xC0)
      Length = 2;
    else if ((Lead & 0xF0) == 0xE0)
      Length = 3;
    else if ((Lead & 0xF8) == 0xF0)
      Length = 4;
    if (Index + Length > Text.size())
      Length = 1;
    Glyphs.push_back(Text.substr(Index, Length));
    Index += Length;
  }
  return Glyphs;
}

std::string Repeat(char Char, int Count) {
  return Count > 0 ? std::string(static_cast<size_t>(Count), Char)
                   : std::string();
}

// 单元格：截断到 Width（超出补 "…"）并按对齐方式补齐。
std::string FitCell(const std::string &Text, int Width, bool RightAlign) {
  return TerminalFit(Text, Width, RightAlign);
}

int ConsoleColumns() {
  CONSOLE_SCREEN_BUFFER_INFO Info{};
  if (GetConsoleScreenBufferInfo(ConsoleWriteHandle(), &Info))
    return std::max(
        20, static_cast<int>(Info.srWindow.Right - Info.srWindow.Left + 1));
  return 80;
}

} // namespace

std::vector<std::string> WrapText(const std::string &Text, int Width,
                                  const std::string &Indent) {
  std::vector<std::string> Lines;
  if (Width <= 0)
    Width = 80;
  const int Available = std::max(2, Width - TerminalWidth(Indent));
  size_t Begin = 0;
  while (Begin <= Text.size()) {
    size_t End = Text.find('\n', Begin);
    if (End == std::string::npos)
      End = Text.size();
    const std::string Paragraph = Text.substr(Begin, End - Begin);
    Begin = End + 1;
    if (Paragraph.empty()) {
      Lines.push_back(Indent);
    } else {
      const auto Points = TerminalCodepoints(Paragraph);
      size_t Position = 0;
      while (Position < Points.size()) {
        size_t EndPoint = Position;
        size_t LastSpace = Position;
        int Cells = 0;
        while (EndPoint < Points.size() &&
               Cells + TerminalCellWidth(Points[EndPoint]) <= Available) {
          if (Points[EndPoint] == U' ')
            LastSpace = EndPoint;
          Cells += TerminalCellWidth(Points[EndPoint++]);
        }
        if (EndPoint < Points.size() && LastSpace > Position)
          EndPoint = LastSpace;
        if (EndPoint == Position)
          ++EndPoint;
        Lines.push_back(Indent + TerminalUtf8(Points.substr(
                                     Position, EndPoint - Position)));
        Position = EndPoint;
        while (Position < Points.size() && Points[Position] == U' ')
          ++Position;
      }
    }
    if (End == Text.size())
      break;
  }
  return Lines;
}

// ------------------------------------------------------------
// TuiTable
// ------------------------------------------------------------

void TuiTable::Rebuild() {
  Visible.clear();
  const std::string Needle = LowerAscii(Filter);
  for (size_t Index = 0; Index < Rows.size(); ++Index) {
    if (!Needle.empty()) {
      std::string Haystack;
      for (const std::string &Cell : Rows[Index].Cells) {
        Haystack += Cell;
        Haystack += ' ';
      }
      if (!TerminalContains(Haystack, Filter))
        continue;
    }
    Visible.push_back(static_cast<int>(Index));
  }
  if (Visible.empty()) {
    Selected = 0;
    Scroll = 0;
  } else {
    Selected = std::clamp(Selected, 0, static_cast<int>(Visible.size()) - 1);
  }

  ColumnWidths.assign(Headers.size(), 0);
  for (size_t Column = 0; Column < Headers.size(); ++Column)
    ColumnWidths[Column] = std::min<int>(48, GlyphCount(Headers[Column]));
  for (const TuiRow &Row : Rows) {
    for (size_t Column = 0;
         Column < ColumnWidths.size() && Column < Row.Cells.size(); ++Column) {
      ColumnWidths[Column] =
          std::max(ColumnWidths[Column], GlyphCount(Row.Cells[Column]));
      ColumnWidths[Column] = std::min<int>(48, ColumnWidths[Column]);
    }
  }
  if (RightAlign.size() < Headers.size())
    RightAlign.resize(Headers.size(), false);
}

const TuiRow *TuiTable::Current() const {
  if (Selected < 0 || Selected >= static_cast<int>(Visible.size()))
    return nullptr;
  return &Rows[static_cast<size_t>(Visible[static_cast<size_t>(Selected)])];
}

int TuiTable::CurrentRowIndex() const {
  if (Selected < 0 || Selected >= static_cast<int>(Visible.size()))
    return -1;
  return Visible[static_cast<size_t>(Selected)];
}

void TuiTable::CopyCurrentToClipboard() const {
  const TuiRow *Row = Current();
  if (!Row)
    return;
  std::string Line;
  for (size_t Index = 0; Index < Row->Cells.size(); ++Index) {
    if (Index)
      Line += '\t';
    Line += Row->Cells[Index];
  }
  TuiClipboard::Set(Line);
}

TuiInk TuiCellInk(const TuiTable &Table, const TuiRow &Row, size_t Column) {
  const std::string Header = Column < Table.Headers.size() ? LowerAscii(Table.Headers[Column]) : "";
  const std::string Value = Column < Row.Cells.size() ? LowerAscii(TrimAscii(Row.Cells[Column])) : "";
  if (Header == "#" || Header == "index") return ToneInk(TuiTone::Muted);
  if (Header.find("path") != std::string::npos || Header == "location") return ToneInk(TuiTone::Path);
  if (Header.find("size") != std::string::npos || Header == "bytes") return ToneInk(TuiTone::Size);
  if (Header.find("time") != std::string::npos || Header == "modified" || Header == "created") return ToneInk(TuiTone::Time);
  if (Header == "type" || Header == "start type" || Header == "protocol") return ToneInk(TuiTone::Type);
  if (Header == "state" || Header == "status" || Header == "value") {
    if (Value == "running" || Value == "enabled" || Value == "on" || Value == "true" ||
        Value == "yes" || Value == "established" || Value == "connected" || Value == "ok") return ToneInk(TuiTone::Success);
    if (Value == "failed" || Value == "error" || Value == "denied") return ToneInk(TuiTone::Error);
    if (Value == "stopped" || Value == "disabled" || Value == "off" || Value == "false" ||
        Value == "no" || Value == "listening" || Value.find("pending") != std::string::npos ||
        Value.find("wait") != std::string::npos) return ToneInk(TuiTone::Warning);
  }
  if (Header == "name" || Header == "file" || Header == "filename") {
    const bool File = Row.Kind == TuiRowKind::Directory ||
        std::find(Table.Headers.begin(), Table.Headers.end(), "Modified") != Table.Headers.end();
    if (File && Column < Row.Cells.size()) return FileNameInk(Row.Cells[Column], Row.Kind == TuiRowKind::Directory, Row.Hidden);
    return ToneInk(TuiTone::Accent);
  }
  if (Header == "group" || Header == "service") return ToneInk(TuiTone::Accent);
  if (Header == "pid" || Header.find("port") != std::string::npos || Header.find("address") != std::string::npos)
    return ToneInk(TuiTone::Path);
  return ToneInk(TuiTone::Plain);
}

namespace {
thread_local TuiTableCapture *ActiveTableCapture = nullptr;

std::string RenderTableRows(const TuiTable &Table, int Begin, int Count,
                            int Columns, bool Numbered) {
  const int Full = std::max(10, Columns - 1);
  const bool HasNumber = !Table.Headers.empty() && Table.Headers.front() == "#";
  std::vector<std::string> Headers = Table.Headers;
  std::vector<bool> Align = Table.RightAlign;
  Align.resize(Headers.size(), false);
  if (Numbered && !HasNumber) {
    Headers.insert(Headers.begin(), "#");
    Align.insert(Align.begin(), true);
  }
  if (Headers.empty()) return {};
  std::vector<std::vector<std::string>> Rows;
  std::vector<bool> Directories;
  std::vector<std::vector<TuiInk>> Inks;
  const int End = std::min(Begin + Count, static_cast<int>(Table.Visible.size()));
  for (int Pos = Begin; Pos < End; ++Pos) {
    const auto &Row = Table.Rows.at(static_cast<size_t>(Table.Visible.at(Pos)));
    auto Cells = Row.Cells;
    Cells.resize(Table.Headers.size());
    const bool Directory = Row.Kind == TuiRowKind::Directory;
    if (Directory && !Cells.empty() && !Cells[0].empty() &&
        Cells[0].back() != '/' && Cells[0].back() != '\\') Cells[0] += '/';
    if (Numbered) {
      if (HasNumber) Cells[0] = std::to_string(Pos + 1);
      else Cells.insert(Cells.begin(), std::to_string(Pos + 1));
    }
    std::vector<TuiInk> RowInks;
    if (Numbered && !HasNumber) RowInks.push_back(ToneInk(TuiTone::Muted));
    for (size_t C = 0; C < Table.Headers.size(); ++C) RowInks.push_back(TuiCellInk(Table, Row, C));
    Inks.push_back(std::move(RowInks));
    Rows.push_back(std::move(Cells));
    Directories.push_back(Directory);
  }
  std::vector<int> Widths(Headers.size()), Min(Headers.size());
  for (size_t C = 0; C < Headers.size(); ++C) {
    Widths[C] = std::min(48, TerminalWidth(Headers[C]));
    for (const auto &Row : Rows)
      Widths[C] = std::min(60, std::max(Widths[C], TerminalWidth(TerminalClean(Row[C]))));
    const bool Index = Headers[C] == "#";
    Min[C] = Index ? std::max(1, static_cast<int>(std::to_string(End).size()))
        : std::min(Widths[C], std::max(C == (Numbered && !HasNumber ? 1u : 0u) ? 12 : 7,
                                       std::min(10, TerminalWidth(Headers[C]))));
    Widths[C] = std::max(Widths[C], Min[C]);
  }
  const int Gaps = 2 + static_cast<int>(Headers.size() - 1) * 2;
  const auto Sum = [](const std::vector<int> &V) {
    int Total = 0; for (int N : V) Total += N; return Total;
  };
  // "  │ " prefix and " │" suffix cost 4 more cells than the unframed layout.
  const bool Framed = Gaps + Sum(Min) + 4 <= Full;
  const int Available = Full - (Framed ? 4 : 0);
  if (Gaps + Sum(Min) > Available) {
    std::string Out;
    for (size_t R = 0; R < Rows.size(); ++R) {
      Out += SectionHeading("#" + std::to_string(Begin + static_cast<int>(R) + 1) +
                              (Directories[R] ? UiText("  Directory", "  目录") : ""), Columns);
      for (size_t C = 0; C < Headers.size(); ++C) {
        if (Headers[C] == "#") continue;
        const auto Label = TerminalClip(Headers[C], std::max(3, std::min(16, Available / 3)));
        const std::string Prefix = "  " + Label + ": ";
        const auto Lines = TerminalWrapStyled(TerminalHighlight(Rows[R][C], {Table.Filter}, Inks[R][C]), Available - TerminalWidth(Prefix));
        for (size_t I = 0; I < Lines.size(); ++I)
          Out += (I == 0 ? Paint(Prefix, TuiTone::Muted)
                         : std::string(static_cast<size_t>(TerminalWidth(Prefix)), ' ')) +
                 Lines[I] + '\n';
      }
    }
    return Out;
  }
  while (Gaps + Sum(Widths) > Available) {
    size_t Best = Widths.size();
    for (size_t C = 0; C < Widths.size(); ++C)
      if (Widths[C] > Min[C] && (Best == Widths.size() || Widths[C] > Widths[Best])) Best = C;
    if (Best == Widths.size()) break;
    --Widths[Best];
  }
  const auto RowText = [&](const std::vector<std::string> &Cells, bool Header, size_t RowIndex) {
    std::string Line = "  ";
    for (size_t C = 0; C < Widths.size(); ++C) {
      if (C) Line += "  ";
      const std::string Value = TerminalClip(Cells[C], Widths[C]);
      const auto Padding = std::string(static_cast<size_t>(std::max(0, Widths[C] - TerminalWidth(Value))), ' ');
      std::string Cell = !Header && Align[C] ? Padding + Value : Value + Padding;
      if (Header) Cell = Paint(Cell, ToneInk(C % 2 ? TuiTone::Header : TuiTone::Title));
      else Cell = TerminalHighlight(Cell, {Table.Filter}, Inks[RowIndex][C]);
      Line += Cell;
    }
    return Line + '\n';
  };
  std::string Out;
  if (Framed) {
    const int Inner = Gaps + Sum(Widths) - 2; // RowText's leading two cells are replaced by "  │ "
    const auto Corner = [](const char *Unicode, const char *Ascii) {
      // Dim frame keeps the data rows as the visual focus.
      return Paint(std::string(ConsoleVtEnabled() ? Unicode : Ascii), TuiTone::Muted);
    };
    const auto FrameRule = [&] { return Paint(TerminalRule(Inner + 2), TuiTone::Muted); };
    const auto Edge = [&](const std::string &Row) {
      std::string Body = Row.substr(2);
      if (!Body.empty() && Body.back() == '\n') Body.pop_back();
      return "  " + Corner("│", "|") + " " + Body + " " + Corner("│", "|") + "\n";
    };
    Out += "  " + Corner("╭", "+") + FrameRule() + Corner("╮", "+") + '\n';
    Out += Edge(RowText(Headers, true, 0));
    Out += "  " + Corner("├", "+") + FrameRule() + Corner("┤", "+") + '\n';
    for (size_t R = 0; R < Rows.size(); ++R) Out += Edge(RowText(Rows[R], false, R));
    Out += "  " + Corner("╰", "+") + FrameRule() + Corner("╯", "+") + '\n';
    return Out;
  }
  Out = RowText(Headers, true, 0);
  std::string Rule = "  ";
  for (int I = 2; I < Gaps + Sum(Widths); ++I) Rule += ConsoleVtEnabled() ? "─" : "-";
  Out += Paint(Rule, TuiTone::Muted) + '\n';
  for (size_t R = 0; R < Rows.size(); ++R) Out += RowText(Rows[R], false, R);
  return Out;
}
std::string WrappedMeta(const std::string &Text, int Columns) {
  std::string Out;
  for (const auto &Line : WrapText(Text, std::max(10, Columns - 1), "  "))
    Out += Paint(Line, TuiTone::Muted) + '\n';
  return Out;
}
} // namespace

void TuiTableView::Capture(const TuiTable &Table) {
  Snapshot = Table;
  Snapshot.Rebuild();
  Page = 1;
  All = false;
  Valid = true;
}
int TuiTableView::PageCount() const {
  return std::max(1, (static_cast<int>(Snapshot.Visible.size()) + PageSize - 1) / PageSize);
}
bool TuiTableView::SetPage(int Number) {
  if (!Valid || Number < 1 || Number > PageCount()) return false;
  Page = Number;
  All = false;
  return true;
}
const TuiRow *TuiTableView::RowAt(int Number) const {
  if (!Valid || Number < 1 || Number > static_cast<int>(Snapshot.Visible.size())) return nullptr;
  return &Snapshot.Rows.at(static_cast<size_t>(Snapshot.Visible.at(Number - 1)));
}
std::string TuiTableView::Render(int Columns) const {
  if (!Valid) return {};
  if (Columns <= 0) Columns = TerminalColumns();
  const int Total = static_cast<int>(Snapshot.Visible.size());
  const int Begin = All ? 0 : (Page - 1) * PageSize;
  const int End = All ? Total : std::min(Begin + PageSize, Total);
  std::string Out = RenderTableRows(Snapshot, Begin, End - Begin, Columns, true);
  if (!Total)
    Out += WrappedMeta(Snapshot.Filter.empty()
        ? UiText("No rows. Try refresh or another view.", "暂无数据，可使用 refresh 或切换视图。")
        : UiText("No matching rows. Use 'filter' to clear.", "没有匹配项，输入 filter 清除筛选。"), Columns);
  const auto Count = std::to_string(Snapshot.Rows.size());
  const std::string Summary = TerminalChinese.load()
      ? "行 " + std::to_string(Total ? Begin + 1 : 0) + "-" + std::to_string(End) +
        " / 匹配 " + std::to_string(Total) + " / 总计 " + Count
      : "Rows " + std::to_string(Total ? Begin + 1 : 0) + "-" + std::to_string(End) +
        " / " + std::to_string(Total) + " matched / " + Count + " total";
  std::string Tail = All ? UiText(" / all", " / 全部")
      : UiText("   Page ", "   页 ") + std::to_string(Page) + "/" +
            std::to_string(PageCount());
  if (!All && PageCount() > 1) {
    // Position bar after "Page x/y" (plain glyphs: WrappedMeta re-wraps by
    // measured cells and must not see SGR bytes here).
    const int Cells = std::min(PageCount(), 20);
    const int Filled = std::clamp(Page * Cells / PageCount(), 1, Cells);
    const std::string Full = ConsoleVtEnabled() ? "█" : "#";
    const std::string Empty = ConsoleVtEnabled() ? "░" : "-";
    for (int I = 0; I < Cells; ++I)
      Tail += I < Filled ? Full : Empty;
  }
  Out += WrappedMeta(Summary + Tail, Columns);
  if (!Snapshot.Filter.empty()) Out += WrappedMeta(UiText("Filter: ", "筛选：") + TerminalClean(Snapshot.Filter), Columns);
  if (PageCount() > 1)
    Out += WrappedMeta("next-page  prev-page  show <n>  show all", Columns);
  return Out;
}
TuiTableCapture::TuiTableCapture(const TuiTable *Value)
    : Target(Value), Previous(ActiveTableCapture) { ActiveTableCapture = this; }
TuiTableCapture::~TuiTableCapture() { ActiveTableCapture = Previous; }
std::string TuiTableToText(const TuiTable &Table, int MaxRows) {
  if (ActiveTableCapture && ActiveTableCapture->Target == &Table) {
    ActiveTableCapture->View.Capture(Table);
    return TuiTableCapture::Marker;
  }
  TuiTable Copy = Table;
  Copy.Rebuild();
  const int Total = static_cast<int>(Copy.Visible.size());
  const int Limit = MaxRows > 0 ? std::min(MaxRows, Total) : Total;
  const int Columns = TerminalColumns();
  std::string Out = RenderTableRows(Copy, 0, Limit, Columns, false);
  if (!Total) Out += WrappedMeta(Table.Filter.empty() ? UiText("No rows.", "暂无数据。")
      : UiText("No matching rows. Use 'filter' to clear.", "没有匹配项，输入 filter 清除筛选。"), Columns);
  if (Limit < Total) Out += WrappedMeta(std::to_string(Total - Limit) + UiText(" more; use filter.", " 条未显示，可使用 filter。"), Columns);
  return Out;
}

void ShowSelectedRowDetails(const TuiTable &Table, const TuiRow &Row) {
  for (size_t Column = 0; Column < Row.Cells.size(); ++Column) {
    const std::string Header = Column < Table.Headers.size() ? Table.Headers[Column] : std::to_string(Column + 1);
    const std::string Prefix = "  " + TerminalClip(Header, std::max(3, TerminalColumns()/3)) + ": ";
    const auto Lines = TerminalWrapStyled(TerminalHighlight(Row.Cells[Column], {Table.Filter},
        TuiCellInk(Table, Row, Column)), TerminalColumns() - 1 - TerminalWidth(Prefix));
    for (size_t I = 0; I < Lines.size(); ++I)
      WriteConsoleLine((I == 0 ? Paint(Prefix, TuiTone::Muted) : std::string(TerminalWidth(Prefix), ' ')) + Lines[I]);
  }
  if (!Row.Detail.empty()) {
    const auto Lines = TerminalTextLines(Row.Detail);
    for (const auto &Line : Lines)
      for (const auto &Part : TerminalWrapStyled(TerminalHighlight(Line.Text, {Table.Filter}, TuiTone::Path), TerminalColumns()-1))
        WriteConsoleLine(Part);
  }
}

// ------------------------------------------------------------
// 剪贴板
// ------------------------------------------------------------

namespace TuiClipboard {

void Set(const std::string &Text) {
  if (!OpenClipboard(nullptr))
    return;
  EmptyClipboard();
  const int WideLength = MultiByteToWideChar(
      CP_UTF8, 0, Text.c_str(), static_cast<int>(Text.size()), nullptr, 0);
  if (WideLength > 0) {
    HGLOBAL Memory =
        GlobalAlloc(GMEM_MOVEABLE, (WideLength + 1) * sizeof(wchar_t));
    if (Memory) {
      if (auto *Wide = static_cast<wchar_t *>(GlobalLock(Memory))) {
        MultiByteToWideChar(CP_UTF8, 0, Text.c_str(),
                            static_cast<int>(Text.size()), Wide, WideLength);
        Wide[WideLength] = L'\0';
        GlobalUnlock(Memory);
        if (!SetClipboardData(CF_UNICODETEXT, Memory))
          GlobalFree(Memory);
      } else {
        GlobalFree(Memory);
      }
    }
  }
  CloseClipboard();
}

} // namespace TuiClipboard

// ------------------------------------------------------------
// 十六进制解析 / 转储
// ------------------------------------------------------------

bool ParseHexBytes(const std::string &Text, std::vector<unsigned char> &Bytes,
                   std::string *ErrorText) {
  Bytes.clear();
  std::string Clean;
  for (char C : Text) {
    if (C == ' ' || C == '\t' || C == '\r' || C == '\n' || C == ',' ||
        C == ':' || C == '-')
      continue;
    Clean += C;
  }
  if (Clean.size() >= 2 && Clean[0] == '0' &&
      (Clean[1] == 'x' || Clean[1] == 'X'))
    Clean.erase(0, 2);
  if (Clean.empty() || (Clean.size() % 2) != 0) {
    if (ErrorText)
      *ErrorText = "Hex bytes must have an even number of digits.";
    return false;
  }
  for (size_t Index = 0; Index < Clean.size(); Index += 2) {
    const std::string Pair = Clean.substr(Index, 2);
    char *End = nullptr;
    const long Value = std::strtol(Pair.c_str(), &End, 16);
    if (End == nullptr || *End != '\0') {
      if (ErrorText)
        *ErrorText = "Invalid hex byte: " + Pair;
      return false;
    }
    Bytes.push_back(static_cast<unsigned char>(Value));
  }
  return true;
}

std::string FormatHexAscii(const std::vector<unsigned char> &Buffer,
                           uint64_t BaseOffset) {
  std::string Out;
  char Line[160];
  for (size_t Offset = 0; Offset < Buffer.size(); Offset += 16) {
    const size_t Count = std::min<size_t>(16, Buffer.size() - Offset);
    std::snprintf(Line, sizeof(Line), "%012llX  ",
                  static_cast<unsigned long long>(BaseOffset + Offset));
    Out += Line;
    for (size_t Index = 0; Index < 16; ++Index) {
      if (Index < Count) {
        std::snprintf(Line, sizeof(Line), "%02X ", Buffer[Offset + Index]);
        Out += Line;
      } else {
        Out += "   ";
      }
      if (Index == 7)
        Out += ' ';
    }
    Out += " |";
    for (size_t Index = 0; Index < Count; ++Index) {
      const unsigned char Byte = Buffer[Offset + Index];
      Out += (Byte >= 0x20 && Byte < 0x7F) ? static_cast<char>(Byte) : '.';
    }
    Out += "|\n";
  }
  return Out;
}

// ------------------------------------------------------------
// 对话框（同步文本执行器）
// ------------------------------------------------------------

namespace {

const char *NoticeTag(NoticeKind Kind) {
  switch (Kind) {
  case NoticeKind::Success:
    return "[+]";
  case NoticeKind::Warning:
    return "[!]";
  case NoticeKind::Error:
    return "[-]";
  case NoticeKind::Info:
  default:
    return "[*]";
  }
}

AnsiColor NoticeColor(NoticeKind Kind) {
  switch (Kind) {
  case NoticeKind::Success:
    return AnsiColor::Green;
  case NoticeKind::Warning:
    return AnsiColor::Yellow;
  case NoticeKind::Error:
    return AnsiColor::Red;
  case NoticeKind::Info:
  default:
    return AnsiColor::Cyan;
  }
}

std::string FieldPrompt(const TuiField &Field, const std::string &Suffix) {
  std::string Prompt = "  " + Field.Label;
  if (!Field.Hint.empty())
    Prompt += " (" + Field.Hint + ")";
  Prompt += Suffix;
  return Prompt;
}

} // namespace

void TuiDialogStack::Notice(const std::string &Text, NoticeKind Kind) {
  if (Kind == NoticeKind::Error) ConsoleOutputCapture::MarkFailed();
  WriteConsoleLine(NoticeText(Text, Kind == NoticeKind::Error ? TuiTone::Error
      : Kind == NoticeKind::Warning ? TuiTone::Warning
      : Kind == NoticeKind::Success ? TuiTone::Success : TuiTone::Accent));
}

void TuiDialogStack::PushMessage(const std::string &Title,
                                 const std::string &Text, NoticeKind Kind) {
  TuiDialog Dialog;
  Dialog.Title = Title;
  Dialog.Body = Text;
  Dialog.PrimaryLabel = "OK";
  Dialog.SecondaryLabel.clear();
  Push(std::move(Dialog));
  Notice(Text, Kind);
}

bool TuiDialogStack::RenderFieldInput(TuiField &Field) {
  if (Field.ReadOnly || Field.Kind == TuiFieldKind::ReadOnly) {
    WriteConsoleLine("  " + Field.Label + ": " + Field.Value);
    return true;
  }

  if (Field.Kind == TuiFieldKind::Combo) {
    if (Field.Choices.empty())
      return true;
    for (size_t Index = 0; Index < Field.Choices.size(); ++Index)
      WriteConsoleLine("    " + std::to_string(Index + 1) + ") " +
                       Field.Choices[Index]);
    for (;;) {
      const int Current = std::clamp(
          Field.Choice, 0, static_cast<int>(Field.Choices.size()) - 1);
      std::string Line;
      if (!AskLine(
              FieldPrompt(Field, " [" + std::to_string(Current + 1) + "]: "),
              false, Line))
        return false;
      const std::string Text = TrimAscii(Line);
      if (Text.empty())
        return true;
      char *End = nullptr;
      const long Value = std::strtol(Text.c_str(), &End, 10);
      if (End != nullptr && *End == '\0' && Value >= 1 &&
          Value <= static_cast<long>(Field.Choices.size())) {
        Field.Choice = static_cast<int>(Value - 1);
        return true;
      }
      WriteConsoleLine(AnsiColorize(UiText("Enter a number between 1 and ", "请输入 1 至 ") +
                                        std::to_string(Field.Choices.size()) +
                                        UiText(".", " 之间的序号。"),
                                    AnsiColor::Red, true));
    }
  }

  if (Field.Kind == TuiFieldKind::Check) {
    for (;;) {
      std::string Line;
      if (!AskLine(FieldPrompt(Field, Field.Checked ? " [Y/n]: " : " [y/N]: "),
                   false, Line))
        return false;
      const std::string Text = LowerAscii(TrimAscii(Line));
      if (Text.empty())
        return true;
      if (Text == "y" || Text == "yes" || Text == "1" || Text == "true") {
        Field.Checked = true;
        return true;
      }
      if (Text == "n" || Text == "no" || Text == "0" || Text == "false") {
        Field.Checked = false;
        return true;
      }
      WriteConsoleLine(AnsiColorize(UiText("Enter y or n.", "请输入 y 或 n。"), AnsiColor::Red, true));
    }
  }

  if (Field.Kind == TuiFieldKind::Password) {
    std::string Line;
    if (!AskLine(FieldPrompt(Field, ": "), true, Line))
      return false;
    if (!Line.empty())
      Field.Value = Line;
    return true;
  }

  if (Field.Kind == TuiFieldKind::Multiline) {
    std::string Collected;
    for (;;) {
      std::string Line;
      if (!AskLine(FieldPrompt(Field, UiText(" (end with '.'): ", "（单独输入 '.' 结束）：")), false, Line))
        return false;
      if (TrimAscii(Line) == ".")
        break;
      Collected += Line;
      Collected += '\n';
    }
    if (!Collected.empty())
      Field.Value = Collected;
    return true;
  }

  std::string Line;
  if (!AskLine(FieldPrompt(Field, ": "), false, Line))
    return false;
  if (!TrimAscii(Line).empty())
    Field.Value = Line;
  return true;
}

void TuiDialogStack::Push(TuiDialog Dialog) {
  WriteConsoleLine(AnsiColorize(Dialog.Title, AnsiColor::Cyan, true));
  if (!Dialog.Body.empty()) {
    for (const std::string &Line :
         WrapText(Dialog.Body, ConsoleColumns(), "  "))
      WriteConsoleLine(Line);
  }

  for (int Round = 0; Round < 5; ++Round) {
    for (TuiField &Field : Dialog.Fields) {
      if (!RenderFieldInput(Field)) {
        Notice(UiText("Cancelled; no changes applied.", "已取消，未应用更改。"), NoticeKind::Info);
        return;
      }
    }
    Dialog.Error.clear();
    if (Dialog.Validate) {
      const std::string Error = Dialog.Validate(Dialog);
      if (!Error.empty()) {
        WriteConsoleLine(AnsiColorize("[-] " + Error, AnsiColor::Red, true));
        continue;
      }
    }
    if (Dialog.OnSubmit)
      Dialog.OnSubmit(Dialog);
    return;
  }
  WriteConsoleLine(AnsiColorize(UiText("Cancelled.", "已取消。"), AnsiColor::Red, true));
}

// ------------------------------------------------------------
// 便捷对话框
// ------------------------------------------------------------

void ConfirmDialog(TuiDialogStack &Stack, const std::string &Title,
                   const std::string &Text, std::function<void()> OnYes,
                   std::string YesLabel, std::string NoLabel, std::string Id) {
  (void)Id;
  (void)NoLabel;
  TuiDialog Dialog;
  Dialog.Title = Title;
  Dialog.Body = Text;
  Dialog.PrimaryLabel = std::move(YesLabel);
  TuiField Field;
  Field.Label = std::move(Dialog.PrimaryLabel);
  Field.Kind = TuiFieldKind::Check;
  Field.Checked = false;
  Dialog.Fields.push_back(std::move(Field));
  Dialog.OnSubmit = [OnYes = std::move(OnYes)](TuiDialog &Result) {
    if (Result.Fields.empty() || !Result.Fields.front().Checked)
      return;
    if (OnYes)
      OnYes();
  };
  Stack.Push(std::move(Dialog));
}

void PromptTextDialog(TuiDialogStack &Stack, const std::string &Title,
                      const std::string &Label, const std::string &Initial,
                      std::function<void(std::string)> OnSubmit,
                      std::string Hint) {
  TuiDialog Dialog;
  Dialog.Title = Title;
  TuiField Field;
  Field.Label = Label;
  Field.Value = Initial;
  Field.Hint = std::move(Hint);
  Dialog.Fields.push_back(std::move(Field));
  Dialog.OnSubmit = [OnSubmit = std::move(OnSubmit)](TuiDialog &Submitted) {
    if (OnSubmit && !Submitted.Fields.empty())
      OnSubmit(Submitted.Fields.front().Value);
  };
  Stack.Push(std::move(Dialog));
}

void DetailDialog(TuiDialogStack &Stack, const std::string &Title,
                  const std::vector<TuiRow> &Rows) {
  TuiDialog Dialog;
  Dialog.Title = Title;
  Dialog.PrimaryLabel = "Close";
  Dialog.SecondaryLabel.clear();
  std::string Body;
  for (const TuiRow &Row : Rows) {
    std::string Line;
    for (size_t Index = 0; Index < Row.Cells.size(); ++Index) {
      if (Index)
        Line += ": ";
      Line += Row.Cells[Index];
    }
    Body += Line;
    Body += '\n';
  }
  Dialog.Body = Body;
  Stack.Push(std::move(Dialog));
}

// ------------------------------------------------------------
// 行解析
// ------------------------------------------------------------

void EraseLastUtf8(std::string &Text) {
  if (Text.empty())
    return;
  size_t Start = Text.size() - 1;
  while (Start > 0 && (static_cast<unsigned char>(Text[Start]) & 0xC0) == 0x80)
    --Start;
  Text.erase(Start);
}

bool ParseCommandLine(const std::string &Line, std::vector<std::string> &Args,
                      std::string &Error) {
  Args.clear();
  Error.clear();
  std::string Token;
  char Quote = 0;
  bool Started = false;
  // Backslashes are literal: Windows paths must not become escape sequences.
  for (char C : Line) {
    if (Quote) {
      if (C == Quote)
        Quote = 0;
      else
        Token += C;
    } else if (C == '\'' || C == '"') {
      Quote = C;
      Started = true;
    } else if (std::isspace(static_cast<unsigned char>(C))) {
      if (Started) {
        Args.push_back(Token);
        Token.clear();
        Started = false;
      }
    } else {
      Token += C;
      Started = true;
    }
  }
  if (Quote) {
    Error = UiText("Unclosed quote in command", "命令的引号未闭合");
    return false;
  }
  if (Started)
    Args.push_back(Token);
  return true;
}

} // namespace AegisNT::Tui
