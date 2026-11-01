#pragma once
#include "TuiStyle.h"
#include <QString>
#include <vector>

namespace AegisNT::Tui {
// Search is literal and Unicode case-insensitive. No regular-expression or
// external shell interpretation; quoted pipes and Windows paths stay literal.
inline bool TerminalContains(const std::string &Text, const std::string &Needle) {
  return QString::fromStdString(Text).contains(QString::fromStdString(Needle), Qt::CaseInsensitive);
}
inline std::string TerminalPlain(const std::string &Text) {
  std::string Out;
  for (const unsigned char C : StripTerminalStyles(Text))
    if (C == '\n' || C == '\t' || C >= 32) Out += static_cast<char>(C);
  return Out;
}
inline std::string TerminalHighlight(const std::string &Text,
                                     const std::vector<std::string> &Needles,
                                     TuiInk Base) {
  const auto Safe = TerminalClean(Text);
  if (GetTerminalColorMode() == TerminalColorMode::None || Needles.empty()) return Paint(Safe, Base);
  const auto Value = QString::fromStdString(Safe);
  std::vector<bool> Mark(static_cast<size_t>(Value.size()), false);
  for (const auto &Needle : Needles) {
    const auto Query = QString::fromStdString(Needle);
    if (Query.isEmpty()) continue;
    qsizetype Start = 0;
    while ((Start = Value.indexOf(Query, Start, Qt::CaseInsensitive)) >= 0) {
      for (auto I = Start; I < Start + Query.size(); ++I) Mark[static_cast<size_t>(I)] = true;
      Start += Query.size();
    }
  }
  std::string Out;
  for (size_t I = 0; I < Mark.size();) {
    size_t End = I + 1;
    while (End < Mark.size() && Mark[End] == Mark[I]) ++End;
    const auto Part = Value.mid(static_cast<qsizetype>(I), static_cast<qsizetype>(End - I)).toStdString();
    Out += Mark[I] ? Paint(Part, TuiTone::Match) : Paint(Part, Base);
    I = End;
  }
  return Out;
}

inline std::string TerminalHighlight(const std::string &Text,
    const std::vector<std::string> &Needles, TuiTone Base = TuiTone::Plain) {
  return TerminalHighlight(Text, Needles, ToneInk(Base));
}

// Wrap already styled output by measured cells, carrying only SGR styles.
// Keyword spans survive a line break, and ANSI bytes never consume columns.
inline std::vector<std::string> TerminalWrapStyled(const std::string &Text, int Width) {
  struct Glyph { char32_t Point; std::string Style; int Cells; };
  std::vector<Glyph> Glyphs;
  std::string Style;
  const auto Points = TerminalCodepoints(Text);
  for (size_t I = 0; I < Points.size();) {
    if (Points[I] == 27 && I + 1 < Points.size() && Points[I + 1] == U'[') {
      const size_t Begin = I;
      I += 2;
      while (I < Points.size() && !(Points[I] >= U'@' && Points[I] <= U'~')) ++I;
      if (I < Points.size()) {
        if (Points[I] == U'm') {
          const auto Sequence = TerminalUtf8(Points.substr(Begin, I - Begin + 1));
          if (Sequence == "\x1b[0m" || Sequence == "\x1b[m") Style.clear();
          else Style += Sequence;
        }
        ++I;
      }
    } else {
      const char32_t Point = Points[I++];
      if (Point >= U' ' && Point != 0x7f) Glyphs.push_back({Point, Style, TerminalCellWidth(Point)});
    }
  }
  std::vector<std::string> Lines;
  Width = std::max(2, Width);
  for (size_t Begin = 0; Begin < Glyphs.size();) {
    size_t End = Begin, LastSpace = Begin;
    int Cells = 0;
    while (End < Glyphs.size() && Cells + Glyphs[End].Cells <= Width) {
      if (Glyphs[End].Point == U' ') LastSpace = End;
      Cells += Glyphs[End++].Cells;
    }
    if (End < Glyphs.size() && LastSpace > Begin) End = LastSpace;
    if (End == Begin) ++End;
    std::string Line, Current;
    for (size_t I = Begin; I < End; ++I) {
      if (Glyphs[I].Style != Current) {
        if (!Current.empty()) Line += "\x1b[0m";
        Line += Glyphs[I].Style;
        Current = Glyphs[I].Style;
      }
      Line += TerminalUtf8(std::u32string(1, Glyphs[I].Point));
    }
    if (!Current.empty()) Line += "\x1b[0m";
    Lines.push_back(std::move(Line));
    Begin = End;
    while (Begin < Glyphs.size() && Glyphs[Begin].Point == U' ') ++Begin;
  }
  if (Lines.empty()) Lines.emplace_back();
  return Lines;
}
struct TerminalSearchLine {
  size_t Number;
  std::string Text;
  // Semantic spans are metadata from the same table snapshot, never captured
  // escape sequences. Text remains the sole matching/copy payload.
  std::vector<std::pair<std::string, TuiInk>> Spans;
};
inline std::string HighlightSearchLine(const TerminalSearchLine &Line,
    const std::vector<std::string> &Queries) {
  if (Line.Spans.empty()) return TerminalHighlight(Line.Text, Queries);
  // Match the full plain row first so a literal spanning two fields still
  // highlights correctly. Offset masks include field separators.
  const auto Value = QString::fromStdString(Line.Text);
  std::vector<bool> Mask(static_cast<size_t>(Value.size()), false);
  for (const auto &Q : Queries) {
    const auto Needle = QString::fromStdString(Q);
    if (Needle.isEmpty()) continue;
    qsizetype Pos = 0;
    while ((Pos = Value.indexOf(Needle, Pos, Qt::CaseInsensitive)) >= 0) {
      for (qsizetype I = Pos; I < Pos + Needle.size(); ++I) Mask[static_cast<size_t>(I)] = true;
      Pos += Needle.size();
    }
  }
  std::string Out;
  size_t Offset = 0;
  for (const auto &[Text, Ink] : Line.Spans) {
    const auto Part = QString::fromStdString(Text);
    for (size_t I = 0; I < static_cast<size_t>(Part.size());) {
      const bool Hit = Offset + I < Mask.size() && Mask[Offset + I];
      size_t End = I + 1;
      while (End < static_cast<size_t>(Part.size()) &&
             (Offset + End < Mask.size() && Mask[Offset + End]) == Hit) ++End;
      const auto Run = Part.mid(static_cast<qsizetype>(I), static_cast<qsizetype>(End-I)).toStdString();
      Out += Paint(Run, Hit ? ToneInk(TuiTone::Match) : Ink);
      I = End;
    }
    Offset += static_cast<size_t>(Part.size());
  }
  return Out;
}
inline std::vector<TerminalSearchLine> TerminalTextLines(const std::string &Text) {
  std::vector<TerminalSearchLine> Lines;
  const auto Plain = TerminalPlain(Text);
  size_t Start = 0;
  for (size_t Number = 1; Start < Plain.size(); ++Number) {
    const auto End = Plain.find('\n', Start);
    Lines.push_back({Number, TerminalClean(Plain.substr(Start, End == std::string::npos ? End : End - Start))});
    if (End == std::string::npos) break;
    Start = End + 1;
  }
  return Lines;
}
inline std::vector<TerminalSearchLine> TerminalFindLines(
    const std::vector<TerminalSearchLine> &Lines, const std::vector<std::string> &Needles) {
  std::vector<TerminalSearchLine> Matches;
  for (const auto &Line : Lines)
    if (std::all_of(Needles.begin(), Needles.end(), [&](const auto &N) { return TerminalContains(Line.Text, N); }))
      Matches.push_back(Line);
  return Matches;
}
inline bool SplitTerminalPipeline(const std::string &Line, std::vector<std::string> &Parts, std::string &Error) {
  Parts.clear(); Error.clear();
  char Quote = 0;
  size_t Start = 0;
  for (size_t I = 0; I < Line.size(); ++I) {
    const char C = Line[I];
    if (Quote) { if (C == Quote) Quote = 0; }
    else if (C == '\'' || C == '"') Quote = C;
    else if (C == '|') { Parts.push_back(Line.substr(Start, I - Start)); Start = I + 1; }
  }
  Parts.push_back(Line.substr(Start));
  if (Quote) Error = UiText("Unclosed quote in command", "命令的引号未闭合");
  else if (Parts.size() > 8) Error = UiText("At most 8 pipeline stages.", "管道最多支持 8 段。");
  else for (const auto &Part : Parts)
    if (Part.find_first_not_of(" \t\r\n") == std::string::npos) {
      Error = UiText("Empty pipeline stage. Example: show | find \"text\"", "管道中存在空命令。例如：show | find \"文本\""); break;
    }
  return Error.empty();
}

// Completion is a preview only until Tab is pressed. Context is the segment
// after the last unquoted pipe, so `ls | gr` can complete to `ls | grep`.
inline std::vector<std::string> TerminalCompletions(
    const std::string &Input, const std::vector<std::string> &Candidates) {
  char Quote = 0;
  size_t Segment = 0;
  bool Pipe = false;
  for (size_t I = 0; I < Input.size(); ++I) {
    if (Quote) { if (Input[I] == Quote) Quote = 0; }
    else if (Input[I] == '\'' || Input[I] == '"') Quote = Input[I];
    else if (Input[I] == '|') { Segment = I + 1; Pipe = true; }
  }
  if (Quote) return {};
  while (Segment < Input.size() && Input[Segment] == ' ') ++Segment;
  const auto Prefix = QString::fromStdString(Input.substr(Segment));
  const auto Stem = Input.substr(0, Segment);
  const std::vector<std::string> PipeCommands = {"find", "grep", "findstr", "copy"};
  const auto &Pool = Pipe ? PipeCommands : Candidates;
  std::vector<std::string> Out;
  for (const auto &Candidate : Pool)
    if (QString::fromStdString(Candidate).startsWith(Prefix, Qt::CaseInsensitive) &&
        std::find(Out.begin(), Out.end(), Stem + Candidate) == Out.end())
      Out.push_back(Stem + Candidate);
  return Out;
}
} // namespace AegisNT::Tui
