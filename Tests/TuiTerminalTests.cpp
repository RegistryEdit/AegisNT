#define NOMINMAX
#include "../Source/Tui/TuiConsole.h"
#include "../Source/Tui/TuiText.h"
#include "../Source/Tui/TuiStyle.h"
#include "../Source/Tui/TuiSearch.h"
#include "../Source/Tui/TuiWidgets.h"
#include <QJsonObject>
#include <QJsonValue>
#include <QString>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <stdexcept>
#include <windows.h>

namespace {
struct Answer {
  bool Accepted;
  std::string Text;
};
std::deque<Answer> Answers;
std::string Output;
int NetworkRequests = 0;
int SessionChanges = 0;
int Checks = 0;
bool SavedLoginEnabled = false;
bool VtEnabled = false;
bool ColorEnabled = false;
struct AccountState {
  bool IsLoggedIn = false;
  QString UserName;
} Account;
void Check(bool Value, const char *Message) {
  ++Checks;
  if (!Value)
    throw std::runtime_error(Message);
}
QJsonValue ConfigurationValue(const char *, const char *Key, QJsonValue Default) {
  if (SavedLoginEnabled) {
    const std::string Name(Key);
    if (Name == "AutoLogin" || Name == "SaveCredentials")
      return true;
    if (Name == "UserName")
      return QString("saved-test-user");
    if (Name == "Password")
      return QString("synthetic-test-password");
  }
  return Default;
}
QString DecryptPassword(const QString &Text) { return Text; }
QString Sha256Hex(const QString &Text) { return Text; }
void HandleLoginSuccess(void *, const QJsonObject &, const QString &,
                        const QString &, bool, bool) {}
} // namespace

namespace AegisNT {
void NotifyAccountSessionChanged() { ++SessionChanges; }
namespace Tui {
bool HttpPostJson(const QString &, const QJsonObject &, int, QJsonObject *,
                  QString *Error) {
  ++NetworkRequests;
  *Error = "test server unavailable";
  return false;
}
void MarkMutated() {}
HANDLE ConsoleWriteHandle() { return INVALID_HANDLE_VALUE; }
bool AnsiEnabled() { return ColorEnabled; }
bool ConsoleVtEnabled() { return VtEnabled; }
TerminalColorMode GetTerminalColorMode() {
  return ColorEnabled ? (VtEnabled ? TerminalColorMode::TrueColor
                                   : TerminalColorMode::Ansi16)
                      : TerminalColorMode::None;
}
bool TerminalTrueColorEnabled() { return ColorEnabled && VtEnabled; }
std::string AnsiColorize(const std::string &Text, AnsiColor, bool) {
  return ColorEnabled ? "\x1b[93m" + Text + "\x1b[0m" : Text;
}
std::string RgbColorize(const std::string &Text, RgbColor Color, bool Bold, bool Underline) {
  return FormatTerminalColor(Text, Color, Bold, Underline, GetTerminalColorMode());
}
void WriteConsoleText(const char *Data, size_t Size) {
  Output.append(Data, Size);
}
void WriteConsoleLine(const std::string &Text) { Output += Text + '\n'; }
void ConsoleOutputCapture::MarkFailed() {}
bool AskLine(const std::string &, bool, std::string &Line) {
  if (Answers.empty()) {
    Line.clear();
    return false;
  }
  const auto Answer = Answers.front();
  Answers.pop_front();
  Line = Answer.Text;
  return Answer.Accepted;
}
} // namespace Tui
} // namespace AegisNT

// Exercise the production implementation, not a duplicated parser or renderer.
#include "../Source/Tui/TuiSession.cpp"
#include "../Source/Tui/TuiWidgets.cpp"

int main() {
  using namespace AegisNT::Tui;
  try {
    ColorEnabled = VtEnabled = true;
    Check(Paint("brand",TuiTone::Title).find("38;2;92;226;255")!=std::string::npos,"real RGB palette in renderer");
    Check(Paint("muted",TuiTone::Muted).find("38;2;142;157;177")!=std::string::npos,"muted RGB palette");
    Check(TerminalWidth(Paint("中文e\xcc\x81",TuiTone::Active))==5,"styles consume no cells");
    Check(TerminalWidth(std::string("\x1b]0;title\a中文"))==4,"OSC consumes no cells");
    TuiTable Colors;
    Colors.Headers={"Name","Size","Type","Modified"};
    Colors.Rows={{{"module.dll","4 KB","DLL","2026-10-31"},"D:/module.dll"},
                 {{"中文目录","-","Folder","2026-10-31"},"D:/中文目录",TuiRowKind::Directory},
                 {{"settings.json","2 KB","JSON","2026-10-31"},"D:/settings.json"}};
    Colors.Rebuild();
    Check(TuiCellInk(Colors,Colors.Rows[0],0).Color.Red==255,"file extension detected before padding");
    Check(TuiCellInk(Colors,Colors.Rows[1],0).Color.Ansi==14,"directory cyan fallback");
    Colors.Rows[1].Hidden=true;
    Check(TuiCellInk(Colors,Colors.Rows[1],0).Color.Ansi==8,"hidden item muted");
    Colors.Rows[1].Hidden=false;
    for (int Width : {40,80,120}) {
      TuiTableView View; View.Capture(Colors);
      const auto Rendered=View.Render(Width);
      Check(Rendered.find("38;2;255;177;92")!=std::string::npos,"file ink survives clipping and narrow layout");
      for (const auto &Line : TerminalTextLines(Rendered)) Check(TerminalWidth(Line.Text)<=Width-1,"colored table layout width");
    }
    Colors.Filter="module";
    TuiTableView Filtered; Filtered.Capture(Colors);
    const auto FilteredText=Filtered.Render(120);
    Check(FilteredText.find("38;2;255;224;102")!=std::string::npos &&
          FilteredText.find("38;2;255;177;92")!=std::string::npos,"highlight restores file type color");
    TerminalSearchLine SearchLine{7,"module.dll  |  DLL",{{"module.dll",FileNameInk("module.dll",false)},
        {"  |  ",ToneInk(TuiTone::Muted)},{"DLL",ToneInk(TuiTone::Type)}}};
    const auto Highlight=HighlightSearchLine(SearchLine,{"dll  |  d"});
    Check(TerminalPlain(Highlight)==SearchLine.Text,"cross-field highlight keeps search row identity");
    Check(Highlight.find("38;2;255;177;92")!=std::string::npos && Highlight.find("38;2;195;169;235")!=std::string::npos,
          "search restores both file and type colors");
    for (const auto &Line : TerminalWrapStyled(Highlight,6))
      Check(TerminalWidth(Line)<=6 && Line.ends_with("\x1b[0m"),"wrapped styled match resets each line");
    ColorEnabled = VtEnabled = false;
    std::vector<std::string> Args;
    std::string Error;
    Check(ParseCommandLine(R"(use "C:\Program Files\工具")", Args, Error),
          "quoted command parses");
    Check(Args.size() == 2 && Args[1] == "C:\\Program Files\\工具",
          "Windows paths stay literal");
    Check(!ParseCommandLine("use \"unterminated", Args, Error),
          "unclosed quote rejected");
    Check(ParseCommandLine("filter \"\"", Args, Error) && Args.size() == 2 &&
              Args[1].empty(),
          "empty quoted argument preserved");
    Check(TerminalWidth(std::string("中文")) == 4, "CJK width");
    Check(TerminalWidth(std::string("🙂")) == 2, "surrogate pair width");
    Check(TerminalWidth(std::string("e\xcc\x81")) == 1, "combining mark width");
    for (int Width = 1; Width < 10; ++Width) {
      const auto Fitted = TerminalFit("中文🙂abcdef", Width);
      Check(TerminalWidth(Fitted) == Width,
            "truncation fills exact cell width");
      Check(QString::fromUtf8(Fitted.c_str()).toUtf8().toStdString() == Fitted,
            "truncation preserves UTF-8");
    }
    Check(TerminalFit("x\x1b[31m", 12).find('\x1b') == std::string::npos,
          "table values cannot inject ANSI");
    const auto Wrapped = WrapText("中文长句🙂abcdef", 6, "  ");
    for (const auto &Line : Wrapped)
      Check(TerminalWidth(Line) <= 6 &&
                Line.find("\xef\xbf\xbd") == std::string::npos,
            "Unicode wrapping respects columns");

    TerminalEditor Editor;
    Editor.Set("你🙂x");
    Editor.Left();
    Editor.Backspace();
    Check(TerminalUtf8(Editor.Text) == "你x" && Editor.Cursor == 1,
          "backspace removes whole supplementary character");
    Editor.Insert(U'好');
    Editor.Delete();
    Check(TerminalUtf8(Editor.Text) == "你好", "insert and delete at cursor");
    Editor.Set("e\xcc\x81!");
    Editor.Cursor = 0;
    Editor.Delete();
    Check(TerminalUtf8(Editor.Text) == "!", "delete combines base and mark");
    Editor.Set("one two ");
    Editor.EraseWord();
    Check(TerminalUtf8(Editor.Text) == "one ", "Ctrl+W removes previous word");
    Editor.Set("alpha beta ");
    Editor.WordLeft();
    Check(Editor.Cursor == 6, "Ctrl+Left lands at the previous word start");
    Editor.WordLeft();
    Check(Editor.Cursor == 0, "Ctrl+Left stops at the first word");
    Editor.WordRight();
    Check(Editor.Cursor == 6, "Ctrl+Right lands at the next word start");
    Editor.Set("alpha beta gamma");
    Editor.Cursor = 0;
    Check(TerminalUtf8(Editor.DeleteWord()) == "alpha " &&
              TerminalUtf8(Editor.Text) == "beta gamma",
          "Ctrl+Delete erases the forward word and reports it");
    Editor.Set("one two ");
    Check(TerminalUtf8(Editor.EraseWord()) == "two ",
          "Ctrl+W reports the erased word for yank");
    Editor.Set(std::string(9000, 'x'));
    Editor.Insert(U'y');
    Check(Editor.Text.size() == TerminalEditor::MaxLength, "bounded input");

    TuiTable Table;
    Table.Headers = {"名称", "Path", "Size"};
    Table.Rows = {{{"测试", "C:\\one", "123"}, {}},
                  {{"🙂", "C:\\two", "987"}, {}}};
    Table.Rebuild();
    auto Rendered = TuiTableToText(Table, 0);
    size_t Start = 0;
    int LineWidth = -1;
    while (Start < Rendered.size()) {
      const auto End = Rendered.find('\n', Start);
      if (End == std::string::npos)
        break;
      const auto Line = Rendered.substr(Start, End - Start);
      if (LineWidth < 0)
        LineWidth = TerminalWidth(Line);
      Check(TerminalWidth(Line) == LineWidth, "Unicode table borders align");
      Start = End + 1;
    }
    Table.Filter = "no-match";
    Table.Rebuild();
    Rendered = TuiTableToText(Table, 0);
    Check(Rendered.find("C:\\one") == std::string::npos &&
              Rendered.find("No matching rows") != std::string::npos,
          "zero matches never redisplay all rows");

    const auto Fits = [&](const std::string &Text, int Columns) {
      size_t Begin = 0;
      while (Begin < Text.size()) {
        const auto End = Text.find('\n', Begin);
        const auto Line = Text.substr(Begin, End == std::string::npos ? End : End - Begin);
        Check(TerminalWidth(Line) < Columns, "rendered line fits viewport");
        Check(Line.find("\xef\xbf\xbd") == std::string::npos, "no broken Unicode");
        if (End == std::string::npos) break;
        Begin = End + 1;
      }
    };
    for (bool Chinese : {false, true}) {
      TerminalChinese = Chinese;
      for (bool Unicode : {false, true}) {
        VtEnabled = Unicode;
        for (int Width : {40, 80, 120}) {
          const TerminalPromptContext Context{"File", "D:\\一个很长的目录\\开发工具\\AegisNT", false, Chinese};
          const auto Prompt = RenderTerminalPrompt(Context, "14:35:20", Width);
          Check(Prompt.find("[14:35:20] AegisNT") != std::string::npos, "prompt time and brand");
          Check(std::count(Prompt.begin(), Prompt.end(), '\n') == 1, "exactly two prompt lines");
          Check(Prompt.find(Unicode ? "╰─❯ " : "+- > ") != std::string::npos, "prompt capability fallback");
          Fits(Prompt, Width);
          TuiTable Data;
          Data.Headers = {"Name", "Size", "Type", "Modified"};
          Data.RightAlign = {false, true, false, false};
          for (int N = 0; N < 21; ++N)
            Data.Rows.push_back({{"item" + std::to_string(N + 1) + "中文", "123 B", "TXT", "2026-10-29"}, "path-" + std::to_string(N + 1)});
          Data.Rows.front().Kind = TuiRowKind::Directory;
          TuiTableView View;
          View.Capture(Data);
          Check(View.PageCount() == 2 && View.Page == 1, "21 rows make two pages");
          auto First = View.Render(Width);
          Check(First.find("item21") == std::string::npos, "first page stops at 20");
          Check(First.find("1/2") != std::string::npos,
                "summary shows page position");
          Check(First.find(Unicode ? "█░" : "#-") != std::string::npos,
                "page progress bar renders");
          Fits(First, Width);
          Check(View.SetPage(2), "can enter last page");
          auto Last = View.Render(Width);
          Check(Last.find("item21") != std::string::npos && Last.find("item20") == std::string::npos, "last page contains only remainder");
          Fits(Last, Width);
          Check(!View.SetPage(0) && !View.SetPage(3) && View.Page == 2, "invalid page preserves current state");
          Data.Rows[20].Detail = "mutated-live-data";
          Check(View.RowAt(21)->Detail == "path-21", "detail reads displayed snapshot");
          Check(!View.RowAt(0) && !View.RowAt(22), "detail rejects invalid row");
          View.All = true;
          const auto All = View.Render(Width);
          Check(All.find("item1") != std::string::npos && All.find("item21") != std::string::npos, "show all bypasses page limit");
          Data.Filter = "item21";
          View.Capture(Data);
          Check(View.Page == 1 && !View.All && View.Snapshot.Visible.size() == 1, "filter resets pagination");
          Check(View.RowAt(1)->Detail == "mutated-live-data", "filtered row numbering restarts at one");
          Data.Filter = "missing";
          View.Capture(Data);
          Check(View.PageCount() == 1 && !View.RowAt(1), "empty filter has valid empty page");
          Fits(View.Render(Width), Width);
        }
      }
    }
    TerminalChinese = false;
    VtEnabled = true;
    ColorEnabled = false;
    const auto Heading = SectionHeading("SESSION", 40);
    Check(Heading.find("▌ SESSION") != std::string::npos,
          "sections use an accent block plus rule");
    Check(TerminalWidth(Heading.substr(0, Heading.size() - 1)) == 39,
          "section rule fills the requested width");
    const auto Notice = NoticeText("hello", TuiTone::Error);
    Check(Notice.find("[-] ERROR") != std::string::npos &&
              Notice.find(" \xe2\x94\x82 ") != std::string::npos,
          "notices render as a bracketed badge");
    Check(TabStrip({"A", "B"}, 1).find("[B]") != std::string::npos,
          "active view stays bracketed");
    const auto Banner = RenderTerminalBanner("3.6.2", "TERMINAL", 80);
    Check(Banner.find("\xe2\x95\xad") != std::string::npos &&
              Banner.find("AegisNT") != std::string::npos,
          "banner is framed");
    int BannerLines = 0;
    size_t BannerStart = 0;
    while (BannerStart < Banner.size()) {
      const auto End = Banner.find('\n', BannerStart);
      const auto Line = Banner.substr(BannerStart, End == std::string::npos ? End : End - BannerStart);
      Check(TerminalWidth(Line) <= 79, "banner fits the viewport");
      ++BannerLines;
      if (End == std::string::npos) break;
      BannerStart = End + 1;
    }
    Check(BannerLines == 3, "banner occupies three lines");
    const auto HostBanner = RenderTerminalBanner("3.6.2", "TERMINAL", 80,
                                                 "DESKTOP · admin · Windows 11");
    size_t HostStart = 0;
    int HostLines = 0;
    while (HostStart < HostBanner.size()) {
      const auto End = HostBanner.find('\n', HostStart);
      const auto Line = HostBanner.substr(HostStart, End == std::string::npos ? End : End - HostStart);
      Check(TerminalWidth(Line) <= 79, "banner with host row fits the viewport");
      ++HostLines;
      if (End == std::string::npos) break;
      HostStart = End + 1;
    }
    Check(HostLines == 4 && HostBanner.find("DESKTOP · admin · Windows 11") != std::string::npos,
          "banner host row adds one framed line");
    TuiTable Grid;
    Grid.Headers = {"Name", "Size"};
    for (int N = 0; N < 3; ++N)
      Grid.Rows.push_back({{"file" + std::to_string(N), "12 B"}, {}});
    Grid.Rebuild();
    TuiTableView GridView;
    GridView.Capture(Grid);
    const auto Box = GridView.Render(80);
    Check(Box.rfind("  \xe2\x95\xad", 0) == 0 &&
              Box.find("  \xe2\x94\x9c") != std::string::npos,
          "tables are framed with a header rule");
    {
      int BoxWidth = -1;
      size_t BoxStart = 0;
      while (BoxStart < Box.size()) {
        const auto End = Box.find('\n', BoxStart);
        const auto Line = Box.substr(BoxStart, End == std::string::npos ? End : End - BoxStart);
        if (Line.rfind("  \xe2\x95", 0) == 0 || Line.rfind("  \xe2\x94", 0) == 0) {
          if (BoxWidth < 0) BoxWidth = TerminalWidth(Line);
          Check(TerminalWidth(Line) == BoxWidth, "framed rows share one width");
        }
        if (End == std::string::npos) break;
        BoxStart = End + 1;
      }
      Check(BoxWidth > 0, "framed rows were found");
    }
    VtEnabled = false;
    Check(SectionHeading("SESSION", 40).find("-- SESSION") != std::string::npos,
          "sections fall back to ASCII rules");
    Check(NoticeText("hello", TuiTone::Error).find(" | ") != std::string::npos,
          "notices fall back to an ASCII badge");
    const auto AsciiBox = GridView.Render(80);
    Check(AsciiBox.rfind("  +", 0) == 0 &&
              AsciiBox.find("\xe2\x95\xad") == std::string::npos &&
              AsciiBox.find("\xe2\x94\x82") == std::string::npos &&
              AsciiBox.find("\xe2\x94\x80") == std::string::npos,
          "tables fall back to ASCII borders");
    TerminalChinese = false;
    VtEnabled = false;
    std::vector<std::string> Pipeline;
    Check(SplitTerminalPipeline("ls \"C:\\folder name\"|grep -n \"中文|literal\" | find .txt", Pipeline, Error) && Pipeline.size() == 3,
          "quoted pipe is literal; adjacent unquoted pipe splits stages");
    Check(ParseCommandLine(Pipeline[1], Args, Error) && Args[2] == "中文|literal", "pipeline keeps quoted search text");
    Check(!SplitTerminalPipeline("ls || find x", Pipeline, Error), "empty stage rejected");
    Check(!SplitTerminalPipeline("ls | find \"x", Pipeline, Error), "unclosed pipe quote rejected");
    Check(!SplitTerminalPipeline("ls |", Pipeline, Error), "trailing pipe rejected");
    Check(TerminalContains("ÄBC 中文 e\xcc\x81", "äbc") && TerminalContains("中文.txt", "中文"), "Unicode insensitive literal search");
    auto SearchLines = TerminalTextLines("alpha\n\x1b[32m中文 Beta\x1b[0m\ngamma\n");
    auto Found = TerminalFindLines(SearchLines, {"中文", "BETA"});
    Check(Found.size() == 1 && Found[0].Number == 2 && Found[0].Text == "中文 Beta", "chained matches preserve source line numbers and strip ANSI");
    Check(TerminalFindLines(SearchLines, {"missing"}).empty(), "no false search result");
    Check(TerminalFindLines({{21, "last page match"}}, {"match"})[0].Number == 21, "snapshot search keeps detail row identity");
    ColorEnabled = true;
    auto Highlighted = TerminalHighlight("alpha ALPHA 中文", {"alpha", "中文"});
    Check(Highlighted.find("\x1b[") != std::string::npos && TerminalPlain(Highlighted) == "alpha ALPHA 中文", "all matching occurrences highlighted without changing content");
    const auto StyledLines = TerminalWrapStyled(TerminalHighlight("abcdefghijklmnopqrst", {"defghijklmnop"}), 8);
    Check(StyledLines.size() == 3 && StyledLines[0].find("\x1b[") != std::string::npos &&
          StyledLines[1].find("\x1b[") != std::string::npos, "keyword stays colored on both sides of a hard wrap");
    std::string Rejoined;
    for (const auto &Line : StyledLines) {
      Check(TerminalWidth(TerminalPlain(Line)) <= 8, "SGR bytes do not consume layout columns");
      Rejoined += TerminalPlain(Line);
    }
    Check(Rejoined == "abcdefghijklmnopqrst", "styled wrap keeps all original characters");
    ColorEnabled = false;
    Check(TerminalHighlight("alpha", {"alpha"}) == "alpha", "NO_COLOR search emits no ANSI");
    const std::vector<std::string> Complete = {"show", "show all", "search", "show", "use File"};
    Check(TerminalCompletions("sh", Complete).size() == 2, "completion candidates deduplicate");
    Check(TerminalCompletions("ls | gr", Complete) == std::vector<std::string>{"ls | grep"}, "pipe-aware completion");
    Check(TerminalCompletions("find \"x|", Complete).empty(), "quoted search data never receives command suggestions");
    Check(TerminalCompletions("use fi", Complete) == std::vector<std::string>{"use File"}, "completion ignores command case");
    Check(TerminalCommonPrefix({"use File", "use Filter"}) == "use Fil",
          "Tab extends to the longest common candidate prefix");
    Check(TerminalCommonPrefix({"use File", "use files"}) == "use File",
          "common prefix keeps candidate casing");
    Check(TerminalCommonPrefix({"use File", "help File"}).empty(),
          "unrelated candidates extend nothing");
    Check(TerminalCompletions("show | co", Complete) ==
              std::vector<std::string>{"show | copy"},
          "copy pipeline stage completes");
    // Simulate conhost's measured ambiguous and combining widths.
    TerminalNativeCellWidth = [](char32_t C) { return C == U'…' || C == U'·' ? 2 : C == 0x301 ? 1 : -1; };
    VtEnabled = true;
    for (int Width : {40, 80, 120}) {
      Fits(RenderTerminalPrompt({"File", "D:\\目录\\" + std::string(180, 'x') + "e\xcc\x81.txt", false, true}, "14:35:20", Width), Width);
      Check(TerminalWidth(TerminalClip(std::string(200, 'x'), Width - 1, true)) < Width, "wide ellipsis fits measured host width");
      Check(TerminalWidth(TerminalFit(std::string(200, 'x'), Width)) == Width, "table uses host ellipsis width");
    }
    TerminalNativeCellWidth = nullptr;
    VtEnabled = false;
    for (int Count : {0, 1, 20}) {
      TuiTable Data;
      Data.Headers = {"#", "Value"};
      for (int I = 0; I < Count; ++I) Data.Rows.push_back({{std::to_string(I + 1), "value"}, {}});
      TuiTableView View;
      View.Capture(Data);
      Check(View.PageCount() == 1, "zero/one/exact page boundary");
      const auto Text = View.Render(80);
      Check(std::count(Text.begin(), Text.end(), '#') == 1, "existing number column is not duplicated");
      TuiTable Auxiliary;
      Auxiliary.Headers = {"Other"};
      Auxiliary.Rebuild();
      {
        TuiTableCapture Capture(&Data);
        Check(TuiTableToText(Auxiliary, 200).find(TuiTableCapture::Marker) == std::string::npos, "auxiliary table remains unpaged");
        Check(TuiTableToText(Data, 200) == TuiTableCapture::Marker && Capture.View.Valid, "only active table is captured");
      }
      Check(TuiTableToText(Data, 200).find(TuiTableCapture::Marker) == std::string::npos, "capture scope restored");
    }

    TuiDialogStack Dialogs;
    bool Submitted = false;
    TuiDialog Form;
    Form.Title = "Cancellation regression";
    Form.Fields = {{"First", TuiFieldKind::Text},
                   {"Second", TuiFieldKind::Password}};
    Form.OnSubmit = [&](TuiDialog &) { Submitted = true; };
    Answers = {{true, "first value"}, {false, ""}};
    Dialogs.Push(Form);
    Check(!Submitted && Answers.empty(),
          "cancel second field aborts entire form");
    Answers = {{false, ""}};
    Dialogs.Push(Form);
    Check(!Submitted, "cancel first field aborts entire form");
    Answers = {{true, "value"}, {true, "password"}};
    Dialogs.Push(Form);
    Check(Submitted, "completed form submits");

    for (const std::string Choice : {"", "s", "skip", "SKIP", "g", "guest"}) {
      Account = {true, "stale"};
      Answers = {{true, Choice}};
      Output.clear();
      Check(RunConsoleLoginGate(false),
            "guest choice enters shell immediately");
      Check(!Account.IsLoggedIn && Account.UserName.isEmpty(),
            "guest clears in-memory identity");
      Check(NetworkRequests == 0 && Answers.empty(),
            "skip never asks for credentials or sends a request");
      Check(Output.find("Guest session ready") != std::string::npos,
            "guest feedback is explicit");
    }
    Answers = {{true, "l"}, {false, ""}, {true, "s"}};
    Check(RunConsoleLoginGate(false) && NetworkRequests == 0,
          "cancel sign-in returns to menu");
    Answers = {
        {true, "l"}, {true, "tester"}, {true, "test-password"}, {true, "s"}};
    Check(RunConsoleLoginGate(false) && NetworkRequests == 1,
          "failed login can immediately continue as guest");
    Answers = {{true, "q"}};
    Check(!RunConsoleLoginGate(false), "quit leaves login gate");
    SavedLoginEnabled = true;
    const int RequestsBefore = NetworkRequests;
    Answers = {{true, "s"}};
    Output.clear();
    Check(RunConsoleLoginGate(), "saved login still offers immediate guest input");
    Check(NetworkRequests == RequestsBefore &&
              Output.find("[A] Use saved sign-in") != std::string::npos,
          "saved credentials never start a request before the menu");
    Answers = {{true, "a"}, {true, "s"}};
    Output.clear();
    Check(RunConsoleLoginGate() && NetworkRequests == RequestsBefore + 1,
          "saved login starts only on explicit A");
    Check(Output.find("Saved sign-in failed") != std::string::npos &&
              !Account.IsLoggedIn,
          "failed saved login returns to functional guest menu");
    std::printf("PASS: %d terminal assertions\n", Checks);
    return 0;
  } catch (const std::exception &Error) {
    std::fprintf(stderr, "FAIL: %s\n", Error.what());
    return 1;
  }
}
