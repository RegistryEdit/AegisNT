#define NOMINMAX
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#include <cstdio>
#include <cwchar>
#include <stdexcept>
#include "../Source/Tui/TuiConsole.cpp"
// Console implementation depends on these general string utilities, not page
// models or application/account state. The color writer itself is production.
namespace AegisNT::Tui {
std::string LowerAscii(std::string S) {
  for (char &C : S) C = static_cast<char>(std::tolower(static_cast<unsigned char>(C)));
  return S;
}
std::string TrimAscii(const std::string &S) {
  const auto A = S.find_first_not_of(" \t\r\n");
  return A == std::string::npos ? "" : S.substr(A, S.find_last_not_of(" \t\r\n") - A + 1);
}
}
namespace {
int Checks = 0;
void Check(bool Value, const char *Message) {
  ++Checks;
  if (!Value) throw std::runtime_error(Message);
}
}
int main() {
  using namespace AegisNT::Tui;
  HANDLE Buffer = INVALID_HANDLE_VALUE;
  bool Allocated = false;
  try {
    for (int Bits = 0; Bits < 32; ++Bits) {
      const bool Console = Bits & 1, Vt = Bits & 2, Pseudo = Bits & 4,
                 Advertised = Bits & 8, NoColor = Bits & 16;
      const auto Mode = SelectTerminalColorMode(Console,Vt,Pseudo,Advertised,NoColor);
      Check(Mode == (!Console || NoColor ? TerminalColorMode::None :
          Vt && (Pseudo || Advertised) ? TerminalColorMode::TrueColor : TerminalColorMode::Ansi16), "mode capability matrix");
    }
    Check(AnsiToWin32(1)==4 && AnsiToWin32(4)==1 && AnsiToWin32(6)==3 && AnsiToWin32(3)==6,
          "ANSI RGB order must map to Win32 BGR bits");
    for (unsigned char I=0; I<16; ++I) {
      TerminalSgrState State(0x17);
      State.Apply({I<8 ? 30+I : 90+I-8});
      Check(State.Attributes()==(0x10|AnsiToWin32(I)), "all foreground indices preserve background");
      State.Apply({I<8 ? 40+I : 100+I-8});
      Check((State.Attributes()>>4 & 15)==AnsiToWin32(I), "all background indices");
      State.Apply({0}); Check(State.Attributes()==0x17, "reset restores base");
    }
    TerminalSgrState State(0x17);
    State.Apply({31,1,4}); Check(State.Attributes()==0x801c, "bold and underline");
    State.Apply({22,24}); Check(State.Attributes()==0x14, "22 and 24 clear flags");
    State.Apply({38,2,255,0,0}); Check((State.Attributes()&15)==12, "RGB red map");
    State.Apply({38,5,12}); Check((State.Attributes()&15)==9, "indexed bright blue map");
    const auto Before = State.Attributes();
    State.Apply({38,2,255}); Check(State.Attributes()==Before, "incomplete RGB ignored");
    State.Apply({48,5}); Check(State.Attributes()==Before, "incomplete indexed ignored");
    Check(IndexedColor(16).Red==0 && IndexedColor(21).Blue==255 && IndexedColor(232).Red==8,
          "xterm cube and grayscale");
    Check(FormatTerminalColor("x",{92,226,255,14},true,true,TerminalColorMode::TrueColor)==
          "\x1b[1;4;38;2;92;226;255mx\x1b[0m", "exact RGB encoding");
    Check(FormatTerminalColor("x",{142,157,177,8},false,false,TerminalColorMode::Ansi16)==
          "\x1b[90mx\x1b[0m", "muted is gray, never blue");
    Check(FormatTerminalColor("x",{},true,true,TerminalColorMode::None)=="x", "plain encoding");
    for (const auto &Text : {"a\x1b[31mb\x1b[0mc", "a\x1b[38:2:1m\x1b[2Jbc",
                             "a\x1b]0;title\ab\x1b]8;;url\x1b\\c\x1b]8;;\x1b\\"})
      Check(StripTerminalStyles(Text)=="abc", "strip SGR CSI OSC without escaping payload");
    Check(StripTerminalStyles("safe\x1b[38;2;")=="safe", "incomplete escape discarded");
    Check(StripTerminalStyles("a\x1b[\x1b[31mb")=="ab", "nested malformed escape makes progress");

    // Automation may inherit a headless console association with no HWND.
    // Detach this test process only before allocating its private console.
    FreeConsole(); Allocated = AllocConsole()!=FALSE; Check(Allocated,"allocate test console");
    if (Allocated) ShowWindow(GetConsoleWindow(), SW_HIDE);
    Buffer = CreateConsoleScreenBuffer(GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,
                                       nullptr,CONSOLE_TEXTMODE_BUFFER,nullptr);
    Check(Buffer!=INVALID_HANDLE_VALUE,"inactive real console buffer");
    OwnedOutput() = Buffer;
    _putenv_s("NO_COLOR",""); _putenv_s("AEGISNT_NO_COLOR","");
    _putenv_s("WT_SESSION","synthetic-inherited-value"); _putenv_s("COLORTERM","truecolor");
    Check(SetConsoleMode(Buffer,ENABLE_PROCESSED_OUTPUT)!=FALSE,"disable VT");
    Check(GetTerminalColorMode()==TerminalColorMode::Ansi16,"non-VT classic fallback");
    const WORD Base = 0x17;
    const auto Cells = [&](const std::string &Text, const std::wstring &Expected,
                           const std::vector<WORD> &Attrs) {
      SetConsoleCursorPosition(Buffer,{0,0}); SetConsoleTextAttribute(Buffer,Base);
      WriteConsoleText(Text.data(),Text.size());
      std::vector<CHAR_INFO> Result(Expected.size());
      SMALL_RECT Rect{0,0,static_cast<SHORT>(Expected.size()-1),0};
      Check(ReadConsoleOutputW(Buffer,Result.data(),{static_cast<SHORT>(Expected.size()),1},{0,0},&Rect)!=FALSE,"read real cells");
      for (size_t I=0; I<Expected.size(); ++I) {
        Check(Result[I].Char.UnicodeChar==Expected[I],"no escape bytes in real cells");
        Check(Result[I].Attributes==Attrs[I],"exact Win32 cell color and preserved background");
      }
      CONSOLE_SCREEN_BUFFER_INFO Info{}; GetConsoleScreenBufferInfo(Buffer,&Info);
      Check(Info.wAttributes==Base,"writer restores host attributes");
    };
    Cells("\x1b[31mR\x1b[34mB\x1b[36mC\x1b[33mY\x1b[90mG\x1b[0m.",L"RBCYG.",{0x14,0x11,0x13,0x16,0x18,Base});
    Cells(Paint("A",TuiTone::Title)+Paint("M",TuiTone::Muted)+Paint("S",TuiTone::Success)+".",
          L"AMS.",{0x1b,0x18,0x1a,Base});
    Cells("\x1b[1;4;31mA\x1b[22;24mB\x1b[0mC",L"ABC",{0x801c,0x14,Base});
    Cells("A\x1b[38:2:1mB\x1b[2JC\x1b[31;",L"ABC",{Base,Base,Base});
    Check(SetConsoleMode(Buffer,ENABLE_PROCESSED_OUTPUT|ENABLE_VIRTUAL_TERMINAL_PROCESSING)!=FALSE,"enable VT");
    wchar_t HostClass[128]{};
    GetClassNameW(GetConsoleWindow(),HostClass,128);
    std::printf("Color test host: %s (mode %d)\n",QString::fromWCharArray(HostClass).toUtf8().constData(),int(GetTerminalColorMode()));
    Check(GetTerminalColorMode()==(std::wcscmp(HostClass,L"PseudoConsoleWindow")==0 ?
        TerminalColorMode::TrueColor : TerminalColorMode::Ansi16),"window capability wins over inherited WT hints");
    _putenv_s("WT_SESSION",""); _putenv_s("COLORTERM","");
    if (std::wcscmp(HostClass,L"PseudoConsoleWindow")==0)
      Check(GetTerminalColorMode()==TerminalColorMode::TrueColor,"ConPTY detected without environment hints");
    for (const auto *Variable : {"NO_COLOR","AEGISNT_NO_COLOR"}) {
      _putenv_s(Variable,"1");
      Check(GetTerminalColorMode()==TerminalColorMode::None,"no-color priority");
      Check(Paint("plain",TuiTone::Active)=="plain","no-color emits no ANSI");
      Cells("\x1b[31mR\x1b[1;4mU\x1b[0m.",L"RU.",{Base,Base,Base});
      _putenv_s(Variable,"");
    }
    { ConsoleOutputCapture Capture;
      WriteConsoleLine(Paint("captured",TuiTone::Title));
      Check(Capture.Text=="captured\n","pipeline capture is plain"); }
    CloseHandle(Buffer); Buffer=INVALID_HANDLE_VALUE; OwnedOutput()=INVALID_HANDLE_VALUE;
    Check(GetTerminalColorMode()==TerminalColorMode::None,"no output handle means no color");
    if (Allocated) FreeConsole();
    std::printf("PASS: %d color assertions (production encoder, parser, Win32 writer)\n",Checks);
    return 0;
  } catch (const std::exception &E) {
    if (Buffer!=INVALID_HANDLE_VALUE) CloseHandle(Buffer);
    if (Allocated) FreeConsole();
    std::fprintf(stderr,"FAIL: %s\n",E.what()); return 1;
  }
}
