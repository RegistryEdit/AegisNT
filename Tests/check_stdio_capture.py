"""Compile the production capture/decoder functions and exercise mixed CRT/Qt I/O.

The .inc files belong to the application's unity translation unit. Extract only
the actual capture and decoder definitions so this regression runs without GUI
widgets, account configuration, modules, or drivers.
"""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "out" / "terminal-regression"
OUT.mkdir(parents=True, exist_ok=True)
capture = (ROOT / "Source/Core/Runtime/PayloadShell.inc").read_text(encoding="utf-8")
capture = capture[capture.index("struct StandardIoCaptureState"):capture.index("QtMessageHandler PreviousQtMessageHandler")]
decoder = (ROOT / "Source/Core/Runtime/Configuration.inc").read_text(encoding="utf-8")
decoder = decoder[decoder.index("QString DecodeMultiByteText"):]
header = r'''
#define NOMINMAX
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#include <cstdio>
#include <cwchar>
#include <clocale>
#include <array>
#include <mutex>
#include <thread>
#include <QCoreApplication>
#include <QDebug>
#include <QString>
#include <QByteArray>
std::mutex OutputMutex;
QString Transcript;
void AppendConsoleOutput(const QString &Text) {
  std::lock_guard<std::mutex> Lock(OutputMutex);
  Transcript += Text;
}
'''
main = r'''
int main(int argc, char **argv) {
  qputenv("QT_FORCE_STDERR_LOGGING", "1");
  QCoreApplication App(argc, argv);
  const std::string DecimalPoint = std::localeconv()->decimal_point;
  StartStandardIoCapture();
  const int Narrow = std::fprintf(stdout, "narrow-stdout\n");
  const int Err = std::fprintf(stderr, "narrow-stderr\n");
  const int Wide = std::wprintf(L"wide-ASCII 中文\n");
  qInfo("qt-info-smoke");
  qWarning("qt-warning-smoke");
  StopStandardIoCapture();
  const bool Valid = Narrow > 0 && Err > 0 && Wide > 0 &&
      Transcript.contains("narrow-stdout") && Transcript.contains("narrow-stderr") &&
      Transcript.contains(QString::fromUtf8("wide-ASCII 中文")) &&
      Transcript.contains("qt-info-smoke") && Transcript.contains("qt-warning-smoke") &&
      !Transcript.contains(QChar('\0')) &&
      DecimalPoint == std::localeconv()->decimal_point;
  std::puts(Valid ? "PASS: mixed printf / wprintf / Qt log capture, Unicode and restoration"
                  : "FAIL: mixed standard-stream capture");
  return Valid ? 0 : 1;
}
'''
(OUT / "StandardIoCaptureTests.cpp").write_text(header + decoder + capture + main, encoding="utf-8")
script = r'''@echo off
setlocal
call "D:\Visual Studio\VC\Auxiliary\Build\vcvars64.bat" >nul
set "PATH=D:\Qt\6.7.3\msvc2022_64\bin;%PATH%"
cl /nologo /std:c++20 /Zc:__cplusplus /EHsc /MD /utf-8 ^
 /I"D:\Qt\6.7.3\msvc2022_64\include" /I"D:\Qt\6.7.3\msvc2022_64\include\QtCore" ^
 /Fo"out\terminal-regression\StandardIoCaptureTests.obj" /Fe"out\terminal-regression\StandardIoCaptureTests.exe" ^
 "out\terminal-regression\StandardIoCaptureTests.cpp" ^
 /link /LIBPATH:"D:\Qt\6.7.3\msvc2022_64\lib" Qt6Core.lib
if errorlevel 1 exit /b 1
"out\terminal-regression\StandardIoCaptureTests.exe"
exit /b %errorlevel%
'''
runner = OUT / "run-standard-io-tests.cmd"
runner.write_text(script, encoding="utf-8")
raise SystemExit(subprocess.call(["cmd.exe", "/d", "/c", str(runner)], cwd=ROOT))
