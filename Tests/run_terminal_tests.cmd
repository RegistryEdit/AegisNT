@echo off
setlocal
call "D:\Visual Studio\VC\Auxiliary\Build\vcvars64.bat" >nul
set "PATH=D:\Qt\6.7.3\msvc2022_64\bin;%PATH%"
set "OUT=%~dp0..\out\terminal-regression"
if not exist "%OUT%" mkdir "%OUT%"
cl /nologo /std:c++20 /Zc:__cplusplus /EHsc /MD /utf-8 ^
  /I"D:\Qt\6.7.3\msvc2022_64\include" ^
  /I"D:\Qt\6.7.3\msvc2022_64\include\QtCore" ^
  /Fo"%OUT%\TuiTerminalTests.obj" /Fe"%OUT%\TuiTerminalTests.exe" ^
  "%~dp0TuiTerminalTests.cpp" ^
  /link /LIBPATH:"D:\Qt\6.7.3\msvc2022_64\lib" Qt6Core.lib user32.lib
if errorlevel 1 exit /b 1
"%OUT%\TuiTerminalTests.exe"
if errorlevel 1 exit /b 1
cl /nologo /std:c++20 /Zc:__cplusplus /EHsc /MD /utf-8 ^
  /I"D:\Qt\6.7.3\msvc2022_64\include" ^
  /I"D:\Qt\6.7.3\msvc2022_64\include\QtCore" ^
  /Fo"%OUT%\TuiColorTests.obj" /Fe"%OUT%\TuiColorTests.exe" ^
  "%~dp0TuiColorTests.cpp" ^
  /link /LIBPATH:"D:\Qt\6.7.3\msvc2022_64\lib" Qt6Core.lib user32.lib
if errorlevel 1 exit /b 1
"%OUT%\TuiColorTests.exe"
if errorlevel 1 exit /b 1
python -X utf8 "%~dp0check_stdio_capture.py"
exit /b %errorlevel%
