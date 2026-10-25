@echo off
setlocal
rem Override these paths when using a different Visual Studio / Qt installation.
if not defined VCVARS64 set "VCVARS64=D:\Visual Studio\VC\Auxiliary\Build\vcvars64.bat"
if not defined QTDIR set "QTDIR=D:\Qt\6.7.3\msvc2022_64"
call "%VCVARS64%" >nul
if errorlevel 1 exit /b 1
set "PATH=%QTDIR%\bin;%PATH%"
set "OUT=%~dp0..\Bin\DriverServiceEnumTests"
if not exist "%OUT%" mkdir "%OUT%"
cl /nologo /std:c++20 /Zc:__cplusplus /EHsc /MD /utf-8 /DNOMINMAX ^
 /I"%QTDIR%\include" /I"%QTDIR%\include\QtCore" ^
 /Fo"%OUT%/" /Fe"%OUT%\DriverServiceEnumTests.exe" ^
 "%~dp0DriverServiceEnumTests.cpp" ^
 "%~dp0..\Source\Services\DriverServiceEnumImpl.cpp" ^
 /link /LIBPATH:"%QTDIR%\lib" Qt6Core.lib ntdll.lib advapi32.lib user32.lib
if errorlevel 1 exit /b 1
"%OUT%\DriverServiceEnumTests.exe"
exit /b %errorlevel%
