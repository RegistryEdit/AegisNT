@echo off
echo ======================================
echo AegisNT 编译验证
echo ======================================

REM 查找 MSBuild
set MSBUILD="D:\Visual Studio\MSBuild\Current\Bin\MSBuild.exe"
if not exist %MSBUILD% (
    set MSBUILD="C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
)
if not exist %MSBUILD% (
    set MSBUILD="C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe"
)

echo 使用 MSBuild: %MSBUILD%
echo.

REM 编译 Debug 配置（仅新文件）
echo 编译新增文件...
%MSBUILD% AegisNT.vcxproj /t:ClCompile /p:Configuration=Debug /p:Platform=x64 /v:minimal /nologo

if %errorlevel% neq 0 (
    echo.
    echo [错误] 编译失败！
    exit /b 1
)

echo.
echo [成功] 新文件编译验证通过！
exit /b 0
