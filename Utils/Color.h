#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <iostream>

namespace Color
{
    inline const char* FgRed()     { return "\033[31m"; }
    inline const char* FgGreen()   { return "\033[32m"; }
    inline const char* FgYellow()  { return "\033[33m"; }
    inline const char* FgBlue()    { return "\033[34m"; }
    inline const char* FgMagenta() { return "\033[35m"; }
    inline const char* FgCyan()    { return "\033[36m"; }
    inline const char* FgWhite()   { return "\033[37m"; }

    inline const char* BoldRed()    { return "\033[1;31m"; }
    inline const char* BoldGreen()  { return "\033[1;32m"; }
    inline const char* BoldYellow() { return "\033[1;33m"; }
    inline const char* BoldCyan()   { return "\033[1;36m"; }
    inline const char* BoldWhite()  { return "\033[1;37m"; }

    inline const char* DimCode()     { return "\033[2m"; }
    inline const char* ColorNone()   { return "\033[0m"; }

    void EnableAnsi()
    {
        HANDLE Out = GetStdHandle(STD_OUTPUT_HANDLE);
        if (Out != INVALID_HANDLE_VALUE)
        {
            DWORD Mode = 0;
            if (GetConsoleMode(Out, &Mode))
                SetConsoleMode(Out, Mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
        HANDLE Err = GetStdHandle(STD_ERROR_HANDLE);
        if (Err != INVALID_HANDLE_VALUE)
        {
            DWORD Mode = 0;
            if (GetConsoleMode(Err, &Mode))
                SetConsoleMode(Err, Mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }

    inline std::string Wrap(const char* Code, const std::string& Text)
    {
        std::string S(Code);
        S += Text;
        S += ColorNone();
        return S;
    }

    inline std::string Bold(const std::string& T)   { return Wrap(BoldWhite(), T); }
    inline std::string Cyan(const std::string& T)   { return Wrap(FgCyan(), T); }
    inline std::string Green(const std::string& T)  { return Wrap(BoldGreen(), T); }
    inline std::string Red(const std::string& T)    { return Wrap(BoldRed(), T); }
    inline std::string Yellow(const std::string& T) { return Wrap(BoldYellow(), T); }
    inline std::string Dim(const std::string& T)    { return Wrap(DimCode(), T); }
    inline std::string Highlight(const std::string& T) { return Wrap(BoldCyan(), T); }

    inline std::ostream& PrintInfo(std::ostream& Os = std::cout)
    {
        Os << FgBlue() << "[*] " << ColorNone();
        return Os;
    }

    inline std::ostream& PrintGood(std::ostream& Os = std::cout)
    {
        Os << BoldGreen() << "[+] " << ColorNone();
        return Os;
    }

    inline std::ostream& PrintBad(std::ostream& Os = std::cout)
    {
        Os << BoldRed() << "[-] " << ColorNone();
        return Os;
    }

    inline std::ostream& PrintWarn(std::ostream& Os = std::cout)
    {
        Os << BoldYellow() << "[!] " << ColorNone();
        return Os;
    }
}
