#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <string>

namespace Platform {

inline bool CopyUtf8ToClipboardText(const std::string& Text) {
    const int WideLen = MultiByteToWideChar(CP_UTF8, 0, Text.c_str(), -1, nullptr, 0);
    if (WideLen <= 0) {
        return false;
    }

    HGLOBAL Mem = GlobalAlloc(GMEM_MOVEABLE, static_cast<SIZE_T>(WideLen) * sizeof(wchar_t));
    if (!Mem) {
        return false;
    }

    wchar_t* Buf = static_cast<wchar_t*>(GlobalLock(Mem));
    if (!Buf) {
        GlobalFree(Mem);
        return false;
    }

    const int Written = MultiByteToWideChar(CP_UTF8, 0, Text.c_str(), -1, Buf, WideLen);
    GlobalUnlock(Mem);
    if (Written <= 0) {
        GlobalFree(Mem);
        return false;
    }

    if (!OpenClipboard(nullptr)) {
        GlobalFree(Mem);
        return false;
    }
    EmptyClipboard();
    if (!SetClipboardData(CF_UNICODETEXT, Mem)) {
        CloseClipboard();
        GlobalFree(Mem);
        return false;
    }
    CloseClipboard();
    // Ownership of Mem transfers to the clipboard on success.
    return true;
}

} // namespace Platform
