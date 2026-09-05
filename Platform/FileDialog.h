#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define GLFW_EXPOSE_NATIVE_WIN32
#include <commdlg.h>
#include <shlobj.h>
#include <windows.h>

#include <GLFW/glfw3.h>
#include <GLFW/glfw3native.h>

#include <string>
#include <utility>
#include <vector>

namespace Platform {

inline std::wstring
MakeFilterForExtension(const std::wstring &Extension,
                       const std::wstring &Description = L"File") {
  std::wstring Ext = Extension;
  if (!Ext.empty() && Ext.front() == L'*') {
    Ext.erase(Ext.begin());
  }
  if (!Ext.empty() && Ext.front() != L'.') {
    Ext.insert(Ext.begin(), L'.');
  }
  if (Ext.empty()) {
    Ext = L".*";
  }

  std::wstring Filter;
  Filter += Description;
  Filter += L" (";
  Filter += Ext;
  Filter += L")";
  Filter.push_back(L'\0');
  Filter += L"*";
  Filter += Ext;
  Filter.push_back(L'\0');
  Filter += L"All Files";
  Filter.push_back(L'\0');
  Filter += L"*.*";
  Filter.push_back(L'\0');
  Filter.push_back(L'\0');
  return Filter;
}

inline std::string
OpenFileDialog(GLFWwindow *Window,
               const wchar_t *Filter =
                   L"DLL Files\0*.dll\0Driver Files\0*.sys\0All Files\0*.*\0",
               const wchar_t *Title = L"Open File") {
  wchar_t FilePath[1024] = {};
  OPENFILENAMEW Ofn = {sizeof(Ofn)};
  Ofn.hwndOwner = glfwGetWin32Window(Window);
  Ofn.lpstrFilter = Filter;
  Ofn.lpstrFile = FilePath;
  Ofn.nMaxFile = 1024;
  Ofn.lpstrTitle = Title;
  Ofn.Flags = OFN_FILEMUSTEXIST | OFN_HIDEREADONLY | OFN_PATHMUSTEXIST;

  if (GetOpenFileNameW(&Ofn)) {
    int Len = WideCharToMultiByte(CP_UTF8, 0, FilePath, -1, nullptr, 0, nullptr,
                                  nullptr);
    std::string Result(static_cast<std::size_t>(Len), '\0');
    WideCharToMultiByte(CP_UTF8, 0, FilePath, -1, &Result[0], Len, nullptr,
                        nullptr);
    while (!Result.empty() && Result.back() == '\0')
      Result.pop_back();
    return Result;
  }
  return "";
}

inline std::string OpenFileDialog(GLFWwindow *Window,
                                  const std::wstring &Extension,
                                  const std::wstring &Description = L"File",
                                  const wchar_t *Title = L"Open File") {
  std::wstring Filter = MakeFilterForExtension(Extension, Description);
  return OpenFileDialog(Window, Filter.c_str(), Title);
}

inline std::string SaveFileDialog(GLFWwindow *Window,
                                  const wchar_t *Filter = L"All Files\0*.*\0\0",
                                  const wchar_t *Title = L"Save File") {
  wchar_t FilePath[1024] = {};
  OPENFILENAMEW Ofn = {sizeof(Ofn)};
  Ofn.hwndOwner = glfwGetWin32Window(Window);
  Ofn.lpstrFilter = Filter;
  Ofn.lpstrFile = FilePath;
  Ofn.nMaxFile = 1024;
  Ofn.lpstrTitle = Title;
  Ofn.Flags = OFN_OVERWRITEPROMPT | OFN_HIDEREADONLY | OFN_PATHMUSTEXIST;

  if (GetSaveFileNameW(&Ofn)) {
    const int Len = WideCharToMultiByte(CP_UTF8, 0, FilePath, -1, nullptr, 0,
                                        nullptr, nullptr);
    if (Len <= 0)
      return {};
    std::string Result(static_cast<std::size_t>(Len), '\0');
    WideCharToMultiByte(CP_UTF8, 0, FilePath, -1, &Result[0], Len, nullptr,
                        nullptr);
    while (!Result.empty() && Result.back() == '\0')
      Result.pop_back();
    return Result;
  }
  return {};
}

inline std::string OpenFolderDialog(GLFWwindow *Window) {
  CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  std::string Result;
  IFileDialog *pfd = nullptr;
  if (SUCCEEDED(CoCreateInstance(CLSID_FileOpenDialog, nullptr,
                                 CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pfd)))) {
    DWORD Options;
    pfd->GetOptions(&Options);
    pfd->SetOptions(Options | FOS_PICKFOLDERS);
    if (SUCCEEDED(pfd->Show(glfwGetWin32Window(Window)))) {
      IShellItem *psi = nullptr;
      if (SUCCEEDED(pfd->GetResult(&psi))) {
        wchar_t *Path = nullptr;
        if (SUCCEEDED(psi->GetDisplayName(SIGDN_FILESYSPATH, &Path))) {
          int Len = WideCharToMultiByte(CP_UTF8, 0, Path, -1, nullptr, 0,
                                        nullptr, nullptr);
          Result = std::string(static_cast<std::size_t>(Len), '\0');
          WideCharToMultiByte(CP_UTF8, 0, Path, -1, &Result[0], Len, nullptr,
                              nullptr);
          while (!Result.empty() && Result.back() == '\0')
            Result.pop_back();
          CoTaskMemFree(Path);
        }
        psi->Release();
      }
    }
    pfd->Release();
  }
  CoUninitialize();
  return Result;
}

} // namespace Platform
