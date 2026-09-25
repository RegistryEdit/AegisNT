#include "../../Module/ModuleBase.h"
#include "../../Utils/Color.h"
#include <iostream>
#define WIN32_LEAN_AND_MEAN
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <format>
#include <windows.h>

class YourModule : public ModuleBase {
public:
    YourModule() {
        // 在此注册模块选项（见 Module/Option.h 与示例模块）。
    }

    ModuleInfo Info() const override {
        ModuleInfo Info;
        Info.Name = "";
        Info.Description = "";
        Info.Author = "";
        Info.License = "";
        Info.Type = //ModuleType::Auxiliary; //你的模块类型
        Info.Targets = { "Windows 10 x64", "Windows 11 x64" };
        Info.DefaultTarget = "Windows 10 x64";
        Info.Platform = { "Windows" };
        Info.Arch = "x64";
        Info.DisclosureDate = "NULL";
        Info.References = { "NULL", "NULL" };
        Info.Rank = 0;// 危险等级（0-5，越高越危险）
        return Info;
    }

    bool Check() override {
        Color::PrintInfo()
            << "Checking if the module is compatible with the current system..."
            << std::endl;

        // 在此实现兼容性检查（当前不可用）。
        return true;
    }

    bool Run() override {
        // 在此实现模块主逻辑（在后台线程执行）。
    }
};

extern "C" __declspec(dllexport) void StopModule() {
    ArptControl::RequestStop();
}
BOOL APIENTRY DllMain(HMODULE, DWORD Reason, LPVOID) {
    if (Reason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(GetModuleHandle(nullptr));
    return TRUE;
}

extern "C" __declspec(dllexport) ModuleBase* CreateModule() {
    return new YourModule();
}

extern "C" __declspec(dllexport) void DestroyModule(ModuleBase* Module) {
    delete Module;
}
