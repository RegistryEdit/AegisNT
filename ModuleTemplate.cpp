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
        //RegisterOption//Registry Option
    }

    ModuleInfo Info() const override {
        ModuleInfo Info;
        Info.Name = "";
        Info.Description = "";
        Info.Author = "";
        Info.License = "";
        Info.Type = //ModuleType::Auxiliary; //YourType
        Info.Targets = { "Windows 10 x64", "Windows 11 x64" };
        Info.DefaultTarget = "Windows 10 x64";
        Info.Platform = { "Windows" };
        Info.Arch = "x64";
        Info.DisclosureDate = "NULL";
        Info.References = { "NULL", "NULL" };
        Info.Rank = 0;// Your Rank
        return Info;
    }

    bool Check() override {
        Color::PrintInfo()
            << "Checking if the module is compatible with the current system..."
            << std::endl;

        //Checking Step (Not Availiable)
        return true;
    }

    bool Run() override {
        //Main
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
