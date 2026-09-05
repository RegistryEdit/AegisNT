#include "../../Module/ModuleBase.h"
#include "../../Utils/Color.h"
#include "../ARPT.h"
#include <iostream>
#define WIN32_LEAN_AND_MEAN
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <format>
#include <windows.h>

class ARPFlood : public ModuleBase {
public:
  ARPFlood() {
    RegisterOption("Rate",
                   std::make_unique<OptInt>("", OptionRequired::Required,
                                            "The arp flood rating"));
  }

  ModuleInfo Info() const override {
    ModuleInfo Info;
    Info.Name = "LocalNetwork/ARPFlood";
    Info.Description = "ARPFlood Tool";
    Info.Author = "RegistryEdit";
    Info.License = "DLL_LICENSE";
    Info.Type = ModuleType::Auxiliary;
    Info.Targets = {"Windows 10 x64", "Windows 11 x64"};
    Info.DefaultTarget = "Windows 10 x64";
    Info.Platform = {"Windows"};
    Info.Arch = "x64";
    Info.DisclosureDate = "NULL";
    Info.References = {"NULL", "NULL"};
    Info.Rank = 300;
    return Info;
  }

  bool Check() override {
    Color::PrintInfo()
        << "Checking if the module is compatible with the current system..."
        << std::endl;
    return true;
  }

  bool Run() override {
    ArpDll Dll = ArpLoad();
    if (!Dll.Module) {
      Color::PrintBad() << "Failed to load ARPDepend DLL." << std::endl;
      return false;
    }
    std::cout << std::endl;
    ArpFloodA(&Dll, stoi(GetOption("Rate")));
    return true;
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

extern "C" __declspec(dllexport) ModuleBase *CreateModule() {
  return new ARPFlood();
}

extern "C" __declspec(dllexport) void DestroyModule(ModuleBase *Module) {
  delete Module;
}
