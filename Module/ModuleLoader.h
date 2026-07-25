#pragma once

#include "ModuleTypes.h"
#include "ModuleBase.h"
#include "../State.h"
#include "../ConfigLoader.h"
#include "../Platform/DriverControl.h"

#include <algorithm>
#include <filesystem>
#include <vector>
#include <string>

namespace AppState { inline void ScanModules(); }

namespace ModuleLoader {

struct ProbeResult {
    char Name[256] = {};
    char Desc[256] = {};
    char Author[128] = {};
    char TypeName[64] = {};
    int OptCount = 0;
    struct { char Name[128]; char Val[256]; char Def[256]; char Desc[256]; char Type[64]; bool Req; } Opts[32];
    bool Valid = false;
};

inline ProbeResult ProbeModuleInfo(const wchar_t* DllPath) {
    ProbeResult R = {};
    HMODULE H = LoadLibraryW(DllPath);
    if (!H) return R;
    auto Create = reinterpret_cast<ModuleBase*(*)()>(GetProcAddress(H, "CreateModule"));
    auto Destroy = reinterpret_cast<void(*)(ModuleBase*)>(GetProcAddress(H, "DestroyModule"));
    if (!Create || !Destroy) { FreeLibrary(H); return R; }
    ModuleBase* Inst = Create();
    if (!Inst) { FreeLibrary(H); return R; }

    ModuleInfo Info = Inst->Info();
    const auto& Opts = Inst->GetOptions();

    strncpy_s(R.Name, Info.Name.c_str(), sizeof(R.Name) - 1);
    std::string TypeStr = ModuleTypeToString(Info.Type);
    strncpy_s(R.Desc, Info.Description.c_str(), sizeof(R.Desc) - 1);
    strncpy_s(R.Author, Info.Author.c_str(), sizeof(R.Author) - 1);
    strncpy_s(R.TypeName, TypeStr.c_str(), sizeof(R.TypeName) - 1);

    int Idx = 0;
    for (const auto& [Key, OptPtr] : Opts) {
        if (Idx >= 32) break;
        strncpy_s(R.Opts[Idx].Name, OptPtr->GetName().c_str(), sizeof(R.Opts[Idx].Name) - 1);
        strncpy_s(R.Opts[Idx].Val, OptPtr->GetValue().c_str(), sizeof(R.Opts[Idx].Val) - 1);
        strncpy_s(R.Opts[Idx].Def, OptPtr->GetDefaultValue().c_str(), sizeof(R.Opts[Idx].Def) - 1);
        strncpy_s(R.Opts[Idx].Desc, OptPtr->GetDescription().c_str(), sizeof(R.Opts[Idx].Desc) - 1);
        strncpy_s(R.Opts[Idx].Type, OptPtr->TypeName().c_str(), sizeof(R.Opts[Idx].Type) - 1);
        R.Opts[Idx].Req = (OptPtr->GetRequired() == OptionRequired::Required);
        ++Idx;
    }
    R.OptCount = Idx;
    R.Valid = true;
    Destroy(Inst);
    FreeLibrary(H);
    return R;
}

inline bool TryLoadModuleDllFile(const wchar_t* Path, HMODULE& OutHandle, ModuleBase*& OutInst) {
    HMODULE H = LoadLibraryW(Path);
    if (!H) return false;
    auto Create = reinterpret_cast<ModuleBase*(*)()>(GetProcAddress(H, "CreateModule"));
    auto Destroy = reinterpret_cast<void(*)(ModuleBase*)>(GetProcAddress(H, "DestroyModule"));
    if (!Create || !Destroy) { FreeLibrary(H); return false; }
    ModuleBase* Inst = Create();
    if (!Inst) { FreeLibrary(H); return false; }
    OutHandle = H;
    OutInst = Inst;
    return true;
}

inline void ScanModuleDirectory(const std::string& Dir, std::vector<ModuleEntry>& Out, const std::string& Category) {
    namespace fs = std::filesystem;
    std::error_code Ec;
    if (!fs::exists(Dir, Ec)) return;

    for (const auto& Entry : fs::directory_iterator(Dir, Ec)) {
        if (!Entry.is_regular_file()) continue;
        std::string Ext = Entry.path().extension().string();
        std::transform(Ext.begin(), Ext.end(), Ext.begin(), ::tolower);
        if (Ext != ".dll" && Ext != ".sys") continue;

        ModuleEntry Mod;
        Mod.Path = fs::absolute(Entry.path(), Ec).string();
        Mod.Category = Category;
        Mod.Loaded = false;
        Mod.Handle = nullptr;
        Mod.ModuleInstance = nullptr;

        if (Ext == ".dll") {
            auto R = ProbeModuleInfo(Entry.path().c_str());
            if (R.Valid) {
                Mod.Name = R.Name;
                Mod.Description = R.Desc;
                Mod.Author = R.Author;
                Mod.Category = R.TypeName;
                for (int I = 0; I < R.OptCount; ++I) {
                    ModuleOption O;
                    O.Name = R.Opts[I].Name;
                    O.Value = R.Opts[I].Val;
                    O.Default = R.Opts[I].Def;
                    O.Description = R.Opts[I].Desc;
                    O.Required = R.Opts[I].Req;
                    O.Type = R.Opts[I].Type;
                    Mod.Options.push_back(O);
                }
            } else {
                Mod.Valid = false;
            }
        }

        if (Mod.Name.empty()) {
            Mod.Name = Entry.path().stem().string();
        }
        if (Mod.Description.empty()) Mod.Description = Mod.Name;
        if (Mod.Author.empty()) Mod.Author = "Unknown";

        Out.push_back(Mod);
    }
}

inline std::string NormalizeServiceNameText(std::string Name) {
    if (Name.empty()) {
        return "Driver";
    }
    for (char& Ch : Name) {
        const unsigned char C = static_cast<unsigned char>(Ch);
        const bool Ok = (C >= '0' && C <= '9') || (C >= 'A' && C <= 'Z') || (C >= 'a' && C <= 'z') || C == '_' || C == '-';
        if (!Ok) {
            Ch = '_';
        }
    }
    if (Name.size() > 120) {
        Name.resize(120);
    }
    return Name;
}

inline std::wstring Utf8ToWideText(const std::string& Value) {
    if (Value.empty()) return {};
    const int WideLen = MultiByteToWideChar(CP_UTF8, 0, Value.c_str(), -1, nullptr, 0);
    if (WideLen <= 0) return {};
    std::wstring Out(static_cast<size_t>(WideLen), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, Value.c_str(), -1, &Out[0], WideLen);
    while (!Out.empty() && Out.back() == L'\0') Out.pop_back();
    return Out;
}

inline void ScanDriverModuleDirectory(const std::string& Dir, std::vector<ModuleEntry>& Out) {
    namespace fs = std::filesystem;
    std::error_code Ec;
    if (!fs::exists(Dir, Ec)) return;

    for (const auto& Entry : fs::directory_iterator(Dir, Ec)) {
        if (!Entry.is_regular_file()) continue;
        std::string Ext = Entry.path().extension().string();
        std::transform(Ext.begin(), Ext.end(), Ext.begin(), ::tolower);
        if (Ext != ".sys") continue;

        ModuleEntry Mod;
        Mod.Path = fs::absolute(Entry.path(), Ec).string();
        Mod.Name = Entry.path().stem().string();
        Mod.Category = "System Driver";
        Mod.Description = Mod.Name;
        Mod.Author = "Unknown";
        Mod.ServiceName = NormalizeServiceNameText(Mod.Name);
        Mod.Loaded = false;
        Mod.Handle = nullptr;
        Mod.ModuleInstance = nullptr;
        Mod.Valid = true;
        Out.push_back(Mod);
    }
}

inline bool LoadDriverModule(ModuleEntry& Mod) {
    if (Mod.Loaded) return false;
    if (Mod.Path.empty()) return false;
    if (Mod.ServiceName.empty()) {
        Mod.ServiceName = NormalizeServiceNameText(std::filesystem::path(Mod.Path).stem().string());
    }
    const std::wstring WPath = Utf8ToWideText(Mod.Path);
    const std::wstring WService = Utf8ToWideText(Mod.ServiceName);
    if (WPath.empty() || WService.empty()) return false;
    const DWORD Rc = LoadDriverService(WPath.c_str(), WService.c_str());
    if (Rc == 0) {
        Mod.Loaded = true;
        return true;
    }
    return false;
}

inline bool UnloadDriverModule(ModuleEntry& Mod) {
    if (!Mod.Loaded) return false;
    if (Mod.ServiceName.empty()) return false;
    const std::wstring WService = Utf8ToWideText(Mod.ServiceName);
    if (WService.empty()) return false;
    const DWORD Rc = UnloadDriverService(WService.c_str());
    if (Rc == 0) {
        Mod.Loaded = false;
        return true;
    }
    return false;
}

inline bool LoadLibraryModule(ModuleEntry& Mod) {
    if (Mod.Loaded || Mod.Handle) return false;
    HMODULE H = nullptr;
    ModuleBase* Inst = nullptr;
    if (!TryLoadModuleDllFile(std::filesystem::path(Mod.Path).c_str(), H, Inst)) return false;
    Mod.Handle = H;
    Mod.ModuleInstance = Inst;
    Mod.Loaded = true;
    return true;
}

inline bool UnloadLibraryModule(ModuleEntry& Mod) {
    if (!Mod.Handle) return false;

    if (Mod.ModuleInstance) {
        auto Destroy = reinterpret_cast<void(*)(ModuleBase*)>(GetProcAddress(Mod.Handle, "DestroyModule"));
        if (Destroy) Destroy(static_cast<ModuleBase*>(Mod.ModuleInstance));
        Mod.ModuleInstance = nullptr;
    }

    FreeLibrary(Mod.Handle);
    Mod.Handle = nullptr;
    Mod.Loaded = false;
    return true;
}

inline ModuleEntry* FindModuleByName(std::vector<ModuleEntry>& List, const std::string& Name) {
    for (auto& M : List) {
        if (M.Name == Name) return &M;
    }
    return nullptr;
}

inline void ToggleModule(std::vector<ModuleEntry>& List, const std::string& Name) {
    auto* M = FindModuleByName(List, Name);
    if (!M) return;
    if (M->Loaded) {
        UnloadLibraryModule(*M);
    } else {
        LoadLibraryModule(*M);
    }
}

inline void ToggleDriver(std::vector<ModuleEntry>& List, const std::string& Name) {
    auto* M = FindModuleByName(List, Name);
    if (!M) return;
    if (M->Loaded) {
        UnloadDriverModule(*M);
    } else {
        LoadDriverModule(*M);
    }
}

inline std::vector<std::string> CategoryLabelList() {
    return {"All", "DLL Module", "System Driver"};
}

inline std::vector<ModuleEntry*> FilterModuleEntries(int CategoryIndex) {
    std::vector<ModuleEntry*> Result;
    if (CategoryIndex == 0) {
        for (auto& M : AppState::DllModules) if (M.Valid) Result.push_back(&M);
        for (auto& M : AppState::SysModules) if (M.Valid) Result.push_back(&M);
    } else if (CategoryIndex == 1) {
        for (auto& M : AppState::DllModules) if (M.Valid) Result.push_back(&M);
    } else if (CategoryIndex == 2) {
        for (auto& M : AppState::SysModules) if (M.Valid) Result.push_back(&M);
    }
    return Result;
}

inline std::vector<std::string> ModuleNameList(int CategoryIndex) {
    std::vector<std::string> Names;
    auto Mods = FilterModuleEntries(CategoryIndex);
    for (auto* M : Mods) Names.push_back(M->Name);
    return Names;
}

} 

namespace AppState {

inline void ScanModules() {
    DllModules.clear();
    ++ModuleScanVersion;

    auto& Cfg = Config::Current();
    for (const auto& Path : Cfg.Modules.Paths) {
        ModuleLoader::ScanModuleDirectory(Path, DllModules, "DLL Module");
    }
}

inline void ScanDrivers() {
    SysModules.clear();
    ++ModuleScanVersion;
    auto& Cfg = Config::Current();
    for (const auto& Path : Cfg.Drivers.Paths) {
        ModuleLoader::ScanDriverModuleDirectory(Path, SysModules);
    }
}

} 
