#pragma once

#include "Option.h"
#include <string>
#include <vector>
#include <map>
#include <memory>

enum class ModuleType
{
    Exploit,
    Payload,
    Auxiliary,
    Post
};

inline std::string ModuleTypeToString(ModuleType Type)
{
    switch (Type)
    {
    case ModuleType::Exploit:   return "Exploit";
    case ModuleType::Payload:   return "Payload";
    case ModuleType::Auxiliary: return "Auxiliary";
    case ModuleType::Post:      return "Post";
    default:                    return "Unknown";
    }
}

inline ModuleType ModuleTypeFromString(const std::string& Str)
{
    if (Str == "exploit")   return ModuleType::Exploit;
    if (Str == "payload")   return ModuleType::Payload;
    if (Str == "auxiliary") return ModuleType::Auxiliary;
    if (Str == "post")      return ModuleType::Post;
    return ModuleType::Auxiliary;
}

struct ModuleInfo
{
    std::string Name;
    std::string Description;
    std::string Author;
    std::string License;
    std::vector<std::string> References;
    ModuleType Type = ModuleType::Auxiliary;
    std::vector<std::string> Targets;
    std::string DefaultTarget;
    std::vector<std::string> Platform;
    std::string Arch;
    std::string DisclosureDate;
    int Rank = 0;
};

class ModuleBase
{
public:
    virtual ~ModuleBase() = default;

    virtual ModuleInfo Info() const = 0;
    virtual bool Check() { return false; }
    virtual bool Run() = 0;

    void RegisterOption(const std::string& Name, std::unique_ptr<Option> OptionPtr)
    {
        OptionPtr->InternalSetName(Name);
        Options_[Name] = std::move(OptionPtr);
    }

    bool ValidateOptions()
    {
        for (const auto& Pair : Options_)
        {
            if (Pair.second->GetRequired() == OptionRequired::Required && Pair.second->GetValue().empty())
                return false;
            if (!Pair.second->GetValue().empty() && !Pair.second->Validate(Pair.second->GetValue()))
                return false;
        }
        return true;
    }

    void SetOption(const std::string& Name, const std::string& Value)
    {
        auto It = Options_.find(Name);
        if (It == Options_.end()) return;
        It->second->SetValue(Value);
    }

    std::string GetOption(const std::string& Name) const
    {
        auto It = Options_.find(Name);
        if (It == Options_.end()) return "";
        return It->second->GetValue();
    }

    const std::map<std::string, std::unique_ptr<Option>>& GetOptions() const
    {
        return Options_;
    }

    bool HasOption(const std::string& Name) const
    {
        return Options_.find(Name) != Options_.end();
    }

protected:
    std::map<std::string, std::unique_ptr<Option>> Options_;
};
