#pragma once

#include <string>
#include <vector>
#include <windows.h>

struct ModuleOption {
  std::string Name;
  std::string Type;
  std::string Value;
  std::string Default;
  std::string Description;
  bool Required = false;
};

struct ModuleEntry {
  std::string Name;
  std::string Path;
  std::string Category;
  std::string Description;
  std::string Author;
  std::string ServiceName;
  HMODULE Handle = nullptr;
  void *ModuleInstance = nullptr;
  bool Loaded = false;
  bool Valid = true;
  std::vector<ModuleOption> Options;
};
