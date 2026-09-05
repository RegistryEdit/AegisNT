bool OptionNameMatches(const std::string &Name, const QStringList &Aliases) {
  const QString CurrentName = QString::fromStdString(Name);
  for (const QString &Alias : Aliases) {
    if (CurrentName.compare(Alias, Qt::CaseInsensitive) == 0)
      return true;
  }
  return false;
}

QString CachedModuleOptionValue(const ModuleEntry &Module,
                                const QStringList &Aliases) {
  for (const ModuleOption &Option : Module.Options) {
    if (OptionNameMatches(Option.Name, Aliases))
      return QString::fromStdString(Option.Value);
  }
  return {};
}

void SetCachedModuleOptionValue(ModuleEntry &Module, const QStringList &Aliases,
                                const QString &Value) {
  for (ModuleOption &Option : Module.Options) {
    if (OptionNameMatches(Option.Name, Aliases))
      Option.Value = Utf8Bytes(Value);
  }
  if (Module.ModuleInstance) {
    auto *Instance = static_cast<ModuleBase *>(Module.ModuleInstance);
    for (const auto &[Name, OptionPointer] : Instance->GetOptions()) {
      Q_UNUSED(OptionPointer);
      if (OptionNameMatches(Name, Aliases))
        Instance->SetOption(Name, Utf8Bytes(Value));
    }
  }
}

QString NormalizedServiceName(QString Name) {
  if (Name.isEmpty())
    Name = "Driver";
  for (QChar &Character : Name) {
    if (!Character.isLetterOrNumber() && Character != '_' && Character != '-')
      Character = '_';
  }
  return Name.left(120);
}

void DestroyModuleInstance(ModuleEntry &Module) {
  if (!Module.Handle)
    return;
  if (Module.ModuleInstance) {
    const auto Destroy = reinterpret_cast<void (*)(ModuleBase *)>(
        GetProcAddress(Module.Handle, "DestroyModule"));
    if (Destroy)
      Destroy(static_cast<ModuleBase *>(Module.ModuleInstance));
    Module.ModuleInstance = nullptr;
  }
  FreeLibrary(Module.Handle);
  Module.Handle = nullptr;
  Module.Loaded = false;
}

bool LoadModuleInstance(ModuleEntry &Module, QString *Error = nullptr) {
  if (Module.Loaded && Module.Handle && Module.ModuleInstance)
    return true;
  const std::wstring Path = WidePath(QString::fromStdString(Module.Path));
  HMODULE Handle = LoadLibraryW(Path.c_str());
  if (!Handle) {
    if (Error)
      *Error = QString("LoadLibrary failed (%1)").arg(GetLastError());
    return false;
  }
  const auto Create = reinterpret_cast<ModuleBase *(*)()>(
      GetProcAddress(Handle, "CreateModule"));
  const auto Destroy = reinterpret_cast<void (*)(ModuleBase *)>(
      GetProcAddress(Handle, "DestroyModule"));
  if (!Create || !Destroy) {
    FreeLibrary(Handle);
    if (Error)
      *Error = "CreateModule/DestroyModule exports were not found.";
    return false;
  }
  ModuleBase *Instance = Create();
  if (!Instance) {
    FreeLibrary(Handle);
    if (Error)
      *Error = "CreateModule returned null.";
    return false;
  }
  Module.Handle = Handle;
  Module.ModuleInstance = Instance;
  for (const ModuleOption &Option : Module.Options) {
    if (!Option.Value.empty())
      Instance->SetOption(Option.Name, Option.Value);
  }
  Module.Loaded = true;
  return true;
}

ModuleEntry ProbeModuleFile(const QString &Path) {
  ModuleEntry Module;
  Module.Path = Utf8Bytes(QFileInfo(Path).absoluteFilePath());
  Module.Name = Utf8Bytes(QFileInfo(Path).completeBaseName());
  Module.Category = "DLL Module";
  Module.Description = Module.Name;
  Module.Author = "Unknown";
  QString Error;
  if (!LoadModuleInstance(Module, &Error)) {
    Module.Valid = false;
    Module.Description = Utf8Bytes(Error);
    return Module;
  }
  ModuleBase *Instance = static_cast<ModuleBase *>(Module.ModuleInstance);
  const ModuleInfo Info = Instance->Info();
  Module.Name = Info.Name.empty() ? Module.Name : Info.Name;
  Module.Description =
      Info.Description.empty() ? Module.Name : Info.Description;
  Module.Author = Info.Author.empty() ? "Unknown" : Info.Author;
  Module.Category = ModuleTypeToString(Info.Type);
  for (const auto &[Name, OptionPointer] : Instance->GetOptions()) {
    ModuleOption Item;
    Item.Name = Name;
    Item.Type = OptionPointer->TypeName();
    Item.Value = OptionPointer->GetValue();
    Item.Default = OptionPointer->GetDefaultValue();
    Item.Description = OptionPointer->GetDescription();
    Item.Required = OptionPointer->GetRequired() == OptionRequired::Required;
    Module.Options.push_back(Item);
  }
  DestroyModuleInstance(Module);
  Module.Valid = true;
  return Module;
}

bool SetDriverLoaded(ModuleEntry &Module, bool Loaded,
                     QString *Error = nullptr);
bool QueryDriverLoadedState(ModuleEntry &Module);
void CleanupManagedDriversOnExit();

bool InvokeModuleWithSeh(ModuleBase *Instance, bool *Result,
                         DWORD *ExceptionCode) {
  if (Result)
    *Result = false;
  if (ExceptionCode)
    *ExceptionCode = ERROR_SUCCESS;

  __try {
    if (Result)
      *Result = Instance->Run();
    return true;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    if (ExceptionCode)
      *ExceptionCode = GetExceptionCode();
    return false;
  }
}

void ScanRuntimeModules() {
  if (ModuleRunning.load())
    return;
  for (ModuleEntry &Module : DllModules)
    DestroyModuleInstance(Module);
  for (ModuleEntry &Driver : DriverModules)
    Driver.Loaded = QueryDriverLoadedState(Driver);
  DllModules.clear();
  DriverModules.clear();

  for (const QString &ConfiguredPath :
       ConfigurationPaths("Modules", "./Modules")) {
    QDir Directory(ResolveRuntimePath(ConfiguredPath));
    for (const QFileInfo &File :
         Directory.entryInfoList({"*.dll"}, QDir::Files, QDir::Name))
      DllModules.push_back(ProbeModuleFile(File.absoluteFilePath()));
  }
  for (const QString &ConfiguredPath :
       ConfigurationPaths("Drivers", "./Drivers")) {
    QDir Directory(ResolveRuntimePath(ConfiguredPath));
    for (const QFileInfo &File :
         Directory.entryInfoList({"*.sys"}, QDir::Files, QDir::Name)) {
      ModuleEntry Module;
      Module.Name = Utf8Bytes(File.completeBaseName());
      Module.Path = Utf8Bytes(File.absoluteFilePath());
      Module.Category = "System Driver";
      Module.Description = Module.Name;
      Module.Author = "Unknown";
      Module.ServiceName =
          Utf8Bytes(NormalizedServiceName(File.completeBaseName()));
      Module.Loaded = QueryDriverLoadedState(Module);
      DriverModules.push_back(Module);
    }
  }

  if (ConfigurationValue("Modules", "AutoLoad", true).toBool()) {
    for (ModuleEntry &Module : DllModules) {
      if (Module.Valid)
        LoadModuleInstance(Module);
    }
  }
  if (ConfigurationValue("Drivers", "AutoLoad", true).toBool()) {
    for (ModuleEntry &Driver : DriverModules)
      SetDriverLoaded(Driver, true);
  }
  ModulesScanned = true;
}

void EnsureRuntimeModulesScanned() {
  if (!ModulesScanned)
    ScanRuntimeModules();
}

void CleanupManagedDriversOnExit() {
  if (AegisNT::ApplicationContext().DriverShutdownPerformed.exchange(true))
    return;

  if (!ModulesScanned && DriverModules.empty())
    return;

  QStringList Failures;
  for (auto It = DriverModules.rbegin(); It != DriverModules.rend(); ++It) {
    ModuleEntry &Driver = *It;
    if (!Driver.Loaded)
      continue;

    QString Error;
    if (!SetDriverLoaded(Driver, false, &Error)) {
      const QString Name = QString::fromStdString(
          Driver.ServiceName.empty() ? Driver.Name : Driver.ServiceName);
      Failures.append(
          Name + ": " +
          (Error.isEmpty() ? "Failed to unload the driver service." : Error));
    }
  }

  if (!Failures.isEmpty()) {
    const std::wstring Message =
        (QStringLiteral("[AegisNT] Driver shutdown cleanup failures:\n") +
         Failures.join('\n'))
            .toStdWString();
    AppendConsoleOutput(QString::fromStdWString(Message) + "\n");
  }
}

bool SetDriverLoaded(ModuleEntry &Module, bool Loaded, QString *Error) {
  const std::wstring Service =
      QString::fromStdString(Module.ServiceName).toStdWString();
  DWORD Result = 1;
  if (Loaded) {
    const std::wstring Path =
        QString::fromStdString(Module.Path).toStdWString();
    Result = LoadDriverService(Path.c_str(), Service.c_str());
  } else {
    Result = UnloadDriverService(Service.c_str());
  }
  if (Result != 0) {
    Module.Loaded = QueryDriverLoadedState(Module);
    if (Error)
      *Error = Loaded ? "Failed to load the driver service."
                      : "Failed to unload the driver service.";
    return false;
  }
  Module.Loaded = QueryDriverLoadedState(Module);
  return true;
}

bool QueryDriverLoadedState(ModuleEntry &Module) {
  const std::wstring Service =
      QString::fromStdString(Module.ServiceName).toStdWString();
  if (Service.empty())
    return false;
  return IsDriverServiceRunning(Service.c_str());
}

std::vector<ModuleEntry *> ModulesByCategory(const QString &Category,
                                             bool IncludePayload = false) {
  EnsureRuntimeModulesScanned();
  std::vector<ModuleEntry *> Result;
  for (ModuleEntry &Module : DllModules) {
    if (!Module.Valid)
      continue;
    if (!IncludePayload && Module.Category == "Payload")
      continue;
    if (Category == "All" ||
        QString::fromStdString(Module.Category) == Category)
      Result.push_back(&Module);
  }
  return Result;
}

bool StartModuleExecution(ModuleEntry *Entry, PlainTextEdit *Output) {
  if (!Entry || ModuleRunning.exchange(true))
    return false;
  QString Error;
  if (!LoadModuleInstance(*Entry, &Error)) {
    ModuleRunning = false;
    AppendModuleOutput("[!] " + Error + "\n");
    return false;
  }
  ModuleBase *Instance = static_cast<ModuleBase *>(Entry->ModuleInstance);
  if (!Instance->ValidateOptions()) {
    ModuleRunning = false;
    AppendModuleOutput("[!] Required options are missing or invalid.\n");
    return false;
  }
  ModuleOutputWidget = Output;
  RunningModulePath = QString::fromStdString(Entry->Path);
  const QString Name = QString::fromStdString(Entry->Name);
  ClearModuleOutput();
  AppendModuleOutput("[*] Starting: " + Name + "\n");
  std::thread([Entry, Instance, Name] {
    bool Ok = false;
    QString Failure;
    const std::string Captured = Module::CaptureOutputStreaming(
        [&] {
          DWORD SehCode = ERROR_SUCCESS;
          try {
            if (!InvokeModuleWithSeh(Instance, &Ok, &SehCode))
              Failure = QString("[!] Module raised SEH exception 0x%1.\n")
                            .arg(static_cast<qulonglong>(SehCode), 8, 16,
                                 QLatin1Char('0'))
                            .toUpper();
          } catch (...) {
            Failure = "[!] Module raised a C++ exception.\n";
          }
        },
        [](const std::string &Chunk) { AppendModuleOutput(Utf8Text(Chunk)); });
    if (!Failure.isEmpty())
      AppendModuleOutput(Failure);
    if (Captured.empty() && !Ok && Failure.isEmpty())
      AppendModuleOutput("[!] Module returned failure without output.\n");
    AppendModuleOutput(QString("[*] Finished: %1\n").arg(Ok ? "OK" : "FAILED"));
    RunningModulePath.clear();
    ModuleRunning = false;
  }).detach();
  return true;
}
