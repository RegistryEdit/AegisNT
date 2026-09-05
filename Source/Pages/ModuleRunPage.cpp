QWidget *CreateModuleRunPage() {
  auto *Page = new QWidget;
  auto *Layout = new QVBoxLayout(Page);
  ConfigurePageLayout(Layout, 10);

  auto *Toolbar = new QHBoxLayout;
  ConfigureToolbarLayout(Toolbar);
  auto *Categories = new ComboBox;
  Categories->addItems({"All", "Exploit", "Auxiliary", "Post"});
  Categories->setCurrentIndex(0);
  Categories->setMinimumWidth(150);
  auto *Modules = new ComboBox;
  Modules->setCurrentIndex(0);
  Modules->setMinimumWidth(260);
  auto *Refresh = MakeButton("Refresh");
  auto *Execute = MakeButton("Run", true);
  auto *Stop = MakeButton("Stop");
  Toolbar->addWidget(Categories);
  Toolbar->addWidget(Modules);
  Toolbar->addStretch();
  Toolbar->addWidget(Refresh);
  Toolbar->addWidget(Stop);
  Toolbar->addWidget(Execute);
  Layout->addLayout(Toolbar);

  auto *Information =
      new BodyLabel("Select a module to configure its call controls.");
  Information->setWordWrap(true);
  Information->setMinimumHeight(42);
  Layout->addWidget(Information);

  auto *Options = new TableWidget;
  InstallFluentScrollBar(Options, Qt::Vertical);
  InstallFluentScrollBar(Options, Qt::Horizontal);
  Options->setColumnCount(4);
  Options->setRowCount(0);
  Options->setHorizontalHeaderLabels(
      {"Option", "Type", "Value", "Description"});
  Options->horizontalHeader()->setSectionResizeMode(
      0, QHeaderView::ResizeToContents);
  Options->horizontalHeader()->setSectionResizeMode(
      1, QHeaderView::ResizeToContents);
  Options->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
  Options->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
  Options->verticalHeader()->hide();
  Options->setSelectionMode(QAbstractItemView::NoSelection);
  Options->setEditTriggers(QAbstractItemView::NoEditTriggers);
  Options->setMinimumHeight(160);
  Options->verticalHeader()->setDefaultSectionSize(KCompactTableRowHeight);

  auto *OutputToolbar = new QHBoxLayout;
  ConfigureToolbarLayout(OutputToolbar);
  auto *OutputButton = MakeButton("Module Output");
  OutputButton->setSizePolicy(QSizePolicy::Maximum, QSizePolicy::Preferred);
  OutputToolbar->addWidget(OutputButton);
  OutputToolbar->addStretch();
  Layout->addWidget(Options, 1);
  Layout->addLayout(OutputToolbar);
  QObject::connect(OutputButton, &QPushButton::clicked, Page,
                   [Page] { ShowModuleOutputDialog(Page, "Module Output"); });

  const auto PopulateOptions = [Modules, Options, Information, Execute, Stop] {
    Options->setRowCount(0);
    const QString Path = Modules->currentData().toString();
    ModuleEntry *Entry = FindDllModule(Path);
    Execute->setEnabled(false);
    Stop->setEnabled(false);
    if (!Entry) {
      Information->setText("Select a module to configure its call controls.");
      return;
    }

    QString Error;
    if (!LoadModuleInstance(*Entry, &Error)) {
      const QString Message = "Failed to load module: " + Error + "\n" + Path;
      Information->setText(Message);
      AppendConsoleOutput("[!] ModuleRun: " + Message + "\n");
      return;
    }
    ModuleBase *Instance = static_cast<ModuleBase *>(Entry->ModuleInstance);
    const ModuleInfo Info = Instance->Info();
    Information->setText(
        QString("%1/%2  |  Author: %3  |  Target: %4\n%5")
            .arg(QString::fromStdString(ModuleTypeToString(Info.Type)),
                 QString::fromStdString(Info.Name),
                 QString::fromStdString(Info.Author.empty() ? Entry->Author
                                                            : Info.Author),
                 QString::fromStdString(Info.DefaultTarget.empty()
                                            ? "Unknown"
                                            : Info.DefaultTarget),
                 QString::fromStdString(Info.Description.empty()
                                            ? Entry->Description
                                            : Info.Description)));

    const auto &ModuleOptions = Instance->GetOptions();
    Options->setRowCount(static_cast<int>(ModuleOptions.size()));
    int Row = 0;
    for (const auto &[Name, OptionPointer] : ModuleOptions) {
      const bool Required =
          OptionPointer->GetRequired() == OptionRequired::Required;
      auto *NameItem = new QTableWidgetItem(QString::fromStdString(Name) +
                                            (Required ? " *" : ""));
      NameItem->setToolTip(
          QString::fromStdString(OptionPointer->GetDescription()));
      Options->setItem(Row, 0, NameItem);
      Options->setItem(Row, 1,
                       new QTableWidgetItem(
                           QString::fromStdString(OptionPointer->TypeName())));
      Options->setItem(Row, 3,
                       new QTableWidgetItem(QString::fromStdString(
                           OptionPointer->GetDescription())));

      const QString InitialValue =
          QString::fromStdString(OptionPointer->GetValue());
      if (auto *EnumOption = dynamic_cast<OptEnum *>(OptionPointer.get())) {
        auto *Editor = new ComboBox;
        for (const std::string &Choice : EnumOption->GetChoices())
          Editor->addItem(QString::fromStdString(Choice));
        Editor->setCurrentText(InitialValue);
        QObject::connect(Editor, &ComboBox::currentTextChanged, Editor,
                         [Path, Name](const QString &Value) {
                           if (ModuleEntry *Module = FindDllModule(Path);
                               Module && Module->ModuleInstance)
                             static_cast<ModuleBase *>(Module->ModuleInstance)
                                 ->SetOption(Name, Utf8Bytes(Value));
                         });
        Options->setCellWidget(Row, 2, Editor);
      } else if (dynamic_cast<OptBool *>(OptionPointer.get())) {
        auto *Editor = new ComboBox;
        Editor->addItems({"true", "false"});
        Editor->setCurrentText(
            InitialValue.compare("false", Qt::CaseInsensitive) == 0 ? "false"
                                                                    : "true");
        QObject::connect(Editor, &ComboBox::currentTextChanged, Editor,
                         [Path, Name](const QString &Value) {
                           if (ModuleEntry *Module = FindDllModule(Path);
                               Module && Module->ModuleInstance)
                             static_cast<ModuleBase *>(Module->ModuleInstance)
                                 ->SetOption(Name, Utf8Bytes(Value));
                         });
        Options->setCellWidget(Row, 2, Editor);
      } else {
        auto *Editor = new LineEdit;
        Editor->setText(InitialValue);
        Editor->setPlaceholderText(
            QString::fromStdString(OptionPointer->GetDefaultValue()));
        QObject::connect(Editor, &QLineEdit::textChanged, Editor,
                         [Path, Name](const QString &Value) {
                           if (ModuleEntry *Module = FindDllModule(Path);
                               Module && Module->ModuleInstance)
                             static_cast<ModuleBase *>(Module->ModuleInstance)
                                 ->SetOption(Name, Utf8Bytes(Value));
                         });
        Options->setCellWidget(Row, 2, Editor);
      }
      Options->setRowHeight(Row, KCompactTableRowHeight + 4);
      ++Row;
    }
    Execute->setEnabled(!ModuleRunning.load());
    Stop->setEnabled(ModuleRunning.load() && RunningModulePath == Path);
  };

  const auto PopulateModules = [Categories, Modules, PopulateOptions] {
    Modules->blockSignals(true);
    Modules->clear();
    Modules->addItem("Select module", QString());
    const QString Category = Categories->currentText();
    for (ModuleEntry *Module : ModulesByCategory(Category)) {
      const QString Path = QString::fromStdString(Module->Path);
      Modules->addItem(
          QString::fromStdString(Module->Category + "/" + Module->Name), Path);
    }
    Modules->setCurrentIndex(0);
    Modules->blockSignals(false);
    PopulateOptions();
  };

  QObject::connect(Categories, &ComboBox::currentTextChanged, Page,
                   [PopulateModules](const QString &) { PopulateModules(); });
  QObject::connect(Modules, &ComboBox::currentIndexChanged, Page,
                   [PopulateOptions](int) { PopulateOptions(); });
  QObject::connect(
      Refresh, &QPushButton::clicked, Page, [Page, PopulateModules] {
        if (ModuleRunning.load()) {
          ShowWarningNotice(
              Page, "ModuleRun",
              "Wait for the running module to finish before refreshing.");
          return;
        }
        ScanRuntimeModules();
        PopulateModules();
        ShowSuccessNotice(Page, "ModuleRun", "Module list refreshed.");
      });
  QObject::connect(Execute, &QPushButton::clicked, Page, [Modules, Page] {
    ModuleEntry *Entry = FindDllModule(Modules->currentData().toString());
    if (!Entry)
      return;
    if (!Entry->ModuleInstance) {
      QString Error;
      if (!LoadModuleInstance(*Entry, &Error)) {
        ShowErrorNotice(Page, "ModuleRun", Error);
        return;
      }
    }
    if (StartModuleExecution(Entry, nullptr))
      ShowSuccessNotice(Page, "ModuleRun", "Module execution started.");
  });
  QObject::connect(Stop, &QPushButton::clicked, Page, [Modules] {
    ModuleEntry *Entry = FindDllModule(Modules->currentData().toString());
    if (!Entry || !Entry->Handle ||
        RunningModulePath != QString::fromStdString(Entry->Path)) {
      AppendModuleOutput("[!] No running module.\n");
      return;
    }
    const auto StopModule = reinterpret_cast<void (*)()>(
        GetProcAddress(Entry->Handle, "StopModule"));
    if (!StopModule) {
      AppendModuleOutput(
          "[!] StopModule export not found; cannot signal module.\n");
      return;
    }
    StopModule();
    AppendModuleOutput("[*] Stop requested.\n");
    ShowSuccessNotice(qobject_cast<QWidget *>(Modules->window()), "ModuleRun",
                      "Stop request sent.");
  });

  auto *StateTimer = new QTimer(Page);
  QObject::connect(
      StateTimer, &QTimer::timeout, Page, [Page, Modules, Execute, Stop] {
        if (!Page->isVisible())
          return;
        const QString Path = Modules->currentData().toString();
        Execute->setEnabled(!Path.isEmpty() && !ModuleRunning.load());
        Stop->setEnabled(!Path.isEmpty() && ModuleRunning.load() &&
                         RunningModulePath == Path);
      });
  StateTimer->start(150);
  PopulateModules();
  return Page;
}
