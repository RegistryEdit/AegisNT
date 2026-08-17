QWidget *CreateKernelResearchPage() {
  using namespace AegisNT::KernelResearch;
  auto *Page = new QWidget;
  auto *Layout = new QVBoxLayout(Page);
  ConfigurePageLayout(Layout);

  auto *Toolbar = new QHBoxLayout;
  ConfigureToolbarLayout(Toolbar);
  auto *Search = new SearchLineEdit;
  ConfigureSearchLineEdit(Search, "Filter current research results", 320);
  auto *Refresh = MakeButton("Refresh", true);
  auto *SaveBaseline = MakeButton("Save Baseline");
  auto *LoadBaseline = MakeButton("Load Baseline");
  auto *Status = new BodyLabel("Ready");
  Toolbar->addWidget(Search);
  Toolbar->addWidget(Status, 1);
  Toolbar->addWidget(LoadBaseline);
  Toolbar->addWidget(SaveBaseline);
  Toolbar->addWidget(Refresh);
  Layout->addLayout(Toolbar);

  auto *Tabs = new TabBar;
  Tabs->setAddButtonVisible(false);
  Tabs->setTabsClosable(false);
  Tabs->setMovable(false);
  Layout->addWidget(Tabs);
  auto *Pages = new QStackedWidget;
  Layout->addWidget(Pages, 1);
  const auto MakeResearchTable = [](const QStringList &Headers) {
    auto *Table = MakeTable(Headers);
    Table->setSortingEnabled(true);
    Table->setTextElideMode(Qt::ElideRight);
    Table->verticalHeader()->setDefaultSectionSize(KCompactTableRowHeight);
    for (int I = 0; I < Headers.size(); ++I)
      Table->horizontalHeader()->setSectionResizeMode(
          I, I == Headers.size() - 1 ? QHeaderView::Stretch
                                     : QHeaderView::ResizeToContents);
    return Table;
  };

  auto *Symbols = MakeResearchTable(
      {"Module", "Base", "Size", "PDB/Symbol", "Path", "Status"});
  auto *Ownership = MakeResearchTable(
      {"Source", "Address", "Module", "RVA", "Symbol", "Status"});
  auto *Integrity = MakeResearchTable(
      {"Kind", "Index", "Address", "Baseline", "Module/Symbol", "State"});
  auto *BigPool = MakeResearchTable(
      {"Tag", "Allocations", "Bytes", "Largest", "Paged", "Status"});
  auto *Objects = new QTreeWidget;
  Objects->setHeaderLabels({"Object", "Type", "Address", "Detail"});
  Objects->header()->setSectionResizeMode(0, QHeaderView::Stretch);
  Objects->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
  Objects->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
  Objects->header()->setSectionResizeMode(3, QHeaderView::Stretch);
  InstallFluentScrollBar(Objects, Qt::Vertical);
  Tabs->addTab("symbols", "Symbols", Fluent::IconType::CODE);
  Tabs->addTab("ownership", "Address Ownership", Fluent::IconType::LINK);
  Tabs->addTab("integrity", "Integrity", Fluent::IconType::CERTIFICATE);
  Tabs->addTab("bigpool", "Big Pool", Fluent::IconType::TILES);
  Tabs->addTab("objects", "Objects", Fluent::IconType::FOLDER);
  Pages->addWidget(Symbols);
  Pages->addWidget(Ownership);
  Pages->addWidget(Integrity);
  Pages->addWidget(BigPool);
  Pages->addWidget(Objects);
  QObject::connect(Tabs, &TabBar::currentChanged, Pages,
                   &QStackedWidget::setCurrentIndex);
  QObject::connect(Pages, &QStackedWidget::currentChanged, Tabs,
                   &TabBar::setCurrentIndex);

  struct StateData {
    std::vector<MDV2_RECORD> Modules;
    QJsonObject Baseline;
  };
  auto State = std::make_shared<StateData>();

  const auto AddCell = [](QTableWidget *Table, int Row, int Column,
                          const QString &Text) {
    Table->setItem(Row, Column, new QTableWidgetItem(Text));
  };
  const auto AddAddressRow = [AddCell](QTableWidget *Table, const QString &Source,
                                       quint64 Address,
                                       const AddressInfo &Info) {
    const int Row = Table->rowCount();
    Table->insertRow(Row);
    AddCell(Table, Row, 0, Source);
    AddCell(Table, Row, 1, Hex(Address));
    AddCell(Table, Row, 2, Info.Module);
    AddCell(Table, Row, 3, Hex(Info.Rva));
    AddCell(Table, Row, 4, Info.Symbol.isEmpty() ? "-" : Info.Symbol);
    AddCell(Table, Row, 5, Info.Status);
  };

  const auto RefreshAll = [=] {
    Status->setText("Refreshing kernel research data...");
    QApplication::setOverrideCursor(Qt::WaitCursor);
    State->Modules = QueryAll(IOCTL_ENUM_KERNEL_MODULES_V2);
    QString SymbolError;
    auto &SymbolSvc = SymbolService::Instance();
    const bool SymbolsOk = SymbolSvc.Initialize(&SymbolError);
    if (SymbolsOk)
      SymbolSvc.ReloadModules(State->Modules);

    Symbols->setSortingEnabled(false);
    Symbols->setRowCount(0);
    for (const auto &Module : State->Modules) {
      const int Row = Symbols->rowCount();
      Symbols->insertRow(Row);
      const auto Owner = ResolveAddress(Module.Address, State->Modules);
      AddCell(Symbols, Row, 0, QString::fromWCharArray(Module.Name));
      AddCell(Symbols, Row, 1, Hex(Module.Address));
      AddCell(Symbols, Row, 2, QString::number(Module.SizeBytes));
      AddCell(Symbols, Row, 3, Owner.Symbol.isEmpty() ? "-" : Owner.Symbol);
      AddCell(Symbols, Row, 4, QString::fromWCharArray(Module.Path));
      AddCell(Symbols, Row, 5, SymbolsOk ? "Loaded/Deferred" : SymbolError);
    }
    Symbols->setSortingEnabled(true);

    Ownership->setSortingEnabled(false);
    Ownership->setRowCount(0);
    SYSTEM_TABLES_OUTPUT Summary{};
    if (QuerySystemTables(&Summary)) {
      AddAddressRow(Ownership, "SSDT", Summary.SsdtBase,
                    ResolveAddress(Summary.SsdtBase, State->Modules));
      AddAddressRow(Ownership, "ShadowSSDT", Summary.ShadowSsdtBase,
                    ResolveAddress(Summary.ShadowSsdtBase, State->Modules));
      AddAddressRow(Ownership, "IDT", Summary.IdtBase,
                    ResolveAddress(Summary.IdtBase, State->Modules));
      AddAddressRow(Ownership, "GDT", Summary.GdtBase,
                    ResolveAddress(Summary.GdtBase, State->Modules));
    }
    auto CallbackRecords = QueryAll(IOCTL_ENUM_CALLBACKS);
    if (CallbackRecords.empty()) {
      ULONG Count = 0;
      if (SendIoctlWithOutput(IOCTL_ENUM_CALLBACKS, nullptr, 0, &Count,
                              sizeof(Count), nullptr) && Count) {
        const size_t Bytes = FIELD_OFFSET(CALLBACK_ENUM_OUTPUT, Entries) +
                             Count * sizeof(CALLBACK_ENTRY);
        std::vector<unsigned char> Buffer(Bytes);
        if (SendIoctlWithOutput(IOCTL_ENUM_CALLBACKS, nullptr, 0, Buffer.data(),
                                static_cast<DWORD>(Bytes), nullptr)) {
          auto *Output = reinterpret_cast<CALLBACK_ENUM_OUTPUT *>(Buffer.data());
          for (ULONG I = 0; I < Output->Count; ++I)
            AddAddressRow(Ownership, "Callback", Output->Entries[I].Address,
                          ResolveAddress(Output->Entries[I].Address,
                                         State->Modules));
        }
      }
    }
    Ownership->setSortingEnabled(true);

    Integrity->setSortingEnabled(false);
    Integrity->setRowCount(0);
    QJsonObject Current;
    for (ULONG Kind : {SYSTEM_TABLE_KIND_IDT, SYSTEM_TABLE_KIND_SSDT,
                       SYSTEM_TABLE_KIND_SHADOW_SSDT}) {
      SYSTEM_TABLE_ENTRIES_OUTPUT Entries{};
      if (!QuerySystemTableEntries(Kind, &Entries))
        continue;
      const QString KindName = Kind == SYSTEM_TABLE_KIND_IDT ? "IDT" :
          (Kind == SYSTEM_TABLE_KIND_SSDT ? "SSDT" : "ShadowSSDT");
      QJsonArray Values;
      for (ULONG I = 0; I < Entries.Count; ++I) {
        const auto &Entry = Entries.Entries[I];
        Values.append(Hex(Entry.Address));
        const QString Key = KindName + ":" + QString::number(Entry.Index);
        const QJsonArray BaselineValues = State->Baseline.value(KindName).toArray();
        const QString Old = static_cast<int>(I) < BaselineValues.size()
                                ? BaselineValues.at(static_cast<int>(I)).toString()
                                : QString();
        const QString Now = Hex(Entry.Address);
        const auto Owner = ResolveAddress(Entry.Address, State->Modules);
        const int Row = Integrity->rowCount();
        Integrity->insertRow(Row);
        AddCell(Integrity, Row, 0, KindName);
        AddCell(Integrity, Row, 1, QString::number(Entry.Index));
        AddCell(Integrity, Row, 2, Now);
        AddCell(Integrity, Row, 3, Old.isEmpty() ? "-" : Old);
        AddCell(Integrity, Row, 4, Owner.Module + (Owner.Symbol.isEmpty() ? "" : "!" + Owner.Symbol));
        AddCell(Integrity, Row, 5, Old.isEmpty() ? "Unknown" : (Old == Now ? "Clean" : "Changed"));
        (void)Key;
      }
      Current.insert(KindName, Values);
    }
    Current.insert("capturedAtUtc", QDateTime::currentDateTimeUtc().toString(Qt::ISODate));
    Current.insert("schemaVersion", 1);
    Integrity->setProperty("currentBaseline", QJsonDocument(Current).toJson(QJsonDocument::Compact));
    Integrity->setSortingEnabled(true);

    struct PoolAggregate { quint64 Count = 0, Bytes = 0, Largest = 0, Paged = 0; };
    std::map<QString, PoolAggregate> Pools;
    for (const auto &Record : QueryAll(IOCTL_ENUM_BIG_POOL_V2)) {
      QString Tag = QString::fromWCharArray(Record.Name);
      if (Tag.isEmpty()) Tag = QString::fromWCharArray(Record.TypeName);
      auto &A = Pools[Tag.isEmpty() ? "????" : Tag];
      ++A.Count; A.Bytes += Record.SizeBytes; A.Largest = std::max(A.Largest, Record.SizeBytes);
      A.Paged += (Record.Flags & 1) ? 1 : 0;
    }
    BigPool->setSortingEnabled(false); BigPool->setRowCount(0);
    for (const auto &[Tag, A] : Pools) {
      const int Row = BigPool->rowCount(); BigPool->insertRow(Row);
      AddCell(BigPool, Row, 0, Tag); AddCell(BigPool, Row, 1, QString::number(A.Count));
      AddCell(BigPool, Row, 2, QString::number(A.Bytes));
      AddCell(BigPool, Row, 3, QString::number(A.Largest));
      AddCell(BigPool, Row, 4, QString::number(A.Paged));
      AddCell(BigPool, Row, 5, A.Bytes > 64ull * 1024 * 1024 ? "Large" : "Normal");
    }
    BigPool->setSortingEnabled(true);

    Objects->clear();
    std::map<QString, QTreeWidgetItem *> Nodes;
    Nodes["\\"] = new QTreeWidgetItem(Objects, {"\\", "Directory", "", "Object namespace"});
    for (const auto &Record : QueryAll(IOCTL_ENUM_OBJECTS_V2, "\\")) {
      const QString Name = QString::fromWCharArray(Record.Name);
      auto *Item = new QTreeWidgetItem(Nodes["\\"],
          {Name, QString::fromWCharArray(Record.TypeName), Hex(Record.Address),
           QString::fromWCharArray(Record.Detail)});
      (void)Item;
    }
    Objects->expandToDepth(0);
    QApplication::restoreOverrideCursor();
    Status->setText(QString("%1 modules | %2 symbols | %3 pool tags | %4 objects")
                        .arg(State->Modules.size()).arg(SymbolsOk ? "ready" : "offline")
                        .arg(Pools.size()).arg(Objects->topLevelItem(0)->childCount()));
  };

  QObject::connect(Refresh, &QPushButton::clicked, Page, RefreshAll);
  QObject::connect(SaveBaseline, &QPushButton::clicked, Page, [=] {
    const QString Path = QFileDialog::getSaveFileName(
        Page, "Save Kernel Baseline", "kernel-baseline.aegis-kernel-baseline.json",
        "Aegis Kernel Baseline (*.json)");
    if (Path.isEmpty()) return;
    QFile File(Path);
    if (File.open(QIODevice::WriteOnly)) {
      File.write(Integrity->property("currentBaseline").toByteArray());
      File.close();
      ShowSuccessNotice(Page, "Kernel Research", "Baseline saved.");
    }
  });
  QObject::connect(LoadBaseline, &QPushButton::clicked, Page, [=] {
    const QString Path = QFileDialog::getOpenFileName(Page, "Load Kernel Baseline", {}, "JSON (*.json)");
    if (Path.isEmpty()) return;
    QFile File(Path);
    if (!File.open(QIODevice::ReadOnly)) return;
    const auto Doc = QJsonDocument::fromJson(File.readAll());
    if (!Doc.isObject()) { ShowErrorNotice(Page, "Kernel Research", "Invalid baseline JSON."); return; }
    State->Baseline = Doc.object();
    RefreshAll();
  });
  QObject::connect(Search, &QLineEdit::textChanged, Page, [=](const QString &Text) {
    auto *Table = qobject_cast<QTableWidget *>(Pages->currentWidget());
    if (!Table) return;
    for (int Row = 0; Row < Table->rowCount(); ++Row) {
      bool Match = Text.isEmpty();
      for (int Col = 0; !Match && Col < Table->columnCount(); ++Col)
        Match = Table->item(Row, Col) && Table->item(Row, Col)->text().contains(Text, Qt::CaseInsensitive);
      Table->setRowHidden(Row, !Match);
    }
  });
  QTimer::singleShot(0, Refresh, &QPushButton::click);
  return Page;
}
