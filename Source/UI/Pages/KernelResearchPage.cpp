// ============================================================
// 内核研究页：符号/完整性基线/大页池/对象/地址归属 查询，
// 支持内核地址解析（KernelResearch.h）与符号缓存。
// ============================================================
#include "../../../Platform/AegisCoreCall.h"

QWidget *CreateKernelResearchPage() {
  using namespace AegisNT::KernelResearch;
  auto *Page = new AegisNT::PageBase(nullptr);
  auto *Layout = Page->GetMainLayout();
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
  auto *Rootkit = MakeResearchTable(
      {"Kind", "Severity", "Address", "Module", "Detail"});
  auto *ScanPanel = new QWidget;
  auto *ScanLayout = new QVBoxLayout(ScanPanel);
  ScanLayout->setContentsMargins(0, 0, 0, 0);
  ScanLayout->setSpacing(8);
  auto *ScanToolbar = new QHBoxLayout;
  auto *ScanModuleEdit = new LineEdit;
  ScanModuleEdit->setPlaceholderText(
      "Target module (empty = all), e.g. ntoskrnl.exe");
  auto *ScanPatternEdit = new LineEdit;
  ScanPatternEdit->setPlaceholderText(
      "Byte pattern with ?? wildcards, e.g. 4D 5A 90 ?? 00");
  auto *ScanButton = MakeButton("Scan", true);
  ScanToolbar->addWidget(ScanModuleEdit, 1);
  ScanToolbar->addWidget(ScanPatternEdit, 2);
  ScanToolbar->addWidget(ScanButton);
  ScanLayout->addLayout(ScanToolbar);
  auto *ScanTable =
      MakeResearchTable({"Module", "Address", "RVA", "Detail"});
  ScanLayout->addWidget(ScanTable, 1);
  Tabs->addTab("symbols", "Symbols", Fluent::IconType::CODE);
  Tabs->addTab("ownership", "Address Ownership", Fluent::IconType::LINK);
  Tabs->addTab("integrity", "Integrity", Fluent::IconType::CERTIFICATE);
  Tabs->addTab("bigpool", "Big Pool", Fluent::IconType::TILES);
  Tabs->addTab("objects", "Objects", Fluent::IconType::FOLDER);
  Tabs->addTab("rootkit", "Rootkit", Fluent::IconType::SEARCH);
  Tabs->addTab("scan", "Pattern Scan", Fluent::IconType::SEARCH);
  Pages->addWidget(Symbols);
  Pages->addWidget(Ownership);
  Pages->addWidget(Integrity);
  Pages->addWidget(BigPool);
  Pages->addWidget(Objects);
  Pages->addWidget(Rootkit);
  Pages->addWidget(ScanPanel);
  QObject::connect(Tabs, &TabBar::currentChanged, Pages,
                   &QStackedWidget::setCurrentIndex);
  QObject::connect(Pages, &QStackedWidget::currentChanged, Tabs,
                   &TabBar::setCurrentIndex);

  struct StateData {
    std::vector<INVENTORY_RECORD> Modules;
    QJsonObject Baseline;
    std::atomic_bool Refreshing = false;
  };
  auto State = std::make_shared<StateData>();

  struct SymbolRow { QString Module, Base, Size, Symbol, Path, Status; };
  struct AddressRow { QString Source, Address, Module, Rva, Symbol, Status; };
  struct IntegrityRow { QString Kind, Index, Address, Baseline, Owner, State; };
  struct PoolRow { QString Tag, Count, Bytes, Largest, Paged, Status; };
  struct ObjectRow { QString Name, Type, Address, Detail; };
  struct RootkitRow { QString Kind, Severity, Address, Size, Module, Detail; };
  struct RefreshResult {
    std::vector<INVENTORY_RECORD> Modules;
    std::vector<SymbolRow> Symbols;
    std::vector<AddressRow> Ownership;
    std::vector<IntegrityRow> Integrity;
    std::vector<PoolRow> BigPool;
    std::vector<ObjectRow> Objects;
    std::vector<RootkitRow> Rootkit;
    QJsonObject CurrentBaseline;
    bool SymbolsOk = false;
    bool BigPoolOk = false;
    QString SymbolError;
  };

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
    bool Expected = false;
    if (!State->Refreshing.compare_exchange_strong(Expected, true))
      return;
    Status->setText("Refreshing kernel research data...");
    Refresh->setEnabled(false);
    const QJsonObject Baseline = State->Baseline;
    QPointer<QWidget> Guard(Page);
    std::thread([=]() mutable {
      RefreshResult Result;
      Result.Modules = QueryAll(IOCTL_ENUM_KERNEL_MODULES);
      auto &SymbolSvc = SymbolService::Instance();
      Result.SymbolsOk = SymbolSvc.Initialize(&Result.SymbolError);
      if (Result.SymbolsOk)
        SymbolSvc.ReloadModules(Result.Modules);

      for (const auto &Module : Result.Modules) {
        const auto Owner = ResolveAddress(Module.Address, Result.Modules);
        Result.Symbols.push_back({QString::fromWCharArray(Module.Name),
                                  Hex(Module.Address),
                                  QString::number(Module.SizeBytes),
                                  Owner.Symbol.isEmpty() ? "-" : Owner.Symbol,
                                  QString::fromWCharArray(Module.Path),
                                  Result.SymbolsOk ? "Loaded/Deferred"
                                                  : Result.SymbolError});
      }

      const auto AddAddress = [&Result](const QString &Source, quint64 Address,
                                        const AddressInfo &Info) {
        Result.Ownership.push_back({Source, Hex(Address), Info.Module,
                                    Hex(Info.Rva),
                                    Info.Symbol.isEmpty() ? "-" : Info.Symbol,
                                    Info.Status});
      };
      SYSTEM_TABLES_OUTPUT Summary{};
      if (QuerySystemTables(&Summary)) {
        AddAddress("SSDT", Summary.SsdtBase,
                   ResolveAddress(Summary.SsdtBase, Result.Modules));
        AddAddress("ShadowSSDT", Summary.ShadowSsdtBase,
                   ResolveAddress(Summary.ShadowSsdtBase, Result.Modules));
        AddAddress("IDT", Summary.IdtBase,
                   ResolveAddress(Summary.IdtBase, Result.Modules));
        AddAddress("GDT", Summary.GdtBase,
                   ResolveAddress(Summary.GdtBase, Result.Modules));
      }
      const auto CallbackRecords = QueryAll(IOCTL_ENUM_CALLBACKS);
      ULONG CallbackCount = 0;
      if (CallbackRecords.empty() &&
          SendIoctlWithOutput(IOCTL_ENUM_CALLBACKS, nullptr, 0,
                              &CallbackCount, sizeof(CallbackCount), nullptr) &&
          CallbackCount != 0) {
        const size_t Bytes = FIELD_OFFSET(CALLBACK_ENUM_OUTPUT, Entries) +
                             CallbackCount * sizeof(CALLBACK_ENTRY);
        std::vector<unsigned char> Buffer(Bytes);
        if (SendIoctlWithOutput(IOCTL_ENUM_CALLBACKS, nullptr, 0, Buffer.data(),
                                static_cast<DWORD>(Bytes), nullptr)) {
          const auto *Output =
              reinterpret_cast<const CALLBACK_ENUM_OUTPUT *>(Buffer.data());
          for (ULONG I = 0; I < Output->Count; ++I)
            AddAddress("Callback", Output->Entries[I].Address,
                       ResolveAddress(Output->Entries[I].Address,
                                      Result.Modules));
        }
      }

      for (ULONG Kind : {SYSTEM_TABLE_KIND_IDT, SYSTEM_TABLE_KIND_SSDT,
                         SYSTEM_TABLE_KIND_SHADOW_SSDT}) {
        SYSTEM_TABLE_ENTRIES_OUTPUT Entries{};
        if (!QuerySystemTableEntries(Kind, &Entries))
          continue;
        const QString KindName = Kind == SYSTEM_TABLE_KIND_IDT ? "IDT" :
            (Kind == SYSTEM_TABLE_KIND_SSDT ? "SSDT" : "ShadowSSDT");
        QJsonArray Values;
        const QJsonArray BaselineValues = Baseline.value(KindName).toArray();
        for (ULONG I = 0; I < Entries.Count; ++I) {
          const auto &Entry = Entries.Entries[I];
          const QString Now = Hex(Entry.Address);
          const QString Old = static_cast<int>(I) < BaselineValues.size()
                                  ? BaselineValues.at(static_cast<int>(I)).toString()
                                  : QString();
          const auto Owner = ResolveAddress(Entry.Address, Result.Modules);
          Result.Integrity.push_back({KindName, QString::number(Entry.Index),
                                      Now, Old.isEmpty() ? "-" : Old,
                                      Owner.Module + (Owner.Symbol.isEmpty()
                                                          ? ""
                                                          : "!" + Owner.Symbol),
                                      Old.isEmpty() ? "Unknown"
                                                    : (Old == Now ? "Clean" : "Changed")});
          Values.append(Now);
        }
        Result.CurrentBaseline.insert(KindName, Values);
      }
      Result.CurrentBaseline.insert("capturedAtUtc",
          QDateTime::currentDateTimeUtc().toString(Qt::ISODate));
      Result.CurrentBaseline.insert("schemaVersion", 1);

      struct PoolAggregate { quint64 Count = 0, Bytes = 0, Largest = 0, Paged = 0; };
      std::map<QString, PoolAggregate> Pools;
      std::vector<INVENTORY_RECORD> BigPoolRecords = QueryAll(IOCTL_ENUM_BIG_POOL);
      Result.BigPoolOk = !BigPoolRecords.empty();

      // 较旧的 Ring0Core 构建可能不暴露 SystemBigPoolInformation：
      // 回退到用户态的原生查询作为兼容方案，避免页面静默渲染空表。
      if (BigPoolRecords.empty()) {
        using NtQuerySystemInformationFn =
            NTSTATUS(NTAPI *)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
        struct NativeBigPoolEntry {
          union { PVOID VirtualAddress; ULONG_PTR NonPaged : 1; };
          ULONG_PTR SizeInBytes;
          union { UCHAR Tag[4]; ULONG TagUlong; };
        };
        struct NativeBigPoolInformation {
          ULONG Count;
          NativeBigPoolEntry AllocatedInfo[1];
        };
        const auto QueryNative = reinterpret_cast<NtQuerySystemInformationFn>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                           "NtQuerySystemInformation"));
        constexpr SYSTEM_INFORMATION_CLASS BigPoolClass =
            static_cast<SYSTEM_INFORMATION_CLASS>(66);
        constexpr NTSTATUS ResizeStatuses[] = {
            static_cast<NTSTATUS>(0xC0000004L),
            static_cast<NTSTATUS>(0x80000005L),
            static_cast<NTSTATUS>(0xC0000023L)};
        auto IsResizeStatus = [&](NTSTATUS Status) {
          return Status == ResizeStatuses[0] || Status == ResizeStatuses[1] ||
                 Status == ResizeStatuses[2];
        };
        if (QueryNative) {
          ULONG Size = 1u << 20;
          std::vector<BYTE> Buffer(Size);
          ULONG ReturnLength = 0;
          NTSTATUS Status = QueryNative(BigPoolClass, Buffer.data(), Size,
                                        &ReturnLength);
          for (int Attempt = 0; IsResizeStatus(Status) && Attempt < 8;
               ++Attempt) {
            Size = std::max(Size * 2u, ReturnLength + 0x1000u);
            Buffer.resize(Size);
            Status = QueryNative(BigPoolClass, Buffer.data(), Size,
                                 &ReturnLength);
          }
          if (Status >= 0 && Buffer.size() >= sizeof(ULONG)) {
            const auto *Native = reinterpret_cast<const NativeBigPoolInformation *>(
                Buffer.data());
            const size_t Required = FIELD_OFFSET(NativeBigPoolInformation, AllocatedInfo) +
                static_cast<size_t>(Native->Count) * sizeof(NativeBigPoolEntry);
            if (Required <= Buffer.size()) {
              BigPoolRecords.reserve(Native->Count);
              for (ULONG Index = 0; Index < Native->Count; ++Index) {
                const auto &Pool = Native->AllocatedInfo[Index];
                INVENTORY_RECORD Record{};
                Record.Kind = 5;
                Record.Address = reinterpret_cast<ULONG64>(Pool.VirtualAddress) & ~1ull;
                Record.SizeBytes = Pool.SizeInBytes;
                Record.Flags = (reinterpret_cast<ULONG_PTR>(Pool.VirtualAddress) & 1) ? 1u : 0u;
                for (ULONG Char = 0; Char < 4; ++Char)
                  Record.Name[Char] = static_cast<WCHAR>(Pool.Tag[Char]);
                Record.Name[4] = L'\0';
                BigPoolRecords.push_back(Record);
              }
              Result.BigPoolOk = true;
            }
          }
        }
      }
      for (const auto &Record : BigPoolRecords) {
        QString Tag = QString::fromWCharArray(Record.Name);
        if (Tag.isEmpty()) Tag = QString::fromWCharArray(Record.TypeName);
        auto &A = Pools[Tag.isEmpty() ? "????" : Tag];
        ++A.Count; A.Bytes += Record.SizeBytes; A.Largest = std::max(A.Largest, Record.SizeBytes);
        A.Paged += (Record.Flags & 1) ? 1 : 0;
      }
      for (const auto &[Tag, A] : Pools)
        Result.BigPool.push_back({Tag, QString::number(A.Count),
                                  QString::number(A.Bytes), QString::number(A.Largest),
                                  QString::number(A.Paged),
                                  A.Bytes > 64ull * 1024 * 1024 ? "Large" : "Normal"});
      if (Result.BigPool.empty())
        Result.BigPool.push_back({"(none)", "0", "0", "0", "0",
                                  Result.BigPoolOk ? "No allocations" :
                                                      "Unavailable"});
      for (const auto &Record : QueryAll(IOCTL_ENUM_OBJECTS, "\\"))
        Result.Objects.push_back({QString::fromWCharArray(Record.Name),
                                  QString::fromWCharArray(Record.TypeName),
                                  Hex(Record.Address),
                                  QString::fromWCharArray(Record.Detail)});

      ROOTKIT_SCAN_INPUT ScanInput{};
      ScanInput.Size = sizeof(ScanInput);
      ScanInput.Version = 1;
      ScanInput.Kind = ROOTKIT_SCAN_KIND_ALL;
      ScanInput.Flags = ROOTKIT_SCAN_FLAG_REPORT_ONLY;
      std::vector<unsigned char> ScanBuffer(sizeof(ROOTKIT_SCAN_OUTPUT));
      if (SendIoctlWithOutput(IOCTL_ROOTKIT_SCAN, &ScanInput, sizeof(ScanInput),
                              ScanBuffer.data(),
                              static_cast<DWORD>(ScanBuffer.size()), nullptr)) {
        const auto *Scan = reinterpret_cast<const ROOTKIT_SCAN_OUTPUT *>(
            ScanBuffer.data());
        const auto DescribeKind = [](ULONG Kind) {
          switch (Kind) {
          case ROOTKIT_SCAN_KIND_HIDDEN_MODULES: return "Hidden Module";
          case ROOTKIT_SCAN_KIND_TEXT_INTEGRITY: return "Text Integrity";
          case ROOTKIT_SCAN_KIND_CALLBACKS: return "Callback";
          default: return "Scan";
          }
        };
        const auto DescribeSeverity = [](ULONG Severity) {
          switch (Severity) {
          case 0: return "Info";
          case 1: return "Warning";
          case 2: return "Critical";
          default: return "Info";
          }
        };
        for (ULONG I = 0; I < Scan->Count && I < ROOTKIT_SCAN_MAX_RECORDS; ++I) {
          const auto &Record = Scan->Records[I];
          Result.Rootkit.push_back(
              {DescribeKind(Record.Kind), DescribeSeverity(Record.Severity),
               Hex(Record.Address), Hex(Record.Size),
               QString::fromWCharArray(Record.ModuleName),
               QString::fromWCharArray(Record.Detail)});
        }
      }
      if (Result.Rootkit.empty())
        Result.Rootkit.push_back(
            {"Scan", "Info", "-", "-", "-", "No findings or scan unavailable"});

      if (!Guard)
        return;
      QMetaObject::invokeMethod(Guard, [=, Result = std::move(Result)]() mutable {
        if (!Guard)
          return;
        State->Modules = std::move(Result.Modules);
    Symbols->setSortingEnabled(false);
    Symbols->setRowCount(0);
        for (const auto &Value : Result.Symbols) {
          const int Row = Symbols->rowCount();
          Symbols->insertRow(Row);
          AddCell(Symbols, Row, 0, Value.Module);
          AddCell(Symbols, Row, 1, Value.Base);
          AddCell(Symbols, Row, 2, Value.Size);
          AddCell(Symbols, Row, 3, Value.Symbol);
          AddCell(Symbols, Row, 4, Value.Path);
          AddCell(Symbols, Row, 5, Value.Status);
    }
    Symbols->setSortingEnabled(true);

    Ownership->setSortingEnabled(false);
    Ownership->setRowCount(0);
        for (const auto &Value : Result.Ownership) {
          const int Row = Ownership->rowCount(); Ownership->insertRow(Row);
          AddCell(Ownership, Row, 0, Value.Source); AddCell(Ownership, Row, 1, Value.Address);
          AddCell(Ownership, Row, 2, Value.Module); AddCell(Ownership, Row, 3, Value.Rva);
          AddCell(Ownership, Row, 4, Value.Symbol); AddCell(Ownership, Row, 5, Value.Status);
        }
    Ownership->setSortingEnabled(true);

    Integrity->setSortingEnabled(false);
    Integrity->setRowCount(0);
        for (const auto &Value : Result.Integrity) {
        const int Row = Integrity->rowCount();
        Integrity->insertRow(Row);
          AddCell(Integrity, Row, 0, Value.Kind); AddCell(Integrity, Row, 1, Value.Index);
          AddCell(Integrity, Row, 2, Value.Address); AddCell(Integrity, Row, 3, Value.Baseline);
          AddCell(Integrity, Row, 4, Value.Owner); AddCell(Integrity, Row, 5, Value.State);
      }
        Integrity->setProperty("currentBaseline", QJsonDocument(Result.CurrentBaseline).toJson(QJsonDocument::Compact));
    Integrity->setSortingEnabled(true);

    BigPool->setSortingEnabled(false); BigPool->setRowCount(0);
        for (const auto &Value : Result.BigPool) {
          const int Row = BigPool->rowCount(); BigPool->insertRow(Row);
          AddCell(BigPool, Row, 0, Value.Tag); AddCell(BigPool, Row, 1, Value.Count);
          AddCell(BigPool, Row, 2, Value.Bytes); AddCell(BigPool, Row, 3, Value.Largest);
          AddCell(BigPool, Row, 4, Value.Paged); AddCell(BigPool, Row, 5, Value.Status);
    }
    BigPool->setSortingEnabled(true);

    Objects->clear();
        auto *Root = new QTreeWidgetItem(Objects, {"\\", "Directory", "", "Object namespace"});
        for (const auto &Value : Result.Objects)
          new QTreeWidgetItem(Root, {Value.Name, Value.Type, Value.Address, Value.Detail});
    Objects->expandToDepth(0);

    Rootkit->setSortingEnabled(false);
    Rootkit->setRowCount(0);
        for (const auto &Value : Result.Rootkit) {
          const int Row = Rootkit->rowCount();
          Rootkit->insertRow(Row);
          AddCell(Rootkit, Row, 0, Value.Kind);
          auto *SeverityItem = new QTableWidgetItem(Value.Severity);
          const QString Severity = Value.Severity.toLower();
          if (Severity == "critical")
            SeverityItem->setForeground(QColor("#E81123"));
          else if (Severity == "warning")
            SeverityItem->setForeground(QColor("#FF8C00"));
          else
            SeverityItem->setForeground(QColor("#107C10"));
          Rootkit->setItem(Row, 1, SeverityItem);
          AddCell(Rootkit, Row, 2, Value.Address);
          AddCell(Rootkit, Row, 3, Value.Module);
          AddCell(Rootkit, Row, 4, Value.Detail);
        }
    Rootkit->setSortingEnabled(true);

    Status->setText(QString("%1 modules | %2 symbols | %3 pool tags | %4 objects | %5 rootkit")
                        .arg(State->Modules.size()).arg(Result.SymbolsOk ? "ready" : "offline")
                        .arg(Result.BigPool.size()).arg(Result.Objects.size())
                        .arg(Result.Rootkit.size()));
        Refresh->setEnabled(true);
        State->Refreshing.store(false);
      }, Qt::QueuedConnection);
    }).detach();
  };

  QObject::connect(Refresh, &QPushButton::clicked, Page, RefreshAll);
  QObject::connect(SaveBaseline, &QPushButton::clicked, Page, [=] {
    const QString Path = QFileDialog::getSaveFileName(
        Page, "Save Kernel Baseline", "kernel-baseline.aegis-kernel-baseline.json",
        "Aegis Kernel Baseline (*.json)");
    if (Path.isEmpty()) return;
    QFile File(Path);
    if (File.open(QIODevice::WriteOnly)) {
      const QByteArray Data = Integrity->property("currentBaseline").toByteArray();
      if (File.write(Data) != Data.size()) {
        ShowErrorNotice(Page, "Kernel Research",
                        "Failed to save baseline: " + File.errorString());
        return;
      }
      File.close();
      ShowSuccessNotice(Page, "Kernel Research", "Baseline saved.");
    } else
      ShowErrorNotice(Page, "Kernel Research",
                      "Failed to save baseline: " + File.errorString());
  });
  QObject::connect(LoadBaseline, &QPushButton::clicked, Page, [=] {
    const QString Path = QFileDialog::getOpenFileName(Page, "Load Kernel Baseline", {}, "JSON (*.json)");
    if (Path.isEmpty()) return;
    QFile File(Path);
    if (!File.open(QIODevice::ReadOnly)) {
      ShowErrorNotice(Page, "Kernel Research",
                      "Failed to open baseline: " + File.errorString());
      return;
    }
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
  QObject::connect(ScanButton, &QPushButton::clicked, Page, [=] {
    const QString Pattern = ScanPatternEdit->text().trimmed();
    if (Pattern.isEmpty()) {
      ShowErrorNotice(Page, "Kernel Research",
                      "Enter a byte pattern first.");
      return;
    }
    ScanButton->setEnabled(false);
    Status->setText("Scanning kernel memory...");
    const std::wstring ModuleW = ScanModuleEdit->text().trimmed().toStdWString();
    const std::wstring PatternW = Pattern.toStdWString();
    QPointer<QWidget> Guard(Page);
    std::thread([=]() mutable {
      KERNEL_PATTERN_SCAN_OUTPUT Output{};
      const bool Ok = KernelPatternScan(
          ModuleW.empty() ? nullptr : ModuleW.c_str(), PatternW.c_str(),
          &Output);
      QMetaObject::invokeMethod(
          qApp,
          [Guard, ScanTable, ScanButton, Status, Ok, Output]() {
            if (!Guard) return;
            ScanButton->setEnabled(true);
            ScanTable->setRowCount(0);
            if (!Ok) {
              Status->setText("Pattern scan failed");
              ShowErrorNotice(Guard, "Kernel Research",
                              "Kernel pattern scan failed.\nWin32 error: " +
                                  QString::number(G_LastAegisCoreError));
              return;
            }
            Status->setText(QString("Pattern scan: %1 hit(s) across %2 "
                                    "module(s) (per page, first hit)")
                                .arg(Output.TotalHits)
                                .arg(Output.ScannedModules));
            for (ULONG I = 0; I < Output.HitCount; ++I) {
              const int Row = ScanTable->rowCount();
              ScanTable->insertRow(Row);
              ScanTable->setItem(
                  Row, 0,
                  new QTableWidgetItem(
                      QString::fromWCharArray(Output.Hits[I].ModuleName)));
              ScanTable->setItem(Row, 1,
                                 new QTableWidgetItem(Hex(Output.Hits[I].Address)));
              ScanTable->setItem(Row, 2,
                                 new QTableWidgetItem(Hex(Output.Hits[I].Rva)));
              ScanTable->setItem(
                  Row, 3,
                  new QTableWidgetItem(
                      QString("Module base %1")
                          .arg(Hex(Output.Hits[I].ModuleBase))));
            }
          });
    }).detach();
  });
  QTimer::singleShot(0, Refresh, &QPushButton::click);
  return Page;
}
