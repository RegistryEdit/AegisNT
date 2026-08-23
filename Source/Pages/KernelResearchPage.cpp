#include "../../Platform/AegisCoreCall.h"

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
    std::atomic_bool Refreshing = false;
  };
  auto State = std::make_shared<StateData>();

  struct SymbolRow { QString Module, Base, Size, Symbol, Path, Status; };
  struct AddressRow { QString Source, Address, Module, Rva, Symbol, Status; };
  struct IntegrityRow { QString Kind, Index, Address, Baseline, Owner, State; };
  struct PoolRow { QString Tag, Count, Bytes, Largest, Paged, Status; };
  struct ObjectRow { QString Name, Type, Address, Detail; };
  struct RefreshResult {
    std::vector<MDV2_RECORD> Modules;
    std::vector<SymbolRow> Symbols;
    std::vector<AddressRow> Ownership;
    std::vector<IntegrityRow> Integrity;
    std::vector<PoolRow> BigPool;
    std::vector<ObjectRow> Objects;
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
      Result.Modules = QueryAll(IOCTL_ENUM_KERNEL_MODULES_V2);
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
      std::vector<MDV2_RECORD> BigPoolRecords = QueryAll(IOCTL_ENUM_BIG_POOL_V2);
      Result.BigPoolOk = !BigPoolRecords.empty();

      // Older Ring0Core builds may not expose SystemBigPoolInformation. Use
      // the same native query from user mode as a compatibility fallback so
      // the page does not silently render an empty table.
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
                MDV2_RECORD Record{};
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
      for (const auto &Record : QueryAll(IOCTL_ENUM_OBJECTS_V2, "\\"))
        Result.Objects.push_back({QString::fromWCharArray(Record.Name),
                                  QString::fromWCharArray(Record.TypeName),
                                  Hex(Record.Address),
                                  QString::fromWCharArray(Record.Detail)});

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
    Status->setText(QString("%1 modules | %2 symbols | %3 pool tags | %4 objects")
                        .arg(State->Modules.size()).arg(Result.SymbolsOk ? "ready" : "offline")
                        .arg(Result.BigPool.size()).arg(Result.Objects.size()));
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
