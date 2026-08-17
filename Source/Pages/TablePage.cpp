QWidget *CreateTablePage() {
  struct TableQueryResult {
    SYSTEM_TABLES_OUTPUT Summary{};
    std::array<SYSTEM_TABLE_ENTRIES_OUTPUT, 5> Entries{};
    std::array<bool, 5> Available{};
    PIDDB_CACHE_ENUM_OUTPUT PiDDB{};
    bool PiDDBAvailable = false;
    bool PiDDBQueried = false;
    DWORD ErrorCode = ERROR_SUCCESS;
    bool Success = false;
  };
  struct TablePageState {
    std::shared_ptr<TableQueryResult> Result =
        std::make_shared<TableQueryResult>();
    std::atomic_bool Refreshing = false;
    std::atomic_bool TabLoading = false;
    std::vector<MDV2_RECORD> Modules;
  };

  auto *Page = new QWidget;
  auto *Layout = new QVBoxLayout(Page);
  ConfigurePageLayout(Layout);
  auto *Toolbar = new QHBoxLayout;
  ConfigureToolbarLayout(Toolbar);
  auto *Kind = new ComboBox;
  Kind->addItems({"InterruptDescriptorTable", "I/O Timer", "SSDT", "ShadowSSDT",
                  "GlobalDescriptorTable", "PiDDBCacheTable", "CPU Registers"});
  Kind->setCurrentIndex(0);
  Kind->setMinimumWidth(300);
  auto *Search = new SearchLineEdit;
  Search->setPlaceholderText("Search index, name, address, or metadata");
  Search->setClearButtonEnabled(true);
  Search->setMaximumWidth(320);
  auto *Status = new BodyLabel("Not queried.");
  auto *RefreshIndicator = new IndeterminateProgressRing(Page, false);
  RefreshIndicator->setFixedSize(22, 22);
  RefreshIndicator->hide();
  auto *Refresh = MakeButton("Refresh", true);
  Toolbar->addWidget(Kind);
  Toolbar->addWidget(Search);
  Toolbar->addStretch();
  Toolbar->addWidget(Status);
  Toolbar->addWidget(RefreshIndicator);
  Toolbar->addWidget(Refresh);
  Layout->addLayout(Toolbar);
  auto *Table = MakeTable({"Index", "Name", "Address", "Module / Symbol", "State", "Metadata"});
  Table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
  Table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
  Layout->addWidget(Table, 1);
  const auto State = std::make_shared<TablePageState>();
  const auto Populate = [Kind, Search, Table, State] {
    Table->clearContents();
    Table->setRowCount(0);
    const int Tab = Kind->currentIndex();
    const std::shared_ptr<TableQueryResult> Result = State->Result;
    const SYSTEM_TABLES_OUTPUT &Summary = Result->Summary;
    const QString SearchText = Search->text().trimmed();
    const auto AddRow = [Table, State,
                         SearchText](const QString &Index, const QString &Name,
                                     const QString &Address,
                                     const QString &Metadata = QString(),
                                     quint64 TargetAddress = 0) {
      AegisNT::KernelResearch::AddressInfo Owner;
      if (TargetAddress)
        Owner = AegisNT::KernelResearch::ResolveAddress(TargetAddress, State->Modules);
      const QString Ownership = TargetAddress
          ? (Owner.Module.isEmpty() ? QString("-") : Owner.Module + QString("+0x%1").arg(Owner.Rva, 0, 16).toUpper()) +
                (Owner.Symbol.isEmpty() ? QString() : " | " + Owner.Symbol)
          : QString("-");
      const QString OwnershipState = TargetAddress ? Owner.Status : QString("-");
      if (!SearchText.isEmpty() &&
          !(Index + " " + Name + " " + Address + " " + Ownership + " " + OwnershipState + " " + Metadata)
               .contains(SearchText, Qt::CaseInsensitive))
        return;
      const int Row = Table->rowCount();
      Table->insertRow(Row);
      Table->setItem(Row, 0, new QTableWidgetItem(Index));
      Table->setItem(Row, 1, new QTableWidgetItem(Name));
      Table->setItem(Row, 2, new QTableWidgetItem(Address));
      Table->setItem(Row, 3, new QTableWidgetItem(Ownership));
      auto *StateItem = new QTableWidgetItem(OwnershipState);
      if (OwnershipState == "OutsideModule")
        StateItem->setForeground(QColor(220, 70, 70));
      Table->setItem(Row, 4, StateItem);
      Table->setItem(Row, 5, new QTableWidgetItem(Metadata));
      Table->setRowHeight(Row, KCompactTableRowHeight);
    };
    if (Tab < 5 && Result->Available[Tab]) {
      const auto &Output = Result->Entries[Tab];
      AddRow(
          "-", "Table Base",
          QString("0x%1")
              .arg(Output.TableBase, sizeof(ULONG_PTR) * 2, 16,
                   QLatin1Char('0'))
              .toUpper(),
          QString("%1 of %2 entries").arg(Output.Count).arg(Output.TotalCount), Output.TableBase);
      for (ULONG Index = 0; Index < Output.Count; ++Index) {
        const SYSTEM_TABLE_ENTRY &Entry = Output.Entries[Index];
        AddRow(
            QString::number(Entry.Index), SystemTableEntryName(Tab, Entry),
            QString("0x%1")
                .arg(Entry.Address, sizeof(ULONG_PTR) * 2, 16, QLatin1Char('0'))
                .toUpper(),
            QString::number(Entry.ArgumentBytes), Entry.Address);
      }
      return;
    }
    if (Tab == 5 && Result->PiDDBQueried && Result->PiDDBAvailable) {
      AddRow("-", "PiDDBCacheTable",
             QString("0x%1")
                 .arg(Result->PiDDB.TableAddress, sizeof(ULONG_PTR) * 2, 16,
                      QLatin1Char('0'))
                 .toUpper(),
             QString("%1 of %2 entries")
                 .arg(Result->PiDDB.Count)
                 .arg(Result->PiDDB.TotalCount));
      if (Result->PiDDB.Count == 0) {
        AddRow("-", "(no entries)", "-", "PiDDB cache is present but returned 0 entries");
      }
      for (ULONG Index = 0; Index < Result->PiDDB.Count; ++Index) {
        const PIDDB_CACHE_ENTRY_INFO &Entry = Result->PiDDB.Entries[Index];
        const QString Name = Entry.DriverName[0]
                                 ? QString::fromWCharArray(Entry.DriverName)
                                 : "(unknown)";
        const QString Address =
            QString("0x%1")
                .arg(Entry.Address, sizeof(ULONG_PTR) * 2, 16, QLatin1Char('0'))
                .toUpper();
        const QString Metadata =
            QString("TimeDateStamp: %1 | LoadStatus: 0x%2")
                .arg(FormatPeTimeDateStamp(Entry.TimeDateStamp))
                .arg(static_cast<quint32>(Entry.LoadStatus), 8, 16,
                     QLatin1Char('0'))
                .toUpper();
        AddRow(QString::number(Entry.Index), Name, Address, Metadata);
      }
      return;
    }
    const auto Hex = [](ULONG_PTR Value) {
      return QString("0x%1")
          .arg(Value, sizeof(ULONG_PTR) * 2, 16, QLatin1Char('0'))
          .toUpper();
    };
    if (Tab == 0) {
      AddRow("-", "IDT Base", Hex(Summary.IdtBase));
      AddRow("-", "IDT Limit", QString::number(Summary.IdtLimit));
    } else if (Tab == 1) {
      AddRow("-", "KUSER_SHARED_DATA", Hex(Summary.KuserSharedData));
      AddRow("-", "System Time",
             QString("0x%1")
                 .arg(Summary.SystemTime, 16, 16, QLatin1Char('0'))
                 .toUpper());
      AddRow("-", "Interrupt Time",
             QString("0x%1")
                 .arg(Summary.InterruptTime, 16, 16, QLatin1Char('0'))
                 .toUpper());
      AddRow("-", "Tick Count", QString::number(Summary.TickCount));
    } else if (Tab == 2) {
      AddRow("-", "SSDT Base", Hex(Summary.SsdtBase));
      AddRow("-", "Service Count", QString::number(Summary.SsdtCount));
      AddRow("-", "Argument Table", Hex(Summary.SsdtArgTable));
    } else if (Tab == 3) {
      AddRow("-", "Shadow SSDT Base", Hex(Summary.ShadowSsdtBase));
      AddRow("-", "Service Count", QString::number(Summary.ShadowSsdtCount));
      AddRow("-", "Argument Table", Hex(Summary.ShadowSsdtArgTable));
    } else if (Tab == 4) {
      AddRow("-", "GDT Base", Hex(Summary.GdtBase));
      AddRow("-", "GDT Limit", QString::number(Summary.GdtLimit));
    } else if (Tab == 5)
      AddRow("-", "PiDDBCacheTable", Hex(Summary.PiDDBCacheTable));
    else {
      AddRow("-", "CR0", Hex(Summary.Cr0), "Protection and paging controls");
      AddRow("-", "CR2", Hex(Summary.Cr2), "Last page-fault linear address");
      AddRow("-", "CR3", Hex(Summary.Cr3), "Current page-table root");
      AddRow("-", "CR4", Hex(Summary.Cr4), "Extended processor controls");
      AddRow("-", "IA32_LSTAR", Hex(Summary.MsrLstar), "64-bit syscall entry");
      AddRow("-", "IA32_STAR", Hex(Summary.MsrStar), "Syscall segment selectors");
      AddRow("-", "IA32_FMASK", Hex(Summary.MsrFmask), "Syscall RFLAGS mask");
      AddRow("-", "IA32_EFER", Hex(Summary.MsrEfer), "Extended feature enable");
    }
  };
  const auto LoadTabAsync = std::make_shared<std::function<void(int, bool)>>();
  *LoadTabAsync = [Page, Kind, Status, Refresh, RefreshIndicator, State,
                   Populate](int Tab, bool ShowResult) {
    if (Tab < 0 || State->Refreshing.load())
      return;

    const std::shared_ptr<TableQueryResult> Result = State->Result;
    const bool AlreadyLoaded = Tab == 6 ||
        (Tab < 5 && Result->Available[Tab]) || (Tab == 5 && Result->PiDDBQueried);
    if (AlreadyLoaded) {
      Populate();
      return;
    }

    if (State->TabLoading.exchange(true))
      return;

    Refresh->setEnabled(false);
    RefreshIndicator->show();
    RefreshIndicator->start();
    Status->setText(QString("Loading %1...")
                        .arg(Kind->itemText(Tab)));

    QPointer<QWidget> SafePage(Page);
    std::thread([SafePage, Kind, Status, Refresh, RefreshIndicator, State,
                 Populate, Tab, ShowResult] {
      DWORD ErrorCode = ERROR_SUCCESS;
      bool Success = false;
      if (Tab >= 0 && Tab < 5) {
        Success = QuerySystemTableEntries(static_cast<ULONG>(Tab),
                                          &State->Result->Entries[Tab]) != FALSE;
        State->Result->Available[Tab] = Success;
        if (Success) {
          if (Tab == 2)
            ServiceNamesForTable(SYSTEM_TABLE_KIND_SSDT);
          else if (Tab == 3)
            ServiceNamesForTable(SYSTEM_TABLE_KIND_SHADOW_SSDT);
        }
      } else if (Tab == 5) {
        Success = QueryPiDDBCacheEntries(&State->Result->PiDDB) != FALSE;
        ErrorCode = G_LastMultiDrvError;
        State->Result->PiDDBQueried = true;
        State->Result->PiDDBAvailable =
            Success || ErrorCode == ERROR_NOT_FOUND;
      } else if (Tab == 6) {
        Success = true;
      }
      if (!(Tab == 5 && ErrorCode == ERROR_NOT_FOUND))
        ErrorCode = G_LastMultiDrvError;

      QMetaObject::invokeMethod(
          qApp,
          [SafePage, Kind, Status, Refresh, RefreshIndicator, State, Populate,
           Tab, ShowResult, Success, ErrorCode] {
            State->TabLoading = false;
            RefreshIndicator->stop();
            RefreshIndicator->hide();
            Refresh->setEnabled(true);
            if (!SafePage)
              return;

            if (!Success &&
                !(Tab == 5 && State->Result->PiDDBQueried &&
                  State->Result->PiDDBAvailable)) {
              const QString Message =
                  QString("Load failed (error %1)").arg(ErrorCode);
              Status->setText(Message);
              if (ShowResult)
                ShowErrorNotice(SafePage, "Table", Message);
              return;
            }

            if (Kind->currentIndex() == Tab)
              Populate();
            Status->setText(QString("Loaded %1").arg(Kind->itemText(Tab)));
            if (ShowResult)
              ShowSuccessNotice(SafePage, "Table", "Selected table loaded.");
          },
          Qt::QueuedConnection);
    }).detach();
  };
  const auto Query = [Page, Status, Refresh, RefreshIndicator, State,
                      Populate, Kind, LoadTabAsync](bool ShowResult) {
    if (State->Refreshing.exchange(true))
      return;
    Refresh->setEnabled(false);
    Refresh->setText("Refreshing...");
    RefreshIndicator->show();
    RefreshIndicator->start();
    Status->setText("Reading system tables...");
    QPointer<QWidget> SafePage(Page);
    const int SelectedTab = Kind->currentIndex();
    std::thread([SafePage, Status, Refresh, RefreshIndicator, State, Populate,
                 ShowResult, SelectedTab, LoadTabAsync] {
      auto Result = std::make_shared<TableQueryResult>();
      Result->Success = QuerySystemTables(&Result->Summary) != FALSE;
      Result->ErrorCode = G_LastMultiDrvError;
      const auto Modules = AegisNT::KernelResearch::QueryAll(IOCTL_ENUM_KERNEL_MODULES_V2);
      auto &Symbols = AegisNT::KernelResearch::SymbolService::Instance();
      Symbols.Initialize();
      Symbols.ReloadModules(Modules);
      QMetaObject::invokeMethod(
          qApp,
          [SafePage, Status, Refresh, RefreshIndicator, State, Populate,
           Result = std::move(Result), Modules, ShowResult, SelectedTab, LoadTabAsync] {
            State->Result = Result;
            State->Modules = Modules;
            State->Refreshing = false;
            RefreshIndicator->stop();
            RefreshIndicator->hide();
            Refresh->setText("Refresh");
            Refresh->setEnabled(true);
            if (!SafePage)
              return;
            if (!Result->Success) {
              const QString Message =
                  QString("Query failed (error %1)").arg(Result->ErrorCode);
              Status->setText(Message);
              if (ShowResult)
                ShowErrorNotice(SafePage, "Table", Message);
            } else {
              Status->setText("System table summary updated.");
              if (ShowResult)
                ShowSuccessNotice(SafePage, "Table",
                                  "System tables updated from MultiDrv.");
              if (SelectedTab >= 0)
                (*LoadTabAsync)(SelectedTab, false);
            }
            Populate();
          },
          Qt::QueuedConnection);
    }).detach();
  };
  QObject::connect(Kind, &ComboBox::currentIndexChanged, Page,
                   [Populate, LoadTabAsync](int Index) {
                     Populate();
                     (*LoadTabAsync)(Index, false);
                   });
  QObject::connect(Search, &QLineEdit::textChanged, Page,
                   [Populate] { Populate(); });
  QObject::connect(Refresh, &QPushButton::clicked, Page,
                   [Query] { Query(true); });
  Query(false);
  return Page;
}
