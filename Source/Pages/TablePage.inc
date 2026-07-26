QWidget *CreateTablePage()
{
    struct TableQueryResult
    {
        SYSTEM_TABLES_OUTPUT Summary{};
        std::array<SYSTEM_TABLE_ENTRIES_OUTPUT, 5> Entries{};
        std::array<bool, 5> Available{};
        PIDDB_CACHE_ENUM_OUTPUT PiDDB{};
        bool PiDDBAvailable = false;
        DWORD ErrorCode = ERROR_SUCCESS;
        bool Success = false;
    };
    struct TablePageState
    {
        std::shared_ptr<TableQueryResult> Result = std::make_shared<TableQueryResult>();
        std::atomic_bool Refreshing = false;
    };

    auto *Page = new QWidget;
    auto *Layout = new QVBoxLayout(Page);
    ConfigurePageLayout(Layout);
    auto *Toolbar = new QHBoxLayout;
    ConfigureToolbarLayout(Toolbar);
    auto *Kind = new ComboBox; Kind->addItems({"InterruptDescriptorTable", "I/O Timer", "SSDT", "ShadowSSDT", "GlobalDescriptorTable", "PiDDBCacheTable"}); Kind->setCurrentIndex(0); Kind->setMinimumWidth(300);
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
    Toolbar->addWidget(Status); Toolbar->addWidget(RefreshIndicator); Toolbar->addWidget(Refresh);
    Layout->addLayout(Toolbar);
    auto *Table = MakeTable({"Index", "Name", "Address", "Metadata"}); Table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch); Table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch); Layout->addWidget(Table, 1);
    const auto State = std::make_shared<TablePageState>();
    const auto Populate = [Kind, Search, Table, State] {
        Table->clearContents(); Table->setRowCount(0); const int Tab = Kind->currentIndex();
        const std::shared_ptr<TableQueryResult> Result = State->Result;
        const SYSTEM_TABLES_OUTPUT &Summary = Result->Summary;
        const QString SearchText = Search->text().trimmed();
        const auto AddRow = [Table, SearchText](const QString &Index, const QString &Name, const QString &Address, const QString &Metadata = QString()) { if (!SearchText.isEmpty() && !(Index + " " + Name + " " + Address + " " + Metadata).contains(SearchText, Qt::CaseInsensitive)) return; const int Row = Table->rowCount(); Table->insertRow(Row); Table->setItem(Row, 0, new QTableWidgetItem(Index)); Table->setItem(Row, 1, new QTableWidgetItem(Name)); Table->setItem(Row, 2, new QTableWidgetItem(Address)); Table->setItem(Row, 3, new QTableWidgetItem(Metadata)); Table->setRowHeight(Row, KCompactTableRowHeight); };
        if (Tab < 5 && Result->Available[Tab]) { const auto &Output = Result->Entries[Tab]; AddRow("-", "Table Base", QString("0x%1").arg(Output.TableBase, sizeof(ULONG_PTR) * 2, 16, QLatin1Char('0')).toUpper(), QString("%1 of %2 entries").arg(Output.Count).arg(Output.TotalCount));
            for (ULONG Index = 0; Index < Output.Count; ++Index) { const SYSTEM_TABLE_ENTRY &Entry = Output.Entries[Index];
                AddRow(QString::number(Entry.Index), SystemTableEntryName(Tab, Entry), QString("0x%1").arg(Entry.Address, sizeof(ULONG_PTR) * 2, 16, QLatin1Char('0')).toUpper(), QString::number(Entry.ArgumentBytes)); } return; }
        if (Tab == 5 && Result->PiDDBAvailable) {
            AddRow("-", "PiDDBCacheTable", QString("0x%1").arg(Result->PiDDB.TableAddress, sizeof(ULONG_PTR) * 2, 16, QLatin1Char('0')).toUpper(),
                   QString("%1 of %2 entries").arg(Result->PiDDB.Count).arg(Result->PiDDB.TotalCount));
            for (ULONG Index = 0; Index < Result->PiDDB.Count; ++Index) {
                const PIDDB_CACHE_ENTRY_INFO &Entry = Result->PiDDB.Entries[Index];
                const QString Name = Entry.DriverName[0] ? QString::fromWCharArray(Entry.DriverName) : "(unknown)";
                const QString Address = QString("0x%1").arg(Entry.Address, sizeof(ULONG_PTR) * 2, 16, QLatin1Char('0')).toUpper();
                const QString Metadata = QString("TimeDateStamp: %1 | LoadStatus: 0x%2")
                    .arg(FormatPeTimeDateStamp(Entry.TimeDateStamp))
                    .arg(static_cast<quint32>(Entry.LoadStatus), 8, 16, QLatin1Char('0')).toUpper();
                AddRow(QString::number(Entry.Index), Name, Address, Metadata);
            }
            return;
        }
        const auto Hex = [](ULONG_PTR Value) { return QString("0x%1").arg(Value, sizeof(ULONG_PTR) * 2, 16, QLatin1Char('0')).toUpper(); };
        if (Tab == 0) { AddRow("-", "IDT Base", Hex(Summary.IdtBase)); AddRow("-", "IDT Limit", QString::number(Summary.IdtLimit)); }
        else if (Tab == 1) { AddRow("-", "KUSER_SHARED_DATA", Hex(Summary.KuserSharedData)); AddRow("-", "System Time", QString("0x%1").arg(Summary.SystemTime, 16, 16, QLatin1Char('0')).toUpper()); AddRow("-", "Interrupt Time", QString("0x%1").arg(Summary.InterruptTime, 16, 16, QLatin1Char('0')).toUpper()); AddRow("-", "Tick Count", QString::number(Summary.TickCount)); }
        else if (Tab == 2) { AddRow("-", "SSDT Base", Hex(Summary.SsdtBase)); AddRow("-", "Service Count", QString::number(Summary.SsdtCount)); AddRow("-", "Argument Table", Hex(Summary.SsdtArgTable)); }
        else if (Tab == 3) { AddRow("-", "Shadow SSDT Base", Hex(Summary.ShadowSsdtBase)); AddRow("-", "Service Count", QString::number(Summary.ShadowSsdtCount)); AddRow("-", "Argument Table", Hex(Summary.ShadowSsdtArgTable)); }
        else if (Tab == 4) { AddRow("-", "GDT Base", Hex(Summary.GdtBase)); AddRow("-", "GDT Limit", QString::number(Summary.GdtLimit)); }
        else AddRow("-", "PiDDBCacheTable", Hex(Summary.PiDDBCacheTable));
    };
    const auto Query = [Page, Status, Refresh, RefreshIndicator, State, Populate](bool ShowResult) {
        if (State->Refreshing.exchange(true))
            return;
        Refresh->setEnabled(false);
        Refresh->setText("Refreshing...");
        RefreshIndicator->show();
        RefreshIndicator->start();
        Status->setText("Reading system tables...");
        QPointer<QWidget> SafePage(Page);
        std::thread([SafePage, Status, Refresh, RefreshIndicator, State, Populate, ShowResult] {
            auto Result = std::make_shared<TableQueryResult>();
            Result->Success = QuerySystemTables(&Result->Summary) != FALSE;
            Result->ErrorCode = G_LastMultiDrvError;
            if (Result->Success)
            {
                for (ULONG TableKind = 0; TableKind < Result->Entries.size(); ++TableKind)
                    Result->Available[TableKind] =
                        QuerySystemTableEntries(TableKind, &Result->Entries[TableKind]) != FALSE;
                Result->PiDDBAvailable = QueryPiDDBCacheEntries(&Result->PiDDB) != FALSE;
                ServiceNamesForTable(SYSTEM_TABLE_KIND_SSDT);
                ServiceNamesForTable(SYSTEM_TABLE_KIND_SHADOW_SSDT);
            }
            QMetaObject::invokeMethod(qApp, [SafePage, Status, Refresh, RefreshIndicator, State, Populate,
                                             Result = std::move(Result), ShowResult] {
                if (!SafePage)
                    return;
                State->Result = Result;
                State->Refreshing = false;
                RefreshIndicator->stop();
                RefreshIndicator->hide();
                Refresh->setText("Refresh");
                Refresh->setEnabled(true);
                if (!Result->Success)
                {
                    const QString Message = QString("Query failed (error %1)").arg(Result->ErrorCode);
                    Status->setText(Message);
                    if (ShowResult)
                        ShowErrorNotice(SafePage, "Table", Message);
                }
                else
                {
                    const int AvailableCount = static_cast<int>(std::count(
                        Result->Available.begin(), Result->Available.end(), true)) + (Result->PiDDBAvailable ? 1 : 0);
                    Status->setText(QString("Updated from MultiDrv (%1/6 tables)").arg(AvailableCount));
                    if (ShowResult)
                        ShowSuccessNotice(SafePage, "Table", "System tables updated from MultiDrv.");
                }
                Populate();
            }, Qt::QueuedConnection);
        }).detach();
    };
    QObject::connect(Kind, &ComboBox::currentIndexChanged, Page, [Populate](int) { Populate(); }); QObject::connect(Search, &QLineEdit::textChanged, Page, [Populate] { Populate(); }); QObject::connect(Refresh, &QPushButton::clicked, Page, [Query] { Query(true); }); Query(false);
    return Page;
}

