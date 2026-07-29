QWidget *CreateKernelInspectorPage()
{
    struct InspectorTab {
        DWORD Ioctl;
        QString Path;
        QTableWidget *Table = nullptr;
        BodyLabel *Count = nullptr;
    };
    struct KernelControlWidgets {
        BodyLabel *Summary = nullptr;
        BodyLabel *Detail = nullptr;
        QTableWidget *Table = nullptr;
        PushButton *EnableDebug = nullptr;
        PushButton *DisableDebug = nullptr;
        PushButton *DisableDse = nullptr;
        PushButton *RestoreDse = nullptr;
        PushButton *DisablePatchGuard = nullptr;
        PushButton *RestorePatchGuard = nullptr;
        PushButton *TriggerPatchGuard = nullptr;
    };
    struct KernelControlState {
        bool DebugOk = false;
        DWORD DebugError = ERROR_SUCCESS;
        DEBUG_STATE_OUTPUT Debug{};
        bool DseOk = false;
        DWORD DseError = ERROR_SUCCESS;
        DSE_CONTROL_OUTPUT Dse{};
        bool PatchGuardOk = false;
        DWORD PatchGuardError = ERROR_SUCCESS;
        PG_CONTROL_OUTPUT PatchGuard{};
    };
    auto *Page = new QWidget;
    auto *Layout = new QVBoxLayout(Page);
    ConfigurePageLayout(Layout);
    const auto ConfigureInspectorMeta = [](QHBoxLayout *MetaLayout) {
        MetaLayout->setContentsMargins(0, 0, 0, 0);
        MetaLayout->setSpacing(KCompactToolbarSpacing);
    };
    const auto ConfigureInspectorTabLayout = [](QVBoxLayout *TabLayout) {
        TabLayout->setContentsMargins(0, 0, 0, 0);
        TabLayout->setSpacing(8);
    };

    auto *Header = new QWidget;
    auto *HeaderLayout = new QHBoxLayout(Header);
    HeaderLayout->setContentsMargins(0, 0, 0, 0);
    HeaderLayout->setSpacing(10);
    auto *Search = new SearchLineEdit;
    ConfigureSearchLineEdit(Search, "Filter current results", 280);
    Search->setMinimumWidth(220);
    HeaderLayout->addStretch();
    HeaderLayout->addWidget(Search);
    auto *Status = new BodyLabel("Ready");
    Status->setMinimumWidth(120);
    auto *Loading = new IndeterminateProgressRing(Page, false);
    Loading->setFixedSize(22, 22);
    Loading->hide();
    auto *Refresh = new PushButton("Refresh", Fluent::IconType::SYNC);
    HeaderLayout->addWidget(Status);
    HeaderLayout->addWidget(Loading);
    HeaderLayout->addWidget(Refresh);
    Layout->addWidget(Header);

    auto *TabSelector = new ComboBox;
    TabSelector->setMinimumWidth(220);
    auto *Pages = new QStackedWidget;
    auto *Surface = new SimpleCardWidget;
    Surface->setBorderRadius(5);
    auto *SurfaceLayout = new QVBoxLayout(Surface);
    SurfaceLayout->setContentsMargins(14, 14, 14, 14);
    SurfaceLayout->setSpacing(10);
    auto *SelectorLayout = new QHBoxLayout;
    ConfigureToolbarLayout(SelectorLayout);
    SelectorLayout->addWidget(MakeLabel("Section", 11, KTextMuted, QFont::Medium));
    SelectorLayout->addWidget(TabSelector);
    SelectorLayout->addStretch();
    SurfaceLayout->addLayout(SelectorLayout);
    SurfaceLayout->addWidget(Pages, 1);
    Layout->addWidget(Surface, 1);
    auto State = std::make_shared<std::vector<InspectorTab>>();
    auto KernelControlsUi = std::make_shared<KernelControlWidgets>();
    auto KernelControlCache = std::make_shared<KernelControlState>();
    {
        auto *TabPage = new QWidget;
        auto *TabLayout = new QVBoxLayout(TabPage);
        ConfigureInspectorTabLayout(TabLayout);

        auto *ControlCard = new SimpleCardWidget;
        ControlCard->setBorderRadius(5);
        auto *ControlLayout = new QVBoxLayout(ControlCard);
        ControlLayout->setContentsMargins(12, 12, 12, 12);
        ControlLayout->setSpacing(8);

        auto *MetaLayout = new QHBoxLayout;
        ConfigureInspectorMeta(MetaLayout);
        MetaLayout->addWidget(MakeLabel("Control", 11, KTextMuted, QFont::Medium));
        KernelControlsUi->Summary = new BodyLabel("Kernel control overview");
        KernelControlsUi->Detail = new BodyLabel("Debug / DSE / PatchGuard");
        MetaLayout->addWidget(KernelControlsUi->Summary);
        MetaLayout->addStretch();
        MetaLayout->addWidget(KernelControlsUi->Detail);
        ControlLayout->addLayout(MetaLayout);

        KernelControlsUi->Table = MakeTable({"Field", "Value", "Detail"});
        KernelControlsUi->Table->setSortingEnabled(false);
        KernelControlsUi->Table->setTextElideMode(Qt::ElideRight);
        KernelControlsUi->Table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        KernelControlsUi->Table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
        KernelControlsUi->Table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
        ControlLayout->addWidget(KernelControlsUi->Table, 1);

        auto *ActionLayout = new QHBoxLayout;
        ConfigureToolbarLayout(ActionLayout);
        KernelControlsUi->EnableDebug = new PushButton("Enable Local Debug");
        KernelControlsUi->DisableDebug = new PushButton("Disable Local Debug");
        KernelControlsUi->DisableDse = new PushButton("DisableDse");
        KernelControlsUi->RestoreDse = new PushButton("RestoreDse");
        KernelControlsUi->DisablePatchGuard = new PushButton("DisablePatchGuard");
        KernelControlsUi->RestorePatchGuard = new PushButton("RestorePatchGuard");
        KernelControlsUi->TriggerPatchGuard = new PushButton("TriggerPatchGuard");
        ActionLayout->addWidget(KernelControlsUi->EnableDebug);
        ActionLayout->addWidget(KernelControlsUi->DisableDebug);
        ActionLayout->addWidget(KernelControlsUi->DisableDse);
        ActionLayout->addWidget(KernelControlsUi->RestoreDse);
        ActionLayout->addWidget(KernelControlsUi->DisablePatchGuard);
        ActionLayout->addWidget(KernelControlsUi->RestorePatchGuard);
        ActionLayout->addWidget(KernelControlsUi->TriggerPatchGuard);
        ActionLayout->addStretch();
        ControlLayout->addLayout(ActionLayout);
        TabLayout->addWidget(ControlCard, 1);

        TabSelector->addItem("Kernel Controls");
        Pages->addWidget(TabPage);
    }
    const std::array<std::tuple<DWORD, const char*, const wchar_t*, Fluent::IconType>, 4> Definitions{{
        {IOCTL_ENUM_MINIFILTERS_V2, "MiniFilters", L"", Fluent::IconType::DOCUMENT},
        {IOCTL_ENUM_WFP_V2, "WFP", L"", Fluent::IconType::GLOBE},
        {IOCTL_ENUM_NDIS_V2, "NDIS", L"", Fluent::IconType::CONNECT},
        {IOCTL_QUERY_SECURITY_V2, "Security", L"", Fluent::IconType::CERTIFICATE}
    }};
    int TabIndex = 0;
    for (const auto &[Ioctl, Name, Path, Icon] : Definitions) {
        auto *TabPage = new QWidget;
        auto *TabLayout = new QVBoxLayout(TabPage);
        ConfigureInspectorTabLayout(TabLayout);
        auto *MetaLayout = new QHBoxLayout;
        ConfigureInspectorMeta(MetaLayout);
        auto *SectionLabel = MakeLabel(QString::fromLatin1(Name), 11, KTextMuted, QFont::Medium);
        auto *Count = new BodyLabel("0 records");
        MetaLayout->addWidget(SectionLabel);
        MetaLayout->addStretch();
        MetaLayout->addWidget(Count);
        TabLayout->addLayout(MetaLayout);
        auto *Table = MakeTable({"Name", "Type", "Address", "Size/Value", "Path/Detail", "Source", "Confidence", "Status"});
        Table->setSortingEnabled(true);
        Table->setTextElideMode(Qt::ElideRight);
        Table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        Table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
        Table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
        Table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
        Table->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
        Table->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
        Table->horizontalHeader()->setSectionResizeMode(6, QHeaderView::ResizeToContents);
        Table->horizontalHeader()->setSectionResizeMode(7, QHeaderView::ResizeToContents);
        TabLayout->addWidget(Table, 1);
        (void)Icon;
        TabSelector->addItem(QString::fromLatin1(Name));
        Pages->addWidget(TabPage);
        State->push_back({Ioctl, QString::fromWCharArray(Path), Table, Count});
    }
    
    auto *SyncTab = new QWidget;
    auto *SyncLayout = new QVBoxLayout(SyncTab);
    ConfigureInspectorTabLayout(SyncLayout);
    auto *SyncMeta = new QHBoxLayout; ConfigureInspectorMeta(SyncMeta);
    SyncMeta->addWidget(MakeLabel("Synchronization objects", 11, KTextMuted, QFont::Medium));
    auto *SyncCount = new BodyLabel("0 objects");
    SyncMeta->addStretch(); SyncMeta->addWidget(SyncCount);
    SyncLayout->addLayout(SyncMeta);
    auto *SyncTable = MakeTable({"Name", "Type", "Dir", "Extra"});
    SyncTable->setSortingEnabled(true);
    SyncTable->setTextElideMode(Qt::ElideRight);
    SyncTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    SyncTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    SyncTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    SyncTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    SyncLayout->addWidget(SyncTable, 1);
    TabSelector->addItem("Sync Objects");
    Pages->addWidget(SyncTab);

    
    auto *SessTab = new QWidget;
    auto *SessLayout = new QVBoxLayout(SessTab);
    ConfigureInspectorTabLayout(SessLayout);
    auto *SessMeta = new QHBoxLayout; ConfigureInspectorMeta(SessMeta);
    SessMeta->addWidget(MakeLabel("Session inventory", 11, KTextMuted, QFont::Medium));
    auto *SessCount = new BodyLabel("0 sessions");
    SessMeta->addStretch(); SessMeta->addWidget(SessCount);
    SessLayout->addLayout(SessMeta);
    auto *SessTable = MakeTable({"Session", "State", "ProcessCount", "WinStation"});
    SessTable->setSortingEnabled(true);
    SessTable->setTextElideMode(Qt::ElideRight);
    SessTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    SessTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    SessTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    SessTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    SessTable->setContextMenuPolicy(Qt::CustomContextMenu);
    SessLayout->addWidget(SessTable, 1);
    TabSelector->addItem("Sessions");
    Pages->addWidget(SessTab);

    
    auto *FwTab = new QWidget;
    auto *FwLayout = new QVBoxLayout(FwTab);
    ConfigureInspectorTabLayout(FwLayout);
    auto *FwMeta = new QHBoxLayout; ConfigureInspectorMeta(FwMeta);
    FwMeta->addWidget(MakeLabel("Firewall rules", 11, KTextMuted, QFont::Medium));
    auto *FwCount = new BodyLabel("0 rules");
    auto *FwAddBtn = new PushButton("Add Rule");
    FwMeta->addStretch(); FwMeta->addWidget(FwCount); FwMeta->addWidget(FwAddBtn);
    FwLayout->addLayout(FwMeta);
    auto *FwTable = MakeTable({"Name", "Action", "Protocol", "Port", "State"});
    FwTable->setSortingEnabled(true);
    FwTable->setTextElideMode(Qt::ElideRight);
    FwTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    FwTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    FwTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    FwTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    FwTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    FwTable->setContextMenuPolicy(Qt::CustomContextMenu);
    FwLayout->addWidget(FwTable, 1);
    TabSelector->addItem("Firewall");
    Pages->addWidget(FwTab);

    QObject::connect(TabSelector, &ComboBox::currentIndexChanged, Pages, &QStackedWidget::setCurrentIndex);
    QObject::connect(Pages, &QStackedWidget::currentChanged, TabSelector, &ComboBox::setCurrentIndex);
    TabSelector->setCurrentIndex(0);
    Pages->setCurrentIndex(0);
    const auto ApplyKernelControlView = [KernelControlsUi, KernelControlCache]() {
        if (!KernelControlsUi->Table)
            return;
        const auto Hex = [](qulonglong Value) { return QString("0x%1").arg(Value, 0, 16).toUpper(); };
        const auto SetRow = [KernelControlsUi](int Row, const QString &Field, const QString &Value, const QString &Detail = QString()) {
            KernelControlsUi->Table->setItem(Row, 0, new QTableWidgetItem(Field));
            KernelControlsUi->Table->setItem(Row, 1, new QTableWidgetItem(Value));
            KernelControlsUi->Table->setItem(Row, 2, new QTableWidgetItem(Detail));
            KernelControlsUi->Table->setRowHeight(Row, 36);
        };
        KernelControlsUi->Table->setUpdatesEnabled(false);
        KernelControlsUi->Table->clearContents();
        KernelControlsUi->Table->setRowCount(0);
        KernelControlsUi->Summary->setText("Kernel control overview");

        if (KernelControlCache->DebugOk) {
            const int Row = KernelControlsUi->Table->rowCount();
            KernelControlsUi->Table->insertRow(Row);
            const bool Blocked = !KernelControlCache->Debug.IsPatched;
            SetRow(Row,
                "Debug",
                Blocked ? "Blocked (hook active)" : "Enabled (pass-through)",
                QString("Inlines KdSystemDebugControl entry.  Blocked: all NtSystemDebugControl "
                        "calls return ACCESS_DENIED.  Enabled: original entry bytes restored.  "
                        "Kernel debug variables are never modified.  "
                        "Do NOT click Restart in WinDbg while blocked - close & reopen instead."));
        } else {
            const int Row = KernelControlsUi->Table->rowCount();
            KernelControlsUi->Table->insertRow(Row);
            SetRow(Row, "Debug", "Unavailable", QString("Win32 error %1").arg(KernelControlCache->DebugError));
        }

        {
            const QString DseStateText = KernelControlCache->DseOk
                ? (KernelControlCache->Dse.CurrentValue == KernelControlCache->Dse.OriginalValue ? "Restored" : "Modified")
                : "Unavailable";
            const int Row0 = KernelControlsUi->Table->rowCount();
            KernelControlsUi->Table->insertRow(Row0);
            SetRow(Row0, "DSE.CiOptionsAddress", KernelControlCache->DseOk ? Hex(KernelControlCache->Dse.CiOptionsAddress) : "-");
            const int Row1 = KernelControlsUi->Table->rowCount();
            KernelControlsUi->Table->insertRow(Row1);
            SetRow(Row1, "DSE.OriginalValue", KernelControlCache->DseOk ? Hex(KernelControlCache->Dse.OriginalValue) : "-");
            const int Row2 = KernelControlsUi->Table->rowCount();
            KernelControlsUi->Table->insertRow(Row2);
            SetRow(Row2, "DSE.CurrentValue", KernelControlCache->DseOk ? Hex(KernelControlCache->Dse.CurrentValue) : "-");
            const int Row3 = KernelControlsUi->Table->rowCount();
            KernelControlsUi->Table->insertRow(Row3);
            SetRow(Row3, "DSE.Status", DseStateText, KernelControlCache->DseOk ? QString() : QString("Win32 error %1").arg(KernelControlCache->DseError));
        }

        {
            const QString PgStateText = KernelControlCache->PatchGuardOk
                ? (KernelControlCache->PatchGuard.IsPatched ? "Disabled" : "Active")
                : "Unavailable";
            const int Row0 = KernelControlsUi->Table->rowCount();
            KernelControlsUi->Table->insertRow(Row0);
            SetRow(Row0, "PatchGuard.PgContextOffset", KernelControlCache->PatchGuardOk ? Hex(KernelControlCache->PatchGuard.PgContextOffset) : "-");
            const int Row1 = KernelControlsUi->Table->rowCount();
            KernelControlsUi->Table->insertRow(Row1);
            SetRow(Row1, "PatchGuard.IsPatched", KernelControlCache->PatchGuardOk ? (KernelControlCache->PatchGuard.IsPatched ? "TRUE" : "FALSE") : "-");
            const int Row2 = KernelControlsUi->Table->rowCount();
            KernelControlsUi->Table->insertRow(Row2);
            SetRow(Row2, "PatchGuard.Status", PgStateText, KernelControlCache->PatchGuardOk ? QString() : QString("Win32 error %1").arg(KernelControlCache->PatchGuardError));
        }

        const QString DebugStateText =
            !KernelControlCache->DebugOk ? "Unavailable" :
            (!KernelControlCache->Debug.IsPatched ? "Blocked" : "Enabled");
        const QString DseStateText = !KernelControlCache->DseOk
            ? "Unavailable"
            : (KernelControlCache->Dse.CurrentValue == KernelControlCache->Dse.OriginalValue ? "Restored" : "Modified");
        const QString PgStateText = !KernelControlCache->PatchGuardOk
            ? "Unavailable"
            : (KernelControlCache->PatchGuard.IsPatched ? "Disabled" : "Active");
        KernelControlsUi->Detail->setText(QString("Debug %1 | DSE %2 | PatchGuard %3")
            .arg(DebugStateText)
            .arg(DseStateText)
            .arg(PgStateText));
        KernelControlsUi->Table->setUpdatesEnabled(true);
    };
    const auto ApplyFilter = [Search, State, KernelControlsUi, SyncTable, SessTable, FwTable] {
        const QString Query = Search->text().trimmed();
        const auto FilterTable = [&Query](QTableWidget *Table) {
            for (int Row = 0; Row < Table->rowCount(); ++Row) {
                QString RowText;
                for (int Column = 0; Column < Table->columnCount(); ++Column)
                    if (const QTableWidgetItem *Item = Table->item(Row, Column)) RowText += Item->text() + ' ';
                Table->setRowHidden(Row, !Query.isEmpty() && !RowText.contains(Query, Qt::CaseInsensitive));
            }
        };
        FilterTable(KernelControlsUi->Table);
        for (const InspectorTab &Tab : *State) FilterTable(Tab.Table);
        FilterTable(SyncTable);
        FilterTable(SessTable);
        FilterTable(FwTable);
    };
    QObject::connect(Search, &QLineEdit::textChanged, Page, [ApplyFilter] { ApplyFilter(); });
    ApplyKernelControlView();
    ApplyFilter();
    QObject::connect(Refresh, &QPushButton::clicked, Page, [Page, Refresh, Status, Loading, State, KernelControlsUi, KernelControlCache, ApplyKernelControlView, ApplyFilter,
        SyncTable, SyncCount, SessTable, SessCount, FwTable, FwCount] {
        Refresh->setEnabled(false);
        KernelControlsUi->EnableDebug->setEnabled(false);
        KernelControlsUi->DisableDebug->setEnabled(false);
        KernelControlsUi->DisableDse->setEnabled(false);
        KernelControlsUi->RestoreDse->setEnabled(false);
        KernelControlsUi->DisablePatchGuard->setEnabled(false);
        KernelControlsUi->RestorePatchGuard->setEnabled(false);
        KernelControlsUi->TriggerPatchGuard->setEnabled(false);
        Refresh->setText("Refreshing...");
        Status->setText("Reading kernel inventory...");
        Loading->show();
        Loading->start();
        QPointer<QWidget> SafePage(Page);
        std::thread([SafePage, Refresh, Status, Loading, State, KernelControlsUi, KernelControlCache, ApplyKernelControlView, ApplyFilter,
                     SyncTable, SyncCount, SessTable, SessCount, FwTable, FwCount] {
            struct Result { MDV2_LIST_HEADER Header{}; std::vector<MDV2_RECORD> Records; };
            KernelControlState KernelState;
            KernelState.DebugOk = QueryDebugState(&KernelState.Debug);
            KernelState.DebugError = G_LastMultiDrvError;
            KernelState.DseOk = QueryDse(&KernelState.Dse);
            KernelState.DseError = G_LastMultiDrvError;
            KernelState.PatchGuardOk = QueryPatchGuard(&KernelState.PatchGuard);
            KernelState.PatchGuardError = G_LastMultiDrvError;
            std::vector<Result> Results(State->size());
            for (size_t Index = 0; Index < State->size(); ++Index) {
                MDV2_QUERY_INPUT Request{}; Request.MaxEntries = MDV2_MAX_PAGE_RECORDS;
                if (!(*State)[Index].Path.isEmpty()) wcsncpy_s(Request.Path, (*State)[Index].Path.toStdWString().c_str(), _TRUNCATE);
                QueryMultiDrvRecordsV2((*State)[Index].Ioctl, Request, Results[Index].Records, &Results[Index].Header);
            }

            
            std::vector<std::tuple<QString, QString, ULONG>> SyncEntries;
            if (G_DeviceHandle != INVALID_HANDLE_VALUE)
            {
                BYTE SyncBuf[65536] = {};
                ULONG SyncReturned = 0;
                if (EnumSyncObjectsKernel(SyncBuf, sizeof(SyncBuf), &SyncReturned) && SyncReturned >= sizeof(ULONG))
                {
                    PULONG Cnt = (PULONG)SyncBuf;
                    PUCHAR D = (PUCHAR)(Cnt + 1);
                    for (ULONG i = 0; i < *Cnt; i++)
                    {
                        ULONG Dir = *(PULONG)D; D += 4;
                        USHORT NLen = *(PUSHORT)D; D += 2;
                        QString Name = NLen ? QString::fromWCharArray((PWCHAR)D, NLen / sizeof(WCHAR)) : QString();
                        D += NLen;
                        USHORT TLen = *(PUSHORT)D; D += 2;
                        QString Type = TLen ? QString::fromWCharArray((PWCHAR)D, TLen / sizeof(WCHAR)) : QString();
                        D += TLen;
                        D = (PUCHAR)(((ULONG_PTR)D + 3) & ~3ULL);
                        SyncEntries.emplace_back(Name, Type, Dir);
                    }
                }
            }

            
            std::vector<std::tuple<ULONG, ULONG, ULONG, QString>> SessEntries;
            if (G_DeviceHandle != INVALID_HANDLE_VALUE)
            {
                BYTE SessBuf[4096] = {};
                ULONG SessReturned = 0;
                if (EnumSessions(SessBuf, sizeof(SessBuf), &SessReturned) && SessReturned >= sizeof(ULONG))
                {
                    PULONG Cnt = (PULONG)SessBuf;
                    PUCHAR D = (PUCHAR)(Cnt + 1);
                    for (ULONG i = 0; i < *Cnt; i++)
                    {
                        ULONG Sid = *(PULONG)D; D += 4;
                        ULONG St = *(PULONG)D; D += 4;
                        ULONG Pc = *(PULONG)D; D += 4;
                        QString Ws = QString::fromWCharArray((PWCHAR)D);
                        D += 64;
                        SessEntries.emplace_back(Sid, St, Pc, Ws);
                    }
                }
            }
            if (SessEntries.empty())
                EnumerateSessionsFallback(SessEntries);

            
            std::vector<std::tuple<QString, ULONG, ULONG, ULONG, QString>> FwEntries;
            if (G_DeviceHandle != INVALID_HANDLE_VALUE)
            {
                BYTE FwBuf[16384] = {};
                (void)FwBuf;
            }
            if (FwEntries.empty())
                EnumerateFirewallRulesFallback(FwEntries);
            if (FwEntries.empty())
                FwEntries.emplace_back("Firewall enumeration unavailable", 0, 0, 0, "Not implemented");

            if (SyncEntries.empty())
                EnumerateSyncObjectsFallback(SyncEntries);

            QMetaObject::invokeMethod(qApp, [SafePage, Refresh, Status, Loading, State, KernelControlsUi, KernelControlCache, ApplyKernelControlView, ApplyFilter,
                                             KernelState, Results = std::move(Results),
                                             SyncTable, SyncCount, SyncEntries = std::move(SyncEntries),
                                             SessTable, SessCount, SessEntries = std::move(SessEntries),
                                             FwTable, FwCount, FwEntries = std::move(FwEntries)]() mutable {
                if (!SafePage) return;
                const auto Hex = [](qulonglong Value) { return QString("0x%1").arg(Value, 0, 16).toUpper(); };
                const auto RecordAddressText = [&Hex](const MDV2_RECORD &Record) {
                    if (Record.Address != 0)
                        return Hex(Record.Address);
                    for (const ULONG64 Value : Record.Value)
                    {
                        if (Value != 0)
                            return Hex(Value);
                    }
                    return QString("-");
                };
                const auto SourceName = [](ULONG Source) {
                    static const std::array<const char *, 10> Names{
                        "Unknown", "Public API", "System Info", "Object Manager", "Registry",
                        "Process Environment", "Memory Map", "Version Profile", "Signature Scan", "Cross-view"};
                    return Source < Names.size() ? QString::fromLatin1(Names[Source]) : QString("Source %1").arg(Source);
                };
                const auto ConfidenceName = [](ULONG Confidence) {
                    static const std::array<const char *, 4> Names{"Unavailable", "Low", "Medium", "High"};
                    return Confidence < Names.size() ? QString::fromLatin1(Names[Confidence]) : QString("Level %1").arg(Confidence);
                };
                size_t TotalRecords = 0;
                *KernelControlCache = KernelState;
                ApplyKernelControlView();
                for (size_t Index = 0; Index < State->size(); ++Index) {
                    QTableWidget *Table = (*State)[Index].Table; Table->setSortingEnabled(false); Table->clearContents(); Table->setRowCount(0);
                    for (const auto &Record : Results[Index].Records) {
                        const int Row = Table->rowCount(); Table->insertRow(Row);
                        const QString PathText = QString::fromWCharArray(Record.Path);
                        const QString DetailText = QString::fromWCharArray(Record.Detail);
                        const QString Detail = PathText.isEmpty() ? DetailText :
                            (DetailText.isEmpty() ? PathText : PathText + " | " + DetailText);
                        const QString StatusText = Record.Status == 0 ? "Success" : Hex(static_cast<quint32>(Record.Status));
                        const QString AddressText = RecordAddressText(Record);
                        QString SizeOrValueText;
                        if (Record.SizeBytes != 0)
                            SizeOrValueText = QLocale().toString(static_cast<qulonglong>(Record.SizeBytes)) + " B";
                        else if (Record.Value[0] != 0)
                            SizeOrValueText = Hex(Record.Value[0]);
                        else if (Record.Value[1] != 0)
                            SizeOrValueText = Hex(Record.Value[1]);
                        else
                            SizeOrValueText = "-";
                        const QStringList Values{QString::fromWCharArray(Record.Name), QString::fromWCharArray(Record.TypeName),
                            AddressText,
                            SizeOrValueText, Detail,
                            SourceName(Record.Source), ConfidenceName(Record.Confidence), StatusText};
                        for (int Column = 0; Column < Values.size(); ++Column) Table->setItem(Row, Column, new QTableWidgetItem(Values[Column]));
                        Table->setRowHeight(Row, 36);
                    }
                    TotalRecords += Results[Index].Records.size();
                    (*State)[Index].Count->setText(QString("%1 record%2")
                        .arg(Results[Index].Records.size()).arg(Results[Index].Records.size() == 1 ? "" : "s"));
                    if (Results[Index].Records.empty()) {
                        Table->insertRow(0);
                        Table->setItem(0, 0, new QTableWidgetItem("No records"));
                        Table->setItem(0, 7, new QTableWidgetItem(Results[Index].Header.Status == 0
                            ? "Success" : Hex(static_cast<quint32>(Results[Index].Header.Status))));
                    }
                    Table->setSortingEnabled(true);
                }
                
                SyncTable->setSortingEnabled(false);
                SyncTable->clearContents(); SyncTable->setRowCount(0);
                for (const auto &[Name, Type, Dir] : SyncEntries) {
                    int R = SyncTable->rowCount(); SyncTable->insertRow(R);
                    SyncTable->setItem(R, 0, new QTableWidgetItem(Name));
                    SyncTable->setItem(R, 1, new QTableWidgetItem(Type));
                    SyncTable->setItem(R, 2, new QTableWidgetItem(Dir == 0 ? "Global" : "Session"));
                    SyncTable->setRowHeight(R, 36);
                }
                SyncCount->setText(QString("%1 objects").arg(SyncEntries.size()));
                SyncTable->setSortingEnabled(true);

                
                SessTable->setSortingEnabled(false);
                SessTable->clearContents(); SessTable->setRowCount(0);
                for (const auto &[Sid, St, Pc, Ws] : SessEntries) {
                    int R = SessTable->rowCount(); SessTable->insertRow(R);
                    SessTable->setItem(R, 0, new QTableWidgetItem(QString::number(Sid)));
                    SessTable->setItem(R, 1, new QTableWidgetItem(SessionStateText(St)));
                    SessTable->setItem(R, 2, new QTableWidgetItem(QString::number(Pc)));
                    SessTable->setItem(R, 3, new QTableWidgetItem(Ws));
                    SessTable->setRowHeight(R, 36);
                }
                SessCount->setText(QString("%1 sessions").arg(SessEntries.size()));
                SessTable->setSortingEnabled(true);

                
                FwTable->setSortingEnabled(false);
                FwTable->clearContents(); FwTable->setRowCount(0);
                for (const auto &[Name, Action, Proto, Port, StateText] : FwEntries) {
                    int R = FwTable->rowCount(); FwTable->insertRow(R);
                    FwTable->setItem(R, 0, new QTableWidgetItem(Name));
                    FwTable->setItem(R, 1, new QTableWidgetItem(Action == 0 ? "Block" : "Allow"));
                    FwTable->setItem(R, 2, new QTableWidgetItem(Proto == 6 ? "TCP" : Proto == 17 ? "UDP" : QString::number(Proto)));
                    FwTable->setItem(R, 3, new QTableWidgetItem(QString::number(Port)));
                    FwTable->setItem(R, 4, new QTableWidgetItem(StateText));
                    FwTable->setRowHeight(R, 36);
                }
                FwCount->setText(QString("%1 rules").arg(FwEntries.size()));
                FwTable->setSortingEnabled(true);

                ApplyFilter();
                Loading->stop();
                Loading->hide();
                Refresh->setEnabled(true);
                KernelControlsUi->EnableDebug->setEnabled(true);
                KernelControlsUi->DisableDebug->setEnabled(true);
                KernelControlsUi->DisableDse->setEnabled(true);
                KernelControlsUi->RestoreDse->setEnabled(true);
                KernelControlsUi->DisablePatchGuard->setEnabled(true);
                KernelControlsUi->RestorePatchGuard->setEnabled(true);
                KernelControlsUi->TriggerPatchGuard->setEnabled(true);
                Refresh->setText("Refresh");
                Status->setText(QString("%1 records").arg(TotalRecords));
            }, Qt::QueuedConnection);
        }).detach();
    });
    const auto SetKernelControlButtonsEnabled = [KernelControlsUi](bool Enabled) {
        KernelControlsUi->EnableDebug->setEnabled(Enabled);
        KernelControlsUi->DisableDebug->setEnabled(Enabled);
        KernelControlsUi->DisableDse->setEnabled(Enabled);
        KernelControlsUi->RestoreDse->setEnabled(Enabled);
        KernelControlsUi->DisablePatchGuard->setEnabled(Enabled);
        KernelControlsUi->RestorePatchGuard->setEnabled(Enabled);
        KernelControlsUi->TriggerPatchGuard->setEnabled(Enabled);
    };
    const auto RunKernelControlAction = [Page, Refresh, Status, Loading, SetKernelControlButtonsEnabled](const QString &BusyText, const QString &ActionName, std::function<bool()> Action) {
        SetKernelControlButtonsEnabled(false);
        Refresh->setEnabled(false);
        Status->setText(BusyText);
        Loading->show();
        Loading->start();
        QPointer<QWidget> SafePage(Page);
        std::thread([SafePage, Refresh, Status, Loading, SetKernelControlButtonsEnabled, ActionName, Action = std::move(Action)]() mutable {
            const bool Success = Action();
            const DWORD ErrorCode = G_LastMultiDrvError;
            QMetaObject::invokeMethod(qApp, [SafePage, Refresh, Status, Loading, SetKernelControlButtonsEnabled, Success, ErrorCode, ActionName] {
                if (!SafePage) return;
                Loading->stop();
                Loading->hide();
                Refresh->setEnabled(true);
                SetKernelControlButtonsEnabled(true);
                if (!Success) {
                    Status->setText(QString("%1 failed").arg(ActionName));
                    ShowErrorNotice(SafePage, "Kernel Inspector",
                        QString("%1 failed (error %2).").arg(ActionName).arg(ErrorCode));
                } else {
                    ShowSuccessNotice(SafePage, "Kernel Inspector", QString("%1 completed.").arg(ActionName));
                    QTimer::singleShot(0, Refresh, &QPushButton::click);
                }
            }, Qt::QueuedConnection);
        }).detach();
    };
    const auto RunPatchGuardTrigger = [Page, Refresh, Status, Loading, SetKernelControlButtonsEnabled]() {
        SetKernelControlButtonsEnabled(false);
        Refresh->setEnabled(false);
        Status->setText("Triggering PatchGuard...");
        Loading->show();
        Loading->start();
        QPointer<QWidget> SafePage(Page);
        std::thread([SafePage, Refresh, Status, Loading, SetKernelControlButtonsEnabled] {
            IDT_LIMIT_OUTPUT IdtOut{};
            const bool Success = SetIdtLimit();
            const DWORD ErrorCode = G_LastMultiDrvError;
            QMetaObject::invokeMethod(qApp, [SafePage, Refresh, Status, Loading, SetKernelControlButtonsEnabled, Success, ErrorCode] {
                if (!SafePage) return;
                Loading->stop();
                Loading->hide();
                Refresh->setEnabled(true);
                SetKernelControlButtonsEnabled(true);
                if (!Success) {
                    Status->setText("TriggerPatchGuard failed");
                    ShowErrorNotice(SafePage, "Kernel Inspector",
                        QString("TriggerPatchGuard failed (error %1).").arg(ErrorCode));
                    return;
                }
                ShowSuccessNotice(SafePage, "Kernel Inspector", "TriggerPatchGuard completed.");
                QTimer::singleShot(0, Refresh, &QPushButton::click);
            }, Qt::QueuedConnection);
        }).detach();
    };
    QObject::connect(KernelControlsUi->EnableDebug, &QPushButton::clicked, Page, [RunKernelControlAction] {
        RunKernelControlAction("Enabling kernel debug...", "EnableDebug", [] { return EnableDebug(); });
    });
    QObject::connect(KernelControlsUi->DisableDebug, &QPushButton::clicked, Page, [RunKernelControlAction] {
        RunKernelControlAction("Disabling kernel debug...", "DisableDebug", [] { return DisableDebug(); });
    });
    QObject::connect(KernelControlsUi->DisableDse, &QPushButton::clicked, Page, [RunKernelControlAction] {
        RunKernelControlAction("Disabling DSE...", "DisableDse", [] { return DisableDse(); });
    });
    QObject::connect(KernelControlsUi->RestoreDse, &QPushButton::clicked, Page, [RunKernelControlAction] {
        RunKernelControlAction("Restoring DSE...", "RestoreDse", [] { return RestoreDse(); });
    });
    QObject::connect(KernelControlsUi->DisablePatchGuard, &QPushButton::clicked, Page, [RunKernelControlAction] {
        RunKernelControlAction("Disabling PatchGuard...", "DisablePatchGuard", [] { return DisablePatchGuard(); });
    });
    QObject::connect(KernelControlsUi->RestorePatchGuard, &QPushButton::clicked, Page, [RunKernelControlAction] {
        RunKernelControlAction("Restoring PatchGuard...", "RestorePatchGuard", [] { return RestorePatchGuard(); });
    });
    QObject::connect(KernelControlsUi->TriggerPatchGuard, &QPushButton::clicked, Page, [RunPatchGuardTrigger] { RunPatchGuardTrigger(); });
    QObject::connect(FwAddBtn, &QPushButton::clicked, Page, [Page, Refresh] {
        auto *Dialog = new MessageBoxBase(Page->window());
        Dialog->setAttribute(Qt::WA_DeleteOnClose);
        auto *NameEdit = new LineEdit;
        NameEdit->setPlaceholderText("Rule name");
        auto *ActionCombo = new ComboBox;
        ActionCombo->addItems({"Block", "Allow"});
        auto *ProtocolCombo = new ComboBox;
        ProtocolCombo->addItems({"TCP", "UDP"});
        auto *PortEdit = new LineEdit;
        PortEdit->setPlaceholderText("Local port");
        Dialog->viewLayout()->addWidget(MakeLabel("Add firewall rule", 18, KTextPrimary, QFont::DemiBold));
        Dialog->viewLayout()->addWidget(NameEdit);
        Dialog->viewLayout()->addWidget(ActionCombo);
        Dialog->viewLayout()->addWidget(ProtocolCombo);
        Dialog->viewLayout()->addWidget(PortEdit);
        Dialog->yesButton()->setText("Add");
        QObject::connect(Dialog->yesButton(), &QPushButton::clicked, Dialog, [Page, Dialog, NameEdit, ActionCombo, ProtocolCombo, PortEdit, Refresh] {
            const QString Name = NameEdit->text().trimmed();
            bool Ok = false;
            const ULONG Port = PortEdit->text().trimmed().toULong(&Ok);
            if (Name.isEmpty() || !Ok || Port == 0 || Port > 65535)
            {
                ShowWarningNotice(Page, "Kernel Inspector", "Enter a valid rule name and port.");
                return;
            }
            const bool Success = AddFirewallRuleFallback(Name, ActionCombo->currentIndex() == 0 ? 0u : 1u,
                ProtocolCombo->currentIndex() == 0 ? 6u : 17u, Port);
            if (!Success)
            {
                ShowErrorNotice(Page, "Kernel Inspector", "Unable to add firewall rule.");
                return;
            }
            Dialog->accept();
            ShowSuccessNotice(Page, "Kernel Inspector", "Firewall rule added.");
            QTimer::singleShot(0, Refresh, &QPushButton::click);
        });
        QObject::connect(Dialog->cancelButton(), &QPushButton::clicked, Dialog, &QDialog::reject);
        Dialog->show();
    });
    QObject::connect(FwTable, &QWidget::customContextMenuRequested, Page, [Page, FwTable, Refresh](const QPoint &Position) {
        const QModelIndex Index = FwTable->indexAt(Position);
        if (!Index.isValid())
            return;
        FwTable->selectRow(Index.row());
        QTableWidgetItem *NameItem = FwTable->item(Index.row(), 0);
        QTableWidgetItem *StateItem = FwTable->item(Index.row(), 4);
        if (!NameItem || !StateItem)
            return;
        const QString RuleName = NameItem->text().trimmed();
        const bool Enabled = StateItem->text().contains("Enabled", Qt::CaseInsensitive);
        auto *Menu = new RoundMenu(QString(), Page);
        auto *ToggleAction = new QAction(Enabled ? "Disable rule" : "Enable rule", Menu);
        auto *DeleteAction = new QAction("Delete rule", Menu);
        auto *RefreshAction = new QAction("Refresh", Menu);
        Menu->addAction(ToggleAction);
        Menu->addAction(DeleteAction);
        Menu->addAction(RefreshAction);
        ConnectMenuAction(ToggleAction, Page, [Page, RuleName, Enabled, Refresh] {
            if (!SetFirewallRuleEnabledFallback(RuleName, !Enabled))
            {
                ShowErrorNotice(Page, "Kernel Inspector", QString("Unable to %1 firewall rule.").arg(Enabled ? "disable" : "enable"));
                return;
            }
            ShowSuccessNotice(Page, "Kernel Inspector", QString("Firewall rule %1.").arg(Enabled ? "disabled" : "enabled"));
            QTimer::singleShot(0, Refresh, &QPushButton::click);
        });
        ConnectMenuAction(DeleteAction, Page, [Page, RuleName, Refresh] {
            if (!RemoveFirewallRuleFallback(RuleName))
            {
                ShowErrorNotice(Page, "Kernel Inspector", "Unable to delete firewall rule.");
                return;
            }
            ShowSuccessNotice(Page, "Kernel Inspector", "Firewall rule deleted.");
            QTimer::singleShot(0, Refresh, &QPushButton::click);
        });
        ConnectMenuAction(RefreshAction, Page, [Refresh] { QTimer::singleShot(0, Refresh, &QPushButton::click); });
        ReleaseMenuAfterClose(Menu);
        Menu->exec(FwTable->viewport()->mapToGlobal(Position));
    });
    QTimer::singleShot(0, Refresh, &QPushButton::click);

    return Page;
}

