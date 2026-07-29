QWidget *CreateKernelInspectorPage() {
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
  const QColor Accent = ConfiguredColor("AccentColor", KAccent);
  const auto ConfigureInspectorMeta = [](QHBoxLayout *MetaLayout) {
    MetaLayout->setContentsMargins(0, 0, 0, 0);
    MetaLayout->setSpacing(KCompactToolbarSpacing);
  };
  const auto ConfigureInspectorTabLayout = [](QVBoxLayout *TabLayout) {
    TabLayout->setContentsMargins(0, 0, 0, 0);
    TabLayout->setSpacing(10);
  };
  const auto CreateSectionHeader = [ConfigureInspectorMeta](
                                       const QString &Title,
                                       const QString &Subtitle,
                                       BodyLabel **CountLabel = nullptr,
                                       QWidget *RightWidget = nullptr) {
    auto *Header = new QWidget;
    auto *HeaderLayout = new QHBoxLayout(Header);
    ConfigureInspectorMeta(HeaderLayout);
    auto *TitleLayout = new QVBoxLayout;
    TitleLayout->setContentsMargins(0, 0, 0, 0);
    TitleLayout->setSpacing(2);
    TitleLayout->addWidget(MakeLabel(Title, 13, KTextPrimary, QFont::DemiBold));
    TitleLayout->addWidget(MakeLabel(Subtitle, 11, KTextMuted));
    HeaderLayout->addLayout(TitleLayout, 1);
    if (CountLabel != nullptr) {
      *CountLabel = new BodyLabel("0 items");
      (*CountLabel)->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
      (*CountLabel)->setMinimumWidth(110);
      HeaderLayout->addWidget(*CountLabel);
    }
    if (RightWidget != nullptr)
      HeaderLayout->addWidget(RightWidget);
    return Header;
  };
  const auto CreateActionGroup =
      [Accent](const QString &Title, const QString &Subtitle,
               std::initializer_list<PushButton *> Buttons) {
        auto *Card = new SimpleCardWidget;
        Card->setBorderRadius(5);
        auto *CardLayout = new QVBoxLayout(Card);
        CardLayout->setContentsMargins(12, 12, 12, 12);
        CardLayout->setSpacing(8);

        auto *Header = new QWidget;
        Header->setStyleSheet(
            QString("background: rgba(%1,%2,%3,18); border-radius: 6px;")
                .arg(Accent.red())
                .arg(Accent.green())
                .arg(Accent.blue()));
        auto *HeaderLayout = new QVBoxLayout(Header);
        HeaderLayout->setContentsMargins(10, 8, 10, 8);
        HeaderLayout->setSpacing(2);
        HeaderLayout->addWidget(
            MakeLabel(Title, 11, KTextPrimary, QFont::DemiBold));
        HeaderLayout->addWidget(MakeLabel(Subtitle, 10, KTextMuted));
        CardLayout->addWidget(Header);

        auto *ButtonsLayout = new QVBoxLayout;
        ButtonsLayout->setContentsMargins(0, 0, 0, 0);
        ButtonsLayout->setSpacing(6);
        for (PushButton *Button : Buttons) {
          ConfigureActionButton(Button, 170, KStandardButtonHeight);
          ButtonsLayout->addWidget(Button);
        }
        ButtonsLayout->addStretch();
        CardLayout->addLayout(ButtonsLayout, 1);
        return Card;
      };

  auto *HeaderCard = new SimpleCardWidget;
  HeaderCard->setBorderRadius(5);
  auto *HeaderCardLayout = new QVBoxLayout(HeaderCard);
  HeaderCardLayout->setContentsMargins(14, 12, 14, 12);
  HeaderCardLayout->setSpacing(8);

  auto *Search = new SearchLineEdit;
  ConfigureSearchLineEdit(Search, "Filter current results", 280);
  Search->setMinimumWidth(260);
  auto *Status = new BodyLabel("Ready");
  Status->setMinimumWidth(180);

  auto *Toolbar = new QWidget;
  auto *ToolbarLayout = new QHBoxLayout(Toolbar);
  ConfigureToolbarLayout(ToolbarLayout);
  ToolbarLayout->addWidget(Search, 0, Qt::AlignLeft | Qt::AlignVCenter);
  ToolbarLayout->addStretch(1);
  auto *Loading = new IndeterminateProgressRing(Page, false);
  Loading->setFixedSize(22, 22);
  Loading->hide();
  auto *LoadStatus =
      new BodyLabel("Filter current results or refresh kernel state.");
  LoadStatus->setMinimumWidth(240);
  LoadStatus->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
  auto *Refresh = new PushButton("Refresh", Fluent::IconType::SYNC);
  ConfigureActionButton(Refresh, 110, KStandardButtonHeight);
  ToolbarLayout->addWidget(Status, 0, Qt::AlignVCenter);
  ToolbarLayout->addWidget(Loading, 0, Qt::AlignVCenter);
  ToolbarLayout->addWidget(LoadStatus, 0, Qt::AlignVCenter);
  ToolbarLayout->addWidget(Refresh, 0, Qt::AlignRight | Qt::AlignVCenter);
  HeaderCardLayout->addWidget(Toolbar);
  Layout->addWidget(HeaderCard);

  auto *TabSelector = new ComboBox;
  TabSelector->setMinimumWidth(220);
  auto *Pages = new QStackedWidget;
  auto *Surface = new SimpleCardWidget;
  Surface->setBorderRadius(5);
  auto *SurfaceLayout = new QVBoxLayout(Surface);
  SurfaceLayout->setContentsMargins(14, 12, 14, 14);
  SurfaceLayout->setSpacing(10);
  auto *SelectorLayout = new QHBoxLayout;
  ConfigureToolbarLayout(SelectorLayout);
  SelectorLayout->addWidget(
      MakeLabel("Section", 11, KTextPrimary, QFont::DemiBold));
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
    ControlLayout->setContentsMargins(14, 14, 14, 14);
    ControlLayout->setSpacing(12);

    auto *ControlHeader = CreateSectionHeader(
        "Kernel Controls",
        "Review Debug, DSE, and PatchGuard state before taking action.");
    KernelControlsUi->Summary = new BodyLabel("Kernel control overview");
    KernelControlsUi->Summary->setMinimumWidth(180);
    KernelControlsUi->Detail = new BodyLabel("Debug / DSE / PatchGuard");
    auto *ControlHeaderLayout =
        static_cast<QHBoxLayout *>(ControlHeader->layout());
    ControlHeaderLayout->addWidget(KernelControlsUi->Summary);
    ControlHeaderLayout->addWidget(KernelControlsUi->Detail);
    ControlLayout->addWidget(ControlHeader);

    KernelControlsUi->Table = MakeTable({"Field", "Value", "Detail"});
    KernelControlsUi->Table->setSortingEnabled(false);
    KernelControlsUi->Table->setTextElideMode(Qt::ElideRight);
    KernelControlsUi->Table->verticalHeader()->setDefaultSectionSize(
        KCompactTableRowHeight);
    KernelControlsUi->Table->horizontalHeader()->setSectionResizeMode(
        0, QHeaderView::ResizeToContents);
    KernelControlsUi->Table->horizontalHeader()->setSectionResizeMode(
        1, QHeaderView::ResizeToContents);
    KernelControlsUi->Table->horizontalHeader()->setSectionResizeMode(
        2, QHeaderView::Stretch);
    ControlLayout->addWidget(KernelControlsUi->Table, 1);

    KernelControlsUi->EnableDebug = new PushButton("Enable Local Debug");
    KernelControlsUi->DisableDebug = new PushButton("Disable Local Debug");
    KernelControlsUi->DisableDse = new PushButton("DisableDse");
    KernelControlsUi->RestoreDse = new PushButton("RestoreDse");
    KernelControlsUi->DisablePatchGuard = new PushButton("DisablePatchGuard");
    KernelControlsUi->RestorePatchGuard = new PushButton("RestorePatchGuard");
    KernelControlsUi->TriggerPatchGuard = new PushButton("TriggerPatchGuard");

    auto *ActionRow = new QHBoxLayout;
    ActionRow->setContentsMargins(0, 0, 0, 0);
    ActionRow->setSpacing(10);
    ActionRow->addWidget(
        CreateActionGroup(
            "Debug", "Safe toggle for local kernel debug interception.",
            {KernelControlsUi->EnableDebug, KernelControlsUi->DisableDebug}),
        1);
    ActionRow->addWidget(
        CreateActionGroup(
            "DSE", "Modify or restore code integrity policy values.",
            {KernelControlsUi->DisableDse, KernelControlsUi->RestoreDse}),
        1);
    ActionRow->addWidget(
        CreateActionGroup("PatchGuard",
                          "High-risk controls. Use only when necessary.",
                          {KernelControlsUi->DisablePatchGuard,
                           KernelControlsUi->RestorePatchGuard,
                           KernelControlsUi->TriggerPatchGuard}),
        1);
    ControlLayout->addLayout(ActionRow);
    TabLayout->addWidget(ControlCard, 1);

    TabSelector->addItem("Kernel Controls");
    Pages->addWidget(TabPage);
  }
  const std::array<
      std::tuple<DWORD, const char *, const wchar_t *, Fluent::IconType>, 4>
      Definitions{{{IOCTL_ENUM_MINIFILTERS_V2, "MiniFilters", L"",
                    Fluent::IconType::DOCUMENT},
                   {IOCTL_ENUM_WFP_V2, "WFP", L"", Fluent::IconType::GLOBE},
                   {IOCTL_ENUM_NDIS_V2, "NDIS", L"", Fluent::IconType::CONNECT},
                   {IOCTL_QUERY_SECURITY_V2, "Security", L"",
                    Fluent::IconType::CERTIFICATE}}};
  for (const auto &[Ioctl, Name, Path, Icon] : Definitions) {
    auto *TabPage = new QWidget;
    auto *TabLayout = new QVBoxLayout(TabPage);
    ConfigureInspectorTabLayout(TabLayout);
    BodyLabel *Count = nullptr;
    TabLayout->addWidget(CreateSectionHeader(
        QString::fromLatin1(Name),
        "Enumerated kernel records for the current category.", &Count));
    auto *Table = MakeTable({"Name", "Type", "Address", "Size/Value",
                             "Path/Detail", "Source", "Confidence", "Status"});
    Table->setSortingEnabled(true);
    Table->setTextElideMode(Qt::ElideRight);
    Table->verticalHeader()->setDefaultSectionSize(KCompactTableRowHeight);
    Table->horizontalHeader()->setSectionResizeMode(
        0, QHeaderView::ResizeToContents);
    Table->horizontalHeader()->setSectionResizeMode(
        1, QHeaderView::ResizeToContents);
    Table->horizontalHeader()->setSectionResizeMode(
        2, QHeaderView::ResizeToContents);
    Table->horizontalHeader()->setSectionResizeMode(
        3, QHeaderView::ResizeToContents);
    Table->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    Table->horizontalHeader()->setSectionResizeMode(
        5, QHeaderView::ResizeToContents);
    Table->horizontalHeader()->setSectionResizeMode(
        6, QHeaderView::ResizeToContents);
    Table->horizontalHeader()->setSectionResizeMode(
        7, QHeaderView::ResizeToContents);
    TabLayout->addWidget(Table, 1);
    (void)Icon;
    TabSelector->addItem(QString::fromLatin1(Name));
    Pages->addWidget(TabPage);
    State->push_back({Ioctl, QString::fromWCharArray(Path), Table, Count});
  }

  auto *SyncTab = new QWidget;
  auto *SyncLayout = new QVBoxLayout(SyncTab);
  ConfigureInspectorTabLayout(SyncLayout);
  BodyLabel *SyncCount = nullptr;
  SyncLayout->addWidget(CreateSectionHeader(
      "Synchronization Objects",
      "Cross-session and global synchronization objects.", &SyncCount));
  auto *SyncTable = MakeTable({"Name", "Type", "Dir", "Extra"});
  SyncTable->setSortingEnabled(true);
  SyncTable->setTextElideMode(Qt::ElideRight);
  SyncTable->verticalHeader()->setDefaultSectionSize(KCompactTableRowHeight);
  SyncTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
  SyncTable->horizontalHeader()->setSectionResizeMode(
      1, QHeaderView::ResizeToContents);
  SyncTable->horizontalHeader()->setSectionResizeMode(
      2, QHeaderView::ResizeToContents);
  SyncTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
  SyncLayout->addWidget(SyncTable, 1);
  TabSelector->addItem("Sync Objects");
  Pages->addWidget(SyncTab);

  auto *SessTab = new QWidget;
  auto *SessLayout = new QVBoxLayout(SessTab);
  ConfigureInspectorTabLayout(SessLayout);
  auto *SessLogoffBtn = new PushButton("Logoff");
  auto *SessDisconnectBtn = new PushButton("Disconnect");
  auto *SessMessageBtn = new PushButton("Send Message");
  auto *SessRunBtn = new PushButton("Run In Session");
  auto *SessRefreshBtn = new PushButton("Refresh");
  ConfigureActionButton(SessLogoffBtn, 96, KStandardButtonHeight);
  ConfigureActionButton(SessDisconnectBtn, 108, KStandardButtonHeight);
  ConfigureActionButton(SessMessageBtn, 126, KStandardButtonHeight);
  ConfigureActionButton(SessRunBtn, 126, KStandardButtonHeight);
  ConfigureActionButton(SessRefreshBtn, 96, KStandardButtonHeight);
  SessLogoffBtn->setEnabled(false);
  SessDisconnectBtn->setEnabled(false);
  SessMessageBtn->setEnabled(false);
  SessRunBtn->setEnabled(false);
  auto *SessActions = new QWidget;
  auto *SessActionsLayout = new QHBoxLayout(SessActions);
  ConfigureToolbarLayout(SessActionsLayout);
  SessActionsLayout->addWidget(SessLogoffBtn);
  SessActionsLayout->addWidget(SessDisconnectBtn);
  SessActionsLayout->addWidget(SessMessageBtn);
  SessActionsLayout->addWidget(SessRunBtn);
  SessActionsLayout->addWidget(SessRefreshBtn);
  SessActionsLayout->addStretch(1);
  BodyLabel *SessCount = nullptr;
  SessLayout->addWidget(CreateSectionHeader(
      "Session Inventory",
      "Interactive and service session visibility for the local system.",
      &SessCount));
  SessLayout->addWidget(SessActions);
  auto *SessTable =
      MakeTable({"Session", "State", "ProcessCount", "WinStation"});
  SessTable->setSelectionMode(QAbstractItemView::SingleSelection);
  SessTable->setSortingEnabled(true);
  SessTable->setTextElideMode(Qt::ElideRight);
  SessTable->verticalHeader()->setDefaultSectionSize(KCompactTableRowHeight);
  SessTable->horizontalHeader()->setSectionResizeMode(
      0, QHeaderView::ResizeToContents);
  SessTable->horizontalHeader()->setSectionResizeMode(
      1, QHeaderView::ResizeToContents);
  SessTable->horizontalHeader()->setSectionResizeMode(
      2, QHeaderView::ResizeToContents);
  SessTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
  SessTable->setContextMenuPolicy(Qt::CustomContextMenu);
  SessLayout->addWidget(SessTable, 1);
  TabSelector->addItem("Sessions");
  Pages->addWidget(SessTab);

  auto *FwTab = new QWidget;
  auto *FwLayout = new QVBoxLayout(FwTab);
  ConfigureInspectorTabLayout(FwLayout);
  auto *FwAddBtn = new PushButton("Add Rule");
  ConfigureActionButton(FwAddBtn, 100, KStandardButtonHeight);
  BodyLabel *FwCount = nullptr;
  FwLayout->addWidget(CreateSectionHeader(
      "Firewall Rules", "Enumerate and manage local fallback firewall rules.",
      &FwCount, FwAddBtn));
  auto *FwTable = MakeTable({"Name", "Action", "Protocol", "Port", "State"});
  FwTable->setSortingEnabled(true);
  FwTable->setTextElideMode(Qt::ElideRight);
  FwTable->verticalHeader()->setDefaultSectionSize(KCompactTableRowHeight);
  FwTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
  FwTable->horizontalHeader()->setSectionResizeMode(
      1, QHeaderView::ResizeToContents);
  FwTable->horizontalHeader()->setSectionResizeMode(
      2, QHeaderView::ResizeToContents);
  FwTable->horizontalHeader()->setSectionResizeMode(
      3, QHeaderView::ResizeToContents);
  FwTable->horizontalHeader()->setSectionResizeMode(
      4, QHeaderView::ResizeToContents);
  FwTable->setContextMenuPolicy(Qt::CustomContextMenu);
  FwLayout->addWidget(FwTable, 1);
  TabSelector->addItem("Firewall");
  Pages->addWidget(FwTab);

  QObject::connect(TabSelector, &ComboBox::currentIndexChanged, Pages,
                   &QStackedWidget::setCurrentIndex);
  QObject::connect(Pages, &QStackedWidget::currentChanged, TabSelector,
                   &ComboBox::setCurrentIndex);
  TabSelector->setCurrentIndex(0);
  Pages->setCurrentIndex(0);
  const auto ApplyKernelControlView = [KernelControlsUi, KernelControlCache]() {
    if (!KernelControlsUi->Table)
      return;
    const auto Hex = [](qulonglong Value) {
      return QString("0x%1").arg(Value, 0, 16).toUpper();
    };
    const auto SetRow = [KernelControlsUi](int Row, const QString &Field,
                                           const QString &Value,
                                           const QString &Detail = QString()) {
      KernelControlsUi->Table->setItem(Row, 0, new QTableWidgetItem(Field));
      KernelControlsUi->Table->setItem(Row, 1, new QTableWidgetItem(Value));
      KernelControlsUi->Table->setItem(Row, 2, new QTableWidgetItem(Detail));
      KernelControlsUi->Table->setRowHeight(Row, KCompactTableRowHeight);
    };
    KernelControlsUi->Table->setUpdatesEnabled(false);
    KernelControlsUi->Table->clearContents();
    KernelControlsUi->Table->setRowCount(0);
    KernelControlsUi->Summary->setText("Kernel control overview");

    if (KernelControlCache->DebugOk) {
      const int Row = KernelControlsUi->Table->rowCount();
      KernelControlsUi->Table->insertRow(Row);
      const bool Blocked = !KernelControlCache->Debug.IsPatched;
      SetRow(Row, "Debug",
             Blocked ? "Blocked (hook active)" : "Enabled (pass-through)",
             QString("Inlines KdSystemDebugControl entry.  Blocked: all "
                     "NtSystemDebugControl "
                     "calls return ACCESS_DENIED.  Enabled: original entry "
                     "bytes restored.  "
                     "Kernel debug variables are never modified.  "
                     "Do NOT click Restart in WinDbg while blocked - close & "
                     "reopen instead."));
    } else {
      const int Row = KernelControlsUi->Table->rowCount();
      KernelControlsUi->Table->insertRow(Row);
      SetRow(Row, "Debug", "Unavailable",
             QString("Win32 error %1").arg(KernelControlCache->DebugError));
    }

    {
      const QString DseStateText =
          KernelControlCache->DseOk
              ? (KernelControlCache->Dse.CurrentValue ==
                         KernelControlCache->Dse.OriginalValue
                     ? "Restored"
                     : "Modified")
              : "Unavailable";
      const int Row0 = KernelControlsUi->Table->rowCount();
      KernelControlsUi->Table->insertRow(Row0);
      SetRow(Row0, "DSE.CiOptionsAddress",
             KernelControlCache->DseOk
                 ? Hex(KernelControlCache->Dse.CiOptionsAddress)
                 : "-");
      const int Row1 = KernelControlsUi->Table->rowCount();
      KernelControlsUi->Table->insertRow(Row1);
      SetRow(Row1, "DSE.OriginalValue",
             KernelControlCache->DseOk
                 ? Hex(KernelControlCache->Dse.OriginalValue)
                 : "-");
      const int Row2 = KernelControlsUi->Table->rowCount();
      KernelControlsUi->Table->insertRow(Row2);
      SetRow(Row2, "DSE.CurrentValue",
             KernelControlCache->DseOk
                 ? Hex(KernelControlCache->Dse.CurrentValue)
                 : "-");
      const int Row3 = KernelControlsUi->Table->rowCount();
      KernelControlsUi->Table->insertRow(Row3);
      SetRow(Row3, "DSE.Status", DseStateText,
             KernelControlCache->DseOk
                 ? QString()
                 : QString("Win32 error %1").arg(KernelControlCache->DseError));
    }

    {
      const QString PgStateText =
          KernelControlCache->PatchGuardOk
              ? (KernelControlCache->PatchGuard.IsPatched ? "Disabled"
                                                          : "Active")
              : "Unavailable";
      const int Row0 = KernelControlsUi->Table->rowCount();
      KernelControlsUi->Table->insertRow(Row0);
      SetRow(Row0, "PatchGuard.PgContextOffset",
             KernelControlCache->PatchGuardOk
                 ? Hex(KernelControlCache->PatchGuard.PgContextOffset)
                 : "-");
      const int Row1 = KernelControlsUi->Table->rowCount();
      KernelControlsUi->Table->insertRow(Row1);
      SetRow(Row1, "PatchGuard.IsPatched",
             KernelControlCache->PatchGuardOk
                 ? (KernelControlCache->PatchGuard.IsPatched ? "TRUE" : "FALSE")
                 : "-");
      const int Row2 = KernelControlsUi->Table->rowCount();
      KernelControlsUi->Table->insertRow(Row2);
      SetRow(Row2, "PatchGuard.Status", PgStateText,
             KernelControlCache->PatchGuardOk
                 ? QString()
                 : QString("Win32 error %1")
                       .arg(KernelControlCache->PatchGuardError));
    }

    const QString DebugStateText =
        !KernelControlCache->DebugOk
            ? "Unavailable"
            : (!KernelControlCache->Debug.IsPatched ? "Blocked" : "Enabled");
    const QString DseStateText =
        !KernelControlCache->DseOk
            ? "Unavailable"
            : (KernelControlCache->Dse.CurrentValue ==
                       KernelControlCache->Dse.OriginalValue
                   ? "Restored"
                   : "Modified");
    const QString PgStateText =
        !KernelControlCache->PatchGuardOk
            ? "Unavailable"
            : (KernelControlCache->PatchGuard.IsPatched ? "Disabled"
                                                        : "Active");
    KernelControlsUi->Detail->setText(
        QString("Debug %1 | DSE %2 | PatchGuard %3")
            .arg(DebugStateText)
            .arg(DseStateText)
            .arg(PgStateText));
    KernelControlsUi->Table->setUpdatesEnabled(true);
  };
  const auto ApplyFilter = [Search, State, KernelControlsUi, SyncTable,
                            SessTable, FwTable] {
    const QString Query = Search->text().trimmed();
    const auto FilterTable = [&Query](QTableWidget *Table) {
      for (int Row = 0; Row < Table->rowCount(); ++Row) {
        QString RowText;
        for (int Column = 0; Column < Table->columnCount(); ++Column)
          if (const QTableWidgetItem *Item = Table->item(Row, Column))
            RowText += Item->text() + ' ';
        Table->setRowHidden(Row,
                            !Query.isEmpty() &&
                                !RowText.contains(Query, Qt::CaseInsensitive));
      }
    };
    FilterTable(KernelControlsUi->Table);
    for (const InspectorTab &Tab : *State)
      FilterTable(Tab.Table);
    FilterTable(SyncTable);
    FilterTable(SessTable);
    FilterTable(FwTable);
  };
  QObject::connect(Search, &QLineEdit::textChanged, Page,
                   [ApplyFilter] { ApplyFilter(); });
  ApplyKernelControlView();
  ApplyFilter();
  const auto CurrentSessionId = [SessTable]() -> std::optional<ULONG> {
    const int Row = SessTable->currentRow();
    if (Row < 0)
      return std::nullopt;
    QTableWidgetItem *Item = SessTable->item(Row, 0);
    if (!Item)
      return std::nullopt;
    bool Ok = false;
    const qulonglong Value = Item->data(Qt::UserRole).toULongLong(&Ok);
    if (Ok && Value <= std::numeric_limits<ULONG>::max())
      return static_cast<ULONG>(Value);
    const qulonglong Parsed = Item->text().trimmed().toULongLong(&Ok, 10);
    if (!Ok || Parsed > std::numeric_limits<ULONG>::max())
      return std::nullopt;
    return static_cast<ULONG>(Parsed);
  };
  const auto CurrentSessionState = [SessTable]() -> QString {
    const int Row = SessTable->currentRow();
    if (Row < 0)
      return QString();
    QTableWidgetItem *Item = SessTable->item(Row, 1);
    return Item ? Item->text().trimmed() : QString();
  };
  const auto RefreshSessionActionState = [CurrentSessionId, CurrentSessionState,
                                          SessLogoffBtn, SessDisconnectBtn,
                                          SessMessageBtn, SessRunBtn]() {
    const std::optional<ULONG> SessionId = CurrentSessionId();
    const bool HasSession = SessionId.has_value();
    const bool IsInteractiveSession = HasSession && SessionId.value() != 0;
    const QString StateText = CurrentSessionState();
    const bool CanDisconnect =
        IsInteractiveSession &&
        !StateText.contains("Disconnected", Qt::CaseInsensitive) &&
        !StateText.contains("Down", Qt::CaseInsensitive) &&
        !StateText.contains("Reset", Qt::CaseInsensitive);
    SessLogoffBtn->setEnabled(IsInteractiveSession);
    SessDisconnectBtn->setEnabled(CanDisconnect);
    SessMessageBtn->setEnabled(IsInteractiveSession);
    SessRunBtn->setEnabled(IsInteractiveSession);
  };
  QObject::connect(
      Refresh, &QPushButton::clicked, Page,
      [Page, Refresh, Status, LoadStatus, Loading, State, KernelControlsUi,
       KernelControlCache, ApplyKernelControlView, ApplyFilter, SyncTable,
       SyncCount, SessTable, SessCount, FwTable, FwCount, SessLogoffBtn,
       SessDisconnectBtn, SessMessageBtn, SessRunBtn] {
        Refresh->setEnabled(false);
        KernelControlsUi->EnableDebug->setEnabled(false);
        KernelControlsUi->DisableDebug->setEnabled(false);
        KernelControlsUi->DisableDse->setEnabled(false);
        KernelControlsUi->RestoreDse->setEnabled(false);
        KernelControlsUi->DisablePatchGuard->setEnabled(false);
        KernelControlsUi->RestorePatchGuard->setEnabled(false);
        KernelControlsUi->TriggerPatchGuard->setEnabled(false);
        SessLogoffBtn->setEnabled(false);
        SessDisconnectBtn->setEnabled(false);
        SessMessageBtn->setEnabled(false);
        SessRunBtn->setEnabled(false);
        Refresh->setText("Refreshing...");
        Status->setText("Reading kernel inventory...");
        LoadStatus->setText("Refreshing kernel state, inventory sections, and "
                            "fallback views...");
        Loading->show();
        Loading->start();
        QPointer<QWidget> SafePage(Page);
        std::thread([SafePage, Refresh, Status, LoadStatus, Loading, State,
                     KernelControlsUi, KernelControlCache,
                     ApplyKernelControlView, ApplyFilter, SyncTable, SyncCount,
                     SessTable, SessCount, FwTable, FwCount] {
          struct Result {
            MDV2_LIST_HEADER Header{};
            std::vector<MDV2_RECORD> Records;
          };

          KernelControlState KernelState;
          KernelState.DebugOk = QueryDebugState(&KernelState.Debug);
          KernelState.DebugError = G_LastMultiDrvError;
          KernelState.DseOk = QueryDse(&KernelState.Dse);
          KernelState.DseError = G_LastMultiDrvError;
          KernelState.PatchGuardOk = QueryPatchGuard(&KernelState.PatchGuard);
          KernelState.PatchGuardError = G_LastMultiDrvError;

          std::vector<Result> Results(State->size());
          for (size_t Index = 0; Index < State->size(); ++Index) {
            MDV2_QUERY_INPUT Request{};
            Request.MaxEntries = MDV2_MAX_PAGE_RECORDS;
            if (!(*State)[Index].Path.isEmpty())
              wcsncpy_s(Request.Path,
                        (*State)[Index].Path.toStdWString().c_str(), _TRUNCATE);
            QueryMultiDrvRecordsV2((*State)[Index].Ioctl, Request,
                                   Results[Index].Records,
                                   &Results[Index].Header);
          }

          std::vector<std::tuple<QString, QString, ULONG>> SyncEntries;
          if (G_DeviceHandle != INVALID_HANDLE_VALUE) {
            BYTE SyncBuf[65536] = {};
            ULONG SyncReturned = 0;
            if (EnumSyncObjectsKernel(SyncBuf, sizeof(SyncBuf),
                                      &SyncReturned) &&
                SyncReturned >= sizeof(ULONG)) {
              PULONG Cnt = (PULONG)SyncBuf;
              PUCHAR D = (PUCHAR)(Cnt + 1);
              for (ULONG i = 0; i < *Cnt; i++) {
                ULONG Dir = *(PULONG)D;
                D += 4;
                USHORT NLen = *(PUSHORT)D;
                D += 2;
                QString Name = NLen ? QString::fromWCharArray(
                                          (PWCHAR)D, NLen / sizeof(WCHAR))
                                    : QString();
                D += NLen;
                USHORT TLen = *(PUSHORT)D;
                D += 2;
                QString Type = TLen ? QString::fromWCharArray(
                                          (PWCHAR)D, TLen / sizeof(WCHAR))
                                    : QString();
                D += TLen;
                D = (PUCHAR)(((ULONG_PTR)D + 3) & ~3ULL);
                SyncEntries.emplace_back(Name, Type, Dir);
              }
            }
          }

          std::vector<std::tuple<ULONG, ULONG, ULONG, QString>> SessEntries;
          if (G_DeviceHandle != INVALID_HANDLE_VALUE) {
            BYTE SessBuf[4096] = {};
            ULONG SessReturned = 0;
            if (EnumSessions(SessBuf, sizeof(SessBuf), &SessReturned) &&
                SessReturned >= sizeof(ULONG)) {
              PULONG Cnt = (PULONG)SessBuf;
              PUCHAR D = (PUCHAR)(Cnt + 1);
              for (ULONG i = 0; i < *Cnt; i++) {
                ULONG Sid = *(PULONG)D;
                D += 4;
                ULONG St = *(PULONG)D;
                D += 4;
                ULONG Pc = *(PULONG)D;
                D += 4;
                QString Ws = QString::fromWCharArray((PWCHAR)D);
                D += 64;
                SessEntries.emplace_back(Sid, St, Pc, Ws);
              }
            }
          }
          if (SessEntries.empty())
            EnumerateSessionsFallback(SessEntries);

          std::vector<std::tuple<QString, ULONG, ULONG, ULONG, QString>>
              FwEntries;
          if (G_DeviceHandle != INVALID_HANDLE_VALUE) {
            BYTE FwBuf[16384] = {};
            (void)FwBuf;
          }
          if (FwEntries.empty())
            EnumerateFirewallRulesFallback(FwEntries);
          if (FwEntries.empty())
            FwEntries.emplace_back("Firewall enumeration unavailable", 0, 0, 0,
                                   "Not implemented");

          if (SyncEntries.empty())
            EnumerateSyncObjectsFallback(SyncEntries);

          QMetaObject::invokeMethod(
              qApp,
              [SafePage, Refresh, Status, LoadStatus, Loading, State,
               KernelControlsUi, KernelControlCache, ApplyKernelControlView,
               ApplyFilter, KernelState, Results = std::move(Results),
               SyncTable, SyncCount, SyncEntries = std::move(SyncEntries),
               SessTable, SessCount, SessEntries = std::move(SessEntries),
               FwTable, FwCount, FwEntries = std::move(FwEntries)]() mutable {
                if (!SafePage)
                  return;
                const auto Hex = [](qulonglong Value) {
                  return QString("0x%1").arg(Value, 0, 16).toUpper();
                };
                const auto RecordAddressText =
                    [&Hex](const MDV2_RECORD &Record) {
                      if (Record.Address != 0)
                        return Hex(Record.Address);
                      for (const ULONG64 Value : Record.Value) {
                        if (Value != 0)
                          return Hex(Value);
                      }
                      return QString("-");
                    };
                const auto SourceName = [](ULONG Source) {
                  static const std::array<const char *, 10> Names{
                      "Unknown",        "Public API",
                      "System Info",    "Object Manager",
                      "Registry",       "Process Environment",
                      "Memory Map",     "Version Profile",
                      "Signature Scan", "Cross-view"};
                  return Source < Names.size()
                             ? QString::fromLatin1(Names[Source])
                             : QString("Source %1").arg(Source);
                };
                const auto ConfidenceName = [](ULONG Confidence) {
                  static const std::array<const char *, 4> Names{
                      "Unavailable", "Low", "Medium", "High"};
                  return Confidence < Names.size()
                             ? QString::fromLatin1(Names[Confidence])
                             : QString("Level %1").arg(Confidence);
                };
                size_t TotalRecords = 0;
                *KernelControlCache = KernelState;
                ApplyKernelControlView();
                for (size_t Index = 0; Index < State->size(); ++Index) {
                  QTableWidget *Table = (*State)[Index].Table;
                  Table->setSortingEnabled(false);
                  Table->clearContents();
                  Table->setRowCount(0);
                  for (const auto &Record : Results[Index].Records) {
                    const int Row = Table->rowCount();
                    Table->insertRow(Row);
                    const QString PathText =
                        QString::fromWCharArray(Record.Path);
                    const QString DetailText =
                        QString::fromWCharArray(Record.Detail);
                    const QString Detail =
                        PathText.isEmpty()
                            ? DetailText
                            : (DetailText.isEmpty()
                                   ? PathText
                                   : PathText + " | " + DetailText);
                    const QString StatusText =
                        Record.Status == 0
                            ? "Success"
                            : Hex(static_cast<quint32>(Record.Status));
                    const QString AddressText = RecordAddressText(Record);
                    QString SizeOrValueText;
                    if (Record.SizeBytes != 0)
                      SizeOrValueText =
                          QLocale().toString(
                              static_cast<qulonglong>(Record.SizeBytes)) +
                          " B";
                    else if (Record.Value[0] != 0)
                      SizeOrValueText = Hex(Record.Value[0]);
                    else if (Record.Value[1] != 0)
                      SizeOrValueText = Hex(Record.Value[1]);
                    else
                      SizeOrValueText = "-";
                    const QStringList Values{
                        QString::fromWCharArray(Record.Name),
                        QString::fromWCharArray(Record.TypeName),
                        AddressText,
                        SizeOrValueText,
                        Detail,
                        SourceName(Record.Source),
                        ConfidenceName(Record.Confidence),
                        StatusText};
                    for (int Column = 0; Column < Values.size(); ++Column)
                      Table->setItem(Row, Column,
                                     new QTableWidgetItem(Values[Column]));
                    Table->setRowHeight(Row, KCompactTableRowHeight);
                  }
                  TotalRecords += Results[Index].Records.size();
                  (*State)[Index].Count->setText(
                      QString("%1 record%2")
                          .arg(Results[Index].Records.size())
                          .arg(Results[Index].Records.size() == 1 ? "" : "s"));
                  if (Results[Index].Records.empty()) {
                    Table->insertRow(0);
                    Table->setItem(0, 0, new QTableWidgetItem("No records"));
                    Table->setItem(
                        0, 7,
                        new QTableWidgetItem(
                            Results[Index].Header.Status == 0
                                ? "Success"
                                : Hex(static_cast<quint32>(
                                      Results[Index].Header.Status))));
                  }
                  Table->setSortingEnabled(true);
                }

                SyncTable->setSortingEnabled(false);
                SyncTable->clearContents();
                SyncTable->setRowCount(0);
                for (const auto &[Name, Type, Dir] : SyncEntries) {
                  int R = SyncTable->rowCount();
                  SyncTable->insertRow(R);
                  SyncTable->setItem(R, 0, new QTableWidgetItem(Name));
                  SyncTable->setItem(R, 1, new QTableWidgetItem(Type));
                  SyncTable->setItem(
                      R, 2,
                      new QTableWidgetItem(Dir == 0 ? "Global" : "Session"));
                  SyncTable->setRowHeight(R, KCompactTableRowHeight);
                }
                SyncCount->setText(
                    QString("%1 objects").arg(SyncEntries.size()));
                SyncTable->setSortingEnabled(true);

                SessTable->setSortingEnabled(false);
                SessTable->clearContents();
                SessTable->setRowCount(0);
                for (const auto &[Sid, St, Pc, Ws] : SessEntries) {
                  int R = SessTable->rowCount();
                  SessTable->insertRow(R);
                  auto *SessionItem =
                      new QTableWidgetItem(QString::number(Sid));
                  SessionItem->setData(Qt::UserRole,
                                       static_cast<qulonglong>(Sid));
                  SessTable->setItem(R, 0, SessionItem);
                  SessTable->setItem(
                      R, 1, new QTableWidgetItem(SessionStateText(St)));
                  SessTable->setItem(R, 2,
                                     new QTableWidgetItem(QString::number(Pc)));
                  SessTable->setItem(R, 3, new QTableWidgetItem(Ws));
                  SessTable->setRowHeight(R, KCompactTableRowHeight);
                }
                SessCount->setText(
                    QString("%1 sessions").arg(SessEntries.size()));
                SessTable->setSortingEnabled(true);

                FwTable->setSortingEnabled(false);
                FwTable->clearContents();
                FwTable->setRowCount(0);
                for (const auto &[Name, Action, Proto, Port, StateText] :
                     FwEntries) {
                  int R = FwTable->rowCount();
                  FwTable->insertRow(R);
                  FwTable->setItem(R, 0, new QTableWidgetItem(Name));
                  FwTable->setItem(
                      R, 1,
                      new QTableWidgetItem(Action == 0 ? "Block" : "Allow"));
                  FwTable->setItem(R, 2,
                                   new QTableWidgetItem(
                                       Proto == 6    ? "TCP"
                                       : Proto == 17 ? "UDP"
                                                     : QString::number(Proto)));
                  FwTable->setItem(R, 3,
                                   new QTableWidgetItem(QString::number(Port)));
                  FwTable->setItem(R, 4, new QTableWidgetItem(StateText));
                  FwTable->setRowHeight(R, KCompactTableRowHeight);
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
                LoadStatus->setText(
                    "Kernel inventory is up to date. Search filters apply to "
                    "the current results only.");
                if (SessTable->rowCount() > 0 && SessTable->currentRow() < 0)
                  SessTable->selectRow(0);
              },
              Qt::QueuedConnection);
        }).detach();
      });
  QObject::connect(
      SessTable, &QTableWidget::itemSelectionChanged, Page,
      [RefreshSessionActionState] { RefreshSessionActionState(); });
  QObject::connect(SessRefreshBtn, &QPushButton::clicked, Page, [Refresh] {
    QTimer::singleShot(0, Refresh, &QPushButton::click);
  });
  QObject::connect(
      SessLogoffBtn, &QPushButton::clicked, Page,
      [Page, Refresh, CurrentSessionId] {
        const std::optional<ULONG> SessionId = CurrentSessionId();
        if (!SessionId.has_value() || SessionId.value() == 0) {
          ShowWarningNotice(Page, "Kernel Inspector",
                            "Select an interactive session first.");
          return;
        }

        auto *Dialog = new MessageBoxBase(Page->window());
        Dialog->setAttribute(Qt::WA_DeleteOnClose);
        Dialog->viewLayout()->addWidget(
            MakeLabel("Log off session", 18, KTextPrimary, QFont::DemiBold));
        Dialog->viewLayout()->addWidget(
            MakeLabel(QString("Log off session %1? This will terminate that "
                              "user's session processes.")
                          .arg(SessionId.value()),
                      11, KTextMuted));
        Dialog->yesButton()->setText("Logoff");
        Dialog->cancelButton()->setText("Cancel");
        QObject::connect(
            Dialog->yesButton(), &QPushButton::clicked, Dialog,
            [Page, Dialog, Refresh, SessionId] {
              if (!LogoffSession(SessionId.value())) {
                ShowErrorNotice(
                    Page, "Kernel Inspector",
                    QString("Unable to log off session %1 (error %2).")
                        .arg(SessionId.value())
                        .arg(G_LastMultiDrvError));
                return;
              }
              Dialog->accept();
              ShowSuccessNotice(Page, "Kernel Inspector",
                                QString("Session %1 logoff requested.")
                                    .arg(SessionId.value()));
              QTimer::singleShot(0, Refresh, &QPushButton::click);
            });
        QObject::connect(Dialog->cancelButton(), &QPushButton::clicked, Dialog,
                         &QDialog::reject);
        Dialog->show();
      });
  QObject::connect(
      SessDisconnectBtn, &QPushButton::clicked, Page,
      [Page, Refresh, CurrentSessionId] {
        const std::optional<ULONG> SessionId = CurrentSessionId();
        if (!SessionId.has_value() || SessionId.value() == 0) {
          ShowWarningNotice(Page, "Kernel Inspector",
                            "Select an interactive session first.");
          return;
        }

        auto *Dialog = new MessageBoxBase(Page->window());
        Dialog->setAttribute(Qt::WA_DeleteOnClose);
        Dialog->viewLayout()->addWidget(
            MakeLabel("Disconnect session", 18, KTextPrimary, QFont::DemiBold));
        Dialog->viewLayout()->addWidget(
            MakeLabel(QString("Disconnect session %1 and keep its apps running "
                              "in the background.")
                          .arg(SessionId.value()),
                      11, KTextMuted));
        Dialog->yesButton()->setText("Disconnect");
        Dialog->cancelButton()->setText("Cancel");
        QObject::connect(
            Dialog->yesButton(), &QPushButton::clicked, Dialog,
            [Page, Dialog, Refresh, SessionId] {
              if (!DisconnectSessionFallback(SessionId.value())) {
                ShowErrorNotice(
                    Page, "Kernel Inspector",
                    QString("Unable to disconnect session %1.\n%2")
                        .arg(SessionId.value())
                        .arg(DescribeWin32ErrorMessage(GetLastError())));
                return;
              }
              Dialog->accept();
              ShowSuccessNotice(
                  Page, "Kernel Inspector",
                  QString("Session %1 disconnected.").arg(SessionId.value()));
              QTimer::singleShot(0, Refresh, &QPushButton::click);
            });
        QObject::connect(Dialog->cancelButton(), &QPushButton::clicked, Dialog,
                         &QDialog::reject);
        Dialog->show();
      });
  QObject::connect(
      SessMessageBtn, &QPushButton::clicked, Page, [Page, CurrentSessionId] {
        const std::optional<ULONG> SessionId = CurrentSessionId();
        if (!SessionId.has_value() || SessionId.value() == 0) {
          ShowWarningNotice(Page, "Kernel Inspector",
                            "Select an interactive session first.");
          return;
        }

        auto *Dialog = new MessageBoxBase(Page->window());
        Dialog->setAttribute(Qt::WA_DeleteOnClose);
        auto *TitleEdit = new LineEdit;
        TitleEdit->setPlaceholderText("Message title");
        TitleEdit->setText("Kernel Inspector");
        auto *BodyEdit = new PlainTextEdit;
        BodyEdit->setPlaceholderText("Message text");
        BodyEdit->setMinimumHeight(120);
        auto *StyleCombo = new ComboBox;
        StyleCombo->addItems({"Information", "Warning", "Error", "Question"});
        auto *TimeoutEdit = new LineEdit;
        TimeoutEdit->setPlaceholderText("Timeout seconds");
        TimeoutEdit->setText("30");
        auto *WaitCheck = new CheckBox("Wait for user response");
        Dialog->viewLayout()->addWidget(MakeLabel(
            "Send session message", 18, KTextPrimary, QFont::DemiBold));
        Dialog->viewLayout()->addWidget(
            MakeLabel(QString("Deliver a popup message to session %1.")
                          .arg(SessionId.value()),
                      11, KTextMuted));
        Dialog->viewLayout()->addWidget(TitleEdit);
        Dialog->viewLayout()->addWidget(BodyEdit);
        Dialog->viewLayout()->addWidget(StyleCombo);
        Dialog->viewLayout()->addWidget(TimeoutEdit);
        Dialog->viewLayout()->addWidget(WaitCheck);
        Dialog->yesButton()->setText("Send");
        Dialog->cancelButton()->setText("Cancel");
        QObject::connect(
            Dialog->yesButton(), &QPushButton::clicked, Dialog,
            [Page, Dialog, SessionId, TitleEdit, BodyEdit, StyleCombo,
             TimeoutEdit, WaitCheck] {
              const QString Title = TitleEdit->text().trimmed();
              const QString Body = BodyEdit->toPlainText().trimmed();
              bool TimeoutOk = false;
              const ULONG TimeoutSeconds =
                  TimeoutEdit->text().trimmed().toULong(&TimeoutOk, 10);
              if (Title.isEmpty() || Body.isEmpty()) {
                ShowWarningNotice(Page, "Kernel Inspector",
                                  "Enter both a title and message text.");
                return;
              }
              if (!TimeoutOk || TimeoutSeconds == 0) {
                ShowWarningNotice(Page, "Kernel Inspector",
                                  "Enter a valid timeout in seconds.");
                return;
              }

              UINT Style = MB_OK | MB_TOPMOST;
              switch (StyleCombo->currentIndex()) {
              case 1:
                Style |= MB_ICONWARNING;
                break;
              case 2:
                Style |= MB_ICONERROR;
                break;
              case 3:
                Style |= MB_ICONQUESTION;
                break;
              default:
                Style |= MB_ICONINFORMATION;
                break;
              }

              DWORD Response = 0;
              if (!SendSessionMessageFallback(
                      SessionId.value(), Title, Body, Style, TimeoutSeconds,
                      WaitCheck->isChecked(), &Response)) {
                ShowErrorNotice(
                    Page, "Kernel Inspector",
                    QString("Unable to send a message to session %1.\n%2")
                        .arg(SessionId.value())
                        .arg(DescribeWin32ErrorMessage(GetLastError())));
                return;
              }

              Dialog->accept();
              const QString ResponseText =
                  WaitCheck->isChecked()
                      ? QString(" Response=%1.").arg(Response)
                      : QString();
              ShowSuccessNotice(Page, "Kernel Inspector",
                                QString("Message sent to session %1.%2")
                                    .arg(SessionId.value())
                                    .arg(ResponseText));
            });
        QObject::connect(Dialog->cancelButton(), &QPushButton::clicked, Dialog,
                         &QDialog::reject);
        Dialog->show();
      });
  QObject::connect(
      SessRunBtn, &QPushButton::clicked, Page,
      [Page, Refresh, CurrentSessionId] {
        const std::optional<ULONG> SessionId = CurrentSessionId();
        if (!SessionId.has_value() || SessionId.value() == 0) {
          ShowWarningNotice(Page, "Kernel Inspector",
                            "Select an interactive session first.");
          return;
        }

        auto *Dialog = new MessageBoxBase(Page->window());
        Dialog->setAttribute(Qt::WA_DeleteOnClose);
        auto *ExecutableEdit = new LineEdit;
        ExecutableEdit->setPlaceholderText("Select an executable");
        auto *ArgumentsEdit = new LineEdit;
        ArgumentsEdit->setPlaceholderText("Optional arguments");
        auto *ShowWindowCheck = new CheckBox("Show window");
        ShowWindowCheck->setChecked(true);
        auto *BrowseButton = MakeButton("Browse");
        auto *Row = new QWidget;
        auto *RowLayout = new QHBoxLayout(Row);
        ConfigureToolbarLayout(RowLayout);
        RowLayout->addWidget(ExecutableEdit, 1);
        RowLayout->addWidget(BrowseButton);
        Dialog->viewLayout()->addWidget(
            MakeLabel("Run in session", 18, KTextPrimary, QFont::DemiBold));
        Dialog->viewLayout()->addWidget(MakeLabel(
            QString("Launch a process with the user token from session %1.")
                .arg(SessionId.value()),
            11, KTextMuted));
        Dialog->viewLayout()->addWidget(Row);
        Dialog->viewLayout()->addWidget(ArgumentsEdit);
        Dialog->viewLayout()->addWidget(ShowWindowCheck);
        Dialog->yesButton()->setText("Run");
        Dialog->cancelButton()->setText("Cancel");
        QObject::connect(BrowseButton, &QPushButton::clicked, Dialog,
                         [Dialog, ExecutableEdit] {
                           const QString Path = QFileDialog::getOpenFileName(
                               Dialog, "Select executable", QString(),
                               "Executable files (*.exe);;All files (*.*)");
                           if (!Path.isEmpty())
                             ExecutableEdit->setText(
                                 QDir::toNativeSeparators(Path));
                         });
        QObject::connect(
            Dialog->yesButton(), &QPushButton::clicked, Dialog,
            [Page, Dialog, Refresh, SessionId, ExecutableEdit, ArgumentsEdit,
             ShowWindowCheck] {
              const QString Path = ExecutableEdit->text().trimmed();
              if (Path.isEmpty() || !QFileInfo::exists(Path)) {
                ShowWarningNotice(Page, "Kernel Inspector",
                                  "Select an existing executable file.");
                return;
              }

              DWORD ProcessId = 0;
              if (!LaunchProcessInSession(
                      SessionId.value(), Path, ArgumentsEdit->text(),
                      ShowWindowCheck->isChecked(), &ProcessId)) {
                ShowErrorNotice(
                    Page, "Kernel Inspector",
                    QString("Unable to launch the process in session %1.\n%2")
                        .arg(SessionId.value())
                        .arg(DescribeWin32ErrorMessage(GetLastError())));
                return;
              }

              Dialog->accept();
              ShowSuccessNotice(
                  Page, "Kernel Inspector",
                  QString("Process launched in session %1 with PID %2.")
                      .arg(SessionId.value())
                      .arg(ProcessId));
              QTimer::singleShot(0, Refresh, &QPushButton::click);
            });
        QObject::connect(Dialog->cancelButton(), &QPushButton::clicked, Dialog,
                         &QDialog::reject);
        Dialog->show();
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
  const auto RunKernelControlAction = [Page, Refresh, Status, LoadStatus,
                                       Loading, SetKernelControlButtonsEnabled](
                                          const QString &BusyText,
                                          const QString &ActionName,
                                          std::function<bool()> Action) {
    SetKernelControlButtonsEnabled(false);
    Refresh->setEnabled(false);
    Status->setText(BusyText);
    LoadStatus->setText(
        "Applying kernel control change and waiting for refresh...");
    Loading->show();
    Loading->start();
    QPointer<QWidget> SafePage(Page);
    std::thread([SafePage, Refresh, Status, LoadStatus, Loading,
                 SetKernelControlButtonsEnabled, ActionName,
                 Action = std::move(Action)]() mutable {
      const bool Success = Action();
      const DWORD ErrorCode = G_LastMultiDrvError;
      QMetaObject::invokeMethod(
          qApp,
          [SafePage, Refresh, Status, LoadStatus, Loading,
           SetKernelControlButtonsEnabled, Success, ErrorCode, ActionName] {
            if (!SafePage)
              return;
            Loading->stop();
            Loading->hide();
            Refresh->setEnabled(true);
            SetKernelControlButtonsEnabled(true);
            if (!Success) {
              Status->setText(QString("%1 failed").arg(ActionName));
              LoadStatus->setText("Kernel control action failed. Review the "
                                  "error and retry if appropriate.");
              ShowErrorNotice(SafePage, "Kernel Inspector",
                              QString("%1 failed (error %2).")
                                  .arg(ActionName)
                                  .arg(ErrorCode));
            } else {
              LoadStatus->setText(
                  "Kernel control action completed. Refreshing inventory...");
              ShowSuccessNotice(SafePage, "Kernel Inspector",
                                QString("%1 completed.").arg(ActionName));
              QTimer::singleShot(0, Refresh, &QPushButton::click);
            }
          },
          Qt::QueuedConnection);
    }).detach();
  };
  const auto RunPatchGuardTrigger = [Page, Refresh, Status, LoadStatus, Loading,
                                     SetKernelControlButtonsEnabled]() {
    SetKernelControlButtonsEnabled(false);
    Refresh->setEnabled(false);
    Status->setText("Triggering PatchGuard...");
    LoadStatus->setText(
        "Sending PatchGuard trigger request and waiting for completion...");
    Loading->show();
    Loading->start();
    QPointer<QWidget> SafePage(Page);
    std::thread([SafePage, Refresh, Status, LoadStatus, Loading,
                 SetKernelControlButtonsEnabled] {
      IDT_LIMIT_OUTPUT IdtOut{};
      const bool Success = SetIdtLimit();
      const DWORD ErrorCode = G_LastMultiDrvError;
      QMetaObject::invokeMethod(
          qApp,
          [SafePage, Refresh, Status, LoadStatus, Loading,
           SetKernelControlButtonsEnabled, Success, ErrorCode] {
            if (!SafePage)
              return;
            Loading->stop();
            Loading->hide();
            Refresh->setEnabled(true);
            SetKernelControlButtonsEnabled(true);
            if (!Success) {
              Status->setText("TriggerPatchGuard failed");
              LoadStatus->setText("PatchGuard trigger failed. Inspect the "
                                  "reported driver error.");
              ShowErrorNotice(SafePage, "Kernel Inspector",
                              QString("TriggerPatchGuard failed (error %1).")
                                  .arg(ErrorCode));
              return;
            }
            LoadStatus->setText(
                "PatchGuard trigger completed. Refreshing kernel state...");
            ShowSuccessNotice(SafePage, "Kernel Inspector",
                              "TriggerPatchGuard completed.");
            QTimer::singleShot(0, Refresh, &QPushButton::click);
          },
          Qt::QueuedConnection);
    }).detach();
  };
  QObject::connect(KernelControlsUi->EnableDebug, &QPushButton::clicked, Page,
                   [RunKernelControlAction] {
                     RunKernelControlAction("Enabling kernel debug...",
                                            "EnableDebug",
                                            [] { return EnableDebug(); });
                   });
  QObject::connect(KernelControlsUi->DisableDebug, &QPushButton::clicked, Page,
                   [RunKernelControlAction] {
                     RunKernelControlAction("Disabling kernel debug...",
                                            "DisableDebug",
                                            [] { return DisableDebug(); });
                   });
  QObject::connect(KernelControlsUi->DisableDse, &QPushButton::clicked, Page,
                   [RunKernelControlAction] {
                     RunKernelControlAction("Disabling DSE...", "DisableDse",
                                            [] { return DisableDse(); });
                   });
  QObject::connect(KernelControlsUi->RestoreDse, &QPushButton::clicked, Page,
                   [RunKernelControlAction] {
                     RunKernelControlAction("Restoring DSE...", "RestoreDse",
                                            [] { return RestoreDse(); });
                   });
  QObject::connect(KernelControlsUi->DisablePatchGuard, &QPushButton::clicked,
                   Page, [RunKernelControlAction] {
                     RunKernelControlAction("Disabling PatchGuard...",
                                            "DisablePatchGuard",
                                            [] { return DisablePatchGuard(); });
                   });
  QObject::connect(KernelControlsUi->RestorePatchGuard, &QPushButton::clicked,
                   Page, [RunKernelControlAction] {
                     RunKernelControlAction("Restoring PatchGuard...",
                                            "RestorePatchGuard",
                                            [] { return RestorePatchGuard(); });
                   });
  QObject::connect(KernelControlsUi->TriggerPatchGuard, &QPushButton::clicked,
                   Page, [RunPatchGuardTrigger] { RunPatchGuardTrigger(); });
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
    Dialog->viewLayout()->addWidget(
        MakeLabel("Add firewall rule", 18, KTextPrimary, QFont::DemiBold));
    Dialog->viewLayout()->addWidget(NameEdit);
    Dialog->viewLayout()->addWidget(ActionCombo);
    Dialog->viewLayout()->addWidget(ProtocolCombo);
    Dialog->viewLayout()->addWidget(PortEdit);
    Dialog->yesButton()->setText("Add");
    QObject::connect(
        Dialog->yesButton(), &QPushButton::clicked, Dialog,
        [Page, Dialog, NameEdit, ActionCombo, ProtocolCombo, PortEdit,
         Refresh] {
          const QString Name = NameEdit->text().trimmed();
          bool Ok = false;
          const ULONG Port = PortEdit->text().trimmed().toULong(&Ok);
          if (Name.isEmpty() || !Ok || Port == 0 || Port > 65535) {
            ShowWarningNotice(Page, "Kernel Inspector",
                              "Enter a valid rule name and port.");
            return;
          }
          const bool Success = AddFirewallRuleFallback(
              Name, ActionCombo->currentIndex() == 0 ? 0u : 1u,
              ProtocolCombo->currentIndex() == 0 ? 6u : 17u, Port);
          if (!Success) {
            ShowErrorNotice(Page, "Kernel Inspector",
                            "Unable to add firewall rule.");
            return;
          }
          Dialog->accept();
          ShowSuccessNotice(Page, "Kernel Inspector", "Firewall rule added.");
          QTimer::singleShot(0, Refresh, &QPushButton::click);
        });
    QObject::connect(Dialog->cancelButton(), &QPushButton::clicked, Dialog,
                     &QDialog::reject);
    Dialog->show();
  });
  QObject::connect(
      FwTable, &QWidget::customContextMenuRequested, Page,
      [Page, FwTable, Refresh](const QPoint &Position) {
        const QModelIndex Index = FwTable->indexAt(Position);
        if (!Index.isValid())
          return;
        FwTable->selectRow(Index.row());
        QTableWidgetItem *NameItem = FwTable->item(Index.row(), 0);
        QTableWidgetItem *StateItem = FwTable->item(Index.row(), 4);
        if (!NameItem || !StateItem)
          return;
        const QString RuleName = NameItem->text().trimmed();
        const bool Enabled =
            StateItem->text().contains("Enabled", Qt::CaseInsensitive);
        auto *Menu = new RoundMenu(QString(), Page);
        auto *ToggleAction =
            new QAction(Enabled ? "Disable rule" : "Enable rule", Menu);
        auto *DeleteAction = new QAction("Delete rule", Menu);
        auto *RefreshAction = new QAction("Refresh", Menu);
        Menu->addAction(ToggleAction);
        Menu->addAction(DeleteAction);
        Menu->addAction(RefreshAction);
        ConnectMenuAction(
            ToggleAction, Page, [Page, RuleName, Enabled, Refresh] {
              if (!SetFirewallRuleEnabledFallback(RuleName, !Enabled)) {
                ShowErrorNotice(Page, "Kernel Inspector",
                                QString("Unable to %1 firewall rule.")
                                    .arg(Enabled ? "disable" : "enable"));
                return;
              }
              ShowSuccessNotice(Page, "Kernel Inspector",
                                QString("Firewall rule %1.")
                                    .arg(Enabled ? "disabled" : "enabled"));
              QTimer::singleShot(0, Refresh, &QPushButton::click);
            });
        ConnectMenuAction(DeleteAction, Page, [Page, RuleName, Refresh] {
          if (!RemoveFirewallRuleFallback(RuleName)) {
            ShowErrorNotice(Page, "Kernel Inspector",
                            "Unable to delete firewall rule.");
            return;
          }
          ShowSuccessNotice(Page, "Kernel Inspector", "Firewall rule deleted.");
          QTimer::singleShot(0, Refresh, &QPushButton::click);
        });
        ConnectMenuAction(RefreshAction, Page, [Refresh] {
          QTimer::singleShot(0, Refresh, &QPushButton::click);
        });
        ReleaseMenuAfterClose(Menu);
        Menu->exec(FwTable->viewport()->mapToGlobal(Position));
      });
  QObject::connect(
      SessTable, &QWidget::customContextMenuRequested, Page,
      [Page, SessTable, SessLogoffBtn, SessDisconnectBtn, SessMessageBtn,
       SessRunBtn, SessRefreshBtn](const QPoint &Position) {
        const QModelIndex Index = SessTable->indexAt(Position);
        if (!Index.isValid())
          return;
        SessTable->selectRow(Index.row());
        auto *Menu = new RoundMenu(QString(), Page);
        auto *LogoffAction = new QAction("Logoff session", Menu);
        auto *DisconnectAction = new QAction("Disconnect session", Menu);
        auto *MessageAction = new QAction("Send message", Menu);
        auto *RunAction = new QAction("Run in session", Menu);
        auto *RefreshAction = new QAction("Refresh", Menu);
        LogoffAction->setEnabled(SessLogoffBtn->isEnabled());
        DisconnectAction->setEnabled(SessDisconnectBtn->isEnabled());
        MessageAction->setEnabled(SessMessageBtn->isEnabled());
        RunAction->setEnabled(SessRunBtn->isEnabled());
        Menu->addAction(LogoffAction);
        Menu->addAction(DisconnectAction);
        Menu->addAction(MessageAction);
        Menu->addAction(RunAction);
        Menu->addSeparator();
        Menu->addAction(RefreshAction);
        ConnectMenuAction(LogoffAction, Page,
                          [SessLogoffBtn] { SessLogoffBtn->click(); });
        ConnectMenuAction(DisconnectAction, Page,
                          [SessDisconnectBtn] { SessDisconnectBtn->click(); });
        ConnectMenuAction(MessageAction, Page,
                          [SessMessageBtn] { SessMessageBtn->click(); });
        ConnectMenuAction(RunAction, Page,
                          [SessRunBtn] { SessRunBtn->click(); });
        ConnectMenuAction(RefreshAction, Page,
                          [SessRefreshBtn] { SessRefreshBtn->click(); });
        ReleaseMenuAfterClose(Menu);
        Menu->exec(SessTable->viewport()->mapToGlobal(Position));
      });
  QTimer::singleShot(0, Refresh, &QPushButton::click);

  return Page;
}
