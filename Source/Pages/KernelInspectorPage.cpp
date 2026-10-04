// ============================================================
// 内核检视页：以多标签页查询内核内存/对象/过滤器/网络/安全
// 状态（含驱动调试状态），支持模糊过滤与详情查看。
// ============================================================
#include "KernelInspectorRefresh.h"
#include "KernelInspectorData.h"

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
    PushButton *TriggerPatchGuard = nullptr;
    PushButton *EnablePpn = nullptr;
  };
  struct KernelControlState {
    bool Queried = false;
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
  auto *RefreshController = new KernelInspectorRefresh(Page, Refresh);
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
    KernelControlsUi->Detail->setWordWrap(true);
    KernelControlsUi->Detail->setMinimumWidth(260);
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
    KernelControlsUi->TriggerPatchGuard = new PushButton("TriggerPatchGuard");
    KernelControlsUi->EnablePpn = new PushButton("EnablePPN");

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
                           KernelControlsUi->TriggerPatchGuard,
                           KernelControlsUi->EnablePpn}),
        1);
    ControlLayout->addLayout(ActionRow);
    TabLayout->addWidget(ControlCard, 1);

    TabSelector->addItem("Kernel Controls");
    Pages->addWidget(TabPage);
  }
  const std::array<
      std::tuple<DWORD, const char *, const wchar_t *, Fluent::IconType>, 4>
      Definitions{{{IOCTL_ENUM_MINIFILTERS, "MiniFilters", L"",
                    Fluent::IconType::DOCUMENT},
                   {IOCTL_ENUM_WFP, "WFP", L"", Fluent::IconType::GLOBE},
                   {IOCTL_ENUM_NDIS, "NDIS", L"", Fluent::IconType::CONNECT},
                   {IOCTL_QUERY_SECURITY, "Security", L"",
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

  // Firewall 标签已移除：规则枚举与管理统一由 Network 页提供。

  QObject::connect(TabSelector, &ComboBox::currentIndexChanged, Pages,
                   &QStackedWidget::setCurrentIndex);
  QObject::connect(Pages, &QStackedWidget::currentChanged, TabSelector,
                   &ComboBox::setCurrentIndex);
  TabSelector->setCurrentIndex(0);
  Pages->setCurrentIndex(0);
  QObject::connect(Pages, &QStackedWidget::currentChanged, RefreshController,
                   [RefreshController] { RefreshController->RequestRefresh(); });
  const auto ResetDataTable = [](QTableWidget *Table) {
    Table->setSortingEnabled(false);
    Table->clearContents();
    Table->setRowCount(0);
  };
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

    if (!KernelControlCache->Queried) {
      KernelControlsUi->Table->insertRow(0);
      SetRow(0, "Kernel state", "Loading...", "Reading kernel control state.");
      KernelControlsUi->Detail->setText("Loading kernel state...");
      KernelControlsUi->Table->setUpdatesEnabled(true);
      return;
    }

    if (KernelControlCache->DebugOk) {
      {
        // Debug 状态按新 ABI（HookInstalled / IsDebuggerEnabled）渲染
        const int Row = KernelControlsUi->Table->rowCount();
        KernelControlsUi->Table->insertRow(Row);
        SetRow(Row, "Debug Hook",
               KernelControlCache->Debug.HookInstalled
                   ? "Installed (blocking)"
                   : "Not installed");
      }
      {
        const int Row = KernelControlsUi->Table->rowCount();
        KernelControlsUi->Table->insertRow(Row);
        const QString DebuggerValueText =
            KernelControlCache->Debug.Status == 0
                ? (KernelControlCache->Debug.IsDebuggerEnabled
                       ? "1 (debugger present)"
                       : "0 (no debugger)")
                : QString("Query error %1")
                      .arg(KernelControlCache->Debug.Status);
        SetRow(Row, "IsDebuggerEnabled", DebuggerValueText);
      }
    } else {
      const int Row = KernelControlsUi->Table->rowCount();
      KernelControlsUi->Table->insertRow(Row);
      SetRow(Row, "Debug Hook", "Unavailable",
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

      /* 找到的 PG 嫌疑 DPC 数量：查询时驱动会实时重跑一次 DPC 扫描
         （只分类不摘除），因此这里反映的是当前值。 */
      const int Row3 = KernelControlsUi->Table->rowCount();
      KernelControlsUi->Table->insertRow(Row3);
      SetRow(Row3, "PatchGuard.DpcsFound",
             KernelControlCache->PatchGuardOk
                 ? QString::number(KernelControlCache->PatchGuard.DpcFound)
                 : "-",
             KernelControlCache->PatchGuardOk
                 ? QString("scanned %1, cancelled %2")
                       .arg(KernelControlCache->PatchGuard.DpcScanned)
                       .arg(KernelControlCache->PatchGuard.DpcCancelled)
                 : QString("Win32 error %1")
                       .arg(KernelControlCache->PatchGuardError));

      /* 找到的 PG 嫌疑 APC 数量（与 DPC 对称）：查询时驱动实时重跑一次
         只分类的 APC 扫描，因此这里反映的是当前值。 */
      const int RowApc = KernelControlsUi->Table->rowCount();
      KernelControlsUi->Table->insertRow(RowApc);
      SetRow(RowApc, "PatchGuard.ApcsFound",
             KernelControlCache->PatchGuardOk
                 ? QString::number(KernelControlCache->PatchGuard.ApcFound)
                 : "-",
             KernelControlCache->PatchGuardOk
                 ? QString("scanned %1, cancelled %2")
                       .arg(KernelControlCache->PatchGuard.ApcScanned)
                       .arg(KernelControlCache->PatchGuard.ApcCancelled)
                 : QString("Win32 error %1")
                       .arg(KernelControlCache->PatchGuardError));

      /* ---- 早期 bugcheck 拦截（ByePg 式主路径）----
         该路径劫持 HAL 私有派发表，在 PG 校验失败触发 bugcheck 时恢复执行流，
         因此"是否启用"与"已吃掉多少次 bugcheck"是判断 PG 绕过是否真正生效的
         关键指标：仅 KPRCB 上下文清零成功、但拦截未启用时，PG 触发仍会蓝屏。

         Detail 里必须能看出"卡在哪一步"：ResolveStage 是位掩码，
         全部置上（0x7F）才算解析完整；此外附带 InterceptStatus 以便区分
         "解析失败"（NOT_FOUND）与"HAL 版本不支持"（NOT_SUPPORTED）。 */
      const auto DescribeStage = [Hex](ULONG Stage) {
        if (Stage == 0)
          return QString("stage none (resolution never ran)");
        QStringList Parts;
        if (Stage & PG_RESOLVE_STAGE_KPRCB_CONTEXT)
          Parts << "ctx";
        if (Stage & PG_RESOLVE_STAGE_DEBUG_IRQL)
          Parts << "irql";
        if (Stage & PG_RESOLVE_STAGE_HW_TRIGGER)
          Parts << "hwtrig";
        if (Stage & PG_RESOLVE_STAGE_BUGCHECK2)
          Parts << "bc2";
        if (Stage & PG_RESOLVE_STAGE_BUGCHECK_ACTIVE)
          Parts << "bcactive";
        if (Stage & PG_RESOLVE_STAGE_FREEZE_LOCK)
          Parts << "freezelock";
        if (Stage & PG_RESOLVE_STAGE_NT_BASE)
          Parts << "ntbase";
        return QString("stage %1 [%2]")
            .arg(Hex(Stage))
            .arg(Parts.isEmpty() ? QString("unknown") : Parts.join('+'));
      };
      const int Row4 = KernelControlsUi->Table->rowCount();
      KernelControlsUi->Table->insertRow(Row4);
      SetRow(Row4, "PatchGuard.Intercept",
             KernelControlCache->PatchGuardOk
                 ? (KernelControlCache->PatchGuard.InterceptEnabled ? "Enabled"
                                                                    : "Disabled")
                 : "-",
             KernelControlCache->PatchGuardOk
                 ? QString("%1, HAL v%2, hooks %3, status 0x%4, critical %5")
                       .arg(DescribeStage(
                           KernelControlCache->PatchGuard.ResolveStage))
                       .arg(KernelControlCache->PatchGuard.HalVersion)
                       .arg(Hex(KernelControlCache->PatchGuard.HalHookMask))
                       .arg(KernelControlCache->PatchGuard.InterceptStatus, 8, 16,
                            QLatin1Char('0'))
                       .arg(KernelControlCache->PatchGuard.AllCriticalResolved
                                ? "OK"
                                : "INCOMPLETE")
                 : QString());

      const int Row5 = KernelControlsUi->Table->rowCount();
      KernelControlsUi->Table->insertRow(Row5);
      SetRow(Row5, "PatchGuard.Suppressed",
             KernelControlCache->PatchGuardOk
                 ? QString::number(
                       KernelControlCache->PatchGuard.SuppressedCount)
                 : "-",
             KernelControlCache->PatchGuardOk
                 ? QString("freeze %1, bugcheck %2, last 0x%3 @ %4")
                       .arg(KernelControlCache->PatchGuard.FreezeNotifies)
                       .arg(KernelControlCache->PatchGuard.BugCheckNotifies)
                       .arg(KernelControlCache->PatchGuard.LastBugCheckCode, 0, 16)
                       .arg(Hex(KernelControlCache->PatchGuard.LastBugCheckRip))
                 : QString());

      /* KprcbContextOffset 是 _KPRCB 内的**偏移**而非地址，标签里写清楚，
         避免被读成"PG 上下文地址是 0x85C0"。
         Detail 列出三个关键符号的解析结果：地址 + 是否解析成功。
         这两者必须分开显示——地址低 32 位为 0 是页对齐的正常现象，
         不能据此判断成败。 */
      const auto DescribeSymbol = [](const char *Name, ULONG64 Address,
                                     bool Resolved) {
        return QString("%1 %2%3")
            .arg(QLatin1String(Name))
            .arg(Resolved ? QString("0x%1").arg(Address, 0, 16).toUpper()
                          : QString("unresolved"))
            .arg(Resolved ? QString() : QString(" (!)"));
      };
      const int Row6 = KernelControlsUi->Table->rowCount();
      KernelControlsUi->Table->insertRow(Row6);
      SetRow(Row6, "PatchGuard.KprcbContextOffset",
             KernelControlCache->PatchGuardOk
                 ? Hex(KernelControlCache->PatchGuard.KprcbContextOffset)
                 : "-",
             KernelControlCache->PatchGuardOk
                 ? QString("offset in _KPRCB; %1 | %2 | %3")
                       .arg(DescribeSymbol(
                           "KiHardwareTrigger",
                           KernelControlCache->PatchGuard.KiHardwareTriggerAddr,
                           KernelControlCache->PatchGuard
                               .KiHardwareTriggerResolved != FALSE))
                       .arg(DescribeSymbol(
                           "KiBugCheckActive",
                           KernelControlCache->PatchGuard.KiBugCheckActiveAddr,
                           KernelControlCache->PatchGuard
                               .KiBugCheckActiveResolved != FALSE))
                       .arg(DescribeSymbol(
                           "KiFreezeExecutionLock",
                           KernelControlCache->PatchGuard
                               .KiFreezeExecutionLockAddr,
                           KernelControlCache->PatchGuard.KiFreezeLockResolved !=
                               FALSE))
                 : QString());

      /* ---- 辅路径审计：实际清零用的偏移与来源 ----
         清零偏移若走了启发式（OffsetSource == Heuristic），可能与上面的
         KprcbContextOffset（确定性解析）不一致——这正是历史上误清零、破坏
         内核结构的根因。两个值并排显示，一眼看出是否偏航。 */
      const auto DescribeOffsetSource = [](ULONG Source) {
        switch (Source) {
        case PG_OFFSET_SOURCE_DETERMINISTIC:
          return QString("deterministic");
        case PG_OFFSET_SOURCE_HEURISTIC:
          return QString("heuristic (!)");
        default:
          return QString("none");
        }
      };
      const int Row7 = KernelControlsUi->Table->rowCount();
      KernelControlsUi->Table->insertRow(Row7);
      SetRow(Row7, "PatchGuard.ClearOffset",
             KernelControlCache->PatchGuardOk
                 ? Hex(KernelControlCache->PatchGuard.ClearOffset)
                 : "-",
             KernelControlCache->PatchGuardOk
                 ? QString("source %1; ctx offset %2")
                       .arg(DescribeOffsetSource(
                           KernelControlCache->PatchGuard.OffsetSource))
                       .arg(Hex(
                           KernelControlCache->PatchGuard.KprcbContextOffset))
                 : QString());

      /* ---- PPN 路径（第三路径）：PG 代码页 NX 化 + #PF 拦截 ----
         该路径把 PG 校验例程所在可执行页置 NX，并 Hook #PF，PG 取指到这些页
         时抛 #PF。TargetCount 为已 NX 页数，NxFaults 为命中并处理次数。 */
      const int Row8 = KernelControlsUi->Table->rowCount();
      KernelControlsUi->Table->insertRow(Row8);
      SetRow(Row8, "PatchGuard.PpnPageGuard",
             KernelControlCache->PatchGuardOk
                 ? (KernelControlCache->PatchGuard.PpnActive ? "Active" : "Off")
                 : "-",
             KernelControlCache->PatchGuardOk
                 ? QString("pages %1, nx-faults %2, passthrough %3, "
                           "status 0x%4 | p0 %5 p1 %6 p2 %7 p3 %8")
                       .arg(KernelControlCache->PatchGuard.PpnTargetCount)
                       .arg(KernelControlCache->PatchGuard.PpnNxFaults)
                       .arg(KernelControlCache->PatchGuard.PpnPassthrough)
                       .arg(KernelControlCache->PatchGuard.PpnStatus, 8, 16,
                            QLatin1Char('0'))
                       .arg(Hex(KernelControlCache->PatchGuard.PpnTargetPages[0]))
                       .arg(Hex(KernelControlCache->PatchGuard.PpnTargetPages[1]))
                       .arg(Hex(KernelControlCache->PatchGuard.PpnTargetPages[2]))
                       .arg(Hex(KernelControlCache->PatchGuard.PpnTargetPages[3]))
                 : QString());

      const int RowCpu = KernelControlsUi->Table->rowCount();
      KernelControlsUi->Table->insertRow(RowCpu);
      SetRow(RowCpu, "PatchGuard.CpuCoverage",
             KernelControlCache->PatchGuardOk
                 ? QString("%1/%2 cleared")
                       .arg(KernelControlCache->PatchGuard.CpuCleared)
                       .arg(KernelControlCache->PatchGuard.CpuTotal)
                 : "-",
             KernelControlCache->PatchGuardOk
                 ? QString("attempted %1, failed %2, groups %3/%4")
                       .arg(KernelControlCache->PatchGuard.CpuAttempted)
                       .arg(KernelControlCache->PatchGuard.CpuFailed)
                       .arg(KernelControlCache->PatchGuard.ProcessorGroupsCovered)
                       .arg(KernelControlCache->PatchGuard.ProcessorGroupCount)
                 : QString("Win32 error %1")
                       .arg(KernelControlCache->PatchGuardError));

      const int RowContext = KernelControlsUi->Table->rowCount();
      KernelControlsUi->Table->insertRow(RowContext);
      SetRow(RowContext, "PatchGuard.ContextConfidence",
             KernelControlCache->PatchGuardOk
                 ? QString("%1%%")
                       .arg(KernelControlCache->PatchGuard.ContextConfidence)
                 : "-",
             KernelControlCache->PatchGuardOk
                 ? QString("evidence %1")
                       .arg(Hex(KernelControlCache->PatchGuard.ContextEvidence))
                 : QString());

      const int RowDpcConfidence = KernelControlsUi->Table->rowCount();
      KernelControlsUi->Table->insertRow(RowDpcConfidence);
      SetRow(RowDpcConfidence, "PatchGuard.DpcConfidence",
             KernelControlCache->PatchGuardOk
                 ? QString("%1 high / %2 low")
                       .arg(KernelControlCache->PatchGuard.DpcHighConfidenceCount)
                       .arg(KernelControlCache->PatchGuard.DpcLowConfidenceCount)
                 : "-",
             "Scores >= 70 are high confidence.");

      const int RowApcConfidence = KernelControlsUi->Table->rowCount();
      KernelControlsUi->Table->insertRow(RowApcConfidence);
      SetRow(RowApcConfidence, "PatchGuard.ApcResolver",
             KernelControlCache->PatchGuardOk
                 ? QString("%1%% / %2 anchors")
                       .arg(KernelControlCache->PatchGuard.ApcResolverConfidence)
                       .arg(KernelControlCache->PatchGuard.ApcResolverAnchorCount)
                 : "-",
             KernelControlCache->PatchGuardOk
                 ? QString("%1 high / %2 low")
                       .arg(KernelControlCache->PatchGuard.ApcHighConfidenceCount)
                       .arg(KernelControlCache->PatchGuard.ApcLowConfidenceCount)
                 : QString());
    }

    const QString DebugStateText =
        !KernelControlCache->DebugOk
            ? "Unavailable"
            : (KernelControlCache->Debug.HookInstalled ? "Blocked"
                                                       : "Pass-through");
    // 查询成功显示 0/1；失败原因保留在明细中，不用问号掩盖错误。
    const QString DbgEnabledText =
        !KernelControlCache->DebugOk || KernelControlCache->Debug.Status != 0
            ? "Unavailable"
            : (KernelControlCache->Debug.IsDebuggerEnabled ? "1" : "0");
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
    /* PG DPC 摘要：未查询成功时不显示数量，避免把 0 误读成"没有 DPC"。 */
    const QString PgDpcText =
        !KernelControlCache->PatchGuardOk
            ? QString("Unavailable")
            : KernelControlCache->PatchGuard.DpcStatus != 0
                  ? QString("Not scanned")
                  : QString::number(KernelControlCache->PatchGuard.DpcFound);
    /* 拦截摘要：区分"仅清零上下文"与"已建立 bugcheck 拦截"——
       后者才是 PG 触发时不再蓝屏的关键。 */
    /* 清零来源摘要：避免误清零，把来源直接标在总览里。 */
    /* PPN 摘要：页数 + 命中次数。 */
    const QString PgPpnText =
        !KernelControlCache->PatchGuardOk
            ? QString("Unavailable")
            : (KernelControlCache->PatchGuard.PpnActive
                   ? QString("on (%1 pg, %2 nx)")
                         .arg(KernelControlCache->PatchGuard.PpnTargetCount)
                         .arg(KernelControlCache->PatchGuard.PpnNxFaults)
                    : QString("off"));
    /* PG APC 摘要：与 DPC 对称，未查询成功时不显示数量。 */
    const QString PgApcText =
        !KernelControlCache->PatchGuardOk
            ? QString("Unavailable")
            : KernelControlCache->PatchGuard.ApcStatus != 0
                  ? QString("Not scanned")
                  : QString::number(KernelControlCache->PatchGuard.ApcFound);
    const QString PgCpuText =
        !KernelControlCache->PatchGuardOk
            ? QString("Unavailable")
            : QString("%1/%2")
                  .arg(KernelControlCache->PatchGuard.CpuCleared)
                  .arg(KernelControlCache->PatchGuard.CpuTotal);
    const QString PgContextText =
        !KernelControlCache->PatchGuardOk
            ? QString("Unavailable")
            : QString("%1%%")
                  .arg(KernelControlCache->PatchGuard.ContextConfidence);
    const QString PgDpcSummary =
        !KernelControlCache->PatchGuardOk
            ? QString("Unavailable")
            : QString("%1 (%2H/%3L)")
                  .arg(PgDpcText)
                  .arg(KernelControlCache->PatchGuard.DpcHighConfidenceCount)
                  .arg(KernelControlCache->PatchGuard.DpcLowConfidenceCount);
    const QString PgApcSummary =
        !KernelControlCache->PatchGuardOk
            ? QString("Unavailable")
            : QString("%1 (%2H/%3L)")
                  .arg(PgApcText)
                  .arg(KernelControlCache->PatchGuard.ApcHighConfidenceCount)
                  .arg(KernelControlCache->PatchGuard.ApcLowConfidenceCount);
    KernelControlsUi->Detail->setText(
        QString("Dbg %1/%2 | DSE %3 | PG %4\n"
                "CPU %5 | DPC %6 | APC %7 | Ctx %8 | PPN %9")
            .arg(DebugStateText)
            .arg(DbgEnabledText)
            .arg(DseStateText)
            .arg(PgStateText)
            .arg(PgCpuText)
            .arg(PgDpcSummary)
            .arg(PgApcSummary)
            .arg(PgContextText)
            .arg(PgPpnText));
    KernelControlsUi->Table->setUpdatesEnabled(true);
  };
  const auto ApplyFilter = [Search, State, KernelControlsUi, SyncTable,
                            SessTable] {
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
       SyncCount, SessTable, SessCount, SessLogoffBtn, SessDisconnectBtn,
       SessMessageBtn, SessRunBtn, RefreshController] {
        if (!Refresh->isEnabled())
          return;
        Refresh->setEnabled(false);
        KernelControlsUi->EnableDebug->setEnabled(false);
        KernelControlsUi->DisableDebug->setEnabled(false);
        KernelControlsUi->DisableDse->setEnabled(false);
        KernelControlsUi->RestoreDse->setEnabled(false);
        KernelControlsUi->DisablePatchGuard->setEnabled(false);
        KernelControlsUi->TriggerPatchGuard->setEnabled(false);
        KernelControlsUi->EnablePpn->setEnabled(false);
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
                     SessTable, SessCount, RefreshController] {
          struct Result {
            INVENTORY_LIST_HEADER Header{};
            std::vector<INVENTORY_RECORD> Records;
          };

          KernelControlState KernelState;
          KernelState.DebugOk = QueryDebugState(&KernelState.Debug);
          KernelState.DebugError = G_LastAegisCoreError;
          KernelState.DseOk = QueryDse(&KernelState.Dse);
          KernelState.DseError = G_LastAegisCoreError;
          KernelState.PatchGuardOk = QueryPatchGuard(&KernelState.PatchGuard);
          KernelState.PatchGuardError = G_LastAegisCoreError;
          KernelState.Queried = true;

          // 控制字段先显示，避免被后面的库存枚举和回退扫描拖住。
          QMetaObject::invokeMethod(
              qApp,
              [SafePage, KernelControlCache, ApplyKernelControlView,
               ApplyFilter, KernelState] {
                if (!SafePage)
                  return;
                *KernelControlCache = KernelState;
                ApplyKernelControlView();
                ApplyFilter();
              },
              Qt::QueuedConnection);

          std::vector<Result> Results(State->size());
          for (size_t Index = 0; Index < State->size(); ++Index) {
            INVENTORY_QUERY_INPUT Request{};
            Request.MaxEntries = INVENTORY_MAX_PAGE_RECORDS;
            if (!(*State)[Index].Path.isEmpty())
              wcsncpy_s(Request.Path,
                        (*State)[Index].Path.toStdWString().c_str(), _TRUNCATE);
            QueryAegisCoreRecords((*State)[Index].Ioctl, Request,
                                   Results[Index].Records,
                                   &Results[Index].Header);
          }

          std::vector<std::tuple<QString, QString, ULONG>> SyncEntries;
          {
            BYTE SyncBuf[65536] = {};
            ULONG SyncReturned = 0;
            if (EnumSyncObjectsKernel(SyncBuf, sizeof(SyncBuf),
                                      &SyncReturned) &&
                SyncReturned <= sizeof(SyncBuf)) {
              KernelInspectorData::ParseSyncObjects(SyncBuf, SyncReturned,
                                                    SyncEntries);
            }
          }

          std::vector<std::tuple<ULONG, ULONG, ULONG, QString>> SessEntries;
          // WTS supplies the real station name and connection state on both
          // Windows versions. The process snapshot is a fallback only.
          if (!EnumerateSessionsFallback(SessEntries)) {
            BYTE SessBuf[KernelInspectorData::SessionBufferBytes] = {};
            ULONG SessReturned = 0;
            if (EnumSessions(SessBuf, sizeof(SessBuf), &SessReturned) &&
                SessReturned <= sizeof(SessBuf)) {
              KernelInspectorData::ParseProcessSessions(SessBuf, SessReturned,
                                                        SessEntries);
            }
          }
          // The kernel directory query covers global objects; include the
          // current session's BaseNamedObjects even when it returned data.
          EnumerateSyncObjectsFallback(SyncEntries);
          KernelInspectorData::DeduplicateSyncObjects(SyncEntries);

          QMetaObject::invokeMethod(
              qApp,
              [SafePage, Refresh, Status, LoadStatus, Loading, State,
               KernelControlsUi, RefreshController,
               ApplyFilter, KernelState, Results = std::move(Results),
               SyncTable, SyncCount, SyncEntries = std::move(SyncEntries),
               SessTable, SessCount, SessEntries = std::move(SessEntries)]() mutable {
                if (!SafePage)
                  return;
                const auto Hex = [](qulonglong Value) {
                  return QString("0x%1").arg(Value, 0, 16).toUpper();
                };
                const auto RecordAddressText =
                    [&Hex](const INVENTORY_RECORD &Record) {
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
                      R, 1, new QTableWidgetItem(
                                St == (std::numeric_limits<ULONG>::max)()
                                    ? QString("Unavailable")
                                    : SessionStateText(St)));
                  SessTable->setItem(R, 2,
                                     new QTableWidgetItem(QString::number(Pc)));
                  SessTable->setItem(R, 3, new QTableWidgetItem(Ws));
                  SessTable->setRowHeight(R, KCompactTableRowHeight);
                }
                SessCount->setText(
                    QString("%1 sessions").arg(SessEntries.size()));
                SessTable->setSortingEnabled(true);

                ApplyFilter();
                Loading->stop();
                Loading->hide();
                Refresh->setEnabled(true);
                KernelControlsUi->EnableDebug->setEnabled(true);
                KernelControlsUi->DisableDebug->setEnabled(true);
                KernelControlsUi->DisableDse->setEnabled(true);
                KernelControlsUi->RestoreDse->setEnabled(true);
                KernelControlsUi->DisablePatchGuard->setEnabled(true);
                KernelControlsUi->TriggerPatchGuard->setEnabled(true);
                KernelControlsUi->EnablePpn->setEnabled(true);
                Refresh->setText("Refresh");
                Status->setText(QString("%1 records").arg(TotalRecords));
                const bool Incomplete = !KernelState.DebugOk ||
                                        !KernelState.DseOk ||
                                        !KernelState.PatchGuardOk;
                const bool Retrying =
                    RefreshController->RefreshCompleted(Incomplete);
                LoadStatus->setText(
                    Retrying
                        ? "Some kernel fields are unavailable; retrying automatically..."
                        : Incomplete
                              ? "Some kernel fields are unavailable. See the reported errors."
                              : "Kernel inventory is up to date. Search filters apply to "
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
        Dialog->viewLayout()->setContentsMargins(28, 26, 28, 32);
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
                        .arg(G_LastAegisCoreError));
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
        Dialog->viewLayout()->setContentsMargins(28, 26, 28, 32);
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
        Dialog->viewLayout()->setContentsMargins(28, 26, 28, 32);
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
        Dialog->viewLayout()->setContentsMargins(28, 26, 28, 32);
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
    KernelControlsUi->TriggerPatchGuard->setEnabled(Enabled);
    KernelControlsUi->EnablePpn->setEnabled(Enabled);
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
      const DWORD ErrorCode = G_LastAegisCoreError;
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
      const DWORD ErrorCode = G_LastAegisCoreError;
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
  QObject::connect(KernelControlsUi->TriggerPatchGuard, &QPushButton::clicked,
                   Page, [RunPatchGuardTrigger] { RunPatchGuardTrigger(); });
  QObject::connect(KernelControlsUi->EnablePpn, &QPushButton::clicked, Page,
                   [RunKernelControlAction] {
                     RunKernelControlAction("Enabling PPN page guard...",
                                            "EnablePPN",
                                            [] { return EnablePPN(); });
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
  // 首次进入及返回页面由 RefreshController 的 Show 事件统一调度。

  return Page;
}
