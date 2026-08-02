QWidget *CreateHandleLabPage() {
  struct HandleLabPage final : public QWidget {
    struct HandleEntryRow {
      DWORD OwnerPid = 0;
      QString OwnerName;
      quint64 HandleValue = 0;
      quint64 ObjectAddress = 0;
      quint32 GrantedAccess = 0;
      quint32 Attributes = 0;
      QString TypeName;
      QString ObjectName;
      DWORD TargetPid = 0;
      DWORD TargetTid = 0;
      QString TargetName;
      QString AccessDisplay;
      QString RiskText;
      QString SearchText;
      bool Dangerous = false;
      bool CrossProcess = false;
      bool Watchlisted = false;
      QString MatchedRules;
    };
    struct ProcessAggregateRow {
      DWORD OwnerPid = 0;
      QString OwnerName;
      int HandleCount = 0;
      int DangerousCount = 0;
      int CrossCount = 0;
      int WatchCount = 0;
    };
    struct TypeAggregateRow {
      QString TypeName;
      int HandleCount = 0;
      int DangerousCount = 0;
      int CrossCount = 0;
      int WatchCount = 0;
    };
    struct ObjectAggregateRow {
      quint64 ObjectAddress = 0;
      QString ObjectName;
      QString TypeName;
      int HandleCount = 0;
      int ProcessCount = 0;
      int DangerousCount = 0;
    };
    struct WatchRule {
      QString Kind;
      QString Value;
    };
    struct SystemHandleTableEntry {
      PVOID Object;
      ULONG_PTR UniqueProcessId;
      ULONG_PTR HandleValue;
      ULONG GrantedAccess;
      USHORT CreatorBackTraceIndex;
      USHORT ObjectTypeIndex;
      ULONG HandleAttributes;
      ULONG Reserved;
    };
    struct SystemHandleInfo {
      ULONG_PTR NumberOfHandles;
      ULONG_PTR Reserved;
      SystemHandleTableEntry Handles[1];
    };
    struct RefreshResult {
      std::vector<HandleEntryRow> Rows;
      DWORD ErrorCode = ERROR_SUCCESS;
      bool Success = false;
      bool BasicOnly = false;
    };
    struct ObjectIdentity {
      QString TypeName;
      QString ObjectName;
      DWORD TargetPid = 0;
      DWORD TargetTid = 0;
      QString TargetName;
    };

    explicit HandleLabPage(QWidget *Parent = nullptr) : QWidget(Parent) {
      auto *Layout = new QVBoxLayout(this);
      ConfigurePageLayout(Layout);

      auto *Toolbar = new QHBoxLayout;
      ConfigureToolbarLayout(Toolbar);
      SearchEdit = new SearchLineEdit;
      ConfigureSearchLineEdit(
          SearchEdit, "Search PID, handle, type, object, access, or target",
          KStandardWideSearchWidth);
      TypeFilter = new ComboBox;
      TypeFilter->setMinimumWidth(150);
      TypeFilter->addItem("All Types");
      PidFilter = new LineEdit;
      ConfigureLineEdit(PidFilter, "PID", 110);
      DangerousOnly = new CheckBox("Only dangerous");
      CrossOnly = new CheckBox("Only cross-process");
      AutoRefresh = new CheckBox("Auto refresh");
      StatusLabel = new BodyLabel("Ready");
      StatusLabel->setProperty("TextRole", "Muted");
      RefreshIndicator = new IndeterminateProgressRing(this, false);
      RefreshIndicator->setFixedSize(22, 22);
      RefreshIndicator->hide();
      RefreshButton = MakeButton("Refresh", true);
      ConfigureActionButton(RefreshButton);
      Toolbar->addWidget(SearchEdit);
      Toolbar->addWidget(TypeFilter);
      Toolbar->addWidget(PidFilter);
      Toolbar->addWidget(DangerousOnly);
      Toolbar->addWidget(CrossOnly);
      Toolbar->addWidget(AutoRefresh);
      Toolbar->addStretch();
      Toolbar->addWidget(StatusLabel);
      Toolbar->addWidget(RefreshIndicator);
      Toolbar->addWidget(RefreshButton);
      Layout->addLayout(Toolbar);

      auto *Body = new QSplitter(Qt::Horizontal);
      Body->setChildrenCollapsible(false);
      Body->setHandleWidth(1);
      Layout->addWidget(Body, 1);

      ViewList = new QListWidget;
      ViewList->setObjectName("HandleLabViewList");
      ViewList->setMinimumWidth(168);
      ViewList->setMaximumWidth(196);
      ViewList->setSpacing(2);
      ViewList->setFrameShape(QFrame::NoFrame);
      ViewList->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
      ViewList->addItems(
          {"By Handle", "By Process", "By Type", "By Object", "Watchlist"});
      ViewList->setCurrentRow(0);
      Body->addWidget(ViewList);

      auto *CenterHost = new QWidget;
      auto *CenterLayout = new QVBoxLayout(CenterHost);
      CenterLayout->setContentsMargins(0, 0, 0, 0);
      CenterLayout->setSpacing(10);
      Pages = new QStackedWidget;
      CenterLayout->addWidget(Pages, 1);
      Body->addWidget(CenterHost);

      HandleTable = MakeTable({"Owner PID", "Process", "Handle", "Object",
                               "Type", "Access", "Attributes", "Target",
                               "Risk"});
      HandleTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
      HandleTable->setContextMenuPolicy(Qt::CustomContextMenu);
      ConfigureHandleTable(HandleTable);
      Pages->addWidget(HandleTable);

      ProcessTable = MakeTable(
          {"PID", "Process", "Handles", "Dangerous", "Cross", "Watched"});
      ProcessTable->setSelectionMode(QAbstractItemView::SingleSelection);
      ConfigureAggregateTable(ProcessTable, 1);
      Pages->addWidget(ProcessTable);

      TypeTable = MakeTable(
          {"Type", "Handles", "Dangerous", "Cross", "Watched"});
      TypeTable->setSelectionMode(QAbstractItemView::SingleSelection);
      ConfigureAggregateTable(TypeTable, 0);
      Pages->addWidget(TypeTable);

      ObjectTable = MakeTable(
          {"Object", "Name", "Type", "Handles", "PIDs", "Dangerous"});
      ObjectTable->setSelectionMode(QAbstractItemView::SingleSelection);
      ConfigureAggregateTable(ObjectTable, 1);
      Pages->addWidget(ObjectTable);

      WatchTable = MakeTable({"Owner PID", "Process", "Handle", "Object",
                              "Type", "Access", "Matched Rule", "Target",
                              "Risk"});
      WatchTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
      WatchTable->setContextMenuPolicy(Qt::CustomContextMenu);
      ConfigureHandleTable(WatchTable);
      Pages->addWidget(WatchTable);

      auto *RightCard = new SimpleCardWidget;
      RightCard->setBorderRadius(5);
      RightCard->setMinimumWidth(344);
      auto *RightLayout = new QVBoxLayout(RightCard);
      RightLayout->setContentsMargins(16, 16, 16, 16);
      RightLayout->setSpacing(10);

      RightLayout->addWidget(
          MakeLabel("Handle Details", 13, KTextPrimary, QFont::DemiBold));
      DetailText = new PlainTextEdit;
      DetailText->setReadOnly(true);
      DetailText->setPlaceholderText("Select a handle or aggregate row.");
      InstallFluentScrollBar(DetailText, Qt::Vertical);
      RightLayout->addWidget(DetailText, 1);

      auto *ActionLabel =
          MakeLabel("Actions", 12, KTextPrimary, QFont::DemiBold);
      RightLayout->addWidget(ActionLabel);
      auto *ActionGrid = new QGridLayout;
      ActionGrid->setContentsMargins(0, 0, 0, 0);
      ActionGrid->setHorizontalSpacing(8);
      ActionGrid->setVerticalSpacing(8);
      ForceCloseButton = MakeButton("ForceClose", true);
      DowngradeButton = MakeButton("Downgrade");
      DuplicateButton = MakeButton("Duplicate");
      BatchForceCloseButton = MakeButton("Batch ForceClose", true);
      BatchDowngradeButton = MakeButton("Batch Downgrade");
      PivotButton = MakeButton("Pivot to Handles");
      for (PushButton *Button : {ForceCloseButton, DowngradeButton,
                                 DuplicateButton, BatchForceCloseButton,
                                 BatchDowngradeButton, PivotButton})
        ConfigureActionButton(Button, 160, KStandardButtonHeight);
      ActionGrid->addWidget(ForceCloseButton, 0, 0);
      ActionGrid->addWidget(DowngradeButton, 0, 1);
      ActionGrid->addWidget(DuplicateButton, 1, 0);
      ActionGrid->addWidget(PivotButton, 1, 1);
      ActionGrid->addWidget(BatchForceCloseButton, 2, 0);
      ActionGrid->addWidget(BatchDowngradeButton, 2, 1);
      RightLayout->addLayout(ActionGrid);

      RightLayout->addWidget(
          MakeLabel("Watchlist Rules", 12, KTextPrimary, QFont::DemiBold));
      RuleTable = MakeTable({"Kind", "Value"});
      RuleTable->setSelectionMode(QAbstractItemView::SingleSelection);
      RuleTable->horizontalHeader()->setSectionResizeMode(
          0, QHeaderView::ResizeToContents);
      RuleTable->horizontalHeader()->setSectionResizeMode(1,
                                                          QHeaderView::Stretch);
      RuleTable->verticalHeader()->setDefaultSectionSize(KCompactTableRowHeight);
      RightLayout->addWidget(RuleTable, 1);
      auto *RuleActions = new QHBoxLayout;
      ConfigureToolbarLayout(RuleActions);
      AddRuleButton = MakeButton("Add Rule", true);
      RemoveRuleButton = MakeButton("Remove Rule");
      ConfigureActionButton(AddRuleButton, 110, KStandardButtonHeight);
      ConfigureActionButton(RemoveRuleButton, 118, KStandardButtonHeight);
      RuleActions->addWidget(AddRuleButton);
      RuleActions->addWidget(RemoveRuleButton);
      RuleActions->addStretch();
      RightLayout->addLayout(RuleActions);

      Body->addWidget(RightCard);
      Body->setStretchFactor(0, 0);
      Body->setStretchFactor(1, 5);
      Body->setStretchFactor(2, 3);

      SearchDebounceTimer = new QTimer(this);
      SearchDebounceTimer->setSingleShot(true);
      SearchDebounceTimer->setInterval(KSearchDebounceMs);
      RefreshTimer = new QTimer(this);
      RefreshTimer->setInterval(5000);

      LoadWatchRules();
      PopulateRuleTable();
      UpdateActionState();

      QObject::connect(ViewList, &QListWidget::currentRowChanged, Pages,
                       &QStackedWidget::setCurrentIndex);
      QObject::connect(Pages, &QStackedWidget::currentChanged, this,
                       [this] { UpdateDetailPanel(); UpdateActionState(); });
      QObject::connect(SearchDebounceTimer, &QTimer::timeout, this,
                       [this] { RebuildViews(); });
      QObject::connect(SearchEdit, &QLineEdit::textChanged, this,
                       [this] { SearchDebounceTimer->start(); });
      QObject::connect(TypeFilter, &ComboBox::currentTextChanged, this,
                       [this](const QString &) { RebuildViews(); });
      QObject::connect(PidFilter, &QLineEdit::textChanged, this,
                       [this](const QString &) { SearchDebounceTimer->start(); });
      QObject::connect(DangerousOnly, &QCheckBox::toggled, this,
                       [this](bool) { RebuildViews(); });
      QObject::connect(CrossOnly, &QCheckBox::toggled, this,
                       [this](bool) { RebuildViews(); });
      QObject::connect(AutoRefresh, &QCheckBox::toggled, this, [this](bool On) {
        SetConfigurationValue("HandleLab", "AutoRefresh", On);
        On ? RefreshTimer->start() : RefreshTimer->stop();
      });
      QObject::connect(RefreshTimer, &QTimer::timeout, this,
                       [this] { StartRefresh(false); });
      QObject::connect(RefreshButton, &QPushButton::clicked, this,
                       [this] { StartRefresh(true); });

      for (QTableWidget *Table :
           {HandleTable, ProcessTable, TypeTable, ObjectTable, WatchTable}) {
        QObject::connect(Table, &QTableWidget::itemSelectionChanged, this,
                         [this] { UpdateDetailPanel(); UpdateActionState(); });
      }
      QObject::connect(HandleTable, &QWidget::customContextMenuRequested, this,
                       [this](const QPoint &Pos) { ShowHandleMenu(HandleTable, Pos); });
      QObject::connect(WatchTable, &QWidget::customContextMenuRequested, this,
                       [this](const QPoint &Pos) { ShowHandleMenu(WatchTable, Pos); });
      QObject::connect(ProcessTable, &QTableWidget::itemDoubleClicked, this,
                       [this](QTableWidgetItem *) { PivotSelectionToHandles(); });
      QObject::connect(TypeTable, &QTableWidget::itemDoubleClicked, this,
                       [this](QTableWidgetItem *) { PivotSelectionToHandles(); });
      QObject::connect(ObjectTable, &QTableWidget::itemDoubleClicked, this,
                       [this](QTableWidgetItem *) { PivotSelectionToHandles(); });
      QObject::connect(ForceCloseButton, &QPushButton::clicked, this,
                       [this] { ExecuteSingleForceClose(); });
      QObject::connect(DowngradeButton, &QPushButton::clicked, this,
                       [this] { ExecuteSingleDowngrade(); });
      QObject::connect(DuplicateButton, &QPushButton::clicked, this,
                       [this] { ExecuteSingleDuplicate(); });
      QObject::connect(BatchForceCloseButton, &QPushButton::clicked, this,
                       [this] { ExecuteBatchForceClose(); });
      QObject::connect(BatchDowngradeButton, &QPushButton::clicked, this,
                       [this] { ExecuteBatchDowngrade(); });
      QObject::connect(PivotButton, &QPushButton::clicked, this,
                       [this] { PivotSelectionToHandles(); });
      QObject::connect(AddRuleButton, &QPushButton::clicked, this,
                       [this] { AddRule(); });
      QObject::connect(RemoveRuleButton, &QPushButton::clicked, this,
                       [this] { RemoveSelectedRule(); });

      const bool AutoRefreshEnabled =
          ConfigurationValue("HandleLab", "AutoRefresh", false).toBool();
      AutoRefresh->setChecked(AutoRefreshEnabled);
      if (AutoRefreshEnabled)
        RefreshTimer->start();

      StartRefresh(false);
    }

  private:
    static QString HexPtr(quint64 Value) {
      return QString("0x%1")
          .arg(Value, sizeof(quintptr) * 2, 16, QLatin1Char('0'))
          .toUpper();
    }

    static QString FormatHandleAttributes(quint32 Attributes) {
      QStringList Parts;
      if (Attributes & 0x1)
        Parts << "PROTECT_FROM_CLOSE";
      if (Attributes & 0x2)
        Parts << "INHERIT";
      const QString Raw = QString("0x%1").arg(Attributes, 0, 16).toUpper();
      return Parts.isEmpty() ? Raw : Raw + " | " + Parts.join(" | ");
    }

    static QString QueryProcessDisplayName(DWORD Pid,
                                           const QHash<DWORD, QString> &Names) {
      if (Names.contains(Pid))
        return Names.value(Pid);
      return QString("PID %1").arg(Pid);
    }

    static QHash<DWORD, QString> BuildProcessNameMap() {
      QHash<DWORD, QString> Names;
      HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
      if (Snapshot == INVALID_HANDLE_VALUE)
        return Names;
      PROCESSENTRY32W Entry{};
      Entry.dwSize = sizeof(Entry);
      if (Process32FirstW(Snapshot, &Entry)) {
        do {
          Names.insert(Entry.th32ProcessID,
                       QString::fromWCharArray(Entry.szExeFile));
        } while (Process32NextW(Snapshot, &Entry));
      }
      CloseHandle(Snapshot);
      return Names;
    }

    struct HandleAccessEntry {
      quint32 Mask = 0;
      const char *Name = nullptr;
    };

    static std::vector<HandleAccessEntry>
    HandleAccessEntriesForType(const QString &TypeName) {
      std::vector<HandleAccessEntry> Entries{
          {DELETE, "DELETE"},
          {READ_CONTROL, "READ_CONTROL"},
          {WRITE_DAC, "WRITE_DAC"},
          {WRITE_OWNER, "WRITE_OWNER"},
          {SYNCHRONIZE, "SYNCHRONIZE"},
          {ACCESS_SYSTEM_SECURITY, "ACCESS_SYSTEM_SECURITY"},
          {GENERIC_READ, "GENERIC_READ"},
          {GENERIC_WRITE, "GENERIC_WRITE"},
          {GENERIC_EXECUTE, "GENERIC_EXECUTE"},
          {GENERIC_ALL, "GENERIC_ALL"},
      };

      QString Type = TypeName.trimmed();
      if (Type.startsWith("Type ", Qt::CaseInsensitive))
        Type = Type.mid(5).trimmed();
      if (Type.contains('\\'))
        Type = Type.section('\\', -1).trimmed();
      if (Type.compare("Mutant", Qt::CaseInsensitive) == 0 ||
          Type.compare("Mutex", Qt::CaseInsensitive) == 0)
        Type = "Mutant";
      else if (Type.compare("Registry", Qt::CaseInsensitive) == 0 ||
               Type.compare("RegistryKey", Qt::CaseInsensitive) == 0)
        Type = "Key";
      if (Type.compare("Process", Qt::CaseInsensitive) == 0)
        Entries.insert(Entries.end(),
                       {{PROCESS_TERMINATE, "PROCESS_TERMINATE"},
                        {PROCESS_CREATE_THREAD, "PROCESS_CREATE_THREAD"},
                        {PROCESS_VM_OPERATION, "PROCESS_VM_OPERATION"},
                        {PROCESS_VM_READ, "PROCESS_VM_READ"},
                        {PROCESS_VM_WRITE, "PROCESS_VM_WRITE"},
                        {PROCESS_DUP_HANDLE, "PROCESS_DUP_HANDLE"},
                        {PROCESS_CREATE_PROCESS, "PROCESS_CREATE_PROCESS"},
                        {PROCESS_SET_INFORMATION, "PROCESS_SET_INFORMATION"},
                        {PROCESS_QUERY_INFORMATION, "PROCESS_QUERY_INFORMATION"},
                        {PROCESS_SUSPEND_RESUME, "PROCESS_SUSPEND_RESUME"},
                        {PROCESS_QUERY_LIMITED_INFORMATION,
                         "PROCESS_QUERY_LIMITED_INFORMATION"}});
      else if (Type.compare("Thread", Qt::CaseInsensitive) == 0)
        Entries.insert(Entries.end(),
                       {{THREAD_TERMINATE, "THREAD_TERMINATE"},
                        {THREAD_SUSPEND_RESUME, "THREAD_SUSPEND_RESUME"},
                        {THREAD_GET_CONTEXT, "THREAD_GET_CONTEXT"},
                        {THREAD_SET_CONTEXT, "THREAD_SET_CONTEXT"},
                        {THREAD_QUERY_INFORMATION, "THREAD_QUERY_INFORMATION"},
                        {THREAD_SET_INFORMATION, "THREAD_SET_INFORMATION"},
                        {THREAD_IMPERSONATE, "THREAD_IMPERSONATE"},
                        {THREAD_DIRECT_IMPERSONATION,
                         "THREAD_DIRECT_IMPERSONATION"},
                        {THREAD_QUERY_LIMITED_INFORMATION,
                         "THREAD_QUERY_LIMITED_INFORMATION"}});
      else if (Type.compare("Token", Qt::CaseInsensitive) == 0)
        Entries.insert(Entries.end(),
                       {{TOKEN_ASSIGN_PRIMARY, "TOKEN_ASSIGN_PRIMARY"},
                        {TOKEN_DUPLICATE, "TOKEN_DUPLICATE"},
                        {TOKEN_IMPERSONATE, "TOKEN_IMPERSONATE"},
                        {TOKEN_QUERY, "TOKEN_QUERY"},
                        {TOKEN_ADJUST_PRIVILEGES, "TOKEN_ADJUST_PRIVILEGES"},
                        {TOKEN_ADJUST_GROUPS, "TOKEN_ADJUST_GROUPS"},
                        {TOKEN_ADJUST_DEFAULT, "TOKEN_ADJUST_DEFAULT"},
                        {TOKEN_ADJUST_SESSIONID, "TOKEN_ADJUST_SESSIONID"}});
      else if (Type.compare("File", Qt::CaseInsensitive) == 0)
        Entries.insert(Entries.end(),
                       {{FILE_READ_DATA, "FILE_READ_DATA"},
                        {FILE_WRITE_DATA, "FILE_WRITE_DATA"},
                        {FILE_APPEND_DATA, "FILE_APPEND_DATA"},
                        {FILE_READ_ATTRIBUTES, "FILE_READ_ATTRIBUTES"},
                        {FILE_WRITE_ATTRIBUTES, "FILE_WRITE_ATTRIBUTES"}});
      else if (Type.compare("Key", Qt::CaseInsensitive) == 0)
        Entries.insert(Entries.end(),
                       {{KEY_QUERY_VALUE, "KEY_QUERY_VALUE"},
                        {KEY_SET_VALUE, "KEY_SET_VALUE"},
                        {KEY_CREATE_SUB_KEY, "KEY_CREATE_SUB_KEY"},
                        {KEY_ENUMERATE_SUB_KEYS, "KEY_ENUMERATE_SUB_KEYS"},
                        {KEY_NOTIFY, "KEY_NOTIFY"}});
      return Entries;
    }

    static QString FormatAccessMask(
        quint32 Mask,
        std::initializer_list<std::pair<quint32, const char *>> Entries) {
      QStringList Parts;
      quint32 Remaining = Mask;
      for (const auto &[Bit, Name] : Entries) {
        if ((Mask & Bit) == Bit) {
          Parts.append(QString::fromLatin1(Name));
          Remaining &= ~Bit;
        }
      }
      if (Remaining != 0)
        Parts.append(QString("0x%1").arg(Remaining, 0, 16).toUpper());
      return Parts.join(" | ");
    }

    static QString DescribeHandleAccess(const QString &TypeName, quint32 Mask) {
      QStringList Parts;
      const QString Generic = FormatAccessMask(
          Mask,
          {{DELETE, "DELETE"},
           {READ_CONTROL, "READ_CONTROL"},
           {WRITE_DAC, "WRITE_DAC"},
           {WRITE_OWNER, "WRITE_OWNER"},
           {SYNCHRONIZE, "SYNCHRONIZE"},
           {ACCESS_SYSTEM_SECURITY, "ACCESS_SYSTEM_SECURITY"},
           {GENERIC_READ, "GENERIC_READ"},
           {GENERIC_WRITE, "GENERIC_WRITE"},
           {GENERIC_EXECUTE, "GENERIC_EXECUTE"},
           {GENERIC_ALL, "GENERIC_ALL"}});
      if (!Generic.isEmpty())
        Parts.append(Generic);

      const auto Entries = HandleAccessEntriesForType(TypeName);
      QStringList TypeSpecific;
      quint32 Remaining = Mask;
      for (const auto &Entry : Entries) {
        if ((Mask & Entry.Mask) == Entry.Mask) {
          TypeSpecific.append(QString::fromLatin1(Entry.Name));
          Remaining &= ~Entry.Mask;
        }
      }
      if (!TypeSpecific.isEmpty())
        Parts.append(TypeSpecific.join(" | "));
      Parts.removeAll(QString());
      Parts.removeDuplicates();
      return Parts.join(" | ");
    }

    static QString FormatHandleAccessDisplay(const QString &TypeName,
                                             quint32 Mask) {
      const QString Decoded = DescribeHandleAccess(TypeName, Mask);
      const QString Raw = QString("0x%1").arg(Mask, 0, 16).toUpper();
      return Decoded.isEmpty() ? Raw : Raw + " | " + Decoded;
    }

    bool PromptHandleAccessMask(QWidget *Parent, const QString &TypeName,
                                quint32 CurrentAccess, quint32 &SelectedMask,
                                const QString &Title,
                                const QString &Description,
                                const QString &ApplyText = "Apply") {
      QDialog Dialog(Parent);
      Dialog.setWindowTitle(Title);
      Dialog.setModal(true);
      Dialog.resize(520, 280);

      auto *Layout = new QVBoxLayout(&Dialog);
      Layout->setContentsMargins(20, 18, 20, 18);
      Layout->setSpacing(10);

      auto *Desc = MakeLabel(Description, 11, KTextMuted);
      Desc->setWordWrap(true);
      auto *AccessCombo = new MultiViewComboBox;
      AccessCombo->setPlaceholderText("Select handle permissions");
      AccessCombo->setMaxVisibleItems(12);
      AccessCombo->setMinimumHeight(36);
      const auto Entries = HandleAccessEntriesForType(TypeName);
      for (const auto &Entry : Entries) {
        const int Index = AccessCombo->count();
        AccessCombo->addItem(QString::fromLatin1(Entry.Name),
                             QVariant::fromValue<quint32>(Entry.Mask));
        AccessCombo->setItemSelected(Index,
                                     (CurrentAccess & Entry.Mask) == Entry.Mask);
      }

      auto *Preview = new BodyLabel;
      Preview->setWordWrap(true);
      auto UpdatePreview = [Preview, AccessCombo, TypeName]() {
        quint32 Mask = 0;
        for (const QVariant &Data : AccessCombo->selectedDatas())
          Mask |= Data.toUInt();
        Preview->setText("Access: " + FormatHandleAccessDisplay(TypeName, Mask));
      };
      QObject::connect(AccessCombo, &MultiViewComboBox::selectionChanged,
                       &Dialog, UpdatePreview);
      UpdatePreview();

      auto *Buttons = new QHBoxLayout;
      ConfigureToolbarLayout(Buttons);
      Buttons->addStretch();
      auto *Cancel = MakeButton("Cancel");
      auto *Apply = MakeButton(ApplyText, true);
      Buttons->addWidget(Cancel);
      Buttons->addWidget(Apply);

      Layout->addWidget(Desc);
      Layout->addWidget(AccessCombo);
      Layout->addWidget(Preview);
      Layout->addStretch();
      Layout->addLayout(Buttons);

      QObject::connect(Cancel, &QPushButton::clicked, &Dialog,
                       &QDialog::reject);
      QObject::connect(Apply, &QPushButton::clicked, &Dialog,
                       &QDialog::accept);

      if (Dialog.exec() != QDialog::Accepted)
        return false;

      SelectedMask = 0;
      for (const QVariant &Data : AccessCombo->selectedDatas())
        SelectedMask |= Data.toUInt();
      return true;
    }

    static bool IsNtQueryObjectResizeStatus(NTSTATUS Status) {
      constexpr NTSTATUS KStatusInfoLengthMismatch =
          static_cast<NTSTATUS>(0xC0000004L);
      constexpr NTSTATUS KStatusBufferOverflow =
          static_cast<NTSTATUS>(0x80000005L);
      constexpr NTSTATUS KStatusBufferTooSmall =
          static_cast<NTSTATUS>(0xC0000023L);
      return Status == KStatusInfoLengthMismatch ||
             Status == KStatusBufferOverflow ||
             Status == KStatusBufferTooSmall;
    }

    static bool QueryObjectInformationBuffer(HANDLE Handle,
                                             OBJECT_INFORMATION_CLASS InfoClass,
                                             std::vector<BYTE> &Buffer) {
      using NtQueryObjectFn = NTSTATUS(NTAPI *)(HANDLE, OBJECT_INFORMATION_CLASS,
                                                PVOID, ULONG, PULONG);
      static const auto QueryObject = reinterpret_cast<NtQueryObjectFn>(
          GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject"));
      if (!QueryObject || !Handle)
        return false;

      ULONG Size = 0x200;
      ULONG ReturnLength = 0;
      Buffer.resize(Size);
      for (int Attempt = 0; Attempt < 8; ++Attempt) {
        const NTSTATUS Status =
            QueryObject(Handle, InfoClass, Buffer.data(), Size, &ReturnLength);
        if (Status >= 0) {
          if (ReturnLength != 0 && ReturnLength <= Size)
            Buffer.resize(ReturnLength);
          return true;
        }
        if (!IsNtQueryObjectResizeStatus(Status))
          return false;
        Size = std::max<ULONG>(ReturnLength > Size ? ReturnLength + 0x100
                                                   : Size * 2,
                               0x200);
        Buffer.resize(Size);
      }
      return false;
    }

    static QString QueryObjectTypeName(HANDLE Handle) {
      constexpr auto KObjectTypeInformationClass =
          static_cast<OBJECT_INFORMATION_CLASS>(2);
      std::vector<BYTE> Buffer;
      if (!QueryObjectInformationBuffer(Handle, KObjectTypeInformationClass,
                                        Buffer) ||
          Buffer.size() < sizeof(UNICODE_STRING))
        return {};
      const auto *Type = reinterpret_cast<const UNICODE_STRING *>(Buffer.data());
      if (!Type->Buffer || Type->Length == 0)
        return {};
      return QString::fromWCharArray(Type->Buffer, Type->Length / sizeof(WCHAR));
    }

    static QString QueryObjectName(HANDLE Handle) {
      constexpr auto KObjectNameInformationClass =
          static_cast<OBJECT_INFORMATION_CLASS>(1);
      std::vector<BYTE> Buffer;
      if (!QueryObjectInformationBuffer(Handle, KObjectNameInformationClass,
                                        Buffer) ||
          Buffer.size() < sizeof(UNICODE_STRING))
        return {};
      const auto *Name = reinterpret_cast<const UNICODE_STRING *>(Buffer.data());
      if (!Name->Buffer || Name->Length == 0)
        return {};
      return QString::fromWCharArray(Name->Buffer, Name->Length / sizeof(WCHAR));
    }

    static bool IsQueryNameType(const QString &TypeName) {
      return TypeName.compare("File", Qt::CaseInsensitive) == 0 ||
             TypeName.compare("Key", Qt::CaseInsensitive) == 0 ||
             TypeName.compare("Directory", Qt::CaseInsensitive) == 0 ||
             TypeName.compare("SymbolicLink", Qt::CaseInsensitive) == 0 ||
             TypeName.compare("Section", Qt::CaseInsensitive) == 0 ||
             TypeName.compare("Event", Qt::CaseInsensitive) == 0 ||
             TypeName.compare("Mutant", Qt::CaseInsensitive) == 0 ||
             TypeName.compare("Process", Qt::CaseInsensitive) == 0 ||
             TypeName.compare("Thread", Qt::CaseInsensitive) == 0 ||
             TypeName.compare("Desktop", Qt::CaseInsensitive) == 0 ||
             TypeName.compare("WindowStation", Qt::CaseInsensitive) == 0 ||
             TypeName.compare("Semaphore", Qt::CaseInsensitive) == 0;
    }

    static bool QuerySystemHandleBuffer(std::vector<BYTE> &Buffer,
                                        DWORD &ErrorCode) {
      using NtQuerySystemInformationFn =
          NTSTATUS(NTAPI *)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
      constexpr auto KSystemExtendedHandleInformationClass =
          static_cast<SYSTEM_INFORMATION_CLASS>(64);
      constexpr NTSTATUS KStatusInfoLengthMismatch =
          static_cast<NTSTATUS>(0xC0000004L);
      static const auto QuerySystemInformation =
          reinterpret_cast<NtQuerySystemInformationFn>(GetProcAddress(
              GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
      if (!QuerySystemInformation) {
        ErrorCode = ERROR_PROC_NOT_FOUND;
        return false;
      }

      ULONG Size = 1 << 20;
      Buffer.resize(Size);
      NTSTATUS Status = KStatusInfoLengthMismatch;
      ULONG ReturnLength = 0;
      while (Status == KStatusInfoLengthMismatch) {
        Status = QuerySystemInformation(KSystemExtendedHandleInformationClass,
                                        Buffer.data(), Size, &ReturnLength);
        if (Status == KStatusInfoLengthMismatch) {
          Size = std::max(Size * 2, ReturnLength + 0x1000u);
          Buffer.resize(Size);
        }
      }
      if (Status < 0) {
        ErrorCode = RtlNtStatusToDosError(Status);
        return false;
      }
      ErrorCode = ERROR_SUCCESS;
      return true;
    }

    static QString RiskSummary(bool Dangerous, bool CrossProcess,
                               bool Watchlisted) {
      QStringList Parts;
      if (Dangerous)
        Parts << "Danger";
      if (CrossProcess)
        Parts << "Cross";
      if (Watchlisted)
        Parts << "Watch";
      return Parts.isEmpty() ? "Normal" : Parts.join(" | ");
    }

    static bool IsDangerousMask(const QString &TypeName, quint32 Mask) {
      const QString Type = TypeName.trimmed();
      if (Type.compare("Process", Qt::CaseInsensitive) == 0)
        return (Mask & PROCESS_VM_WRITE) != 0 ||
               (Mask & PROCESS_CREATE_THREAD) != 0 ||
               (Mask & PROCESS_DUP_HANDLE) != 0 ||
               (Mask & PROCESS_TERMINATE) != 0;
      if (Type.compare("Thread", Qt::CaseInsensitive) == 0)
        return (Mask & THREAD_SET_CONTEXT) != 0 ||
               (Mask & THREAD_SUSPEND_RESUME) != 0 ||
               (Mask & THREAD_TERMINATE) != 0;
      if (Type.compare("Token", Qt::CaseInsensitive) == 0)
        return (Mask & TOKEN_DUPLICATE) != 0 ||
               (Mask & TOKEN_IMPERSONATE) != 0 ||
               (Mask & TOKEN_ASSIGN_PRIMARY) != 0;
      if (Type.compare("Section", Qt::CaseInsensitive) == 0)
        return (Mask & SECTION_MAP_WRITE) != 0 ||
               (Mask & SECTION_MAP_EXECUTE) != 0;
      if (Type.compare("File", Qt::CaseInsensitive) == 0)
        return (Mask & FILE_WRITE_DATA) != 0 ||
               (Mask & FILE_APPEND_DATA) != 0;
      if (Type.compare("Key", Qt::CaseInsensitive) == 0)
        return (Mask & KEY_SET_VALUE) != 0 ||
               (Mask & KEY_CREATE_SUB_KEY) != 0;
      return false;
    }

    static QString BuildHandleSearchText(const HandleEntryRow &Row) {
      return (QString::number(Row.OwnerPid) + ' ' + Row.OwnerName + ' ' +
              HexPtr(Row.HandleValue) + ' ' + HexPtr(Row.ObjectAddress) + ' ' +
              Row.TypeName + ' ' + Row.ObjectName + ' ' + Row.AccessDisplay +
              ' ' + QString::number(Row.TargetPid) + ' ' +
              QString::number(Row.TargetTid) + ' ' + Row.TargetName + ' ' +
              Row.RiskText + ' ' + Row.MatchedRules)
          .toCaseFolded();
    }

    void RefreshDerivedFields(HandleEntryRow &Row) const {
      Row.AccessDisplay =
          FormatHandleAccessDisplay(Row.TypeName, Row.GrantedAccess);
      Row.Dangerous = IsDangerousMask(Row.TypeName, Row.GrantedAccess);
      Row.CrossProcess =
          (Row.TypeName.compare("Process", Qt::CaseInsensitive) == 0 ||
           Row.TypeName.compare("Thread", Qt::CaseInsensitive) == 0) &&
          Row.TargetPid != 0 && Row.TargetPid != Row.OwnerPid;
      QStringList MatchedRuleTexts;
      for (const WatchRule &Rule : WatchRules) {
        if (MatchesWatchRule(Row, Rule))
          MatchedRuleTexts.append(Rule.Kind + ":" + Rule.Value);
      }
      Row.Watchlisted = !MatchedRuleTexts.isEmpty();
      Row.MatchedRules = MatchedRuleTexts.join(" | ");
      Row.RiskText =
          RiskSummary(Row.Dangerous, Row.CrossProcess, Row.Watchlisted);
      Row.SearchText = BuildHandleSearchText(Row);
    }

    bool ResolveHandleIdentity(HandleEntryRow &Row,
                               const QHash<DWORD, QString> &Names) const {
      HANDLE Process =
          OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
                      FALSE, Row.OwnerPid);
      if (Process == nullptr)
        return false;
      HANDLE Duplicate = nullptr;
      const bool Success =
          DuplicateHandle(Process, reinterpret_cast<HANDLE>(Row.HandleValue),
                          GetCurrentProcess(), &Duplicate, 0, FALSE,
                          DUPLICATE_SAME_ACCESS) != FALSE;
      CloseHandle(Process);
      if (!Success || Duplicate == nullptr)
        return false;

      Row.TypeName = QueryObjectTypeName(Duplicate);
      if (IsQueryNameType(Row.TypeName))
        Row.ObjectName = QueryObjectName(Duplicate);
      if (Row.TypeName.compare("Process", Qt::CaseInsensitive) == 0) {
        Row.TargetPid = GetProcessId(Duplicate);
        Row.TargetName = QueryProcessDisplayName(Row.TargetPid, Names);
      } else if (Row.TypeName.compare("Thread", Qt::CaseInsensitive) == 0) {
        Row.TargetTid = GetThreadId(Duplicate);
        Row.TargetPid = GetProcessIdOfThread(Duplicate);
        Row.TargetName = QueryProcessDisplayName(Row.TargetPid, Names);
      }
      CloseHandle(Duplicate);
      RefreshDerivedFields(Row);
      return true;
    }

    bool MatchesWatchRule(const HandleEntryRow &Row, const WatchRule &Rule) const {
      const QString Value = Rule.Value.trimmed();
      if (Value.isEmpty())
        return false;
      if (Rule.Kind == "type")
        return Row.TypeName.contains(Value, Qt::CaseInsensitive);
      if (Rule.Kind == "name")
        return Row.ObjectName.contains(Value, Qt::CaseInsensitive) ||
               Row.OwnerName.contains(Value, Qt::CaseInsensitive) ||
               Row.TargetName.contains(Value, Qt::CaseInsensitive);
      if (Rule.Kind == "access")
        return Row.AccessDisplay.contains(Value, Qt::CaseInsensitive);
      if (Rule.Kind == "pid")
        return QString::number(Row.OwnerPid) == Value ||
               (Row.TargetPid != 0 && QString::number(Row.TargetPid) == Value);
      return false;
    }

    void ConfigureHandleTable(TableWidget *Table) {
      Table->horizontalHeader()->setSectionResizeMode(
          0, QHeaderView::ResizeToContents);
      Table->horizontalHeader()->setSectionResizeMode(
          1, QHeaderView::ResizeToContents);
      Table->horizontalHeader()->setSectionResizeMode(
          2, QHeaderView::ResizeToContents);
      Table->horizontalHeader()->setSectionResizeMode(
          3, QHeaderView::ResizeToContents);
      Table->horizontalHeader()->setSectionResizeMode(
          4, QHeaderView::ResizeToContents);
      Table->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
      Table->horizontalHeader()->setSectionResizeMode(
          6, QHeaderView::ResizeToContents);
      Table->horizontalHeader()->setSectionResizeMode(
          7, QHeaderView::ResizeToContents);
      Table->horizontalHeader()->setSectionResizeMode(8, QHeaderView::Stretch);
      Table->verticalHeader()->setDefaultSectionSize(KCompactTableRowHeight);
    }

    void ConfigureAggregateTable(TableWidget *Table, int StretchColumn) {
      for (int Column = 0; Column < Table->columnCount(); ++Column)
        Table->horizontalHeader()->setSectionResizeMode(
            Column, Column == StretchColumn ? QHeaderView::Stretch
                                            : QHeaderView::ResizeToContents);
      Table->verticalHeader()->setDefaultSectionSize(KCompactTableRowHeight);
    }

    void LoadWatchRules() {
      WatchRules.clear();
      const QJsonArray Array =
          ConfigurationValue("HandleLab", "WatchRules", QJsonArray()).toArray();
      for (const QJsonValue &Value : Array) {
        const QString Text = Value.toString().trimmed();
        const int Split = Text.indexOf(':');
        if (Split <= 0)
          continue;
        WatchRules.push_back(
            {Text.left(Split).trimmed().toCaseFolded(),
             Text.mid(Split + 1).trimmed()});
      }
    }

    void SaveWatchRules() {
      QJsonArray Array;
      for (const WatchRule &Rule : WatchRules)
        Array.append(Rule.Kind + ":" + Rule.Value);
      SetConfigurationValue("HandleLab", "WatchRules", Array);
    }

    void PopulateRuleTable() {
      SetTableRefreshEnabled(RuleTable, false);
      RuleTable->clearContents();
      RuleTable->setRowCount(static_cast<int>(WatchRules.size()));
      for (int Row = 0; Row < static_cast<int>(WatchRules.size()); ++Row) {
        const WatchRule &Rule = WatchRules[static_cast<size_t>(Row)];
        RuleTable->setItem(Row, 0, new QTableWidgetItem(Rule.Kind));
        RuleTable->setItem(Row, 1, new QTableWidgetItem(Rule.Value));
        RuleTable->setRowHeight(Row, KCompactTableRowHeight);
      }
      SetTableRefreshEnabled(RuleTable, true);
    }

    void ConsumePendingPreset() {
      AegisNT::AppContext &Context = AegisNT::ApplicationContext();
      if (!Context.HandleLabPresetSearch.isEmpty()) {
        SearchEdit->setText(Context.HandleLabPresetSearch);
        Context.HandleLabPresetSearch.clear();
      }
      if (Context.HandleLabPresetPid != 0) {
        PidFilter->setText(QString::number(Context.HandleLabPresetPid));
        Context.HandleLabPresetPid = 0;
      }
      ViewList->setCurrentRow(0);
    }

    void StartRefresh(bool ShowResult) {
      if (Refreshing.exchange(true))
        return;
      const quint64 RefreshId = ++RefreshGeneration;
      SetRefreshUiState(RefreshButton, RefreshIndicator, StatusLabel, true,
                        "Refresh", "Refreshing...", QString(),
                        "Enumerating system handles...");
      QPointer<HandleLabPage> SafeThis(this);
      std::thread([SafeThis, ShowResult, RefreshId] {
        RefreshResult Result;
        Result.Success = SafeThis ? SafeThis->QuerySystemHandles(Result.Rows,
                                                                 Result.ErrorCode)
                                  : false;
        QMetaObject::invokeMethod(
            qApp,
            [SafeThis, ShowResult, RefreshId, Result = std::move(Result)]() mutable {
              if (!SafeThis)
                return;
              if (RefreshId != SafeThis->RefreshGeneration.load())
                return;
              SafeThis->Refreshing = false;
              SetRefreshUiState(SafeThis->RefreshButton,
                                SafeThis->RefreshIndicator,
                                SafeThis->StatusLabel, false);
              if (!Result.Success) {
                const QString Message =
                    QString("Handle enumeration failed (error %1).")
                        .arg(Result.ErrorCode);
                SafeThis->StatusLabel->setText(Message);
                if (ShowResult)
                  ShowErrorNotice(SafeThis, "HandleLab", Message);
                return;
              }
              SafeThis->AllRows = std::move(Result.Rows);
              SafeThis->ConsumePendingPreset();
              SafeThis->PopulateTypeFilter();
              SafeThis->RebuildViews();
              SafeThis->StatusLabel->setText(
                  QString("%1 handle(s) loaded. Resolving details in background...")
                      .arg(SafeThis->AllRows.size()));
              SafeThis->StartBackgroundEnrichment(RefreshId);
              if (ShowResult)
                ShowSuccessNotice(SafeThis, "HandleLab",
                                  QString("Enumerated %1 handle(s).")
                                      .arg(SafeThis->AllRows.size()));
            },
            Qt::QueuedConnection);
      }).detach();
    }

    void StartBackgroundEnrichment(quint64 RefreshId) {
      if (Enriching.exchange(true))
        return;
      QPointer<HandleLabPage> SafeThis(this);
      const std::vector<HandleEntryRow> SnapshotRows = AllRows;
      const std::vector<WatchRule> SnapshotRules = WatchRules;
      std::thread([SafeThis, RefreshId, SnapshotRows, SnapshotRules] {
        if (!SafeThis)
          return;
        const QHash<DWORD, QString> Names = BuildProcessNameMap();
        std::vector<HandleEntryRow> Enriched = SnapshotRows;
        HandleLabPage *Page = SafeThis.data();
        if (!Page)
          return;
        for (HandleEntryRow &Row : Enriched) {
          if (RefreshId != Page->RefreshGeneration.load())
            return;
          Page->ResolveHandleIdentity(Row, Names);
        }
        QMetaObject::invokeMethod(
            qApp,
            [SafeThis, RefreshId, Enriched = std::move(Enriched),
             SnapshotRules]() mutable {
              if (!SafeThis)
                return;
              SafeThis->Enriching = false;
              if (RefreshId != SafeThis->RefreshGeneration.load())
                return;
              SafeThis->WatchRules = SnapshotRules;
              SafeThis->AllRows = std::move(Enriched);
              SafeThis->PopulateTypeFilter();
              SafeThis->RebuildViews();
              SafeThis->StatusLabel->setText(
                  QString("%1 handle(s) loaded. Details resolved.")
                      .arg(SafeThis->AllRows.size()));
            },
            Qt::QueuedConnection);
      }).detach();
    }

    bool QuerySystemHandles(std::vector<HandleEntryRow> &Rows,
                            DWORD &ErrorCode) const {
      std::vector<BYTE> Buffer;
      if (!QuerySystemHandleBuffer(Buffer, ErrorCode))
        return false;
      const auto Names = BuildProcessNameMap();
      const auto *Handles =
          reinterpret_cast<const SystemHandleInfo *>(Buffer.data());

      Rows.clear();
      Rows.reserve(static_cast<size_t>(Handles->NumberOfHandles));

      for (ULONG_PTR Index = 0; Index < Handles->NumberOfHandles; ++Index) {
        const auto &Entry = Handles->Handles[Index];
        const DWORD OwnerPid = static_cast<DWORD>(Entry.UniqueProcessId);
        HandleEntryRow Row;
        Row.OwnerPid = OwnerPid;
        Row.OwnerName = QueryProcessDisplayName(OwnerPid, Names);
        Row.HandleValue = static_cast<quint64>(Entry.HandleValue);
        Row.ObjectAddress = reinterpret_cast<quint64>(Entry.Object);
        Row.GrantedAccess = Entry.GrantedAccess;
        Row.Attributes = Entry.HandleAttributes;
        Row.AccessDisplay = QString("0x%1").arg(Row.GrantedAccess, 0, 16).toUpper();
        Row.RiskText = "Pending";
        Row.SearchText = BuildHandleSearchText(Row);
        Rows.push_back(std::move(Row));
      }
      ErrorCode = ERROR_SUCCESS;
      return true;
    }

    void PopulateTypeFilter() {
      const QString Previous = TypeFilter->currentText();
      QSignalBlocker Blocker(TypeFilter);
      TypeFilter->clear();
      TypeFilter->addItem("All Types");
      QSet<QString> Types;
      for (const HandleEntryRow &Row : AllRows) {
        if (!Row.TypeName.isEmpty())
          Types.insert(Row.TypeName);
      }
      QStringList SortedTypes = Types.values();
      std::sort(SortedTypes.begin(), SortedTypes.end(),
                [](const QString &Left, const QString &Right) {
                  return Left.compare(Right, Qt::CaseInsensitive) < 0;
                });
      for (const QString &Type : SortedTypes)
        TypeFilter->addItem(Type);
      const int Index = TypeFilter->findText(Previous);
      TypeFilter->setCurrentIndex(Index >= 0 ? Index : 0);
    }

    bool MatchesFilters(const HandleEntryRow &Row) const {
      const QString Query = SearchEdit->text().trimmed().toCaseFolded();
      if (!Query.isEmpty() && !Row.SearchText.contains(Query))
        return false;
      const QString TypeValue = TypeFilter->currentText();
      if (TypeValue != "All Types" &&
          Row.TypeName.compare(TypeValue, Qt::CaseInsensitive) != 0)
        return false;
      const QString PidText = PidFilter->text().trimmed();
      if (!PidText.isEmpty()) {
        bool Ok = false;
        const DWORD PidValue = PidText.toUInt(&Ok, 0);
        if (!Ok || (Row.OwnerPid != PidValue && Row.TargetPid != PidValue))
          return false;
      }
      if (DangerousOnly->isChecked() && !Row.Dangerous)
        return false;
      if (CrossOnly->isChecked() && !Row.CrossProcess)
        return false;
      return true;
    }

    void RebuildViews() {
      FilteredIndices.clear();
      WatchIndices.clear();
      ProcessRows.clear();
      TypeRows.clear();
      ObjectRows.clear();

      for (int Index = 0; Index < static_cast<int>(AllRows.size()); ++Index) {
        if (!MatchesFilters(AllRows[static_cast<size_t>(Index)]))
          continue;
        FilteredIndices.push_back(Index);
        if (AllRows[static_cast<size_t>(Index)].Watchlisted)
          WatchIndices.push_back(Index);
      }

      std::map<DWORD, ProcessAggregateRow> ProcessMap;
      std::map<QString, TypeAggregateRow> TypeMap;
      struct ObjectAccumulator {
        ObjectAggregateRow Row;
        QSet<DWORD> Pids;
      };
      std::map<quint64, ObjectAccumulator> ObjectMap;

      for (const int Index : FilteredIndices) {
        const HandleEntryRow &Row = AllRows[static_cast<size_t>(Index)];
        ProcessAggregateRow &Process = ProcessMap[Row.OwnerPid];
        Process.OwnerPid = Row.OwnerPid;
        Process.OwnerName = Row.OwnerName;
        ++Process.HandleCount;
        Process.DangerousCount += Row.Dangerous ? 1 : 0;
        Process.CrossCount += Row.CrossProcess ? 1 : 0;
        Process.WatchCount += Row.Watchlisted ? 1 : 0;

        TypeAggregateRow &Type = TypeMap[Row.TypeName];
        Type.TypeName = Row.TypeName.isEmpty() ? "(unknown)" : Row.TypeName;
        ++Type.HandleCount;
        Type.DangerousCount += Row.Dangerous ? 1 : 0;
        Type.CrossCount += Row.CrossProcess ? 1 : 0;
        Type.WatchCount += Row.Watchlisted ? 1 : 0;

        ObjectAccumulator &Object = ObjectMap[Row.ObjectAddress];
        Object.Row.ObjectAddress = Row.ObjectAddress;
        if (Object.Row.ObjectName.isEmpty())
          Object.Row.ObjectName = Row.ObjectName;
        if (Object.Row.TypeName.isEmpty())
          Object.Row.TypeName = Row.TypeName;
        ++Object.Row.HandleCount;
        Object.Row.DangerousCount += Row.Dangerous ? 1 : 0;
        Object.Pids.insert(Row.OwnerPid);
      }

      for (auto &[Pid, Process] : ProcessMap)
        ProcessRows.push_back(Process);
      for (auto &[Type, Row] : TypeMap)
        TypeRows.push_back(Row);
      for (auto &[Address, Object] : ObjectMap) {
        Object.Row.ProcessCount = Object.Pids.size();
        ObjectRows.push_back(Object.Row);
      }

      std::sort(ProcessRows.begin(), ProcessRows.end(),
                [](const ProcessAggregateRow &Left,
                   const ProcessAggregateRow &Right) {
                  if (Left.DangerousCount != Right.DangerousCount)
                    return Left.DangerousCount > Right.DangerousCount;
                  return Left.HandleCount > Right.HandleCount;
                });
      std::sort(TypeRows.begin(), TypeRows.end(),
                [](const TypeAggregateRow &Left,
                   const TypeAggregateRow &Right) {
                  if (Left.DangerousCount != Right.DangerousCount)
                    return Left.DangerousCount > Right.DangerousCount;
                  return Left.HandleCount > Right.HandleCount;
                });
      std::sort(ObjectRows.begin(), ObjectRows.end(),
                [](const ObjectAggregateRow &Left,
                   const ObjectAggregateRow &Right) {
                  if (Left.ProcessCount != Right.ProcessCount)
                    return Left.ProcessCount > Right.ProcessCount;
                  return Left.HandleCount > Right.HandleCount;
                });

      PopulateHandleTable(HandleTable, FilteredIndices, false);
      PopulateProcessTable();
      PopulateTypeTable();
      PopulateObjectTable();
      PopulateHandleTable(WatchTable, WatchIndices, true);
      UpdateDetailPanel();
      UpdateActionState();
    }

    void PopulateHandleTable(TableWidget *Table, const std::vector<int> &Indices,
                             bool WatchView) {
      SetTableRefreshEnabled(Table, false);
      Table->clearContents();
      Table->setRowCount(static_cast<int>(Indices.size()));
      for (int RowIndex = 0; RowIndex < static_cast<int>(Indices.size());
           ++RowIndex) {
        const HandleEntryRow &Row =
            AllRows[static_cast<size_t>(Indices[static_cast<size_t>(RowIndex)])];
        auto *PidItem = new QTableWidgetItem(QString::number(Row.OwnerPid));
        PidItem->setData(Qt::UserRole,
                         Indices[static_cast<size_t>(RowIndex)]);
        Table->setItem(RowIndex, 0, PidItem);
        Table->setItem(RowIndex, 1, new QTableWidgetItem(Row.OwnerName));
        Table->setItem(RowIndex, 2, new QTableWidgetItem(HexPtr(Row.HandleValue)));
        Table->setItem(RowIndex, 3,
                       new QTableWidgetItem(HexPtr(Row.ObjectAddress)));
        Table->setItem(RowIndex, 4, new QTableWidgetItem(Row.TypeName));
        Table->setItem(RowIndex, 5, new QTableWidgetItem(Row.AccessDisplay));
        if (WatchView)
          Table->setItem(RowIndex, 6, new QTableWidgetItem(Row.MatchedRules));
        else
          Table->setItem(RowIndex, 6,
                         new QTableWidgetItem(
                             FormatHandleAttributes(Row.Attributes)));
        const QString TargetText =
            Row.TargetPid != 0
                ? QString("%1 (%2)")
                      .arg(Row.TargetPid)
                      .arg(Row.TargetName.isEmpty() ? "-" : Row.TargetName)
                : (Row.TargetTid != 0 ? QString("TID %1").arg(Row.TargetTid) : "-");
        Table->setItem(RowIndex, 7, new QTableWidgetItem(TargetText));
        Table->setItem(RowIndex, 8, new QTableWidgetItem(Row.RiskText));
        Table->setRowHeight(RowIndex, KCompactTableRowHeight);
      }
      SetTableRefreshEnabled(Table, true);
    }

    void PopulateProcessTable() {
      SetTableRefreshEnabled(ProcessTable, false);
      ProcessTable->clearContents();
      ProcessTable->setRowCount(static_cast<int>(ProcessRows.size()));
      for (int Row = 0; Row < static_cast<int>(ProcessRows.size()); ++Row) {
        const auto &Item = ProcessRows[static_cast<size_t>(Row)];
        auto *PidItem = new QTableWidgetItem(QString::number(Item.OwnerPid));
        PidItem->setData(Qt::UserRole,
                         QVariant::fromValue<quint32>(Item.OwnerPid));
        ProcessTable->setItem(Row, 0, PidItem);
        ProcessTable->setItem(Row, 1, new QTableWidgetItem(Item.OwnerName));
        ProcessTable->setItem(Row, 2,
                              new QTableWidgetItem(QString::number(Item.HandleCount)));
        ProcessTable->setItem(
            Row, 3, new QTableWidgetItem(QString::number(Item.DangerousCount)));
        ProcessTable->setItem(Row, 4,
                              new QTableWidgetItem(QString::number(Item.CrossCount)));
        ProcessTable->setItem(Row, 5,
                              new QTableWidgetItem(QString::number(Item.WatchCount)));
        ProcessTable->setRowHeight(Row, KCompactTableRowHeight);
      }
      SetTableRefreshEnabled(ProcessTable, true);
    }

    void PopulateTypeTable() {
      SetTableRefreshEnabled(TypeTable, false);
      TypeTable->clearContents();
      TypeTable->setRowCount(static_cast<int>(TypeRows.size()));
      for (int Row = 0; Row < static_cast<int>(TypeRows.size()); ++Row) {
        const auto &Item = TypeRows[static_cast<size_t>(Row)];
        auto *TypeItem = new QTableWidgetItem(Item.TypeName);
        TypeItem->setData(Qt::UserRole, Item.TypeName);
        TypeTable->setItem(Row, 0, TypeItem);
        TypeTable->setItem(Row, 1,
                           new QTableWidgetItem(QString::number(Item.HandleCount)));
        TypeTable->setItem(
            Row, 2, new QTableWidgetItem(QString::number(Item.DangerousCount)));
        TypeTable->setItem(Row, 3,
                           new QTableWidgetItem(QString::number(Item.CrossCount)));
        TypeTable->setItem(Row, 4,
                           new QTableWidgetItem(QString::number(Item.WatchCount)));
        TypeTable->setRowHeight(Row, KCompactTableRowHeight);
      }
      SetTableRefreshEnabled(TypeTable, true);
    }

    void PopulateObjectTable() {
      SetTableRefreshEnabled(ObjectTable, false);
      ObjectTable->clearContents();
      ObjectTable->setRowCount(static_cast<int>(ObjectRows.size()));
      for (int Row = 0; Row < static_cast<int>(ObjectRows.size()); ++Row) {
        const auto &Item = ObjectRows[static_cast<size_t>(Row)];
        auto *ObjectItem = new QTableWidgetItem(HexPtr(Item.ObjectAddress));
        ObjectItem->setData(Qt::UserRole,
                            QVariant::fromValue<qulonglong>(Item.ObjectAddress));
        ObjectTable->setItem(Row, 0, ObjectItem);
        ObjectTable->setItem(Row, 1, new QTableWidgetItem(Item.ObjectName));
        ObjectTable->setItem(Row, 2, new QTableWidgetItem(Item.TypeName));
        ObjectTable->setItem(
            Row, 3, new QTableWidgetItem(QString::number(Item.HandleCount)));
        ObjectTable->setItem(
            Row, 4, new QTableWidgetItem(QString::number(Item.ProcessCount)));
        ObjectTable->setItem(
            Row, 5, new QTableWidgetItem(QString::number(Item.DangerousCount)));
        ObjectTable->setRowHeight(Row, KCompactTableRowHeight);
      }
      SetTableRefreshEnabled(ObjectTable, true);
    }

    QList<int> CurrentHandleSelection() const {
      QTableWidget *Table = nullptr;
      if (Pages->currentIndex() == 0)
        Table = HandleTable;
      else if (Pages->currentIndex() == 4)
        Table = WatchTable;
      if (Table == nullptr)
        return {};
      QList<int> Result;
      const QModelIndexList Selected = Table->selectionModel()->selectedRows(0);
      for (const QModelIndex &Index : Selected) {
        const QTableWidgetItem *Item = Table->item(Index.row(), 0);
        if (!Item)
          continue;
        Result.append(Item->data(Qt::UserRole).toInt());
      }
      return Result;
    }

    std::optional<HandleEntryRow> CurrentSingleHandle() const {
      const QList<int> Selection = CurrentHandleSelection();
      if (Selection.size() != 1)
        return std::nullopt;
      return AllRows[static_cast<size_t>(Selection.first())];
    }

    void UpdateActionState() {
      const bool HandleView = Pages->currentIndex() == 0 || Pages->currentIndex() == 4;
      const int HandleSelectionCount = CurrentHandleSelection().size();
      const bool SingleHandle = HandleSelectionCount == 1;
      ForceCloseButton->setEnabled(SingleHandle);
      DowngradeButton->setEnabled(SingleHandle);
      DuplicateButton->setEnabled(SingleHandle);
      BatchForceCloseButton->setEnabled(HandleView && HandleSelectionCount > 0);
      BatchDowngradeButton->setEnabled(HandleView && HandleSelectionCount > 0);
      PivotButton->setEnabled(Pages->currentIndex() >= 1 && Pages->currentIndex() <= 3);
      RemoveRuleButton->setEnabled(RuleTable->currentRow() >= 0);
    }

    void UpdateDetailPanel() {
      QStringList Lines;
      if (Pages->currentIndex() == 0 || Pages->currentIndex() == 4) {
        if (const auto Row = CurrentSingleHandle(); Row.has_value()) {
          Lines << QString("Owner PID: %1").arg(Row->OwnerPid)
                << QString("Owner: %1").arg(Row->OwnerName)
                << QString("Handle: %1").arg(HexPtr(Row->HandleValue))
                << QString("Object: %1").arg(HexPtr(Row->ObjectAddress))
                << QString("Type: %1").arg(Row->TypeName.isEmpty() ? "-" : Row->TypeName)
                << QString("Object name: %1")
                       .arg(Row->ObjectName.isEmpty() ? "-" : Row->ObjectName)
                << QString("Access: %1").arg(Row->AccessDisplay)
                << QString("Attributes: %1").arg(FormatHandleAttributes(Row->Attributes))
                << QString("Target PID: %1").arg(Row->TargetPid ? QString::number(Row->TargetPid) : "-")
                << QString("Target TID: %1").arg(Row->TargetTid ? QString::number(Row->TargetTid) : "-")
                << QString("Target: %1").arg(Row->TargetName.isEmpty() ? "-" : Row->TargetName)
                << QString("Risk: %1").arg(Row->RiskText)
                << QString("Matched rules: %1").arg(Row->MatchedRules.isEmpty() ? "-" : Row->MatchedRules);
        }
      } else if (Pages->currentIndex() == 1) {
        const auto Rows = ProcessTable->selectionModel()->selectedRows(0);
        if (!Rows.isEmpty()) {
          const int Index = Rows.first().row();
          if (Index >= 0 && Index < static_cast<int>(ProcessRows.size())) {
            const auto &Row = ProcessRows[static_cast<size_t>(Index)];
            Lines << QString("PID: %1").arg(Row.OwnerPid)
                  << QString("Process: %1").arg(Row.OwnerName)
                  << QString("Handles: %1").arg(Row.HandleCount)
                  << QString("Dangerous: %1").arg(Row.DangerousCount)
                  << QString("Cross-process: %1").arg(Row.CrossCount)
                  << QString("Watched: %1").arg(Row.WatchCount);
          }
        }
      } else if (Pages->currentIndex() == 2) {
        const auto Rows = TypeTable->selectionModel()->selectedRows(0);
        if (!Rows.isEmpty()) {
          const int Index = Rows.first().row();
          if (Index >= 0 && Index < static_cast<int>(TypeRows.size())) {
            const auto &Row = TypeRows[static_cast<size_t>(Index)];
            Lines << QString("Type: %1").arg(Row.TypeName)
                  << QString("Handles: %1").arg(Row.HandleCount)
                  << QString("Dangerous: %1").arg(Row.DangerousCount)
                  << QString("Cross-process: %1").arg(Row.CrossCount)
                  << QString("Watched: %1").arg(Row.WatchCount);
          }
        }
      } else if (Pages->currentIndex() == 3) {
        const auto Rows = ObjectTable->selectionModel()->selectedRows(0);
        if (!Rows.isEmpty()) {
          const int Index = Rows.first().row();
          if (Index >= 0 && Index < static_cast<int>(ObjectRows.size())) {
            const auto &Row = ObjectRows[static_cast<size_t>(Index)];
            Lines << QString("Object: %1").arg(HexPtr(Row.ObjectAddress))
                  << QString("Name: %1").arg(Row.ObjectName.isEmpty() ? "-" : Row.ObjectName)
                  << QString("Type: %1").arg(Row.TypeName.isEmpty() ? "-" : Row.TypeName)
                  << QString("Handles: %1").arg(Row.HandleCount)
                  << QString("PIDs: %1").arg(Row.ProcessCount)
                  << QString("Dangerous: %1").arg(Row.DangerousCount);
          }
        }
      }
      DetailText->setPlainText(
          Lines.isEmpty() ? "Select a handle or aggregate row."
                          : Lines.join('\n'));
    }

    void ShowHandleMenu(TableWidget *Table, const QPoint &Position) {
      const QModelIndex Index = Table->indexAt(Position);
      if (!Index.isValid())
        return;
      if (!Table->selectionModel()->isRowSelected(Index.row(), QModelIndex()))
        Table->selectRow(Index.row());
      auto *Menu = new RoundMenu(QString(), this);
      auto *ForceClose = new QAction("ForceClose", Menu);
      auto *Downgrade = new QAction("Downgrade", Menu);
      auto *Duplicate = new QAction("Duplicate", Menu);
      auto *BatchClose = new QAction("Batch ForceClose", Menu);
      auto *BatchDown = new QAction("Batch Downgrade", Menu);
      Menu->addAction(ForceClose);
      Menu->addAction(Downgrade);
      Menu->addAction(Duplicate);
      Menu->addAction(BatchClose);
      Menu->addAction(BatchDown);
      ConnectMenuAction(ForceClose, this, [this] { ExecuteSingleForceClose(); });
      ConnectMenuAction(Downgrade, this, [this] { ExecuteSingleDowngrade(); });
      ConnectMenuAction(Duplicate, this, [this] { ExecuteSingleDuplicate(); });
      ConnectMenuAction(BatchClose, this,
                        [this] { ExecuteBatchForceClose(); });
      ConnectMenuAction(BatchDown, this,
                        [this] { ExecuteBatchDowngrade(); });
      ReleaseMenuAfterClose(Menu);
      Menu->exec(Table->viewport()->mapToGlobal(Position));
    }

    void ExecuteSingleForceClose() {
      const auto Row = CurrentSingleHandle();
      if (!Row.has_value())
        return;
      if (QMessageBox::question(
              this, "ForceClose",
              QString("Force close handle %1 in PID %2?")
                  .arg(HexPtr(Row->HandleValue))
                  .arg(Row->OwnerPid)) != QMessageBox::Yes)
        return;
      if (!ForceCloseHandleKernel(Row->OwnerPid,
                                  static_cast<ULONG>(Row->HandleValue))) {
        ShowErrorNotice(this, "HandleLab",
                        QString("Force close failed (error %1).")
                            .arg(G_LastMultiDrvError));
        return;
      }
      ShowSuccessNotice(this, "HandleLab",
                        QString("Handle %1 closed.")
                            .arg(HexPtr(Row->HandleValue)));
      StartRefresh(false);
    }

    void ExecuteSingleDowngrade() {
      const auto Row = CurrentSingleHandle();
      if (!Row.has_value())
        return;
      quint32 SelectedMask = Row->GrantedAccess;
      if (!PromptHandleAccessMask(
              this, Row->TypeName, Row->GrantedAccess, SelectedMask,
              "Downgrade Handle",
              QString("Select the permissions to keep for handle %1 in PID %2.")
                  .arg(HexPtr(Row->HandleValue))
                  .arg(Row->OwnerPid),
              "Downgrade"))
        return;
      ULONG NewHandle = 0;
      if (!DowngradeHandleKernel(Row->OwnerPid,
                                 static_cast<ULONG>(Row->HandleValue),
                                 static_cast<ACCESS_MASK>(SelectedMask),
                                 &NewHandle)) {
        ShowErrorNotice(this, "HandleLab",
                        QString("Downgrade failed (error %1).")
                            .arg(G_LastMultiDrvError));
        return;
      }
      ShowSuccessNotice(this, "HandleLab",
                        QString("Handle downgraded. New handle: %1")
                            .arg(HexPtr(NewHandle)));
      StartRefresh(false);
    }

    void ExecuteSingleDuplicate() {
      const auto Row = CurrentSingleHandle();
      if (!Row.has_value())
        return;
      bool TargetOk = false;
      const QString TargetText = QInputDialog::getText(
          this, "Duplicate Handle", "Target PID:", QLineEdit::Normal,
          QString::number(Row->OwnerPid), &TargetOk);
      if (!TargetOk || TargetText.trimmed().isEmpty())
        return;
      bool PidOk = false;
      const qulonglong TargetPidValue = TargetText.trimmed().toULongLong(&PidOk, 0);
      if (!PidOk || TargetPidValue == 0 ||
          TargetPidValue > std::numeric_limits<ULONG>::max()) {
        ShowWarningNotice(this, "HandleLab", "Enter a valid target PID.");
        return;
      }
      quint32 SelectedMask = Row->GrantedAccess;
      if (!PromptHandleAccessMask(
              this, Row->TypeName, Row->GrantedAccess, SelectedMask,
              "Duplicate Handle",
              QString("Select the permissions for duplicated handle %1 in PID %2.")
                  .arg(HexPtr(Row->HandleValue))
                  .arg(TargetPidValue),
              "Duplicate"))
        return;
      ULONG_PTR NewHandle = 0;
      if (!DuplicateAndDowngradeHandleKernel(
              Row->OwnerPid, static_cast<ULONG>(Row->HandleValue),
              static_cast<ULONG>(TargetPidValue),
              static_cast<ACCESS_MASK>(SelectedMask), &NewHandle)) {
        ShowErrorNotice(this, "HandleLab",
                        QString("Duplicate failed (error %1).")
                            .arg(G_LastMultiDrvError));
        return;
      }
      ShowSuccessNotice(this, "HandleLab",
                        QString("Handle duplicated to PID %1 as %2.")
                            .arg(TargetPidValue)
                            .arg(HexPtr(NewHandle)));
      StartRefresh(false);
    }

    void ExecuteBatchForceClose() {
      const QList<int> Selection = CurrentHandleSelection();
      if (Selection.isEmpty())
        return;
      if (QMessageBox::question(
              this, "Batch ForceClose",
              QString("Force close %1 selected handle(s)?")
                  .arg(Selection.size())) != QMessageBox::Yes)
        return;
      int SuccessCount = 0;
      DWORD LastError = ERROR_SUCCESS;
      for (const int Index : Selection) {
        const HandleEntryRow &Row = AllRows[static_cast<size_t>(Index)];
        if (ForceCloseHandleKernel(Row.OwnerPid,
                                   static_cast<ULONG>(Row.HandleValue)))
          ++SuccessCount;
        else
          LastError = G_LastMultiDrvError;
      }
      if (SuccessCount == 0) {
        ShowErrorNotice(this, "HandleLab",
                        QString("Batch force close failed (error %1).")
                            .arg(LastError));
        return;
      }
      ShowSuccessNotice(this, "HandleLab",
                        QString("%1 handle(s) closed.").arg(SuccessCount));
      StartRefresh(false);
    }

    void ExecuteBatchDowngrade() {
      const QList<int> Selection = CurrentHandleSelection();
      if (Selection.isEmpty())
        return;
      const HandleEntryRow &First = AllRows[static_cast<size_t>(Selection.first())];
      for (const int Index : Selection) {
        if (AllRows[static_cast<size_t>(Index)].TypeName.compare(
                First.TypeName, Qt::CaseInsensitive) != 0) {
          ShowWarningNotice(this, "HandleLab",
                            "Batch downgrade requires the same handle type.");
          return;
        }
      }
      quint32 SelectedMask = First.GrantedAccess;
      if (!PromptHandleAccessMask(
              this, First.TypeName, First.GrantedAccess, SelectedMask,
              "Batch Downgrade",
              QString("Apply one permission template to %1 selected handle(s).")
                  .arg(Selection.size()),
              "Downgrade"))
        return;
      int SuccessCount = 0;
      DWORD LastError = ERROR_SUCCESS;
      for (const int Index : Selection) {
        const HandleEntryRow &Row = AllRows[static_cast<size_t>(Index)];
        ULONG NewHandleValue = 0;
        if (DowngradeHandleKernel(Row.OwnerPid,
                                  static_cast<ULONG>(Row.HandleValue),
                                  static_cast<ACCESS_MASK>(SelectedMask),
                                  &NewHandleValue))
          ++SuccessCount;
        else
          LastError = G_LastMultiDrvError;
      }
      if (SuccessCount == 0) {
        ShowErrorNotice(this, "HandleLab",
                        QString("Batch downgrade failed (error %1).")
                            .arg(LastError));
        return;
      }
      ShowSuccessNotice(this, "HandleLab",
                        QString("%1 handle(s) downgraded.").arg(SuccessCount));
      StartRefresh(false);
    }

    void PivotSelectionToHandles() {
      if (Pages->currentIndex() == 1) {
        const auto Rows = ProcessTable->selectionModel()->selectedRows(0);
        if (Rows.isEmpty())
          return;
        const int Index = Rows.first().row();
        if (Index < 0 || Index >= static_cast<int>(ProcessRows.size()))
          return;
        PidFilter->setText(QString::number(
            ProcessRows[static_cast<size_t>(Index)].OwnerPid));
      } else if (Pages->currentIndex() == 2) {
        const auto Rows = TypeTable->selectionModel()->selectedRows(0);
        if (Rows.isEmpty())
          return;
        const int Index = Rows.first().row();
        if (Index < 0 || Index >= static_cast<int>(TypeRows.size()))
          return;
        TypeFilter->setCurrentText(TypeRows[static_cast<size_t>(Index)].TypeName);
      } else if (Pages->currentIndex() == 3) {
        const auto Rows = ObjectTable->selectionModel()->selectedRows(0);
        if (Rows.isEmpty())
          return;
        const int Index = Rows.first().row();
        if (Index < 0 || Index >= static_cast<int>(ObjectRows.size()))
          return;
        SearchEdit->setText(
            HexPtr(ObjectRows[static_cast<size_t>(Index)].ObjectAddress));
      }
      ViewList->setCurrentRow(0);
      RebuildViews();
    }

    void AddRule() {
      QDialog Dialog(this);
      Dialog.setWindowTitle("Add Watch Rule");
      Dialog.resize(420, 210);
      auto *Layout = new QVBoxLayout(&Dialog);
      Layout->setContentsMargins(20, 18, 20, 18);
      Layout->setSpacing(10);
      auto *Kind = new ComboBox;
      Kind->addItems({"type", "name", "access", "pid"});
      auto *Value = new LineEdit;
      ConfigureLineEdit(Value, "Rule value");
      auto *Desc = MakeLabel(
          "Kinds: type/name/access/pid. Example: Process, TOKEN_DUPLICATE, 4",
          11, KTextMuted);
      Desc->setWordWrap(true);
      auto *Buttons = new QHBoxLayout;
      ConfigureToolbarLayout(Buttons);
      Buttons->addStretch();
      auto *Cancel = MakeButton("Cancel");
      auto *Apply = MakeButton("Add", true);
      Buttons->addWidget(Cancel);
      Buttons->addWidget(Apply);
      Layout->addWidget(MakeLabel("Rule kind", 11, KTextPrimary, QFont::DemiBold));
      Layout->addWidget(Kind);
      Layout->addWidget(MakeLabel("Value", 11, KTextPrimary, QFont::DemiBold));
      Layout->addWidget(Value);
      Layout->addWidget(Desc);
      Layout->addStretch();
      Layout->addLayout(Buttons);
      QObject::connect(Cancel, &QPushButton::clicked, &Dialog, &QDialog::reject);
      QObject::connect(Apply, &QPushButton::clicked, &Dialog, &QDialog::accept);
      if (Dialog.exec() != QDialog::Accepted)
        return;
      const QString RuleValue = Value->text().trimmed();
      if (RuleValue.isEmpty()) {
        ShowWarningNotice(this, "HandleLab", "Rule value is required.");
        return;
      }
      WatchRules.push_back({Kind->currentText().trimmed().toCaseFolded(), RuleValue});
      SaveWatchRules();
      PopulateRuleTable();
      RebuildViews();
    }

    void RemoveSelectedRule() {
      const int Row = RuleTable->currentRow();
      if (Row < 0 || Row >= static_cast<int>(WatchRules.size()))
        return;
      WatchRules.erase(WatchRules.begin() + Row);
      SaveWatchRules();
      PopulateRuleTable();
      RebuildViews();
    }

    SearchLineEdit *SearchEdit = nullptr;
    ComboBox *TypeFilter = nullptr;
    LineEdit *PidFilter = nullptr;
    CheckBox *DangerousOnly = nullptr;
    CheckBox *CrossOnly = nullptr;
    CheckBox *AutoRefresh = nullptr;
    BodyLabel *StatusLabel = nullptr;
    PushButton *RefreshButton = nullptr;
    IndeterminateProgressRing *RefreshIndicator = nullptr;
    QListWidget *ViewList = nullptr;
    QStackedWidget *Pages = nullptr;
    TableWidget *HandleTable = nullptr;
    TableWidget *ProcessTable = nullptr;
    TableWidget *TypeTable = nullptr;
    TableWidget *ObjectTable = nullptr;
    TableWidget *WatchTable = nullptr;
    PlainTextEdit *DetailText = nullptr;
    PushButton *ForceCloseButton = nullptr;
    PushButton *DowngradeButton = nullptr;
    PushButton *DuplicateButton = nullptr;
    PushButton *BatchForceCloseButton = nullptr;
    PushButton *BatchDowngradeButton = nullptr;
    PushButton *PivotButton = nullptr;
    TableWidget *RuleTable = nullptr;
    PushButton *AddRuleButton = nullptr;
    PushButton *RemoveRuleButton = nullptr;
    QTimer *SearchDebounceTimer = nullptr;
    QTimer *RefreshTimer = nullptr;
    std::vector<HandleEntryRow> AllRows;
    std::vector<int> FilteredIndices;
    std::vector<int> WatchIndices;
    std::vector<ProcessAggregateRow> ProcessRows;
    std::vector<TypeAggregateRow> TypeRows;
    std::vector<ObjectAggregateRow> ObjectRows;
    std::vector<WatchRule> WatchRules;
    std::atomic_bool Refreshing = false;
    std::atomic_bool Enriching = false;
    std::atomic_uint64_t RefreshGeneration = 0;
  };

  return new HandleLabPage;
}
