class DiskProtectionPage final : public QWidget {
  struct EventRow {
    DISKDRV_EVENT Event{};
    QString Time;
    QString Type;
    QString Process;
    QString Detail;
  };

public:
  explicit DiskProtectionPage(QWidget *Parent = nullptr) : QWidget(Parent) {
    auto *Layout = new QVBoxLayout(this);
    ConfigurePageLayout(Layout);

    auto *ProtectionToolbar = new QHBoxLayout;
    ConfigureToolbarLayout(ProtectionToolbar);
    DiskEdit = new LineEdit;
    DiskEdit->setPlaceholderText("Disk number");
    DiskEdit->setText("0");
    PartitionCombo = new ComboBox;
    PartitionCombo->addItems({"MBR", "GPT", "RAW"});
    PartitionCombo->setCurrentIndex(0);
    AutoPartitionLabel = new BodyLabel("Detected: unknown");
    EnabledCheck = new CheckBox("Enabled");
    EnabledCheck->setChecked(true);
    AuditOnlyCheck = new CheckBox("Audit only");
    RefreshButton = MakeButton("Refresh", true);
    ApplyButton = MakeButton("Apply", true);
    DrainButton = MakeButton("Drain events");
    AllowButton = MakeButton("Allow next time", true);
    AllowCurrentButton = MakeButton("Allow current", true);
    DenyCurrentButton = MakeButton("Deny current");
    ClearButton = MakeButton("Clear queue");
    AllowButton->setEnabled(false);
    AllowCurrentButton->setEnabled(false);
    DenyCurrentButton->setEnabled(false);
    ProtectionToolbar->addWidget(DiskEdit);
    ProtectionToolbar->addWidget(PartitionCombo);
    ProtectionToolbar->addWidget(AutoPartitionLabel);
    ProtectionToolbar->addWidget(EnabledCheck);
    ProtectionToolbar->addWidget(AuditOnlyCheck);
    ProtectionToolbar->addStretch(1);
    ProtectionToolbar->addWidget(RefreshButton);
    ProtectionToolbar->addWidget(ApplyButton);
    ProtectionToolbar->addWidget(DrainButton);
    ProtectionToolbar->addWidget(AllowButton);
    ProtectionToolbar->addWidget(AllowCurrentButton);
    ProtectionToolbar->addWidget(DenyCurrentButton);
    ProtectionToolbar->addWidget(ClearButton);
    Layout->addLayout(ProtectionToolbar);

    StateLabel = new BodyLabel("State: unavailable");
    Layout->addWidget(StateLabel);

    auto *Splitter = new QSplitter(Qt::Vertical, this);
    auto *EventPane = new QWidget;
    auto *EventLayout = new QVBoxLayout(EventPane);
    EventLayout->setContentsMargins(0, 0, 0, 0);
    EventLayout->setSpacing(KCompactPageSpacing);
    EventLayout->addWidget(
        MakeLabel("Blocked Events", 13, KTextPrimary, QFont::DemiBold));
    EventTable = MakeTable({"Time", "Type", "PID", "Process", "Disk", "Offset",
                            "Length", "Detail"});
    EventTable->setSelectionMode(QAbstractItemView::SingleSelection);
    EventTable->horizontalHeader()->setSectionResizeMode(
        0, QHeaderView::ResizeToContents);
    EventTable->horizontalHeader()->setSectionResizeMode(
        1, QHeaderView::ResizeToContents);
    EventTable->horizontalHeader()->setSectionResizeMode(
        2, QHeaderView::ResizeToContents);
    EventTable->horizontalHeader()->setSectionResizeMode(3,
                                                         QHeaderView::Stretch);
    EventTable->horizontalHeader()->setSectionResizeMode(
        4, QHeaderView::ResizeToContents);
    EventTable->horizontalHeader()->setSectionResizeMode(
        5, QHeaderView::ResizeToContents);
    EventTable->horizontalHeader()->setSectionResizeMode(
        6, QHeaderView::ResizeToContents);
    EventTable->horizontalHeader()->setSectionResizeMode(7,
                                                         QHeaderView::Stretch);
    EventLayout->addWidget(EventTable, 1);
    Splitter->addWidget(EventPane);

    auto *SectorPane = new QWidget;
    auto *SectorLayout = new QVBoxLayout(SectorPane);
    SectorLayout->setContentsMargins(0, 0, 0, 0);
    SectorLayout->setSpacing(KCompactPageSpacing);
    SectorLayout->addWidget(MakeLabel("Protected Sector Viewer", 13,
                                      KTextPrimary, QFont::DemiBold));

    auto *RangeToolbar = new QHBoxLayout;
    ConfigureToolbarLayout(RangeToolbar);
    RangeModeCombo = new ComboBox;
    RangeModeCombo->addItems({"Protected range", "Custom range"});
    RangeModeCombo->setCurrentIndex(0);
    ProtectedRegionCombo = new ComboBox;
    ProtectedRegionCombo->addItems({"Head", "Tail"});
    ProtectedRegionCombo->setCurrentIndex(0);
    StartLbaEdit = new LineEdit;
    StartLbaEdit->setPlaceholderText("Start LBA");
    SectorCountEdit = new LineEdit;
    SectorCountEdit->setPlaceholderText("Sector count");
    UseProtectedButton = MakeButton("Use protected range");
    UseEventButton = MakeButton("Use event offset");
    ReadButton = MakeButton("Read sectors", true);
    UseEventButton->setEnabled(false);
    RangeToolbar->addWidget(RangeModeCombo);
    RangeToolbar->addWidget(ProtectedRegionCombo);
    RangeToolbar->addWidget(StartLbaEdit);
    RangeToolbar->addWidget(SectorCountEdit);
    RangeToolbar->addWidget(UseProtectedButton);
    RangeToolbar->addWidget(UseEventButton);
    RangeToolbar->addStretch(1);
    RangeToolbar->addWidget(ReadButton);
    SectorLayout->addLayout(RangeToolbar);

    RangeLabel = new BodyLabel("Range: unavailable");
    SectorLayout->addWidget(RangeLabel);

    SectorView = new PlainTextEdit;
    SectorView->setReadOnly(true);
    SectorView->setPlaceholderText(
        "Read protected sectors to inspect MBR / GPT bytes.");
    SectorView->setFont(QFont("Cascadia Mono", 10));
    InstallFluentScrollBar(SectorView, Qt::Vertical);
    SectorLayout->addWidget(SectorView, 1);
    Splitter->addWidget(SectorPane);
    Splitter->setStretchFactor(0, 3);
    Splitter->setStretchFactor(1, 2);
    Layout->addWidget(Splitter, 1);

    QObject::connect(RefreshButton, &QPushButton::clicked, this,
                     [this] { RefreshState(true); });
    QObject::connect(ApplyButton, &QPushButton::clicked, this,
                     [this] { ApplyState(); });
    QObject::connect(DrainButton, &QPushButton::clicked, this,
                     [this] { DrainEvents(); });
    QObject::connect(ClearButton, &QPushButton::clicked, this,
                     [this] { ClearEvents(); });
    QObject::connect(AllowButton, &QPushButton::clicked, this,
                     [this] { AllowSelected(); });
    QObject::connect(AllowCurrentButton, &QPushButton::clicked, this,
                     [this] { DecideSelected(true); });
    QObject::connect(DenyCurrentButton, &QPushButton::clicked, this,
                     [this] { DecideSelected(false); });
    QObject::connect(UseProtectedButton, &QPushButton::clicked, this,
                     [this] { SwitchToProtectedRangeMode(); });
    QObject::connect(UseEventButton, &QPushButton::clicked, this,
                     [this] { ApplySelectedEventRange(); });
    QObject::connect(ReadButton, &QPushButton::clicked, this,
                     [this] { ReadSectors(true); });
    QObject::connect(RangeModeCombo, &ComboBox::currentTextChanged, this,
                     [this](const QString &) { SyncRangeInputState(); });
    QObject::connect(ProtectedRegionCombo, &ComboBox::currentTextChanged, this,
                     [this](const QString &) { SyncRangeInputState(); });
    QObject::connect(DiskEdit, &LineEdit::textChanged, this,
                     [this](const QString &) {
                       RefreshDetectedPartitionStyle();
                       SyncRangeInputState();
                     });
    QObject::connect(PartitionCombo, &ComboBox::currentTextChanged, this,
                     [this](const QString &) {
                       UpdateProtectedRegionUi();
                       SyncRangeInputState();
                     });
    QObject::connect(
        EventTable, &QTableWidget::itemSelectionChanged, this, [this] {
          const bool HasSelection =
              EventTable->currentRow() >= 0 &&
              EventTable->currentRow() < static_cast<int>(Events.size());
          AllowButton->setEnabled(HasSelection);
          const bool HasPending =
              HasSelection &&
              Events[EventTable->currentRow()].Event.RequestId != 0;
          AllowCurrentButton->setEnabled(HasPending);
          DenyCurrentButton->setEnabled(HasPending);
          UseEventButton->setEnabled(HasSelection);
        });

    PollTimer = new QTimer(this);
    PollTimer->setInterval(1500);
    QObject::connect(PollTimer, &QTimer::timeout, this, [this] {
      if (!isVisible())
        return;
      RefreshState(false, false);
      DrainEvents(false);
    });
    PollTimer->start();

    SyncRangeInputState();
    RefreshState(false, true);
    DrainEvents(false);
  }

private:
  static ULONG PartitionStyleFromIndex(int Index) {
    switch (Index) {
    case 1:
      return PARTITION_STYLE_GPT;
    case 2:
      return PARTITION_STYLE_RAW;
    default:
      return PARTITION_STYLE_MBR;
    }
  }

  static QString PartitionStyleText(ULONG Value) {
    switch (Value) {
    case PARTITION_STYLE_GPT:
      return "GPT";
    case PARTITION_STYLE_RAW:
      return "RAW";
    default:
      return "MBR";
    }
  }

  static QString EventTypeText(ULONG Value) {
    switch (Value) {
    case DiskDrvEventWriteBlocked:
      return "WriteBlocked";
    case DiskDrvEventLayoutBlocked:
      return "LayoutBlocked";
    default:
      return "Unknown";
    }
  }

  static QString DetectedPartitionStyleText(ULONG Value) {
    switch (Value) {
    case PARTITION_STYLE_GPT:
      return "Detected: GPT";
    case PARTITION_STYLE_RAW:
      return "Detected: RAW";
    case PARTITION_STYLE_MBR:
      return "Detected: MBR";
    default:
      return "Detected: unknown";
    }
  }

  ULONG CurrentDiskNumber() const {
    bool Ok = false;
    const uint Value = DiskEdit->text().trimmed().toUInt(&Ok);
    return Ok ? static_cast<ULONG>(Value) : 0u;
  }

  bool IsProtectedRangeMode() const {
    return RangeModeCombo->currentIndex() == 0;
  }

  bool IsGptPartitionStyle() const {
    return PartitionStyleFromIndex(PartitionCombo->currentIndex()) ==
           PARTITION_STYLE_GPT;
  }

  DISKDRV_PROTECTED_REGION CurrentProtectedRegion() const {
    return ProtectedRegionCombo->currentIndex() == 1
               ? DiskDrvProtectedRegionTail
               : DiskDrvProtectedRegionHead;
  }

  void SyncRangeInputState() {
    const bool CustomMode = !IsProtectedRangeMode();
    StartLbaEdit->setEnabled(CustomMode);
    SectorCountEdit->setEnabled(CustomMode);
    UpdateProtectedRegionUi();
    UseProtectedButton->setEnabled(CanResolveProtectedRange());
    RefreshRangePresentation();
  }

  void UpdateProtectedRegionUi() {
    const bool EnableProtectedRegion =
        IsProtectedRangeMode() && IsGptPartitionStyle();
    ProtectedRegionCombo->setEnabled(EnableProtectedRegion);
    if (!IsGptPartitionStyle())
      ProtectedRegionCombo->setCurrentIndex(0);
  }

  void RefreshDetectedPartitionStyle() {
    ULONG PartitionStyle = PARTITION_STYLE_RAW;
    if (!DiskDrvQueryPartitionStyleRobust(CurrentDiskNumber(),
                                          &PartitionStyle)) {
      AutoPartitionLabel->setText("Detected: unavailable");
      return;
    }

    AutoPartitionLabel->setText(DetectedPartitionStyleText(PartitionStyle));
  }

  void ReloadFormFromCachedState() {
    const QSignalBlocker DiskBlocker(DiskEdit);
    const QSignalBlocker PartitionBlocker(PartitionCombo);
    const QSignalBlocker EnabledBlocker(EnabledCheck);
    const QSignalBlocker AuditBlocker(AuditOnlyCheck);

    DiskEdit->setText(QString::number(CachedState.DiskNumber));
    PartitionCombo->setCurrentIndex(
        CachedState.PartitionStyle == PARTITION_STYLE_GPT
            ? 1
            : (CachedState.PartitionStyle == PARTITION_STYLE_RAW ? 2 : 0));
    EnabledCheck->setChecked(CachedState.Enabled != FALSE);
    AuditOnlyCheck->setChecked(CachedState.AuditOnly != FALSE);
    RefreshDetectedPartitionStyle();
    UpdateProtectedRegionUi();
  }

  void RefreshRangePresentation() {
    if (IsProtectedRangeMode()) {
      RefreshProtectedRangePresentation();
      return;
    }

    RefreshCustomRangePresentation();
  }

  void RefreshState(bool Report, bool ReloadForm = true) {
    if (StateRefreshing.exchange(true))
      return;
    if (Report)
      StateLabel->setText("Refreshing protection state...");
    QPointer<DiskProtectionPage> Page(this);
    std::thread([Page, Report, ReloadForm] {
      DISKDRV_STATE_OUTPUT State{};
      const bool Ok = DiskDrvQueryState(&State);
      const DWORD Error = Ok ? ERROR_SUCCESS : GetLastError();
      if (!Page)
        return;
      QMetaObject::invokeMethod(
          Page,
          [Page, Report, ReloadForm, Ok, Error, State = std::move(State)]() mutable {
            if (!Page)
              return;
            Page->StateRefreshing = false;
            Page->ApplyStateSnapshot(Report, ReloadForm, Ok, Error, State);
          },
          Qt::QueuedConnection);
    }).detach();
  }

  void ApplyStateSnapshot(bool Report, bool ReloadForm, bool Ok, DWORD Error,
                          const DISKDRV_STATE_OUTPUT &State) {
    if (!Ok) {
      if (Report)
        ShowErrorNotice(this, "DiskDrv",
                        QString("State query failed (error %1).").arg(Error));
      StateLabel->setText("State: unavailable");
      RangeLabel->setText("Range: unavailable");
      return;
    }

    CachedState = State;
    StateLabel->setText(
        QString("State: disk %1 | %2 | enabled=%3 | audit=%4 | blocked "
                "writes=%5 | blocked layouts=%6 | queued=%7")
            .arg(State.DiskNumber)
            .arg(PartitionStyleText(State.PartitionStyle))
            .arg(State.Enabled ? "yes" : "no")
            .arg(State.AuditOnly ? "yes" : "no")
            .arg(State.BlockedWriteCount)
            .arg(State.BlockedLayoutIoctlCount)
            .arg(State.PendingEventCount));

    if (ReloadForm)
      ReloadFormFromCachedState();

    RefreshRangePresentation();
    if (Report)
      ShowSuccessNotice(this, "DiskDrv", "Protection state refreshed.");
  }

  void ApplyState() {
    DISKDRV_SET_PROTECTION_INPUT Input{};
    Input.DiskNumber = CurrentDiskNumber();
    Input.PartitionStyle =
        PartitionStyleFromIndex(PartitionCombo->currentIndex());
    Input.Enabled = EnabledCheck->isChecked() ? TRUE : FALSE;
    Input.AuditOnly = AuditOnlyCheck->isChecked() ? TRUE : FALSE;
    if (!DiskDrvSetProtection(Input)) {
      ShowErrorNotice(this, "DiskDrv",
                      QString("Apply failed (error %1).").arg(GetLastError()));
      return;
    }
    RefreshState(false, true);
    ShowSuccessNotice(this, "DiskDrv", "Protection configuration updated.");
  }

  void DrainEvents(bool Report = true) {
    int Added = 0;
    for (;;) {
      DISKDRV_EVENT Event{};
      if (!DiskDrvReadEvent(&Event)) {
        const DWORD Error = GetLastError();
        if (Error != ERROR_NO_MORE_ITEMS && Error != ERROR_GEN_FAILURE)
          break;
        break;
      }

      FILETIME FileTime{Event.TimeStamp.LowPart,
                        static_cast<DWORD>(Event.TimeStamp.HighPart)};
      SYSTEMTIME SystemTime{};
      FileTimeToSystemTime(&FileTime, &SystemTime);
      EventRow Row;
      Row.Event = Event;
      Row.Time = QString("%1-%2-%3 %4:%5:%6")
                     .arg(SystemTime.wYear, 4, 10, QLatin1Char('0'))
                     .arg(SystemTime.wMonth, 2, 10, QLatin1Char('0'))
                     .arg(SystemTime.wDay, 2, 10, QLatin1Char('0'))
                     .arg(SystemTime.wHour, 2, 10, QLatin1Char('0'))
                     .arg(SystemTime.wMinute, 2, 10, QLatin1Char('0'))
                     .arg(SystemTime.wSecond, 2, 10, QLatin1Char('0'));
      Row.Type = EventTypeText(Event.EventType);
      Row.Process = QString::fromWCharArray(
          Event.ProcessImage[0] ? Event.ProcessImage : L"<unknown>");
      Row.Detail = QString::fromWCharArray(Event.Detail);
      Events.insert(Events.begin(), Row);
      ++Added;
    }

    if (Events.size() > 256)
      Events.resize(256);
    if (Added > 0)
      PopulateEvents();
    if (Report)
      ShowSuccessNotice(this, "DiskDrv",
                        QString("Read %1 event(s).").arg(Added));
  }

  void PopulateEvents() {
    SetTableRefreshEnabled(EventTable, false);
    EventTable->clearContents();
    EventTable->setRowCount(static_cast<int>(Events.size()));
    for (int RowIndex = 0; RowIndex < static_cast<int>(Events.size());
         ++RowIndex) {
      const EventRow &Row = Events[RowIndex];
      EventTable->setItem(RowIndex, 0, new QTableWidgetItem(Row.Time));
      EventTable->setItem(RowIndex, 1, new QTableWidgetItem(Row.Type));
      EventTable->setItem(
          RowIndex, 2,
          new QTableWidgetItem(QString::number(Row.Event.ProcessId)));
      EventTable->setItem(RowIndex, 3, new QTableWidgetItem(Row.Process));
      EventTable->setItem(
          RowIndex, 4,
          new QTableWidgetItem(QString::number(Row.Event.DiskNumber)));
      EventTable->setItem(
          RowIndex, 5,
          new QTableWidgetItem(
              QString("0x%1").arg(Row.Event.Offset, 0, 16).toUpper()));
      EventTable->setItem(
          RowIndex, 6,
          new QTableWidgetItem(
              QString("0x%1").arg(Row.Event.Length, 0, 16).toUpper()));
      EventTable->setItem(RowIndex, 7, new QTableWidgetItem(Row.Detail));
      EventTable->setRowHeight(RowIndex, KCompactTableRowHeight);
    }
    SetTableRefreshEnabled(EventTable, true);
  }

  void AllowSelected() {
    const int Row = EventTable->currentRow();
    if (Row < 0 || Row >= static_cast<int>(Events.size()))
      return;

    const DISKDRV_EVENT &Event = Events[Row].Event;
    DISKDRV_ALLOW_ONCE_INPUT Input{};
    Input.DiskNumber = Event.DiskNumber;
    Input.OperationType = Event.Flags;
    Input.ProcessId = Event.ProcessId;
    Input.Offset = Event.Offset;
    Input.Length = Event.Length;
    Input.TimeoutMs = 10000;
    if (!DiskDrvAllowOnce(Input)) {
      ShowErrorNotice(
          this, "DiskDrv",
          QString("Allow-once failed (error %1).").arg(GetLastError()));
      return;
    }
    ShowSuccessNotice(this, "DiskDrv",
                      "One-shot token issued for the selected event.");
  }

  void DecideSelected(bool Allow) {
    const int Row = EventTable->currentRow();
    if (Row < 0 || Row >= static_cast<int>(Events.size()))
      return;

    const ULONGLONG RequestId = Events[Row].Event.RequestId;
    if (RequestId == 0) {
      ShowErrorNotice(this, "DiskDrv",
                      "The selected event has no pending write request.");
      return;
    }

    if (!DiskDrvDecideRequest(RequestId, Allow)) {
      ShowErrorNotice(this, "DiskDrv",
                      QString("Decision failed (error %1).")
                          .arg(GetLastError()));
      return;
    }

    Events.erase(Events.begin() + Row);
    PopulateEvents();
    AllowCurrentButton->setEnabled(false);
    DenyCurrentButton->setEnabled(false);
    ShowSuccessNotice(this, "DiskDrv",
                      Allow ? "Current write allowed."
                            : "Current write denied.");
  }

  void ClearEvents() {
    if (!DiskDrvClearEvents()) {
      ShowErrorNotice(this, "DiskDrv",
                      QString("Clear failed (error %1).").arg(GetLastError()));
      return;
    }
    Events.clear();
    PopulateEvents();
    RefreshState(false, false);
    ShowSuccessNotice(this, "DiskDrv", "Event queue cleared.");
  }

  bool BuildProtectedRange(DISKDRV_SECTOR_RANGE *Range) {
    if (!Range)
      return false;
    DISKDRV_STATE_OUTPUT State = CachedState;
    State.DiskNumber = CurrentDiskNumber();
    State.PartitionStyle =
        PartitionStyleFromIndex(PartitionCombo->currentIndex());
    return BuildProtectedSectorRangeEx(State, CurrentProtectedRegion(), Range);
  }

  bool CanResolveProtectedRange() {
    DISKDRV_SECTOR_RANGE Range{};
    return BuildProtectedRange(&Range);
  }

  void RefreshProtectedRangePresentation() {
    DISKDRV_SECTOR_RANGE Range{};
    if (!BuildProtectedRange(&Range)) {
      RangeLabel->setText("Range: unavailable");
      return;
    }

    ProtectedRange = Range;
    const QString RegionText =
        IsGptPartitionStyle()
            ? (CurrentProtectedRegion() == DiskDrvProtectedRegionTail
                   ? "Protected tail"
                   : "Protected head")
            : "Protected";
    UpdateRangeLabel(Range, RegionText);
  }

  void RefreshCustomRangePresentation() {
    DISKDRV_SECTOR_RANGE Range{};
    if (!BuildCustomRange(&Range)) {
      RangeLabel->setText("Range: unavailable");
      return;
    }

    UpdateRangeLabel(Range, "Custom");
  }

  void SwitchToProtectedRangeMode() {
    if (!CanResolveProtectedRange()) {
      ShowErrorNotice(this, "DiskDrv",
                      QString("Unable to resolve protected range (error %1).")
                          .arg(GetLastError()));
      SyncRangeInputState();
      return;
    }

    RangeModeCombo->setCurrentIndex(0);
    SyncRangeInputState();
    ShowSuccessNotice(this, "DiskDrv", "Protected range mode selected.");
  }

  void ApplySelectedEventRange() {
    const int Row = EventTable->currentRow();
    if (Row < 0 || Row >= static_cast<int>(Events.size()))
      return;

    DISKDRV_SECTOR_RANGE BaseRange{};
    if (!BuildProtectedRange(&BaseRange)) {
      ShowErrorNotice(this, "DiskDrv",
                      QString("Unable to query bytes per sector (error %1).")
                          .arg(GetLastError()));
      return;
    }

    const DISKDRV_EVENT &Event = Events[Row].Event;
    const ULONGLONG Offset = Event.Offset;
    const ULONGLONG Length =
        Event.Length == 0 ? BaseRange.BytesPerSector : Event.Length;
    const ULONGLONG StartLba = Offset / BaseRange.BytesPerSector;
    const ULONGLONG EndOffset = Offset + std::max<ULONGLONG>(Length, 1) - 1;
    const ULONGLONG EndLba = EndOffset / BaseRange.BytesPerSector;
    const ULONGLONG SectorCount = (EndLba - StartLba) + 1;
    RangeModeCombo->setCurrentIndex(1);
    StartLbaEdit->setText(QString::number(static_cast<qulonglong>(StartLba)));
    SectorCountEdit->setText(
        QString::number(static_cast<qulonglong>(SectorCount)));
    SyncRangeInputState();
    ShowSuccessNotice(this, "DiskDrv",
                      "Custom range moved to the selected event offset.");
  }

  bool BuildCustomRange(DISKDRV_SECTOR_RANGE *Range) {
    if (!Range)
      return false;

    bool StartOk = false;
    bool CountOk = false;
    const qulonglong StartLba =
        StartLbaEdit->text().trimmed().toULongLong(&StartOk);
    const qulonglong SectorCount =
        SectorCountEdit->text().trimmed().toULongLong(&CountOk);
    if (!StartOk || !CountOk || SectorCount == 0 || SectorCount > 4096) {
      SetLastError(ERROR_INVALID_PARAMETER);
      return false;
    }

    Range->DiskNumber = CurrentDiskNumber();
    Range->PartitionStyle =
        PartitionStyleFromIndex(PartitionCombo->currentIndex());
    Range->StartLba = StartLba;
    Range->SectorCount = static_cast<ULONG>(SectorCount);
    Range->BytesPerSector = 512;
    DiskDrvQueryBytesPerSector(Range->DiskNumber, &Range->BytesPerSector);
    SetLastError(ERROR_SUCCESS);
    return true;
  }

  bool BuildActiveRange(DISKDRV_SECTOR_RANGE *Range) {
    if (!Range)
      return false;

    if (IsProtectedRangeMode())
      return BuildProtectedRange(Range);
    return BuildCustomRange(Range);
  }

  void UpdateRangeLabel(const DISKDRV_SECTOR_RANGE &Range,
                        const QString &ModeText) {
    RangeLabel->setText(QString("Range: %1 | disk %2 | %3 | LBA %4 | sectors "
                                "%5 | bytes/sector %6 | total %7 bytes")
                            .arg(ModeText)
                            .arg(Range.DiskNumber)
                            .arg(PartitionStyleText(Range.PartitionStyle))
                            .arg(Range.StartLba)
                            .arg(Range.SectorCount)
                            .arg(Range.BytesPerSector)
                            .arg(static_cast<qulonglong>(Range.SectorCount) *
                                 Range.BytesPerSector));
  }

  QString FormatHexAscii(const std::vector<BYTE> &Buffer, ULONGLONG StartLba,
                         ULONG BytesPerSector) const {
    QString Output;
    const int BytesPerLine = 16;
    for (size_t Offset = 0; Offset < Buffer.size(); Offset += BytesPerLine) {
      const ULONGLONG AbsoluteByteOffset = StartLba * BytesPerSector + Offset;
      QString Line = QString("%1  ")
                         .arg(AbsoluteByteOffset, 12, 16, QLatin1Char('0'))
                         .toUpper();
      QString Ascii;
      for (int Index = 0; Index < BytesPerLine; ++Index) {
        if (Offset + Index < Buffer.size()) {
          const BYTE Value = Buffer[Offset + Index];
          Line += QString("%1 ").arg(Value, 2, 16, QLatin1Char('0')).toUpper();
          Ascii += (Value >= 32 && Value <= 126) ? QChar(Value) : '.';
        } else {
          Line += "   ";
          Ascii += ' ';
        }
        if (Index == 7)
          Line += ' ';
      }
      Output += Line + " |" + Ascii + "|\n";
    }
    return Output.trimmed();
  }

  void ReadSectors(bool Report) {
    DISKDRV_SECTOR_RANGE Range{};
    if (!BuildActiveRange(&Range)) {
      if (Report)
        ShowErrorNotice(
            this, "DiskDrv",
            QString("Invalid range (error %1).").arg(GetLastError()));
      return;
    }

    std::vector<BYTE> Buffer;
    if (!ReadPhysicalDiskSectors(Range, &Buffer)) {
      if (Report)
        ShowErrorNotice(this, "DiskDrv",
                        QString("Read failed (error %1).").arg(GetLastError()));
      return;
    }

    LastReadRange = Range;
    const QString ModeText =
        IsProtectedRangeMode()
            ? (IsGptPartitionStyle()
                   ? (CurrentProtectedRegion() == DiskDrvProtectedRegionTail
                          ? "Protected tail"
                          : "Protected head")
                   : "Protected")
            : "Custom";
    UpdateRangeLabel(Range, ModeText);
    SectorView->setPlainText(
        FormatHexAscii(Buffer, Range.StartLba, Range.BytesPerSector));
    if (Report)
      ShowSuccessNotice(this, "DiskDrv",
                        QString("Read %1 byte(s) from disk %2.")
                            .arg(Buffer.size())
                            .arg(Range.DiskNumber));
  }

  LineEdit *DiskEdit = nullptr;
  ComboBox *PartitionCombo = nullptr;
  CheckBox *EnabledCheck = nullptr;
  CheckBox *AuditOnlyCheck = nullptr;
  BodyLabel *AutoPartitionLabel = nullptr;
  PushButton *RefreshButton = nullptr;
  PushButton *ApplyButton = nullptr;
  PushButton *DrainButton = nullptr;
  PushButton *AllowButton = nullptr;
  PushButton *AllowCurrentButton = nullptr;
  PushButton *DenyCurrentButton = nullptr;
  PushButton *ClearButton = nullptr;
  BodyLabel *StateLabel = nullptr;
  TableWidget *EventTable = nullptr;
  ComboBox *RangeModeCombo = nullptr;
  ComboBox *ProtectedRegionCombo = nullptr;
  LineEdit *StartLbaEdit = nullptr;
  LineEdit *SectorCountEdit = nullptr;
  PushButton *UseProtectedButton = nullptr;
  PushButton *UseEventButton = nullptr;
  PushButton *ReadButton = nullptr;
  BodyLabel *RangeLabel = nullptr;
  PlainTextEdit *SectorView = nullptr;
  QTimer *PollTimer = nullptr;
  std::vector<EventRow> Events;
  DISKDRV_STATE_OUTPUT CachedState{};
  DISKDRV_SECTOR_RANGE ProtectedRange{};
  DISKDRV_SECTOR_RANGE LastReadRange{};
  std::atomic_bool StateRefreshing = false;
};

QWidget *CreateDiskPage() { return new DiskProtectionPage; }
