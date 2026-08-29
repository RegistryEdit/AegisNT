struct MonitorEventRow {
  QString Text;
  QString Detail;
};

struct MonitorHistoryRow {
  QString Timestamp;
  QString Type;
  DWORD Pid = 0;
  QString Process;
  QString Detail;
};

struct MonitorStreamState {
  std::mutex Mutex;
  std::vector<MonitorEventRow> Rows;
  std::atomic_uint64_t Version = 0;
};

struct MonitorSharedState {
  std::array<MonitorStreamState, 5> Streams;
  std::mutex HistoryMutex;
  std::vector<MonitorHistoryRow> HistoryRows;
  std::atomic_uint64_t HistoryVersion = 0;
};

std::weak_ptr<MonitorSharedState> G_ActiveMonitorState;

MonitorHistoryRow BuildMonitorHistoryRow(const QString &Text,
                                         const QString &Detail) {
  MonitorHistoryRow Row;
  Row.Detail = Detail.isEmpty() ? Text : Detail;
  const QStringList Parts = Text.split(" | ");
  if (!Parts.isEmpty())
    Row.Timestamp = Parts[0].trimmed();
  if (Parts.size() > 1)
    Row.Type = Parts[1].trimmed();
  if (Parts.size() > 2)
    Row.Process = Parts[2].trimmed();
  static const QRegularExpression PidPattern(
      R"(\bPID\s+(\d+)\b)", QRegularExpression::CaseInsensitiveOption);
  const QRegularExpressionMatch Match = PidPattern.match(Text);
  if (Match.hasMatch())
    Row.Pid = Match.captured(1).toULong();
  if (Row.Process.isEmpty())
    Row.Process = Row.Pid ? QString("PID %1").arg(Row.Pid) : "-";
  if (Row.Type.isEmpty())
    Row.Type = "Event";
  if (Row.Timestamp.isEmpty())
    Row.Timestamp =
        QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss.zzz");
  return Row;
}

void PushMonitorEvent(const std::shared_ptr<MonitorSharedState> &State,
                      int StreamIndex, QString Text,
                      QString Detail = QString()) {
  if (!State || StreamIndex < 0 ||
      StreamIndex >= static_cast<int>(State->Streams.size()))
    return;
  MonitorStreamState &Stream = State->Streams[StreamIndex];
  std::lock_guard<std::mutex> Lock(Stream.Mutex);
  Stream.Rows.insert(Stream.Rows.begin(), {std::move(Text), std::move(Detail)});
  if (Stream.Rows.size() > 500)
    Stream.Rows.resize(500);
  Stream.Version.fetch_add(1, std::memory_order_relaxed);
  if (StreamIndex < 4) {
    std::lock_guard<std::mutex> HistoryLock(State->HistoryMutex);
    State->HistoryRows.insert(
        State->HistoryRows.begin(),
        BuildMonitorHistoryRow(Stream.Rows.front().Text,
                               Stream.Rows.front().Detail));
    if (State->HistoryRows.size() > 4000)
      State->HistoryRows.resize(4000);
    State->HistoryVersion.fetch_add(1, std::memory_order_relaxed);
  }
}

QString MonitorTimestamp(const FILETIME &Timestamp) {
  return QString::fromStdWString(FormatTimestamp(Timestamp));
}

QString MonitorTimestamp(const LARGE_INTEGER &Timestamp) {
  FILETIME FileTime{Timestamp.LowPart, static_cast<DWORD>(Timestamp.HighPart)};
  return MonitorTimestamp(FileTime);
}

QString NetworkAddressText(const uint32_t *Address, bool IsIpv6) {
  char Text[INET6_ADDRSTRLEN]{};
  return InetNtopA(IsIpv6 ? AF_INET6 : AF_INET, Address, Text, sizeof(Text))
             ? QString::fromLatin1(Text)
             : "?";
}

void MonitorNetworkCallback(const NetMon_ParsedPacket *Packet) {
  const std::shared_ptr<MonitorSharedState> State = G_ActiveMonitorState.lock();
  if (!State || !Packet)
    return;
  const QString Protocol = Packet->Protocol == IPPROTO_TCP   ? "TCP"
                           : Packet->Protocol == IPPROTO_UDP ? "UDP"
                                                             : "IP";
  const QString Local = NetworkAddressText(Packet->LocalAddr, Packet->IsIpv6);
  const QString Remote = NetworkAddressText(Packet->RemoteAddr, Packet->IsIpv6);
  const QString Process = Packet->ProcessName[0]
                              ? QString::fromLatin1(Packet->ProcessName)
                              : "<unknown>";
  const QString Text =
      QString("%1 | %2 | %3:%4 -> %5:%6 | %7 | PID %8 | %9 bytes")
          .arg(Packet->Outbound ? "OUT" : "IN", Protocol, Local)
          .arg(Packet->LocalPort)
          .arg(Remote)
          .arg(Packet->RemotePort)
          .arg(Process)
          .arg(Packet->Pid)
          .arg(Packet->TotalLength);
  const std::string Hex = NetMon_Detail::PayloadToHex(
      Packet->Payload.empty() ? nullptr : Packet->Payload.data(),
      Packet->Payload.size());
  const std::string Ascii = NetMon_Detail::PayloadToAscii(
      Packet->Payload.empty() ? nullptr : Packet->Payload.data(),
      Packet->Payload.size());
  const QString Detail =
      Text +
      QString("\n\nPayload (%1 bytes)\n\nHEX:\n%2\n\nASCII:\n%3")
          .arg(Packet->Payload.size())
          .arg(QString::fromStdString(Hex), QString::fromStdString(Ascii));
  PushMonitorEvent(State, 2, Text, Detail);
}

class MonitorManagerPage final : public QWidget {
public:
  explicit MonitorManagerPage(QWidget *Parent = nullptr)
      : QWidget(Parent), SharedState(std::make_shared<MonitorSharedState>()) {
    G_ActiveMonitorState = SharedState;
    auto *Layout = new QVBoxLayout(this);
    ConfigurePageLayout(Layout);
    auto *Tabs = new TabBar;
    Tabs->setAddButtonVisible(false);
    Tabs->setTabsClosable(false);
    Tabs->setMovable(false);
    Tabs->addTab("system", "System", Fluent::IconType::COMMAND_PROMPT);
    Tabs->addTab("process", "Process", Fluent::IconType::APPLICATION);
    Tabs->addTab("network", "Network", Fluent::IconType::GLOBE);
    Tabs->addTab("http", "HTTP(S)", Fluent::IconType::LINK);
    Tabs->addTab("history", "History", Fluent::IconType::HISTORY);
    Tabs->addTab("rules", "Rules", Fluent::IconType::EDIT);
    Layout->addWidget(Tabs);
    Pages = new QStackedWidget;
    Pages->addWidget(CreateSystemPage());
    Pages->addWidget(CreateProcessPage());
    Pages->addWidget(CreateNetworkPage());
    Pages->addWidget(CreateHttpPage());
    Pages->addWidget(CreateHistoryPage());
    Pages->addWidget(CreateRulesPage());
    Layout->addWidget(Pages, 1);
    QObject::connect(Tabs, &TabBar::currentChanged, Pages,
                     &QStackedWidget::setCurrentIndex);
    UpdateTimer = new QTimer(this);
    QObject::connect(UpdateTimer, &QTimer::timeout, this, [this] {
      if (!isVisible())
        return;
      const int Index = Pages->currentIndex();
      if (Index >= 0 && Index < 4) {
        const uint64_t Version =
            SharedState->Streams[Index].Version.load(std::memory_order_relaxed);
        if (DisplayedVersions[Index] != Version) {
          DisplayedVersions[Index] = Version;
          Populate(Index);
        }
      } else if (Index == 4) {
        const uint64_t Version =
            SharedState->HistoryVersion.load(std::memory_order_relaxed);
        if (DisplayedHistoryVersion != Version) {
          DisplayedHistoryVersion = Version;
          PopulateHistory(HistorySearchEdit
                              ? HistorySearchEdit->text().trimmed()
                              : QString());
        } else if (Index == 5) {
          RefreshRules();
        }
      }
    });
    QObject::connect(
        Pages, &QStackedWidget::currentChanged, this, [this](int Index) {
          if (Index >= 0 && Index < 4) {
            DisplayedVersions[Index] = SharedState->Streams[Index].Version.load(
                std::memory_order_relaxed);
            Populate(Index);
          } else if (Index == 4) {
            DisplayedHistoryVersion =
                SharedState->HistoryVersion.load(std::memory_order_relaxed);
            PopulateHistory(HistorySearchEdit
                                ? HistorySearchEdit->text().trimmed()
                                : QString());
          } else if (Index == 5) {
            RefreshRules();
          }
        });
    UpdateTimer->start(150);
    TelemetryTimer = new QTimer(this);
    TelemetryTimer->setInterval(1000);
    QObject::connect(TelemetryTimer, &QTimer::timeout, this,
                     [this] { RefreshKernelTelemetry(); });
    TelemetryTimer->start();
  }

  ~MonitorManagerPage() override {
    StopHttp(false);
    StopNetwork(false);
    StopProcess(false);
    StopSystem(false);
    G_ActiveMonitorState.reset();
  }

private:
  QWidget *CreateEventPage(int Index, QHBoxLayout *Controls,
                           const QString &Placeholder) {
    auto *Page = new QWidget;
    auto *Layout = new QVBoxLayout(Page);
    Layout->setContentsMargins(0, 0, 0, 0);
    Layout->setSpacing(KCompactPageSpacing);
    Layout->addLayout(Controls);
    auto *FilterLayout = new QHBoxLayout;
    Searches[Index] = new SearchLineEdit;
    ConfigureSearchLineEdit(Searches[Index], Placeholder, 0);
    auto *ClearButton = MakeButton("Clear");
    FilterLayout->addWidget(Searches[Index], 1);
    FilterLayout->addWidget(ClearButton);
    Layout->addLayout(FilterLayout);
    Tables[Index] = MakeTable({"Event"});
    Tables[Index]->setProperty("UseGenericDetailDialog", false);
    Tables[Index]->horizontalHeader()->setSectionResizeMode(
        0, QHeaderView::Stretch);
    Tables[Index]->setContextMenuPolicy(Qt::CustomContextMenu);
    Layout->addWidget(Tables[Index], 1);
    if (!SearchDebounceTimers[Index]) {
      SearchDebounceTimers[Index] = new QTimer(this);
      SearchDebounceTimers[Index]->setSingleShot(true);
      SearchDebounceTimers[Index]->setInterval(KSearchDebounceMs);
      QObject::connect(SearchDebounceTimers[Index], &QTimer::timeout, this,
                       [this, Index] { Populate(Index); });
    }
    QObject::connect(Searches[Index], &QLineEdit::textChanged, this,
                     [this, Index] { SearchDebounceTimers[Index]->start(); });
    QObject::connect(ClearButton, &QPushButton::clicked, this,
                     [this, Index] { Clear(Index); });
    QObject::connect(Tables[Index], &QWidget::customContextMenuRequested, this,
                     [this, Index](const QPoint &Position) {
                       ShowEventMenu(Index, Position);
                     });
    QObject::connect(
        Tables[Index], &QTableWidget::cellDoubleClicked, this,
        [this, Index](int Row, int) { ShowEventDetail(Index, Row); });
    return Page;
  }

  QWidget *CreateSystemPage() {
    auto *Controls = new QHBoxLayout;
    SystemMode = new ComboBox;
    SystemMode->addItems({"ETWMode", "KernelMode"});
    SystemMode->setCurrentIndex(0);
    SystemMode->setMinimumWidth(190);
    SystemFilterPid = new LineEdit;
    ConfigureLineEdit(SystemFilterPid, "PID filter (0 = all)", 150);
    SystemFilterPid->setMaximumWidth(150);
    SystemPathPrefix = new LineEdit;
    ConfigureLineEdit(SystemPathPrefix, "Path prefix");
    RegistryPreview = new CheckBox("Registry preview");
    SystemStart = MakeButton("Start", true);
    SystemStop = MakeButton("Stop");
    SystemStop->setEnabled(false);
    Statuses[0] = new BodyLabel("Stopped");
    KernelTelemetryStatus = new BodyLabel("V3 telemetry: idle");
    Controls->addWidget(SystemMode);
    Controls->addWidget(SystemFilterPid);
    Controls->addWidget(SystemPathPrefix, 1);
    Controls->addWidget(RegistryPreview);
    Controls->addWidget(SystemStart);
    Controls->addWidget(SystemStop);
    Controls->addWidget(KernelTelemetryStatus);
    Controls->addWidget(Statuses[0], 1);
    QObject::connect(SystemStart, &QPushButton::clicked, this,
                     [this] { StartSystem(); });
    QObject::connect(SystemStop, &QPushButton::clicked, this,
                     [this] { StopSystem(true); });
    return CreateEventPage(
        0, Controls, "Search PID, TID, type, image, path, or registry key");
  }

  QWidget *CreateProcessPage() {
    auto *Controls = new QHBoxLayout;
    ProcessTarget = new LineEdit;
    ConfigureLineEdit(ProcessTarget, "Process PID or name");
    ProcessMethod = new ComboBox;
    ProcessMethod->addItems({"R3CreateRemoteThread", "R3NtCreateThreadEx",
                             "R3QueueUserAPC", "R3SetWindowsHookEx",
                             "R0DllInjectApc", "R0DllInjectThread"});
    ProcessMethod->setCurrentIndex(0);
    ProcessStart = MakeButton("Start", true);
    ProcessStop = MakeButton("Stop");
    ProcessStop->setEnabled(false);
    Statuses[1] = new BodyLabel("Stopped");
    Controls->addWidget(ProcessTarget, 1);
    Controls->addWidget(ProcessMethod);
    Controls->addWidget(ProcessStart);
    Controls->addWidget(ProcessStop);
    Controls->addWidget(Statuses[1]);
    QObject::connect(ProcessStart, &QPushButton::clicked, this,
                     [this] { StartProcess(); });
    QObject::connect(ProcessStop, &QPushButton::clicked, this,
                     [this] { StopProcess(true); });
    return CreateEventPage(1, Controls, "Search category, PID, TID, or target");
  }

  QWidget *CreateNetworkPage() {
    auto *Controls = new QHBoxLayout;
    NetworkStart = MakeButton("Start", true);
    NetworkStop = MakeButton("Stop");
    NetworkStop->setEnabled(false);
    Statuses[2] = new BodyLabel("Stopped");
    Controls->addWidget(NetworkStart);
    Controls->addWidget(NetworkStop);
    Controls->addWidget(Statuses[2], 1);
    QObject::connect(NetworkStart, &QPushButton::clicked, this,
                     [this] { StartNetwork(); });
    QObject::connect(NetworkStop, &QPushButton::clicked, this,
                     [this] { StopNetwork(true); });
    return CreateEventPage(2, Controls,
                           "Search process, PID, protocol, or address");
  }

  QWidget *CreateHttpPage() {
    auto *Controls = new QHBoxLayout;
    HttpProxyPort = new LineEdit;
    ConfigureLineEdit(HttpProxyPort, "Proxy port", 110);
    HttpProxyPort->setText("8443");
    HttpProxyPort->setMaximumWidth(110);
    HttpStart = MakeButton("Start", true);
    HttpStop = MakeButton("Stop");
    HttpStop->setEnabled(false);
    Statuses[3] = new BodyLabel("Stopped | HTTPS proxy 127.0.0.1:8443");
    Controls->addWidget(HttpProxyPort);
    Controls->addWidget(HttpStart);
    Controls->addWidget(HttpStop);
    Controls->addWidget(Statuses[3], 1);
    QObject::connect(HttpStart, &QPushButton::clicked, this,
                     [this] { StartHttp(); });
    QObject::connect(HttpStop, &QPushButton::clicked, this,
                     [this] { StopHttp(true); });
    return CreateEventPage(
        3, Controls, "Search URL, host, method, status, SNI, process, or PID");
  }

  QWidget *CreateHistoryPage() {
    auto *Page = new QWidget;
    auto *Layout = new QVBoxLayout(Page);
    Layout->setContentsMargins(0, 0, 0, 0);
    Layout->setSpacing(KCompactPageSpacing);

    auto *CtrlBar = new QHBoxLayout;
    auto *ExportBtn = MakeButton("Export CSV");
    auto *ClearBtn = MakeButton("Clear");
    ConfigureActionButton(ExportBtn, 110, KStandardButtonHeight);
    ConfigureActionButton(ClearBtn);
    HistorySearchEdit = new SearchLineEdit;
    ConfigureSearchLineEdit(HistorySearchEdit,
                            "Search events by type, PID, process, or detail",
                            KStandardSearchWidth);
    HistoryStatus = new BodyLabel("Persistent event history");
    CtrlBar->addWidget(HistorySearchEdit);
    CtrlBar->addStretch();
    CtrlBar->addWidget(ExportBtn);
    CtrlBar->addWidget(ClearBtn);
    CtrlBar->addWidget(HistoryStatus);
    Layout->addLayout(CtrlBar);

    HistoryTable = MakeTable({"Timestamp", "Type", "PID", "Process", "Detail"});
    HistoryTable->setProperty("DetailDialogTitle", "Event details");
    Layout->addWidget(HistoryTable, 1);

    HistorySearchDebounceTimer = new QTimer(this);
    HistorySearchDebounceTimer->setSingleShot(true);
    HistorySearchDebounceTimer->setInterval(KSearchDebounceMs);
    QObject::connect(
        HistorySearchDebounceTimer, &QTimer::timeout, this,
        [this] { PopulateHistory(HistorySearchEdit->text().trimmed()); });
    QObject::connect(HistorySearchEdit, &QLineEdit::textChanged, this,
                     [this] { HistorySearchDebounceTimer->start(); });
    QObject::connect(ExportBtn, &QPushButton::clicked, this, [this] {
      QString Path = QFileDialog::getSaveFileName(this, "Export Events",
                                                  "events.csv", "CSV (*.csv)");
      if (!Path.isEmpty()) {
        QFile File(Path);
        if (File.open(QIODevice::WriteOnly | QIODevice::Text)) {
          std::vector<MonitorHistoryRow> HistoryRows;
          {
            std::lock_guard<std::mutex> Lock(SharedState->HistoryMutex);
            HistoryRows = SharedState->HistoryRows;
          }
          QTextStream Out(&File);
          Out << "Timestamp,Type,PID,Process,Detail\n";
          for (const auto &Evt : HistoryRows)
            Out << Evt.Timestamp << "," << Evt.Type << "," << Evt.Pid << ","
                << Evt.Process << ",\"" << Evt.Detail << "\"\n";
          if (Out.status() != QTextStream::Ok)
            ShowErrorNotice(this, "Monitor",
                            "Failed to export events: " + File.errorString());
        } else
          ShowErrorNotice(this, "Monitor",
                          "Failed to export events: " + File.errorString());
      }
    });
    QObject::connect(ClearBtn, &QPushButton::clicked, this, [this] {
      {
        std::lock_guard<std::mutex> Lock(SharedState->HistoryMutex);
        SharedState->HistoryRows.clear();
        SharedState->HistoryVersion.fetch_add(1, std::memory_order_relaxed);
      }
      PopulateHistory(QString());
    });

    return Page;
  }

  QWidget *CreateRulesPage() {
    auto *Page = new QWidget;
    auto *Layout = new QVBoxLayout(Page);
    Layout->setContentsMargins(0, 0, 0, 0);
    Layout->setSpacing(KCompactPageSpacing);
    auto *Controls = new QHBoxLayout;
    const auto MakeRuleField = [](const QString &Label, QWidget *Control) {
      auto *Field = new QVBoxLayout;
      Field->setContentsMargins(0, 0, 0, 0);
      Field->setSpacing(2);
      Field->addWidget(MakeLabel(Label, 11, KTextPrimary));
      Field->addWidget(Control);
      return Field;
    };
    RuleType = new ComboBox;
    RuleType->addItems({"File", "Registry", "Network"});
    RuleAction = new ComboBox;
    RuleAction->addItems({"Audit", "Block"});
    RulePid = new LineEdit;
    ConfigureLineEdit(RulePid, "PID (0 = all)", 125);
    RulePid->setText("0");
    RuleProtocol = new LineEdit;
    ConfigureLineEdit(RuleProtocol, "Protocol (0 = all)", 145);
    RuleProtocol->setText("0");
    RulePort = new LineEdit;
    ConfigureLineEdit(RulePort, "Remote port (0 = all)", 175);
    RulePort->setText("0");
    RuleTarget = new LineEdit;
    ConfigureLineEdit(RuleTarget, "Path or registry prefix");
    auto *Add = MakeButton("Add rule", true);
    auto *Remove = MakeButton("Remove rule");
    auto *ClearAll = MakeButton("Clear rules");
    auto *Refresh = MakeButton("Refresh rules");
    for (PushButton *Button : {Add, Remove, ClearAll, Refresh})
      ConfigureActionButton(Button);
    RulesStatus = new BodyLabel("Rules not loaded");
    Controls->addLayout(MakeRuleField("Rule type", RuleType));
    Controls->addLayout(MakeRuleField("Rule action", RuleAction));
    Controls->addLayout(MakeRuleField("Process ID", RulePid));
    Controls->addLayout(MakeRuleField("Protocol", RuleProtocol));
    Controls->addLayout(MakeRuleField("Remote port", RulePort));
    Controls->addLayout(MakeRuleField("Target", RuleTarget), 1);
    auto *Actions = new QVBoxLayout;
    Actions->setContentsMargins(0, 0, 0, 0);
    Actions->setSpacing(2);
    Actions->addWidget(MakeLabel("Actions", 11, KTextPrimary));
    auto *ActionButtons = new QHBoxLayout;
    ActionButtons->setContentsMargins(0, 0, 0, 0);
    ActionButtons->setSpacing(KCompactPageSpacing);
    ActionButtons->addWidget(Add);
    ActionButtons->addWidget(Remove);
    ActionButtons->addWidget(ClearAll);
    ActionButtons->addWidget(Refresh);
    Actions->addLayout(ActionButtons);
    Controls->addLayout(Actions);
    Layout->addLayout(Controls);
    RulesTable = MakeTable({"ID", "Type", "Action", "PID", "Protocol",
                            "Remote Port", "Target", "Hit count"});
    RulesTable->setSelectionMode(QAbstractItemView::SingleSelection);
    for (int Column = 0; Column < RulesTable->columnCount(); ++Column)
      RulesTable->horizontalHeader()->setSectionResizeMode(
          Column, Column == 6 ? QHeaderView::Stretch
                              : QHeaderView::ResizeToContents);
    Layout->addWidget(RulesTable, 1);
    Layout->addWidget(RulesStatus);
    QObject::connect(RuleType, &ComboBox::currentTextChanged, this,
                     [this](const QString &) { UpdateRuleInputState(); });
    QObject::connect(Add, &QPushButton::clicked, this, [this] { AddRule(); });
    QObject::connect(Remove, &QPushButton::clicked, this,
                     [this] { RemoveSelectedRule(); });
    QObject::connect(ClearAll, &QPushButton::clicked, this,
                     [this] { ClearRules(); });
    QObject::connect(Refresh, &QPushButton::clicked, this,
                     [this] { RefreshRules(); });
    UpdateRuleInputState();
    return Page;
  }

  void UpdateRuleInputState() {
    const bool IsNetwork = RuleType && RuleType->currentIndex() == 2;
    RuleProtocol->setEnabled(IsNetwork);
    RulePort->setEnabled(IsNetwork);
    RuleTarget->setEnabled(!IsNetwork);
    RuleTarget->setPlaceholderText(IsNetwork ? "Network rules match PID, protocol, and port"
                                             : "Path or registry prefix");
  }

  bool ParseRuleNumber(LineEdit *Input, ULONG Maximum, ULONG *Value,
                       const QString &Field) {
    bool Ok = false;
    const qulonglong Number = Input->text().trimmed().toULongLong(&Ok);
    if (!Ok || Number > Maximum) {
      ShowErrorNotice(this, "Monitor", QString("Invalid %1.").arg(Field));
      return false;
    }
    *Value = static_cast<ULONG>(Number);
    return true;
  }

  void AddRule() {
    MonitorRuleV3 Rule{};
    Rule.Type = static_cast<MonitorRuleType>(RuleType->currentIndex() + 1);
    Rule.Action = static_cast<MonitorRuleAction>(RuleAction->currentIndex() + 1);
    if (!ParseRuleNumber(RulePid, static_cast<ULONG>(0xFFFFFFFFu),
                         &Rule.ProcessId, "PID"))
      return;
    if (Rule.Type == MonitorRuleNetwork) {
      if (!ParseRuleNumber(RuleProtocol, 255, &Rule.Protocol, "protocol") ||
          !ParseRuleNumber(RulePort, 65535, &Rule.RemotePort, "remote port"))
        return;
    } else {
      const std::wstring Target = RuleTarget->text().trimmed().toStdWString();
      if (Target.empty()) {
        ShowErrorNotice(this, "Monitor", "A path or registry prefix is required for this rule.");
        return;
      }
      wcsncpy_s(Rule.Target, Target.c_str(), _TRUNCATE);
    }
    if (!AegisSentinelOperateRule(MonitorRuleAdd, &Rule)) {
      ShowErrorNotice(this, "Monitor", QString("Failed to add rule (error %1).").arg(GetLastError()));
      return;
    }
    ShowSuccessNotice(this, "Monitor", "Rule added.");
    RefreshRules();
  }

  void RemoveSelectedRule() {
    const int Row = RulesTable ? RulesTable->currentRow() : -1;
    if (Row < 0 || Row >= static_cast<int>(Rules.size())) {
      ShowErrorNotice(this, "Monitor", "Select a rule first.");
      return;
    }
    MonitorRuleV3 Rule{};
    Rule.Id = Rules[static_cast<size_t>(Row)].Id;
    if (!AegisSentinelOperateRule(MonitorRuleRemove, &Rule)) {
      ShowErrorNotice(this, "Monitor", QString("Failed to remove rule (error %1).").arg(GetLastError()));
      return;
    }
    ShowSuccessNotice(this, "Monitor", "Rule removed.");
    RefreshRules();
  }

  void ClearRules() {
    if (QMessageBox::question(this, "Clear rules", "Remove all monitor rules?") != QMessageBox::Yes)
      return;
    if (!AegisSentinelOperateRule(MonitorRuleClear)) {
      ShowErrorNotice(this, "Monitor", QString("Failed to clear rules (error %1).").arg(GetLastError()));
      return;
    }
    ShowSuccessNotice(this, "Monitor", "All monitor rules were removed.");
    RefreshRules();
  }

  void RefreshRules() {
    if (!RulesTable || !RulesStatus)
      return;
    if (RulesRefreshing.exchange(true))
      return;
    RulesStatus->setText("Loading rules...");
    QPointer<MonitorManagerPage> Page(this);
    std::thread([Page] {
      MonitorRuleListV3 List{};
      const bool Ok = AegisSentinelEnumerateRules(&List);
      const DWORD Error = Ok ? ERROR_SUCCESS : GetLastError();
      if (!Page)
        return;
      QMetaObject::invokeMethod(
          Page,
          [Page, Ok, Error, List = std::move(List)]() mutable {
            if (!Page)
              return;
            Page->RulesRefreshing = false;
            if (!Ok) {
              Page->RulesStatus->setText(
                  QString("Rules unavailable (error %1)").arg(Error));
              return;
            }
            Page->Rules.assign(List.Rules, List.Rules + List.Count);
            Page->PopulateRules();
          },
          Qt::QueuedConnection);
    }).detach();
  }

  void PopulateRules() {
    SetTableRefreshEnabled(RulesTable, false);
    RulesTable->clearContents();
    RulesTable->setRowCount(static_cast<int>(Rules.size()));
    for (int Row = 0; Row < static_cast<int>(Rules.size()); ++Row) {
      const MonitorRuleV3 &Rule = Rules[static_cast<size_t>(Row)];
      const QString Type = Rule.Type == MonitorRuleFile ? "File"
                         : Rule.Type == MonitorRuleRegistry ? "Registry" : "Network";
      const QString Action = Rule.Action == MonitorRuleBlock ? "Block" : "Audit";
      RulesTable->setItem(Row, 0, new QTableWidgetItem(QString::number(Rule.Id)));
      RulesTable->setItem(Row, 1, new QTableWidgetItem(Type));
      RulesTable->setItem(Row, 2, new QTableWidgetItem(Action));
      RulesTable->setItem(Row, 3, new QTableWidgetItem(QString::number(Rule.ProcessId)));
      RulesTable->setItem(Row, 4, new QTableWidgetItem(QString::number(Rule.Protocol)));
      RulesTable->setItem(Row, 5, new QTableWidgetItem(QString::number(Rule.RemotePort)));
      RulesTable->setItem(Row, 6, new QTableWidgetItem(QString::fromWCharArray(Rule.Target)));
      RulesTable->setItem(Row, 7, new QTableWidgetItem(QString::number(Rule.HitCount)));
      RulesTable->setRowHeight(Row, KCompactTableRowHeight);
    }
    SetTableRefreshEnabled(RulesTable, true);
    RulesStatus->setText(QString("Rules: %1").arg(Rules.size()));
  }

  void Populate(int Index) {
    if (!Tables[Index])
      return;
    std::vector<MonitorEventRow> Rows;
    {
      std::lock_guard<std::mutex> Lock(SharedState->Streams[Index].Mutex);
      Rows = SharedState->Streams[Index].Rows;
    }
    const QString Query = Searches[Index]->text().trimmed();
    std::vector<const MonitorEventRow *> VisibleRows;
    VisibleRows.reserve(Rows.size());
    for (const MonitorEventRow &Event : Rows) {
      if (!Query.isEmpty() &&
          !Event.Text.contains(Query, Qt::CaseInsensitive) &&
          !Event.Detail.contains(Query, Qt::CaseInsensitive))
        continue;
      VisibleRows.push_back(&Event);
    }
    SetTableRefreshEnabled(Tables[Index], false);
    Tables[Index]->clearContents();
    Tables[Index]->setRowCount(static_cast<int>(VisibleRows.size()));
    for (int Row = 0; Row < static_cast<int>(VisibleRows.size()); ++Row) {
      const MonitorEventRow &Event = *VisibleRows[Row];
      auto *Item = new QTableWidgetItem(Event.Text);
      Item->setData(Qt::UserRole, Event.Detail);
      Tables[Index]->setItem(Row, 0, Item);
      Tables[Index]->setRowHeight(Row, KCompactTableRowHeight);
    }
    SetTableRefreshEnabled(Tables[Index], true);
  }

  void Clear(int Index) {
    MonitorStreamState &Stream = SharedState->Streams[Index];
    {
      std::lock_guard<std::mutex> Lock(Stream.Mutex);
      Stream.Rows.clear();
      Stream.Version.fetch_add(1, std::memory_order_relaxed);
    }
    Populate(Index);
  }

  void ShowEventMenu(int Index, const QPoint &Position) {
    const QModelIndex ModelIndex = Tables[Index]->indexAt(Position);
    if (!ModelIndex.isValid())
      return;
    Tables[Index]->selectRow(ModelIndex.row());
    auto *Menu = new RoundMenu(QString(), this);
    auto *Copy = new QAction("Copy information", Menu);
    auto *Details = new QAction("Detailed information", Menu);
    Menu->addAction(Copy);
    Menu->addAction(Details);
    QObject::connect(
        Copy, &QAction::triggered, this, [this, Index, Row = ModelIndex.row()] {
          if (auto *Item = Tables[Index]->item(Row, 0)) {
            QApplication::clipboard()->setText(Item->text());
            ShowSuccessNotice(this, "Monitor", "Event information copied.");
          }
        });
    QObject::connect(
        Details, &QAction::triggered, this,
        [this, Index, Row = ModelIndex.row()] { ShowEventDetail(Index, Row); });
    ReleaseMenuAfterClose(Menu);
    Menu->exec(Tables[Index]->viewport()->mapToGlobal(Position));
  }

  void ShowEventDetail(int Index, int Row) {
    QTableWidgetItem *Item = Tables[Index]->item(Row, 0);
    if (!Item)
      return;
    QString Detail = Item->data(Qt::UserRole).toString();
    if (Detail.isEmpty())
      Detail = Item->text();
    auto *Dialog = new QDialog(this);
    Dialog->setAttribute(Qt::WA_DeleteOnClose);
    Dialog->setWindowTitle("Monitor event details");
    Dialog->resize(900, 620);
    auto *Layout = new QVBoxLayout(Dialog);
    auto *Text = new PlainTextEdit;
    Text->setReadOnly(true);
    Text->setFont(QFont("Cascadia Mono", 10));
    Text->setPlainText(Detail);
    InstallFluentScrollBar(Text, Qt::Vertical);
    Layout->addWidget(Text, 1);
    auto *Close = MakeButton("Close", true);
    Layout->addWidget(Close, 0, Qt::AlignRight);
    QObject::connect(Close, &QPushButton::clicked, Dialog, &QDialog::accept);
    Dialog->show();
  }

  static QString FormatEtwEvent(const ParsedEvent &Event) {
    QString Text =
        QString("%1 | %2 | %3 | PID %4 | TID %5")
            .arg(MonitorTimestamp(Event.TimeStamp),
                 QString::fromWCharArray(CategoryToString(Event.Category)),
                 Event.ProcessName.empty()
                     ? "<unknown>"
                     : QString::fromStdWString(Event.ProcessName))
            .arg(Event.ProcessId)
            .arg(Event.ThreadId);
    if (Event.ParentPid)
      Text += QString(" | PPID %1").arg(Event.ParentPid);
    if (Event.StartAddr)
      Text += QString(" | Start 0x%1").arg(Event.StartAddr, 0, 16).toUpper();
    if (!Event.ImageName.empty())
      Text += " | Image " + QString::fromStdWString(Event.ImageName);
    if (!Event.FileName.empty())
      Text += " | File " + QString::fromStdWString(Event.FileName);
    if (!Event.RegistryPath.empty())
      Text += " | Key " + QString::fromStdWString(Event.RegistryPath);
    if (!Event.ValueName.empty())
      Text += " | Value " + QString::fromStdWString(Event.ValueName);
    if (Event.DataSize)
      Text += QString(" | Size %1").arg(Event.DataSize);
    return Text;
  }

  static QString FormatKernelEvent(const MonitorEvent &Event) {
    const std::wstring ProcessName = GetProcessNameFromPid(Event.ProcessId);
    QString Text =
        QString("%1 | %2 | %3 | PID %4 | TID %5")
            .arg(MonitorTimestamp(Event.TimeStamp),
                 QString::fromWCharArray(EventTypeToString(Event.Type)),
                 ProcessName.empty() ? "<unknown>"
                                     : QString::fromStdWString(ProcessName))
            .arg(Event.ProcessId)
            .arg(Event.ThreadId);
    if (Event.ParentPid)
      Text += QString(" | PPID %1").arg(Event.ParentPid);
    if (Event.Path[0])
      Text += " | " + QString::fromWCharArray(Event.Path);
    if (Event.Extra[0])
      Text += " | " + QString::fromWCharArray(Event.Extra);
    if (Event.Data1)
      Text += QString(" | Data1 %1 (0x%2)")
                  .arg(Event.Data1)
                  .arg(Event.Data1, 0, 16)
                  .toUpper();
    if (Event.Data2)
      Text += QString(" | Data2 %1 (0x%2)")
                  .arg(Event.Data2)
                  .arg(Event.Data2, 0, 16)
                  .toUpper();
    return Text;
  }

  static QString FormatKernelEventV2(const MonitorEventV2 &Event) {
    const std::wstring ProcessName = GetProcessNameFromPid(Event.ProcessId);
    QString Text =
        QString("%1 | #%2 | %3 | %4 | PID %5 | TID %6")
            .arg(MonitorTimestamp(Event.TimeStamp))
            .arg(Event.Sequence)
            .arg(QString::fromWCharArray(
                EventTypeToString(static_cast<MonitorEventType>(Event.Type))))
            .arg(ProcessName.empty() ? "<unknown>"
                                     : QString::fromStdWString(ProcessName))
            .arg(Event.ProcessId)
            .arg(Event.ThreadId);
    if (Event.ParentPid)
      Text += QString(" | PPID %1").arg(Event.ParentPid);
    if (Event.TargetProcessId)
      Text += QString(" | Target PID %1").arg(Event.TargetProcessId);
    if (Event.TargetThreadId)
      Text += QString(" | Target TID %1").arg(Event.TargetThreadId);
    if (Event.Address)
      Text += QString(" | Address 0x%1").arg(Event.Address, 0, 16).toUpper();
    if (Event.SizeBytes)
      Text += QString(" | Size %1").arg(Event.SizeBytes);
    if (Event.Type == EventNetworkConnect || Event.Type == EventNetworkAccept)
      Text += QString(" | Protocol %1 | Local %2 | Remote %3")
                  .arg(Event.Operation)
                  .arg(Event.Value1)
                  .arg(Event.Value2);
    if (Event.Path[0])
      Text += " | " + QString::fromWCharArray(Event.Path);
    if (Event.Extra[0])
      Text += " | " + QString::fromWCharArray(Event.Extra);
    if (Event.Status)
      Text +=
          QString(" | Status 0x%1")
              .arg(static_cast<quint32>(Event.Status), 8, 16, QLatin1Char('0'))
              .toUpper();
    return Text;
  }

  void StartSystem() {
    if (SystemStopping || SystemRunning.exchange(true))
      return;
    Clear(0);
    SystemMode->setEnabled(false);
    SystemStart->setEnabled(false);
    SystemStop->setEnabled(true);
    const std::weak_ptr<MonitorSharedState> WeakState = SharedState;
    if (SystemMode->currentIndex() == 0) {
      Statuses[0]->setText("Starting ETWMode...");
      SetEtwEventCallback([WeakState](const ParsedEvent &Event) {
        if (const auto State = WeakState.lock())
          PushMonitorEvent(State, 0, FormatEtwEvent(Event));
      });
      QPointer<MonitorManagerPage> Page(this);
      EtwThread = std::thread([Page, WeakState] {
        if (StartKernelTrace()) {
          if (Page)
            QMetaObject::invokeMethod(
                Page,
                [Page] {
                  if (Page)
                    Page->Statuses[0]->setText("ETWMode running");
                },
                Qt::QueuedConnection);
          OpenAndProcessTrace();
        } else if (const auto State = WeakState.lock())
          PushMonitorEvent(
              State, 0,
              QString("ETW start failed: %1").arg(GetLastStartTraceStatus()));
        StopTrace();
        SetEtwEventCallback(nullptr);
        if (Page)
          QMetaObject::invokeMethod(
              Page,
              [Page] {
                if (Page)
                  Page->HandleSystemWorkerExit();
              },
              Qt::QueuedConnection);
      });
    } else {
      try {
        MonitorFilterV2 Filter{};
        Filter.EventMask = ~0ull;
        Filter.ProcessId = SystemFilterPid->text().trimmed().toUInt();
        const std::wstring Prefix =
            SystemPathPrefix->text().trimmed().toStdWString();
        if (!Prefix.empty())
          wcsncpy_s(Filter.PathPrefix, Prefix.c_str(), _TRUNCATE);
        if (RegistryPreview->isChecked()) {
          Filter.Flags |= MONITOR_FILTER_REGISTRY_PREVIEW;
          Filter.RegistryPreviewBytes = 256;
        }
        AegisSentinelSetFilterV2(Filter);
        Kernel = std::make_unique<KernelMonitorV2>();
        Kernel->SetCallback([WeakState](const MonitorEventV2 &Event) {
          if (const auto State = WeakState.lock())
            PushMonitorEvent(State, 0, FormatKernelEventV2(Event));
        });
        if (!Kernel->Start())
          throw std::runtime_error("Kernel monitor start failed");
        Statuses[0]->setText("KernelMode running");
        RefreshKernelTelemetry();
      } catch (const std::exception &Error) {
        Kernel.reset();
        SystemRunning = false;
        FinishSystemStop();
        ShowErrorNotice(this, "Monitor", QString::fromLocal8Bit(Error.what()));
      }
    }
    if (SystemRunning)
      ShowSuccessNotice(this, "Monitor", "System monitor started.");
  }

  void FinishSystemStop() {
    SystemRunning = false;
    SystemStopping = false;
    SystemMode->setEnabled(true);
    SystemStart->setEnabled(true);
    SystemStop->setEnabled(false);
    Statuses[0]->setText("Stopped");
    if (KernelTelemetryStatus)
      KernelTelemetryStatus->setText("V3 telemetry: idle");
  }

  void RefreshKernelTelemetry() {
    if (!KernelTelemetryStatus || !SystemRunning || !SystemMode ||
        SystemMode->currentIndex() != 1)
      return;
    if (KernelTelemetryRefreshing.exchange(true))
      return;
    QPointer<MonitorManagerPage> Page(this);
    std::thread([Page] {
      MonitorStatsV2 Stats{};
      const bool Ok = AegisSentinelQueryStatsV2(&Stats);
      const DWORD Error = Ok ? ERROR_SUCCESS : GetLastError();
      if (!Page)
        return;
      QMetaObject::invokeMethod(
          Page,
          [Page, Ok, Error, Stats = std::move(Stats)]() mutable {
            if (!Page)
              return;
            Page->KernelTelemetryRefreshing = false;
            if (!Page->SystemRunning || !Page->SystemMode ||
                Page->SystemMode->currentIndex() != 1)
              return;
            if (!Ok) {
              Page->KernelTelemetryStatus->setText(
                  QString("V3 telemetry unavailable (%1)").arg(Error));
              return;
            }
            Page->UpdateKernelTelemetry(Stats);
          },
          Qt::QueuedConnection);
    }).detach();
  }

  void UpdateKernelTelemetry(const MonitorStatsV2 &Stats) {
    const quint64 Dropped = Stats.SystemDropped + Stats.FileDropped +
                            Stats.NetworkDropped;
    KernelTelemetryStatus->setText(
        QString("V3 seq %1 | queue S %2/%3 F %4/%5 N %6/%7 (cap %8) | lost %9")
            .arg(Stats.LastSequence)
            .arg(Stats.SystemQueued).arg(Stats.SystemHighWatermark)
            .arg(Stats.FileQueued).arg(Stats.FileHighWatermark)
            .arg(Stats.NetworkQueued).arg(Stats.NetworkHighWatermark)
            .arg(Stats.QueueCapacity).arg(Dropped));
    KernelTelemetryStatus->setToolTip(
        QString("Dropped: system %1, file %2, network %3")
            .arg(Stats.SystemDropped).arg(Stats.FileDropped)
            .arg(Stats.NetworkDropped));
  }

  void HandleSystemWorkerExit() {
    if (SystemStopping)
      return;
    if (EtwThread.joinable())
      EtwThread.join();
    FinishSystemStop();
  }

  void StopSystem(bool ShowResult) {
    if (SystemStopping.exchange(true))
      return;
    if (!SystemRunning.exchange(false) && !EtwThread.joinable() && !Kernel) {
      SystemStopping = false;
      return;
    }
    SystemStart->setEnabled(false);
    SystemStop->setEnabled(false);
    SystemMode->setEnabled(false);
    Statuses[0]->setText("Stopping...");
    QPointer<MonitorManagerPage> Page(this);
    std::thread EtwWorker = std::move(EtwThread);
    std::unique_ptr<KernelMonitorV2> KernelWorker = std::move(Kernel);
    std::thread([Page, EtwWorker = std::move(EtwWorker),
                 KernelWorker = std::move(KernelWorker), ShowResult]() mutable {
      StopTrace();
      SetEtwEventCallback(nullptr);
      if (KernelWorker) {
        KernelWorker->Stop();
        KernelWorker.reset();
      }
      if (EtwWorker.joinable())
        EtwWorker.join();
      if (Page)
        QMetaObject::invokeMethod(
            Page,
            [Page, ShowResult] {
              if (!Page)
                return;
              Page->FinishSystemStop();
              if (ShowResult)
                ShowSuccessNotice(Page, "Monitor", "System monitor stopped.");
            },
            Qt::QueuedConnection);
    }).detach();
  }

  void StartProcess() {
    if (ProcessStopping || ProcessRunning)
      return;
    const QString Target = ProcessTarget->text().trimmed();
    DWORD Pid = Target.toUInt();
    if (!Pid)
      Pid = GetProcessIdByName(Target.toStdWString());
    if (!Pid) {
      ShowErrorNotice(this, "Monitor", "Process not found.");
      return;
    }
    Clear(1);
    const std::weak_ptr<MonitorSharedState> WeakState = SharedState;
    Dll = std::make_unique<DllMonitor>();
    Dll->SetCallback([WeakState, Target](const DllEvent &Event) {
      if (const auto State = WeakState.lock())
        PushMonitorEvent(
            State, 1,
            QString("%1 | PID %2 | TID %3 | Timestamp %4 | Target %5")
                .arg(QString::fromStdString(Event.Category))
                .arg(Event.ProcessId)
                .arg(Event.ThreadId)
                .arg(Event.Timestamp)
                .arg(Target));
    });
    if (!Dll->Start()) {
      Dll.reset();
      ShowErrorNotice(this, "Monitor", "Failed to create monitor pipe.");
      return;
    }
    const std::filesystem::path DllPath =
        std::filesystem::path(
            QCoreApplication::applicationDirPath().toStdWString()) /
        L"ExtraDLL" / L"MonitorHook.dll";
    if (!std::filesystem::exists(DllPath)) {
      Dll->Stop();
      Dll.reset();
      ShowErrorNotice(this, "Monitor", "MonitorHook.dll was not found.");
      return;
    }
    EnableDebugPrivilege();
    BOOL Result = FALSE;
    switch (ProcessMethod->currentIndex()) {
    case 0:
      Result = Inject_RemoteThread(Pid, DllPath.wstring());
      break;
    case 1:
      Result = Inject_NtCreateThreadEx(Pid, DllPath.wstring());
      break;
    case 2:
      Result = Inject_QueueUserAPC(Pid, DllPath.wstring());
      break;
    case 3:
      Result = Inject_SetWindowsHookEx(Pid, DllPath.wstring());
      break;
    case 4:
      Result = DllInjectApc(Pid, DllPath.wstring().c_str());
      break;
    case 5:
      Result = DllInjectThread(Pid, DllPath.wstring().c_str());
      break;
    }
    if (!Result) {
      Dll->Stop();
      Dll.reset();
      ShowErrorNotice(this, "Monitor", "MonitorHook.dll injection failed.");
      return;
    }
    ProcessRunning = true;
    ProcessTarget->setEnabled(false);
    ProcessMethod->setEnabled(false);
    ProcessStart->setEnabled(false);
    ProcessStop->setEnabled(true);
    Statuses[1]->setText(QString("Monitoring PID %1").arg(Pid));
    ShowSuccessNotice(this, "Monitor", "Process monitor started.");
  }

  void StopProcess(bool ShowResult) {
    if (ProcessStopping.exchange(true))
      return;
    if (!ProcessRunning.exchange(false) && !Dll) {
      ProcessStopping = false;
      return;
    }
    ProcessStart->setEnabled(false);
    ProcessStop->setEnabled(false);
    ProcessTarget->setEnabled(false);
    ProcessMethod->setEnabled(false);
    Statuses[1]->setText("Stopping...");
    QPointer<MonitorManagerPage> Page(this);
    std::unique_ptr<DllMonitor> DllWorker = std::move(Dll);
    std::thread([Page, DllWorker = std::move(DllWorker), ShowResult]() mutable {
      if (DllWorker) {
        DllWorker->Stop();
        DllWorker.reset();
      }
      if (Page)
        QMetaObject::invokeMethod(
            Page,
            [Page, ShowResult] {
              if (!Page)
                return;
              Page->ProcessStopping = false;
              Page->ProcessTarget->setEnabled(true);
              Page->ProcessMethod->setEnabled(true);
              Page->ProcessStart->setEnabled(true);
              Page->ProcessStop->setEnabled(false);
              Page->Statuses[1]->setText("Stopped");
              if (ShowResult)
                ShowSuccessNotice(Page, "Monitor", "Process monitor stopped.");
            },
            Qt::QueuedConnection);
    }).detach();
  }

  std::filesystem::path ExtraDllPath() const {
    return std::filesystem::path(
               QCoreApplication::applicationDirPath().toStdWString()) /
           L"ExtraDLL";
  }

  void StartNetwork() {
    if (NetworkRunning)
      return;
    if (HttpRunning) {
      ShowWarningNotice(
          this, "Monitor",
          "Stop HTTP(S) capture before starting Network capture.");
      return;
    }
    Clear(2);
    const std::filesystem::path Directory = ExtraDllPath();
    if (!NetMon_LoadWinDivertDllFromDirectory(Directory.c_str())) {
      ShowErrorNotice(this, "Monitor",
                      QString("Unable to load WinDivert.dll (error %1).")
                          .arg(GetLastError()));
      return;
    }
    if (!NetMon_IsWinDivertDriverRunning()) {
      ShowErrorNotice(this, "Monitor",
                      QString("WinDivert driver is not running (error %1).")
                          .arg(GetLastError()));
      return;
    }
    if (!NetMon_Start(MonitorNetworkCallback)) {
      ShowErrorNotice(
          this, "Monitor",
          QString("Network capture failed (error %1).").arg(GetLastError()));
      return;
    }
    NetworkRunning = true;
    NetworkStart->setEnabled(false);
    NetworkStop->setEnabled(true);
    Statuses[2]->setText("WinDivert network capture running");
    ShowSuccessNotice(this, "Monitor", "Network capture started.");
  }

  void StopNetwork(bool ShowResult) {
    if (!NetworkRunning.exchange(false))
      return;
    NetMon_Stop();
    NetworkStart->setEnabled(true);
    NetworkStop->setEnabled(false);
    Statuses[2]->setText("Stopped");
    if (ShowResult)
      ShowSuccessNotice(this, "Monitor", "Network capture stopped.");
  }

  static QString HttpAddress(uint32_t Address) {
    return QString("%1.%2.%3.%4")
        .arg((Address >> 24) & 0xFF)
        .arg((Address >> 16) & 0xFF)
        .arg((Address >> 8) & 0xFF)
        .arg(Address & 0xFF);
  }

  uint16_t CurrentHttpProxyPort() const {
    bool Ok = false;
    const int Port =
        HttpProxyPort ? HttpProxyPort->text().trimmed().toInt(&Ok) : 0;
    return Ok && Port >= 1 && Port <= 65535 ? static_cast<uint16_t>(Port) : 0;
  }

  QString HttpProxyStatusText(const QString &Prefix) const {
    const uint16_t Port = CurrentHttpProxyPort();
    return Port == 0
               ? Prefix
               : QString("%1 | HTTPS proxy 127.0.0.1:%2").arg(Prefix).arg(Port);
  }

  void StartHttp() {
    if (HttpRunning)
      return;
    if (NetworkRunning) {
      ShowWarningNotice(
          this, "Monitor",
          "Stop Network capture before starting HTTP(S) capture.");
      return;
    }
    const uint16_t ProxyPort = CurrentHttpProxyPort();
    if (ProxyPort == 0) {
      ShowErrorNotice(this, "Monitor",
                      "Proxy port must be between 1 and 65535.");
      return;
    }
    Clear(3);
    const std::filesystem::path ExecutableDirectory(
        QCoreApplication::applicationDirPath().toStdWString());
    http_capture::Config Config;
    Config.CaptureHttp = true;
    Config.CaptureHttps = true;
    Config.HttpsMitm = true;
    Config.ProxyPort = ProxyPort;
    Config.WinDivertDllPath =
        (ExecutableDirectory / L"ExtraDLL" / L"WinDivert.dll").string();
    Config.CaCertPath =
        (ExecutableDirectory / L"Data" / L"CA_CERT.pem").string();
    Config.CaKeyPath = (ExecutableDirectory / L"Data" / L"CA_KEY.pem").string();
    Http = std::make_unique<http_capture::HttpCapture>(Config);
    const std::weak_ptr<MonitorSharedState> WeakState = SharedState;
    Http->OnHttpRequest([WeakState](const http_capture::FlowInfo &Flow,
                                    const http_capture::HttpRequest &Request) {
      if (const auto State = WeakState.lock()) {
        const QString Host = Request.Host.empty()
                                 ? HttpAddress(Flow.DstIp)
                                 : QString::fromStdString(Request.Host);
        const QString Text =
            QString("HTTP REQUEST | %1 %2%3 | %4:%5 -> %6:%7 | %8 bytes")
                .arg(QString::fromStdString(Request.Method), Host,
                     QString::fromStdString(Request.Url),
                     HttpAddress(Flow.SrcIp))
                .arg(Flow.SrcPort)
                .arg(HttpAddress(Flow.DstIp))
                .arg(Flow.DstPort)
                .arg(Request.Body.size());
        QString Detail = Text + "\n\nHeaders:\n";
        for (const auto &Header : Request.Headers)
          Detail +=
              QString::fromStdString(Header.Name + ": " + Header.Value + "\n");
        Detail += "\nBody:\n" +
                  QString::fromUtf8(
                      reinterpret_cast<const char *>(Request.Body.data()),
                      static_cast<qsizetype>(Request.Body.size()));
        PushMonitorEvent(State, 3, Text, Detail);
      }
    });
    Http->OnHttpResponse([WeakState](
                             const http_capture::FlowInfo &Flow,
                             const http_capture::HttpResponse &Response) {
      if (const auto State = WeakState.lock()) {
        const QString Text =
            QString("HTTP RESPONSE | %1 %2 | %3:%4 -> %5:%6 | %7 bytes")
                .arg(Response.StatusCode)
                .arg(QString::fromStdString(Response.Reason),
                     HttpAddress(Flow.SrcIp))
                .arg(Flow.SrcPort)
                .arg(HttpAddress(Flow.DstIp))
                .arg(Flow.DstPort)
                .arg(Response.Body.size());
        QString Detail = Text + "\n\nHeaders:\n";
        for (const auto &Header : Response.Headers)
          Detail +=
              QString::fromStdString(Header.Name + ": " + Header.Value + "\n");
        Detail += "\nBody:\n" +
                  QString::fromUtf8(
                      reinterpret_cast<const char *>(Response.Body.data()),
                      static_cast<qsizetype>(Response.Body.size()));
        PushMonitorEvent(State, 3, Text, Detail);
      }
    });
    Http->OnTlsSni([WeakState](const http_capture::FlowInfo &Flow,
                               const http_capture::TlsSniInfo &Sni) {
      if (const auto State = WeakState.lock()) {
        const QString Text = QString("HTTPS SNI | %1 | %2:%3 -> %4:%5")
                                 .arg(QString::fromStdString(Sni.ServerName),
                                      HttpAddress(Flow.SrcIp))
                                 .arg(Flow.SrcPort)
                                 .arg(HttpAddress(Flow.DstIp))
                                 .arg(Flow.DstPort);
        PushMonitorEvent(State, 3, Text,
                         Text +
                             QString("\nTLS version: %1\nClientHello: %2 bytes")
                                 .arg(Sni.TlsVersion)
                                 .arg(Sni.RawClientHello.size()));
      }
    });
    if (!Http->Start()) {
      const QString Error = QString::fromStdString(Http->LastError());
      Http.reset();
      const QString Message =
          Error.isEmpty() ? "HTTP(S) capture failed to start."
                          : "HTTP(S) capture failed to start.\n" + Error;
      Statuses[3]->setText("Start failed");
      ShowErrorNotice(this, "Monitor", Message);
      return;
    }
    HttpRunning = true;
    HttpStart->setEnabled(false);
    HttpStop->setEnabled(true);
    HttpProxyPort->setEnabled(false);
    Statuses[3]->setText(HttpProxyStatusText("HTTP(S) capture running"));
    ShowSuccessNotice(this, "Monitor", "HTTP(S) capture started.");
  }

  void StopHttp(bool ShowResult) {
    if (Http) {
      Http->Stop();
      Http.reset();
    }
    if (!HttpRunning.exchange(false))
      return;
    HttpStart->setEnabled(true);
    HttpStop->setEnabled(false);
    HttpProxyPort->setEnabled(true);
    Statuses[3]->setText(HttpProxyStatusText("Stopped"));
    if (ShowResult)
      ShowSuccessNotice(this, "Monitor", "HTTP(S) capture stopped.");
  }

  std::shared_ptr<MonitorSharedState> SharedState;
  QStackedWidget *Pages = nullptr;
  std::array<SearchLineEdit *, 4> Searches{};
  std::array<TableWidget *, 4> Tables{};
  std::array<BodyLabel *, 4> Statuses{};
  std::array<uint64_t, 4> DisplayedVersions{};
  std::array<QTimer *, 4> SearchDebounceTimers{};
  uint64_t DisplayedHistoryVersion = 0;
  QTimer *UpdateTimer = nullptr;
  QTimer *TelemetryTimer = nullptr;

  SearchLineEdit *HistorySearchEdit = nullptr;
  TableWidget *HistoryTable = nullptr;
  BodyLabel *HistoryStatus = nullptr;
  BodyLabel *KernelTelemetryStatus = nullptr;
  QTimer *HistorySearchDebounceTimer = nullptr;
  ComboBox *RuleType = nullptr;
  ComboBox *RuleAction = nullptr;
  LineEdit *RulePid = nullptr;
  LineEdit *RuleProtocol = nullptr;
  LineEdit *RulePort = nullptr;
  LineEdit *RuleTarget = nullptr;
  TableWidget *RulesTable = nullptr;
  BodyLabel *RulesStatus = nullptr;
  std::vector<MonitorRuleV3> Rules;
  std::atomic_bool RulesRefreshing = false;
  std::atomic_bool KernelTelemetryRefreshing = false;
  void PopulateHistory(const QString &Query) {
    if (!HistoryTable)
      return;
    std::vector<MonitorHistoryRow> HistoryRows;
    {
      std::lock_guard<std::mutex> Lock(SharedState->HistoryMutex);
      HistoryRows = SharedState->HistoryRows;
    }
    std::vector<const MonitorHistoryRow *> VisibleRows;
    VisibleRows.reserve(HistoryRows.size());
    for (const auto &Evt : HistoryRows) {
      if (!Query.isEmpty() && !Evt.Type.contains(Query, Qt::CaseInsensitive) &&
          !Evt.Process.contains(Query, Qt::CaseInsensitive) &&
          !Evt.Detail.contains(Query, Qt::CaseInsensitive) &&
          !QString::number(Evt.Pid).contains(Query))
        continue;
      VisibleRows.push_back(&Evt);
    }
    SetTableRefreshEnabled(HistoryTable, false);
    HistoryTable->clearContents();
    HistoryTable->setRowCount(static_cast<int>(VisibleRows.size()));
    for (int Row = 0; Row < static_cast<int>(VisibleRows.size()); ++Row) {
      const MonitorHistoryRow &Evt = *VisibleRows[Row];
      HistoryTable->setItem(Row, 0, new QTableWidgetItem(Evt.Timestamp));
      HistoryTable->setItem(Row, 1, new QTableWidgetItem(Evt.Type));
      HistoryTable->setItem(Row, 2,
                            new QTableWidgetItem(QString::number(Evt.Pid)));
      HistoryTable->setItem(Row, 3, new QTableWidgetItem(Evt.Process));
      HistoryTable->setItem(Row, 4, new QTableWidgetItem(Evt.Detail));
      HistoryTable->setRowHeight(Row, KCompactTableRowHeight);
    }
    SetTableRefreshEnabled(HistoryTable, true);
    HistoryStatus->setText(QString("Events: %1").arg(HistoryRows.size()));
  }

  ComboBox *SystemMode = nullptr;
  PushButton *SystemStart = nullptr;
  PushButton *SystemStop = nullptr;
  LineEdit *SystemFilterPid = nullptr;
  LineEdit *SystemPathPrefix = nullptr;
  CheckBox *RegistryPreview = nullptr;
  LineEdit *ProcessTarget = nullptr;
  ComboBox *ProcessMethod = nullptr;
  PushButton *ProcessStart = nullptr;
  PushButton *ProcessStop = nullptr;
  PushButton *NetworkStart = nullptr;
  PushButton *NetworkStop = nullptr;
  LineEdit *HttpProxyPort = nullptr;
  PushButton *HttpStart = nullptr;
  PushButton *HttpStop = nullptr;
  std::unique_ptr<KernelMonitorV2> Kernel;
  std::unique_ptr<DllMonitor> Dll;
  std::unique_ptr<http_capture::HttpCapture> Http;
  std::thread EtwThread;
  std::atomic_bool SystemRunning = false;
  std::atomic_bool SystemStopping = false;
  std::atomic_bool ProcessRunning = false;
  std::atomic_bool ProcessStopping = false;
  std::atomic_bool NetworkRunning = false;
  std::atomic_bool HttpRunning = false;

protected:
  void showEvent(QShowEvent *Event) override {
    QWidget::showEvent(Event);
    if (UpdateTimer)
      UpdateTimer->start(150);
    const int Index = Pages->currentIndex();
    if (Index >= 0 && Index < 4) {
      DisplayedVersions[Index] =
          SharedState->Streams[Index].Version.load(std::memory_order_relaxed);
      Populate(Index);
    } else if (Index == 5) {
      RefreshRules();
    }
  }

  void hideEvent(QHideEvent *Event) override {
    if (UpdateTimer)
      UpdateTimer->stop();
    QWidget::hideEvent(Event);
  }
};
