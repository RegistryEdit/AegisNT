// ============================================================
// 监控页（MonitorManagerPage）：系统/进程/网络/HTTP/设备五条
// 事件流 + 告警面板；事件来自 ETW 追踪与内核回调，
// 表格按 150ms 节拍增量刷新（见 MonitorStreamState）。
// ============================================================
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

// 事件表流（系统 / 进程 / 网络 / HTTP / 设备）。
// 告警面板各自维护独立的 MonitorStreamState，历史记录彼此分开。
static constexpr int KMonitorStreamCount = 5;

struct MonitorSharedState {
  std::array<MonitorStreamState, KMonitorStreamCount> Streams;
  MonitorStreamState Alerts;
  std::mutex HistoryMutex;
  std::vector<MonitorHistoryRow> HistoryRows;
  std::atomic_uint64_t HistoryVersion = 0;
};

std::weak_ptr<MonitorSharedState> G_ActiveMonitorState;

struct EtwDisplayFilter {
  bool Enabled = false;
  QString Pid;
  QString ProcessName;
  QString FilePath;
  QString EventId;
  QString Behavior;
  QString NetworkAddress;
  QString RegistryPath;
  QString Interface;
};

static QString EtwBehaviorTag(const ParsedEvent &Event) {
  switch (Event.Category) {
  case EventCategory::ProcessCreate:
  case EventCategory::ThreadCreate:
  case EventCategory::FileCreate:
  case EventCategory::RegCreateKey:
    return "create";
  case EventCategory::ProcessExit:
  case EventCategory::ThreadExit:
  case EventCategory::FileDelete:
  case EventCategory::RegDeleteKey:
  case EventCategory::RegDeleteValue:
  case EventCategory::VirtualFree:
    return "delete";
  case EventCategory::FileRead:
  case EventCategory::RegQueryKey:
  case EventCategory::RegQueryValue:
  case EventCategory::RegEnumerateKey:
  case EventCategory::RegEnumerateValueKey:
    return "read";
  case EventCategory::FileWrite:
  case EventCategory::RegSetValue:
    return "write";
  case EventCategory::TcpSend:
  case EventCategory::UdpSend:
    return "send";
  case EventCategory::TcpRecv:
  case EventCategory::UdpRecv:
    return "receive";
  case EventCategory::TcpConnect:
  case EventCategory::TcpAccept:
    return "connect";
  case EventCategory::RegOpenKey:
    return "open";
  case EventCategory::ImageLoad:
    return "load";
  case EventCategory::VirtualAlloc:
    return "alloc";
  default:
    return "other";
  }
}

static bool EtwEventMatchesFilter(const ParsedEvent &Event,
                                  const EtwDisplayFilter &Filter) {
  if (!Filter.Enabled)
    return true;
  if (!Filter.Pid.isEmpty()) {
    bool Ok = false;
    const qulonglong Value = Filter.Pid.toULongLong(&Ok);
    if (!Ok || Value != Event.ProcessId)
      return false;
  }
  if (!Filter.ProcessName.isEmpty() &&
      !QString::fromStdWString(Event.ProcessName)
           .contains(Filter.ProcessName, Qt::CaseInsensitive))
    return false;
  if (!Filter.FilePath.isEmpty() &&
      !QString::fromStdWString(Event.FileName)
           .contains(Filter.FilePath, Qt::CaseInsensitive))
    return false;
  if (!Filter.EventId.isEmpty()) {
    bool Ok = false;
    const qulonglong Value = Filter.EventId.toULongLong(&Ok);
    if (!Ok || Value != Event.EventId)
      return false;
  }
  if (!Filter.Behavior.isEmpty() &&
      Filter.Behavior.compare("Any", Qt::CaseInsensitive) != 0 &&
      EtwBehaviorTag(Event) != Filter.Behavior)
    return false;
  if (!Filter.NetworkAddress.isEmpty()) {
    const QString Address = Filter.NetworkAddress;
    const bool Local =
        QString::fromStdWString(Event.LocalAddress)
            .contains(Address, Qt::CaseInsensitive);
    const bool Remote =
        QString::fromStdWString(Event.RemoteAddress)
            .contains(Address, Qt::CaseInsensitive);
    if (!Local && !Remote)
      return false;
  }
  if (!Filter.RegistryPath.isEmpty() &&
      !QString::fromStdWString(Event.RegistryPath)
           .contains(Filter.RegistryPath, Qt::CaseInsensitive))
    return false;
  if (!Filter.Interface.isEmpty()) {
    bool Ok = false;
    const qulonglong Value = Filter.Interface.toULongLong(&Ok);
    if (!Ok || Value != Event.InterfaceIndex)
      return false;
  }
  return true;
}

static QString EtwFilterSummary(const EtwDisplayFilter &Filter) {
  if (!Filter.Enabled)
    return "ETW filter: off";
  QStringList Parts;
  const auto AddField = [&Parts](const char *Name, const QString &Value) {
    if (!Value.isEmpty())
      Parts.append(QString("%1=%2").arg(Name, Value));
  };
  AddField("pid", Filter.Pid);
  AddField("process", Filter.ProcessName);
  AddField("file", Filter.FilePath);
  AddField("event", Filter.EventId);
  AddField("behavior", Filter.Behavior);
  AddField("addr", Filter.NetworkAddress);
  AddField("registry", Filter.RegistryPath);
  AddField("if", Filter.Interface);
  return Parts.isEmpty() ? QString("ETW filter: on (no fields)")
                         : QString("ETW filter: %1").arg(Parts.join(", "));
}

static QString EtwGuidToString(const GUID &Guid) {
  wchar_t Text[40];
  swprintf_s(Text, L"{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
             Guid.Data1, Guid.Data2, Guid.Data3, Guid.Data4[0], Guid.Data4[1],
             Guid.Data4[2], Guid.Data4[3], Guid.Data4[4], Guid.Data4[5],
             Guid.Data4[6], Guid.Data4[7]);
  return QString::fromWCharArray(Text);
}

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

// 告警事件:内核阻断/注入检测/回调变更等关键字命中的行会同时进入 Alerts 流。
bool IsAlertEventText(const QString &Text) {
  static const QStringList Keys = {
      "Blocked", "Inject", "Callback Change", "Callback registered",
      "Callback removed", "blacklist"};
  for (const QString &Key : Keys)
    if (Text.contains(Key, Qt::CaseInsensitive))
      return true;
  return false;
}

void PushAlertEvent(const std::shared_ptr<MonitorSharedState> &State,
                    const QString &Text, const QString &Detail);
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
  if (IsAlertEventText(Stream.Rows.front().Text))
    PushAlertEvent(State, Stream.Rows.front().Text, Stream.Rows.front().Detail);
}

void PushAlertEvent(const std::shared_ptr<MonitorSharedState> &State,
                    const QString &Text, const QString &Detail) {
  if (!State)
    return;
  std::lock_guard<std::mutex> Lock(State->Alerts.Mutex);
  State->Alerts.Rows.insert(State->Alerts.Rows.begin(), {Text, Detail});
  if (State->Alerts.Rows.size() > 500)
    State->Alerts.Rows.resize(500);
  State->Alerts.Version.fetch_add(1, std::memory_order_relaxed);
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
    SelectedProviders.assign(KProviders, KProviders + KProviderCount);
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
    Tabs->addTab("devices", "Devices", Fluent::IconType::FINGERPRINT);
    Tabs->addTab("alerts", "Alerts", Fluent::IconType::INFO);
    Layout->addWidget(Tabs);
    Pages = new QStackedWidget;
    Pages->addWidget(CreateSystemPage());
    Pages->addWidget(CreateProcessPage());
    Pages->addWidget(CreateNetworkPage());
    Pages->addWidget(CreateHttpPage());
    Pages->addWidget(CreateHistoryPage());
    Pages->addWidget(CreateRulesPage());
    Pages->addWidget(CreateDevicesPage());
    Pages->addWidget(CreateAlertsPage());
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
        }
      } else if (Index == 5) {
        RefreshRules();
      } else if (Index == 6) {
        const uint64_t Version =
            SharedState->Streams[4].Version.load(std::memory_order_relaxed);
        if (DisplayedDeviceVersion != Version) {
          DisplayedDeviceVersion = Version;
          Populate(4);
        }
      } else if (Index == 7) {
        const uint64_t Version =
            SharedState->Alerts.Version.load(std::memory_order_relaxed);
        if (DisplayedAlertsVersion != Version) {
          DisplayedAlertsVersion = Version;
          PopulateAlerts();
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
          } else if (Index == 6) {
            DisplayedDeviceVersion =
                SharedState->Streams[4].Version.load(std::memory_order_relaxed);
            Populate(4);
          } else if (Index == 7) {
            DisplayedAlertsVersion =
                SharedState->Alerts.Version.load(std::memory_order_relaxed);
            PopulateAlerts();
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
    StopDevices(false);
    G_ActiveMonitorState.reset();
  }

private:
  QWidget *CreateAlertsPage() {
    auto *Page = new QWidget;
    auto *Layout = new QVBoxLayout(Page);
    Layout->setContentsMargins(0, 0, 0, 0);
    Layout->setSpacing(KCompactPageSpacing);
    auto *FilterLayout = new QHBoxLayout;
    AlertsSearch = new SearchLineEdit;
    ConfigureSearchLineEdit(AlertsSearch, "Filter alerts", 0);
    auto *ClearButton = MakeButton("Clear");
    FilterLayout->addWidget(AlertsSearch, 1);
    FilterLayout->addWidget(ClearButton);
    Layout->addLayout(FilterLayout);
    AlertsTable = MakeTable({"Alert"});
    // 关掉 MakeTable 的逐列通用弹窗：告警只有一列，通用弹窗只会重复行文本，
    // 而且会把 PushAlertEvent 已带上的 Detail 丢掉。改为复用 ShowEventDetail 通路。
    AlertsTable->setProperty("UseGenericDetailDialog", false);
    AlertsTable->setContextMenuPolicy(Qt::CustomContextMenu);
    Layout->addWidget(AlertsTable, 1);
    QObject::connect(ClearButton, &QPushButton::clicked, this, [this] {
      if (SharedState) {
        std::lock_guard<std::mutex> Lock(SharedState->Alerts.Mutex);
        SharedState->Alerts.Rows.clear();
        SharedState->Alerts.Version.fetch_add(1, std::memory_order_relaxed);
      }
      AlertsTable->setRowCount(0);
    });
    QObject::connect(
        AlertsSearch, &QLineEdit::textChanged, this, [this](const QString &Text) {
          for (int Row = 0; Row < AlertsTable->rowCount(); ++Row)
            AlertsTable->setRowHidden(
                Row, !Text.isEmpty() &&
                         !(AlertsTable->item(Row, 0) &&
                           AlertsTable->item(Row, 0)->text().contains(
                               Text, Qt::CaseInsensitive)));
        });
    return Page;
  }

  void PopulateAlerts() {
    if (!AlertsTable || !SharedState)
      return;
    std::vector<MonitorEventRow> Rows;
    {
      std::lock_guard<std::mutex> Lock(SharedState->Alerts.Mutex);
      Rows = SharedState->Alerts.Rows;
    }
    SetTableRefreshEnabled(AlertsTable, false);
    AlertsTable->clearContents();
    AlertsTable->setRowCount(static_cast<int>(Rows.size()));
    for (int Row = 0; Row < static_cast<int>(Rows.size()); ++Row) {
      auto *Item = new QTableWidgetItem(Rows[Row].Text);
      // Detail 存进 UserRole：ShowEventDetail 从这里读，空则回退单行文本
      Item->setData(Qt::UserRole,
                    Rows[Row].Detail.isEmpty() ? Rows[Row].Text : Rows[Row].Detail);
      AlertsTable->setItem(Row, 0, Item);
    }
    SetTableRefreshEnabled(AlertsTable, true);
  }

  QWidget *CreateEventPage(int Index, QHBoxLayout *Controls,
                           const QString &Placeholder) {
    if (Index < 0 || Index >= KMonitorStreamCount)
      return new QWidget;
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
    EtwProvidersButton =
        MakeButton(QString("Providers (%1)...").arg(SelectedProviders.size()));
    EtwFilterButton = MakeButton("Filter...");
    EtwFilterStatus = new BodyLabel(EtwFilterSummary(EtwFilter));
    Statuses[0] = new BodyLabel("Stopped");
    KernelTelemetryStatus = new BodyLabel("V3 telemetry: idle");
    Controls->addWidget(SystemMode);
    Controls->addWidget(EtwProvidersButton);
    Controls->addWidget(EtwFilterButton);
    Controls->addWidget(EtwFilterStatus, 1);
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
    QObject::connect(EtwProvidersButton, &QPushButton::clicked, this,
                     [this] { ShowEtwProvidersDialog(); });
    QObject::connect(EtwFilterButton, &QPushButton::clicked, this,
                     [this] { ShowEtwFilterDialog(); });
    QObject::connect(SystemMode, &ComboBox::currentIndexChanged, this,
                     [this](int Index) {
                       const bool EtwMode = Index == 0;
                       EtwProvidersButton->setEnabled(EtwMode);
                       EtwFilterButton->setEnabled(EtwMode);
                     });
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

  QWidget *CreateDeviceControlCard() {
    auto *Card = new SimpleCardWidget;
    Card->setBorderRadius(5);
    auto *Layout = new QVBoxLayout(Card);
    Layout->setContentsMargins(16, 14, 16, 14);
    Layout->setSpacing(8);
    Layout->addWidget(MakeLabel("Device Filter & Blocking", 13, KTextPrimary,
                                QFont::DemiBold));

    auto *IdRow = new QHBoxLayout;
    ConfigureToolbarLayout(IdRow);
    DeviceHwIdEdit = new LineEdit;
    ConfigureLineEdit(DeviceHwIdEdit, "Hardware ID prefix (e.g. USB\\VID_0781)");
    DeviceInstanceEdit = new LineEdit;
    ConfigureLineEdit(DeviceInstanceEdit, "Instance / enumerator prefix");
    IdRow->addWidget(DeviceHwIdEdit, 2);
    IdRow->addWidget(DeviceInstanceEdit, 1);
    Layout->addLayout(IdRow);

    auto *VidRow = new QHBoxLayout;
    ConfigureToolbarLayout(VidRow);
    DeviceVendorIdEdit = new LineEdit;
    ConfigureLineEdit(DeviceVendorIdEdit, "VID (e.g. VID_0781)");
    DeviceVendorIdEdit->setMaxLength(7);
    DeviceProductIdEdit = new LineEdit;
    ConfigureLineEdit(DeviceProductIdEdit, "PID (e.g. PID_5583)");
    DeviceProductIdEdit->setMaxLength(7);
    DeviceClassEdit = new LineEdit;
    ConfigureLineEdit(DeviceClassEdit,
                      "Interface class GUID, empty = all classes");
    VidRow->addWidget(DeviceVendorIdEdit);
    VidRow->addWidget(DeviceProductIdEdit);
    VidRow->addWidget(DeviceClassEdit, 2);
    Layout->addLayout(VidRow);

    auto *FlagRow = new QHBoxLayout;
    ConfigureToolbarLayout(FlagRow);
    DeviceArrivalCheck = new CheckBox("Report arrival");
    DeviceArrivalCheck->setChecked(true);
    DeviceRemovalCheck = new CheckBox("Report removal");
    DeviceRemovalCheck->setChecked(true);
    DeviceBlockCheck =
        new CheckBox("Block matched devices (disable on arrival)");
    FlagRow->addWidget(DeviceArrivalCheck);
    FlagRow->addWidget(DeviceRemovalCheck);
    FlagRow->addWidget(DeviceBlockCheck);
    FlagRow->addStretch(1);
    Layout->addLayout(FlagRow);

    auto *ActionRow = new QHBoxLayout;
    ConfigureToolbarLayout(ActionRow);
    auto *ApplyButton = MakeButton("Apply Filter", true);
    auto *QueryButton = MakeButton("Query Current");
    auto *ClearButton = MakeButton("Clear Filter");
    DeviceFilterStatus = new BodyLabel(
        "No filter applied. Blocking disables the device interface on "
        "arrival; replug or re-enable it in Device Manager to recover.");
    DeviceFilterStatus->setWordWrap(true);
    ActionRow->addWidget(ApplyButton);
    ActionRow->addWidget(QueryButton);
    ActionRow->addWidget(ClearButton);
    ActionRow->addWidget(DeviceFilterStatus, 1);
    Layout->addLayout(ActionRow);

    QObject::connect(ApplyButton, &QPushButton::clicked, this,
                     [this] { ApplyDeviceFilter(); });
    QObject::connect(QueryButton, &QPushButton::clicked, this,
                     [this] { QueryDeviceFilter(); });
    QObject::connect(ClearButton, &QPushButton::clicked, this,
                     [this] { ClearDeviceFilter(); });
    return Card;
  }

  void CopyDeviceText(LineEdit *Edit, WCHAR *Target, ULONG Capacity) {
    const QString Text = Edit->text().trimmed();
    wcsncpy_s(Target, Capacity, (const WCHAR *)Text.utf16(), _TRUNCATE);
  }

  void ApplyDeviceFilter() {
    MonitorPnpFilter Filter{};
    Filter.Size = sizeof(MonitorPnpFilter);
    Filter.Version = MONITOR_PROTOCOL_VERSION;
    ULONG Flags = 0;
    if (DeviceArrivalCheck->isChecked())
      Flags |= MONITOR_PNP_FILTER_FLAG_ARRIVAL;
    if (DeviceRemovalCheck->isChecked())
      Flags |= MONITOR_PNP_FILTER_FLAG_REMOVAL;
    if (DeviceBlockCheck->isChecked())
      Flags |= MONITOR_PNP_FILTER_FLAG_BLOCK;
    Filter.Flags = Flags;
    const QString ClassText = DeviceClassEdit->text().trimmed();
    if (!ClassText.isEmpty()) {
      const QUuid Guid(ClassText);
      if (Guid.isNull()) {
        ShowErrorNotice(this, "Monitor", "Invalid interface class GUID.");
        return;
      }
      memcpy(&Filter.InterfaceClass, &Guid, sizeof(GUID));
      Filter.MatchAllInterfaces = FALSE;
    } else {
      Filter.MatchAllInterfaces = TRUE;
    }
    CopyDeviceText(DeviceHwIdEdit, Filter.HardwareIdPrefix,
                   RTL_NUMBER_OF(Filter.HardwareIdPrefix));
    CopyDeviceText(DeviceVendorIdEdit, Filter.VendorId,
                   RTL_NUMBER_OF(Filter.VendorId));
    CopyDeviceText(DeviceProductIdEdit, Filter.ProductId,
                   RTL_NUMBER_OF(Filter.ProductId));
    CopyDeviceText(DeviceInstanceEdit, Filter.InstancePrefix,
                   RTL_NUMBER_OF(Filter.InstancePrefix));
    if (!AegisSentinelSetPnpFilter(Filter, MONITOR_PNP_OP_SET_FILTER)) {
      ShowErrorNotice(this, "Monitor",
                      QString("Apply filter failed (error %1).")
                          .arg(GetLastError()));
      return;
    }
    DeviceFilterStatus->setText(
        DeviceBlockCheck->isChecked()
            ? QString("Blocking devices matching '%1' on arrival.")
                  .arg(DeviceHwIdEdit->text().trimmed().isEmpty()
                           ? "any hardware ID"
                           : DeviceHwIdEdit->text().trimmed())
            : "Filter applied (event reporting only).");
    ShowSuccessNotice(this, "Monitor", "Device filter applied.");
  }

  void QueryDeviceFilter() {
    MonitorPnpFilter Filter{};
    if (!AegisSentinelQueryPnpFilter(&Filter)) {
      ShowErrorNotice(this, "Monitor",
                      QString("Query filter failed (error %1).")
                          .arg(GetLastError()));
      return;
    }
    DeviceHwIdEdit->setText(QString::fromWCharArray(Filter.HardwareIdPrefix));
    DeviceVendorIdEdit->setText(QString::fromWCharArray(Filter.VendorId));
    DeviceProductIdEdit->setText(QString::fromWCharArray(Filter.ProductId));
    DeviceInstanceEdit->setText(QString::fromWCharArray(Filter.InstancePrefix));
    DeviceArrivalCheck->setChecked(
        (Filter.Flags & MONITOR_PNP_FILTER_FLAG_ARRIVAL) != 0);
    DeviceRemovalCheck->setChecked(
        (Filter.Flags & MONITOR_PNP_FILTER_FLAG_REMOVAL) != 0);
    DeviceBlockCheck->setChecked(
        (Filter.Flags & MONITOR_PNP_FILTER_FLAG_BLOCK) != 0);
    QStringList Parts;
    if (Filter.MatchAllInterfaces)
      Parts << "all classes";
    else
      Parts << "class " + QUuid(Filter.InterfaceClass).toString();
    Parts << (Filter.Flags & MONITOR_PNP_FILTER_FLAG_BLOCK ? "blocking ON"
                                                           : "blocking OFF");
    DeviceFilterStatus->setText("Current: " + Parts.join(", ") + ".");
  }

  void ClearDeviceFilter() {
    MonitorPnpFilter Filter{};
    Filter.Size = sizeof(MonitorPnpFilter);
    Filter.Version = MONITOR_PROTOCOL_VERSION;
    if (!AegisSentinelSetPnpFilter(Filter, MONITOR_PNP_OP_CLEAR_FILTER)) {
      ShowErrorNotice(this, "Monitor",
                      QString("Clear filter failed (error %1).")
                          .arg(GetLastError()));
      return;
    }
    DeviceHwIdEdit->clear();
    DeviceVendorIdEdit->clear();
    DeviceProductIdEdit->clear();
    DeviceInstanceEdit->clear();
    DeviceBlockCheck->setChecked(false);
    DeviceFilterStatus->setText(
        "Filter cleared; previously blocked devices must be re-enabled "
        "manually or replugged.");
    ShowSuccessNotice(this, "Monitor", "Device filter cleared.");
  }

  QWidget *CreateDevicesPage() {
    auto *Page = new QWidget;
    auto *Layout = new QVBoxLayout(Page);
    Layout->setContentsMargins(0, 0, 0, 0);
    Layout->setSpacing(KCompactPageSpacing);
    Layout->addWidget(CreateDeviceControlCard());
    auto *Controls = new QHBoxLayout;
    DeviceStart = MakeButton("Start", true);
    DeviceStop = MakeButton("Stop");
    DeviceStop->setEnabled(false);
    Statuses[4] = new BodyLabel("Stopped");
    Controls->addWidget(DeviceStart);
    Controls->addWidget(DeviceStop);
    Controls->addWidget(Statuses[4], 1);
    QObject::connect(DeviceStart, &QPushButton::clicked, this,
                     [this] { StartDevices(); });
    QObject::connect(DeviceStop, &QPushButton::clicked, this,
                     [this] { StopDevices(true); });
    Layout->addWidget(CreateEventPage(
                          4, Controls,
                          "Search device description, ID, or instance path"),
                      1);
    return Page;
  }

  void StartDevices() {
    if (DeviceRunning.exchange(true))
      return;
    Statuses[4]->setText("Starting...");
    QPointer<MonitorManagerPage> Page(this);
    std::thread([Page] {
      while (Page && Page->DeviceRunning) {
        MonitorSimpleEvent Evt{};
        if (AegisSentinelPopPnpEvent(&Evt)) {
          if (Page)
            PushMonitorEvent(Page->SharedState, 4,
                             Page->FormatDeviceEvent(Evt),
                             Page->FormatDeviceEventDetail(Evt));
        } else {
          Sleep(50);
        }
      }
    }).detach();
    Statuses[4]->setText("Listening for device arrival / removal...");
    DeviceStart->setEnabled(false);
    DeviceStop->setEnabled(true);
  }

  void StopDevices(bool Notify) {
    if (!DeviceRunning.exchange(false))
      return;
    DeviceStart->setEnabled(true);
    DeviceStop->setEnabled(false);
    Statuses[4]->setText("Stopped");
    if (Notify)
      ShowSuccessNotice(this, "Monitor", "Device monitoring stopped.");
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
    auto *Import = MakeButton("Import");
    auto *Export = MakeButton("Export");
    for (PushButton *Button : {Add, Remove, ClearAll, Refresh, Import, Export})
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
    ActionButtons->addWidget(Import);
    ActionButtons->addWidget(Export);
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
    QObject::connect(Import, &QPushButton::clicked, this,
                     [this] { ImportRules(); });
    QObject::connect(Export, &QPushButton::clicked, this,
                     [this] { ExportRules(); });
    UpdateRuleInputState();
    QTimer::singleShot(0, this, [this] { RestoreRulesFromConfig(); });
    return Page;
  }

  static QString FormatDeviceEvent(const MonitorSimpleEvent &Event) {
    const QString Description = Event.Path[0]
                                    ? QString::fromWCharArray(Event.Path)
                                    : QString();
    const QString DeviceId = Event.Extra[0]
                                 ? QString::fromWCharArray(Event.Extra)
                                 : QString();
    const QString Action =
        Event.Type == EventUsbDeviceArrival ? "Arrival" : "Removal";
    QString Text =
        QString("%1 | %2 | Device %3")
            .arg(MonitorTimestamp(Event.TimeStamp),
                 Action, Description.isEmpty() ? "Unknown device" : Description);
    if (DeviceId.isEmpty())
      Text += QString(" | PID %1").arg(Event.ProcessId);
    if (!DeviceId.isEmpty())
      Text += " | " + DeviceId;
    if (Event.Data2 != 0 || (Event.Flags2 & MONITOR_FLAG2_BLOCKED))
      Text += " | BLOCKED";
    return Text;
  }

  // 设备事件详情：注意单行文本的行尾被右键“Block by this device ID”解析，
  // 因此实例路径/类别 GUID 只能进详情弹窗，不能追加到单行尾部。
  static QString FormatDeviceEventDetail(const MonitorSimpleEvent &Event) {
    QStringList Lines;
    Lines << QString("Timestamp      : %1").arg(MonitorTimestamp(Event.TimeStamp));
    Lines << QString("Type           : %1")
                 .arg(QString::fromWCharArray(EventTypeToString(Event.Type)));
    if (Event.Path[0])
      Lines << QString("Description    : %1").arg(QString::fromWCharArray(Event.Path));
    if (Event.Extra[0])
      Lines << QString("Hardware / ID  : %1").arg(QString::fromWCharArray(Event.Extra));
    // Name[] = 真实设备实例路径（SymbolicLinkName）
    if (Event.Name[0])
      Lines << QString("Instance path  : %1").arg(QString::fromWCharArray(Event.Name));
    if (Event.DataBytes >= sizeof(GUID)) {
      const GUID *ClassGuid = reinterpret_cast<const GUID *>(Event.Data);
      Lines << QString("Interface class: {%1-%2-%3-%4-%5}")
                   .arg(ClassGuid->Data1, 8, 16, QLatin1Char('0'))
                   .arg(ClassGuid->Data2, 4, 16, QLatin1Char('0'))
                   .arg(ClassGuid->Data3, 4, 16, QLatin1Char('0'))
                   .arg([&] {
                     QString Out;
                     for (int i = 0; i < 2; ++i)
                       Out += QString("%1").arg(ClassGuid->Data4[i], 2, 16, QLatin1Char('0'));
                     return Out;
                   }())
                   .arg([&] {
                     QString Out;
                     for (int i = 2; i < 8; ++i)
                       Out += QString("%1").arg(ClassGuid->Data4[i], 2, 16, QLatin1Char('0'));
                     return Out;
                   }())
                   .toUpper();
    }
    if (Event.Data2 != 0 || (Event.Flags2 & MONITOR_FLAG2_BLOCKED))
      Lines << QString("State          : blocked (interface disabled)");
    return Lines.join('\n');
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
    MonitorRule Rule{};
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
    RulesDirty = true;
    RefreshRules();
  }

  void RemoveSelectedRule() {
    const int Row = RulesTable ? RulesTable->currentRow() : -1;
    if (Row < 0 || Row >= static_cast<int>(Rules.size())) {
      ShowErrorNotice(this, "Monitor", "Select a rule first.");
      return;
    }
    MonitorRule Rule{};
    Rule.Id = Rules[static_cast<size_t>(Row)].Id;
    if (!AegisSentinelOperateRule(MonitorRuleRemove, &Rule)) {
      ShowErrorNotice(this, "Monitor", QString("Failed to remove rule (error %1).").arg(GetLastError()));
      return;
    }
    ShowSuccessNotice(this, "Monitor", "Rule removed.");
    RulesDirty = true;
    RefreshRules();
  }

  void ClearRules() {
    if (!ShowConfirmDialog(this, "Clear rules", "Remove all monitor rules?", "Yes", "No"))
      return;
    if (!AegisSentinelOperateRule(MonitorRuleClear)) {
      ShowErrorNotice(this, "Monitor", QString("Failed to clear rules (error %1).").arg(GetLastError()));
      return;
    }
    ShowSuccessNotice(this, "Monitor", "All monitor rules were removed.");
    RulesDirty = true;
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
      MonitorRuleList List{};
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

  static QJsonArray RulesToJson(const std::vector<MonitorRule> &List) {
    QJsonArray Array;
    for (const MonitorRule &Rule : List) {
      QJsonObject Obj;
      Obj["type"] = static_cast<int>(Rule.Type);
      Obj["action"] = static_cast<int>(Rule.Action);
      Obj["pid"] = static_cast<qint64>(Rule.ProcessId);
      Obj["protocol"] = static_cast<int>(Rule.Protocol);
      Obj["port"] = static_cast<int>(Rule.RemotePort);
      Obj["target"] = QString::fromWCharArray(Rule.Target);
      Array.append(Obj);
    }
    return Array;
  }

  static std::vector<MonitorRule> RulesFromJson(const QJsonArray &Array) {
    std::vector<MonitorRule> List;
    for (const auto &Value : Array) {
      const QJsonObject Obj = Value.toObject();
      MonitorRule Rule{};
      Rule.Type = static_cast<MonitorRuleType>(Obj["type"].toInt(1));
      Rule.Action = static_cast<MonitorRuleAction>(Obj["action"].toInt(1));
      Rule.ProcessId = static_cast<ULONG>(Obj["pid"].toInteger());
      Rule.Protocol = static_cast<ULONG>(Obj["protocol"].toInt());
      Rule.RemotePort = static_cast<ULONG>(Obj["port"].toInt());
      const QString Target = Obj["target"].toString();
      if (!Target.isEmpty())
        wcsncpy_s(Rule.Target, Target.toStdWString().c_str(), _TRUNCATE);
      List.push_back(Rule);
    }
    return List;
  }

  void PersistRulesIfDirty() {
    if (!RulesDirty)
      return;
    RulesDirty = false;
    SetConfigurationValue("Monitor", "RulesV3", RulesToJson(Rules));
  }

  void RestoreRulesFromConfig() {
    const QJsonArray Saved =
        ConfigurationValue("Monitor", "RulesV3", QJsonArray()).toArray();
    if (Saved.isEmpty())
      return;
    // 仅在内核当前没有规则时恢复,避免重复下发或覆盖运行态。
    MonitorRuleList Current{};
    if (AegisSentinelEnumerateRules(&Current) && Current.Count > 0) {
      RulesStatus->setText(
          QString("Rules: %1 (config restore skipped, kernel already has rules)")
              .arg(Current.Count));
      return;
    }
    for (const MonitorRule &Rule : RulesFromJson(Saved))
      AegisSentinelOperateRule(MonitorRuleAdd, &Rule);
    RefreshRules();
  }

  void ExportRules() {
    const QString Path = QFileDialog::getSaveFileName(
        this, "Export monitor rules", "monitor-rules.json", "JSON (*.json)");
    if (Path.isEmpty())
      return;
    QSaveFile File(Path);
    if (File.open(QIODevice::WriteOnly) &&
        File.write(QJsonDocument(RulesToJson(Rules)).toJson()) != -1) {
      File.commit();
      ShowSuccessNotice(this, "Monitor", "Rules exported.");
    } else {
      ShowErrorNotice(this, "Monitor",
                      "Failed to export rules: " + File.errorString());
    }
  }

  void ImportRules() {
    const QString Path = QFileDialog::getOpenFileName(
        this, "Import monitor rules", {}, "JSON (*.json)");
    if (Path.isEmpty())
      return;
    QFile File(Path);
    if (!File.open(QIODevice::ReadOnly)) {
      ShowErrorNotice(this, "Monitor",
                      "Failed to open file: " + File.errorString());
      return;
    }
    const QJsonDocument Doc = QJsonDocument::fromJson(File.readAll());
    if (!Doc.isArray()) {
      ShowErrorNotice(this, "Monitor", "Invalid rules JSON (array expected).");
      return;
    }
    ULONG Added = 0;
    for (const MonitorRule &Rule : RulesFromJson(Doc.array())) {
      if (AegisSentinelOperateRule(MonitorRuleAdd, &Rule))
        ++Added;
    }
    ShowSuccessNotice(this, "Monitor",
                      QString("Imported %1 rule(s).").arg(Added));
    RulesDirty = true;
    RefreshRules();
  }

  void PopulateRules() {
    SetTableRefreshEnabled(RulesTable, false);
    RulesTable->clearContents();
    RulesTable->setRowCount(static_cast<int>(Rules.size()));
    for (int Row = 0; Row < static_cast<int>(Rules.size()); ++Row) {
      const MonitorRule &Rule = Rules[static_cast<size_t>(Row)];
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
    PersistRulesIfDirty();
  }

  void Populate(int Index) {
    if (Index < 0 || Index >= KMonitorStreamCount || !Tables[Index])
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
    auto *Table = Tables[Index];
    QStringList &Keys = DisplayedKeys[Index];
    const auto RebuildKeys = [VisibleRows, &Keys] {
      QStringList NewKeys;
      NewKeys.reserve(static_cast<int>(VisibleRows.size()));
      for (const MonitorEventRow *Event : VisibleRows)
        NewKeys.append(Event->Text);
      Keys = std::move(NewKeys);
    };

    // 事件只从头部插入、尾部溢出删除：先尝试只插入新增的头部行，
    // 避免每 150ms 全表丢弃并重建 500 个 QTableWidgetItem。
    if (Query.isEmpty() && !Keys.isEmpty() && !VisibleRows.empty() &&
        Table->rowCount() == Keys.size()) {
      int NewCount = -1;
      for (int I = 0; I < static_cast<int>(VisibleRows.size()); ++I) {
        if (VisibleRows[I]->Text == Keys.first()) {
          NewCount = I;
          break;
        }
      }
      if (NewCount == 0)
        return;
      if (NewCount > 0) {
        const int TailCount = std::min<int>(
            Keys.size(), static_cast<int>(VisibleRows.size()) - NewCount);
        bool Aligned = TailCount > 0;
        for (int J = 0; Aligned && J < TailCount; ++J) {
          if (VisibleRows[NewCount + J]->Text != Keys[J])
            Aligned = false;
        }
        if (Aligned) {
          SetTableRefreshEnabled(Table, false);
          for (int NewRow = 0; NewRow < NewCount; ++NewRow)
            Table->insertRow(0);
          for (int Row = NewCount - 1; Row >= 0; --Row) {
            auto *Item = new QTableWidgetItem(VisibleRows[Row]->Text);
            Item->setData(Qt::UserRole, VisibleRows[Row]->Detail);
            Table->setItem(Row, 0, Item);
            Table->setRowHeight(Row, KCompactTableRowHeight);
          }
          Table->setRowCount(static_cast<int>(VisibleRows.size()));
          SetTableRefreshEnabled(Table, true);
          RebuildKeys();
          return;
        }
      }
    }

    SetTableRefreshEnabled(Table, false);
    Table->clearContents();
    Table->setRowCount(static_cast<int>(VisibleRows.size()));
    for (int Row = 0; Row < static_cast<int>(VisibleRows.size()); ++Row) {
      const MonitorEventRow &Event = *VisibleRows[Row];
      auto *Item = new QTableWidgetItem(Event.Text);
      Item->setData(Qt::UserRole, Event.Detail);
      Table->setItem(Row, 0, Item);
      Table->setRowHeight(Row, KCompactTableRowHeight);
    }
    SetTableRefreshEnabled(Table, true);
    RebuildKeys();
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
    if (Index == 4) {
      auto *Block = new QAction("Block by this device ID...", Menu);
      Menu->addAction(Block);
      QObject::connect(Block, &QAction::triggered, this,
                       [this, Row = ModelIndex.row()] {
                         auto *Item = Tables[4]->item(Row, 0);
                         if (!Item)
                           return;
                         const QString Text = Item->text();
                         const int Separator = Text.lastIndexOf(" | ");
                         QString DeviceId =
                             Separator >= 0 ? Text.mid(Separator + 3) : Text;
                         if (DeviceId == "BLOCKED" || DeviceId.startsWith("PID ")) {
                           ShowWarningNotice(
                               this, "Monitor",
                               "This event has no usable device ID.");
                           return;
                         }
                         DeviceHwIdEdit->setText(DeviceId);
                         DeviceBlockCheck->setChecked(true);
                         ShowSuccessNotice(
                             this, "Monitor",
                             "Device ID prefilled; press Apply Filter to "
                             "block matching devices.");
                       });
    }
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
    Dialog->resize(940, 650);
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
    ApplyDialogTheme(Dialog);
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
    if (!Event.ProviderName.empty())
      Text += " | Provider " + QString::fromStdWString(Event.ProviderName);
    if (Event.EventId)
      Text += QString(" | Id %1").arg(Event.EventId);
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
    if (!Event.LocalAddress.empty())
      Text += QString(" | Local %1:%2")
                  .arg(QString::fromStdWString(Event.LocalAddress))
                  .arg(Event.LocalPort);
    if (!Event.RemoteAddress.empty())
      Text += QString(" | Remote %1:%2")
                  .arg(QString::fromStdWString(Event.RemoteAddress))
                  .arg(Event.RemotePort);
    if (Event.InterfaceIndex)
      Text += QString(" | If %1").arg(Event.InterfaceIndex);
    if (Event.DataSize)
      Text += QString(" | Size %1").arg(Event.DataSize);
    return Text;
  }

  // 注册表值类型名（REG_*）
  static QString RegistryTypeName(ULONG Type) {
    switch (Type) {
    case REG_SZ: return "REG_SZ";
    case REG_EXPAND_SZ: return "REG_EXPAND_SZ";
    case REG_BINARY: return "REG_BINARY";
    case REG_DWORD: return "REG_DWORD";
    case REG_DWORD_BIG_ENDIAN: return "REG_DWORD_BIG_ENDIAN";
    case REG_LINK: return "REG_LINK";
    case REG_MULTI_SZ: return "REG_MULTI_SZ";
    case REG_RESOURCE_LIST: return "REG_RESOURCE_LIST";
    case REG_FULL_RESOURCE_DESCRIPTOR: return "REG_FULL_RESOURCE_DESCRIPTOR";
    case REG_RESOURCE_REQUIREMENTS_LIST: return "REG_RESOURCE_REQUIREMENTS_LIST";
    case REG_QWORD: return "REG_QWORD";
    default: return QString("REG_0x%1").arg(Type, 0, 16).toUpper();
    }
  }

  // 按值类型渲染注册表原始数据（Data[]/DataBytes 由驱动采集，全类型）
  static QString RegistryDataText(const MonitorEvent &Event, int MaxChars) {
    if (Event.DataBytes == 0)
      return QString();
    const UCHAR *Data = Event.Data;
    const ULONG Bytes = Event.DataBytes;
    const ULONG Type = Event.DataType;
    const auto HexDump = [&](ULONG Limit) {
      QString Out;
      const ULONG Count = qMin(Bytes, Limit);
      for (ULONG i = 0; i < Count; ++i)
        Out += QString("%1 ").arg(Data[i], 2, 16, QLatin1Char('0'));
      if (Count < Bytes) Out += "…";
      return Out.trimmed().toUpper();
    };
    if (Type == REG_SZ || Type == REG_EXPAND_SZ) {
      const int Chars = static_cast<int>(Bytes / sizeof(WCHAR));
      QString Text = QString::fromWCharArray(reinterpret_cast<const wchar_t *>(Data), Chars);
      Text.replace(QChar('\0'), QChar(' '));
      if (MaxChars > 0 && Text.size() > MaxChars)
        Text = Text.left(MaxChars) + "…";
      return Text.trimmed();
    }
    if (Type == REG_MULTI_SZ) {
      const int Chars = static_cast<int>(Bytes / sizeof(WCHAR));
      const QString Raw = QString::fromWCharArray(reinterpret_cast<const wchar_t *>(Data), Chars);
      QStringList Parts = Raw.split(QChar('\0'), Qt::SkipEmptyParts);
      QString Text = Parts.join(" | ");
      if (MaxChars > 0 && Text.size() > MaxChars)
        Text = Text.left(MaxChars) + "…";
      return Text;
    }
    if (Type == REG_DWORD && Bytes >= sizeof(ULONG)) {
      ULONG Value = 0;
      memcpy(&Value, Data, sizeof(Value));
      return QString("%1 (0x%2)")
          .arg(Value)
          .arg(Value, 0, 16)
          .toUpper();
    }
    if (Type == REG_QWORD && Bytes >= sizeof(ULONGLONG)) {
      ULONGLONG Value = 0;
      memcpy(&Value, Data, sizeof(Value));
      return QString("%1 (0x%2)")
          .arg(Value)
          .arg(Value, 0, 16)
          .toUpper();
    }
    return HexDump(MaxChars > 0 ? static_cast<ULONG>(MaxChars / 3) : 32);
  }

  // 网络事件地址：驱动把本地/远端地址放在 Data[] 的前 16/后 16 字节
  static QString NetworkAddressPair(const MonitorEvent &Event) {
    if (Event.DataBytes < 32) return QString();
    const auto IsZero = [&](int Offset) {
      for (int i = 0; i < 16; ++i)
        if (Event.Data[Offset + i] != 0) return false;
      return true;
    };
    const bool IsIpv4 = IsZero(4) && IsZero(20);   // 后 12 字节全 0 → IPv4
    const auto AddrText = [&](int Offset, bool V4) {
      if (V4)
        return QString("%1.%2.%3.%4")
            .arg(Event.Data[Offset + 0])
            .arg(Event.Data[Offset + 1])
            .arg(Event.Data[Offset + 2])
            .arg(Event.Data[Offset + 3]);
      QStringList Groups;
      for (int i = 0; i < 16; i += 2)
        Groups << QString("%1")
                      .arg((Event.Data[Offset + i] << 8) | Event.Data[Offset + i + 1],
                           4, 16, QLatin1Char('0'));
      return Groups.join(':').toUpper();
    };
    const QString Local = AddrText(0, IsIpv4);
    const QString Remote = AddrText(16, IsIpv4);
    if (Local.isEmpty() && Remote.isEmpty()) return QString();
    return QString("%1:%2 -> %3:%4")
        .arg(Local)
        .arg(Event.Value1 & 0xFFFF)
        .arg(Remote)
        .arg(Event.Value2 & 0xFFFF);
  }

  // 内核回调地址：模块名 + 完整地址。
  // 注意：模块基址在用户态不可靠（可能被 unload / 地址随机化），
  // 所以这里不做偏移换算，只给出可交叉验证的绝对地址。
  static QString CallbackAddressText(const MonitorEvent &Event) {
    const QString Module =
        Event.Path[0] ? QString::fromWCharArray(Event.Path) : QString();
    const QString Address =
        QString("0x%1").arg(Event.Address, 0, 16).toUpper();
    if (Module.isEmpty() || Module == "<unknown>")
      return Address;
    return QString("%1 @ %2").arg(Module, Address);
  }

  static QString FormatKernelEvent(const MonitorSimpleEvent &Event) {
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

  // 按事件类型追加富字段（父进程路径、注册表键值、签名等级、重命名目标、设备实例路径…）。
  // 注意：前 3 个 `" | "` 段必须保持「时间 | 类型 | 进程」顺序，History 依赖该分段解析。
  static QString KernelEventTypeDetails(const MonitorEvent &Event) {
    QString Text;
    const bool Truncated = (Event.Flags & MONITOR_EVENT_FLAG_TRUNCATED) != 0;

    switch (Event.Type) {
    case EventProcessCreate: {
      if (Event.Name[0])
        Text += QString(" | Parent %1").arg(QString::fromWCharArray(Event.Name));
      if (Event.TargetPath[0])
        Text += QString(" | Parent path %1").arg(QString::fromWCharArray(Event.TargetPath));
      if (Event.CreatorPid)
        Text += QString(" | Creator PID %1").arg(Event.CreatorPid);
      if (Event.Flags2 & MONITOR_FLAG2_CREATOR_DIFFERS)
        Text += " | creator differs from parent";
      if (Event.Flags2 & MONITOR_FLAG2_SUBSYSTEM_PROCESS)
        Text += " | subsystem process";
      break;
    }
    case EventThreadCreate:
      if (Event.Name[0])
        Text += QString(" | Host %1").arg(QString::fromWCharArray(Event.Name));
      if (Event.Flags2 & MONITOR_FLAG2_CREATOR_DIFFERS)
        Text += QString(" | Creator PID %1 (remote)").arg(Event.CreatorPid);
      break;
    case EventProcessExit:
    case EventThreadExit:
      // 退出事件也带映像名（驱动在回调里采集，此时进程仍可查）
      if (Event.Name[0])
        Text += QString(" | Image %1").arg(QString::fromWCharArray(Event.Name));
      break;
    case EventImageLoad:
    case EventDriverLoad:
    case EventDriverUnload:
      if (Event.Name[0])
        Text += QString(" | Module %1").arg(QString::fromWCharArray(Event.Name));
      if (Event.SizeBytes)
        Text += QString(" | Image size %1").arg(Event.SizeBytes);
      if (Event.Value1 || Event.Value2)
        Text += QString(" | Signature level %1 type %2").arg(Event.Value1).arg(Event.Value2);
      if (Event.Flags2 & MONITOR_FLAG2_SYSTEM_MODE_IMAGE)
        Text += " | kernel-mode image";
      break;
    case EventRegistryOperation: {
      if (Event.Name[0])
        Text += QString(" | Value %1").arg(QString::fromWCharArray(Event.Name));
      if (Event.DataType)
        Text += QString(" | %1").arg(RegistryTypeName(Event.DataType));
      const QString Data = RegistryDataText(Event, 96);
      if (!Data.isEmpty())
        Text += QString(" | Value data %1").arg(Data);
      if (Truncated) Text += " | data truncated";
      break;
    }
    case EventHandleOperation:
      if (Event.Name[0])
        Text += QString(" | Object %1").arg(QString::fromWCharArray(Event.Name));
      if (Event.Value1)
        Text += QString(" | Requested 0x%1")
                    .arg(static_cast<quint32>(Event.Value1), 0, 16)
                    .toUpper();
      if (Event.Flags2 & MONITOR_FLAG2_KERNEL_HANDLE)
        Text += " | kernel handle";
      if (Event.Flags2 & MONITOR_FLAG2_TARGET_IS_THREAD)
        Text += " | target is thread";
      break;
    case EventFileOperation:
    case EventFileCapture:
      if (Event.CreatorPid && Event.CreatorPid != Event.ProcessId)
        Text += QString(" | Requestor PID %1").arg(Event.CreatorPid);
      if (Event.Type == EventFileCapture) {
        if (Event.SizeBytes)
          Text += QString(" | Write %1 bytes").arg(Event.SizeBytes);
        if (Event.Offset)
          Text += QString(" | Offset 0x%1").arg(Event.Offset, 0, 16).toUpper();
      } else {
        // DataType = FILE_INFORMATION_CLASS（SetInformation 场景）。这里用数值常量：
        // FILE_INFORMATION_CLASS 只在内核头里定义，用户态按值匹配。
        // 10=FileRenameInformation, 65=FileRenameInformationEx,
        // 13=FileDispositionInformation, 64=FileDispositionInformationEx
        if (Event.DataType) {
          const ULONG InfoClass = Event.DataType;
          const QString Name =
              (InfoClass == 10 || InfoClass == 65)
                  ? QString("Rename")
                  : (InfoClass == 13 || InfoClass == 64)
                        ? QString("Delete")
                        : (InfoClass == 4 ? QString("Delete (basic)")
                                          : QString("Class %1").arg(InfoClass));
          Text += QString(" | %1").arg(Name);
        }
        if (Event.TargetPath[0])
          Text += QString(" | Rename to %1").arg(QString::fromWCharArray(Event.TargetPath));
        if (Event.Value1)
          Text += QString(" | Access 0x%1")
                      .arg(static_cast<quint32>(Event.Value1), 0, 16)
                      .toUpper();
      }
      break;
    case EventNetworkConnect:
    case EventNetworkAccept:
    case EventDnsQuery:
    case EventHttpRequest: {
      const QString Pair = NetworkAddressPair(Event);
      if (!Pair.isEmpty())
        Text += QString(" | %1").arg(Pair);
      else if (Event.Value1 || Event.Value2)
        Text += QString(" | Local %1 | Remote %2").arg(Event.Value1).arg(Event.Value2);
      if (Event.DataBytes >= 32 && Event.Path[0])
        Text += QString(" | Family %1").arg(QString::fromWCharArray(Event.Path));
      if (Event.Name[0])
        Text += QString(" | Process path %1").arg(QString::fromWCharArray(Event.Name));
      if (Event.Flags2 & MONITOR_FLAG2_BLOCKED)
        Text += " | blocked";
      break;
    }
    case EventServiceStateChange: {
      const QString Op = Event.Operation == MONITOR_SERVICE_OP_REGISTERED
                             ? QString("registered")
                             : Event.Operation == MONITOR_SERVICE_OP_REMOVED
                                   ? QString("removed")
                                   : Event.Operation == MONITOR_SERVICE_OP_START
                                         ? QString("start state changed")
                                         : QString("changed");
      Text += QString(" | Service %1").arg(Op);
      if (Event.Name[0])
        Text += QString(" | %1").arg(QString::fromWCharArray(Event.Name));
      if (Event.Operation == MONITOR_SERVICE_OP_START && Event.Value1)
        Text += QString(" | Start type %1").arg(Event.Value1);
      break;
    }
    case EventCallbackChange:
      if (Event.Name[0])
        Text += QString(" | Source %1").arg(QString::fromWCharArray(Event.Name));
      if (Event.Address)
        Text += QString(" | %1").arg(CallbackAddressText(Event));
      break;
    case EventUsbDeviceArrival:
    case EventUsbDeviceRemoval:
      if (Event.Name[0])
        Text += QString(" | Instance %1").arg(QString::fromWCharArray(Event.Name));
      if (Event.Flags2 & MONITOR_FLAG2_BLOCKED)
        Text += " | blocked";
      break;
    case EventProcessInject:
      if (Event.Name[0])
        Text += QString(" | Target %1").arg(QString::fromWCharArray(Event.Name));
      if (Event.CreatorPid)
        Text += QString(" | Creator PID %1").arg(Event.CreatorPid);
      break;
    default:
      break;
    }
    return Text;
  }

  static QString FormatKernelMonitorEvent(const MonitorEvent &Event) {
    // 优先用驱动带出的映像名（退出事件里进程已消失，OpenProcess 反查会失败）
    std::wstring ProcessName;
    if (Event.Name[0] &&
        (Event.Type == EventProcessExit || Event.Type == EventThreadExit ||
         Event.Type == EventProcessCreate || Event.Type == EventThreadCreate))
      ProcessName = Event.Name;
    if (ProcessName.empty())
      ProcessName = GetProcessNameFromPid(Event.ProcessId);
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
    if (Event.Address && Event.Type != EventCallbackChange)
      Text += QString(" | Address 0x%1").arg(Event.Address, 0, 16).toUpper();
    if (Event.SizeBytes && Event.Type != EventFileCapture &&
        Event.Type != EventImageLoad && Event.Type != EventDriverLoad &&
        Event.Type != EventDriverUnload)
      Text += QString(" | Size %1").arg(Event.SizeBytes);
    // 按类型补充富字段（父进程路径 / 注册表键值 / 签名等级 / 重命名目标 / 设备实例路径…）
    Text += KernelEventTypeDetails(Event);
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

  // 结构化详情（双击/右键“详细信息”弹窗内容）——把全部字段逐行铺开，便于复制分析。
  static QString FormatKernelMonitorEventDetail(const MonitorEvent &Event) {
    std::wstring ProcessName;
    if (Event.Name[0] &&
        (Event.Type == EventProcessExit || Event.Type == EventThreadExit ||
         Event.Type == EventProcessCreate || Event.Type == EventThreadCreate))
      ProcessName = Event.Name;
    if (ProcessName.empty())
      ProcessName = GetProcessNameFromPid(Event.ProcessId);
    QStringList Lines;
    Lines << QString("Timestamp      : %1").arg(MonitorTimestamp(Event.TimeStamp));
    Lines << QString("Sequence       : %1").arg(Event.Sequence);
    Lines << QString("Type           : %1 (%2)")
                 .arg(QString::fromWCharArray(
                     EventTypeToString(static_cast<MonitorEventType>(Event.Type))))
                 .arg(Event.Type);
    Lines << QString("Process        : %1 (PID %2)")
                 .arg(ProcessName.empty() ? QString("<unknown>")
                                          : QString::fromStdWString(ProcessName))
                 .arg(Event.ProcessId);
    Lines << QString("Thread         : TID %1").arg(Event.ThreadId);
    if (Event.ParentPid) Lines << QString("Parent PID     : %1").arg(Event.ParentPid);
    if (Event.Name[0]) Lines << QString("Name           : %1").arg(QString::fromWCharArray(Event.Name));
    if (Event.CreatorPid || Event.CreatorTid)
      Lines << QString("Creator        : PID %1 TID %2").arg(Event.CreatorPid).arg(Event.CreatorTid);
    if (Event.TargetProcessId)
      Lines << QString("Target PID     : %1").arg(Event.TargetProcessId);
    if (Event.TargetThreadId)
      Lines << QString("Target TID     : %1").arg(Event.TargetThreadId);
    if (Event.TargetPath[0])
      Lines << QString("Target path    : %1").arg(QString::fromWCharArray(Event.TargetPath));
    if (Event.Address)
      Lines << QString("Address        : 0x%1").arg(Event.Address, 0, 16).toUpper();
    if (Event.SizeBytes) Lines << QString("Size           : %1").arg(Event.SizeBytes);
    if (Event.Offset) Lines << QString("Offset         : 0x%1").arg(Event.Offset, 0, 16).toUpper();
    if (Event.Operation || Event.Value1 || Event.Value2) {
      Lines << QString("Operation      : %1").arg(Event.Operation);
      Lines << QString("Value1         : %1 (0x%2)")
                   .arg(Event.Value1)
                   .arg(Event.Value1, 0, 16)
                   .toUpper();
      Lines << QString("Value2         : %1 (0x%2)")
                   .arg(Event.Value2)
                   .arg(Event.Value2, 0, 16)
                   .toUpper();
    }
    if (Event.DataType && Event.Type == EventRegistryOperation)
      Lines << QString("Value type     : %1").arg(RegistryTypeName(Event.DataType));
    else if (Event.DataType)
      Lines << QString("DataType       : %1").arg(Event.DataType);
    if (Event.Path[0]) Lines << QString("Path           : %1").arg(QString::fromWCharArray(Event.Path));
    if (Event.Extra[0]) Lines << QString("Extra          : %1").arg(QString::fromWCharArray(Event.Extra));
    if (Event.Flags2) {
      QStringList Flags;
      if (Event.Flags2 & MONITOR_FLAG2_KERNEL_HANDLE) Flags << "kernel handle";
      if (Event.Flags2 & MONITOR_FLAG2_SYSTEM_MODE_IMAGE) Flags << "system-mode image";
      if (Event.Flags2 & MONITOR_FLAG2_SUBSYSTEM_PROCESS) Flags << "subsystem process";
      if (Event.Flags2 & MONITOR_FLAG2_CREATOR_DIFFERS) Flags << "creator differs";
      if (Event.Flags2 & MONITOR_FLAG2_TARGET_IS_THREAD) Flags << "target is thread";
      if (Event.Flags2 & MONITOR_FLAG2_BLOCKED) Flags << "blocked";
      if (Event.Flags2 & MONITOR_FLAG2_FILE_CAPTURE) Flags << "file capture";
      if (Event.Flags2 & MONITOR_FLAG2_DATA_TRUNCATED) Flags << "data truncated";
      Lines << QString("Flags          : %1").arg(Flags.join(", "));
    }
    // 原始负载：注册表按类型渲染，其它类型给十六进制，便于离线分析
    if (Event.DataBytes != 0) {
      const bool IsRegistry = Event.Type == EventRegistryOperation;
      if (IsRegistry) {
        const QString Data = RegistryDataText(Event, 0);
        if (!Data.isEmpty()) Lines << QString("Value data     : %1").arg(Data);
      }
      Lines << QString("Data (%1 bytes) : %2")
                   .arg(Event.DataBytes)
                   .arg([&] {
                     QString Hex;
                     for (ULONG i = 0; i < Event.DataBytes; ++i)
                       Hex += QString("%1 ").arg(Event.Data[i], 2, 16, QLatin1Char('0'));
                     return Hex.trimmed().toUpper();
                   }());
    }
    if (Event.Status)
      Lines << QString("Status         : 0x%1")
                   .arg(static_cast<quint32>(Event.Status), 8, 16, QLatin1Char('0'))
                   .toUpper();
    return Lines.join('\n');
  }

  void ShowEtwProvidersDialog() {
    auto *Dialog = new QDialog(this);
    Dialog->setAttribute(Qt::WA_DeleteOnClose);
    Dialog->setWindowTitle("ETW Providers");
    Dialog->resize(580, 610);
    auto *Layout = new QVBoxLayout(Dialog);

    std::vector<EtwProvider> Current;
    {
      std::lock_guard<std::mutex> Lock(EtwStateMutex);
      Current = SelectedProviders;
    }

    auto *List = new ListWidget(Dialog);
    InstallFluentScrollBar(List, Qt::Vertical);
    auto *Catalog = new std::vector<EtwProvider>;
    auto AddRow = [List, Catalog](const EtwProvider &Provider,
                                  bool Checked) {
      auto *Item = new QListWidgetItem(
          QString("%1  %2")
              .arg(QString::fromStdWString(Provider.Name),
                   EtwGuidToString(Provider.Guid)),
          List);
      Item->setFlags(Item->flags() | Qt::ItemIsUserCheckable);
      Item->setCheckState(Checked ? Qt::Checked : Qt::Unchecked);
      Item->setData(Qt::UserRole, (int)Catalog->size());
      Catalog->push_back(Provider);
    };
    auto IsSelected = [&Current](const EtwProvider &Provider) {
      return std::any_of(Current.begin(), Current.end(),
                         [&Provider](const EtwProvider &Selected) {
                           return Selected.Guid == Provider.Guid;
                         });
    };
    auto *KernelGroup = new QListWidgetItem("Kernel providers", List);
    KernelGroup->setFlags(Qt::ItemIsEnabled);
    for (int I = 0; I < KProviderCount; ++I)
      AddRow(KProviders[I], IsSelected(KProviders[I]));
    auto *SystemGroup = new QListWidgetItem("System providers", List);
    SystemGroup->setFlags(Qt::ItemIsEnabled);
    for (int I = 0; I < KSystemProviderCount; ++I)
      AddRow(KSystemProviders[I], IsSelected(KSystemProviders[I]));

    auto *EnumerateButton = MakeButton("Enumerate system providers...");
    QObject::connect(EnumerateButton, &QPushButton::clicked, Dialog,
                     [Dialog, List, Catalog] {
                       std::vector<EtwProvider> Found;
                       if (!EnumerateSystemProviders(Found)) {
                         ShowErrorNotice(Dialog, "ETW Providers",
                                         "Failed to enumerate system "
                                         "providers (TdhEnumerateProviders).");
                         return;
                       }
                       int Added = 0;
                       for (const EtwProvider &Provider : Found) {
                         const bool Exists = std::any_of(
                             Catalog->begin(), Catalog->end(),
                             [&Provider](const EtwProvider &Known) {
                               return Known.Guid == Provider.Guid;
                             });
                         if (Exists)
                           continue;
                         auto *Item = new QListWidgetItem(
                             QString("%1  %2")
                                 .arg(QString::fromStdWString(Provider.Name),
                                      EtwGuidToString(Provider.Guid)),
                             List);
                         Item->setFlags(Item->flags() |
                                        Qt::ItemIsUserCheckable);
                         Item->setCheckState(Qt::Unchecked);
                         Item->setData(Qt::UserRole, (int)Catalog->size());
                         Catalog->push_back(Provider);
                         ++Added;
                       }
                       ShowSuccessNotice(
                           Dialog, "ETW Providers",
                           QString("Found %1 system provider(s); %2 new.")
                               .arg(Found.size())
                               .arg(Added));
                     });

    auto *ButtonRow = new QHBoxLayout;
    ButtonRow->addStretch();
    auto *OkButton = MakeButton("OK", true);
    auto *CancelButton = MakeButton("Cancel");
    ButtonRow->addWidget(OkButton);
    ButtonRow->addWidget(CancelButton);
    QObject::connect(OkButton, &QPushButton::clicked, Dialog, &QDialog::accept);
    QObject::connect(CancelButton, &QPushButton::clicked, Dialog,
                     &QDialog::reject);
    QObject::connect(Dialog, &QDialog::accepted, this, [this, List, Catalog] {
      std::vector<EtwProvider> Selected;
      for (int Row = 0; Row < List->count(); ++Row) {
        QListWidgetItem *Item = List->item(Row);
        if (!(Item->flags() & Qt::ItemIsUserCheckable))
          continue;
        const int CatalogIndex = Item->data(Qt::UserRole).toInt();
        if (CatalogIndex < 0 || CatalogIndex >= (int)Catalog->size())
          continue;
        if (Item->checkState() == Qt::Checked)
          Selected.push_back((*Catalog)[(size_t)CatalogIndex]);
      }
      if (Selected.empty()) {
        ShowWarningNotice(this, "ETW Providers",
                          "Select at least one provider.");
        return;
      }
      {
        std::lock_guard<std::mutex> Lock(EtwStateMutex);
        SelectedProviders = Selected;
      }
      EtwProvidersButton->setText(
          QString("Providers (%1)...").arg(Selected.size()));
    });

    Layout->addWidget(new BodyLabel(
        "Providers enabled for the ETW session. Kernel providers use their "
        "default keyword/level; system providers are enabled with all "
        "keywords at verbose level."));
    Layout->addWidget(List, 1);
    Layout->addWidget(EnumerateButton);
    Layout->addLayout(ButtonRow);
    ApplyDialogTheme(Dialog);
    Dialog->show();
  }

  void ShowEtwFilterDialog() {
    EtwDisplayFilter Current;
    {
      std::lock_guard<std::mutex> Lock(EtwStateMutex);
      Current = EtwFilter;
    }

    auto *Dialog = new QDialog(this);
    Dialog->setAttribute(Qt::WA_DeleteOnClose);
    Dialog->setWindowTitle("ETW Event Filter");
    Dialog->resize(520, 490);
    auto *Layout = new QVBoxLayout(Dialog);
    auto *Form = new QGridLayout;
    Form->setHorizontalSpacing(12);
    Form->setVerticalSpacing(8);

    auto *Enable = new CheckBox("Enable filter");
    Enable->setChecked(Current.Enabled);
    auto *Pid = new LineEdit;
    ConfigureLineEdit(Pid, "Exact PID");
    Pid->setText(Current.Pid);
    auto *ProcessName = new LineEdit;
    ConfigureLineEdit(ProcessName, "Contains, case-insensitive");
    ProcessName->setText(Current.ProcessName);
    auto *FilePath = new LineEdit;
    ConfigureLineEdit(FilePath, "Contains, case-insensitive");
    FilePath->setText(Current.FilePath);
    auto *EventId = new LineEdit;
    ConfigureLineEdit(EventId, "Exact event ID");
    EventId->setText(Current.EventId);
    auto *Behavior = new ComboBox;
    Behavior->addItems({"Any", "create", "delete", "read", "write", "send",
                        "receive", "connect", "open", "load", "alloc"});
    if (!Current.Behavior.isEmpty())
      Behavior->setCurrentText(Current.Behavior);
    auto *NetworkAddress = new LineEdit;
    ConfigureLineEdit(NetworkAddress, "Contains in local/remote address");
    NetworkAddress->setText(Current.NetworkAddress);
    auto *RegistryPath = new LineEdit;
    ConfigureLineEdit(RegistryPath, "Contains, case-insensitive");
    RegistryPath->setText(Current.RegistryPath);
    auto *Interface = new LineEdit;
    ConfigureLineEdit(Interface, "Exact interface index (nid)");
    Interface->setText(Current.Interface);

    const auto AddRow = [&Form](int Row, const QString &Label,
                                QWidget *Field) {
      Form->addWidget(new BodyLabel(Label), Row, 0);
      Form->addWidget(Field, Row, 1);
    };
    Form->addWidget(Enable, 0, 0, 1, 2);
    AddRow(1, "PID", Pid);
    AddRow(2, "Process name", ProcessName);
    AddRow(3, "File path", FilePath);
    AddRow(4, "Event ID", EventId);
    AddRow(5, "Behavior", Behavior);
    AddRow(6, "Network address", NetworkAddress);
    AddRow(7, "Registry path", RegistryPath);
    AddRow(8, "Network interface", Interface);

    auto *ButtonRow = new QHBoxLayout;
    ButtonRow->addStretch();
    auto *OkButton = MakeButton("OK", true);
    auto *CancelButton = MakeButton("Cancel");
    ButtonRow->addWidget(OkButton);
    ButtonRow->addWidget(CancelButton);
    QObject::connect(OkButton, &QPushButton::clicked, Dialog, &QDialog::accept);
    QObject::connect(CancelButton, &QPushButton::clicked, Dialog,
                     &QDialog::reject);
    QObject::connect(Dialog, &QDialog::accepted, this,
                     [this, Enable, Pid, ProcessName, FilePath, EventId,
                      Behavior, NetworkAddress, RegistryPath, Interface] {
                       EtwDisplayFilter Updated;
                       Updated.Enabled = Enable->isChecked();
                       Updated.Pid = Pid->text().trimmed();
                       Updated.ProcessName = ProcessName->text().trimmed();
                       Updated.FilePath = FilePath->text().trimmed();
                       Updated.EventId = EventId->text().trimmed();
                       Updated.Behavior = Behavior->currentText();
                       Updated.NetworkAddress =
                           NetworkAddress->text().trimmed();
                       Updated.RegistryPath = RegistryPath->text().trimmed();
                       Updated.Interface = Interface->text().trimmed();
                       {
                         std::lock_guard<std::mutex> Lock(EtwStateMutex);
                         EtwFilter = Updated;
                       }
                       EtwFilterStatus->setText(EtwFilterSummary(Updated));
                     });

    Layout->addLayout(Form);
    Layout->addStretch();
    Layout->addLayout(ButtonRow);
    ApplyDialogTheme(Dialog);
    Dialog->show();
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
      std::vector<EtwProvider> ProvidersSnapshot;
      {
        std::lock_guard<std::mutex> Lock(EtwStateMutex);
        ProvidersSnapshot = SelectedProviders;
      }
      QPointer<MonitorManagerPage> Page(this);
      SetEtwEventCallback([WeakState, Page](const ParsedEvent &Event) {
        if (Page) {
          EtwDisplayFilter Filter;
          {
            std::lock_guard<std::mutex> Lock(Page->EtwStateMutex);
            Filter = Page->EtwFilter;
          }
          if (!EtwEventMatchesFilter(Event, Filter))
            return;
        }
        if (const auto State = WeakState.lock())
          PushMonitorEvent(State, 0, FormatEtwEvent(Event));
      });
      EtwThread = std::thread([Page, WeakState,
                               Providers =
                                   std::move(ProvidersSnapshot)] {
        if (StartKernelTrace(&Providers)) {
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
        MonitorFilter Filter{};
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
        AegisSentinelSetFilter(Filter);
        Kernel = std::make_unique<KernelMonitor>();
        Kernel->SetCallback([WeakState](const MonitorEvent &Event) {
          if (const auto State = WeakState.lock()) {
            // 协议版本不匹配说明驱动与程序不是同一份构建：忽略事件并提示，避免误解析字段
            if (Event.Version != MONITOR_PROTOCOL_VERSION) {
              static std::atomic_bool Warned{false};
              if (!Warned.exchange(true))
                PushMonitorEvent(State, 0,
                                 QString("AegisSentinel protocol mismatch (driver v%1, app v%2) — "
                                         "reload the driver and restart the app")
                                     .arg(Event.Version)
                                     .arg(MONITOR_PROTOCOL_VERSION));
              return;
            }
            PushMonitorEvent(State, 0, FormatKernelMonitorEvent(Event),
                             FormatKernelMonitorEventDetail(Event));
          }
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
      MonitorStats Stats{};
      const bool Ok = AegisSentinelQueryStats(&Stats);
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

  void UpdateKernelTelemetry(const MonitorStats &Stats) {
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
    std::unique_ptr<KernelMonitor> KernelWorker = std::move(Kernel);
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
  std::array<SearchLineEdit *, KMonitorStreamCount> Searches{};
  std::array<TableWidget *, KMonitorStreamCount> Tables{};
  std::array<BodyLabel *, KMonitorStreamCount> Statuses{};
  std::array<uint64_t, KMonitorStreamCount> DisplayedVersions{};
  std::array<QStringList, KMonitorStreamCount> DisplayedKeys{};
  std::array<QTimer *, KMonitorStreamCount> SearchDebounceTimers{};
  QStringList DisplayedHistoryKeys{};
  uint64_t DisplayedHistoryVersion = 0;
  QTimer *UpdateTimer = nullptr;
  QTimer *TelemetryTimer = nullptr;

  SearchLineEdit *HistorySearchEdit = nullptr;
  TableWidget *HistoryTable = nullptr;
  BodyLabel *HistoryStatus = nullptr;
  BodyLabel *KernelTelemetryStatus = nullptr;
  QTimer *HistorySearchDebounceTimer = nullptr;
  LineEdit *DeviceHwIdEdit = nullptr;
  LineEdit *DeviceInstanceEdit = nullptr;
  LineEdit *DeviceVendorIdEdit = nullptr;
  LineEdit *DeviceProductIdEdit = nullptr;
  LineEdit *DeviceClassEdit = nullptr;
  CheckBox *DeviceArrivalCheck = nullptr;
  CheckBox *DeviceRemovalCheck = nullptr;
  CheckBox *DeviceBlockCheck = nullptr;
  BodyLabel *DeviceFilterStatus = nullptr;
  ComboBox *RuleType = nullptr;
  ComboBox *RuleAction = nullptr;
  LineEdit *RulePid = nullptr;
  LineEdit *RuleProtocol = nullptr;
  LineEdit *RulePort = nullptr;
  LineEdit *RuleTarget = nullptr;
  TableWidget *RulesTable = nullptr;
  BodyLabel *RulesStatus = nullptr;
  std::vector<MonitorRule> Rules;
  std::atomic_bool RulesRefreshing = false;
  bool RulesDirty = false;
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

    const auto RowKey = [](const MonitorHistoryRow &Evt) {
      return Evt.Timestamp + QChar('\x1F') + Evt.Detail;
    };
    const auto FillRow = [this](int Row, const MonitorHistoryRow &Evt) {
      HistoryTable->setItem(Row, 0, new QTableWidgetItem(Evt.Timestamp));
      HistoryTable->setItem(Row, 1, new QTableWidgetItem(Evt.Type));
      HistoryTable->setItem(Row, 2,
                            new QTableWidgetItem(QString::number(Evt.Pid)));
      HistoryTable->setItem(Row, 3, new QTableWidgetItem(Evt.Process));
      HistoryTable->setItem(Row, 4, new QTableWidgetItem(Evt.Detail));
      HistoryTable->setRowHeight(Row, KCompactTableRowHeight);
    };

    // 历史事件同样只从头部插入、尾部溢出删除，优先增量填充头部新行，
    // 避免 150ms 节拍下每轮重建最多 2 万个 QTableWidgetItem。
    if (Query.isEmpty() && !DisplayedHistoryKeys.isEmpty() &&
        !VisibleRows.empty() &&
        HistoryTable->rowCount() == DisplayedHistoryKeys.size()) {
      int NewCount = -1;
      for (int I = 0; I < static_cast<int>(VisibleRows.size()); ++I) {
        if (RowKey(*VisibleRows[I]) == DisplayedHistoryKeys.first()) {
          NewCount = I;
          break;
        }
      }
      if (NewCount == 0) {
        HistoryStatus->setText(QString("Events: %1").arg(HistoryRows.size()));
        return;
      }
      if (NewCount > 0) {
        const int TailCount =
            std::min<int>(DisplayedHistoryKeys.size(),
                          static_cast<int>(VisibleRows.size()) - NewCount);
        bool Aligned = TailCount > 0;
        for (int J = 0; Aligned && J < TailCount; ++J) {
          if (RowKey(*VisibleRows[NewCount + J]) != DisplayedHistoryKeys[J])
            Aligned = false;
        }
        if (Aligned) {
          SetTableRefreshEnabled(HistoryTable, false);
          for (int NewRow = 0; NewRow < NewCount; ++NewRow)
            HistoryTable->insertRow(0);
          for (int Row = NewCount - 1; Row >= 0; --Row)
            FillRow(Row, *VisibleRows[Row]);
          HistoryTable->setRowCount(static_cast<int>(VisibleRows.size()));
          SetTableRefreshEnabled(HistoryTable, true);
          RebuildHistoryKeys(VisibleRows, RowKey);
          HistoryStatus->setText(QString("Events: %1").arg(HistoryRows.size()));
          return;
        }
      }
    }

    SetTableRefreshEnabled(HistoryTable, false);
    HistoryTable->clearContents();
    HistoryTable->setRowCount(static_cast<int>(VisibleRows.size()));
    for (int Row = 0; Row < static_cast<int>(VisibleRows.size()); ++Row)
      FillRow(Row, *VisibleRows[Row]);
    SetTableRefreshEnabled(HistoryTable, true);
    RebuildHistoryKeys(VisibleRows, RowKey);
    HistoryStatus->setText(QString("Events: %1").arg(HistoryRows.size()));
  }

  template <typename Rows, typename KeyFn>
  void RebuildHistoryKeys(const Rows &VisibleRows, KeyFn RowKey) {
    QStringList NewKeys;
    NewKeys.reserve(static_cast<int>(VisibleRows.size()));
    for (const auto *Evt : VisibleRows)
      NewKeys.append(RowKey(*Evt));
    DisplayedHistoryKeys = std::move(NewKeys);
  }

  ComboBox *SystemMode = nullptr;
  PushButton *SystemStart = nullptr;
  PushButton *SystemStop = nullptr;
  PushButton *EtwProvidersButton = nullptr;
  PushButton *EtwFilterButton = nullptr;
  BodyLabel *EtwFilterStatus = nullptr;
  LineEdit *SystemFilterPid = nullptr;
  LineEdit *SystemPathPrefix = nullptr;
  CheckBox *RegistryPreview = nullptr;
  std::mutex EtwStateMutex;
  std::vector<EtwProvider> SelectedProviders;
  EtwDisplayFilter EtwFilter;
  LineEdit *ProcessTarget = nullptr;
  ComboBox *ProcessMethod = nullptr;
  PushButton *ProcessStart = nullptr;
  PushButton *ProcessStop = nullptr;
  PushButton *NetworkStart = nullptr;
  PushButton *NetworkStop = nullptr;
  LineEdit *HttpProxyPort = nullptr;
  PushButton *HttpStart = nullptr;
  PushButton *HttpStop = nullptr;
  std::unique_ptr<KernelMonitor> Kernel;
  std::unique_ptr<DllMonitor> Dll;
  std::unique_ptr<http_capture::HttpCapture> Http;
  std::thread EtwThread;
  std::atomic_bool SystemRunning = false;
  std::atomic_bool SystemStopping = false;
  std::atomic_bool ProcessRunning = false;
  std::atomic_bool ProcessStopping = false;
  std::atomic_bool NetworkRunning = false;
  std::atomic_bool HttpRunning = false;
  std::atomic_bool DeviceRunning = false;
  QPushButton *DeviceStart = nullptr;
  QPushButton *DeviceStop = nullptr;
  uint64_t DisplayedDeviceVersion = 0;
  uint64_t DisplayedAlertsVersion = 0;
  QTableWidget *AlertsTable = nullptr;
  SearchLineEdit *AlertsSearch = nullptr;

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
    } else if (Index == 6) {
      DisplayedDeviceVersion =
          SharedState->Streams[4].Version.load(std::memory_order_relaxed);
      Populate(4);
    } else if (Index == 7) {
      DisplayedAlertsVersion =
          SharedState->Alerts.Version.load(std::memory_order_relaxed);
      PopulateAlerts();
    }
  }

  void hideEvent(QHideEvent *Event) override {
    if (UpdateTimer)
      UpdateTimer->stop();
    QWidget::hideEvent(Event);
  }
};
