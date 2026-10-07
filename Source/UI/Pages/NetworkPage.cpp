// 网络管控页:系统 TCP/UDP 连接表 + 内核 WFP 防火墙规则管理。
// 连接数据来自 iphlpapi(用户态,含 TCPv6/UDPv6);规则走 AegisCore 驱动
// 0x84E(FIREWALL_OPERATION)/0x84F(ENUM_FIREWALL_RULES),支持按协议、
// 远程端口、远程地址(IPv4/IPv6)与方向/协议族组合封禁或放行。

#include <unordered_map>

// IPv6 复用同一 TABLE_CLASS,由地址族参数区分(MIB_TCP6TABLE_OWNER_PID)。
namespace {

struct ConnRow {
  QString Protocol;
  QString Local;
  QString Remote;
  QString State;
  quint32 Pid = 0;
  QString Process;
  int RemotePort = 0;
  QString RemoteAddress;
  QString BaseProtocol;  // "TCP" / "UDP",用于封禁预填
  bool RemoteV6 = false;

  bool Matches(const QString &Needle, int ProtocolIndex) const {
    if (ProtocolIndex == 1 && !Protocol.startsWith("TCP"))
      return false;
    if (ProtocolIndex == 2 && !Protocol.startsWith("UDP"))
      return false;
    if (Needle.isEmpty())
      return true;
    const QString Folded = Needle;
    return Local.contains(Folded, Qt::CaseInsensitive) ||
           Remote.contains(Folded, Qt::CaseInsensitive) ||
           State.contains(Folded, Qt::CaseInsensitive) ||
           Process.contains(Folded, Qt::CaseInsensitive) ||
           QString::number(Pid) == Needle;
  }
};

const char *TcpStateName(DWORD State) {
  switch (State) {
  case MIB_TCP_STATE_CLOSED: return "Closed";
  case MIB_TCP_STATE_LISTEN: return "Listen";
  case MIB_TCP_STATE_SYN_SENT: return "SYN Sent";
  case MIB_TCP_STATE_SYN_RCVD: return "SYN Received";
  case MIB_TCP_STATE_ESTAB: return "Established";
  case MIB_TCP_STATE_FIN_WAIT1: return "FIN Wait 1";
  case MIB_TCP_STATE_FIN_WAIT2: return "FIN Wait 2";
  case MIB_TCP_STATE_CLOSE_WAIT: return "Close Wait";
  case MIB_TCP_STATE_CLOSING: return "Closing";
  case MIB_TCP_STATE_LAST_ACK: return "Last ACK";
  case MIB_TCP_STATE_TIME_WAIT: return "Time Wait";
  case MIB_TCP_STATE_DELETE_TCB: return "Delete TCB";
  default: return "Unknown";
  }
}

QString FormatIpv4(DWORD NetworkOrder) {
  const in_addr Address{NetworkOrder};
  char Text[INET_ADDRSTRLEN] = {};
  if (inet_ntop(AF_INET, &Address, Text, sizeof(Text)))
    return QString::fromLatin1(Text);
  return QString::fromLatin1("0.0.0.0");
}

QString FormatIpv6(const UCHAR *Bytes) {
  in6_addr Address{};
  memcpy(&Address, Bytes, 16);
  char Text[INET6_ADDRSTRLEN] = {};
  if (inet_ntop(AF_INET6, &Address, Text, sizeof(Text)))
    return QString::fromLatin1(Text);
  return QString();
}

QString FormatEndpoint(const QString &Address, DWORD PortNetworkOrder,
                       bool Remote) {
  const quint16 Port = ntohs(static_cast<u_short>(PortNetworkOrder));
  if (Remote && Address.isEmpty())
    return QString("*:*");
  return QString("[%1]:%2").arg(Address).arg(Port);
}

std::unordered_map<quint32, QString> SnapshotProcessNames() {
  std::unordered_map<quint32, QString> Names;
  const HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (Snapshot == INVALID_HANDLE_VALUE)
    return Names;
  PROCESSENTRY32W Entry{};
  Entry.dwSize = sizeof(Entry);
  if (Process32FirstW(Snapshot, &Entry)) {
    do {
      Names.try_emplace(Entry.th32ProcessID,
                        QString::fromWCharArray(Entry.szExeFile));
    } while (Process32NextW(Snapshot, &Entry));
  }
  CloseHandle(Snapshot);
  return Names;
}

std::vector<ConnRow> CollectConnectionRows() {
  std::vector<ConnRow> Rows;
  const auto ProcessNames = SnapshotProcessNames();
  const auto ProcessOf = [&ProcessNames](quint32 Pid) {
    const auto It = ProcessNames.find(Pid);
    return It == ProcessNames.end() ? QString() : It->second;
  };

  for (const int Family : {AF_INET, AF_INET6}) {
    const bool V6 = Family == AF_INET6;
    const TCP_TABLE_CLASS TableClass = TCP_TABLE_OWNER_PID_ALL;
    std::vector<char> Buffer;
    DWORD Size = 0;
    if (GetExtendedTcpTable(nullptr, &Size, FALSE, Family, TableClass, 0) ==
            ERROR_INSUFFICIENT_BUFFER &&
        Size > 0) {
      Buffer.resize(Size);
      if (GetExtendedTcpTable(Buffer.data(), &Size, FALSE, Family, TableClass,
                              0) != NO_ERROR)
        Buffer.clear();
    }
    if (!Buffer.empty() && !V6) {
      const auto *Table = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(
          Buffer.data());
      for (DWORD I = 0; I < Table->dwNumEntries; ++I) {
        const MIB_TCPROW_OWNER_PID &R = Table->table[I];
        ConnRow Row;
        Row.Protocol = "TCP";
        Row.Local = FormatEndpoint(FormatIpv4(R.dwLocalAddr), R.dwLocalPort, false);
        const QString RemoteAddress = FormatIpv4(R.dwRemoteAddr);
        Row.Remote = FormatEndpoint(RemoteAddress, R.dwRemotePort, true);
        Row.State = TcpStateName(R.dwState);
        Row.Pid = R.dwOwningPid;
        Row.Process = ProcessOf(R.dwOwningPid);
        Row.RemotePort = ntohs(static_cast<u_short>(R.dwRemotePort));
        Row.RemoteAddress = RemoteAddress;
        Row.BaseProtocol = "TCP";
        Row.RemoteV6 = false;
        Rows.push_back(std::move(Row));
      }
    } else if (!Buffer.empty()) {
      const auto *Table = reinterpret_cast<PMIB_TCP6TABLE_OWNER_PID>(
          Buffer.data());
      for (DWORD I = 0; I < Table->dwNumEntries; ++I) {
        const MIB_TCP6ROW_OWNER_PID &R = Table->table[I];
        ConnRow Row;
        Row.Protocol = "TCP6";
        Row.Local = FormatEndpoint(FormatIpv6(R.ucLocalAddr), R.dwLocalPort, false);
        const QString RemoteAddress = FormatIpv6(R.ucRemoteAddr);
        Row.Remote = FormatEndpoint(RemoteAddress, R.dwRemotePort, true);
        Row.State = TcpStateName(R.dwState);
        Row.Pid = R.dwOwningPid;
        Row.Process = ProcessOf(R.dwOwningPid);
        Row.RemotePort = ntohs(static_cast<u_short>(R.dwRemotePort));
        Row.RemoteAddress = RemoteAddress;
        Row.BaseProtocol = "TCP";
        Row.RemoteV6 = true;
        Rows.push_back(std::move(Row));
      }
    }
  }

  for (const int Family : {AF_INET, AF_INET6}) {
    const bool V6 = Family == AF_INET6;
    const UDP_TABLE_CLASS TableClass = UDP_TABLE_OWNER_PID;
    std::vector<char> Buffer;
    DWORD Size = 0;
    if (GetExtendedUdpTable(nullptr, &Size, FALSE, Family, TableClass, 0) ==
            ERROR_INSUFFICIENT_BUFFER &&
        Size > 0) {
      Buffer.resize(Size);
      if (GetExtendedUdpTable(Buffer.data(), &Size, FALSE, Family, TableClass,
                              0) != NO_ERROR)
        Buffer.clear();
    }
    if (!Buffer.empty() && !V6) {
      const auto *Table = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(
          Buffer.data());
      for (DWORD I = 0; I < Table->dwNumEntries; ++I) {
        const MIB_UDPROW_OWNER_PID &R = Table->table[I];
        ConnRow Row;
        Row.Protocol = "UDP";
        Row.Local = FormatEndpoint(FormatIpv4(R.dwLocalAddr), R.dwLocalPort, false);
        Row.Remote = "*:*";
        Row.State = "-";
        Row.Pid = R.dwOwningPid;
        Row.Process = ProcessOf(R.dwOwningPid);
        Row.BaseProtocol = "UDP";
        Rows.push_back(std::move(Row));
      }
    } else if (!Buffer.empty()) {
      const auto *Table = reinterpret_cast<PMIB_UDP6TABLE_OWNER_PID>(
          Buffer.data());
      for (DWORD I = 0; I < Table->dwNumEntries; ++I) {
        const MIB_UDP6ROW_OWNER_PID &R = Table->table[I];
        ConnRow Row;
        Row.Protocol = "UDP6";
        Row.Local = FormatEndpoint(FormatIpv6(R.ucLocalAddr), R.dwLocalPort, false);
        Row.Remote = "*:*";
        Row.State = "-";
        Row.Pid = R.dwOwningPid;
        Row.Process = ProcessOf(R.dwOwningPid);
        Row.BaseProtocol = "UDP";
        Row.RemoteV6 = true;
        Rows.push_back(std::move(Row));
      }
    }
  }
  return Rows;
}

QString FirewallAddressText(const FIREWALL_RULE_ENTRY &Entry) {
  if (Entry.RemoteIpv4 != 0)
    return FormatIpv4(Entry.RemoteIpv4);
  for (int I = 0; I < 16; ++I) {
    if (Entry.RemoteIpv6[I] != 0)
      return FormatIpv6(Entry.RemoteIpv6);
  }
  return "-";
}

QString FirewallDirectionText(ULONG Direction) {
  switch (Direction) {
  case FIREWALL_DIRECTION_OUT_V4:
  case FIREWALL_DIRECTION_OUT_V6:
    return "Outbound";
  case FIREWALL_DIRECTION_IN_V4:
  case FIREWALL_DIRECTION_IN_V6:
    return "Inbound";
  default:
    return "-";
  }
}

QString FirewallProtocolText(ULONG Protocol) {
  if (Protocol == 6)
    return "TCP";
  if (Protocol == 17)
    return "UDP";
  if (Protocol == 0)
    return "Any";
  return QString::number(Protocol);
}

// 添加规则对话框;PrefillPort/PrefillProtocol/PrefillV6 >= 0 时预填,
// 供连接列表"Block remote port"复用。
void ShowAddFirewallRuleDialog(QWidget *Parent, int PrefillPort,
                               const QString &PrefillBaseProtocol,
                               bool PrefillV6) {
  auto *Dialog = new QDialog(Parent);
  Dialog->setAttribute(Qt::WA_DeleteOnClose);
  Dialog->setWindowTitle("Add Firewall Rule");
  Dialog->resize(560, 450);
  auto *Layout = new QVBoxLayout(Dialog);
  Layout->setSpacing(10);

  auto *NameEdit = new LineEdit;
  if (PrefillPort > 0)
    NameEdit->setText(QString("Block %1 port %2")
                          .arg(PrefillBaseProtocol).arg(PrefillPort));
  NameEdit->setPlaceholderText("Rule name (required)");
  auto *ActionBox = new ComboBox;
  ActionBox->addItems({"Block", "Permit"});
  auto *ProtocolBox = new ComboBox;
  ProtocolBox->addItems({"Any", "TCP", "UDP"});
  if (PrefillBaseProtocol == "TCP")
    ProtocolBox->setCurrentIndex(1);
  else if (PrefillBaseProtocol == "UDP")
    ProtocolBox->setCurrentIndex(2);
  auto *PortEdit = new LineEdit;
  if (PrefillPort > 0)
    PortEdit->setText(QString::number(PrefillPort));
  PortEdit->setPlaceholderText("Remote port, 0 = any");
  auto *DirectionBox = new ComboBox;
  DirectionBox->addItems({"Both directions", "Outbound only",
                          "Inbound only"});
  auto *FamilyBox = new ComboBox;
  FamilyBox->addItems({"IPv4 + IPv6", "IPv4 only", "IPv6 only"});
  if (PrefillV6)
    FamilyBox->setCurrentIndex(2);
  auto *Ipv4Edit = new LineEdit;
  Ipv4Edit->setPlaceholderText("Remote IPv4, empty = any (e.g. 1.2.3.4)");
  auto *Ipv6Edit = new LineEdit;
  Ipv6Edit->setPlaceholderText("Remote IPv6, empty = any (e.g. ::1)");

  // 页面文件被包含进 AegisNT.cpp 的匿名命名空间,此处不能 #include
  // <QFormLayout>(dllimport 类会被卷进匿名命名空间),改用 QGridLayout。
  auto *Form = new QGridLayout;
  int FormRow = 0;
  const auto AddFormRow = [&FormRow, Form](const QString &Label,
                                           QWidget *Widget) {
    Form->addWidget(MakeLabel(Label, 12, KTextPrimary), FormRow, 0);
    Form->addWidget(Widget, FormRow, 1);
    ++FormRow;
  };
  AddFormRow("Name", NameEdit);
  AddFormRow("Action", ActionBox);
  AddFormRow("Protocol", ProtocolBox);
  AddFormRow("Remote Port", PortEdit);
  AddFormRow("Scope", DirectionBox);
  AddFormRow("Family", FamilyBox);
  AddFormRow("IPv4", Ipv4Edit);
  AddFormRow("IPv6", Ipv6Edit);
  Layout->addLayout(Form);

  auto *ButtonRow = new QHBoxLayout;
  auto *CancelButton = new PushButton("Cancel");
  auto *OkButton = MakeButton("Add Rule", true);
  ButtonRow->addStretch(1);
  ButtonRow->addWidget(CancelButton);
  ButtonRow->addWidget(OkButton);
  Layout->addLayout(ButtonRow);

  QObject::connect(CancelButton, &QPushButton::clicked, Dialog,
                   &QDialog::reject);
  QObject::connect(OkButton, &QPushButton::clicked, Dialog,
                   [Dialog, Parent, NameEdit, ActionBox, ProtocolBox, PortEdit,
                    DirectionBox, FamilyBox, Ipv4Edit, Ipv6Edit] {
                     const QString Name = NameEdit->text().trimmed();
                     if (Name.isEmpty()) {
                       ShowWarningNotice(Parent, "Network",
                                         "Enter a rule name.");
                       return;
                     }
                     bool PortOk = false;
                     const uint Port =
                         PortEdit->text().trimmed().toUInt(&PortOk, 0);
                     if (!PortOk || Port > 65535) {
                       ShowWarningNotice(Parent, "Network",
                                         "Remote port must be 0-65535.");
                       return;
                     }
                     ULONG RemoteIpv4 = 0;
                     const QString Ipv4Text = Ipv4Edit->text().trimmed();
                     if (!Ipv4Text.isEmpty()) {
                       in_addr Address{};
                       if (inet_pton(AF_INET, Ipv4Text.toLatin1().constData(),
                                     &Address) != 1) {
                         ShowWarningNotice(Parent, "Network",
                                           "Invalid IPv4 address.");
                         return;
                       }
                       RemoteIpv4 = Address.s_addr;
                     }
                     UCHAR RemoteIpv6[16] = {};
                     const QString Ipv6Text = Ipv6Edit->text().trimmed();
                     if (!Ipv6Text.isEmpty()) {
                       in6_addr Address{};
                       if (inet_pton(AF_INET6, Ipv6Text.toLatin1().constData(),
                                     &Address) != 1) {
                         ShowWarningNotice(Parent, "Network",
                                           "Invalid IPv6 address.");
                         return;
                       }
                       memcpy(RemoteIpv6, &Address, 16);
                     }
                     const ULONG Action =
                         ActionBox->currentIndex() == 1
                             ? FIREWALL_ACTION_PERMIT
                             : FIREWALL_ACTION_BLOCK;
                     const ULONG Protocol =
                         ProtocolBox->currentIndex() == 1
                             ? 6ul
                             : ProtocolBox->currentIndex() == 2 ? 17ul : 0ul;
                     const ULONG DirectionMask =
                         DirectionBox->currentIndex() == 1
                             ? FIREWALL_DIRBIT_OUT
                             : DirectionBox->currentIndex() == 2
                                   ? FIREWALL_DIRBIT_IN
                                   : 0ul;
                     const ULONG FamilyMask =
                         FamilyBox->currentIndex() == 1
                             ? FIREWALL_FAMILYBIT_V4
                             : FamilyBox->currentIndex() == 2
                                   ? FIREWALL_FAMILYBIT_V6
                                   : 0ul;
                     if (!FirewallKernelOpEx(
                             (const WCHAR *)Name.utf16(), FIREWALL_OP_ADD,
                             Action, Port, Protocol, RemoteIpv4,
                             Ipv6Text.isEmpty() ? nullptr : RemoteIpv6,
                             DirectionMask, FamilyMask)) {
                       ShowErrorNotice(Parent, "Network",
                                       QString("Add rule failed (error %1).")
                                           .arg(G_LastAegisCoreError));
                       return;
                     }
                     ShowSuccessNotice(Parent, "Network",
                                       QString("Rule '%1' added.").arg(Name));
                     Dialog->accept();
                   });
  ApplyDialogTheme(Dialog);
  Dialog->exec();
}

struct NetworkPageWidget : AegisNT::PageBase {
  NetworkPageWidget() : AegisNT::PageBase(nullptr) {}
  QTimer *AutoTimer = nullptr;
  CheckBox *AutoRefresh = nullptr;

  void showEvent(QShowEvent *Event) override {
    QWidget::showEvent(Event);
    if (AutoRefresh && AutoRefresh->isChecked())
      AutoTimer->start();
  }
  void hideEvent(QHideEvent *Event) override {
    QWidget::hideEvent(Event);
    if (AutoTimer)
      AutoTimer->stop();
  }
};

} // namespace

QWidget *CreateNetworkControlPage() {
  auto *Page = new NetworkPageWidget;
  auto *Layout = Page->GetMainLayout();
  ConfigurePageLayout(Layout);

  auto *Tabs = new TabBar;
  Tabs->setAddButtonVisible(false);
  Tabs->setTabsClosable(false);
  Tabs->setMovable(false);
  Tabs->addTab("connections", "Connections", Fluent::IconType::GLOBE);
  Tabs->addTab("rules", "Firewall Rules", Fluent::IconType::TILES);
  Layout->addWidget(Tabs);
  auto *Pages = new QStackedWidget;
  Layout->addWidget(Pages, 1);
  QObject::connect(Tabs, &TabBar::currentChanged, Pages,
                   &QStackedWidget::setCurrentIndex);

  // ---- 连接表标签页 ----
  auto *ConnectionsPage = new AegisNT::PageBase(nullptr);
  auto *ConnectionsLayout = ConnectionsPage->GetMainLayout();
  ConnectionsLayout->setContentsMargins(0, 0, 0, 0);
  ConnectionsLayout->setSpacing(KCompactPageSpacing);

  auto *Toolbar = new QHBoxLayout;
  ConfigureToolbarLayout(Toolbar);
  auto *Search = new SearchLineEdit;
  Search->setPlaceholderText(
      "Search address, port, state, process, or PID");
  Search->setMaximumWidth(340);
  auto *ProtocolBox = new ComboBox;
  ProtocolBox->addItems({"All protocols", "TCP", "UDP"});
  auto *AutoRefresh = new CheckBox("Auto refresh");
  auto *Status = new BodyLabel("Ready");
  auto *Ring = new IndeterminateProgressRing;
  Ring->setFixedSize(18, 18);
  Ring->hide();
  auto *RefreshButton = MakeButton("Refresh", true);
  Toolbar->addWidget(Search);
  Toolbar->addWidget(ProtocolBox);
  Toolbar->addWidget(AutoRefresh);
  Toolbar->addStretch(1);
  Toolbar->addWidget(Status, 1);
  Toolbar->addWidget(Ring);
  Toolbar->addWidget(RefreshButton);
  ConnectionsLayout->addLayout(Toolbar);

  auto *ConnTable = MakeTable({"Protocol", "Local Address", "Remote Address",
                               "State", "PID", "Process"});
  ConnTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
  ConnTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
  ConnTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
  ConnTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
  ConnTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
  ConnTable->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
  ConnTable->setProperty("DetailDialogTitle", "Connection Details");
  ConnectionsLayout->addWidget(ConnTable, 1);
  Pages->addWidget(ConnectionsPage);

  const auto ConnRows = std::make_shared<std::vector<ConnRow>>();

  const auto RepopulateConnections = [ConnRows, ConnTable, Search,
                                      ProtocolBox] {
    const QString Needle = Search->text().trimmed();
    const int ProtocolIndex = ProtocolBox->currentIndex();
    ConnTable->setRowCount(0);
    for (const ConnRow &Row : *ConnRows) {
      if (!Row.Matches(Needle, ProtocolIndex))
        continue;
      const int ColumnCount = ConnTable->columnCount();
      const int RowIndex = ConnTable->rowCount();
      ConnTable->insertRow(RowIndex);
      const QStringList Values{Row.Protocol, Row.Local, Row.Remote, Row.State,
                               QString::number(Row.Pid), Row.Process};
      for (int Column = 0; Column < Values.size() && Column < ColumnCount;
           ++Column)
        ConnTable->setItem(RowIndex, Column,
                           new QTableWidgetItem(Values[Column]));
      ConnTable->item(RowIndex, 0)
          ->setData(Qt::UserRole, static_cast<int>(&Row - ConnRows->data()));
    }
  };

  // ---- 防火墙规则标签页 ----
  auto *RulesPage = new AegisNT::PageBase(nullptr);
  auto *RulesLayout = RulesPage->GetMainLayout();
  RulesLayout->setContentsMargins(0, 0, 0, 0);
  RulesLayout->setSpacing(KCompactPageSpacing);

  auto *RulesToolbar = new QHBoxLayout;
  ConfigureToolbarLayout(RulesToolbar);
  auto *RulesStatus = new BodyLabel("Ready");
  auto *AddRuleButton = MakeButton("Add Rule", true);
  auto *RemoveRuleButton = MakeButton("Remove Selected");
  auto *ClearRulesButton = MakeButton("Clear All");
  auto *RefreshRulesButton = MakeButton("Refresh Rules", true);
  RulesToolbar->addWidget(AddRuleButton);
  RulesToolbar->addWidget(RemoveRuleButton);
  RulesToolbar->addWidget(ClearRulesButton);
  RulesToolbar->addStretch(1);
  RulesToolbar->addWidget(RulesStatus, 1);
  RulesToolbar->addWidget(RefreshRulesButton);
  RulesLayout->addLayout(RulesToolbar);

  auto *RulesTable = MakeTable({"Name", "Action", "Protocol", "Remote Port",
                                "Remote Address", "Direction", "State",
                                "Filter ID"});
  RulesTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
  RulesTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
  RulesTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
  RulesTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
  RulesTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
  RulesTable->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
  RulesTable->horizontalHeader()->setSectionResizeMode(6, QHeaderView::ResizeToContents);
  RulesTable->horizontalHeader()->setSectionResizeMode(7, QHeaderView::ResizeToContents);
  RulesTable->setProperty("DetailDialogTitle", "Firewall Rule Details");
  RulesLayout->addWidget(RulesTable, 1);
  Pages->addWidget(RulesPage);

  // 连接表刷新：结果在 UI 线程回写。
  const auto RefreshConnections = [Page, ConnRows, RepopulateConnections,
                                   RefreshButton, Ring, Status] {
    SetRefreshUiState(RefreshButton, Ring, Status, true, "Refresh",
                      "Refreshing", "Ready", "Enumerating connections...");
    QPointer<NetworkPageWidget> Guard(Page);
    std::thread([Guard, ConnRows, RepopulateConnections, RefreshButton, Ring,
                 Status] {
      const auto Rows = CollectConnectionRows();
      QMetaObject::invokeMethod(
          qApp,
          [Guard, ConnRows, RepopulateConnections, RefreshButton, Ring,
           Status, Rows] {
            if (!Guard)
              return;
            *ConnRows = std::move(Rows);
            RepopulateConnections();
            SetRefreshUiState(RefreshButton, Ring, Status, false, "Refresh",
                              "Refreshing", "Ready", "Ready");
          });
    }).detach();
  };

  // 规则刷新：输出 blob 约 38 KB，故用堆分配承载。
  // 内核查询失败时 COM 用户态枚举让标签页保持可用；
  // 由于 Remove/Clear 只作用于内核子层，显示回退行时保持禁用。
  const auto RefreshRules = [Page, RulesTable, RefreshRulesButton,
                             RemoveRuleButton, ClearRulesButton,
                             RulesStatus] {
    RefreshRulesButton->setEnabled(false);
    RulesStatus->setText("Querying kernel firewall rules...");
    QPointer<NetworkPageWidget> Guard(Page);
    std::thread([Guard, RulesTable, RefreshRulesButton, RemoveRuleButton,
                 ClearRulesButton, RulesStatus] {
      auto Output = std::make_unique<FIREWALL_RULE_OUTPUT>();
      const BOOL Success =
          EnumerateFirewallRulesKernel(Output.get());
      const DWORD Error = G_LastAegisCoreError;
      // 驱动在 IOCTL 失败前就会写 KernelStatus，因此即使
      // DeviceIoControl 返回 FALSE，该字段依然有效。
      const ULONG KernelStatus = Success ? 0 : Output->KernelStatus;
      const ULONG Count = Success ? Output->Count : 0;
      std::vector<std::tuple<QString, ULONG, ULONG, ULONG, QString>>
          FallbackEntries;
      if (!Success)
        EnumerateFirewallRulesFallback(FallbackEntries);
      QMetaObject::invokeMethod(
          qApp,
          [Guard, RulesTable, RefreshRulesButton, RemoveRuleButton,
           ClearRulesButton, RulesStatus, Success, Error, KernelStatus, Count,
           Output = std::move(Output),
           FallbackEntries = std::move(FallbackEntries)]() mutable {
            if (!Guard)
              return;
            RefreshRulesButton->setEnabled(true);
            RulesTable->setRowCount(0);
            if (!Success) {
              for (const auto &Entry : FallbackEntries) {
                const int Row = RulesTable->rowCount();
                RulesTable->insertRow(Row);
                const QStringList Values{
                    std::get<0>(Entry),
                    std::get<1>(Entry) == FIREWALL_ACTION_BLOCK ? "Block"
                                                                : "Permit",
                    FirewallProtocolText(std::get<2>(Entry)),
                    std::get<3>(Entry)
                        ? QString::number(std::get<3>(Entry))
                        : "Any",
                    "-",
                    "-",
                    std::get<4>(Entry),
                    "-"};
                for (int Column = 0; Column < Values.size(); ++Column)
                  RulesTable->setItem(Row, Column,
                                      new QTableWidgetItem(Values[Column]));
              }
              const QString Message =
                  FallbackEntries.empty()
                      ? QString("Firewall query failed (error %1, kernel "
                                "status 0x%2).")
                            .arg(Error)
                            .arg(KernelStatus, 8, 16, QChar('0'))
                      : QString("Kernel query failed (error %1, kernel "
                                "status 0x%2); showing %3 user-mode "
                                "rule(s).")
                            .arg(Error)
                            .arg(KernelStatus, 8, 16, QChar('0'))
                            .arg(FallbackEntries.size());
              RulesStatus->setText(Message);
              if (FallbackEntries.empty())
                ShowErrorNotice(Guard, "Network", Message);
              else
                ShowWarningNotice(Guard, "Network", Message);
              RemoveRuleButton->setEnabled(false);
              ClearRulesButton->setEnabled(false);
              return;
            }
            RemoveRuleButton->setEnabled(true);
            ClearRulesButton->setEnabled(true);
            for (ULONG I = 0; I < Count && I < Output->Count; ++I) {
              const FIREWALL_RULE_ENTRY &Entry = Output->Entries[I];
              const int Row = RulesTable->rowCount();
              RulesTable->insertRow(Row);
              const QStringList Values{
                  QString::fromWCharArray(Entry.RuleName),
                  Entry.Action == FIREWALL_ACTION_BLOCK ? "Block" :
                      Entry.Action == FIREWALL_ACTION_PERMIT ? "Permit" :
                      QString("WFP action 0x%1").arg(Entry.Action, 0, 16),
                  FirewallProtocolText(Entry.Protocol),
                  Entry.RemotePort ? QString::number(Entry.RemotePort) : "Any",
                  FirewallAddressText(Entry),
                  FirewallDirectionText(Entry.Direction),
                  Entry.Enabled ? "Enabled" : "Disabled",
                  QString::number(Entry.FilterId)};
              for (int Column = 0; Column < Values.size(); ++Column)
                RulesTable->setItem(Row, Column,
                                    new QTableWidgetItem(Values[Column]));
            }
            const QString Message = Output->TotalCount > Count
                ? QString("Showing %1 of %2 kernel filters (output limit reached).")
                    .arg(Count).arg(Output->TotalCount)
                : QString("%1 kernel filter(s) across ALE layers.").arg(Count);
            RulesStatus->setText(Message);
          });
    }).detach();
  };

  const auto ShowAddRule = [Page](int PrefillPort,
                                  const QString &PrefillBaseProtocol,
                                  bool PrefillV6, const auto &After) {
    QPointer<NetworkPageWidget> Guard(Page);
    ShowAddFirewallRuleDialog(Page, PrefillPort, PrefillBaseProtocol,
                              PrefillV6);
    if (Guard)
      After();
  };

  // ---- 连接表交互 ----
  QObject::connect(RefreshButton, &QPushButton::clicked, Page,
                   RefreshConnections);
  QObject::connect(Search, &SearchLineEdit::textChanged, Page,
                   RepopulateConnections);
  QObject::connect(ProtocolBox, &ComboBox::currentIndexChanged, Page,
                   RepopulateConnections);

  Page->AutoTimer = new QTimer(Page);
  Page->AutoTimer->setInterval(3000);
  Page->AutoRefresh = AutoRefresh;
  QObject::connect(Page->AutoTimer, &QTimer::timeout, Page,
                   RefreshConnections);
  QObject::connect(AutoRefresh, &QCheckBox::toggled, Page, [Page](bool On) {
    if (On)
      Page->AutoTimer->start();
    else
      Page->AutoTimer->stop();
  });

  auto AddMenuAction = [](RoundMenu *Menu, const QString &Text,
                           const std::function<void()> &Handler) {
    auto *Action = new QAction(Text, Menu);
    Menu->addAction(Action);
    QObject::connect(Action, &QAction::triggered, Menu,
                     [Handler] { Handler(); });
  };

  QObject::connect(
      ConnTable, &QTableWidget::customContextMenuRequested, Page,
      [Page, ConnTable, ConnRows, ShowAddRule, RefreshConnections,
       RefreshRules, AddMenuAction](const QPoint &Position) {
        const int Row = ConnTable->rowAt(Position.y());
        if (Row < 0)
          return;
        ConnTable->selectRow(Row);
        const int SourceIndex =
            ConnTable->item(Row, 0)->data(Qt::UserRole).toInt();
        if (SourceIndex < 0 ||
            SourceIndex >= static_cast<int>(ConnRows->size()))
          return;
        const ConnRow Source = ConnRows->at(SourceIndex);
        auto *Menu = new RoundMenu(QString(), Page);
        AddMenuAction(Menu, "End Process", [Page, Source] {
          if (Source.Pid == 0 || Source.Pid == GetCurrentProcessId())
            return;
          if (!ShowConfirmDialog(Page, "End Process",
                                 QString("Kill %1 (PID %2)?")
                                     .arg(Source.Process.isEmpty()
                                              ? "this process"
                                              : Source.Process)
                                     .arg(Source.Pid),
                                 "Kill", "Cancel"))
            return;
          if (!KillProcessForce(Source.Pid))
            ShowErrorNotice(Page, "Network",
                            QString("Failed to kill PID %1.").arg(Source.Pid));
          else
            ShowSuccessNotice(Page, "Network",
                              QString("PID %1 terminated.").arg(Source.Pid));
        });
        const bool HasRemote = !Source.RemoteAddress.isEmpty() &&
                               Source.RemotePort > 0;
        AddMenuAction(Menu, "Block Remote Port...", [Page, Source, HasRemote,
                                                     ShowAddRule,
                                                     RefreshRules] {
          if (!HasRemote) {
            ShowWarningNotice(Page, "Network",
                              "UDP rows have no remote endpoint to block.");
            return;
          }
          ShowAddRule(Source.RemotePort, Source.BaseProtocol,
                      Source.RemoteV6, RefreshRules);
        });
        AddMenuAction(Menu, "Copy Row", [ConnTable, Row] {
          QStringList Values;
          for (int Column = 0; Column < ConnTable->columnCount(); ++Column) {
            const QTableWidgetItem *Item = ConnTable->item(Row, Column);
            Values << (Item ? Item->text() : QString());
          }
          qApp->clipboard()->setText(Values.join('\t'));
        });
        Menu->exec(ConnTable->viewport()->mapToGlobal(Position));
        Menu->deleteLater();
      });

  // ---- 规则交互 ----
  QObject::connect(RefreshRulesButton, &QPushButton::clicked, Page,
                   RefreshRules);
  QObject::connect(AddRuleButton, &QPushButton::clicked, Page,
                   [Page, ShowAddRule, RefreshRules] {
                     ShowAddRule(-1, QString(), false, RefreshRules);
                   });
  QObject::connect(RemoveRuleButton, &QPushButton::clicked, Page,
                   [Page, RulesTable, RulesStatus, RefreshRules] {
                     const int Row = RulesTable->currentRow();
                     if (Row < 0) {
                       ShowWarningNotice(Page, "Network",
                                         "Select a rule to remove.");
                       return;
                     }
                     const QString Name =
                         RulesTable->item(Row, 0)->text();
                     if (Name.isEmpty()) {
                       ShowWarningNotice(Page, "Network",
                                         "This rule has no name; use Clear "
                                         "All to remove unnamed filters.");
                       return;
                     }
                     if (!FirewallKernelOpEx(
                             (const WCHAR *)Name.utf16(), FIREWALL_OP_REMOVE,
                             0, 0, 0, 0, nullptr, 0, 0)) {
                       ShowErrorNotice(Page, "Network",
                                       QString("Remove failed (error %1).")
                                           .arg(G_LastAegisCoreError));
                       return;
                     }
                     RulesStatus->setText(QString("Rule '%1' removed.")
                                              .arg(Name));
                     ShowSuccessNotice(Page, "Network",
                                       QString("Rule '%1' removed.").arg(Name));
                     RefreshRules();
                   });
  QObject::connect(ClearRulesButton, &QPushButton::clicked, Page,
                   [Page, RefreshRules] {
                     if (!ShowConfirmDialog(
                             Page, "Clear Firewall Rules",
                             "Remove ALL filters created by AegisNT on its "
                             "sublayer? Rules from other vendors are not "
                             "touched.",
                             "Clear", "Cancel"))
                       return;
                     if (!FirewallKernelOpEx(L"", FIREWALL_OP_CLEAR, 0, 0, 0,
                                             0, nullptr, 0, 0)) {
                       ShowErrorNotice(Page, "Network",
                                       QString("Clear failed (error %1).")
                                           .arg(G_LastAegisCoreError));
                       return;
                     }
                     ShowSuccessNotice(Page, "Network",
                                       "All AegisNT firewall rules cleared.");
                     RefreshRules();
                   });

  // 进入页面先各刷一次。
  RefreshConnections();
  RefreshRules();
  return Page;
}
