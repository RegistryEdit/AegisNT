// ============================================================
// 任务管理器页（TaskManagerPage）：进程/线程双视图管理，
// 支持结束/挂起、权限令牌设置、句柄查看、内存转储、
// 注入器与启动方式（LaunchAs）管理等（经 AegisCore 驱动）。
// ============================================================
#include <QCursor>

class TaskManagerPage final : public QWidget {
  static constexpr int KProcessPinnedRole = Qt::UserRole + 1;
  static constexpr qint64 KProcessTableRenderBudgetMs = 2;
  static constexpr int KProcessTableRenderMaxRowsPerBatch = 12;

  class ProcessTableItem final : public QTableWidgetItem {
  public:
    using QTableWidgetItem::QTableWidgetItem;

    bool operator<(const QTableWidgetItem &Other) const override {
      const bool LeftPinned = data(KProcessPinnedRole).toBool();
      const bool RightPinned = Other.data(KProcessPinnedRole).toBool();
      if (LeftPinned != RightPinned) {
        const QTableWidget *Table = tableWidget();
        const Qt::SortOrder Order =
            Table && Table->horizontalHeader()
                ? Table->horizontalHeader()->sortIndicatorOrder()
                : Qt::AscendingOrder;
        return Order == Qt::AscendingOrder ? LeftPinned : !LeftPinned;
      }
      return QTableWidgetItem::operator<(Other);
    }
  };

  struct ProcessRow {
    DWORD Pid = 0;
    DWORD ParentPid = 0;
    DWORD ThreadCount = 0;
    DWORD HandleCount = 0;
    DWORD HandleCountError = ERROR_SUCCESS;
    DWORD SessionId = 0;
    DWORD IntegrityRid = 0;
    quint64 Eprocess = 0;
    QString Name;
    QString User;
    QString EprocessText;
    bool DriverData = false;
    bool HandleCountAvailable = false;
    bool Protected = false;
    bool Ppl = false;
    bool Critical = false;
    bool Hidden = false;
    UCHAR PplRaw = 0;
  };

  struct ThreadRow {
    DWORD Tid = 0;
    DWORD ProcessId = 0;
    UCHAR PreviousMode = 0;
    UCHAR ApcQueueable = 0;
    quint64 Ethread = 0;
    quint64 StartAddress = 0;
    DWORD Priority = 0;
    DWORD State = 0;
    QString ProcessName;
  };

  struct TableRenderState {
    struct Operation {
      enum class Type { Remove, Upsert };
      Type OperationType = Type::Upsert;
      DWORD Pid = 0;
      ProcessRow Row;
    };

    quint64 Generation = 0;
    int SortColumn = -1;
    Qt::SortOrder SortOrder = Qt::AscendingOrder;
    int CurrentRowCount = 0;
    int TargetRowCount = 0;
    int NextRow = 0;
    QSet<DWORD> SelectedPids;
    std::vector<ProcessRow> VisibleRows;
    std::vector<Operation> Operations;
    int NextOperation = 0;
  };

public:
  explicit TaskManagerPage(QWidget *Parent = nullptr) : QWidget(Parent) {
    auto *Layout = new QVBoxLayout(this);
    ConfigurePageLayout(Layout);
    auto *Toolbar = new QHBoxLayout;
    ConfigureToolbarLayout(Toolbar);
    ViewCombo = new ComboBox;
    ViewCombo->addItem("Process");
    ViewCombo->addItem("Thread");
    ViewCombo->setCurrentIndex(0);
    ViewCombo->setMinimumWidth(96);
    SearchEdit = new SearchLineEdit;
    SearchEdit->setPlaceholderText("Search by name, PID, or user");
    SearchEdit->setClearButtonEnabled(true);
    SearchEdit->setMaximumWidth(320);
    StatusLabel = new BodyLabel("Ready");
    RefreshIndicator = new IndeterminateProgressRing(this, false);
    RefreshIndicator->setFixedSize(22, 22);
    RefreshIndicator->hide();
    auto *RunButton = MakeButton("Run");
    auto *ProcessBlockButton = MakeButton("ProcessBlock");
    RefreshButton = MakeButton("Refresh", true);
    Toolbar->addWidget(ViewCombo);
    Toolbar->addWidget(SearchEdit);
    Toolbar->addWidget(StatusLabel, 1);
    Toolbar->addWidget(RefreshIndicator, 0, Qt::AlignVCenter);
    Toolbar->addWidget(RunButton);
    Toolbar->addWidget(ProcessBlockButton);
    Toolbar->addWidget(RefreshButton);
    Layout->addLayout(Toolbar);

    ProcessTable = MakeTable(
        {"PID", "Name", "User", "Integrity", "PPL", "EPROCESS", "Parent PID"});
    ProcessTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
    ProcessTable->setContextMenuPolicy(Qt::CustomContextMenu);
    ProcessTable->setSortingEnabled(true);
    ProcessTable->setProperty("UseGenericDetailDialog", false);
    ProcessTable->setTextElideMode(Qt::ElideNone);
    ProcessTable->horizontalHeader()->setSectionResizeMode(
        0, QHeaderView::ResizeToContents);
    ProcessTable->horizontalHeader()->setSectionResizeMode(
        1, QHeaderView::Stretch);
    ProcessTable->horizontalHeader()->setSectionResizeMode(
        2, QHeaderView::Stretch);
    for (int Column = 3; Column < ProcessTable->columnCount(); ++Column)
      ProcessTable->horizontalHeader()->setSectionResizeMode(
          Column, QHeaderView::ResizeToContents);
    Layout->addWidget(ProcessTable, 1);
    ProcessTable->verticalHeader()->setDefaultSectionSize(
        KCompactTableRowHeight);

    // 线程分视图表格：与 ProcessTable 同层布局，通过 SwitchView 互斥显示。
    ThreadTable = MakeTable(
        {"TID", "Parent ID", "Process", "ETHREAD", "Start Address",
         "PreviousMode", "ApcQueueable", "Priority", "State"});
    ThreadTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
    ThreadTable->setContextMenuPolicy(Qt::CustomContextMenu);
    ThreadTable->setProperty("UseGenericDetailDialog", false);
    ThreadTable->setTextElideMode(Qt::ElideNone);
    ThreadTable->horizontalHeader()->setSectionResizeMode(
        2, QHeaderView::Stretch);
    for (int Column = 0; Column < ThreadTable->columnCount(); ++Column)
      if (Column != 2)
        ThreadTable->horizontalHeader()->setSectionResizeMode(
            Column, QHeaderView::ResizeToContents);
    ThreadTable->verticalHeader()->setDefaultSectionSize(
        KCompactTableRowHeight);
    ThreadTable->hide();
    Layout->addWidget(ThreadTable, 1);
    QObject::connect(
        ThreadTable, &QWidget::customContextMenuRequested, this,
        [this](const QPoint &Position) { ShowThreadMenu(Position); });
    QObject::connect(
        ThreadTable, &QTableWidget::cellDoubleClicked, this,
        [this](int Row, int) {
          if (Row < 0 || Row >= static_cast<int>(RowTids.size()))
            return;
          if (const ThreadRow *Found = FindThread(RowTids[Row]))
            ShowThreadInspector(*Found);
        });

    SearchDebounceTimer = new QTimer(this);
    SearchDebounceTimer->setSingleShot(true);
    SearchDebounceTimer->setInterval(KSearchDebounceMs);
    QObject::connect(SearchDebounceTimer, &QTimer::timeout, this,
                     [this] {
                       // 搜索回填按当前视图路由到对应的表格。
                       if (ViewCombo && ViewCombo->currentIndex() == 1)
                         PopulateThreadTable();
                       else
                         PopulateTable();
                     });
    QObject::connect(SearchEdit, &QLineEdit::textChanged, this,
                     [this] { SearchDebounceTimer->start(); });
    QObject::connect(RunButton, &QPushButton::clicked, this,
                     [this] { ShowLaunchAsDialog(this); });
    QObject::connect(RefreshButton, &QPushButton::clicked, this, [this] {
      // 刷新按钮按当前视图刷新对应的表格。
      if (ViewCombo && ViewCombo->currentIndex() == 1) {
        RefreshThreads();
        ShowSuccessNotice(this, "Task", "Thread refresh started.");
      } else {
        RefreshProcesses();
        ShowSuccessNotice(this, "Task", "Process refresh started.");
      }
    });
    QObject::connect(
        ViewCombo,
        qOverload<int>(&ComboBox::currentIndexChanged), this,
        [this](int Index) { SwitchView(Index); });
    QObject::connect(ProcessBlockButton, &QPushButton::clicked, this,
                     [this] { ShowProcessBlockDialog(); });
    QObject::connect(
        ProcessTable, &QWidget::customContextMenuRequested, this,
        [this](const QPoint &Position) { ShowProcessMenu(Position); });
    QObject::connect(
        ProcessTable, &QTableWidget::cellDoubleClicked, this,
        [this](int Row, int) {
          if (ProcessTable->item(Row, 0))
            ShowProcessInspector(
                ProcessTable->item(Row, 0)->data(Qt::UserRole).toUInt());
        });

    auto *RefreshTimer = new QTimer(this);
    AutoRefreshTimer = RefreshTimer;
    QObject::connect(RefreshTimer, &QTimer::timeout, this, [this] {
      if (!isVisible())
        return;
      // 自动刷新同样按当前视图路由。
      if (ViewCombo && ViewCombo->currentIndex() == 1)
        RefreshThreads();
      else
        RefreshProcesses();
    });
    RefreshTimer->start(10000);
    RefreshProcesses();
  }

private:
  static QString QueryProcessUser(DWORD Pid) {
    QString Result = "N/A";
    HANDLE Process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
    if (!Process)
      return Result;
    HANDLE Token = nullptr;
    if (OpenProcessToken(Process, TOKEN_QUERY, &Token)) {
      DWORD Size = 0;
      GetTokenInformation(Token, TokenUser, nullptr, 0, &Size);
      std::vector<unsigned char> Buffer(Size);
      if (Size &&
          GetTokenInformation(Token, TokenUser, Buffer.data(), Size, &Size)) {
        const auto *TokenUserInformation =
            reinterpret_cast<TOKEN_USER *>(Buffer.data());
        wchar_t Name[256]{};
        wchar_t Domain[256]{};
        DWORD NameSize = 256;
        DWORD DomainSize = 256;
        SID_NAME_USE Use = SidTypeUnknown;
        if (LookupAccountSidW(nullptr, TokenUserInformation->User.Sid, Name,
                              &NameSize, Domain, &DomainSize, &Use))
          Result = QString::fromWCharArray(Domain) + "\\" +
                   QString::fromWCharArray(Name);
      }
      CloseHandle(Token);
    }
    CloseHandle(Process);
    return Result;
  }

  static DWORD QueryIntegrityRid(DWORD Pid) {
    HANDLE Process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
    if (!Process)
      return 0;
    HANDLE Token = nullptr;
    DWORD Result = 0;
    if (OpenProcessToken(Process, TOKEN_QUERY, &Token)) {
      Result = GetIntegrityLevel(Token);
      CloseHandle(Token);
    }
    CloseHandle(Process);
    return Result;
  }

  static bool QueryProcessHandleCount(DWORD Pid, DWORD &HandleCount,
                                      DWORD &ErrorCode) {
    HandleCount = 0;
    ErrorCode = ERROR_SUCCESS;

    HANDLE Process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
    if (!Process) {
      ErrorCode = GetLastError();
      return false;
    }

    const BOOL Success = GetProcessHandleCount(Process, &HandleCount);
    if (!Success)
      ErrorCode = GetLastError();

    CloseHandle(Process);
    return Success != FALSE;
  }

  static void QueryProcessDetails(DWORD Pid, ProcessRow &Row,
                                  QHash<QByteArray, QString> &UserCache) {
    Row.User = "N/A";
    Row.IntegrityRid = 0;
    Row.HandleCount = 0;
    Row.HandleCountError = ERROR_SUCCESS;
    Row.HandleCountAvailable = false;

    HANDLE Process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
    if (!Process) {
      Row.HandleCountError = GetLastError();
      return;
    }

    Row.HandleCountAvailable =
        GetProcessHandleCount(Process, &Row.HandleCount) != FALSE;
    if (!Row.HandleCountAvailable)
      Row.HandleCountError = GetLastError();

    HANDLE Token = nullptr;
    if (OpenProcessToken(Process, TOKEN_QUERY, &Token)) {
      Row.IntegrityRid = GetIntegrityLevel(Token);
      DWORD Size = 0;
      GetTokenInformation(Token, TokenUser, nullptr, 0, &Size);
      std::vector<unsigned char> Buffer(Size);
      if (Size &&
          GetTokenInformation(Token, TokenUser, Buffer.data(), Size, &Size)) {
        const auto *TokenUserInformation =
            reinterpret_cast<TOKEN_USER *>(Buffer.data());
        const QByteArray SidKey(
            reinterpret_cast<const char *>(TokenUserInformation->User.Sid),
            GetLengthSid(TokenUserInformation->User.Sid));
        const auto CachedUser = UserCache.constFind(SidKey);
        if (CachedUser != UserCache.cend()) {
          Row.User = CachedUser.value();
          CloseHandle(Token);
          CloseHandle(Process);
          return;
        }
        wchar_t Name[256]{};
        wchar_t Domain[256]{};
        DWORD NameSize = ARRAYSIZE(Name);
        DWORD DomainSize = ARRAYSIZE(Domain);
        SID_NAME_USE Use = SidTypeUnknown;
        if (LookupAccountSidW(nullptr, TokenUserInformation->User.Sid, Name,
                              &NameSize, Domain, &DomainSize, &Use)) {
          Row.User = QString::fromWCharArray(Domain) + "\\" +
                     QString::fromWCharArray(Name);
          UserCache.insert(SidKey, Row.User);
        }
      }
      CloseHandle(Token);
    }
    CloseHandle(Process);
  }

  static QString FormatTaskPointer(quint64 Value) {
    if (Value == 0)
      return "-";
    return QString("0x%1")
        .arg(Value, sizeof(quintptr) * 2, 16, QLatin1Char('0'))
        .toUpper();
  }

  static bool ParseHexPointerValue(const QString &Text, ULONG_PTR &Value) {
    QString Clean = Text.trimmed();
    if (Clean.isEmpty())
      return false;
    Clean.replace("0x", "", Qt::CaseInsensitive);
    Clean.remove(' ');
    Clean.remove('\t');
    Clean.remove('\r');
    Clean.remove('\n');
    if (Clean.isEmpty())
      return false;

    bool Ok = false;
    const qulonglong Parsed = Clean.toULongLong(&Ok, 16);
    if (!Ok || Parsed > std::numeric_limits<ULONG_PTR>::max())
      return false;

    Value = static_cast<ULONG_PTR>(Parsed);
    return true;
  }

  static bool ParseHexBytes(const QString &Text, QByteArray &Bytes,
                            QString *ErrorText = nullptr) {
    QString Clean = Text.trimmed();
    Clean.replace("0x", "", Qt::CaseInsensitive);
    Clean.remove(' ');
    Clean.remove('\t');
    Clean.remove('\r');
    Clean.remove('\n');
    Clean.remove(',');
    Clean.remove(':');
    Clean.remove('-');

    if (Clean.isEmpty()) {
      if (ErrorText)
        *ErrorText = "Enter shellcode bytes in hex.";
      return false;
    }

    for (const QChar Ch : Clean) {
      const ushort Code = Ch.unicode();
      if (!((Code >= '0' && Code <= '9') || (Code >= 'a' && Code <= 'f') ||
            (Code >= 'A' && Code <= 'F'))) {
        if (ErrorText)
          *ErrorText = "Shellcode must contain hex bytes only.";
        return false;
      }
    }

    if ((Clean.size() & 1) != 0) {
      if (ErrorText)
        *ErrorText = "Shellcode hex length must be even.";
      return false;
    }

    Bytes.clear();
    Bytes.reserve(Clean.size() / 2);
    for (int Index = 0; Index < Clean.size(); Index += 2) {
      bool Ok = false;
      const int Byte = Clean.mid(Index, 2).toInt(&Ok, 16);
      if (!Ok || Byte < 0 || Byte > 0xFF) {
        if (ErrorText)
          *ErrorText = "Shellcode parse failed.";
        return false;
      }
      Bytes.append(static_cast<char>(Byte));
    }
    return true;
  }

  static QString FormatProcessCpuTime(quint64 HundredNanoseconds) {
    return FormatDuration(HundredNanoseconds / 10000);
  }

  struct InspectorHandleRow {
    quint64 HandleValue = 0;
    quint64 ObjectAddress = 0;
    quint32 GrantedAccess = 0;
    quint32 Attributes = 0;
    QString TypeName;
    QString ObjectName;
  };

  struct HandleAccessEntry {
    quint32 Mask = 0;
    const char *Name = nullptr;
  };

  static constexpr quint32 KEventQueryState = 0x0001;
  static constexpr quint32 KEventModifyState = 0x0002;
  static constexpr quint32 KMutantQueryState = 0x0001;
  static constexpr long KStatusUnsuccessful = static_cast<long>(0xC0000001L);

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
    if (Type.contains(QLatin1Char('\\')))
      Type = Type.section(QLatin1Char('\\'), -1).trimmed();
    if (Type.compare("Mutant", Qt::CaseInsensitive) == 0 ||
        Type.compare("Mutex", Qt::CaseInsensitive) == 0)
      Type = "Mutant";
    else if (Type.compare("Registry", Qt::CaseInsensitive) == 0 ||
             Type.compare("RegistryKey", Qt::CaseInsensitive) == 0)
      Type = "Key";
    if (Type.compare("Process", Qt::CaseInsensitive) == 0)
      Entries.insert(
          Entries.end(),
          {
              {PROCESS_TERMINATE, "PROCESS_TERMINATE"},
              {PROCESS_CREATE_THREAD, "PROCESS_CREATE_THREAD"},
              {PROCESS_SET_SESSIONID, "PROCESS_SET_SESSIONID"},
              {PROCESS_VM_OPERATION, "PROCESS_VM_OPERATION"},
              {PROCESS_VM_READ, "PROCESS_VM_READ"},
              {PROCESS_VM_WRITE, "PROCESS_VM_WRITE"},
              {PROCESS_DUP_HANDLE, "PROCESS_DUP_HANDLE"},
              {PROCESS_CREATE_PROCESS, "PROCESS_CREATE_PROCESS"},
              {PROCESS_SET_QUOTA, "PROCESS_SET_QUOTA"},
              {PROCESS_SET_INFORMATION, "PROCESS_SET_INFORMATION"},
              {PROCESS_QUERY_INFORMATION, "PROCESS_QUERY_INFORMATION"},
              {PROCESS_SUSPEND_RESUME, "PROCESS_SUSPEND_RESUME"},
              {PROCESS_QUERY_LIMITED_INFORMATION,
               "PROCESS_QUERY_LIMITED_INFORMATION"},
          });
    else if (Type.compare("Thread", Qt::CaseInsensitive) == 0)
      Entries.insert(
          Entries.end(),
          {
              {THREAD_TERMINATE, "THREAD_TERMINATE"},
              {THREAD_SUSPEND_RESUME, "THREAD_SUSPEND_RESUME"},
              {THREAD_GET_CONTEXT, "THREAD_GET_CONTEXT"},
              {THREAD_SET_CONTEXT, "THREAD_SET_CONTEXT"},
              {THREAD_QUERY_INFORMATION, "THREAD_QUERY_INFORMATION"},
              {THREAD_SET_INFORMATION, "THREAD_SET_INFORMATION"},
              {THREAD_SET_THREAD_TOKEN, "THREAD_SET_THREAD_TOKEN"},
              {THREAD_IMPERSONATE, "THREAD_IMPERSONATE"},
              {THREAD_DIRECT_IMPERSONATION, "THREAD_DIRECT_IMPERSONATION"},
              {THREAD_SET_LIMITED_INFORMATION,
               "THREAD_SET_LIMITED_INFORMATION"},
              {THREAD_QUERY_LIMITED_INFORMATION,
               "THREAD_QUERY_LIMITED_INFORMATION"},
          });
    else if (Type.compare("File", Qt::CaseInsensitive) == 0)
      Entries.insert(Entries.end(),
                     {
                         {FILE_READ_DATA, "FILE_READ_DATA"},
                         {FILE_WRITE_DATA, "FILE_WRITE_DATA"},
                         {FILE_APPEND_DATA, "FILE_APPEND_DATA"},
                         {FILE_READ_EA, "FILE_READ_EA"},
                         {FILE_WRITE_EA, "FILE_WRITE_EA"},
                         {FILE_EXECUTE, "FILE_EXECUTE"},
                         {FILE_DELETE_CHILD, "FILE_DELETE_CHILD"},
                         {FILE_READ_ATTRIBUTES, "FILE_READ_ATTRIBUTES"},
                         {FILE_WRITE_ATTRIBUTES, "FILE_WRITE_ATTRIBUTES"},
                     });
    else if (Type.compare("Key", Qt::CaseInsensitive) == 0)
      Entries.insert(Entries.end(),
                     {
                         {KEY_QUERY_VALUE, "KEY_QUERY_VALUE"},
                         {KEY_SET_VALUE, "KEY_SET_VALUE"},
                         {KEY_CREATE_SUB_KEY, "KEY_CREATE_SUB_KEY"},
                         {KEY_ENUMERATE_SUB_KEYS, "KEY_ENUMERATE_SUB_KEYS"},
                         {KEY_NOTIFY, "KEY_NOTIFY"},
                         {KEY_CREATE_LINK, "KEY_CREATE_LINK"},
                         {KEY_WOW64_32KEY, "KEY_WOW64_32KEY"},
                         {KEY_WOW64_64KEY, "KEY_WOW64_64KEY"},
                     });
    else if (Type.compare("Section", Qt::CaseInsensitive) == 0)
      Entries.insert(
          Entries.end(),
          {
              {SECTION_QUERY, "SECTION_QUERY"},
              {SECTION_MAP_WRITE, "SECTION_MAP_WRITE"},
              {SECTION_MAP_READ, "SECTION_MAP_READ"},
              {SECTION_MAP_EXECUTE, "SECTION_MAP_EXECUTE"},
              {SECTION_EXTEND_SIZE, "SECTION_EXTEND_SIZE"},
              {SECTION_MAP_EXECUTE_EXPLICIT, "SECTION_MAP_EXECUTE_EXPLICIT"},
          });
    else if (Type.compare("Event", Qt::CaseInsensitive) == 0)
      Entries.insert(Entries.end(),
                     {
                         {KEventQueryState, "EVENT_QUERY_STATE"},
                         {KEventModifyState, "EVENT_MODIFY_STATE"},
                     });
    else if (Type.compare("Mutant", Qt::CaseInsensitive) == 0)
      Entries.insert(Entries.end(),
                     {
                         {KMutantQueryState, "MUTANT_QUERY_STATE"},
                     });
    else if (Type.compare("Token", Qt::CaseInsensitive) == 0)
      Entries.insert(Entries.end(),
                     {
                         {TOKEN_ASSIGN_PRIMARY, "TOKEN_ASSIGN_PRIMARY"},
                         {TOKEN_DUPLICATE, "TOKEN_DUPLICATE"},
                         {TOKEN_IMPERSONATE, "TOKEN_IMPERSONATE"},
                         {TOKEN_QUERY, "TOKEN_QUERY"},
                         {TOKEN_QUERY_SOURCE, "TOKEN_QUERY_SOURCE"},
                         {TOKEN_ADJUST_PRIVILEGES, "TOKEN_ADJUST_PRIVILEGES"},
                         {TOKEN_ADJUST_GROUPS, "TOKEN_ADJUST_GROUPS"},
                         {TOKEN_ADJUST_DEFAULT, "TOKEN_ADJUST_DEFAULT"},
                         {TOKEN_ADJUST_SESSIONID, "TOKEN_ADJUST_SESSIONID"},
                     });
    else if (Type.compare("Semaphore", Qt::CaseInsensitive) == 0)
      Entries.insert(Entries.end(), {
                                        {0x0001, "SEMAPHORE_QUERY_STATE"},
                                        {0x0002, "SEMAPHORE_MODIFY_STATE"},
                                    });
    else if (Type.compare("Timer", Qt::CaseInsensitive) == 0)
      Entries.insert(Entries.end(), {
                                        {0x0001, "TIMER_QUERY_STATE"},
                                        {0x0002, "TIMER_MODIFY_STATE"},
                                    });
    else if (Type.compare("Job", Qt::CaseInsensitive) == 0)
      Entries.insert(
          Entries.end(),
          {
              {JOB_OBJECT_ASSIGN_PROCESS, "JOB_OBJECT_ASSIGN_PROCESS"},
              {JOB_OBJECT_SET_ATTRIBUTES, "JOB_OBJECT_SET_ATTRIBUTES"},
              {JOB_OBJECT_QUERY, "JOB_OBJECT_QUERY"},
              {JOB_OBJECT_TERMINATE, "JOB_OBJECT_TERMINATE"},
              {JOB_OBJECT_SET_SECURITY_ATTRIBUTES,
               "JOB_OBJECT_SET_SECURITY_ATTRIBUTES"},
              {JOB_OBJECT_IMPERSONATE, "JOB_OBJECT_IMPERSONATE"},
          });
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
        Mask, {
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
              });
    if (!Generic.isEmpty())
      Parts.append(Generic);

    const auto Type = TypeName.trimmed();
    if (Type.compare("Process", Qt::CaseInsensitive) == 0) {
      Parts.append(FormatAccessMask(
          Mask, {
                    {PROCESS_TERMINATE, "PROCESS_TERMINATE"},
                    {PROCESS_CREATE_THREAD, "PROCESS_CREATE_THREAD"},
                    {PROCESS_SET_SESSIONID, "PROCESS_SET_SESSIONID"},
                    {PROCESS_VM_OPERATION, "PROCESS_VM_OPERATION"},
                    {PROCESS_VM_READ, "PROCESS_VM_READ"},
                    {PROCESS_VM_WRITE, "PROCESS_VM_WRITE"},
                    {PROCESS_DUP_HANDLE, "PROCESS_DUP_HANDLE"},
                    {PROCESS_CREATE_PROCESS, "PROCESS_CREATE_PROCESS"},
                    {PROCESS_SET_QUOTA, "PROCESS_SET_QUOTA"},
                    {PROCESS_SET_INFORMATION, "PROCESS_SET_INFORMATION"},
                    {PROCESS_QUERY_INFORMATION, "PROCESS_QUERY_INFORMATION"},
                    {PROCESS_SUSPEND_RESUME, "PROCESS_SUSPEND_RESUME"},
                    {PROCESS_QUERY_LIMITED_INFORMATION,
                     "PROCESS_QUERY_LIMITED_INFORMATION"},
                }));
    } else if (Type.compare("Thread", Qt::CaseInsensitive) == 0) {
      Parts.append(FormatAccessMask(
          Mask,
          {
              {THREAD_TERMINATE, "THREAD_TERMINATE"},
              {THREAD_SUSPEND_RESUME, "THREAD_SUSPEND_RESUME"},
              {THREAD_GET_CONTEXT, "THREAD_GET_CONTEXT"},
              {THREAD_SET_CONTEXT, "THREAD_SET_CONTEXT"},
              {THREAD_QUERY_INFORMATION, "THREAD_QUERY_INFORMATION"},
              {THREAD_SET_INFORMATION, "THREAD_SET_INFORMATION"},
              {THREAD_SET_THREAD_TOKEN, "THREAD_SET_THREAD_TOKEN"},
              {THREAD_IMPERSONATE, "THREAD_IMPERSONATE"},
              {THREAD_DIRECT_IMPERSONATION, "THREAD_DIRECT_IMPERSONATION"},
              {THREAD_SET_LIMITED_INFORMATION,
               "THREAD_SET_LIMITED_INFORMATION"},
              {THREAD_QUERY_LIMITED_INFORMATION,
               "THREAD_QUERY_LIMITED_INFORMATION"},
          }));
    } else if (Type.compare("File", Qt::CaseInsensitive) == 0) {
      Parts.append(FormatAccessMask(
          Mask, {
                    {FILE_READ_DATA, "FILE_READ_DATA"},
                    {FILE_WRITE_DATA, "FILE_WRITE_DATA"},
                    {FILE_APPEND_DATA, "FILE_APPEND_DATA"},
                    {FILE_READ_EA, "FILE_READ_EA"},
                    {FILE_WRITE_EA, "FILE_WRITE_EA"},
                    {FILE_EXECUTE, "FILE_EXECUTE"},
                    {FILE_DELETE_CHILD, "FILE_DELETE_CHILD"},
                    {FILE_READ_ATTRIBUTES, "FILE_READ_ATTRIBUTES"},
                    {FILE_WRITE_ATTRIBUTES, "FILE_WRITE_ATTRIBUTES"},
                }));
    } else if (Type.compare("Key", Qt::CaseInsensitive) == 0) {
      Parts.append(FormatAccessMask(
          Mask, {
                    {KEY_QUERY_VALUE, "KEY_QUERY_VALUE"},
                    {KEY_SET_VALUE, "KEY_SET_VALUE"},
                    {KEY_CREATE_SUB_KEY, "KEY_CREATE_SUB_KEY"},
                    {KEY_ENUMERATE_SUB_KEYS, "KEY_ENUMERATE_SUB_KEYS"},
                    {KEY_NOTIFY, "KEY_NOTIFY"},
                    {KEY_CREATE_LINK, "KEY_CREATE_LINK"},
                    {KEY_WOW64_32KEY, "KEY_WOW64_32KEY"},
                    {KEY_WOW64_64KEY, "KEY_WOW64_64KEY"},
                }));
    } else if (Type.compare("Section", Qt::CaseInsensitive) == 0) {
      Parts.append(FormatAccessMask(
          Mask,
          {
              {SECTION_QUERY, "SECTION_QUERY"},
              {SECTION_MAP_WRITE, "SECTION_MAP_WRITE"},
              {SECTION_MAP_READ, "SECTION_MAP_READ"},
              {SECTION_MAP_EXECUTE, "SECTION_MAP_EXECUTE"},
              {SECTION_EXTEND_SIZE, "SECTION_EXTEND_SIZE"},
              {SECTION_MAP_EXECUTE_EXPLICIT, "SECTION_MAP_EXECUTE_EXPLICIT"},
          }));
    } else if (Type.compare("Event", Qt::CaseInsensitive) == 0) {
      Parts.append(
          FormatAccessMask(Mask, {
                                     {KEventQueryState, "EVENT_QUERY_STATE"},
                                     {KEventModifyState, "EVENT_MODIFY_STATE"},
                                 }));
    } else if (Type.compare("Mutant", Qt::CaseInsensitive) == 0) {
      Parts.append(
          FormatAccessMask(Mask, {
                                     {KMutantQueryState, "MUTANT_QUERY_STATE"},
                                 }));
    } else if (Type.compare("Token", Qt::CaseInsensitive) == 0) {
      Parts.append(FormatAccessMask(
          Mask, {
                    {TOKEN_ASSIGN_PRIMARY, "TOKEN_ASSIGN_PRIMARY"},
                    {TOKEN_DUPLICATE, "TOKEN_DUPLICATE"},
                    {TOKEN_IMPERSONATE, "TOKEN_IMPERSONATE"},
                    {TOKEN_QUERY, "TOKEN_QUERY"},
                    {TOKEN_QUERY_SOURCE, "TOKEN_QUERY_SOURCE"},
                    {TOKEN_ADJUST_PRIVILEGES, "TOKEN_ADJUST_PRIVILEGES"},
                    {TOKEN_ADJUST_GROUPS, "TOKEN_ADJUST_GROUPS"},
                    {TOKEN_ADJUST_DEFAULT, "TOKEN_ADJUST_DEFAULT"},
                    {TOKEN_ADJUST_SESSIONID, "TOKEN_ADJUST_SESSIONID"},
                }));
    }

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
                              const QString &Title, const QString &Description,
                              const QString &ApplyText = "Apply") {
    QDialog Dialog(Parent);
    Dialog.setWindowTitle(Title);
    Dialog.setModal(true);
    Dialog.resize(560, 310);

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
    Preview->setMinimumHeight(38);
    Preview->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    auto UpdatePreview = [Preview, AccessCombo, TypeName]() {
      quint32 Mask = 0;
      for (const QVariant &Data : AccessCombo->selectedDatas())
        Mask |= Data.toUInt();
      Preview->setText("Access: " + FormatHandleAccessDisplay(TypeName, Mask));
    };
    QObject::connect(AccessCombo, &MultiViewComboBox::selectionChanged, &Dialog,
                     UpdatePreview);
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

    QObject::connect(Cancel, &QPushButton::clicked, &Dialog, &QDialog::reject);
    QObject::connect(Apply, &QPushButton::clicked, &Dialog, &QDialog::accept);

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
           Status == KStatusBufferOverflow || Status == KStatusBufferTooSmall;
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
    NTSTATUS Status = static_cast<NTSTATUS>(KStatusUnsuccessful);
    Buffer.resize(Size);
    for (int Attempt = 0; Attempt < 8; ++Attempt) {
      Status =
          QueryObject(Handle, InfoClass, Buffer.data(), Size, &ReturnLength);
      if (Status >= 0) {
        if (ReturnLength != 0 && ReturnLength <= Size)
          Buffer.resize(ReturnLength);
        return true;
      }
      if (!IsNtQueryObjectResizeStatus(Status))
        return false;

      const ULONG NextSize =
          ReturnLength > Size ? ReturnLength + 0x100 : Size * 2;
      Size = std::max<ULONG>(NextSize, 0x200);
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

  static bool QueryUserModeHandles(DWORD Pid,
                                   std::vector<InspectorHandleRow> &Rows,
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

    struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_LOCAL {
      PVOID Object;
      ULONG_PTR UniqueProcessId;
      ULONG_PTR HandleValue;
      ULONG GrantedAccess;
      USHORT CreatorBackTraceIndex;
      USHORT ObjectTypeIndex;
      ULONG HandleAttributes;
      ULONG Reserved;
    };

    struct SYSTEM_HANDLE_INFORMATION_EX_LOCAL {
      ULONG_PTR NumberOfHandles;
      ULONG_PTR Reserved;
      SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_LOCAL Handles[1];
    };

    ULONG Size = 1 << 20;
    std::vector<BYTE> Buffer(Size);
    NTSTATUS Status = KStatusInfoLengthMismatch;
    ULONG ReturnLength = 0;
    for (int Attempt = 0; Attempt < 8 &&
                           Status == KStatusInfoLengthMismatch;
         ++Attempt) {
      Status = QuerySystemInformation(KSystemExtendedHandleInformationClass,
                                      Buffer.data(), Size, &ReturnLength);
      if (Status == KStatusInfoLengthMismatch) {
        // 防止 Size 翻倍溢出 ULONG 或尝试 >1GB 的荒谬分配。
        if (Size >= 0x40000000u) {
          ErrorCode = ERROR_NOT_ENOUGH_MEMORY;
          return false;
        }
        Size = std::max(Size * 2, ReturnLength + 0x1000u);
        Buffer.resize(Size);
      }
    }
    if (Status < 0) {
      ErrorCode = RtlNtStatusToDosError(Status);
      return false;
    }

    HANDLE Process = OpenProcess(
        PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
    ErrorCode = Process ? ERROR_SUCCESS : GetLastError();

    const auto *Handles =
        reinterpret_cast<const SYSTEM_HANDLE_INFORMATION_EX_LOCAL *>(
            Buffer.data());
    Rows.clear();
    for (ULONG_PTR Index = 0; Index < Handles->NumberOfHandles; ++Index) {
      const auto &Entry = Handles->Handles[Index];
      if (static_cast<DWORD>(Entry.UniqueProcessId) != Pid)
        continue;

      InspectorHandleRow Row;
      Row.HandleValue = static_cast<quint64>(Entry.HandleValue);
      Row.ObjectAddress = reinterpret_cast<quint64>(Entry.Object);
      Row.GrantedAccess = Entry.GrantedAccess;
      Row.Attributes = Entry.HandleAttributes;

      if (Process) {
        HANDLE Duplicate = nullptr;
        if (DuplicateHandle(Process,
                            reinterpret_cast<HANDLE>(Entry.HandleValue),
                            GetCurrentProcess(), &Duplicate, 0, FALSE,
                            DUPLICATE_SAME_ACCESS)) {
          Row.TypeName = QueryObjectTypeName(Duplicate);
          // 文件/管道的名字查询可能等待 I/O 完成，保留对象地址即可。
          const bool QueryName =
              Row.TypeName.compare("Key", Qt::CaseInsensitive) == 0 ||
              Row.TypeName.compare("Directory", Qt::CaseInsensitive) == 0 ||
              Row.TypeName.compare("SymbolicLink", Qt::CaseInsensitive) == 0 ||
              Row.TypeName.compare("Section", Qt::CaseInsensitive) == 0 ||
              Row.TypeName.compare("Event", Qt::CaseInsensitive) == 0 ||
              Row.TypeName.compare("Mutant", Qt::CaseInsensitive) == 0 ||
              Row.TypeName.compare("Process", Qt::CaseInsensitive) == 0 ||
              Row.TypeName.compare("Thread", Qt::CaseInsensitive) == 0 ||
              Row.TypeName.compare("Desktop", Qt::CaseInsensitive) == 0 ||
              Row.TypeName.compare("WindowStation", Qt::CaseInsensitive) == 0;
          if (QueryName)
            Row.ObjectName = QueryObjectName(Duplicate);
          CloseHandle(Duplicate);
        }
      }

      Rows.push_back(std::move(Row));
    }

    if (Process)
      CloseHandle(Process);
    return true;
  }

  QString IntegrityName(DWORD Rid) const {
    if (Rid >= 0x5000)
      return "Protected";
    if (Rid >= 0x4000)
      return "System";
    if (Rid >= 0x3000)
      return "High";
    if (Rid >= 0x2000)
      return "Medium";
    if (Rid >= 0x1000)
      return "Low";
    return Rid == 0 ? "Unknown" : "Untrusted";
  }

  static void SortProcessRows(std::vector<ProcessRow> &ProcessRows) {
    std::stable_sort(ProcessRows.begin(), ProcessRows.end(),
                     [](const ProcessRow &Left, const ProcessRow &Right) {
                       if (Left.Hidden != Right.Hidden)
                         return Left.Hidden;
                       return Left.Pid < Right.Pid;
                     });
  }

  void RefreshProcesses() {
    if (Rendering || Refreshing.load()) {
      RefreshPending = true;
      return;
    }
    if (Refreshing.exchange(true))
      return;
    RefreshButton->setEnabled(false);
    RefreshButton->setText("Refreshing...");
    SearchEdit->setEnabled(true);
    if (RefreshIndicator) {
      RefreshIndicator->show();
      RefreshIndicator->start();
    }
    QPointer<TaskManagerPage> Page(this);
    const QSet<DWORD> ProtectedSnapshot = ProtectedPids;
    std::thread([Page, ProtectedSnapshot] {
      SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST);
      std::vector<ProcessRow> Result;
      std::vector<PROCESS_ENUM_ENTRY> DriverEntries;
      QHash<QByteArray, QString> UserCache;
      // 路径缓冲提到循环外复用：每进程 64KB 的栈/堆分配是纯浪费。
      std::vector<WCHAR> ImagePath(32768);
      const bool UsedDriver =
          EnumProcessEntries(DriverEntries) && !DriverEntries.empty();
      if (UsedDriver) {
        for (const PROCESS_ENUM_ENTRY &Entry : DriverEntries) {
          ProcessRow Row;
          Row.Pid = Entry.ProcessId;
          Row.ParentPid = Entry.ParentPid;
          Row.ThreadCount = Entry.ThreadCount;
          Row.SessionId = Entry.SessionId;
          DWORD UserModeSessionId = 0;
          if (ProcessIdToSessionId(Row.Pid, &UserModeSessionId))
            Row.SessionId = UserModeSessionId;
          Row.Name = Entry.ImageName[0]
                         ? QString::fromWCharArray(Entry.ImageName)
                         : "Unknown";
          Row.DriverData = true;
          Row.Ppl = Entry.IsPplProtected != FALSE;
          Row.PplRaw = Entry.PplRawLevel;
          Row.Critical = Entry.IsCritical != FALSE;
          Row.Hidden = Entry.IsHidden != FALSE;
          QueryProcessDetails(Row.Pid, Row, UserCache);
          HANDLE Process =
              OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Row.Pid);
          if (Process) {
            DWORD ImagePathLength = static_cast<DWORD>(ImagePath.size());
            if (QueryFullProcessImageNameW(Process, 0, ImagePath.data(),
                                           &ImagePathLength)) {
              const QString FullPath =
                  QString::fromWCharArray(ImagePath.data(), ImagePathLength);
              const QString FullName = QFileInfo(FullPath).fileName();
              if (!FullName.isEmpty())
                Row.Name = FullName;
            }
            CloseHandle(Process);
          }
          Row.Eprocess = Entry.ObjectAddress;
          Row.EprocessText = FormatTaskPointer(Row.Eprocess);
          Result.push_back(std::move(Row));
        }
      } else {
        HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (Snapshot != INVALID_HANDLE_VALUE) {
          PROCESSENTRY32W Entry{sizeof(Entry)};
          if (Process32FirstW(Snapshot, &Entry)) {
            do {
              ProcessRow Row;
              Row.Pid = Entry.th32ProcessID;
              Row.ParentPid = Entry.th32ParentProcessID;
              Row.ThreadCount = Entry.cntThreads;
              Row.Name = QString::fromWCharArray(Entry.szExeFile);
              ProcessIdToSessionId(Row.Pid, &Row.SessionId);
              QueryProcessDetails(Row.Pid, Row, UserCache);
              Row.EprocessText = "-";
              Result.push_back(std::move(Row));
            } while (Process32NextW(Snapshot, &Entry));
          }
          CloseHandle(Snapshot);
        }
      }
      for (ProcessRow &Row : Result) {
        if (ProtectedSnapshot.contains(Row.Pid))
          Row.Protected = true;
      }
      QMetaObject::invokeMethod(
          qApp,
          [Page, Result = std::move(Result), UsedDriver]() mutable {
            if (!Page)
              return;
            for (auto Retained = Page->RetainedProcesses.begin();
                 Retained != Page->RetainedProcesses.end();) {
              const DWORD Pid = Retained->first;
              auto Match = std::find_if(
                  Result.begin(), Result.end(),
                  [Pid](const ProcessRow &Row) { return Row.Pid == Pid; });
              if (Match != Result.end()) {
                if (Retained->second.Hidden) {
                  Match->Hidden = true;
                  ++Retained;
                } else {
                  Retained = Page->RetainedProcesses.erase(Retained);
                }
                continue;
              }

              bool ProcessExited = false;
              HANDLE Process = OpenProcess(SYNCHRONIZE, FALSE, Pid);
              if (Process) {
                ProcessExited =
                    WaitForSingleObject(Process, 0) == WAIT_OBJECT_0;
                CloseHandle(Process);
              }
              if (ProcessExited) {
                Retained = Page->RetainedProcesses.erase(Retained);
                continue;
              }
              Result.push_back(Retained->second);
              ++Retained;
            }
            SortProcessRows(Result);
            Page->Rows = std::move(Result);
            Page->StatusLabel->setText(QString("%1 processes  |  %2")
                                           .arg(Page->Rows.size())
                                           .arg(UsedDriver
                                                    ? "Driver enumeration"
                                                    : "Toolhelp fallback"));
            Page->Refreshing = false;
            if (Page->ActiveInspectorDialogs > 0)
              Page->ProcessTablePopulatePending = true;
            else
              Page->PopulateTable();
          },
          Qt::QueuedConnection);
    }).detach();
  }

  void PopulateTable() {
    if (ActiveInspectorDialogs > 0) {
      ProcessTablePopulatePending = true;
      return;
    }
    ProcessTablePopulatePending = false;

    TableRenderState NextState;
    NextState.Generation = ++TableRenderGeneration;
    NextState.SortColumn =
        ProcessTable->horizontalHeader()->sortIndicatorSection();
    NextState.SortOrder =
        ProcessTable->horizontalHeader()->sortIndicatorOrder();
    NextState.CurrentRowCount = ProcessTable->rowCount();
    for (const QModelIndex &Selected :
         ProcessTable->selectionModel()->selectedRows(0)) {
      if (const QTableWidgetItem *Item = ProcessTable->item(Selected.row(), 0))
        NextState.SelectedPids.insert(Item->data(Qt::UserRole).toUInt());
    }

    const QString Query = SearchEdit->text().trimmed();
    NextState.VisibleRows.reserve(Rows.size());
    for (const ProcessRow &Process : Rows) {
      if (!Query.isEmpty() &&
          !Process.Name.contains(Query, Qt::CaseInsensitive) &&
          !Process.User.contains(Query, Qt::CaseInsensitive) &&
          !Process.EprocessText.contains(Query, Qt::CaseInsensitive) &&
          !QString::number(Process.Pid).contains(Query))
        continue;
      NextState.VisibleRows.push_back(Process);
    }
    NextState.TargetRowCount = static_cast<int>(NextState.VisibleRows.size());
    const QSet<DWORD> VisiblePids = [this, &NextState] {
      QSet<DWORD> Pids;
      Pids.reserve(NextState.VisibleRows.size());
      for (const ProcessRow &Process : NextState.VisibleRows)
        Pids.insert(Process.Pid);
      return Pids;
    }();
    QHash<DWORD, int> ExistingRows;
    ExistingRows.reserve(ProcessTable->rowCount());
    for (int Row = 0; Row < ProcessTable->rowCount(); ++Row) {
      if (const QTableWidgetItem *Item = ProcessTable->item(Row, 0))
        ExistingRows.insert(Item->data(Qt::UserRole).toUInt(), Row);
    }
    for (int Row = ProcessTable->rowCount() - 1; Row >= 0; --Row) {
      const QTableWidgetItem *Item = ProcessTable->item(Row, 0);
      const DWORD Pid = Item ? Item->data(Qt::UserRole).toUInt() : 0;
      if (Pid == 0 || !VisiblePids.contains(Pid)) {
        TableRenderState::Operation Operation;
        Operation.OperationType = TableRenderState::Operation::Type::Remove;
        Operation.Pid = Pid;
        NextState.Operations.push_back(std::move(Operation));
      }
    }
    for (const ProcessRow &Process : NextState.VisibleRows) {
      const int ExistingRow = ExistingRows.value(Process.Pid, -1);
      if (ExistingRow < 0 || !ProcessTableRowsMatch(ExistingRow, Process)) {
        TableRenderState::Operation Operation;
        Operation.OperationType = TableRenderState::Operation::Type::Upsert;
        Operation.Pid = Process.Pid;
        Operation.Row = Process;
        NextState.Operations.push_back(std::move(Operation));
      }
    }
    RenderState = std::move(NextState);
    Rendering = true;
    RefreshButton->setEnabled(false);
    RefreshButton->setText("Rendering...");
    ProcessTable->setSortingEnabled(false);
    ProcessTable->setUpdatesEnabled(false);
    ContinuePopulateTable(RenderState.Generation);
  }

  bool ProcessTableRowsMatch(int Row, const ProcessRow &Process) const {
    const QTableWidgetItem *PidItem = ProcessTable->item(Row, 0);
    const QTableWidgetItem *NameItem = ProcessTable->item(Row, 1);
    const QTableWidgetItem *UserItem = ProcessTable->item(Row, 2);
    const QTableWidgetItem *IntegrityItem = ProcessTable->item(Row, 3);
    const QTableWidgetItem *PplItem = ProcessTable->item(Row, 4);
    const QTableWidgetItem *EprocessItem = ProcessTable->item(Row, 5);
    const QTableWidgetItem *ParentPidItem = ProcessTable->item(Row, 6);
    if (!PidItem || !NameItem || !UserItem || !IntegrityItem || !PplItem ||
        !EprocessItem || !ParentPidItem)
      return false;
    const QString PplText =
        Process.Ppl
            ? QString("Yes (0x%1)").arg(Process.PplRaw, 2, 16, QLatin1Char('0'))
            : "No";
    const QString EprocessText = Process.EprocessText.isEmpty()
                                     ? FormatTaskPointer(Process.Eprocess)
                                     : Process.EprocessText;
    return PidItem->data(Qt::UserRole).toUInt() == Process.Pid &&
           PidItem->data(KProcessPinnedRole).toBool() == Process.Hidden &&
           NameItem->text() == Process.Name &&
           UserItem->text() == Process.User &&
           IntegrityItem->text() == IntegrityName(Process.IntegrityRid) &&
           PplItem->text() == PplText && EprocessItem->text() == EprocessText &&
           ParentPidItem->text() == QString::number(Process.ParentPid);
  }

  void ContinuePopulateTable(quint64 Generation) {
    if (!Rendering || Generation != TableRenderGeneration)
      return;
    if (!isVisible()) {
      QTimer::singleShot(
          100, this, [this, Generation] { ContinuePopulateTable(Generation); });
      return;
    }

    QElapsedTimer Timer;
    Timer.start();
    // Pid->行号索引：每批重建一次，批内删除行后置为失效、下次查找前重建，
    // 替代对每个操作线性扫描整张表。
    QHash<DWORD, int> RowIndex;
    bool RowIndexStale = false;
    const auto RebuildRowIndex = [this, &RowIndex, &RowIndexStale] {
      RowIndex.clear();
      RowIndex.reserve(ProcessTable->rowCount());
      for (int Row = 0; Row < ProcessTable->rowCount(); ++Row) {
        if (const QTableWidgetItem *Item = ProcessTable->item(Row, 0))
          RowIndex.insert(Item->data(Qt::UserRole).toUInt(), Row);
      }
      RowIndexStale = false;
    };
    RebuildRowIndex();
    const auto FindRow = [&](DWORD Pid) -> int {
      if (RowIndexStale)
        RebuildRowIndex();
      return RowIndex.value(Pid, -1);
    };
    int RowsProcessed = 0;
    while (Timer.elapsed() < KProcessTableRenderBudgetMs &&
           RowsProcessed < KProcessTableRenderMaxRowsPerBatch) {
      if (RenderState.NextOperation >=
          static_cast<int>(RenderState.Operations.size()))
        break;

      const TableRenderState::Operation &Operation =
          RenderState.Operations[RenderState.NextOperation++];
      if (Operation.OperationType ==
          TableRenderState::Operation::Type::Remove) {
        const int Row = FindRow(Operation.Pid);
        if (Row >= 0) {
          ProcessTable->removeRow(Row);
          RowIndexStale = true;
        }
      } else {
        int Row = FindRow(Operation.Pid);
        if (Row < 0) {
          Row = ProcessTable->rowCount();
          ProcessTable->insertRow(Row);
        }
        FillProcessTableRow(Row, Operation.Row);
      }
      ++RowsProcessed;
    }

    if (Generation != TableRenderGeneration)
      return;
    if (RenderState.NextOperation <
        static_cast<int>(RenderState.Operations.size())) {
      QTimer::singleShot(
          1, this, [this, Generation] { ContinuePopulateTable(Generation); });
      return;
    }

    ProcessTable->setSortingEnabled(true);
    if (RenderState.SortColumn >= 0 &&
        RenderState.SortColumn < ProcessTable->columnCount())
      ProcessTable->sortItems(RenderState.SortColumn, RenderState.SortOrder);
    ProcessTable->clearSelection();
    for (int Row = 0; Row < ProcessTable->rowCount(); ++Row) {
      const QTableWidgetItem *Item = ProcessTable->item(Row, 0);
      if (Item &&
          RenderState.SelectedPids.contains(Item->data(Qt::UserRole).toUInt()))
        ProcessTable->selectionModel()->select(
            ProcessTable->model()->index(Row, 0),
            QItemSelectionModel::Select | QItemSelectionModel::Rows);
    }
    ProcessTable->setUpdatesEnabled(true);
    Rendering = false;
    if (Refreshing.load()) {
      RefreshButton->setText("Refreshing...");
      RefreshButton->setEnabled(false);
    } else {
      RefreshButton->setText("Refresh");
      RefreshButton->setEnabled(true);
      if (RefreshIndicator) {
        RefreshIndicator->stop();
        RefreshIndicator->hide();
      }
    }
    if (RefreshPending && !Refreshing.load()) {
      RefreshPending = false;
      QTimer::singleShot(0, this, [this] { RefreshProcesses(); });
    }
  }

  void FillProcessTableRow(int Row, const ProcessRow &Process) {
    const auto CreateItem = [&Process](const QString &Text) {
      auto *Item = new ProcessTableItem(Text);
      Item->setData(KProcessPinnedRole, Process.Hidden);
      return Item;
    };
    auto *PidItem = new ProcessTableItem;
    PidItem->setData(Qt::DisplayRole,
                     QVariant::fromValue<qulonglong>(Process.Pid));
    PidItem->setData(Qt::UserRole,
                     QVariant::fromValue<qulonglong>(Process.Pid));
    PidItem->setData(KProcessPinnedRole, Process.Hidden);
    ProcessTable->setItem(Row, 0, PidItem);
    ProcessTable->setItem(Row, 1, CreateItem(Process.Name));
    ProcessTable->setItem(Row, 2, CreateItem(Process.User));
    ProcessTable->setItem(Row, 3,
                          CreateItem(IntegrityName(Process.IntegrityRid)));
    ProcessTable->setItem(
        Row, 4,
        CreateItem(Process.Ppl
                       ? QString("Yes (0x%1)")
                             .arg(Process.PplRaw, 2, 16, QLatin1Char('0'))
                       : "No"));
    ProcessTable->setItem(Row, 5,
                          CreateItem(Process.EprocessText.isEmpty()
                                         ? FormatTaskPointer(Process.Eprocess)
                                         : Process.EprocessText));
    ProcessTable->setItem(Row, 6,
                          CreateItem(QString::number(Process.ParentPid)));
    ProcessTable->setRowHeight(Row, KCompactTableRowHeight);
  }

  const ProcessRow *FindProcess(DWORD Pid) const {
    const auto Match =
        std::find_if(Rows.begin(), Rows.end(),
                     [Pid](const ProcessRow &Row) { return Row.Pid == Pid; });
    return Match == Rows.end() ? nullptr : &*Match;
  }

  // --- 线程分视图支持函数 ---

  const ThreadRow *FindThread(DWORD Tid) const {
    const auto Match =
        std::find_if(ThreadRows.begin(), ThreadRows.end(),
                     [Tid](const ThreadRow &Row) { return Row.Tid == Tid; });
    return Match == ThreadRows.end() ? nullptr : &*Match;
  }

  void RefreshThreads() {
    // 背景线程分页拉取全量线程数据，UI 线程回填 ThreadRows + 表格。
    if (ThreadsRefreshing.exchange(true))
      return;
    RefreshButton->setEnabled(false);
    RefreshButton->setText("Refreshing...");
    if (RefreshIndicator) {
      RefreshIndicator->show();
      RefreshIndicator->start();
    }
    QPointer<TaskManagerPage> Page(this);
    std::thread([Page] {
      SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST);
      std::vector<ThreadRow> Result;
      ULONG Cursor = 0;
      // 分页循环：驱动每批最多返回 THREAD_ENUM_BATCH_SIZE(512) 条线程，
      // 通过 Cursor/NextCursor 续取；64 页上限防止驱动异常导致死循环。
      for (int PageIndex = 0; PageIndex < 64; ++PageIndex) {
        THREAD_ENUM_OUTPUT Output = {};
        if (!EnumerateThreadsAll(&Output, Cursor))
          break;
        for (ULONG Index = 0; Index < Output.Count; ++Index) {
          const THREAD_ENUM_ENTRY &Entry = Output.Entries[Index];
          ThreadRow Row;
          Row.Tid = Entry.ThreadId;
          Row.ProcessId = Entry.ProcessId;
          Row.PreviousMode = static_cast<UCHAR>(Entry.PreviousMode);
          Row.ApcQueueable = Entry.ApcQueueable;
          Row.Ethread = Entry.Ethread;
          Row.StartAddress = Entry.StartAddress;
          Row.Priority = Entry.Priority;
          Row.State = Entry.State;
          Result.push_back(std::move(Row));
        }
        if (Output.NextCursor == 0 || Output.Count == 0)
          break;
        Cursor = Output.NextCursor;
      }
      QMetaObject::invokeMethod(
          qApp,
          [Page, Result = std::move(Result)]() mutable {
            if (!Page)
              return;
            Page->ThreadRows = std::move(Result);
            Page->ThreadsRefreshing = false;
            // 线程视图激活时回填表格并更新状态栏。
            if (Page->ViewCombo && Page->ViewCombo->currentIndex() == 1)
              Page->PopulateThreadTable();
            Page->StatusLabel->setText(
                QString("%1 threads").arg(Page->ThreadRows.size()));
            if (Page->RefreshIndicator) {
              Page->RefreshIndicator->stop();
              Page->RefreshIndicator->hide();
            }
            Page->RefreshButton->setText("Refresh");
            Page->RefreshButton->setEnabled(true);
          },
          Qt::QueuedConnection);
    }).detach();
  }

  void PopulateThreadTable() {
    // 按当前进程表构建 PID→Name 映射，供线程表格显示进程名。
    std::map<DWORD, QString> PidNames;
    for (const ProcessRow &Process : Rows)
      PidNames[Process.Pid] = Process.Name;
    for (ThreadRow &Row : ThreadRows) {
      const auto Match = PidNames.find(Row.ProcessId);
      Row.ProcessName = Match != PidNames.end() ? Match->second : QString();
    }
    const QString Query = SearchEdit->text().trimmed();
    ThreadTable->setSortingEnabled(false);
    ThreadTable->setUpdatesEnabled(false);
    ThreadTable->setRowCount(0);
    RowTids.clear();
    RowTids.reserve(static_cast<qsizetype>(ThreadRows.size()));
    const auto CreateItem = [](const QString &Text) {
      return new QTableWidgetItem(Text);
    };
    for (const ThreadRow &Row : ThreadRows) {
      if (!Query.isEmpty() &&
          !QString::number(Row.Tid).contains(Query) &&
          !QString::number(Row.ProcessId).contains(Query) &&
          !Row.ProcessName.contains(Query, Qt::CaseInsensitive))
        continue;
      const int RowIndex = ThreadTable->rowCount();
      ThreadTable->insertRow(RowIndex);
      RowTids.push_back(Row.Tid);
      auto *TidItem = new QTableWidgetItem(
          QString::number(Row.Tid));
      TidItem->setData(Qt::UserRole,
                       QVariant::fromValue<qulonglong>(Row.Tid));
      ThreadTable->setItem(RowIndex, 0, TidItem);
      ThreadTable->setItem(RowIndex, 1,
                           CreateItem(QString::number(Row.ProcessId)));
      ThreadTable->setItem(RowIndex, 2, CreateItem(Row.ProcessName));
      ThreadTable->setItem(
          RowIndex, 3,
          CreateItem(QString("0x%1").arg(Row.Ethread, 0, 16).toUpper()));
      ThreadTable->setItem(
          RowIndex, 4,
          CreateItem(QString("0x%1").arg(Row.StartAddress, 0, 16).toUpper()));
      // PreviousMode：0=KernelMode, 1=UserMode, 其它=?
      ThreadTable->setItem(
          RowIndex, 5,
          CreateItem(Row.PreviousMode == 1
                         ? "UserMode"
                         : (Row.PreviousMode == 0 ? "KernelMode" : "?")));
      ThreadTable->setItem(RowIndex, 6,
                           CreateItem(Row.ApcQueueable ? "Yes" : "No"));
      ThreadTable->setItem(
          RowIndex, 7, CreateItem(QString::number(Row.Priority)));
      ThreadTable->setItem(RowIndex, 8,
                           CreateItem(QString::number(Row.State)));
      ThreadTable->setRowHeight(RowIndex, KCompactTableRowHeight);
    }
    ThreadTable->setUpdatesEnabled(true);
  }

  void SwitchView(int Index) {
    // 切换 Process/Thread 视图：互斥显示两个表格，按需触发刷新。
    const bool ProcessView = Index == 0;
    ProcessTable->setVisible(ProcessView);
    ThreadTable->setVisible(!ProcessView);
    if (ProcessView) {
      PopulateTable();
    } else {
      PopulateThreadTable();
      if (ThreadRows.empty())
        RefreshThreads();
    }
  }

  void ShowThreadMenu(const QPoint &Position) {
    // 线程表格右键菜单：单选走共享菜单，多选构建批量菜单。
    const QModelIndex Index = ThreadTable->indexAt(Position);
    if (!Index.isValid())
      return;
    if (!ThreadTable->selectionModel()->isRowSelected(Index.row(),
                                                      QModelIndex())) {
      ThreadTable->clearSelection();
      ThreadTable->selectRow(Index.row());
    }
    const QTableWidgetItem *TidItem = ThreadTable->item(Index.row(), 0);
    if (!TidItem)
      return;
    const DWORD Tid = TidItem->data(Qt::UserRole).toUInt();
    if (Tid == 0)
      return;
    const ThreadRow *Found = FindThread(Tid);
    if (!Found)
      return;
    if (Found->ProcessId == GetCurrentProcessId()) {
      ShowWarningNotice(
          this, "Task",
          "Thread operations on AegisNT itself are disabled.");
      return;
    }
    // 多选时若当前行在选中集中则应用到全部选中行，否则视为单选。
    std::vector<DWORD> SelectedTids;
    const auto SelectedRows =
        ThreadTable->selectionModel()->selectedRows(0);
    const bool Multi = std::any_of(
        SelectedRows.begin(), SelectedRows.end(),
        [Index](const QModelIndex &M) { return M.row() == Index.row(); });
    if (!Multi) {
      SelectedTids.push_back(Tid);
    } else {
      for (const QModelIndex &Selected : SelectedRows) {
        const QTableWidgetItem *Item =
            ThreadTable->item(Selected.row(), 0);
        if (Item) {
          const DWORD SelectedTid =
              Item->data(Qt::UserRole).toUInt();
          if (SelectedTid != 0 &&
              SelectedTid != GetCurrentProcessId())
            SelectedTids.push_back(SelectedTid);
        }
      }
    }
    if (SelectedTids.empty())
      return;
    if (SelectedTids.size() == 1) {
      const ThreadRow *Single = FindThread(SelectedTids.front());
      if (!Single)
        return;
      ShowThreadActionsMenu(SelectedTids.front(), Single->ProcessId,
                            ThreadTable);
      return;
    }
    // 多选批量菜单。
    auto *Menu = new RoundMenu(QString(), this);
    AddMenuAction(Menu, "Suspend", [this, SelectedTids] {
      int Count = 0;
      for (DWORD SelectedTid : SelectedTids)
        if (SuspendThreadKernel(SelectedTid))
          ++Count;
      ShowSuccessNotice(
          this, "Suspend threads",
          QString("%1 of %2 thread(s) suspended.")
              .arg(Count)
              .arg(SelectedTids.size()));
      RefreshThreads();
    });
    AddMenuAction(Menu, "Resume", [this, SelectedTids] {
      int Count = 0;
      for (DWORD SelectedTid : SelectedTids)
        if (ResumeThreadKernel(SelectedTid))
          ++Count;
      ShowSuccessNotice(
          this, "Resume threads",
          QString("%1 of %2 thread(s) resumed.")
              .arg(Count)
              .arg(SelectedTids.size()));
      RefreshThreads();
    });
    AddMenuAction(Menu, "Set PreviousMode...",
                  [this, SelectedTids] {
                    ShowThreadPreviousModeDialog(SelectedTids);
                  });
    AddMenuAction(Menu, "Set ApcQueueable...",
                  [this, SelectedTids] {
                    ShowThreadApcQueueableDialog(SelectedTids);
                  });
    AddMenuAction(Menu, "Terminate Threads", [this, SelectedTids] {
      int Count = 0;
      for (DWORD SelectedTid : SelectedTids) {
        const ThreadRow *Tr = FindThread(SelectedTid);
        if (Tr && KillThread(SelectedTid, Tr->ProcessId))
          ++Count;
      }
      ShowSuccessNotice(
          this, "Terminate threads",
          QString("%1 of %2 thread(s) terminated.")
              .arg(Count)
              .arg(SelectedTids.size()));
      RefreshThreads();
    });
    AddMenuAction(Menu, "Copy", [this, SelectedTids] {
      QStringList Lines;
      for (DWORD SelectedTid : SelectedTids) {
        const ThreadRow *Tr = FindThread(SelectedTid);
        if (!Tr)
          continue;
        const QString PrevMode =
            Tr->PreviousMode == 1 ? "UserMode"
                                  : (Tr->PreviousMode == 0 ? "KernelMode"
                                                           : "?");
        const QString Apc = Tr->ApcQueueable ? "Yes" : "No";
        Lines << QString("%1\t%2\t%3\t0x%4\t0x%5\t%6\t%7\t%8\t%9")
                     .arg(Tr->Tid)
                     .arg(Tr->ProcessId)
                     .arg(Tr->ProcessName)
                     .arg(Tr->Ethread, 0, 16)
                     .arg(Tr->StartAddress, 0, 16)
                     .arg(PrevMode)
                     .arg(Apc)
                     .arg(Tr->Priority)
                     .arg(Tr->State);
      }
      if (!Lines.isEmpty()) {
        qApp->clipboard()->setText(Lines.join(QLatin1Char('\n')));
        ShowSuccessNotice(this, "Copy",
                          QString("Copied %1 thread(s).").arg(Lines.size()));
      }
    });
    ReleaseMenuAfterClose(Menu);
    Menu->exec(ThreadTable->viewport()->mapToGlobal(Position));
  }

  // 单线程共享操作菜单（主线程视图 + Inspector 复用）。
  void ShowThreadActionsMenu(ULONG Tid, ULONG Pid, QWidget *Target) {
    auto *Menu = new RoundMenu(QString(), this);
    AddMenuAction(Menu, "Suspend", [this, Tid] {
      if (SuspendThreadKernel(Tid))
        ShowSuccessNotice(this, "Suspend",
                          QString("Thread %1 suspended.").arg(Tid));
      else
        ShowErrorNotice(
            this, "Suspend",
            QString("Suspend failed (error %1).")
                .arg(G_LastAegisCoreError));
      RefreshThreads();
    });
    AddMenuAction(Menu, "Resume", [this, Tid] {
      if (ResumeThreadKernel(Tid))
        ShowSuccessNotice(this, "Resume",
                          QString("Thread %1 resumed.").arg(Tid));
      else
        ShowErrorNotice(
            this, "Resume",
            QString("Resume failed (error %1).")
                .arg(G_LastAegisCoreError));
      RefreshThreads();
    });
    AddMenuAction(Menu, "Set PreviousMode...",
                  [this, Tid] { ShowThreadPreviousModeDialog({Tid}); });
    AddMenuAction(Menu, "Set Process PreviousMode...",
                  [this, Pid] { ShowProcessPreviousModeDialog(Pid); });
    AddMenuAction(
        Menu, "Set ApcQueueable...",
        [this, Tid] { ShowThreadApcQueueableDialog({Tid}); });
    AddMenuAction(Menu, "Terminate Thread", [this, Tid, Pid] {
      if (KillThread(Tid, Pid))
        ShowSuccessNotice(
            this, "Terminate Thread",
            QString("Thread %1 terminated.").arg(Tid));
      else
        ShowErrorNotice(
            this, "Terminate Thread",
            QString("Terminate failed (error %1).")
                .arg(G_LastAegisCoreError));
      RefreshThreads();
    });
    AddMenuAction(Menu, "Inspect", [this, Tid] {
      if (const ThreadRow *Found = FindThread(Tid))
        ShowThreadInspector(*Found);
    });
    AddMenuAction(Menu, "Find In Process",
                  [this, Pid] { FindThreadInProcess(Pid); });
    AddMenuAction(Menu, "Copy", [this, Tid] {
      const ThreadRow *Tr = FindThread(Tid);
      if (!Tr)
        return;
      const QString PrevMode =
          Tr->PreviousMode == 1
              ? "UserMode"
              : (Tr->PreviousMode == 0 ? "KernelMode" : "?");
      const QString Apc = Tr->ApcQueueable ? "Yes" : "No";
      const QString Line =
          QString("%1\t%2\t%3\t0x%4\t0x%5\t%6\t%7\t%8\t%9")
              .arg(Tr->Tid)
              .arg(Tr->ProcessId)
              .arg(Tr->ProcessName)
              .arg(Tr->Ethread, 0, 16)
              .arg(Tr->StartAddress, 0, 16)
              .arg(PrevMode)
              .arg(Apc)
              .arg(Tr->Priority)
              .arg(Tr->State);
      qApp->clipboard()->setText(Line);
      ShowSuccessNotice(this, "Copy", "Thread information copied.");
    });
    ReleaseMenuAfterClose(Menu);
    Menu->exec(QCursor::pos());
  }

  // 进程 PreviousMode 设置对话框（与线程版一致：可选 KernelMode / UserMode）。
  void ShowProcessPreviousModeDialog(DWORD Pid) {
    auto *Dialog = new QDialog(this);
    Dialog->setAttribute(Qt::WA_DeleteOnClose);
    Dialog->setWindowTitle("Set Process PreviousMode");
    Dialog->setModal(true);
    Dialog->resize(520, 260);
    auto *DialogLayout = new QVBoxLayout(Dialog);
    DialogLayout->setContentsMargins(20, 18, 20, 18);
    DialogLayout->setSpacing(12);
    auto *Description = MakeLabel(
        QString("Applies to every thread of process %1. PreviousMode controls "
                "whether the kernel treats a thread's last call as user- or "
                "kernel-originated.")
            .arg(Pid),
        11, KTextMuted);
    Description->setWordWrap(true);
    auto *ModeLabel = MakeLabel("Mode", 11, KTextPrimary, QFont::DemiBold);
    auto *Mode = new ComboBox;
    Mode->addItems({"KernelMode (0)", "UserMode (1)"});
    Mode->setCurrentIndex(0);
    auto *Buttons = new QHBoxLayout;
    ConfigureToolbarLayout(Buttons);
    Buttons->addStretch();
    auto *Cancel = MakeButton("Cancel");
    auto *Apply = MakeButton("Apply", true);
    Buttons->addWidget(Cancel);
    Buttons->addWidget(Apply);
    DialogLayout->addWidget(Description);
    DialogLayout->addWidget(ModeLabel);
    DialogLayout->addWidget(Mode);
    DialogLayout->addStretch();
    DialogLayout->addLayout(Buttons);
    QObject::connect(Cancel, &QPushButton::clicked, Dialog, &QDialog::reject);
    QObject::connect(Apply, &QPushButton::clicked, Dialog,
                     [this, Dialog, Mode, Pid] {
                       const UCHAR ModeValue =
                           Mode->currentIndex() == 1 ? 1 : 0;
                       const QString ModeText =
                           ModeValue == 1 ? "UserMode" : "KernelMode";
                       if (SetProcessPreviousMode(Pid, ModeValue)) {
                         ShowSuccessNotice(
                             this, "Set Process PreviousMode",
                             QString("Process %1 PreviousMode set to %2.")
                                 .arg(Pid)
                                 .arg(ModeText));
                       } else {
                         ShowErrorNotice(
                             this, "Set Process PreviousMode",
                             QString("Failed to set %1 (error %2).")
                                 .arg(ModeText)
                                 .arg(G_LastAegisCoreError));
                       }
                       RefreshThreads();
                       RefreshProcesses();
                       Dialog->accept();
                     });
    ApplyDialogTheme(Dialog);
    Dialog->show();
  }

  // 线程 PreviousMode 设置对话框。
  void ShowThreadPreviousModeDialog(std::vector<DWORD> Tids) {
    auto *Dialog = new QDialog(this);
    Dialog->setAttribute(Qt::WA_DeleteOnClose);
    Dialog->setWindowTitle("Set Thread PreviousMode");
    Dialog->setModal(true);
    Dialog->resize(520, 250);
    auto *DialogLayout = new QVBoxLayout(Dialog);
    DialogLayout->setContentsMargins(20, 18, 20, 18);
    DialogLayout->setSpacing(12);
    auto *Description = MakeLabel(
        "PreviousMode controls whether the kernel treats the thread's last "
        "call as user- or kernel-originated.",
        11, KTextMuted);
    Description->setWordWrap(true);
    auto *ModeLabel =
        MakeLabel("Mode", 11, KTextPrimary, QFont::DemiBold);
    auto *Mode = new ComboBox;
    Mode->addItems({"KernelMode (0)", "UserMode (1)"});
    Mode->setCurrentIndex(0);
    auto *Buttons = new QHBoxLayout;
    ConfigureToolbarLayout(Buttons);
    Buttons->addStretch();
    auto *Cancel = MakeButton("Cancel");
    auto *Apply = MakeButton("Apply", true);
    Buttons->addWidget(Cancel);
    Buttons->addWidget(Apply);
    DialogLayout->addWidget(Description);
    DialogLayout->addWidget(ModeLabel);
    DialogLayout->addWidget(Mode);
    DialogLayout->addStretch();
    DialogLayout->addLayout(Buttons);
    QObject::connect(Cancel, &QPushButton::clicked, Dialog,
                     &QDialog::reject);
    QObject::connect(
        Apply, &QPushButton::clicked, Dialog,
        [this, Dialog, Mode, Tids] {
          const UCHAR ModeValue =
              Mode->currentIndex() == 1 ? 1 : 0;
          int Count = 0;
          for (DWORD Tid : Tids)
            if (SetThreadPreviousMode(Tid, ModeValue))
              ++Count;
          const QString ModeText =
              ModeValue == 1 ? "UserMode" : "KernelMode";
          if (Count > 0)
            ShowSuccessNotice(
                this, "Set Thread PreviousMode",
                QString("%1 of %2 thread(s) PreviousMode set to %3.")
                    .arg(Count)
                    .arg(Tids.size())
                    .arg(ModeText));
          else
            ShowErrorNotice(
                this, "Set Thread PreviousMode",
                QString("Set PreviousMode failed (error %1).")
                    .arg(G_LastAegisCoreError));
          Dialog->accept();
          RefreshThreads();
        });
    ApplyDialogTheme(Dialog);
    Dialog->show();
  }

  // 线程 ApcQueueable 设置对话框。
  void ShowThreadApcQueueableDialog(std::vector<DWORD> Tids) {
    auto *Dialog = new QDialog(this);
    Dialog->setAttribute(Qt::WA_DeleteOnClose);
    Dialog->setWindowTitle("Set Thread ApcQueueable");
    Dialog->setModal(true);
    Dialog->resize(520, 250);
    auto *DialogLayout = new QVBoxLayout(Dialog);
    DialogLayout->setContentsMargins(20, 18, 20, 18);
    DialogLayout->setSpacing(12);
    auto *Description = MakeLabel(
        "ApcQueueable (KTHREAD+0x90 bit 0) gates whether APCs can be "
        "queued to this thread.",
        11, KTextMuted);
    Description->setWordWrap(true);
    auto *ModeLabel =
        MakeLabel("Mode", 11, KTextPrimary, QFont::DemiBold);
    auto *Mode = new ComboBox;
    Mode->addItems({"Enable (1)", "Disable (0)"});
    Mode->setCurrentIndex(0);
    auto *Buttons = new QHBoxLayout;
    ConfigureToolbarLayout(Buttons);
    Buttons->addStretch();
    auto *Cancel = MakeButton("Cancel");
    auto *Apply = MakeButton("Apply", true);
    Buttons->addWidget(Cancel);
    Buttons->addWidget(Apply);
    DialogLayout->addWidget(Description);
    DialogLayout->addWidget(ModeLabel);
    DialogLayout->addWidget(Mode);
    DialogLayout->addStretch();
    DialogLayout->addLayout(Buttons);
    QObject::connect(Cancel, &QPushButton::clicked, Dialog,
                     &QDialog::reject);
    QObject::connect(
        Apply, &QPushButton::clicked, Dialog,
        [this, Dialog, Mode, Tids] {
          const UCHAR Value =
              Mode->currentIndex() == 1 ? 0 : 1;
          int Count = 0;
          for (DWORD Tid : Tids)
            if (SetThreadApcQueueable(Tid, Value))
              ++Count;
          if (Count > 0)
            ShowSuccessNotice(
                this, "Set ApcQueueable",
                QString("%1 of %2 thread(s) ApcQueueable updated.")
                    .arg(Count)
                    .arg(Tids.size()));
          else
            ShowErrorNotice(
                this, "Set ApcQueueable",
                QString("Set ApcQueueable failed (error %1).")
                    .arg(G_LastAegisCoreError));
          Dialog->accept();
          RefreshThreads();
        });
    ApplyDialogTheme(Dialog);
    Dialog->show();
  }

  // 线程详情检查器对话框（字段表 + 操作按钮）。
  void ShowThreadInspector(const ThreadRow &Row) {
    auto *Dialog = new QDialog(this);
    Dialog->setAttribute(Qt::WA_DeleteOnClose);
    Dialog->setWindowTitle(QString("Thread %1 - Thread Inspector")
                               .arg(Row.Tid));
    Dialog->resize(600, 470);
    Dialog->setMinimumSize(460, 380);
    auto *DialogLayout = new QVBoxLayout(Dialog);
    DialogLayout->setContentsMargins(18, 16, 18, 16);
    DialogLayout->setSpacing(10);
    auto *Table = MakeTable({"Field", "Value"});
    Table->horizontalHeader()->setSectionResizeMode(
        0, QHeaderView::ResizeToContents);
    Table->horizontalHeader()->setSectionResizeMode(
        1, QHeaderView::Stretch);
    const auto AddField = [Table](const QString &Field,
                                  const QString &Value) {
      const int Row = Table->rowCount();
      Table->insertRow(Row);
      Table->setItem(Row, 0, new QTableWidgetItem(Field));
      Table->setItem(Row, 1, new QTableWidgetItem(Value));
      Table->setRowHeight(Row, KCompactTableRowHeight);
    };
    AddField("TID", QString::number(Row.Tid));
    AddField("Parent Process ID", QString::number(Row.ProcessId));
    AddField("Process", Row.ProcessName);
    AddField("PreviousMode",
             Row.PreviousMode == 1
                 ? "UserMode"
                 : (Row.PreviousMode == 0 ? "KernelMode" : "Unknown"));
    AddField("ApcQueueable", Row.ApcQueueable ? "Yes" : "No");
    AddField("ETHREAD",
             QString("0x%1")
                 .arg(Row.Ethread, sizeof(quintptr) * 2, 16,
                      QLatin1Char('0'))
                 .toUpper());
    AddField("Start Address",
             QString("0x%1")
                 .arg(Row.StartAddress, sizeof(quintptr) * 2, 16,
                      QLatin1Char('0'))
                 .toUpper());
    AddField("Priority", QString::number(Row.Priority));
    AddField("State", QString::number(Row.State));
    DialogLayout->addWidget(Table, 1);
    // 操作按钮行。
    auto *ButtonRow = new QHBoxLayout;
    ButtonRow->setSpacing(8);
    const DWORD Tid = Row.Tid;
    const DWORD Pid = Row.ProcessId;
    auto *BtnSuspend = MakeButton("Suspend");
    auto *BtnResume = MakeButton("Resume");
    auto *BtnPrevMode = MakeButton("Set PreviousMode...");
    auto *BtnApc = MakeButton("Set ApcQueueable...");
    auto *BtnTerminate = MakeButton("Terminate");
    auto *BtnFind = MakeButton("Find In Process");
    auto *BtnClose = MakeButton("Close", true);
    ButtonRow->addWidget(BtnSuspend);
    ButtonRow->addWidget(BtnResume);
    ButtonRow->addWidget(BtnPrevMode);
    ButtonRow->addWidget(BtnApc);
    ButtonRow->addWidget(BtnTerminate);
    ButtonRow->addWidget(BtnFind);
    ButtonRow->addStretch();
    ButtonRow->addWidget(BtnClose);
    DialogLayout->addLayout(ButtonRow);
    QObject::connect(BtnSuspend, &QPushButton::clicked, Dialog, [this, Tid] {
      if (SuspendThreadKernel(Tid))
        ShowSuccessNotice(this, "Suspend",
                          QString("Thread %1 suspended.").arg(Tid));
      else
        ShowErrorNotice(this, "Suspend",
                        QString("Suspend failed (error %1).")
                            .arg(G_LastAegisCoreError));
      RefreshThreads();
    });
    QObject::connect(BtnResume, &QPushButton::clicked, Dialog, [this, Tid] {
      if (ResumeThreadKernel(Tid))
        ShowSuccessNotice(this, "Resume",
                          QString("Thread %1 resumed.").arg(Tid));
      else
        ShowErrorNotice(this, "Resume",
                        QString("Resume failed (error %1).")
                            .arg(G_LastAegisCoreError));
      RefreshThreads();
    });
    QObject::connect(BtnPrevMode, &QPushButton::clicked, Dialog,
                     [this, Tid] {
                       ShowThreadPreviousModeDialog({Tid});
                     });
    QObject::connect(BtnApc, &QPushButton::clicked, Dialog,
                     [this, Tid] {
                       ShowThreadApcQueueableDialog({Tid});
                     });
    QObject::connect(BtnTerminate, &QPushButton::clicked, Dialog,
                     [this, Tid, Pid] {
                       if (KillThread(Tid, Pid))
                         ShowSuccessNotice(
                             this, "Terminate Thread",
                             QString("Thread %1 terminated.").arg(Tid));
                       else
                         ShowErrorNotice(
                             this, "Terminate Thread",
                             QString("Terminate failed (error %1).")
                                 .arg(G_LastAegisCoreError));
                       RefreshThreads();
                     });
    QObject::connect(BtnFind, &QPushButton::clicked, Dialog,
                     [this, Pid] { FindThreadInProcess(Pid); });
    QObject::connect(BtnClose, &QPushButton::clicked, Dialog,
                     &QDialog::accept);
    ApplyDialogTheme(Dialog);
    Dialog->show();
  }

  // 从线程视图跳转到进程视图并定位到指定 PID 的行。
  void FindThreadInProcess(DWORD Pid) {
    // 清空搜索文本并切换到进程视图。
    if (!SearchEdit->text().isEmpty())
      SearchEdit->clear();
    if (ViewCombo && ViewCombo->currentIndex() != 0)
      ViewCombo->setCurrentIndex(0);
    else
      PopulateTable();
    // 在进程表中查找匹配 PID 的行。
    for (int Row = 0; Row < ProcessTable->rowCount(); ++Row) {
      const QTableWidgetItem *Item = ProcessTable->item(Row, 0);
      if (Item && Item->data(Qt::UserRole).toUInt() == Pid) {
        ProcessTable->selectRow(Row);
        ProcessTable->scrollToItem(Item,
                                   QAbstractItemView::PositionAtCenter);
        ShowSuccessNotice(this, "Task",
                          QString("Selected process %1").arg(Pid));
        return;
      }
    }
    ShowWarningNotice(
        this, "Task",
        QString("Process %1 not found in the current process view.")
            .arg(Pid));
  }

  bool ConfirmDangerous(const QString &Title, const QString &Text) {
    return ShowConfirmDialog(this, Title, Text, "Yes", "No");
  }

  void ReportDriverResult(const QString &Action) {
    if (G_LastAegisCoreError != ERROR_SUCCESS)
      ShowErrorNotice(this, Action,
                      QString("Driver operation failed (error %1).")
                          .arg(G_LastAegisCoreError));
    else {
      ShowSuccessNotice(this, Action, "Operation completed successfully.");
      QTimer::singleShot(250, this, [this] { RefreshProcesses(); });
    }
  }

  void AddMenuAction(RoundMenu *Menu, const QString &Text,
                     const std::function<void()> &Handler) {
    auto *Action = new QAction(Text, Menu);
    Menu->addAction(Action);
    ConnectMenuAction(Action, this, Handler);
  }

  void ShowProcessMenu(const QPoint &Position) {
    const QModelIndex Index = ProcessTable->indexAt(Position);
    if (!Index.isValid())
      return;
    if (!ProcessTable->selectionModel()->isRowSelected(Index.row(),
                                                       QModelIndex())) {
      ProcessTable->clearSelection();
      ProcessTable->selectRow(Index.row());
    }
    const DWORD Pid =
        ProcessTable->item(Index.row(), 0)->data(Qt::UserRole).toUInt();
    const ProcessRow *Process = FindProcess(Pid);
    if (!Process || Pid == 0)
      return;
    if (Pid == GetCurrentProcessId()) {
      ShowWarningNotice(this, "Task",
                        "Operations on AegisNT itself are disabled.");
      return;
    }
    const QString Name = Process->Name;
    std::vector<DWORD> SelectedPids;
    for (const QModelIndex &Selected :
         ProcessTable->selectionModel()->selectedRows(0)) {
      const DWORD SelectedPid =
          ProcessTable->item(Selected.row(), 0)->data(Qt::UserRole).toUInt();
      if (SelectedPid != 0 && SelectedPid != GetCurrentProcessId())
        SelectedPids.push_back(SelectedPid);
    }
    if (SelectedPids.empty())
      return;

    auto *Menu = new RoundMenu(QString(), this);
    AddMenuAction(Menu, "Copy", [this] {
      QStringList Lines;
      for (const QModelIndex &Selected :
           ProcessTable->selectionModel()->selectedRows(0)) {
        QStringList Cells;
        for (int Column = 0; Column < ProcessTable->columnCount(); ++Column) {
          const QTableWidgetItem *Item =
              ProcessTable->item(Selected.row(), Column);
          Cells << (Item ? Item->text() : QString());
        }
        Lines << Cells.join(QLatin1Char('\t'));
      }
      if (!Lines.isEmpty()) {
        qApp->clipboard()->setText(Lines.join(QLatin1Char('\n')));
        ShowSuccessNotice(this, "Copy",
                          QString("Copied %1 row(s).").arg(Lines.size()));
      }
    });
    Menu->addSeparator();
    AddMenuAction(Menu, "Terminate",
                  [this, SelectedPids] { ShowTerminateDialog(SelectedPids); });

    auto *PplMenu = new RoundMenu("PPL", Menu);
    AddMenuAction(PplMenu, "RemovePPL", [this, SelectedPids] {
      for (DWORD SelectedPid : SelectedPids)
        RemovePpl(SelectedPid);
      ReportDriverResult("RemovePPL");
    });
    AddMenuAction(PplMenu, "SetPPL",
                  [this, SelectedPids] { ConfigurePpl(SelectedPids); });
    Menu->addMenu(PplMenu);

    auto *ProtectMenu = new RoundMenu("Protect", Menu);
    AddMenuAction(ProtectMenu, "Protect", [this, SelectedPids] {
      for (DWORD SelectedPid : SelectedPids) {
        ProtectProcess(SelectedPid);
        if (G_LastAegisCoreError == ERROR_SUCCESS)
          ProtectedPids.insert(SelectedPid);
      }
      ReportDriverResult("Protect");
    });
    AddMenuAction(ProtectMenu, "UnProtect", [this, SelectedPids] {
      for (DWORD SelectedPid : SelectedPids) {
        UnprotectProcess(SelectedPid);
        if (G_LastAegisCoreError == ERROR_SUCCESS)
          ProtectedPids.remove(SelectedPid);
      }
      ReportDriverResult("UnProtect");
    });
    ProtectMenu->addSeparator();
    AddMenuAction(ProtectMenu, "InjectProtect", [this, SelectedPids] {
      for (DWORD SelectedPid : SelectedPids) {
        AddInjectionProtectKernel(SelectedPid);
      }
      ReportDriverResult("InjectProtect");
    });
    AddMenuAction(ProtectMenu, "InjectUnprotect", [this, SelectedPids] {
      for (DWORD SelectedPid : SelectedPids) {
        RemoveInjectionProtectKernel(SelectedPid);
      }
      ReportDriverResult("InjectUnprotect");
    });
    Menu->addMenu(ProtectMenu);

    auto *CriticalMenu = new RoundMenu("Critical", Menu);
    AddMenuAction(CriticalMenu, "SetCritical", [this, SelectedPids] {
      const size_t NameCount = std::min<size_t>(SelectedPids.size(), 4);
      QStringList Names;
      for (size_t i = 0; i < NameCount; ++i) {
        const ProcessRow *Selected = FindProcess(SelectedPids[i]);
        if (Selected)
          Names << QString("%1 (PID %2)")
                       .arg(Selected->Name)
                       .arg(SelectedPids[i]);
      }
      if (SelectedPids.size() > NameCount)
        Names << QString("... and %1 more")
                     .arg(SelectedPids.size() - NameCount);
      if (!ConfirmDangerous(
              "SetCritical",
              QString("Mark %1 process(es) critical? Terminating them may "
                      "crash Windows.\n%2")
                  .arg(SelectedPids.size())
                  .arg(Names.join("\n"))))
        return;
      for (DWORD SelectedPid : SelectedPids)
        SetCritical(SelectedPid);
      ReportDriverResult("SetCritical");
    });
    AddMenuAction(CriticalMenu, "UnsetCritical", [this, SelectedPids] {
      for (DWORD SelectedPid : SelectedPids)
        RemoveCritical(SelectedPid);
      ReportDriverResult("UnsetCritical");
    });
    Menu->addMenu(CriticalMenu);

    auto *HideMenu = new RoundMenu("Hide", Menu);
    AddMenuAction(HideMenu, "Hide", [this, SelectedPids] {
      bool Changed = false;
      for (DWORD SelectedPid : SelectedPids) {
        const ProcessRow *Current = FindProcess(SelectedPid);
        const std::optional<ProcessRow> Cached =
            Current ? std::optional<ProcessRow>(*Current) : std::nullopt;
        HideProcess(SelectedPid);
        if (G_LastAegisCoreError == ERROR_SUCCESS && Cached) {
          ProcessRow Retained = *Cached;
          Retained.Hidden = true;
          RetainedProcesses[SelectedPid] = Retained;
          for (ProcessRow &Row : Rows) {
            if (Row.Pid == SelectedPid)
              Row.Hidden = true;
          }
          Changed = true;
        }
      }
      if (Changed) {
        SortProcessRows(Rows);
        PopulateTable();
      }
      ReportDriverResult("Hide");
    });
    AddMenuAction(HideMenu, "Hide (Can't Unhide)", [this, SelectedPids] {
      bool Changed = false;
      for (DWORD SelectedPid : SelectedPids) {
        const ProcessRow *Current = FindProcess(SelectedPid);
        const std::optional<ProcessRow> Cached =
            Current ? std::optional<ProcessRow>(*Current) : std::nullopt;
        HideProcessCid(SelectedPid);
        if (G_LastAegisCoreError == ERROR_SUCCESS && Cached) {
          ProcessRow Retained = *Cached;
          Retained.Hidden = true;
          RetainedProcesses[SelectedPid] = Retained;
          for (ProcessRow &Row : Rows) {
            if (Row.Pid == SelectedPid)
              Row.Hidden = true;
          }
          Changed = true;
        }
      }
      if (Changed) {
        SortProcessRows(Rows);
        PopulateTable();
      }
      ReportDriverResult("Hide (Can't Unhide)");
    });
    AddMenuAction(HideMenu, "Unhide", [this, SelectedPids] {
      bool Changed = false;
      for (DWORD SelectedPid : SelectedPids) {
        const ProcessRow *Current = FindProcess(SelectedPid);
        const std::optional<ProcessRow> Cached =
            Current ? std::optional<ProcessRow>(*Current) : std::nullopt;
        UnhideProcess(SelectedPid);
        if (G_LastAegisCoreError == ERROR_SUCCESS && Cached) {
          ProcessRow Retained = *Cached;
          Retained.Hidden = false;
          RetainedProcesses[SelectedPid] = Retained;
          for (ProcessRow &Row : Rows) {
            if (Row.Pid == SelectedPid)
              Row.Hidden = false;
          }
          Changed = true;
        }
      }
      if (Changed) {
        SortProcessRows(Rows);
        PopulateTable();
      }
      ReportDriverResult("Unhide");
    });
    Menu->addMenu(HideMenu);

    AddMenuAction(Menu, "Set Integrity",
                  [this, Pid] { ShowIntegrityDialog(Pid); });

    auto *ApcMenu = new RoundMenu("APC", Menu);
    AddMenuAction(ApcMenu, "DisableAPC", [this, SelectedPids] {
      for (DWORD SelectedPid : SelectedPids)
        DisableApc(SelectedPid);
      ReportDriverResult("DisableAPC");
    });
    AddMenuAction(ApcMenu, "EnableAPC", [this, SelectedPids] {
      for (DWORD SelectedPid : SelectedPids)
        EnableApc(SelectedPid);
      ReportDriverResult("EnableAPC");
    });
    AddMenuAction(ApcMenu, "SendAPCSignal",
                  [this, Pid] { ShowApcSignalDialog(Pid); });
    Menu->addMenu(ApcMenu);

    AddMenuAction(Menu, "Suspend", [this, SelectedPids] {
      int Count = 0;
      for (DWORD SelectedPid : SelectedPids)
        if (Suspend(SelectedPid))
          ++Count;
      ShowSuccessNotice(this, "Suspend",
                        QString("%1 of %2 process(es) suspended.")
                            .arg(Count)
                            .arg(SelectedPids.size()));
    });
    AddMenuAction(Menu, "Resume", [this, SelectedPids] {
      int Count = 0;
      for (DWORD SelectedPid : SelectedPids)
        if (Resume(SelectedPid))
          ++Count;
      ShowSuccessNotice(this, "Resume",
                        QString("%1 of %2 process(es) resumed.")
                            .arg(Count)
                            .arg(SelectedPids.size()));
    });

    AddMenuAction(Menu, "SetToken", [this, Pid] { ShowTokenDialog(Pid); });

    AddMenuAction(Menu, "Disguise",
                  [this, Pid] { ShowProcessDisguiseDialog(Pid); });

    auto *DetailMenu = new RoundMenu("Detail Information", Menu);
    AddMenuAction(DetailMenu, "Inspector",
                  [this, Pid] { ShowProcessInspector(Pid); });
    AddMenuAction(DetailMenu, "ModuleList",
                  [this, Pid] { ShowModuleList(Pid); });
    AddMenuAction(DetailMenu, "PEB", [this, Pid] { ShowPebDetails(Pid); });
    Menu->addMenu(DetailMenu);

    auto *InjectMenu = new RoundMenu("Inject", Menu);
    AddMenuAction(InjectMenu, "DLL", [this, Pid] { ShowInjectDllDialog(Pid); });
    AddMenuAction(InjectMenu, "Shellcode",
                  [this, Pid] { ShowInjectShellcodeDialog(Pid); });
    Menu->addMenu(InjectMenu);

    AddMenuAction(Menu, "Block Image",
                  [this, Pid, Name] { AddBlockImageRule(Pid, Name); });
    AddMenuAction(Menu, "Unblock Image",
                  [this, Name] {
                    PROCESS_CREATE_BLOCK_ENTRY Entry{};
                    Name.toWCharArray(Entry.ImagePattern);
                    Entry.ImagePattern[Name.length()] = L'\0';
                    if (RemoveProcessCreateBlock(Entry))
                      ShowSuccessNotice(this, "ProcessBlock",
                                        QString("Unblocked image: %1")
                                            .arg(Name));
                    else
                      ShowErrorNotice(
                          this, "ProcessBlock",
                          QString("No matching block rule for %1 (error %2).")
                              .arg(Name)
                              .arg(G_LastAegisCoreError));
                  });

    ReleaseMenuAfterClose(Menu);
    Menu->exec(ProcessTable->viewport()->mapToGlobal(Position));
  }

  void ShowChoiceDialog(const QString &TitleText,
                        const QString &DescriptionText,
                        const QStringList &Choices,
                        std::function<void(int)> Handler,
                        QWidget *ParentWindow = nullptr) {
    auto *Dialog = new MessageBoxBase(ParentWindow ? ParentWindow : window());
    Dialog->viewLayout()->setContentsMargins(28, 26, 28, 32);
    Dialog->setAttribute(Qt::WA_DeleteOnClose);
    auto *Title = MakeLabel(TitleText, 18, KTextPrimary, QFont::DemiBold);
    auto *Description = MakeLabel(DescriptionText, 11, KTextMuted);
    Description->setWordWrap(true);
    auto *ChoiceLabel =
        MakeLabel("Operation", 11, KTextPrimary, QFont::DemiBold);
    auto *Choice = new ComboBox;
    Choice->addItems(Choices);
    Choice->setCurrentIndex(0);
    Choice->setMinimumWidth(360);
    Dialog->viewLayout()->addWidget(Title);
    Dialog->viewLayout()->addWidget(Description);
    Dialog->viewLayout()->addSpacing(8);
    Dialog->viewLayout()->addWidget(ChoiceLabel);
    Dialog->viewLayout()->addWidget(Choice);
    Dialog->yesButton()->setText("Execute");
    Dialog->cancelButton()->setText("Cancel");
    QObject::connect(Dialog->yesButton(), &QPushButton::clicked, Dialog,
                     [Dialog, Choice, Handler = std::move(Handler)] {
                       const int Index = Choice->currentIndex();
                       Dialog->accept();
                       Handler(Index);
                     });
    QObject::connect(Dialog->cancelButton(), &QPushButton::clicked, Dialog,
                     &QDialog::reject);
    Dialog->show();
  }

  void ShowTerminateDialog(const std::vector<DWORD> &Pids) {
    ShowChoiceDialog(
        "Terminate",
        QString("Select how to terminate %1 selected process(es). This may "
                "cause data loss.")
            .arg(Pids.size()),
        {"R0ZwTerminateProcess", "R0TerminateProcessThreads","R0WriteZeroMemoryToProcess",
         "R3PatchThreadRun", "R3NtTerminate", "R3KillProcessForce",
         "R3RunInjectProc"},
        [this, Pids](int Index) {
          int SuccessCount = 0;
          int PartialCount = 0;
          quint64 EnumeratedThreads = 0;
          quint64 TerminatedThreads = 0;
          quint64 FailedThreads = 0;
          for (const DWORD Pid : Pids) {
            bool Success = false;
            switch (Index) {
            case 0:
              KillProcess(Pid);
              Success = G_LastAegisCoreError == ERROR_SUCCESS;
              break;
            case 1:
            {
              TERMINATE_PROCESS_THREADS_OUTPUT Result = {};
              Success = KillProcessByThreads(Pid, Result) != FALSE;
              EnumeratedThreads += Result.EnumeratedCount;
              TerminatedThreads += Result.TerminatedCount;
              FailedThreads += Result.FailedCount;
              if (!Success && Result.TerminatedCount != 0)
                ++PartialCount;
              break;
            }
            case 2:
				ProcessWriteZeroMemory(Pid);
                Success = true;
				break;
            case 3:
              PatchThreadRun(Pid);
              Success = true;
              break;
            case 4:
              Success = NtTerminate(Pid);
              break;
            case 5:
              Success = KillProcessForce(Pid);
              break;
            case 6:
              Success = RunInjectProc(Pid);
              break;
            default:
              return;
            }
            if (Success)
              ++SuccessCount;
          }
          if (Index == 1) {
            const int FailedProcessCount =
                static_cast<int>(Pids.size()) - SuccessCount - PartialCount;
            const QString Summary =
                QString("Processes: %1 complete, %2 partial, %3 failed. "
                        "Threads: %4/%5 terminated, %6 failed.")
                    .arg(SuccessCount)
                    .arg(PartialCount)
                    .arg(FailedProcessCount)
                    .arg(TerminatedThreads)
                    .arg(EnumeratedThreads)
                    .arg(FailedThreads);
            if (SuccessCount == 0 && PartialCount == 0)
              ShowErrorNotice(this, "Terminate", Summary);
            else if (PartialCount != 0 || FailedProcessCount != 0)
              ShowWarningNotice(this, "Terminate", Summary);
            else
              ShowSuccessNotice(this, "Terminate", Summary);
            QTimer::singleShot(0, this, [this] { RefreshProcesses(); });
            return;
          }
          if (SuccessCount == 0)
            ShowErrorNotice(this, "Terminate",
                            "Unable to terminate the selected processes.");
          else
            ShowSuccessNotice(this, "Terminate",
                              QString("%1 of %2 process(es) processed.")
                                  .arg(SuccessCount)
                                  .arg(Pids.size()));
          QTimer::singleShot(0, this, [this] { RefreshProcesses(); });
        });
  }

  void ShowTerminateDialog(DWORD Pid, const QString &Name) {
    Q_UNUSED(Name);
    ShowTerminateDialog(std::vector<DWORD>{Pid});
  }

  void ShowIntegrityDialog(DWORD Pid) {
    ShowChoiceDialog(
        "Set Integrity",
        QString("Select the integrity level for PID %1.").arg(Pid),
        {"Untrusted", "Low", "Medium", "High", "System", "Protected"},
        [this, Pid](int Index) {
          static const std::array<const wchar_t *, 6> Levels{
              L"S-1-16-0",     L"S-1-16-4096",  L"S-1-16-8192",
              L"S-1-16-12288", L"S-1-16-16384", L"S-1-16-20480"};
          if (Index < 0 || Index >= static_cast<int>(Levels.size()))
            return;
          if (!SetIntegrity(Pid, Levels[Index]))
            ShowErrorNotice(this, "Set Integrity",
                            "SetTokenInformation failed.");
          else
            ShowSuccessNotice(this, "Set Integrity",
                              "Integrity level updated.");
          QTimer::singleShot(0, this, [this] { RefreshProcesses(); });
        });
  }

  void ShowTokenDialog(DWORD Pid) {
    auto *Dialog = new QDialog(this);
    Dialog->setAttribute(Qt::WA_DeleteOnClose);
    Dialog->setWindowTitle("SetToken");
    Dialog->setModal(true);
    Dialog->resize(460, 250);

    auto *Layout = new QVBoxLayout(Dialog);
    Layout->setContentsMargins(20, 18, 20, 18);
    Layout->setSpacing(12);

    auto *Description =
        MakeLabel(QString("Apply a token to PID %1.").arg(Pid), 11, KTextMuted);
    Description->setWordWrap(true);
    auto *ModeLabel =
        MakeLabel("Source token", 11, KTextPrimary, QFont::DemiBold);
    auto *Mode = new ComboBox;
    Mode->addItems({"SYSTEM", "TRUSTEDINSTALLER", "Custom"});
    auto *CustomPidLabel =
        MakeLabel("Custom source PID", 11, KTextPrimary, QFont::DemiBold);
    auto *CustomPid = new LineEdit;
    CustomPid->setPlaceholderText("Enter source PID");
    CustomPidLabel->setVisible(false);
    CustomPid->setVisible(false);

    auto *Buttons = new QHBoxLayout;
    ConfigureToolbarLayout(Buttons);
    Buttons->addStretch();
    auto *Cancel = MakeButton("Cancel");
    auto *Apply = MakeButton("Apply", true);
    Buttons->addWidget(Cancel);
    Buttons->addWidget(Apply);

    Layout->addWidget(Description);
    Layout->addWidget(ModeLabel);
    Layout->addWidget(Mode);
    Layout->addWidget(CustomPidLabel);
    Layout->addWidget(CustomPid);
    Layout->addLayout(Buttons);

    QObject::connect(Mode, &ComboBox::currentTextChanged, Dialog,
                     [CustomPidLabel, CustomPid](const QString &Text) {
                       const bool IsCustom =
                           Text.compare("Custom", Qt::CaseInsensitive) == 0;
                       CustomPidLabel->setVisible(IsCustom);
                       CustomPid->setVisible(IsCustom);
                     });
    QObject::connect(Cancel, &QPushButton::clicked, Dialog, &QDialog::reject);
    QObject::connect(
        Apply, &QPushButton::clicked, Dialog,
        [this, Dialog, Mode, CustomPid, Pid] {
          const QString Choice = Mode->currentText();
          bool Success = false;
          QString SuccessText;
          if (Choice.compare("Custom", Qt::CaseInsensitive) == 0) {
            bool Ok = false;
            const qulonglong SourcePidValue =
                CustomPid->text().trimmed().toULongLong(&Ok, 0);
            if (!Ok || SourcePidValue == 0 ||
                SourcePidValue > std::numeric_limits<ULONG>::max()) {
              ShowWarningNotice(Dialog, "SetToken",
                                "Enter a valid source PID.");
              return;
            }
            Success = SetToken(static_cast<ULONG>(SourcePidValue), Pid);
            SuccessText = QString("Custom token from PID %1 applied.")
                              .arg(SourcePidValue);
          } else {
            const ULONG AccountType =
                Choice.compare("SYSTEM", Qt::CaseInsensitive) == 0
                    ? ACCOUNT_TYPE_SYSTEM
                    : ACCOUNT_TYPE_TRUSTEDINSTALLER;
            Success = SetTokenAs(AccountType, Pid);
            SuccessText = Choice.compare("SYSTEM", Qt::CaseInsensitive) == 0
                              ? "SYSTEM token applied."
                              : "TrustedInstaller token applied.";
          }

          if (!Success)
            ShowErrorNotice(this, "SetToken",
                            DescribeSetTokenError(G_LastAegisCoreError));
          else {
            ShowSuccessNotice(this, "SetToken", SuccessText);
            Dialog->accept();
            QTimer::singleShot(0, this, [this] { RefreshProcesses(); });
          }
        });
    ApplyDialogTheme(Dialog);
    Dialog->show();
  }

  void ShowProcessDisguiseDialog(DWORD Pid) {
    auto *Dialog = new QDialog(this);
    Dialog->setAttribute(Qt::WA_DeleteOnClose);
    Dialog->setWindowTitle("Process Disguise");
    Dialog->setModal(true);
    Dialog->resize(500, 290);

    auto *Layout = new QVBoxLayout(Dialog);
    Layout->setContentsMargins(20, 18, 20, 18);
    Layout->setSpacing(12);

    auto *Description =
        MakeLabel(QString("Disguise PID %1.").arg(Pid), 11, KTextMuted);
    Description->setWordWrap(true);
    auto *ModeLabel =
        MakeLabel("Disguise mode", 11, KTextPrimary, QFont::DemiBold);
    auto *Mode = new ComboBox;
    Mode->addItems({"CurrentProcess", "Custom"});

    auto *RenameTitles = new CheckBox("Rename window titles");
    RenameTitles->setChecked(true);

    auto *SourcePidLabel =
        MakeLabel("Existing PID", 11, KTextPrimary, QFont::DemiBold);
    auto *SourcePid = new LineEdit;
    SourcePid->setPlaceholderText("Enter an existing PID");

    auto *ImagePathLabel =
        MakeLabel("ImagePath", 11, KTextPrimary, QFont::DemiBold);
    auto *ImagePath = new LineEdit;
    ImagePath->setPlaceholderText(
        "C:\\Windows\\System32\\svchost.exe");

    auto *FakePidLabel =
        MakeLabel("PID", 11, KTextPrimary, QFont::DemiBold);
    auto *FakePid = new LineEdit;
    FakePid->setText(QString::number(Pid));
    FakePid->setPlaceholderText("Target PID to disguise");

    auto *ParentPidLabel =
        MakeLabel("ParentPID", 11, KTextPrimary, QFont::DemiBold);
    auto *ParentPid = new LineEdit;
    ParentPid->setPlaceholderText("Fake parent PID");

    auto *Buttons = new QHBoxLayout;
    ConfigureToolbarLayout(Buttons);
    Buttons->addStretch();
    auto *Cancel = MakeButton("Cancel");
    auto *Apply = MakeButton("Apply", true);
    Buttons->addWidget(Cancel);
    Buttons->addWidget(Apply);

    Layout->addWidget(Description);
    Layout->addWidget(ModeLabel);
    Layout->addWidget(Mode);
    Layout->addWidget(RenameTitles);
    Layout->addWidget(SourcePidLabel);
    Layout->addWidget(SourcePid);
    Layout->addWidget(ImagePathLabel);
    Layout->addWidget(ImagePath);
    Layout->addWidget(FakePidLabel);
    Layout->addWidget(FakePid);
    Layout->addWidget(ParentPidLabel);
    Layout->addWidget(ParentPid);
    Layout->addLayout(Buttons);

    auto UpdateModeVisibility = [SourcePidLabel, SourcePid, ImagePathLabel,
                                 ImagePath, FakePidLabel, FakePid,
                                 ParentPidLabel, ParentPid](bool IsCustom) {
      SourcePidLabel->setVisible(!IsCustom);
      SourcePid->setVisible(!IsCustom);
      ImagePathLabel->setVisible(IsCustom);
      ImagePath->setVisible(IsCustom);
      FakePidLabel->setVisible(IsCustom);
      FakePid->setVisible(IsCustom);
      ParentPidLabel->setVisible(IsCustom);
      ParentPid->setVisible(IsCustom);
    };
    UpdateModeVisibility(false);
    QObject::connect(Mode, &ComboBox::currentTextChanged, Dialog,
                     [UpdateModeVisibility](const QString &Text) {
                       UpdateModeVisibility(Text.compare("Custom",
                                                         Qt::CaseInsensitive) ==
                                            0);
                     });
    QObject::connect(Cancel, &QPushButton::clicked, Dialog, &QDialog::reject);
    QObject::connect(
        Apply, &QPushButton::clicked, Dialog,
        [this, Dialog, Mode, RenameTitles, SourcePid, ImagePath, FakePid,
         ParentPid, Pid] {
          const QString Choice = Mode->currentText();
          const bool IsCustom =
              Choice.compare("Custom", Qt::CaseInsensitive) == 0;
          QString BaseName;

          PROCESS_DISGUISE_ENTRY Entry{};
          Entry.TargetPid = Pid;

          if (IsCustom) {
            bool Ok = false;
            const qulonglong FakePidValue =
                FakePid->text().trimmed().toULongLong(&Ok, 0);
            if (!Ok || FakePidValue == 0 ||
                FakePidValue > std::numeric_limits<ULONG>::max()) {
              ShowWarningNotice(Dialog, "ProcessDisguise",
                                "Enter a valid target PID.");
              return;
            }
            const qulonglong FakeParentPidValue =
                ParentPid->text().trimmed().toULongLong(&Ok, 0);
            if (!Ok || FakeParentPidValue == 0 ||
                FakeParentPidValue > std::numeric_limits<ULONG>::max()) {
              ShowWarningNotice(Dialog, "ProcessDisguise",
                                "Enter a valid parent PID.");
              return;
            }
            const QString Image = ImagePath->text().trimmed();
            if (Image.isEmpty() || Image.length() >= 260) {
              ShowWarningNotice(Dialog, "ProcessDisguise",
                                "Enter a valid image path.");
              return;
            }
            Entry.Mode = PROCESS_DISGUISE_MODE_CUSTOM;
            Entry.FakePid = static_cast<ULONG>(FakePidValue);
            Entry.FakeParentPid = static_cast<ULONG>(FakeParentPidValue);
            Image.toWCharArray(Entry.FakeImagePath);
            Entry.FakeImagePath[Image.length()] = L'\0';
            const int NameStart =
                std::max(Image.lastIndexOf('\\'), Image.lastIndexOf('/')) + 1;
            BaseName = Image.mid(NameStart);
          } else {
            bool Ok = false;
            const qulonglong SourcePidValue =
                SourcePid->text().trimmed().toULongLong(&Ok, 0);
            if (!Ok || SourcePidValue == 0 ||
                SourcePidValue > std::numeric_limits<ULONG>::max()) {
              ShowWarningNotice(Dialog, "ProcessDisguise",
                                "Enter a valid source PID.");
              return;
            }
            const ProcessRow *Source =
                FindProcess(static_cast<DWORD>(SourcePidValue));
            if (!Source) {
              ShowWarningNotice(Dialog, "ProcessDisguise",
                                QString("PID %1 does not exist.")
                                    .arg(SourcePidValue));
              return;
            }
            Entry.Mode = PROCESS_DISGUISE_MODE_CURRENT;
            Entry.SourcePid = static_cast<ULONG>(SourcePidValue);
            BaseName = Source->Name;
          }

          if (!ApplyProcessDisguise(Entry))
            ShowErrorNotice(this, "ProcessDisguise",
                            QString("Driver operation failed (error %1).")
                                .arg(G_LastAegisCoreError));
          else {
            int RenamedCount = 0;
            if (RenameTitles->isChecked() && !BaseName.isEmpty()) {
              struct RenameContext {
                DWORD TargetPid;
                std::wstring Title;
                int Count;
              };
              RenameContext Ctx{Pid, BaseName.toStdWString(), 0};
              EnumWindows(
                  [](HWND Hwnd, LPARAM LParam) -> BOOL {
                    auto *Ctx =
                        reinterpret_cast<RenameContext *>(LParam);
                    DWORD WindowPid = 0;
                    GetWindowThreadProcessId(Hwnd, &WindowPid);
                    if (WindowPid != Ctx->TargetPid || !IsWindowVisible(Hwnd))
                      return TRUE;
                    if (SetWindowTextW(Hwnd, Ctx->Title.c_str()))
                      ++Ctx->Count;
                    return TRUE;
                  },
                  reinterpret_cast<LPARAM>(&Ctx));
              RenamedCount = Ctx.Count;
            }
            ShowSuccessNotice(this, "ProcessDisguise",
                              RenameTitles->isChecked()
                                  ? QString("Disguise applied. %1 window(s) "
                                            "renamed.")
                                        .arg(RenamedCount)
                                  : QString("Disguise applied successfully."));
            Dialog->accept();
          }
        });
    ApplyDialogTheme(Dialog);
    Dialog->show();
  }

  void ShowApcSignalDialog(DWORD Pid) {
    ShowChoiceDialog(
        "SendAPCSignal", QString("Select the APC signal for PID %1.").arg(Pid),
        {"NoOp", "Terminate"}, [this, Pid](int Index) {
          static const std::array<ULONG, 2> Actions{APC_ACTION_NOOP,
                                                    APC_ACTION_TERMINATE};
          if (Index < 0 || Index >= static_cast<int>(Actions.size()))
            return;
          QueueApc(Pid, Actions[Index]);
          ReportDriverResult("APC");
        });
  }

  void AddBlockImageRule(DWORD Pid, const QString &ProcessName) {
    PROCESS_CREATE_BLOCK_ENTRY Entry{};
    Entry.Action = PROCESS_CREATE_BLOCK_ACTION_BLOCK;
    Entry.Flags = PROCESS_CREATE_BLOCK_MATCH_IMAGE;
    ProcessName.toWCharArray(Entry.ImagePattern);
    Entry.ImagePattern[ProcessName.length()] = L'\0';
    if (AddProcessCreateBlock(Entry))
      ShowSuccessNotice(this, "ProcessBlock",
                        QString("Blocked image: %1").arg(ProcessName));
    else
      ShowErrorNotice(this, "ProcessBlock",
                      QString("Failed to add rule (error %1).")
                          .arg(G_LastAegisCoreError));
  }

  void ShowProcessBlockDialog() {
    struct State {
      PROCESS_CREATE_BLOCK_ENTRY Entries[PROCESS_CREATE_BLOCK_MAX_ENTRIES];
      ULONG Count = 0;
    };
    auto StatePtr = std::make_shared<State>();

    auto *Dialog = new QDialog(this);
    Dialog->setWindowTitle("Process Block Rules");
    Dialog->setAttribute(Qt::WA_DeleteOnClose);
    Dialog->resize(980, 670);
    auto *Layout = new QVBoxLayout(Dialog);
    ConfigurePageLayout(Layout);

    auto *Toolbar = new QHBoxLayout;
    ConfigureToolbarLayout(Toolbar);
    auto *BlockSearchEdit = new SearchLineEdit;
    ConfigureSearchLineEdit(BlockSearchEdit, "Search image pattern", 260);
    auto *StatusLabel = new BodyLabel("Ready");
    auto *RefreshBtn = MakeButton("Refresh", true);
    Toolbar->addWidget(BlockSearchEdit);
    Toolbar->addWidget(StatusLabel, 1);
    Toolbar->addWidget(RefreshBtn);
    Layout->addLayout(Toolbar);

    auto *Table = MakeTable(
        {"Index", "Image Pattern", "Command Pattern", "Action", "Parent PID", "Flags"});
    Table->setSelectionBehavior(QAbstractItemView::SelectRows);
    Table->setSelectionMode(QAbstractItemView::SingleSelection);
    Table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    Layout->addWidget(Table, 1);

    auto *InputLayout = new QHBoxLayout;
    auto *ImageEdit = new LineEdit;
    ConfigureLineEdit(ImageEdit, "Image pattern (e.g. *malware*.exe)", 0);
    auto *CmdEdit = new LineEdit;
    ConfigureLineEdit(CmdEdit, "Command line pattern", 0);
    auto *ActionCombo = new ComboBox;
    ActionCombo->addItems({"Block", "Audit"});
    ActionCombo->setMinimumWidth(100);
    auto *ParentPidSpin = new SpinBox;
    ParentPidSpin->setRange(0, 999999);
    ParentPidSpin->setValue(0);
    ParentPidSpin->setPrefix("PID ");
    ParentPidSpin->setMinimumWidth(100);
    auto *AddBtn = MakeButton("Add", true);
    InputLayout->addWidget(ImageEdit, 2);
    InputLayout->addWidget(CmdEdit, 2);
    InputLayout->addWidget(ActionCombo);
    InputLayout->addWidget(ParentPidSpin);
    InputLayout->addWidget(AddBtn);
    Layout->addLayout(InputLayout);

    auto *BtnLayout = new QHBoxLayout;
    auto *RemoveBtn = MakeButton("Remove");
    auto *ClearBtn = MakeButton("Clear All");
    BtnLayout->addWidget(RemoveBtn);
    BtnLayout->addWidget(ClearBtn);
    BtnLayout->addStretch();
    auto *CloseBtn = MakeButton("Close");
    BtnLayout->addWidget(CloseBtn);
    Layout->addLayout(BtnLayout);

    auto RefreshTable = [Table, StatePtr, BlockSearchEdit, StatusLabel] {
      PROCESS_CREATE_BLOCK_OUTPUT *Output =
          static_cast<PROCESS_CREATE_BLOCK_OUTPUT *>(
              malloc(sizeof(PROCESS_CREATE_BLOCK_OUTPUT)));
      if (!Output)
        return;
      if (EnumerateProcessCreateBlocks(Output)) {
        StatePtr->Count = Output->Count;
        for (ULONG i = 0; i < Output->Count; ++i)
          StatePtr->Entries[i] = Output->Entries[i];
        StatusLabel->setText(
            QString("%1 rules").arg(Output->TotalCount));
      } else {
        StatusLabel->setText("Query failed");
      }
      free(Output);
      const QString Filter = BlockSearchEdit->text().trimmed().toUpper();
      Table->setRowCount(static_cast<int>(StatePtr->Count));
      int Row = 0;
      for (ULONG i = 0; i < StatePtr->Count; ++i) {
        auto &E = StatePtr->Entries[i];
        QString Pattern = QString::fromWCharArray(E.ImagePattern);
        if (!Filter.isEmpty() && !Pattern.toUpper().contains(Filter))
          continue;
        Table->setItem(Row, 0, new QTableWidgetItem(QString::number(E.Index)));
        Table->setItem(Row, 1, new QTableWidgetItem(Pattern));
        Table->setItem(Row, 2,
                       new QTableWidgetItem(QString::fromWCharArray(E.CommandPattern)));
        Table->setItem(Row, 3,
                       new QTableWidgetItem(E.Action == PROCESS_CREATE_BLOCK_ACTION_BLOCK
                                                ? "Block"
                                                : "Audit"));
        Table->setItem(Row, 4,
                       new QTableWidgetItem(E.ParentPid ? QString::number(E.ParentPid) : "-"));
        QStringList Flags;
        if (E.Flags & PROCESS_CREATE_BLOCK_WHITELIST) Flags << "WHITELIST";
        if (E.Flags & PROCESS_CREATE_BLOCK_MATCH_PARENT) Flags << "MATCH_PARENT";
        if (E.Flags & PROCESS_CREATE_BLOCK_MATCH_COMMAND) Flags << "MATCH_COMMAND";
        Table->setItem(Row, 5,
                       new QTableWidgetItem(Flags.isEmpty() ? "-" : Flags.join(",")));
        ++Row;
      }
      Table->setRowCount(Row);
    };

    QObject::connect(RefreshBtn, &QPushButton::clicked, Dialog,
                     [RefreshTable] { RefreshTable(); });
    QObject::connect(BlockSearchEdit, &QLineEdit::textChanged, Dialog,
                     [RefreshTable] { RefreshTable(); });
    QObject::connect(AddBtn, &QPushButton::clicked, Dialog,
                     [RefreshTable, ImageEdit, CmdEdit, ActionCombo, ParentPidSpin] {
                       PROCESS_CREATE_BLOCK_ENTRY Entry{};
                       Entry.Action = ActionCombo->currentIndex() == 0
                                          ? PROCESS_CREATE_BLOCK_ACTION_BLOCK
                                          : PROCESS_CREATE_BLOCK_ACTION_AUDIT;
                       Entry.Flags = PROCESS_CREATE_BLOCK_MATCH_IMAGE;
                       Entry.ParentPid = static_cast<ULONG>(ParentPidSpin->value());
                       QString Image = ImageEdit->text().trimmed();
                       if (!Image.isEmpty()) {
                         Image.toWCharArray(Entry.ImagePattern);
                         Entry.ImagePattern[Image.length()] = L'\0';
                       }
                       QString Cmd = CmdEdit->text().trimmed();
                       if (!Cmd.isEmpty()) {
                         Entry.Flags |= PROCESS_CREATE_BLOCK_MATCH_COMMAND;
                         Cmd.toWCharArray(Entry.CommandPattern);
                         Entry.CommandPattern[Cmd.length()] = L'\0';
                       }
                       if (Image.isEmpty() && Cmd.isEmpty())
                         return;
                       AddProcessCreateBlock(Entry);
                       ImageEdit->clear();
                       CmdEdit->clear();
                       RefreshTable();
                     });
    QObject::connect(RemoveBtn, &QPushButton::clicked, Dialog,
                     [RefreshTable, Table, StatePtr] {
                       int Row = Table->currentRow();
                       if (Row < 0)
                         return;
                       ULONG Index = 0;
                       auto *Item = Table->item(Row, 0);
                       if (Item)
                         Index = Item->text().toULong();
                       PROCESS_CREATE_BLOCK_ENTRY Entry{};
                       Entry.Index = Index;
                       RemoveProcessCreateBlock(Entry);
                       RefreshTable();
                     });
    QObject::connect(ClearBtn, &QPushButton::clicked, Dialog,
                     [RefreshTable] {
                       ClearProcessCreateBlocks();
                       RefreshTable();
                     });
    QObject::connect(CloseBtn, &QPushButton::clicked, Dialog, &QDialog::accept);
    QTimer::singleShot(100, Dialog, [RefreshTable] { RefreshTable(); });
    ApplyDialogTheme(Dialog);
    Dialog->show();
  }

  void ShowInjectShellcodeDialog(DWORD Pid) {
    bool Ok = false;
    QString Text = QInputDialog::getMultiLineText(
        this, "InjectShellcode",
        QString("Paste shellcode bytes in hex for PID %1.").arg(Pid),
        "48 31 C0 C3", &Ok);
    if (!Ok)
      return;

    QByteArray Shellcode;
    QString ErrorText;
    if (!ParseHexBytes(Text, Shellcode, &ErrorText)) {
      ShowWarningNotice(this, "InjectShellcode", ErrorText);
      return;
    }

    ULONG_PTR Address = 0;
    if (!InjectShellcode(Pid, reinterpret_cast<const UCHAR *>(Shellcode.data()),
                         static_cast<ULONG>(Shellcode.size()), &Address)) {
      ShowErrorNotice(this, "InjectShellcode",
                      QString("Injection failed (error %1).")
                          .arg(G_LastAegisCoreError));
      return;
    }

    const QString AddressText =
        QString("0x%1").arg(Address, 0, 16).toUpper();
    AppendConsoleOutput(QString("[+] Shellcode injected.\n"
                                "    PID: %1\n"
                                "    Size: %2\n"
                                "    Address: %3\n")
                            .arg(Pid)
                            .arg(Shellcode.size())
                            .arg(AddressText));
    ShowSuccessNotice(this, "InjectShellcode",
                      QString("Shellcode injected at %1.").arg(AddressText));
  }

  void ShowThreadHijackDialog(DWORD Pid, const std::vector<DWORD> &Tids,
                              bool UseTrapFrame, const QString &Action) {
    if (Pid == GetCurrentProcessId()) {
      ShowWarningNotice(this, Action,
                        "Thread operations on AegisNT itself are disabled.");
      return;
    }

    bool Ok = false;
    QString Text =
        QInputDialog::getText(this, Action, "Target RIP:", QLineEdit::Normal,
                              "0x", &Ok);
    if (!Ok)
      return;

    ULONG_PTR TargetRip = 0;
    if (!ParseHexPointerValue(Text, TargetRip) || TargetRip == 0) {
      ShowWarningNotice(this, Action, "Enter a valid hex RIP.");
      return;
    }

    int SuccessCount = 0;
    DWORD LastError = ERROR_SUCCESS;
    for (DWORD Tid : Tids) {
      const bool Success = UseTrapFrame ? HijackThreadTrapFrame(Tid, TargetRip)
                                        : HijackThreadContext(Tid, TargetRip);
      if (Success)
        ++SuccessCount;
      else
        LastError = G_LastAegisCoreError;
    }

    if (SuccessCount == 0) {
      ShowErrorNotice(this, Action,
                      QString("Operation failed (error %1).").arg(LastError));
      return;
    }

    const QString RipText = QString("0x%1").arg(TargetRip, 0, 16).toUpper();
    AppendConsoleOutput(QString("[+] %1 completed.\n"
                                "    PID: %2\n"
                                "    RIP: %3\n"
                                "    Threads: %4/%5\n")
                            .arg(Action)
                            .arg(Pid)
                            .arg(RipText)
                            .arg(SuccessCount)
                            .arg(Tids.size()));
    ShowSuccessNotice(this, Action,
                      QString("%1 of %2 thread(s) updated.")
                          .arg(SuccessCount)
                          .arg(Tids.size()));
  }

  void ShowRemoteCallDialog(DWORD Pid, const std::vector<DWORD> &Tids) {
    if (Pid == GetCurrentProcessId()) {
      ShowWarningNotice(this, "RemoteCall",
                        "Thread operations on AegisNT itself are disabled.");
      return;
    }

    const auto ReadValue = [this](const QString &Title,
                                  const QString &Label,
                                  ULONG_PTR &Value) -> bool {
      bool Ok = false;
      const QString Text = QInputDialog::getText(
          this, Title, Label, QLineEdit::Normal, "0x0", &Ok);
      if (!Ok)
        return false;
      if (!ParseHexPointerValue(Text, Value)) {
        ShowWarningNotice(this, Title,
                          QString("Enter a valid hex value for %1.")
                              .arg(Label));
        return false;
      }
      return true;
    };

    ULONG_PTR Function = 0;
    ULONG_PTR Arg1 = 0;
    ULONG_PTR Arg2 = 0;
    ULONG_PTR Arg3 = 0;
    ULONG_PTR Arg4 = 0;
    if (!ReadValue("RemoteCall", "Function address:", Function) ||
        !ReadValue("RemoteCall", "Arg1:", Arg1) ||
        !ReadValue("RemoteCall", "Arg2:", Arg2) ||
        !ReadValue("RemoteCall", "Arg3:", Arg3) ||
        !ReadValue("RemoteCall", "Arg4:", Arg4))
      return;

    int SuccessCount = 0;
    DWORD LastError = ERROR_SUCCESS;
    QStringList Results;
    for (DWORD Tid : Tids) {
      LONG Result = 0;
      if (RemoteCallViaKernel(Tid, Function, Arg1, Arg2, Arg3, Arg4,
                              &Result)) {
        ++SuccessCount;
        Results << QString("    TID %1 => 0x%2")
                       .arg(Tid)
                       .arg(static_cast<quint32>(Result), 8, 16,
                            QLatin1Char('0'))
                       .toUpper();
      } else {
        LastError = G_LastAegisCoreError;
      }
    }

    if (SuccessCount == 0) {
      ShowErrorNotice(this, "RemoteCall",
                      QString("Operation failed (error %1).").arg(LastError));
      return;
    }

    const QString FunctionText =
        QString("0x%1").arg(Function, 0, 16).toUpper();
    const QString Arg1Text = QString("0x%1").arg(Arg1, 0, 16).toUpper();
    const QString Arg2Text = QString("0x%1").arg(Arg2, 0, 16).toUpper();
    const QString Arg3Text = QString("0x%1").arg(Arg3, 0, 16).toUpper();
    const QString Arg4Text = QString("0x%1").arg(Arg4, 0, 16).toUpper();
    AppendConsoleOutput(QString("[+] Remote call completed.\n"
                                "    PID: %1\n"
                                "    Function: %2\n"
                                "    Args: %3 %4 %5 %6\n%7\n")
                            .arg(Pid)
                            .arg(FunctionText)
                            .arg(Arg1Text)
                            .arg(Arg2Text)
                            .arg(Arg3Text)
                            .arg(Arg4Text)
                            .arg(Results.join('\n')));
    ShowSuccessNotice(this, "RemoteCall",
                      QString("%1 of %2 thread(s) processed.")
                          .arg(SuccessCount)
                          .arg(Tids.size()));
  }

  void ShowInjectAndHijackDialog(DWORD Pid, const std::vector<DWORD> &Tids) {
    if (Pid == GetCurrentProcessId()) {
      ShowWarningNotice(this, "InjectAndHijack",
                        "Thread operations on AegisNT itself are disabled.");
      return;
    }

    bool Ok = false;
    QString Text = QInputDialog::getMultiLineText(
        this, "InjectAndHijack",
        QString("Paste shellcode bytes in hex for PID %1.").arg(Pid),
        "48 31 C0 C3", &Ok);
    if (!Ok)
      return;

    QByteArray Shellcode;
    QString ErrorText;
    if (!ParseHexBytes(Text, Shellcode, &ErrorText)) {
      ShowWarningNotice(this, "InjectAndHijack", ErrorText);
      return;
    }

    int SuccessCount = 0;
    DWORD LastError = ERROR_SUCCESS;
    ULONG_PTR LastAddress = 0;
    for (DWORD Tid : Tids) {
      ULONG_PTR Address = 0;
      if (InjectAndHijack(Tid, reinterpret_cast<const UCHAR *>(Shellcode.data()),
                          static_cast<ULONG>(Shellcode.size()), &Address)) {
        ++SuccessCount;
        LastAddress = Address;
      } else {
        LastError = G_LastAegisCoreError;
      }
    }

    if (SuccessCount == 0) {
      ShowErrorNotice(this, "InjectAndHijack",
                      QString("Operation failed (error %1).").arg(LastError));
      return;
    }

    const QString AddressText =
        QString("0x%1").arg(LastAddress, 0, 16).toUpper();
    AppendConsoleOutput(QString("[+] InjectAndHijack completed.\n"
                                "    PID: %1\n"
                                "    Size: %2\n"
                                "    Address: %3\n"
                                "    Threads: %4/%5\n")
                            .arg(Pid)
                            .arg(Shellcode.size())
                            .arg(AddressText)
                            .arg(SuccessCount)
                            .arg(Tids.size()));
    ShowSuccessNotice(this, "InjectAndHijack",
                      QString("%1 of %2 thread(s) processed.")
                          .arg(SuccessCount)
                          .arg(Tids.size()));
  }

  void ConfigurePpl(const std::vector<DWORD> &Pids) {
    auto *Dialog = new MessageBoxBase(window());
    Dialog->viewLayout()->setContentsMargins(28, 26, 28, 32);
    Dialog->setAttribute(Qt::WA_DeleteOnClose);
    auto *Title = MakeLabel("SetPPL", 18, KTextPrimary, QFont::DemiBold);
    auto *Description = MakeLabel(
        QString("Configure protected process light settings for %1 selected "
                "process(es).")
            .arg(Pids.size()),
        11, KTextMuted);
    auto *TypeLabel =
        MakeLabel("Protection type", 11, KTextPrimary, QFont::DemiBold);
    auto *Type = new ComboBox;
    Type->addItems({"None", "ProtectedLight", "Protected"});
    Type->setCurrentIndex(0);
    auto *SignerLabel = MakeLabel("Signer", 11, KTextPrimary, QFont::DemiBold);
    auto *Signer = new ComboBox;
    Signer->addItems({"None", "Authenticode", "CodeGen", "Antimalware", "Lsa",
                      "Windows", "WinTcb", "WinSystem", "App"});
    Signer->setCurrentIndex(0);
    auto *AuditLabel = MakeLabel("Audit", 11, KTextPrimary, QFont::DemiBold);
    auto *Audit = new ComboBox;
    Audit->addItems({"Off", "On"});
    Audit->setCurrentIndex(0);
    Dialog->viewLayout()->addWidget(Title);
    Dialog->viewLayout()->addWidget(Description);
    Dialog->viewLayout()->addSpacing(8);
    Dialog->viewLayout()->addWidget(TypeLabel);
    Dialog->viewLayout()->addWidget(Type);
    Dialog->viewLayout()->addWidget(SignerLabel);
    Dialog->viewLayout()->addWidget(Signer);
    Dialog->viewLayout()->addWidget(AuditLabel);
    Dialog->viewLayout()->addWidget(Audit);
    Dialog->yesButton()->setText("Apply");
    Dialog->cancelButton()->setText("Cancel");
    QObject::connect(Dialog->yesButton(), &QPushButton::clicked, Dialog,
                     [this, Dialog, Type, Signer, Audit, Pids] {
                       for (DWORD SelectedPid : Pids)
                         SetPpl(SelectedPid,
                                static_cast<UCHAR>(Type->currentIndex()),
                                static_cast<UCHAR>(Signer->currentIndex()),
                                Audit->currentIndex() == 1);
                       Dialog->accept();
                       ReportDriverResult("SetPPL");
                     });
    QObject::connect(Dialog->cancelButton(), &QPushButton::clicked, Dialog,
                     &QDialog::reject);
    Dialog->show();
  }

  struct InspectorTableRow {
    QStringList Values;
    std::array<QVariant, 3> Roles;
  };
  using InspectorTableRows =
      std::map<QTableWidget *, std::vector<InspectorTableRow>>;

  template <size_t N>
  static QString InspectorRecordText(const WCHAR (&Text)[N]) {
    return QString::fromWCharArray(
        Text, static_cast<int>(wcsnlen_s(Text, N)));
  }

  static void PopulateInspectorTables(QDialog *Dialog,
                                     QLineEdit *Search,
                                     InspectorTableRows Rows,
                                     std::function<void(bool)> Finished) {
    struct TableBatch {
      QPointer<QTableWidget> Table;
      std::vector<InspectorTableRow> Rows;
      int FirstRow = 0;
    };
    struct RenderState {
      std::vector<TableBatch> Tables;
      size_t TableIndex = 0;
      size_t RowIndex = 0;
    };
    auto State = std::make_shared<RenderState>();
    for (auto &[Table, Values] : Rows) {
      const int FirstRow = Table->rowCount();
      Table->setRowCount(FirstRow + static_cast<int>(Values.size()));
      State->Tables.push_back({Table, std::move(Values), FirstRow});
    }
    // 由对话框拥有定时器；关闭窗口会取消剩余批次并释放快照。
    // 每批返回正常事件循环，不在填表中 processEvents 重入 UI。
    auto *Timer = new QTimer(Dialog);
    Timer->setInterval(1);
    QObject::connect(Timer, &QTimer::timeout, Dialog,
                     [Timer, State, Search, Finished = std::move(Finished)] {
      QElapsedTimer Budget;
      Budget.start();
      int Added = 0;
      try {
        while (State->TableIndex < State->Tables.size()) {
          auto &Batch = State->Tables[State->TableIndex];
          if (!Batch.Table) {
            Timer->stop();
            Timer->deleteLater();
            Finished(false);
            return;
          }
          QTableWidget *Table = Batch.Table;
          Table->setUpdatesEnabled(false);
          const QString Query = Search->text().trimmed();
          while (State->RowIndex < Batch.Rows.size()) {
            const auto &Entry = Batch.Rows[State->RowIndex];
            const int Row = Batch.FirstRow + static_cast<int>(State->RowIndex);
            for (int Column = 0; Column < Entry.Values.size(); ++Column)
              Table->setItem(Row, Column,
                             new QTableWidgetItem(Entry.Values[Column]));
            if (QTableWidgetItem *Item = Table->item(Row, 0)) {
              for (int Role = 0; Role < static_cast<int>(Entry.Roles.size()); ++Role)
                if (Entry.Roles[Role].isValid())
                  Item->setData(Qt::UserRole + Role, Entry.Roles[Role]);
            }
            Table->setRowHidden(
                Row, !Query.isEmpty() &&
                         !Entry.Values.join(QLatin1Char(' '))
                              .contains(Query, Qt::CaseInsensitive));
            ++State->RowIndex;
            if (++Added >= 64 || Budget.elapsed() >= 4) {
              Table->setUpdatesEnabled(true);
              return;
            }
          }
          Table->setUpdatesEnabled(true);
          ++State->TableIndex;
          State->RowIndex = 0;
        }
        Timer->stop();
        Timer->deleteLater();
        Finished(true);
      } catch (...) {
        Timer->stop();
        Timer->deleteLater();
        for (const auto &Batch : State->Tables)
          if (Batch.Table)
            Batch.Table->setUpdatesEnabled(true);
        Finished(false);
      }
    });
    Timer->start();
  }

  void ShowProcessInspector(DWORD Pid) {
    const ProcessRow *SelectedProcess = FindProcess(Pid);
    const QString ProcessName =
        SelectedProcess && !SelectedProcess->Name.isEmpty()
            ? SelectedProcess->Name
            : QString("Process %1").arg(Pid);
    auto *Dialog = new QDialog(this);
    Dialog->setAttribute(Qt::WA_DeleteOnClose);
    ++ActiveInspectorDialogs;
    QObject::connect(Dialog, &QObject::destroyed, this, [this] {
      if (ActiveInspectorDialogs > 0)
        --ActiveInspectorDialogs;
      if (ActiveInspectorDialogs == 0 && ProcessTablePopulatePending) {
        ProcessTablePopulatePending = false;
        PopulateTable();
      }
    });
    Dialog->setWindowTitle(QString("%1 - Process Inspector").arg(ProcessName));
    Dialog->resize(1160, 790);
    Dialog->setMinimumSize(900, 620);
    auto *Layout = new QVBoxLayout(Dialog);
    Layout->setContentsMargins(18, 16, 18, 16);
    Layout->setSpacing(10);

    auto *Header = new QWidget;
    auto *HeaderLayout = new QHBoxLayout(Header);
    HeaderLayout->setContentsMargins(0, 0, 0, 0);
    HeaderLayout->setSpacing(10);
    auto *IconHost = new QWidget;
    IconHost->setFixedSize(42, 42);
    const QColor Accent = ConfiguredColor("AccentColor", KAccent);
    IconHost->setStyleSheet(
        QString("background: rgba(%1,%2,%3,%4); border-radius: 8px;")
            .arg(Accent.red())
            .arg(Accent.green())
            .arg(Accent.blue())
            .arg(42));
    auto *IconLayout = new QVBoxLayout(IconHost);
    IconLayout->setContentsMargins(0, 0, 0, 0);
    IconLayout->addWidget(MakeGlyph(Fluent::IconType::APPLICATION, 24), 0,
                          Qt::AlignCenter);
    HeaderLayout->addWidget(IconHost);
    auto *IdentityLayout = new QVBoxLayout;
    IdentityLayout->setContentsMargins(0, 1, 0, 1);
    IdentityLayout->setSpacing(2);
    IdentityLayout->addWidget(
        MakeLabel(ProcessName, 17, KTextPrimary, QFont::DemiBold));
    IdentityLayout->addWidget(
        MakeLabel(QString("PID %1").arg(Pid), 11, KTextMuted, QFont::Medium));
    HeaderLayout->addLayout(IdentityLayout, 1);
    auto *Loading = new IndeterminateProgressRing(Dialog, false);
    Loading->setFixedSize(22, 22);
    Loading->start();
    auto *LoadStatus = new BodyLabel("Reading process data...");
    HeaderLayout->addWidget(Loading);
    HeaderLayout->addWidget(LoadStatus);
    Layout->addWidget(Header);

    auto *InspectorSearch = new SearchLineEdit;
    InspectorSearch->setPlaceholderText("Search the current process details");
    InspectorSearch->setClearButtonEnabled(true);
    InspectorSearch->setMaximumWidth(380);
    Layout->addWidget(InspectorSearch);

    auto *Tabs = new TabBar;
    Tabs->setAddButtonVisible(false);
    Tabs->setTabsClosable(false);
    Tabs->setMovable(false);
    auto *Pages = new QStackedWidget;
    Layout->addWidget(Tabs);
    Layout->addWidget(Pages, 1);

    const auto AddTable = [Tabs, Pages](const QString &Key, const QString &Name,
                                        Fluent::IconType Icon,
                                        const QStringList &Columns) {
      auto *Table = MakeTable(Columns);
      Table->setSortingEnabled(false);
      Table->setTextElideMode(Qt::ElideRight);
      Table->horizontalHeader()->setStretchLastSection(true);
      Tabs->addTab(Key, Name, Icon);
      Pages->addWidget(Table);
      return Table;
    };
    auto *Summary = AddTable("summary", "Summary", Fluent::IconType::INFO,
                             {"Field", "Value"});
    Summary->horizontalHeader()->setSectionResizeMode(
        0, QHeaderView::ResizeToContents);
    Summary->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    const auto AddSummaryRow = [Summary](const QString &Field,
                                         const QString &Value) {
      const int Row = Summary->rowCount();
      Summary->insertRow(Row);
      Summary->setItem(Row, 0, new QTableWidgetItem(Field));
      Summary->setItem(Row, 1, new QTableWidgetItem(Value));
      Summary->setRowHeight(Row, KCompactTableRowHeight);
    };
    if (SelectedProcess) {
      AddSummaryRow("PID", QString::number(SelectedProcess->Pid));
      AddSummaryRow("Image", SelectedProcess->Name);
      AddSummaryRow("User", SelectedProcess->User);
      AddSummaryRow("Integrity", IntegrityName(SelectedProcess->IntegrityRid));
      AddSummaryRow("Parent PID", QString::number(SelectedProcess->ParentPid));
      AddSummaryRow("Threads", QString::number(SelectedProcess->ThreadCount));
      AddSummaryRow("Handles",
                    SelectedProcess->HandleCountAvailable
                        ? QString::number(SelectedProcess->HandleCount)
                        : QString("Unavailable (error %1)")
                              .arg(SelectedProcess->HandleCountError));
      AddSummaryRow("Session", QString::number(SelectedProcess->SessionId));
      AddSummaryRow("Tool protection",
                    SelectedProcess->Protected ? "Yes" : "No");
      AddSummaryRow("PPL", SelectedProcess->Ppl
                               ? QString("Yes (0x%1)")
                                     .arg(SelectedProcess->PplRaw, 2, 16,
                                          QLatin1Char('0'))
                                     .toUpper()
                               : "No");
      AddSummaryRow("Critical", SelectedProcess->Critical ? "Yes" : "No");
      AddSummaryRow("Hidden", SelectedProcess->Hidden ? "Yes" : "No");
      AddSummaryRow("Enumeration", SelectedProcess->DriverData
                                       ? "Kernel driver"
                                       : "Toolhelp fallback");
    }
    auto *Token = AddTable("token", "Token", Fluent::IconType::CERTIFICATE,
                           {"Category", "Name", "SID", "Attributes"});
    auto *Threads =
        AddTable("threads", "Threads", Fluent::IconType::PEOPLE,
                 {"TID", "Start", "Priority", "State", "Wait", "CPU time",
                  "PreviousMode", "ApcQueueable"});
    Threads->setContextMenuPolicy(Qt::CustomContextMenu);
    Threads->setSelectionMode(QAbstractItemView::ExtendedSelection);
    Threads->setProperty("UseGenericDetailDialog", false);
    // Inspector 线程表行→(TID,PID,StartAddress) 映射，供右键菜单/双击复用。
    struct InspectorThreadRow {
      DWORD Tid = 0;
      DWORD ProcessId = 0;
      quint64 StartAddress = 0;
    };
    auto InspectThreadRows =
        std::make_shared<QVector<InspectorThreadRow>>();
    auto *Handles =
        AddTable("handles", "Handles", Fluent::IconType::LINK,
                 {"Handle", "Object", "Type", "Access", "Attributes"});
    Handles->setContextMenuPolicy(Qt::CustomContextMenu);
    Handles->setSelectionMode(QAbstractItemView::SingleSelection);
    auto *Modules = AddTable("modules", "Modules", Fluent::IconType::LIBRARY,
                             {"Name", "Base", "Size", "Path", "Source"});
    auto *Memory = AddTable("memory", "Memory", Fluent::IconType::TILES,
                            {"Base", "Size", "State", "Protect", "Type"});
    auto *Eprocess =
        AddTable("eprocess", "EPROCESS", Fluent::IconType::LAYOUT,
                 {"Member", "Value", "Raw / Notes"});
    auto *Mitigations =
        AddTable("mitigations", "Mitigations", Fluent::IconType::CERTIFICATE,
                 {"Property", "Value", "Source"});
    auto *PebText = new PlainTextEdit;
    PebText->setReadOnly(true);
    PebText->setFont(QFont("Cascadia Mono", 10));
    PebText->setPlaceholderText("PEB data is unavailable.");
    InstallFluentScrollBar(PebText, Qt::Vertical);
    Tabs->addTab("peb", "PEB", Fluent::IconType::CODE);
    Pages->addWidget(PebText);
    const std::array<QTableWidget *, 8> InspectorTables{
        Summary, Token, Threads, Handles, Modules, Memory, Eprocess,
        Mitigations};
    for (QTableWidget *Table : InspectorTables)
      Table->verticalHeader()->setDefaultSectionSize(KCompactTableRowHeight);
    const auto ApplyInspectorSearch = [InspectorSearch, Pages, PebText,
                                       InspectorTables] {
      const QString Query = InspectorSearch->text().trimmed();
      for (QTableWidget *Table : InspectorTables) {
        for (int Row = 0; Row < Table->rowCount(); ++Row) {
          QString RowText;
          for (int Column = 0; Column < Table->columnCount(); ++Column) {
            if (const QTableWidgetItem *Item = Table->item(Row, Column))
              RowText += Item->text() + QLatin1Char(' ');
          }
          Table->setRowHidden(
              Row, !Query.isEmpty() &&
                       !RowText.contains(Query, Qt::CaseInsensitive));
        }
      }
      if (Pages->currentWidget() == PebText && !Query.isEmpty()) {
        PebText->moveCursor(QTextCursor::Start);
        PebText->find(Query);
      }
    };
    QObject::connect(Tabs, &TabBar::currentChanged, Pages,
                     &QStackedWidget::setCurrentIndex);
    QObject::connect(Pages, &QStackedWidget::currentChanged, Tabs,
                     &TabBar::setCurrentIndex);
    QObject::connect(
        InspectorSearch, &QLineEdit::textChanged, Dialog,
        [ApplyInspectorSearch](const QString &) { ApplyInspectorSearch(); });
    QObject::connect(Pages, &QStackedWidget::currentChanged, Dialog,
                     [ApplyInspectorSearch](int) { ApplyInspectorSearch(); });
    QObject::connect(
        Threads, &QWidget::customContextMenuRequested, Dialog,
        [this, Threads, InspectThreadRows](const QPoint &Position) {
          const QModelIndex Index = Threads->indexAt(Position);
          if (!Index.isValid())
            return;
          if (Index.row() < 0 ||
              Index.row() >= static_cast<int>(InspectThreadRows->size()) ||
              !Threads->item(Index.row(), 0))
            return;
          if (!Threads->selectionModel()->isRowSelected(
                  Index.row(), QModelIndex())) {
            Threads->clearSelection();
            Threads->selectRow(Index.row());
          }
          // 复用主线程视图的共享操作菜单。
          const auto &Row = InspectThreadRows->at(Index.row());
          ShowThreadActionsMenu(Row.Tid, Row.ProcessId, Threads);
        });
    QObject::connect(
        Threads, &QTableWidget::cellDoubleClicked, Dialog,
        [this, Threads, InspectThreadRows](int Row, int) {
          if (Row < 0 || Row >= static_cast<int>(InspectThreadRows->size()) ||
              !Threads->item(Row, 0))
            return;
          const auto &Entry = InspectThreadRows->at(Row);
          // 优先使用全量线程缓存构造 ThreadRow，否则用记录字段构造临时行。
          if (const ThreadRow *Cached = FindThread(Entry.Tid)) {
            ShowThreadInspector(*Cached);
            return;
          }
          ThreadRow Temp;
          Temp.Tid = Entry.Tid;
          Temp.ProcessId = Entry.ProcessId;
          Temp.StartAddress = Entry.StartAddress;
          ShowThreadInspector(Temp);
        });
    QObject::connect(
        Handles, &QWidget::customContextMenuRequested, Dialog,
        [this, Dialog, Handles, Pid](const QPoint &Position) {
          const QModelIndex Index = Handles->indexAt(Position);
          if (!Index.isValid())
            return;
          Handles->selectRow(Index.row());
          const QTableWidgetItem *HandleItem = Handles->item(Index.row(), 0);
          const QTableWidgetItem *TypeItem = Handles->item(Index.row(), 2);
          if (!HandleItem)
            return;
          const ULONG HandleValue = HandleItem->data(Qt::UserRole).toUInt();
          const ULONG OwnerPid = HandleItem->data(Qt::UserRole + 1).toUInt();
          const ACCESS_MASK CurrentAccess = static_cast<ACCESS_MASK>(
              HandleItem->data(Qt::UserRole + 2).toUInt());
          const QString TypeName = TypeItem ? TypeItem->text() : QString();
          if (HandleValue == 0 || OwnerPid == 0)
            return;

          auto *Menu = new RoundMenu(QString(), Dialog);
          AddMenuAction(Menu, "ForceClose", [this, OwnerPid, HandleValue] {
            if (!ForceCloseHandleKernel(OwnerPid, HandleValue))
              ShowErrorNotice(this, "Handle",
                              QString("Force close failed (error %1).")
                                  .arg(G_LastAegisCoreError));
            else
              ShowSuccessNotice(this, "Handle",
                                QString("Handle 0x%1 closed.")
                                    .arg(HandleValue, 0, 16)
                                    .toUpper());
          });
          AddMenuAction(
              Menu, "Downgrade",
              [this, Dialog, OwnerPid, HandleValue, CurrentAccess, TypeName] {
                quint32 SelectedMask = CurrentAccess;
                if (!PromptHandleAccessMask(
                        Dialog, TypeName, CurrentAccess, SelectedMask,
                        "Downgrade Handle",
                        QString(
                            "Select the permissions to keep for handle 0x%1.")
                            .arg(HandleValue, 0, 16)
                            .toUpper(),
                        "Downgrade"))
                  return;
                ULONG NewHandleValue = 0;
                if (!DowngradeHandleKernel(
                        OwnerPid, HandleValue,
                        static_cast<ACCESS_MASK>(SelectedMask),
                        &NewHandleValue))
                  ShowErrorNotice(this, "Handle",
                                  QString("Downgrade failed (error %1).")
                                      .arg(G_LastAegisCoreError));
                else
                  ShowSuccessNotice(
                      this, "Handle",
                      QString("Handle downgraded. New handle: 0x%1")
                          .arg(NewHandleValue, 0, 16)
                          .toUpper());
              });
          AddMenuAction(
              Menu, "DuplicateAndDowngrade",
              [this, Dialog, OwnerPid, HandleValue, CurrentAccess, Pid,
               TypeName] {
                bool TargetOk = false;
                const QString TargetText =
                    QInputDialog::getText(Dialog, "Duplicate Handle",
                                          "Target PID:", QLineEdit::Normal,
                                          QString::number(Pid), &TargetOk);
                if (!TargetOk || TargetText.trimmed().isEmpty())
                  return;
                bool PidOk = false;
                const qulonglong TargetPidValue =
                    TargetText.trimmed().toULongLong(&PidOk, 0);
                if (!PidOk || TargetPidValue == 0 ||
                    TargetPidValue > std::numeric_limits<ULONG>::max()) {
                  ShowWarningNotice(this, "Handle",
                                    "Enter a valid target PID.");
                  return;
                }
                quint32 SelectedMask = CurrentAccess;
                if (!PromptHandleAccessMask(
                        Dialog, TypeName, CurrentAccess, SelectedMask,
                        "Duplicate Handle",
                        QString("Select the permissions for the duplicated "
                                "handle 0x%1 in PID %2.")
                            .arg(HandleValue, 0, 16)
                            .toUpper()
                            .arg(TargetPidValue),
                        "Duplicate"))
                  return;

                ULONG_PTR NewHandle = 0;
                if (!DuplicateAndDowngradeHandleKernel(
                        OwnerPid, HandleValue,
                        static_cast<ULONG>(TargetPidValue),
                        static_cast<ACCESS_MASK>(SelectedMask), &NewHandle))
                  ShowErrorNotice(this, "Handle",
                                  QString("Duplicate failed (error %1).")
                                      .arg(G_LastAegisCoreError));
                else
                  ShowSuccessNotice(
                      this, "Handle",
                      QString("Handle duplicated to PID %1 as 0x%2.")
                          .arg(TargetPidValue)
                          .arg(NewHandle, 0, 16)
                          .toUpper());
              });
          AddMenuAction(
              Menu, "CopyHandleInfo",
              [this, OwnerPid, HandleValue, TypeName, CurrentAccess] {
                const QString Text =
                    QString("PID=%1\nHandle=0x%2\nType=%3\nAccess=0x%4")
                        .arg(OwnerPid)
                        .arg(HandleValue, 0, 16)
                        .arg(TypeName)
                        .arg(CurrentAccess, 0, 16);
                qApp->clipboard()->setText(Text);
                ShowSuccessNotice(this, "Handle", "Handle information copied.");
              });
          AddMenuAction(
              Menu, "Open in Handle",
              [this, OwnerPid, HandleValue] {
                AegisNT::ApplicationContext().HandleLabPresetPid = OwnerPid;
                AegisNT::ApplicationContext().HandleLabPresetSearch =
                    QString("0x%1").arg(HandleValue, 0, 16).toUpper();
                ShowSuccessNotice(
                    this, "Handle",
                    "Handle preset prepared. Open Handle to inspect it.");
              });
          ReleaseMenuAfterClose(Menu);
          Menu->exec(Handles->viewport()->mapToGlobal(Position));
        });
    auto *ButtonRow = new QHBoxLayout;
    ButtonRow->setContentsMargins(0, 0, 0, 0);
    ButtonRow->addStretch(1);
    auto *RefreshButton = new PushButton("Refresh", Fluent::IconType::SYNC);
    auto *Close = new PushButton("Close", Fluent::IconType::ACCEPT);
    ButtonRow->addWidget(RefreshButton);
    ButtonRow->addWidget(Close);
    Layout->addLayout(ButtonRow);
    QObject::connect(Close, &QPushButton::clicked, Dialog, &QDialog::accept);
    ApplyDialogTheme(Dialog);
    Dialog->show();

    const bool HasSelectedProcess = SelectedProcess != nullptr;
    const int StaticSummaryRows = Summary->rowCount();
    QPointer<QDialog> SafeDialog(Dialog);
    auto RefreshBusy = std::make_shared<std::atomic_bool>(false);
    auto RefreshInspector = std::make_shared<std::function<void()>>();
    *RefreshInspector = [SafeDialog, Pid, Summary, Token, Threads, Handles,
                         Modules, Memory, Eprocess, Mitigations, PebText, Loading,
                         LoadStatus, InspectorSearch, HasSelectedProcess,
                         StaticSummaryRows, RefreshBusy, InspectThreadRows, this] {
      if (!SafeDialog || RefreshBusy->exchange(true))
        return;
      Loading->show();
      Loading->start();
      LoadStatus->setText("Refreshing process data...");
      std::thread([SafeDialog, Pid, Summary, Token, Threads, Handles, Modules,
                   Memory, Eprocess, Mitigations, PebText, Loading, LoadStatus,
                   InspectorSearch, HasSelectedProcess, StaticSummaryRows,
                   RefreshBusy, InspectThreadRows, this] {
        try {
        UserTokenInfo TokenInfo;
        const bool TokenOk = QueryUserTokenInfo(Pid, TokenInfo);
        std::vector<INVENTORY_RECORD> ProcessRows, EprocessRows, ThreadRows,
            HandleRows, ModuleRows, MemoryRows;
        std::vector<ToolModuleInfo> UserModuleRows;
        std::vector<MEMORY_BASIC_INFORMATION> UserMemoryRows;
        std::vector<InspectorHandleRow> UserHandleRows;
        INVENTORY_LIST_HEADER ProcessHeader{}, EprocessHeader{}, ThreadHeader{},
            HandleHeader{}, ModuleHeader{}, MemoryHeader{};
        DWORD UserHandleError = ERROR_SUCCESS;
        const bool KernelProcessOk = QueryProcessRecords(
            Pid, IOCTL_QUERY_PROCESS, ProcessRows, &ProcessHeader);
        const bool KernelEprocessOk = QueryProcessRecords(
            Pid, IOCTL_QUERY_EPROCESS, EprocessRows, &EprocessHeader);
        const bool KernelThreadOk = QueryProcessRecords(
            Pid, IOCTL_ENUM_THREADS, ThreadRows, &ThreadHeader);
        const bool KernelHandleOk = QueryProcessRecords(
            Pid, IOCTL_ENUM_HANDLES, HandleRows, &HandleHeader);
        const bool KernelModuleOk = QueryProcessRecords(
            Pid, IOCTL_ENUM_MODULES, ModuleRows, &ModuleHeader);
        const bool KernelMemoryOk = QueryProcessRecords(
            Pid, IOCTL_ENUM_MEMORY, MemoryRows, &MemoryHeader);
        if (!KernelModuleOk || ModuleRows.empty())
          ProcessPeb::ReadModuleList(Pid, UserModuleRows);
        if (!KernelMemoryOk || MemoryRows.empty()) {
          HANDLE Process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, Pid);
          if (Process != nullptr) {
            uintptr_t Address = 0;
            MEMORY_BASIC_INFORMATION Info{};
            while (VirtualQueryEx(Process, reinterpret_cast<LPCVOID>(Address),
                                  &Info, sizeof(Info)) == sizeof(Info)) {
              UserMemoryRows.push_back(Info);
              const uintptr_t Next = reinterpret_cast<uintptr_t>(Info.BaseAddress) +
                                     Info.RegionSize;
              if (Next <= Address || UserMemoryRows.size() >= 65536)
                break;
              Address = Next;
            }
            CloseHandle(Process);
          }
        }
        const bool UserHandleOk =
            (!KernelHandleOk || HandleRows.empty()) &&
            QueryUserModeHandles(Pid, UserHandleRows, UserHandleError);
        std::string PebOutput;
        ProcessPeb::ReadPebInfoText(Pid, PebOutput);

        std::vector<std::tuple<ULONG, ULONG64, QString>> MitigationEntries;
        const bool MitigationAttempted = [&] {
          BYTE MitBuf[4096] = {};
          ULONG MitReturned = 0;
          if (!QueryMitigationKernel(Pid, MitBuf, sizeof(MitBuf),
                                     &MitReturned) ||
              MitReturned < sizeof(ULONG) || MitReturned > sizeof(MitBuf))
            return false;
          PULONG Count = (PULONG)MitBuf;
          // 防止驱动侧返回损坏的 Count 导致越界读取。
          const ULONG MaxEntries = static_cast<ULONG>(
              (MitReturned - sizeof(ULONG)) / (4 + 8 + 64));
          const ULONG EntryCount = std::min(*Count, MaxEntries);
          PUCHAR Data = (PUCHAR)(Count + 1);
          for (ULONG i = 0; i < EntryCount; i++) {
            ULONG Id = *(PULONG)Data;
            Data += 4;
            ULONG64 Flags = *(ULONG64 *)Data;
            Data += 8;
            const WCHAR *NameData = reinterpret_cast<const WCHAR *>(Data);
            QString Name = QString::fromWCharArray(
                NameData, static_cast<int>(wcsnlen_s(NameData, 32)));
            Data += 64;
            MitigationEntries.emplace_back(Id, Flags, Name);
          }
          return true;
        }();

        QMetaObject::invokeMethod(
            qApp,
            [this, SafeDialog, Summary, Token, Threads, Handles, Modules, Memory,
             Eprocess, Mitigations, InspectorSearch, PebText, Loading, LoadStatus,
             InspectThreadRows,
             TokenInfo = std::move(TokenInfo), TokenOk,
             ProcessRows = std::move(ProcessRows),
             EprocessRows = std::move(EprocessRows),
             ThreadRows = std::move(ThreadRows),
             HandleRows = std::move(HandleRows),
             UserHandleRows = std::move(UserHandleRows),
             ModuleRows = std::move(ModuleRows),
             MemoryRows = std::move(MemoryRows), ProcessHeader, EprocessHeader,
             HandleHeader, ModuleHeader, MemoryHeader, UserHandleOk,
             UserHandleError,
             KernelProcessOk, KernelEprocessOk, KernelThreadOk, KernelHandleOk,
             KernelModuleOk, KernelMemoryOk,
             UserModuleRows = std::move(UserModuleRows),
             UserMemoryRows = std::move(UserMemoryRows),
             PebOutput = std::move(PebOutput), HasSelectedProcess,
             MitigationEntries = std::move(MitigationEntries),
             MitigationAttempted, Pid, StaticSummaryRows, RefreshBusy]() mutable {
              if (!SafeDialog) {
                RefreshBusy->store(false);
                return;
              }
              const auto FinishRefresh =
                  [SafeDialog, Summary, Token, Threads, Handles, Modules,
                   Memory, Eprocess, Mitigations, Loading, LoadStatus,
                   RefreshBusy](const QString &Status) {
                RefreshBusy->store(false);
                if (!SafeDialog)
                  return;
                for (QTableWidget *Table : {Summary, Token, Threads, Handles,
                                            Modules, Memory, Eprocess,
                                            Mitigations}) {
                  // 线程行映射依赖原始顺序，不启用排序。
                  if (Table != Threads)
                    Table->setSortingEnabled(true);
                  Table->setUpdatesEnabled(true);
                }
                Loading->stop();
                Loading->hide();
                LoadStatus->setText(Status);
              };
              try {
              for (QTableWidget *Table : {Summary, Token, Threads, Handles,
                                          Modules, Memory, Eprocess,
                                          Mitigations}) {
                Table->setUpdatesEnabled(false);
                Table->setSortingEnabled(false);
              }
              while (Summary->rowCount() > StaticSummaryRows)
                Summary->removeRow(Summary->rowCount() - 1);
              for (QTableWidget *Table :
                   {Token, Threads, Handles, Modules, Memory, Eprocess,
                    Mitigations})
                Table->setRowCount(0);
              // 先准备显示快照，再由有时间预算的定时器分批创建单元格。
              InspectorTableRows PreparedRows;
              const auto Add = [&PreparedRows](
                                   QTableWidget *Table,
                                   const QStringList &Values) {
                PreparedRows[Table].push_back({Values, {}});
              };
              // 每张表最多渲染 KMaxInspectorRows 行，避免巨型表阻塞 GUI 线程。
              constexpr size_t KMaxInspectorRows = 5000;
              const auto AddTruncatedNote =
                  [&Add](QTableWidget *Table, size_t Total, size_t Shown) {
                    if (Total > Shown)
                      Add(Table,
                          {"…",
                           QString("showing first %1 of %2")
                               .arg(Shown)
                               .arg(Total)});
                  };
              const auto SourceName = [](ULONG Source) {
                static const std::array<const char *, 10> Names{
                    "Unknown",        "Public API",      "System Info",
                    "Object Manager", "Registry",        "Process Environment",
                    "Memory Map",     "Version Profile", "Signature Scan",
                    "Cross-view"};
                return Source < Names.size()
                           ? QString::fromLatin1(Names[Source])
                           : QString("Source %1").arg(Source);
              };
              if (KernelProcessOk && !ProcessRows.empty()) {
                const auto &R = ProcessRows.front();
                const QString KernelParentPid =
                    QString::number(static_cast<quint32>(R.Value[0]));
                const QString KernelThreads =
                    QString::number(static_cast<quint32>(R.Value[1]));
                const QString KernelHandles =
                    QString::number(static_cast<quint32>(R.Value[2]));
                const QString KernelSession =
                    QString::number(static_cast<quint32>(R.Value[3]));
                if (!HasSelectedProcess) {
                  Add(Summary, {"Parent PID", KernelParentPid});
                  Add(Summary, {"Threads", KernelThreads});
                  Add(Summary, {"Handles", KernelHandles});
                  Add(Summary, {"Session", KernelSession});
                }
                Add(Summary, {"EPROCESS", FormatTaskPointer(R.Address)});
                if (R.Detail[0])
                  Add(Summary,
                      {"UniqueProcessKey", InspectorRecordText(R.Detail)});
                if (R.Value[4] != 0) {
                  LARGE_INTEGER CreateTime{};
                  CreateTime.QuadPart = static_cast<LONGLONG>(R.Value[4]);
                  Add(Summary, {"Create time", MonitorTimestamp(CreateTime)});
                }
                Add(Summary, {"User time", FormatProcessCpuTime(R.Value[5])});
                Add(Summary, {"Kernel time", FormatProcessCpuTime(R.Value[6])});
                Add(Summary, {"Working set", FormatBytes(R.SizeBytes)});
                Add(Summary, {"Private bytes", FormatBytes(R.Value[7])});
                if (R.Path[0])
                  Add(Summary, {"Path", InspectorRecordText(R.Path)});

              } else
                Add(Summary,
                    {"Kernel query",
                     QString("0x%1")
                         .arg(static_cast<quint32>(ProcessHeader.Status), 8, 16,
                              QLatin1Char('0'))
                         .toUpper()});
              if (KernelEprocessOk && !EprocessRows.empty()) {
                size_t AddedRows = 0;
                for (const auto &Row : EprocessRows) {
                  if (AddedRows >= KMaxInspectorRows)
                    break;
                  ++AddedRows;
                  const QString Member =
                      Row.Name[0] ? InspectorRecordText(Row.Name) : "-";
                  const QString Value =
                      Row.Path[0] ? InspectorRecordText(Row.Path) : "-";
                  QString Notes;
                  if (Row.Value[0] != 0)
                    Notes = QString("offset=0x%1")
                                .arg(Row.Value[0], 0, 16)
                                .toUpper();
                  if (Row.Detail[0]) {
                    const QString Detail = InspectorRecordText(Row.Detail);
                    Notes = Notes.isEmpty() ? Detail : Notes + " | " + Detail;
                  }
                  if (Row.Status != 0) {
                    const QString StatusText =
                        QString("status=0x%1")
                            .arg(static_cast<quint32>(Row.Status), 8, 16,
                                 QLatin1Char('0'))
                            .toUpper();
                    Notes = Notes.isEmpty() ? StatusText
                                            : Notes + " | " + StatusText;
                  }
                  Add(Eprocess, {Member, Value, Notes});
                }
                AddTruncatedNote(Eprocess, EprocessRows.size(), AddedRows);
              }
              if ((!KernelEprocessOk || EprocessRows.empty()) &&
                  PreparedRows[Eprocess].empty()) {
                Add(Eprocess,
                    {"Kernel query",
                     QString("0x%1")
                         .arg(static_cast<quint32>(EprocessHeader.Status), 8, 16,
                              QLatin1Char('0'))
                         .toUpper(),
                     "EPROCESS data unavailable"});
              }
              Add(Token,
                  {"User",
                   TokenOk ? TokenInfo.User
                           : QString("Unavailable (%1)").arg(TokenInfo.Error),
                   TokenInfo.UserSid,
                   TokenInfo.Elevated ? "Elevated" : "Not elevated"});
              Add(Token, {"Integrity", TokenInfo.Integrity, {}, {}});
              Add(Token, {"AppContainer",
                          TokenInfo.AppContainer ? "Yes" : "No",
                          TokenInfo.AppContainerSid,
                          {}});
              size_t TokenEntriesAdded = 0;
              for (const auto &Entry : TokenInfo.Entries) {
                if (TokenEntriesAdded >= KMaxInspectorRows)
                  break;
                Add(Token,
                    {Entry.Category, Entry.Name, Entry.Sid, Entry.Attributes});
                ++TokenEntriesAdded;
              }
              AddTruncatedNote(Token, TokenInfo.Entries.size(), TokenEntriesAdded);
              // 用全量线程缓存构建 TID 查找索引，供 PreviousMode / ApcQueueable 列使用。
              // GUI 线程上复制缓存，后续批次只使用准备好的显示值。
              const std::vector<ThreadRow> ThreadSnapshot = this->ThreadRows;
              QHash<DWORD, ThreadRow> ThreadCache;
              ThreadCache.reserve(static_cast<int>(ThreadSnapshot.size()));
              for (const ThreadRow &Tr : ThreadSnapshot)
                ThreadCache.insert(Tr.Tid, Tr);
              InspectThreadRows->clear();
              InspectThreadRows->reserve(
                  std::min<size_t>(ThreadRows.size(), KMaxInspectorRows));
              size_t AddedRows = 0;
              for (const auto &R : ThreadRows) {
                if (AddedRows >= KMaxInspectorRows)
                  break;
                ++AddedRows;
                const ThreadRow *Tr = nullptr;
                {
                  const auto It = ThreadCache.constFind(R.ThreadId);
                  if (It != ThreadCache.constEnd())
                    Tr = &(*It);
                }
                // Inspector 中："-" 表示全量线程缓存未命中；
                // "?" 表示 PreviousMode 驱动侧读取失败。
                const QString PrevMode =
                    Tr ? (Tr->PreviousMode == 1 ? "UserMode"
                                                : (Tr->PreviousMode == 0
                                                       ? "KernelMode"
                                                       : "?"))
                       : "-";
                const QString Apc =
                    Tr ? (Tr->ApcQueueable ? "Yes" : "No") : "-";
                Add(Threads,
                    {QString::number(R.ThreadId),
                     QString("0x%1").arg(R.Address, 0, 16).toUpper(),
                     QString::number(R.Value[0]),
                     QString::number(R.Value[2]),
                     QString::number(R.Value[3]),
                     QString::number(R.Value[6] + R.Value[7]),
                     PrevMode, Apc});
                PreparedRows[Threads].back().Roles[0] =
                    QVariant::fromValue<qulonglong>(R.ThreadId);
                InspectThreadRows->push_back(
                    {R.ThreadId, R.ProcessId, R.Address});
              }
              AddTruncatedNote(Threads, ThreadRows.size(), AddedRows);
              if (!ModuleRows.empty()) {
                size_t AddedRows = 0;
                for (const auto &R : ModuleRows) {
                  if (AddedRows >= KMaxInspectorRows)
                    break;
                  ++AddedRows;
                  Add(Modules,
                      {R.Name[0] ? InspectorRecordText(R.Name) : "-",
                       QString("0x%1").arg(R.Address, 0, 16).toUpper(),
                       FormatBytes(R.SizeBytes),
                       R.Path[0] ? InspectorRecordText(R.Path) : "-",
                       SourceName(R.Source)});
                }
                AddTruncatedNote(Modules, ModuleRows.size(), AddedRows);
              }
              if (PreparedRows[Modules].empty()) {
                size_t AddedRows = 0;
                for (const auto &R : UserModuleRows) {
                  if (AddedRows >= KMaxInspectorRows)
                    break;
                  ++AddedRows;
                  Add(Modules,
                      {Utf8Text(R.Name),
                       QString("0x%1").arg(R.BaseAddress, 0, 16).toUpper(),
                       FormatBytes(R.SizeOfImage), Utf8Text(R.FullPath),
                       "Toolhelp"});
                }
                AddTruncatedNote(Modules, UserModuleRows.size(), AddedRows);
              }
              if (PreparedRows[Modules].empty()) {
                Add(Modules, {"Unavailable", {}, {}, {},
                              QString("status=0x%1")
                                  .arg(static_cast<quint32>(ModuleHeader.Status),
                                       8, 16, QLatin1Char('0'))
                                  .toUpper()});
              }
              if (!MemoryRows.empty()) {
                size_t AddedRows = 0;
                for (const auto &R : MemoryRows) {
                  if (AddedRows >= KMaxInspectorRows)
                    break;
                  ++AddedRows;
                  Add(Memory,
                      {QString("0x%1").arg(R.Address, 0, 16).toUpper(),
                       FormatBytes(R.SizeBytes),
                       QString("0x%1").arg(R.Value[2], 0, 16).toUpper(),
                       QString("0x%1").arg(R.Value[3], 0, 16).toUpper(),
                       QString("0x%1").arg(R.Value[4], 0, 16).toUpper()});
                }
                AddTruncatedNote(Memory, MemoryRows.size(), AddedRows);
              }
              if (PreparedRows[Memory].empty()) {
                size_t AddedRows = 0;
                for (const auto &R : UserMemoryRows) {
                  if (AddedRows >= KMaxInspectorRows)
                    break;
                  ++AddedRows;
                  Add(Memory,
                      {QString("0x%1")
                           .arg(reinterpret_cast<quintptr>(R.BaseAddress), 0,
                                16)
                           .toUpper(),
                       FormatBytes(R.RegionSize),
                       QString("0x%1").arg(R.State, 0, 16).toUpper(),
                       QString("0x%1").arg(R.Protect, 0, 16).toUpper(),
                       QString("0x%1").arg(R.Type, 0, 16).toUpper()});
                }
                AddTruncatedNote(Memory, UserMemoryRows.size(), AddedRows);
              }
              if (PreparedRows[Memory].empty()) {
                Add(Memory, {"Unavailable", {}, {}, {},
                             QString("status=0x%1")
                                 .arg(static_cast<quint32>(MemoryHeader.Status),
                                      8, 16, QLatin1Char('0'))
                                 .toUpper()});
              }
              if (KernelHandleOk && HandleHeader.Status == 0) {
                size_t AddedRows = 0;
                for (const auto &R : HandleRows) {
                  if (AddedRows >= KMaxInspectorRows)
                    break;
                  ++AddedRows;
                  const QString ObjectText =
                      R.Path[0]
                          ? InspectorRecordText(R.Path)
                          : QString("0x%1").arg(R.Address, 0, 16).toUpper();
                  const QString TypeText =
                      R.TypeName[0]
                          ? InspectorRecordText(R.TypeName)
                          : (R.Detail[0] ? InspectorRecordText(R.Detail)
                                         : QString::number(R.Value[2]));
                  Add(Handles,
                      {QString("0x%1").arg(R.Value[0], 0, 16).toUpper(),
                       ObjectText, TypeText,
                       FormatHandleAccessDisplay(
                           TypeText, static_cast<quint32>(R.Value[1])),
                       QString("0x%1").arg(R.Value[3], 0, 16).toUpper()});
                  PreparedRows[Handles].back().Roles = {
                      QVariant::fromValue<quint32>(static_cast<quint32>(R.Value[0])),
                      QVariant::fromValue<quint32>(Pid),
                      QVariant::fromValue<quint32>(static_cast<quint32>(R.Value[1]))};
                }
                if (HandleRows.empty())
                  Add(Handles, {"No handles", {}, {}, {}, {}});
                else
                  AddTruncatedNote(Handles, HandleRows.size(), AddedRows);
                Add(Mitigations, {"Handle source", "Kernel driver",
                                  QString::number(HandleRows.size())});
              } else if (UserHandleOk && !UserHandleRows.empty()) {
                size_t AddedRows = 0;
                for (const auto &R : UserHandleRows) {
                  if (AddedRows >= KMaxInspectorRows)
                    break;
                  ++AddedRows;
                  Add(Handles,
                      {QString("0x%1").arg(R.HandleValue, 0, 16).toUpper(),
                       R.ObjectName.isEmpty() ? QString("0x%1")
                                                    .arg(R.ObjectAddress, 0, 16)
                                                    .toUpper()
                                              : R.ObjectName,
                       R.TypeName.isEmpty() ? "Unknown" : R.TypeName,
                       FormatHandleAccessDisplay(R.TypeName, R.GrantedAccess),
                       QString("0x%1").arg(R.Attributes, 0, 16).toUpper()});
                  PreparedRows[Handles].back().Roles = {
                      QVariant::fromValue<quint32>(static_cast<quint32>(R.HandleValue)),
                      QVariant::fromValue<quint32>(Pid),
                      QVariant::fromValue<quint32>(R.GrantedAccess)};
                }
                AddTruncatedNote(Handles, UserHandleRows.size(), AddedRows);
                Add(Mitigations,
                    {"Handle source", "User-mode fallback",
                     QString::number(UserHandleRows.size()) +
                         QString(" (kernel status 0x%1)")
                             .arg(static_cast<quint32>(HandleHeader.Status), 8,
                                  16, QLatin1Char('0'))
                             .toUpper()});
              } else {
                Add(Handles,
                    {"Unavailable",
                     {},
                     {},
                     {},
                     KernelHandleOk
                         ? QString("0x%1")
                               .arg(static_cast<quint32>(HandleHeader.Status),
                                    8, 16, QLatin1Char('0'))
                               .toUpper()
                         : QString("fallback error %1").arg(UserHandleError)});
              }
              Add(Mitigations, {"Kernel query", "Capability-dependent",
                                SourceName(ProcessHeader.Source)});

              if (!MitigationEntries.empty()) {
                for (const auto &[Id, Flags, Name] : MitigationEntries) {
                  QString FlagText =
                      QString("0x%1").arg(Flags, 16, 16, QLatin1Char('0'));
                  QString Status = (Flags & 1) ? "Enabled" : "Disabled";
                  Add(Mitigations, {Name, FlagText + " (" + Status + ")",
                                    QString("PID %1").arg(Pid)});
                }
              } else if (MitigationAttempted) {
                Add(Mitigations,
                    {"Mitigation query", "No data / unsupported", {}});
              }
              PebText->setPlainText(QString::fromStdString(PebOutput));
              if (!InspectorSearch->text().trimmed().isEmpty()) {
                PebText->moveCursor(QTextCursor::Start);
                PebText->find(InspectorSearch->text().trimmed());
              }
              const QString ResultStatus =
                  QString("%1 threads | %2 handles | %3 modules")
                      .arg(ThreadRows.size())
                      .arg(UserHandleOk && !UserHandleRows.empty()
                               ? UserHandleRows.size() : HandleRows.size())
                      .arg(ModuleRows.empty() ? UserModuleRows.size() : ModuleRows.size());
              LoadStatus->setText("Rendering process data...");
              PopulateInspectorTables(
                  SafeDialog, InspectorSearch, std::move(PreparedRows),
                  [FinishRefresh, ResultStatus](bool Success) {
                    FinishRefresh(Success ? ResultStatus : "Refresh failed");
                  });
              } catch (...) {
                FinishRefresh("Refresh failed");
              }
            },
            Qt::QueuedConnection);
        } catch (...) {
          // 任何异常（如 bad_alloc）都不允许终止进程；
          // 通知 GUI 结束加载状态并复位刷新锁。
          QMetaObject::invokeMethod(
              qApp,
              [SafeDialog, Loading, LoadStatus, RefreshBusy] {
                if (!SafeDialog)
                  return;
                Loading->stop();
                Loading->hide();
                LoadStatus->setText("Refresh failed");
                RefreshBusy->store(false);
              },
              Qt::QueuedConnection);
        }
      }).detach();
    };
    QObject::connect(RefreshButton, &QPushButton::clicked, Dialog,
                     [RefreshInspector] { (*RefreshInspector)(); });
    (*RefreshInspector)();
  }

  void ShowPebDetails(DWORD Pid) {
    std::string Output;
    if (!ProcessPeb::ReadPebInfoText(Pid, Output)) {
      ShowErrorNotice(this, "PEB", "Unable to read the target process.");
      return;
    }
    auto *Dialog = new QDialog(this);
    Dialog->setAttribute(Qt::WA_DeleteOnClose);
    Dialog->setWindowTitle("PEB");
    Dialog->resize(890, 650);
    auto *Layout = new QVBoxLayout(Dialog);
    auto *Details = new PlainTextEdit;
    Details->setReadOnly(true);
    Details->setFont(QFont("Cascadia Mono", 10));
    Details->setPlainText(Utf8Text(Output));
    InstallFluentScrollBar(Details, Qt::Vertical);
    Layout->addWidget(Details);
    auto *CloseButton = MakeButton("Close", true);
    Layout->addWidget(CloseButton, 0, Qt::AlignRight);
    QObject::connect(CloseButton, &QPushButton::clicked, Dialog,
                     &QDialog::accept);
    ApplyDialogTheme(Dialog);
    Dialog->show();
  }

  void ShowModuleList(DWORD Pid) {
    std::vector<ToolModuleInfo> Modules;
    if (!ProcessPeb::ReadModuleList(Pid, Modules)) {
      ShowErrorNotice(this, "ModuleList",
                      "Unable to enumerate target process modules.");
      return;
    }
    auto *Dialog = new QDialog(this);
    Dialog->setAttribute(Qt::WA_DeleteOnClose);
    Dialog->setWindowTitle(QString("ModuleList - PID %1").arg(Pid));
    Dialog->resize(1090, 680);
    auto *Layout = new QVBoxLayout(Dialog);
    auto *Toolbar = new QHBoxLayout;
    ConfigureToolbarLayout(Toolbar);
    auto *ModuleSearch = new SearchLineEdit;
    ModuleSearch->setPlaceholderText("Search module, address, size, or path");
    ModuleSearch->setClearButtonEnabled(true);
    ModuleSearch->setMaximumWidth(360);
    auto *ModuleCount =
        new BodyLabel(QString("%1 modules").arg(Modules.size()));
    Toolbar->addWidget(ModuleSearch, 1);
    Toolbar->addWidget(ModuleCount);
    Layout->addLayout(Toolbar);
    auto *Table = MakeTable({"Module", "Base address", "Image size", "Path"});
    Table->setSortingEnabled(true);
    Table->horizontalHeader()->setSectionResizeMode(
        0, QHeaderView::ResizeToContents);
    Table->horizontalHeader()->setSectionResizeMode(
        1, QHeaderView::ResizeToContents);
    Table->horizontalHeader()->setSectionResizeMode(
        2, QHeaderView::ResizeToContents);
    Table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    Table->setRowCount(static_cast<int>(Modules.size()));
    for (int Row = 0; Row < static_cast<int>(Modules.size()); ++Row) {
      const ToolModuleInfo &Module = Modules[Row];
      Table->setItem(Row, 0, new QTableWidgetItem(Utf8Text(Module.Name)));
      Table->setItem(Row, 1,
                     new QTableWidgetItem(QString("0x%1")
                                              .arg(Module.BaseAddress,
                                                   sizeof(uintptr_t) * 2, 16,
                                                   QLatin1Char('0'))
                                              .toUpper()));
      Table->setItem(Row, 2,
                     new QTableWidgetItem(QString("%1 bytes (0x%2)")
                                              .arg(Module.SizeOfImage)
                                              .arg(Module.SizeOfImage, 0, 16)
                                              .toUpper()));
      Table->setItem(Row, 3, new QTableWidgetItem(Utf8Text(Module.FullPath)));
      Table->setRowHeight(Row, KCompactTableRowHeight);
    }
    Layout->addWidget(Table, 1);
    QObject::connect(
        ModuleSearch, &QLineEdit::textChanged, Dialog,
        [Table, ModuleCount](const QString &Text) {
          const QString Query = Text.trimmed();
          int VisibleCount = 0;
          for (int Row = 0; Row < Table->rowCount(); ++Row) {
            QString RowText;
            for (int Column = 0; Column < Table->columnCount(); ++Column) {
              if (const QTableWidgetItem *Item = Table->item(Row, Column))
                RowText += Item->text() + QLatin1Char(' ');
            }
            const bool Visible =
                Query.isEmpty() || RowText.contains(Query, Qt::CaseInsensitive);
            Table->setRowHidden(Row, !Visible);
            if (Visible)
              ++VisibleCount;
          }
          ModuleCount->setText(
              Query.isEmpty() ? QString("%1 modules").arg(Table->rowCount())
                              : QString("%1 of %2 modules")
                                    .arg(VisibleCount)
                                    .arg(Table->rowCount()));
        });
    auto *CloseButton = MakeButton("Close", true);
    Layout->addWidget(CloseButton, 0, Qt::AlignRight);
    QObject::connect(CloseButton, &QPushButton::clicked, Dialog,
                     &QDialog::accept);
    ApplyDialogTheme(Dialog);
    Dialog->show();
  }

  void ShowInjectDllDialog(DWORD Pid) {
    auto *Dialog = new MessageBoxBase(window());
    Dialog->viewLayout()->setContentsMargins(28, 26, 28, 32);
    Dialog->setAttribute(Qt::WA_DeleteOnClose);
    Dialog->setModal(true);
    auto *Title = MakeLabel("InjectDLL", 18, KTextPrimary, QFont::DemiBold);
    auto *Description = MakeLabel(
        QString("Select a DLL and injection method for PID %1.").arg(Pid), 11,
        KTextMuted);
    auto *PathLabel = MakeLabel("DLL path", 11, KTextPrimary, QFont::DemiBold);
    auto *PathLayout = new QHBoxLayout;
    auto *PathEdit = new LineEdit;
    PathEdit->setPlaceholderText("Select a DLL file");
    auto *BrowseButton = MakeButton("Browse");
    PathLayout->addWidget(PathEdit, 1);
    PathLayout->addWidget(BrowseButton);
    auto *MethodLabel =
        MakeLabel("Injection method", 11, KTextPrimary, QFont::DemiBold);
    auto *Method = new ComboBox;
    Method->addItems({"R3CreateRemoteThread", "R3NtCreateThreadEx",
                      "R3QueueUserAPC", "R3SetWindowsHookEx", 
                      "R3ThreadHijackFallback", "R3ReflectiveInject", 
                      "R0DllInjectApc",
                      "R0DllInjectThread"});
    Method->setCurrentIndex(0);
    Dialog->viewLayout()->addWidget(Title);
    Dialog->viewLayout()->addWidget(Description);
    Dialog->viewLayout()->addSpacing(8);
    Dialog->viewLayout()->addWidget(PathLabel);
    Dialog->viewLayout()->addLayout(PathLayout);
    Dialog->viewLayout()->addWidget(MethodLabel);
    Dialog->viewLayout()->addWidget(Method);
    Dialog->yesButton()->setText("Inject");
    Dialog->cancelButton()->setText("Cancel");
    QObject::connect(
        BrowseButton, &QPushButton::clicked, Dialog, [Dialog, PathEdit] {
          QFileDialog FileDialog(Dialog, "Select DLL", PathEdit->text(),
                                  "DLL files (*.dll);;All files (*.*)");
          FileDialog.setFileMode(QFileDialog::ExistingFile);
          FileDialog.setAcceptMode(QFileDialog::AcceptOpen);
          FileDialog.setWindowModality(Qt::WindowModal);
          if (FileDialog.exec() == QDialog::Accepted &&
              !FileDialog.selectedFiles().isEmpty())
            PathEdit->setText(
                QDir::toNativeSeparators(FileDialog.selectedFiles().constFirst()));
        });
    QObject::connect(
        Dialog->yesButton(), &QPushButton::clicked, Dialog,
        [this, Dialog, PathEdit, Method, Pid] {
          const QString Path = PathEdit->text().trimmed();
          if (Path.isEmpty() || !QFileInfo::exists(Path)) {
            ShowWarningNotice(this, "InjectDLL",
                              "Select an existing DLL file.");
            return;
          }
          EnableDebugPrivilege();
          const std::wstring WidePath =
              QDir::toNativeSeparators(Path).toStdWString();
          BOOL Result = FALSE;
          QString MethodName = Method->currentText();
          switch (Method->currentIndex()) {
          case 0:
            Result = Inject_RemoteThread(Pid, WidePath);
            break;
          case 1:
            Result = Inject_NtCreateThreadEx(Pid, WidePath);
            break;
          case 2:
            Result = Inject_QueueUserAPC(Pid, WidePath);
            break;
          case 3:
            Result = Inject_SetWindowsHookEx(Pid, WidePath);
            break;
          case 4:
              Result = Inject_QueueUserAPC(Pid, WidePath);
              break;
          case 5:
              Result = Inject_Reflective(Pid, WidePath);
              break;
          case 6:
            Result = DllInjectApc(Pid, WidePath.c_str());
            break;
          case 7:
            Result = DllInjectThread(Pid, WidePath.c_str());
            break;
          default:
            break;
          }
          Dialog->accept();
          if (!Result) {
            AppendConsoleOutput(
                QString("[!] DLL injection failed.\n"
                        "    PID: %1\n"
                        "    Method: %2\n"
                        "    DLL: %3\n"
                        "    %4\n")
                    .arg(Pid)
                    .arg(MethodName)
                    .arg(QDir::toNativeSeparators(Path))
                    .arg(DescribeWin32ErrorMessage(G_LastAegisCoreError)
                             .replace('\n', "\n    ")));
            ShowErrorNotice(this, "InjectDLL",
                            "DLL injection failed. See Console for details.",
                            false);
          } else {
            AppendConsoleOutput(QString("[+] DLL injection started.\n"
                                        "    PID: %1\n"
                                        "    Method: %2\n"
                                        "    DLL: %3\n")
                                    .arg(Pid)
                                    .arg(MethodName)
                                    .arg(QDir::toNativeSeparators(Path)));
            ShowSuccessNotice(this, "InjectDLL",
                              "DLL injection started successfully.");
          }
        });
    QObject::connect(Dialog->cancelButton(), &QPushButton::clicked, Dialog,
                     &QDialog::reject);
    Dialog->show();
  }

  SearchLineEdit *SearchEdit = nullptr;
  QTimer *SearchDebounceTimer = nullptr;
  QTimer *AutoRefreshTimer = nullptr;
  BodyLabel *StatusLabel = nullptr;
  PushButton *RefreshButton = nullptr;
  IndeterminateProgressRing *RefreshIndicator = nullptr;
  TableWidget *ProcessTable = nullptr;
  int ActiveInspectorDialogs = 0;
  bool ProcessTablePopulatePending = false;
  std::vector<ProcessRow> Rows;
  std::map<DWORD, ProcessRow> RetainedProcesses;
  QSet<DWORD> ProtectedPids;
  std::atomic_bool Refreshing = false;
  bool RefreshPending = false;
  bool Rendering = false;
  quint64 TableRenderGeneration = 0;
  TableRenderState RenderState;
  // 线程分视图成员。
  TableWidget *ThreadTable = nullptr;
  ComboBox *ViewCombo = nullptr;
  std::vector<ThreadRow> ThreadRows;
  QVector<DWORD> RowTids;
  std::atomic_bool ThreadsRefreshing = false;

protected:
  void showEvent(QShowEvent *Event) override {
    QWidget::showEvent(Event);
    if (AutoRefreshTimer)
      AutoRefreshTimer->start(10000);
    // 页面显示时按当前视图刷新。
    if (ViewCombo && ViewCombo->currentIndex() == 1)
      RefreshThreads();
    else
      RefreshProcesses();
  }

  void hideEvent(QHideEvent *Event) override {
    if (AutoRefreshTimer)
      AutoRefreshTimer->stop();
    QWidget::hideEvent(Event);
  }
};
