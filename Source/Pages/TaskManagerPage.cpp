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
    SearchEdit = new SearchLineEdit;
    SearchEdit->setPlaceholderText("Search by name, PID, or user");
    SearchEdit->setClearButtonEnabled(true);
    SearchEdit->setMaximumWidth(320);
    StatusLabel = new BodyLabel("Ready");
    RefreshIndicator = new IndeterminateProgressRing(this, false);
    RefreshIndicator->setFixedSize(22, 22);
    RefreshIndicator->hide();
    auto *RunButton = MakeButton("Run");
    RefreshButton = MakeButton("Refresh", true);
    Toolbar->addWidget(SearchEdit);
    Toolbar->addWidget(StatusLabel, 1);
    Toolbar->addWidget(RefreshIndicator, 0, Qt::AlignVCenter);
    Toolbar->addWidget(RunButton);
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

    SearchDebounceTimer = new QTimer(this);
    SearchDebounceTimer->setSingleShot(true);
    SearchDebounceTimer->setInterval(KSearchDebounceMs);
    QObject::connect(SearchDebounceTimer, &QTimer::timeout, this,
                     [this] { PopulateTable(); });
    QObject::connect(SearchEdit, &QLineEdit::textChanged, this,
                     [this] { SearchDebounceTimer->start(); });
    QObject::connect(RunButton, &QPushButton::clicked, this,
                     [this] { ShowLaunchAsDialog(this); });
    QObject::connect(RefreshButton, &QPushButton::clicked, this, [this] {
      RefreshProcesses();
      ShowSuccessNotice(this, "Task", "Process refresh started.");
    });
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
      if (isVisible())
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
          const bool QueryName =
              Row.TypeName.compare("File", Qt::CaseInsensitive) == 0 ||
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
            std::vector<WCHAR> ImagePath(32768);
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
    QHash<DWORD, int> ExistingRows;
    ExistingRows.reserve(ProcessTable->rowCount());
    for (int Row = 0; Row < ProcessTable->rowCount(); ++Row) {
      if (const QTableWidgetItem *Item = ProcessTable->item(Row, 0))
        ExistingRows.insert(Item->data(Qt::UserRole).toUInt(), Row);
    }
    for (int Row = ProcessTable->rowCount() - 1; Row >= 0; --Row) {
      const QTableWidgetItem *Item = ProcessTable->item(Row, 0);
      const DWORD Pid = Item ? Item->data(Qt::UserRole).toUInt() : 0;
      const auto Match = std::find_if(
          NextState.VisibleRows.begin(), NextState.VisibleRows.end(),
          [Pid](const ProcessRow &Process) { return Process.Pid == Pid; });
      if (Pid == 0 || Match == NextState.VisibleRows.end()) {
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

  int FindProcessTableRow(DWORD Pid) const {
    for (int Row = 0; Row < ProcessTable->rowCount(); ++Row) {
      const QTableWidgetItem *Item = ProcessTable->item(Row, 0);
      if (Item && Item->data(Qt::UserRole).toUInt() == Pid)
        return Row;
    }
    return -1;
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
        const int Row = FindProcessTableRow(Operation.Pid);
        if (Row >= 0)
          ProcessTable->removeRow(Row);
      } else {
        int Row = FindProcessTableRow(Operation.Pid);
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

  bool ConfirmDangerous(const QString &Title, const QString &Text) {
    return QMessageBox::warning(this, Title, Text,
                                QMessageBox::Yes | QMessageBox::No,
                                QMessageBox::No) == QMessageBox::Yes;
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
    AddMenuAction(Menu, "Terminate",
                  [this, SelectedPids] { ShowTerminateDialog(SelectedPids); });

    auto *PplMenu = new RoundMenu("PPL", Menu);
    AddMenuAction(PplMenu, "RemovePPL", [this, SelectedPids] {
      for (DWORD SelectedPid : SelectedPids)
        RemovePpl(SelectedPid);
      ReportDriverResult("RemovePPL");
    });
    AddMenuAction(PplMenu, "SetPPL", [this, Pid] { ConfigurePpl(Pid); });
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
    AddMenuAction(CriticalMenu, "SetCritical", [this, Pid, Name] {
      if (!ConfirmDangerous("SetCritical",
                            QString("Mark %1 (PID %2) critical? Terminating it "
                                    "may crash Windows.")
                                .arg(Name)
                                .arg(Pid)))
        return;
      SetCritical(Pid);
      ReportDriverResult("SetCritical");
    });
    AddMenuAction(CriticalMenu, "UnsetCritical", [this, SelectedPids] {
      for (DWORD SelectedPid : SelectedPids)
        RemoveCritical(SelectedPid);
      ReportDriverResult("UnsetCritical");
    });
    Menu->addMenu(CriticalMenu);

    auto *HideMenu = new RoundMenu("Hide", Menu);
    AddMenuAction(HideMenu, "Hide", [this, Pid] {
      const ProcessRow *Current = FindProcess(Pid);
      const std::optional<ProcessRow> Cached =
          Current ? std::optional<ProcessRow>(*Current) : std::nullopt;
      HideProcess(Pid);
      if (G_LastAegisCoreError == ERROR_SUCCESS && Cached) {
        ProcessRow Retained = *Cached;
        Retained.Hidden = true;
        RetainedProcesses[Pid] = Retained;
        for (ProcessRow &Row : Rows) {
          if (Row.Pid == Pid)
            Row.Hidden = true;
        }
        SortProcessRows(Rows);
        PopulateTable();
      }
      ReportDriverResult("Hide");
    });
    AddMenuAction(HideMenu, "Unhide", [this, Pid] {
      const ProcessRow *Current = FindProcess(Pid);
      const std::optional<ProcessRow> Cached =
          Current ? std::optional<ProcessRow>(*Current) : std::nullopt;
      UnhideProcess(Pid);
      if (G_LastAegisCoreError == ERROR_SUCCESS && Cached) {
        ProcessRow Retained = *Cached;
        Retained.Hidden = false;
        RetainedProcesses[Pid] = Retained;
        for (ProcessRow &Row : Rows) {
          if (Row.Pid == Pid)
            Row.Hidden = false;
        }
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

    ReleaseMenuAfterClose(Menu);
    Menu->exec(ProcessTable->viewport()->mapToGlobal(Position));
  }

  void ShowChoiceDialog(const QString &TitleText,
                        const QString &DescriptionText,
                        const QStringList &Choices,
                        std::function<void(int)> Handler,
                        QWidget *ParentWindow = nullptr) {
    auto *Dialog = new MessageBoxBase(ParentWindow ? ParentWindow : window());
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
        {"R0ZwTerminateProcess", "R3PatchThreadRun", "R3NtTerminate",
         "R3KillProcessForce", "R3RunInjectProc"},
        [this, Pids](int Index) {
          int SuccessCount = 0;
          for (const DWORD Pid : Pids) {
            bool Success = false;
            switch (Index) {
            case 0:
              KillProcess(Pid);
              Success = G_LastAegisCoreError == ERROR_SUCCESS;
              break;
            case 1:
              PatchThreadRun(Pid);
              Success = true;
              break;
            case 2:
              Success = NtTerminate(Pid);
              break;
            case 3:
              Success = KillProcessForce(Pid);
              break;
            case 4:
              Success = RunInjectProc(Pid);
              break;
            default:
              return;
            }
            if (Success)
              ++SuccessCount;
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
    ShowChoiceDialog(
        "Terminate",
        QString(
            "Select how to terminate %1 (PID %2). This may cause data loss.")
            .arg(Name)
            .arg(Pid),
        {"R0ZwTerminateProcess", "R3PatchThreadRun", "R3NtTerminate",
         "R3KillProcessForce", "R3RunInjectProc"},
        [this, Pid](int Index) {
          switch (Index) {
          case 0:
            KillProcess(Pid);
            ReportDriverResult("Terminate");
            return;
          case 1:
            PatchThreadRun(Pid);
            ShowSuccessNotice(this, "Terminate",
                              "Thread execution patch requested.");
            break;
          case 2:
            if (!NtTerminate(Pid))
              ShowErrorNotice(this, "Terminate", "NtTerminateProcess failed.");
            else
              ShowSuccessNotice(this, "Terminate", "Process terminated.");
            break;
          case 3:
            if (!KillProcessForce(Pid))
              ShowErrorNotice(this, "Terminate", "Thread termination failed.");
            else
              ShowSuccessNotice(this, "Terminate",
                                "Process threads terminated.");
            break;
          case 4:
            if (!RunInjectProc(Pid))
              ShowErrorNotice(this, "Terminate", "Remote ExitProcess failed.");
            else
              ShowSuccessNotice(this, "Terminate",
                                "Remote ExitProcess completed.");
            break;
          default:
            return;
          }
          QTimer::singleShot(0, this, [this] { RefreshProcesses(); });
        });
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
    Dialog->resize(420, 220);

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

  void ConfigurePpl(DWORD Pid) {
    auto *Dialog = new MessageBoxBase(window());
    Dialog->setAttribute(Qt::WA_DeleteOnClose);
    auto *Title = MakeLabel("SetPPL", 18, KTextPrimary, QFont::DemiBold);
    auto *Description = MakeLabel(
        QString("Configure protected process light settings for PID %1.")
            .arg(Pid),
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
                     [this, Dialog, Type, Signer, Audit, Pid] {
                       SetPpl(Pid, static_cast<UCHAR>(Type->currentIndex()),
                              static_cast<UCHAR>(Signer->currentIndex()),
                              Audit->currentIndex() == 1);
                       Dialog->accept();
                       ReportDriverResult("SetPPL");
                     });
    QObject::connect(Dialog->cancelButton(), &QPushButton::clicked, Dialog,
                     &QDialog::reject);
    Dialog->show();
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
    Dialog->resize(1120, 760);
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
                 {"TID", "Start", "Priority", "State", "Wait", "CPU time"});
    Threads->setContextMenuPolicy(Qt::CustomContextMenu);
    Threads->setSelectionMode(QAbstractItemView::ExtendedSelection);
    Threads->setProperty("UseGenericDetailDialog", false);
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
        [this, Dialog, Threads, Pid](const QPoint &Position) {
          const QModelIndex Index = Threads->indexAt(Position);
          if (!Index.isValid())
            return;
          if (!Threads->selectionModel()->isRowSelected(Index.row(),
                                                        QModelIndex())) {
            Threads->clearSelection();
            Threads->selectRow(Index.row());
          }
          const QTableWidgetItem *TidItem = Threads->item(Index.row(), 0);
          if (!TidItem)
            return;
          const DWORD Tid = TidItem->data(Qt::UserRole).toUInt();
          if (Tid == 0)
            return;
          std::vector<DWORD> SelectedTids;
          for (const QModelIndex &Selected :
               Threads->selectionModel()->selectedRows(0)) {
            const QTableWidgetItem *Item = Threads->item(Selected.row(), 0);
            if (Item && Item->data(Qt::UserRole).toUInt() != 0)
              SelectedTids.push_back(Item->data(Qt::UserRole).toUInt());
          }
          if (SelectedTids.empty())
            return;

          auto *Menu = new RoundMenu(QString(), Dialog);
          AddMenuAction(
              Menu, "Terminate", [this, Dialog, Threads, Pid, SelectedTids] {
                if (Pid == GetCurrentProcessId()) {
                  ShowWarningNotice(this, "Terminate thread",
                                    "Thread operations on AegisNT itself "
                                    "are disabled.");
                  return;
                }
                QPointer<QTableWidget> SafeThreads(Threads);
                ShowChoiceDialog(
                    "Terminate thread",
                    QString(
                        "Select how to terminate %1 selected thread(s). "
                        "Terminating threads can destabilize their process.")
                        .arg(SelectedTids.size()),
                    {"R3 (Win32 API)", "R0 (AegisCore)"},
                    [this, SafeThreads, SelectedTids, Pid](int Method) {
                      int SuccessCount = 0;
                      DWORD LastErrorCode = ERROR_SUCCESS;
                      QString Mode;
                      for (const DWORD SelectedTid : SelectedTids) {
                        bool Success = false;
                        if (Method == 0) {
                          Mode = "R3";
                          EnableDebugPrivilege();
                          HANDLE Thread =
                              OpenThread(THREAD_TERMINATE, FALSE, SelectedTid);
                          if (Thread) {
                            if (::TerminateThread(Thread, 0) != FALSE) {
                              const DWORD WaitResult =
                                  WaitForSingleObject(Thread, 500);
                              if (WaitResult == WAIT_OBJECT_0) {
                                DWORD ExitCode = STILL_ACTIVE;
                                if (GetExitCodeThread(Thread, &ExitCode) &&
                                    ExitCode != STILL_ACTIVE) {
                                  Success = true;
                                } else {
                                  LastErrorCode = ERROR_GEN_FAILURE;
                                }
                              } else if (WaitResult == WAIT_TIMEOUT) {
                                LastErrorCode = WAIT_TIMEOUT;
                              } else {
                                LastErrorCode = GetLastError();
                              }
                            } else {
                              LastErrorCode = GetLastError();
                            }
                            CloseHandle(Thread);
                          } else {
                            LastErrorCode = GetLastError();
                          }
                        } else {
                          Mode = "R0";
                          Success = KillThread(SelectedTid, Pid) != FALSE;
                          if (!Success)
                            LastErrorCode = G_LastAegisCoreError;
                        }
                        if (Success) {
                          ++SuccessCount;
                          if (SafeThreads) {
                            for (int Row = 0; Row < SafeThreads->rowCount();
                                 ++Row) {
                              const QTableWidgetItem *Item =
                                  SafeThreads->item(Row, 0);
                              if (Item && Item->data(Qt::UserRole).toUInt() ==
                                              SelectedTid) {
                                SafeThreads->removeRow(Row);
                                break;
                              }
                            }
                          }
                        }
                      }
                      if (SuccessCount == 0)
                        ShowErrorNotice(
                            this, "Terminate thread",
                            QString("%1 termination failed (error %2).")
                                .arg(Mode)
                                .arg(LastErrorCode));
                      else
                        ShowSuccessNotice(
                            this, "Terminate thread",
                            QString("%1 of %2 thread(s) processed through %3.")
                                .arg(SuccessCount)
                                .arg(SelectedTids.size())
                                .arg(Mode));
                    },
                    Dialog);
              });

          const auto ChangeSuspendState = [this, Pid,
                                           SelectedTids](bool Suspend) {
            if (Pid == GetCurrentProcessId()) {
              ShowWarningNotice(
                  this, Suspend ? "Suspend thread" : "Resume thread",
                  "Thread operations on AegisNT itself are disabled.");
              return;
            }
            EnableDebugPrivilege();
            int SuccessCount = 0;
            DWORD LastErrorCode = ERROR_SUCCESS;
            for (const DWORD SelectedTid : SelectedTids) {
              HANDLE Thread =
                  OpenThread(THREAD_SUSPEND_RESUME, FALSE, SelectedTid);
              if (!Thread) {
                LastErrorCode = GetLastError();
                continue;
              }
              const DWORD PreviousCount =
                  Suspend ? ::SuspendThread(Thread) : ::ResumeThread(Thread);
              if (PreviousCount != static_cast<DWORD>(-1))
                ++SuccessCount;
              else
                LastErrorCode = GetLastError();
              CloseHandle(Thread);
            }
            if (SuccessCount == 0) {
              ShowErrorNotice(
                  this, Suspend ? "Suspend thread" : "Resume thread",
                  QString("Operation failed (error %1).").arg(LastErrorCode));
              return;
            }
            ShowSuccessNotice(this,
                              Suspend ? "Suspend thread" : "Resume thread",
                              QString("%1 of %2 selected thread(s) updated.")
                                  .arg(SuccessCount)
                                  .arg(SelectedTids.size()));
          };
          AddMenuAction(Menu, "Suspend",
                        [ChangeSuspendState] { ChangeSuspendState(true); });
          AddMenuAction(Menu, "Resume",
                        [ChangeSuspendState] { ChangeSuspendState(false); });

          auto *ThreadKernelMenu = new RoundMenu("Kernel", Menu);
          AddMenuAction(ThreadKernelMenu, "HijackContext",
                        [this, Pid, SelectedTids] {
                          ShowThreadHijackDialog(Pid, SelectedTids, false,
                                                 "HijackContext");
                        });
          AddMenuAction(ThreadKernelMenu, "HijackTrapFrame",
                        [this, Pid, SelectedTids] {
                          ShowThreadHijackDialog(Pid, SelectedTids, true,
                                                 "HijackTrapFrame");
                        });
          AddMenuAction(ThreadKernelMenu, "RemoteCall",
                        [this, Pid, SelectedTids] {
                          ShowRemoteCallDialog(Pid, SelectedTids);
                        });
          AddMenuAction(ThreadKernelMenu, "InjectAndHijack",
                        [this, Pid, SelectedTids] {
                          ShowInjectAndHijackDialog(Pid, SelectedTids);
                        });
          Menu->addMenu(ThreadKernelMenu);
          ReleaseMenuAfterClose(Menu);
          Menu->exec(Threads->viewport()->mapToGlobal(Position));
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
    auto *Close = new PushButton("Close", Fluent::IconType::ACCEPT);
    Layout->addWidget(Close, 0, Qt::AlignRight);
    QObject::connect(Close, &QPushButton::clicked, Dialog, &QDialog::accept);
    Dialog->show();

    const bool HasSelectedProcess = SelectedProcess != nullptr;
    const int StaticSummaryRows = Summary->rowCount();
    QPointer<QDialog> SafeDialog(Dialog);
    auto RefreshBusy = std::make_shared<std::atomic_bool>(false);
    auto RefreshInspector = std::make_shared<std::function<void()>>();
    *RefreshInspector = [SafeDialog, Pid, Summary, Token, Threads, Handles,
                         Modules, Memory, Eprocess, Mitigations, PebText, Loading,
                         LoadStatus, InspectorSearch, HasSelectedProcess,
                         StaticSummaryRows, RefreshBusy] {
      if (!SafeDialog || RefreshBusy->exchange(true))
        return;
      Loading->show();
      Loading->start();
      LoadStatus->setText("Refreshing process data...");
      std::thread([SafeDialog, Pid, Summary, Token, Threads, Handles, Modules,
                   Memory, Eprocess, Mitigations, PebText, Loading, LoadStatus,
                   InspectorSearch, HasSelectedProcess, StaticSummaryRows,
                   RefreshBusy] {
        UserTokenInfo TokenInfo;
        const bool TokenOk = QueryUserTokenInfo(Pid, TokenInfo);
        std::vector<MDV2_RECORD> ProcessRows, EprocessRows, ThreadRows,
            HandleRows, ModuleRows, MemoryRows;
        std::vector<ToolModuleInfo> UserModuleRows;
        std::vector<MEMORY_BASIC_INFORMATION> UserMemoryRows;
        std::vector<InspectorHandleRow> UserHandleRows;
        MDV2_LIST_HEADER ProcessHeader{}, EprocessHeader{}, ThreadHeader{},
            HandleHeader{}, ModuleHeader{}, MemoryHeader{};
        DWORD UserHandleError = ERROR_SUCCESS;
        const bool KernelProcessOk = QueryProcessRecordsV2(
            Pid, IOCTL_QUERY_PROCESS_V2, ProcessRows, &ProcessHeader);
        const bool KernelEprocessOk = QueryProcessRecordsV2(
            Pid, IOCTL_QUERY_EPROCESS_V2, EprocessRows, &EprocessHeader);
        const bool KernelThreadOk = QueryProcessRecordsV2(
            Pid, IOCTL_ENUM_THREADS_V2, ThreadRows, &ThreadHeader);
        const bool KernelHandleOk = QueryProcessRecordsV2(
            Pid, IOCTL_ENUM_HANDLES_V2, HandleRows, &HandleHeader);
        const bool KernelModuleOk = QueryProcessRecordsV2(
            Pid, IOCTL_ENUM_MODULES_V2, ModuleRows, &ModuleHeader);
        const bool KernelMemoryOk = QueryProcessRecordsV2(
            Pid, IOCTL_ENUM_MEMORY_V2, MemoryRows, &MemoryHeader);
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
            QueryUserModeHandles(Pid, UserHandleRows, UserHandleError);
        std::string PebOutput;
        ProcessPeb::ReadPebInfoText(Pid, PebOutput);

        std::vector<std::tuple<ULONG, ULONG64, QString>> MitigationEntries;
        if (G_DeviceHandle != INVALID_HANDLE_VALUE) {
          BYTE MitBuf[4096] = {};
          ULONG MitReturned = 0;
          if (QueryMitigationKernel(Pid, MitBuf, sizeof(MitBuf),
                                    &MitReturned) &&
              MitReturned >= sizeof(ULONG)) {
            PULONG Count = (PULONG)MitBuf;
            PUCHAR Data = (PUCHAR)(Count + 1);
            for (ULONG i = 0; i < *Count; i++) {
              ULONG Id = *(PULONG)Data;
              Data += 4;
              ULONG64 Flags = *(ULONG64 *)Data;
              Data += 8;
              QString Name = QString::fromWCharArray((PWCHAR)Data);
              Data += 64;
              MitigationEntries.emplace_back(Id, Flags, Name);
            }
          }
        }

        QMetaObject::invokeMethod(
            qApp,
            [SafeDialog, Summary, Token, Threads, Handles, Modules, Memory,
             Eprocess, Mitigations, PebText, Loading, LoadStatus, InspectorSearch,
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
             MitigationEntries = std::move(MitigationEntries), Pid,
             StaticSummaryRows, RefreshBusy]() mutable {
              if (!SafeDialog) {
                RefreshBusy->store(false);
                return;
              }
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
              const auto Add = [InspectorSearch](QTableWidget *Table,
                                                 const QStringList &Values) {
                const int Row = Table->rowCount();
                Table->insertRow(Row);
                for (int Column = 0; Column < Values.size(); ++Column)
                  Table->setItem(Row, Column,
                                 new QTableWidgetItem(Values[Column]));
                Table->setRowHeight(Row, KCompactTableRowHeight);
                const QString Query = InspectorSearch->text().trimmed();
                Table->setRowHidden(
                    Row, !Query.isEmpty() &&
                             !Values.join(QLatin1Char(' '))
                                  .contains(Query, Qt::CaseInsensitive));
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
                      {"UniqueProcessKey", QString::fromWCharArray(R.Detail)});
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
                  Add(Summary, {"Path", QString::fromWCharArray(R.Path)});

              } else
                Add(Summary,
                    {"Kernel query",
                     QString("0x%1")
                         .arg(static_cast<quint32>(ProcessHeader.Status), 8, 16,
                              QLatin1Char('0'))
                         .toUpper()});
              if (KernelEprocessOk && !EprocessRows.empty()) {
                for (const auto &Row : EprocessRows) {
                  const QString Member =
                      Row.Name[0] ? QString::fromWCharArray(Row.Name) : "-";
                  const QString Value =
                      Row.Path[0] ? QString::fromWCharArray(Row.Path) : "-";
                  QString Notes;
                  if (Row.Value[0] != 0)
                    Notes = QString("offset=0x%1")
                                .arg(Row.Value[0], 0, 16)
                                .toUpper();
                  if (Row.Detail[0]) {
                    const QString Detail = QString::fromWCharArray(Row.Detail);
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
              }
              if ((!KernelEprocessOk || EprocessRows.empty()) &&
                  Eprocess->rowCount() == 0) {
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
              for (const auto &Entry : TokenInfo.Entries)
                Add(Token,
                    {Entry.Category, Entry.Name, Entry.Sid, Entry.Attributes});
              for (const auto &R : ThreadRows) {
                const int Row = Threads->rowCount();
                Add(Threads,
                    {QString::number(R.ThreadId),
                     QString("0x%1").arg(R.Address, 0, 16).toUpper(),
                     QString::number(R.Value[0]), QString::number(R.Value[2]),
                     QString::number(R.Value[3]),
                     QString::number(R.Value[6] + R.Value[7])});
                if (QTableWidgetItem *Item = Threads->item(Row, 0))
                  Item->setData(Qt::UserRole,
                                QVariant::fromValue<qulonglong>(R.ThreadId));
              }
              if (!ModuleRows.empty()) {
                for (const auto &R : ModuleRows) {
                  Add(Modules,
                      {R.Name[0] ? QString::fromWCharArray(R.Name) : "-",
                       QString("0x%1").arg(R.Address, 0, 16).toUpper(),
                       FormatBytes(R.SizeBytes),
                       R.Path[0] ? QString::fromWCharArray(R.Path) : "-",
                       SourceName(R.Source)});
                }
              }
              if (Modules->rowCount() == 0) {
                for (const auto &R : UserModuleRows) {
                  Add(Modules,
                      {Utf8Text(R.Name),
                       QString("0x%1").arg(R.BaseAddress, 0, 16).toUpper(),
                       FormatBytes(R.SizeOfImage), Utf8Text(R.FullPath),
                       "Toolhelp"});
                }
              }
              if (Modules->rowCount() == 0) {
                Add(Modules, {"Unavailable", {}, {}, {},
                              QString("status=0x%1")
                                  .arg(static_cast<quint32>(ModuleHeader.Status),
                                       8, 16, QLatin1Char('0'))
                                  .toUpper()});
              }
              if (!MemoryRows.empty()) {
                for (const auto &R : MemoryRows) {
                  Add(Memory,
                      {QString("0x%1").arg(R.Address, 0, 16).toUpper(),
                       FormatBytes(R.SizeBytes),
                       QString("0x%1").arg(R.Value[2], 0, 16).toUpper(),
                       QString("0x%1").arg(R.Value[3], 0, 16).toUpper(),
                       QString("0x%1").arg(R.Value[4], 0, 16).toUpper()});
                }
              }
              if (Memory->rowCount() == 0) {
                for (const auto &R : UserMemoryRows) {
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
              }
              if (Memory->rowCount() == 0) {
                Add(Memory, {"Unavailable", {}, {}, {},
                             QString("status=0x%1")
                                 .arg(static_cast<quint32>(MemoryHeader.Status),
                                      8, 16, QLatin1Char('0'))
                                 .toUpper()});
              }
              if (KernelHandleOk && HandleHeader.Status == 0) {
                for (const auto &R : HandleRows) {
                  const QString ObjectText =
                      R.Path[0]
                          ? QString::fromWCharArray(R.Path)
                          : QString("0x%1").arg(R.Address, 0, 16).toUpper();
                  const QString TypeText =
                      R.TypeName[0]
                          ? QString::fromWCharArray(R.TypeName)
                          : (R.Detail[0] ? QString::fromWCharArray(R.Detail)
                                         : QString::number(R.Value[2]));
                  const int HandleRow = Handles->rowCount();
                  Add(Handles,
                      {QString("0x%1").arg(R.Value[0], 0, 16).toUpper(),
                       ObjectText, TypeText,
                       FormatHandleAccessDisplay(
                           TypeText, static_cast<quint32>(R.Value[1])),
                       QString("0x%1").arg(R.Value[3], 0, 16).toUpper()});
                  if (QTableWidgetItem *Item = Handles->item(HandleRow, 0)) {
                    Item->setData(Qt::UserRole,
                                  QVariant::fromValue<quint32>(
                                      static_cast<quint32>(R.Value[0])));
                    Item->setData(Qt::UserRole + 1,
                                  QVariant::fromValue<quint32>(Pid));
                    Item->setData(Qt::UserRole + 2,
                                  QVariant::fromValue<quint32>(
                                      static_cast<quint32>(R.Value[1])));
                  }
                }
                if (HandleRows.empty())
                  Add(Handles, {"No handles", {}, {}, {}, {}});
                Add(Mitigations, {"Handle source", "Kernel driver",
                                  QString::number(HandleRows.size())});
              } else if (UserHandleOk && !UserHandleRows.empty()) {
                for (const auto &R : UserHandleRows) {
                  const int HandleRow = Handles->rowCount();
                  Add(Handles,
                      {QString("0x%1").arg(R.HandleValue, 0, 16).toUpper(),
                       R.ObjectName.isEmpty() ? QString("0x%1")
                                                    .arg(R.ObjectAddress, 0, 16)
                                                    .toUpper()
                                              : R.ObjectName,
                       R.TypeName.isEmpty() ? "Unknown" : R.TypeName,
                       FormatHandleAccessDisplay(R.TypeName, R.GrantedAccess),
                       QString("0x%1").arg(R.Attributes, 0, 16).toUpper()});
                  if (QTableWidgetItem *Item = Handles->item(HandleRow, 0)) {
                    Item->setData(Qt::UserRole,
                                  QVariant::fromValue<quint32>(
                                      static_cast<quint32>(R.HandleValue)));
                    Item->setData(Qt::UserRole + 1,
                                  QVariant::fromValue<quint32>(Pid));
                    Item->setData(
                        Qt::UserRole + 2,
                        QVariant::fromValue<quint32>(R.GrantedAccess));
                  }
                }
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
              } else if (G_DeviceHandle != INVALID_HANDLE_VALUE) {
                Add(Mitigations,
                    {"Mitigation query", "No data / unsupported", {}});
              }
              PebText->setPlainText(QString::fromStdString(PebOutput));
              if (!InspectorSearch->text().trimmed().isEmpty()) {
                PebText->moveCursor(QTextCursor::Start);
                PebText->find(InspectorSearch->text().trimmed());
              }
              for (QTableWidget *Table : {Summary, Token, Threads, Handles,
                                          Modules, Memory, Eprocess,
                                          Mitigations}) {
                Table->setSortingEnabled(true);
                Table->setUpdatesEnabled(true);
              }
              Loading->stop();
              Loading->hide();
              LoadStatus->setText(
                  QString("%1 threads | %2 handles | %3 modules")
                      .arg(ThreadRows.size())
                      .arg(UserHandleOk && !UserHandleRows.empty()
                               ? UserHandleRows.size()
                               : HandleRows.size())
                      .arg(ModuleRows.size()));
              RefreshBusy->store(false);
            },
            Qt::QueuedConnection);
      }).detach();
    };
    auto *RefreshTimer = new QTimer(Dialog);
    RefreshTimer->setInterval(2000);
    QObject::connect(RefreshTimer, &QTimer::timeout, Dialog,
                     [RefreshInspector] { (*RefreshInspector)(); });
    RefreshTimer->start();
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
    Dialog->resize(850, 620);
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
    Dialog->resize(1050, 650);
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
    Dialog->show();
  }

  void ShowInjectDllDialog(DWORD Pid) {
    auto *Dialog = new MessageBoxBase(window());
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
                            "DLL injection failed. See Console for details.");
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

protected:
  void showEvent(QShowEvent *Event) override {
    QWidget::showEvent(Event);
    if (AutoRefreshTimer)
      AutoRefreshTimer->start(10000);
    RefreshProcesses();
  }

  void hideEvent(QHideEvent *Event) override {
    if (AutoRefreshTimer)
      AutoRefreshTimer->stop();
    QWidget::hideEvent(Event);
  }
};
