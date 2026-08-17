QWidget *CreateSnapshotLabPage() {
  struct SnapshotLabPage final : public QWidget {
    struct SnapshotDriverState {
      bool MultiDrvAvailable = false;
      bool MonitorDrvAvailable = false;
    };

    struct SnapshotMeta {
      int SchemaVersion = 1;
      QString CapturedAtUtc;
      QString MachineName;
      QString WindowsVersion;
      QString AppVersion;
      SnapshotDriverState DriverState;
    };

    struct ProcessSnapshotEntry {
      quint32 Pid = 0;
      quint32 ParentPid = 0;
      QString ImageName;
      QString ImagePath;
      quint64 Eprocess = 0;
      bool Ppl = false;
      quint32 SessionId = 0;
      quint32 ThreadCount = 0;
      quint32 HandleCount = 0;
      QString CreateTime;
    };

    struct DriverSnapshotEntry {
      QString ServiceName;
      QString DisplayName;
      QString ImagePath;
      quint64 Base = 0;
      quint32 Size = 0;
      quint32 StartType = 0;
      quint32 State = 0;
      quint64 DriverObject = 0;
    };

    struct CallbackSnapshotEntry {
      QString Type;
      quint32 Flags = 0;
      quint64 Address = 0;
      QString ModuleName;
      QString SourceName;
    };

    struct SnapshotDocument {
      SnapshotMeta Meta;
      std::vector<ProcessSnapshotEntry> Processes;
      std::vector<DriverSnapshotEntry> Drivers;
      std::vector<CallbackSnapshotEntry> Callbacks;
      QString Source;
      QString LoadPath;
      QString WarningText;
    };

    struct DiffRow {
      QString Category;
      QString State;
      QString Key;
      QString PrimaryName;
      QString Summary;
      QStringList ChangedFields;
      QJsonObject OldValue;
      QJsonObject NewValue;
    };

    struct DiffStats {
      int Added = 0;
      int Removed = 0;
      int Modified = 0;
      int Warnings = 0;
    };

    struct SnapshotDiffResult {
      std::vector<DiffRow> Processes;
      std::vector<DiffRow> Drivers;
      std::vector<DiffRow> Callbacks;
      DiffStats ProcessStats;
      DiffStats DriverStats;
      DiffStats CallbackStats;
      QStringList Warnings;
    };

    struct CaptureResult {
      SnapshotDocument Document;
      bool ProcessOk = false;
      bool DriverOk = false;
      bool CallbackOk = false;
      QStringList Failures;
    };

    enum class SlotKind { A, B };
    enum class DiffCategory { Process, Driver, Callback };

    explicit SnapshotLabPage(QWidget *Parent = nullptr) : QWidget(Parent) {
      auto *Layout = new QVBoxLayout(this);
      ConfigurePageLayout(Layout);

      auto *Toolbar = new QHBoxLayout;
      ConfigureToolbarLayout(Toolbar);
      CaptureButton = MakeButton("Capture", true);
      LoadButton = MakeButton("Load JSON");
      SaveButton = MakeButton("Save JSON");
      CompareButton = MakeButton("Compare A/B");
      ClearButton = MakeButton("Clear");
      for (PushButton *Button :
           {CaptureButton, LoadButton, SaveButton, CompareButton, ClearButton})
        ConfigureActionButton(Button, 108, KStandardButtonHeight);
      SaveButton->setEnabled(false);
      CompareButton->setEnabled(false);
      ProgressRing = new IndeterminateProgressRing(this, false);
      ProgressRing->setFixedSize(22, 22);
      ProgressRing->hide();
      StatusLabel = new BodyLabel("Ready");
      Toolbar->addWidget(CaptureButton);
      Toolbar->addWidget(LoadButton);
      Toolbar->addWidget(SaveButton);
      Toolbar->addWidget(CompareButton);
      Toolbar->addWidget(ClearButton);
      Toolbar->addStretch(1);
      Toolbar->addWidget(StatusLabel);
      Toolbar->addWidget(ProgressRing);
      Layout->addLayout(Toolbar);

      auto *Body = new QSplitter(Qt::Horizontal);
      Body->setChildrenCollapsible(false);
      Body->setHandleWidth(1);
      Layout->addWidget(Body, 1);

      SlotTable = MakeTable({"Slot", "Captured At", "Source", "Objects"});
      SlotTable->setRowCount(2);
      SlotTable->setSelectionMode(QAbstractItemView::SingleSelection);
      SlotTable->setSelectionBehavior(QAbstractItemView::SelectRows);
      SlotTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
      SlotTable->horizontalHeader()->setSectionResizeMode(
          0, QHeaderView::ResizeToContents);
      SlotTable->horizontalHeader()->setSectionResizeMode(
          1, QHeaderView::ResizeToContents);
      SlotTable->horizontalHeader()->setSectionResizeMode(
          2, QHeaderView::ResizeToContents);
      SlotTable->horizontalHeader()->setSectionResizeMode(3,
                                                          QHeaderView::Stretch);
      InitializeSlotTableRow(0, "Snapshot A");
      InitializeSlotTableRow(1, "Snapshot B");
      Body->addWidget(SlotTable);

      auto *RightBody = new QSplitter(Qt::Horizontal);
      RightBody->setChildrenCollapsible(false);
      RightBody->setHandleWidth(1);
      auto *RightHost = new QWidget;
      auto *RightLayout = new QVBoxLayout(RightHost);
      RightLayout->setContentsMargins(0, 0, 0, 0);
      RightLayout->setSpacing(10);
      DiffViewList = new QListWidget;
      DiffViewList->setObjectName("HandleLabViewList");
      DiffViewList->setMinimumWidth(152);
      DiffViewList->setMaximumWidth(184);
      DiffViewList->setSpacing(2);
      DiffViewList->setFrameShape(QFrame::NoFrame);
      DiffViewList->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
      DiffViewList->addItems({"Processes", "Drivers", "Callbacks", "Summary"});
      DiffViewList->setCurrentRow(0);
      RightBody->addWidget(DiffViewList);

      DiffPages = new QStackedWidget;
      ProcessDiffTable =
          CreateDiffTable({"State", "Key", "Primary Name", "Change Summary"});
      DriverDiffTable =
          CreateDiffTable({"State", "Key", "Primary Name", "Change Summary"});
      CallbackDiffTable =
          CreateDiffTable({"State", "Key", "Primary Name", "Change Summary"});
      SummaryView = new PlainTextEdit;
      SummaryView->setReadOnly(true);
      SummaryView->setPlaceholderText("Compare A and B to view summary.");
      SummaryView->setFont(QFont("Cascadia Mono", 10));
      InstallFluentScrollBar(SummaryView, Qt::Vertical);
      DiffPages->addWidget(ProcessDiffTable);
      DiffPages->addWidget(DriverDiffTable);
      DiffPages->addWidget(CallbackDiffTable);
      DiffPages->addWidget(SummaryView);
      RightLayout->addWidget(DiffPages, 1);

      auto *BottomInfo = new BodyLabel(
          "State bar: source, capture time, object counts, and diff totals.");
      BottomInfo->setProperty("TextRole", "Muted");
      RightLayout->addWidget(BottomInfo);
      RightBody->addWidget(RightHost);
      RightBody->setStretchFactor(0, 0);
      RightBody->setStretchFactor(1, 1);
      Body->addWidget(RightBody);
      Body->setStretchFactor(0, 0);
      Body->setStretchFactor(1, 1);

      QObject::connect(CaptureButton, &QPushButton::clicked, this,
                       [this] { CaptureIntoNextSlot(); });
      QObject::connect(LoadButton, &QPushButton::clicked, this,
                       [this] { LoadSnapshotFromJson(); });
      QObject::connect(SaveButton, &QPushButton::clicked, this,
                       [this] { SaveSelectedSnapshot(); });
      QObject::connect(CompareButton, &QPushButton::clicked, this,
                       [this] { CompareSnapshots(); });
      QObject::connect(ClearButton, &QPushButton::clicked, this,
                       [this] { ClearAll(); });
      QObject::connect(
          SlotTable, &QTableWidget::itemSelectionChanged, this,
          [this] { RefreshUiState(); });
      QObject::connect(DiffViewList, &QListWidget::currentRowChanged, DiffPages,
                       [this](int Row) {
                         if (Row >= 0 && Row < DiffPages->count())
                           DiffPages->setCurrentIndex(Row);
                       });
      ConnectDiffDoubleClick(ProcessDiffTable, DiffCategory::Process);
      ConnectDiffDoubleClick(DriverDiffTable, DiffCategory::Driver);
      ConnectDiffDoubleClick(CallbackDiffTable, DiffCategory::Callback);

      SlotTable->selectRow(0);
      DiffViewList->setCurrentRow(0);
      RefreshUiState();
    }

  private:
    static QString DescribeCallbackType(ULONG Type) {
      switch (Type) {
      case CALLBACK_TYPE_OB_PROCESS:
        return "ObProcess";
      case CALLBACK_TYPE_OB_THREAD:
        return "ObThread";
      case CALLBACK_TYPE_REGISTRY:
        return "Registry";
      case CALLBACK_TYPE_FLT_PRE_CREATE:
        return "FltCreate";
      case CALLBACK_TYPE_FLT_PRE_SET_INFORMATION:
        return "FltSetInfo";
      case CALLBACK_TYPE_FLT_PRE_WRITE:
        return "FltWrite";
      case CALLBACK_TYPE_FLT_PRE_READ:
        return "FltRead";
      case CALLBACK_TYPE_FLT_PRE_QUERY_INFORMATION:
        return "FltQueryInfo";
      case CALLBACK_TYPE_FLT_PRE_DIRECTORY_CONTROL:
        return "FltDirCtrl";
      case CALLBACK_TYPE_FLT_PRE_CLEANUP:
        return "FltCleanup";
      case CALLBACK_TYPE_FLT_PRE_CLOSE:
        return "FltClose";
      case CALLBACK_TYPE_FLT_POST_CREATE:
        return "FltPostCreate";
      case CALLBACK_TYPE_FLT_POST_READ:
        return "FltPostRead";
      case CALLBACK_TYPE_FLT_POST_QUERY_INFORMATION:
        return "FltPostQuery";
      case CALLBACK_TYPE_FLT_POST_SET_INFORMATION:
        return "FltPostSet";
      case CALLBACK_TYPE_FLT_POST_DIRECTORY_CONTROL:
        return "FltPostDir";
      case CALLBACK_TYPE_FLT_POST_WRITE:
        return "FltPostWrite";
      case CALLBACK_TYPE_FLT_POST_CLEANUP:
        return "FltPostCleanup";
      case CALLBACK_TYPE_FLT_POST_CLOSE:
        return "FltPostClose";
      case CALLBACK_TYPE_PS_PROCESS_NOTIFY:
        return "PsProcess";
      case CALLBACK_TYPE_PS_THREAD_NOTIFY:
        return "PsThread";
      case CALLBACK_TYPE_PS_IMAGE_NOTIFY:
        return "PsImage";
      case CALLBACK_TYPE_BUGCHECK:
        return "BugCheck";
      case CALLBACK_TYPE_BUGCHECK_REASON:
        return "BugChkReason";
      case CALLBACK_TYPE_SHUTDOWN:
        return "Shutdown";
      default:
        return QString("Unknown(%1)").arg(Type);
      }
    }

    static QString FormatPointer(quint64 Value) {
      if (Value == 0)
        return "0x0";
      return QString("0x%1")
          .arg(Value, sizeof(quintptr) * 2, 16, QLatin1Char('0'))
          .toUpper();
    }

    static QString FormatFileTimeUtc(const FILETIME &FileTime) {
      if (FileTime.dwLowDateTime == 0 && FileTime.dwHighDateTime == 0)
        return {};
      ULARGE_INTEGER Value{};
      Value.LowPart = FileTime.dwLowDateTime;
      Value.HighPart = FileTime.dwHighDateTime;
      const qint64 UnixMs =
          static_cast<qint64>((Value.QuadPart - 116444736000000000ULL) / 10000);
      return QDateTime::fromMSecsSinceEpoch(UnixMs, Qt::UTC).toString(
          Qt::ISODate);
    }

    static bool QueryProcessHandleCountValue(DWORD Pid, quint32 &Value) {
      Value = 0;
      HANDLE Process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
      if (!Process)
        return false;
      DWORD Count = 0;
      const bool Ok = GetProcessHandleCount(Process, &Count) != FALSE;
      CloseHandle(Process);
      if (Ok)
        Value = Count;
      return Ok;
    }

    static QString QueryProcessImagePath(DWORD Pid) {
      QString Result;
      HANDLE Process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
      if (!Process)
        return Result;
      std::vector<WCHAR> Buffer(32768);
      DWORD Length = static_cast<DWORD>(Buffer.size());
      if (QueryFullProcessImageNameW(Process, 0, Buffer.data(), &Length))
        Result = QDir::toNativeSeparators(
            QString::fromWCharArray(Buffer.data(), Length));
      CloseHandle(Process);
      return Result;
    }

    static QString QueryProcessCreateTime(DWORD Pid) {
      HANDLE Process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
      if (!Process)
        return {};
      FILETIME CreateTime{}, ExitTime{}, KernelTime{}, UserTime{};
      const BOOL Ok = GetProcessTimes(Process, &CreateTime, &ExitTime,
                                      &KernelTime, &UserTime);
      CloseHandle(Process);
      return Ok ? FormatFileTimeUtc(CreateTime) : QString();
    }

    static SnapshotMeta BuildSnapshotMeta() {
      SnapshotMeta Meta;
      Meta.SchemaVersion = 1;
      Meta.CapturedAtUtc = QDateTime::currentDateTimeUtc().toString(Qt::ISODate);
      Meta.MachineName = QSysInfo::machineHostName();
      Meta.WindowsVersion = QueryWindowsVersionText();
      Meta.AppVersion =
          ConfigurationValue("Application", "Version", "1.0.0").toString();
      Meta.DriverState.MultiDrvAvailable =
          G_DeviceHandle != INVALID_HANDLE_VALUE ||
          IsDriverServiceRunning(L"MultiDrv");
      Meta.DriverState.MonitorDrvAvailable = IsDriverServiceRunning(L"MonitorDrv");
      return Meta;
    }

    static std::vector<ProcessSnapshotEntry>
    CaptureProcesses(bool &Success, QStringList &Warnings) {
      std::vector<ProcessSnapshotEntry> Entries;
      std::vector<PROCESS_ENUM_ENTRY> DriverEntries;
      Success = EnumProcessEntries(DriverEntries) && !DriverEntries.empty();
      if (Success) {
        for (const PROCESS_ENUM_ENTRY &Entry : DriverEntries) {
          ProcessSnapshotEntry Row;
          Row.Pid = Entry.ProcessId;
          Row.ParentPid = Entry.ParentPid;
          Row.ThreadCount = Entry.ThreadCount;
          Row.SessionId = Entry.SessionId;
          DWORD UserSessionId = 0;
          if (ProcessIdToSessionId(Row.Pid, &UserSessionId))
            Row.SessionId = UserSessionId;
          Row.ImageName = Entry.ImageName[0]
                              ? QString::fromWCharArray(Entry.ImageName)
                              : "Unknown";
          Row.ImagePath = QueryProcessImagePath(Row.Pid);
          if (!Row.ImagePath.isEmpty()) {
            const QString FileName = QFileInfo(Row.ImagePath).fileName();
            if (!FileName.isEmpty())
              Row.ImageName = FileName;
          }
          Row.Eprocess = Entry.ObjectAddress;
          Row.Ppl = Entry.IsPplProtected != FALSE;
          QueryProcessHandleCountValue(Row.Pid, Row.HandleCount);
          Row.CreateTime = QueryProcessCreateTime(Row.Pid);
          Entries.push_back(std::move(Row));
        }
      } else {
        HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (Snapshot == INVALID_HANDLE_VALUE) {
          Warnings.append("Process capture failed: Toolhelp snapshot unavailable.");
          return Entries;
        }
        PROCESSENTRY32W Entry{sizeof(Entry)};
        if (!Process32FirstW(Snapshot, &Entry)) {
          CloseHandle(Snapshot);
          Warnings.append(
              "Process capture failed: Unable to enumerate Toolhelp processes.");
          return Entries;
        }
        do {
          ProcessSnapshotEntry Row;
          Row.Pid = Entry.th32ProcessID;
          Row.ParentPid = Entry.th32ParentProcessID;
          Row.ThreadCount = Entry.cntThreads;
          DWORD SessionId = 0;
          ProcessIdToSessionId(Row.Pid, &SessionId);
          Row.SessionId = SessionId;
          Row.ImageName = QString::fromWCharArray(Entry.szExeFile);
          Row.ImagePath = QueryProcessImagePath(Row.Pid);
          QueryProcessHandleCountValue(Row.Pid, Row.HandleCount);
          Row.CreateTime = QueryProcessCreateTime(Row.Pid);
          Entries.push_back(std::move(Row));
        } while (Process32NextW(Snapshot, &Entry));
        CloseHandle(Snapshot);
        Warnings.append(
            "Process snapshot used Toolhelp fallback. EPROCESS and PPL may be unavailable.");
      }
      std::stable_sort(Entries.begin(), Entries.end(),
                       [](const ProcessSnapshotEntry &Left,
                          const ProcessSnapshotEntry &Right) {
                         return Left.Pid < Right.Pid;
                       });
      return Entries;
    }

    static std::vector<DriverSnapshotEntry>
    CaptureDrivers(bool &Success, QStringList &Warnings) {
      std::vector<DriverSnapshotEntry> Result;
      DRIVER_ENUM_HEADER Header{};
      std::vector<DRIVER_ENUM_ENTRY> Entries;
      Success = QueryDriverEntries(Entries, &Header);
      if (!Success) {
        if (Header.NtStatus != 0 || !Entries.empty())
          Success = true;
        else {
          Warnings.append(QString("Driver capture failed: %1")
                              .arg(DescribeWin32ErrorMessage(G_LastMultiDrvError)));
          return Result;
        }
      }
      for (const DRIVER_ENUM_ENTRY &Entry : Entries) {
        DriverSnapshotEntry Row;
        Row.ServiceName = QString::fromWCharArray(Entry.ServiceName);
        Row.DisplayName = QString::fromWCharArray(Entry.DisplayName);
        Row.ImagePath =
            NormalizeUserDriverPath(QString::fromWCharArray(Entry.ImagePath));
        Row.Base = Entry.ImageBase;
        Row.Size = Entry.ImageSize;
        Row.StartType = Entry.StartType;
        Row.State = Entry.State;
        Row.DriverObject = Entry.DriverObject;
        Result.push_back(std::move(Row));
      }
      std::stable_sort(Result.begin(), Result.end(),
                       [](const DriverSnapshotEntry &Left,
                          const DriverSnapshotEntry &Right) {
                         return Left.ServiceName.compare(Right.ServiceName,
                                                         Qt::CaseInsensitive) < 0;
                       });
      return Result;
    }

    static std::vector<CallbackSnapshotEntry>
    CaptureCallbacks(bool &Success, QStringList &Warnings) {
      std::vector<CallbackSnapshotEntry> Rows;
      DWORD BytesReturned = 0;
      ULONG Count = 0;
      Success = SendIoctlWithOutput(IOCTL_ENUM_CALLBACKS, nullptr, 0, &Count,
                                    sizeof(Count), &BytesReturned) != FALSE;
      if (!Success) {
        Warnings.append(QString("Callback capture failed: %1")
                            .arg(DescribeWin32ErrorMessage(G_LastMultiDrvError)));
        return Rows;
      }
      if (Count == 0)
        return Rows;
      const DWORD Size =
          sizeof(CALLBACK_ENUM_OUTPUT) + (Count - 1) * sizeof(CALLBACK_ENTRY);
      std::vector<BYTE> Buffer(Size);
      auto *Output = reinterpret_cast<PCALLBACK_ENUM_OUTPUT>(Buffer.data());
      ZeroMemory(Output, Size);
      Success = SendIoctlWithOutput(IOCTL_ENUM_CALLBACKS, nullptr, 0, Output,
                                    Size, &BytesReturned) != FALSE;
      if (!Success) {
        Warnings.append(QString("Callback capture failed: %1")
                            .arg(DescribeWin32ErrorMessage(G_LastMultiDrvError)));
        return Rows;
      }
      for (ULONG Index = 0; Index < Output->Count; ++Index) {
        const CALLBACK_ENTRY &Entry = Output->Entries[Index];
        CallbackSnapshotEntry Row;
        Row.Type = DescribeCallbackType(Entry.Type);
        Row.Flags = Entry.Flags;
        Row.Address = Entry.Address;
        Row.ModuleName = Entry.ModuleName[0]
                             ? QString::fromWCharArray(Entry.ModuleName)
                             : QString();
        Row.SourceName = Entry.SourceName[0]
                             ? QString::fromWCharArray(Entry.SourceName)
                             : QString();
        Rows.push_back(std::move(Row));
      }
      std::stable_sort(Rows.begin(), Rows.end(),
                       [](const CallbackSnapshotEntry &Left,
                          const CallbackSnapshotEntry &Right) {
                         if (Left.Type.compare(Right.Type, Qt::CaseInsensitive) !=
                             0) {
                           return Left.Type.compare(Right.Type,
                                                    Qt::CaseInsensitive) < 0;
                         }
                         return Left.Address < Right.Address;
                       });
      return Rows;
    }

    static CaptureResult CaptureSnapshotDocument() {
      CaptureResult Result;
      Result.Document.Meta = BuildSnapshotMeta();
      Result.Document.Source = "live";
      Result.Document.Processes =
          CaptureProcesses(Result.ProcessOk, Result.Failures);
      Result.Document.Drivers =
          CaptureDrivers(Result.DriverOk, Result.Failures);
      Result.Document.Callbacks =
          CaptureCallbacks(Result.CallbackOk, Result.Failures);
      Result.Document.WarningText = Result.Failures.join('\n');
      return Result;
    }

    static QJsonObject ToJson(const SnapshotMeta &Meta) {
      QJsonObject Object;
      Object.insert("SchemaVersion", Meta.SchemaVersion);
      Object.insert("CapturedAtUtc", Meta.CapturedAtUtc);
      Object.insert("MachineName", Meta.MachineName);
      Object.insert("WindowsVersion", Meta.WindowsVersion);
      Object.insert("AppVersion", Meta.AppVersion);
      QJsonObject DriverState;
      DriverState.insert("MultiDrvAvailable", Meta.DriverState.MultiDrvAvailable);
      DriverState.insert("MonitorDrvAvailable",
                         Meta.DriverState.MonitorDrvAvailable);
      Object.insert("DriverState", DriverState);
      return Object;
    }

    static QJsonObject ToJson(const ProcessSnapshotEntry &Entry) {
      QJsonObject Object;
      Object.insert("Pid", static_cast<int>(Entry.Pid));
      Object.insert("ParentPid", static_cast<int>(Entry.ParentPid));
      Object.insert("ImageName", Entry.ImageName);
      Object.insert("ImagePath", Entry.ImagePath);
      Object.insert("Eprocess", FormatPointer(Entry.Eprocess));
      Object.insert("Ppl", Entry.Ppl);
      Object.insert("SessionId", static_cast<int>(Entry.SessionId));
      Object.insert("ThreadCount", static_cast<int>(Entry.ThreadCount));
      Object.insert("HandleCount", static_cast<int>(Entry.HandleCount));
      Object.insert("CreateTime", Entry.CreateTime);
      return Object;
    }

    static QJsonObject ToJson(const DriverSnapshotEntry &Entry) {
      QJsonObject Object;
      Object.insert("ServiceName", Entry.ServiceName);
      Object.insert("DisplayName", Entry.DisplayName);
      Object.insert("ImagePath", Entry.ImagePath);
      Object.insert("Base", FormatPointer(Entry.Base));
      Object.insert("Size", static_cast<int>(Entry.Size));
      Object.insert("StartType", static_cast<int>(Entry.StartType));
      Object.insert("State", static_cast<int>(Entry.State));
      Object.insert("DriverObject", FormatPointer(Entry.DriverObject));
      return Object;
    }

    static QJsonObject ToJson(const CallbackSnapshotEntry &Entry) {
      QJsonObject Object;
      Object.insert("Type", Entry.Type);
      Object.insert("Flags", static_cast<int>(Entry.Flags));
      Object.insert("Address", FormatPointer(Entry.Address));
      Object.insert("ModuleName", Entry.ModuleName);
      Object.insert("SourceName", Entry.SourceName);
      return Object;
    }

    static QString ProcessKey(const ProcessSnapshotEntry &Entry) {
      return QString::number(Entry.Pid);
    }

    static QString DriverKey(const DriverSnapshotEntry &Entry) {
      const QString Name = Entry.ServiceName.trimmed();
      if (!Name.isEmpty())
        return Name.toCaseFolded();
      return Entry.ImagePath.trimmed().toCaseFolded();
    }

    static QString CallbackKey(const CallbackSnapshotEntry &Entry) {
      return Entry.Type.toCaseFolded() + "|" + FormatPointer(Entry.Address);
    }

    static QString ProcessSummary(const QJsonObject &OldObject,
                                  const QJsonObject &NewObject,
                                  QStringList *ChangedFields = nullptr) {
      const QStringList Preferred{"ImagePath", "Ppl", "HandleCount",
                                  "ThreadCount", "Eprocess"};
      return BuildSummary(OldObject, NewObject, Preferred, ChangedFields);
    }

    static QString DriverSummary(const QJsonObject &OldObject,
                                 const QJsonObject &NewObject,
                                 QStringList *ChangedFields = nullptr) {
      const QStringList Preferred{"Base", "Size", "State", "ImagePath",
                                  "DriverObject"};
      return BuildSummary(OldObject, NewObject, Preferred, ChangedFields);
    }

    static QString CallbackSummary(const QJsonObject &OldObject,
                                   const QJsonObject &NewObject,
                                   QStringList *ChangedFields = nullptr) {
      const QStringList Preferred{"Flags", "ModuleName", "SourceName"};
      return BuildSummary(OldObject, NewObject, Preferred, ChangedFields);
    }

    static QString BuildSummary(const QJsonObject &OldObject,
                                const QJsonObject &NewObject,
                                const QStringList &Preferred,
                                QStringList *ChangedFields = nullptr) {
      QStringList Changes;
      QStringList Changed;
      for (const QString &Field : Preferred) {
        const QJsonValue OldValue = OldObject.value(Field);
        const QJsonValue NewValue = NewObject.value(Field);
        if (OldValue != NewValue) {
          Changed.append(Field);
          Changes.append(QString("%1: %2 -> %3")
                             .arg(Field, JsonValueText(OldValue),
                                  JsonValueText(NewValue)));
        }
      }
      for (auto It = NewObject.begin(); It != NewObject.end(); ++It) {
        if (Preferred.contains(It.key()))
          continue;
        const QJsonValue OldValue = OldObject.value(It.key());
        if (OldValue != It.value()) {
          Changed.append(It.key());
          Changes.append(QString("%1: %2 -> %3")
                             .arg(It.key(), JsonValueText(OldValue),
                                  JsonValueText(It.value())));
        }
      }
      if (ChangedFields)
        *ChangedFields = Changed;
      return Changes.isEmpty() ? "No field changes" : Changes.join(" | ");
    }

    static QString JsonValueText(const QJsonValue &Value) {
      if (Value.isUndefined())
        return "(missing)";
      if (Value.isNull())
        return "null";
      if (Value.isBool())
        return Value.toBool() ? "true" : "false";
      if (Value.isDouble())
        return QString::number(Value.toDouble());
      if (Value.isString())
        return Value.toString();
      return QString::fromUtf8(QJsonDocument(Value.toObject()).toJson(
                                   QJsonDocument::Compact))
          .trimmed();
    }

    static bool ParsePointerString(const QJsonObject &Object, const char *Key,
                                   quint64 &Value, QString &Error) {
      Value = 0;
      const QJsonValue Json = Object.value(QLatin1String(Key));
      if (!Json.isString()) {
        Error = QString("Field `%1` must be a string pointer.").arg(Key);
        return false;
      }
      bool Ok = false;
      Value = Json.toString().trimmed().toULongLong(&Ok, 0);
      if (!Ok) {
        Error = QString("Field `%1` has invalid pointer text.").arg(Key);
        return false;
      }
      return true;
    }

    static bool ParseProcess(const QJsonObject &Object, ProcessSnapshotEntry &Out,
                             QString &Error) {
      if (!Object.contains("Pid") || !Object.value("Pid").isDouble()) {
        Error = "Process entry missing numeric `Pid`.";
        return false;
      }
      Out.Pid = static_cast<quint32>(Object.value("Pid").toInt());
      Out.ParentPid = static_cast<quint32>(Object.value("ParentPid").toInt());
      Out.ImageName = Object.value("ImageName").toString();
      Out.ImagePath = Object.value("ImagePath").toString();
      if (!ParsePointerString(Object, "Eprocess", Out.Eprocess, Error))
        return false;
      Out.Ppl = Object.value("Ppl").toBool(false);
      Out.SessionId = static_cast<quint32>(Object.value("SessionId").toInt());
      Out.ThreadCount = static_cast<quint32>(Object.value("ThreadCount").toInt());
      Out.HandleCount = static_cast<quint32>(Object.value("HandleCount").toInt());
      Out.CreateTime = Object.value("CreateTime").toString();
      return true;
    }

    static bool ParseDriver(const QJsonObject &Object, DriverSnapshotEntry &Out,
                            QString &Error) {
      Out.ServiceName = Object.value("ServiceName").toString();
      Out.DisplayName = Object.value("DisplayName").toString();
      Out.ImagePath = Object.value("ImagePath").toString();
      if (!ParsePointerString(Object, "Base", Out.Base, Error))
        return false;
      Out.Size = static_cast<quint32>(Object.value("Size").toInt());
      Out.StartType = static_cast<quint32>(Object.value("StartType").toInt());
      Out.State = static_cast<quint32>(Object.value("State").toInt());
      if (!ParsePointerString(Object, "DriverObject", Out.DriverObject, Error))
        return false;
      return true;
    }

    static bool ParseCallback(const QJsonObject &Object,
                              CallbackSnapshotEntry &Out, QString &Error) {
      Out.Type = Object.value("Type").toString();
      Out.Flags = static_cast<quint32>(Object.value("Flags").toInt());
      if (!ParsePointerString(Object, "Address", Out.Address, Error))
        return false;
      Out.ModuleName = Object.value("ModuleName").toString();
      Out.SourceName = Object.value("SourceName").toString();
      return true;
    }

    static bool ParseDocument(const QByteArray &Bytes, SnapshotDocument &Out,
                              QString &Error) {
      QJsonParseError ParseError{};
      const QJsonDocument Document = QJsonDocument::fromJson(Bytes, &ParseError);
      if (ParseError.error != QJsonParseError::NoError || !Document.isObject()) {
        Error = QString("Invalid JSON: %1").arg(ParseError.errorString());
        return false;
      }
      const QJsonObject Root = Document.object();
      const QJsonObject Meta = Root.value("Meta").toObject();
      if (Meta.isEmpty()) {
        Error = "Snapshot JSON missing `Meta` object.";
        return false;
      }
      const int Version = Meta.value("SchemaVersion").toInt(-1);
      if (Version != 1) {
        Error = QString("Unsupported schema version %1. Expected %2.")
                    .arg(Version)
                    .arg(1);
        return false;
      }
      SnapshotDocument Parsed;
      Parsed.Source = "json";
      Parsed.Meta.SchemaVersion = Version;
      Parsed.Meta.CapturedAtUtc = Meta.value("CapturedAtUtc").toString();
      Parsed.Meta.MachineName = Meta.value("MachineName").toString();
      Parsed.Meta.WindowsVersion = Meta.value("WindowsVersion").toString();
      Parsed.Meta.AppVersion = Meta.value("AppVersion").toString();
      const QJsonObject DriverState = Meta.value("DriverState").toObject();
      Parsed.Meta.DriverState.MultiDrvAvailable =
          DriverState.value("MultiDrvAvailable").toBool(false);
      Parsed.Meta.DriverState.MonitorDrvAvailable =
          DriverState.value("MonitorDrvAvailable").toBool(false);
      const auto ParseArray = [&Error](const QJsonObject &RootObject,
                                       const char *Name, auto Parser,
                                       auto &Output) {
        const QJsonValue Value = RootObject.value(QLatin1String(Name));
        if (!Value.isArray()) {
          Error = QString("Snapshot JSON missing `%1` array.").arg(Name);
          return false;
        }
        for (const QJsonValue &Item : Value.toArray()) {
          if (!Item.isObject()) {
            Error = QString("Array `%1` contains a non-object item.").arg(Name);
            return false;
          }
          typename std::decay_t<decltype(Output)>::value_type Entry;
          if (!Parser(Item.toObject(), Entry, Error))
            return false;
          Output.push_back(std::move(Entry));
        }
        return true;
      };
      if (!ParseArray(Root, "Processes", ParseProcess, Parsed.Processes) ||
          !ParseArray(Root, "Drivers", ParseDriver, Parsed.Drivers) ||
          !ParseArray(Root, "Callbacks", ParseCallback, Parsed.Callbacks)) {
        return false;
      }
      Out = std::move(Parsed);
      return true;
    }

    static QByteArray SerializeDocument(const SnapshotDocument &Document) {
      QJsonObject Root;
      Root.insert("Meta", ToJson(Document.Meta));
      QJsonArray Processes;
      for (const ProcessSnapshotEntry &Entry : Document.Processes)
        Processes.append(ToJson(Entry));
      QJsonArray Drivers;
      for (const DriverSnapshotEntry &Entry : Document.Drivers)
        Drivers.append(ToJson(Entry));
      QJsonArray Callbacks;
      for (const CallbackSnapshotEntry &Entry : Document.Callbacks)
        Callbacks.append(ToJson(Entry));
      Root.insert("Processes", Processes);
      Root.insert("Drivers", Drivers);
      Root.insert("Callbacks", Callbacks);
      return QJsonDocument(Root).toJson(QJsonDocument::Indented);
    }

    static void AddUniqueDiffEntry(QHash<QString, QJsonObject> &Map,
                                   QHash<QString, QString> &Names,
                                   const QString &Group, const QString &Key,
                                   const QJsonObject &Object,
                                   const QString &Name,
                                   QStringList &Warnings) {
      if (Map.contains(Key)) {
        Warnings.append(QString("%1 duplicate key `%2` detected; kept first entry.")
                            .arg(Group, Key));
        return;
      }
      Map.insert(Key, Object);
      Names.insert(Key, Name);
    }

    static std::vector<DiffRow>
    BuildProcessDiffRows(const std::vector<ProcessSnapshotEntry> &OldEntries,
                         const std::vector<ProcessSnapshotEntry> &NewEntries,
                         DiffStats &Stats, QStringList &Warnings) {
      std::vector<DiffRow> Rows;
      QHash<QString, QJsonObject> OldMap;
      QHash<QString, QString> OldNames;
      QHash<QString, QJsonObject> NewMap;
      QHash<QString, QString> NewNames;
      for (const ProcessSnapshotEntry &Entry : OldEntries)
        AddUniqueDiffEntry(OldMap, OldNames, "Processes", ProcessKey(Entry),
                           ToJson(Entry),
                           Entry.ImageName.isEmpty() ? QString::number(Entry.Pid)
                                                     : Entry.ImageName,
                           Warnings);
      for (const ProcessSnapshotEntry &Entry : NewEntries)
        AddUniqueDiffEntry(NewMap, NewNames, "Processes", ProcessKey(Entry),
                           ToJson(Entry),
                           Entry.ImageName.isEmpty() ? QString::number(Entry.Pid)
                                                     : Entry.ImageName,
                           Warnings);
      for (auto It = NewMap.cbegin(); It != NewMap.cend(); ++It) {
        if (!OldMap.contains(It.key())) {
          DiffRow Row;
          Row.Category = "Processes";
          Row.State = "Added";
          Row.Key = It.key();
          Row.PrimaryName = NewNames.value(It.key());
          Row.Summary = "Present only in snapshot B";
          Row.NewValue = It.value();
          Rows.push_back(std::move(Row));
          Stats.Added++;
        }
      }
      for (auto It = OldMap.cbegin(); It != OldMap.cend(); ++It) {
        if (!NewMap.contains(It.key())) {
          DiffRow Row;
          Row.Category = "Processes";
          Row.State = "Removed";
          Row.Key = It.key();
          Row.PrimaryName = OldNames.value(It.key());
          Row.Summary = "Present only in snapshot A";
          Row.OldValue = It.value();
          Rows.push_back(std::move(Row));
          Stats.Removed++;
        }
      }
      for (auto It = NewMap.cbegin(); It != NewMap.cend(); ++It) {
        if (!OldMap.contains(It.key()))
          continue;
        const QJsonObject OldObject = OldMap.value(It.key());
        const QJsonObject NewObject = It.value();
        if (OldObject == NewObject)
          continue;
        DiffRow Row;
        Row.Category = "Processes";
        Row.State = "Modified";
        Row.Key = It.key();
        Row.PrimaryName = NewNames.value(It.key());
        Row.Summary = ProcessSummary(OldObject, NewObject, &Row.ChangedFields);
        Row.OldValue = OldObject;
        Row.NewValue = NewObject;
        Rows.push_back(std::move(Row));
        Stats.Modified++;
      }
      Stats.Warnings = Warnings.size();
      std::stable_sort(Rows.begin(), Rows.end(),
                       [](const DiffRow &Left, const DiffRow &Right) {
                         if (Left.State != Right.State)
                           return Left.State < Right.State;
                         return Left.Key < Right.Key;
                       });
      return Rows;
    }

    static std::vector<DiffRow>
    BuildDriverDiffRows(const std::vector<DriverSnapshotEntry> &OldEntries,
                        const std::vector<DriverSnapshotEntry> &NewEntries,
                        DiffStats &Stats, QStringList &Warnings) {
      std::vector<DiffRow> Rows;
      QHash<QString, QJsonObject> OldMap;
      QHash<QString, QString> OldNames;
      QHash<QString, QJsonObject> NewMap;
      QHash<QString, QString> NewNames;
      for (const DriverSnapshotEntry &Entry : OldEntries)
        AddUniqueDiffEntry(OldMap, OldNames, "Drivers", DriverKey(Entry),
                           ToJson(Entry),
                           Entry.ServiceName.isEmpty() ? Entry.ImagePath
                                                       : Entry.ServiceName,
                           Warnings);
      for (const DriverSnapshotEntry &Entry : NewEntries)
        AddUniqueDiffEntry(NewMap, NewNames, "Drivers", DriverKey(Entry),
                           ToJson(Entry),
                           Entry.ServiceName.isEmpty() ? Entry.ImagePath
                                                       : Entry.ServiceName,
                           Warnings);
      for (auto It = NewMap.cbegin(); It != NewMap.cend(); ++It) {
        if (!OldMap.contains(It.key())) {
          DiffRow Row;
          Row.Category = "Drivers";
          Row.State = "Added";
          Row.Key = It.key();
          Row.PrimaryName = NewNames.value(It.key());
          Row.Summary = "Present only in snapshot B";
          Row.NewValue = It.value();
          Rows.push_back(std::move(Row));
          Stats.Added++;
        }
      }
      for (auto It = OldMap.cbegin(); It != OldMap.cend(); ++It) {
        if (!NewMap.contains(It.key())) {
          DiffRow Row;
          Row.Category = "Drivers";
          Row.State = "Removed";
          Row.Key = It.key();
          Row.PrimaryName = OldNames.value(It.key());
          Row.Summary = "Present only in snapshot A";
          Row.OldValue = It.value();
          Rows.push_back(std::move(Row));
          Stats.Removed++;
        }
      }
      for (auto It = NewMap.cbegin(); It != NewMap.cend(); ++It) {
        if (!OldMap.contains(It.key()))
          continue;
        const QJsonObject OldObject = OldMap.value(It.key());
        const QJsonObject NewObject = It.value();
        if (OldObject == NewObject)
          continue;
        DiffRow Row;
        Row.Category = "Drivers";
        Row.State = "Modified";
        Row.Key = It.key();
        Row.PrimaryName = NewNames.value(It.key());
        Row.Summary = DriverSummary(OldObject, NewObject, &Row.ChangedFields);
        Row.OldValue = OldObject;
        Row.NewValue = NewObject;
        Rows.push_back(std::move(Row));
        Stats.Modified++;
      }
      Stats.Warnings = Warnings.size();
      std::stable_sort(Rows.begin(), Rows.end(),
                       [](const DiffRow &Left, const DiffRow &Right) {
                         if (Left.State != Right.State)
                           return Left.State < Right.State;
                         return Left.Key < Right.Key;
                       });
      return Rows;
    }

    static std::vector<DiffRow>
    BuildCallbackDiffRows(const std::vector<CallbackSnapshotEntry> &OldEntries,
                          const std::vector<CallbackSnapshotEntry> &NewEntries,
                          DiffStats &Stats, QStringList &Warnings) {
      std::vector<DiffRow> Rows;
      QHash<QString, QJsonObject> OldMap;
      QHash<QString, QString> OldNames;
      QHash<QString, QJsonObject> NewMap;
      QHash<QString, QString> NewNames;
      for (const CallbackSnapshotEntry &Entry : OldEntries)
        AddUniqueDiffEntry(OldMap, OldNames, "Callbacks", CallbackKey(Entry),
                           ToJson(Entry),
                           Entry.ModuleName.isEmpty() ? Entry.Type
                                                      : Entry.ModuleName,
                           Warnings);
      for (const CallbackSnapshotEntry &Entry : NewEntries)
        AddUniqueDiffEntry(NewMap, NewNames, "Callbacks", CallbackKey(Entry),
                           ToJson(Entry),
                           Entry.ModuleName.isEmpty() ? Entry.Type
                                                      : Entry.ModuleName,
                           Warnings);
      for (auto It = NewMap.cbegin(); It != NewMap.cend(); ++It) {
        if (!OldMap.contains(It.key())) {
          DiffRow Row;
          Row.Category = "Callbacks";
          Row.State = "Added";
          Row.Key = It.key();
          Row.PrimaryName = NewNames.value(It.key());
          Row.Summary = "Present only in snapshot B";
          Row.NewValue = It.value();
          Rows.push_back(std::move(Row));
          Stats.Added++;
        }
      }
      for (auto It = OldMap.cbegin(); It != OldMap.cend(); ++It) {
        if (!NewMap.contains(It.key())) {
          DiffRow Row;
          Row.Category = "Callbacks";
          Row.State = "Removed";
          Row.Key = It.key();
          Row.PrimaryName = OldNames.value(It.key());
          Row.Summary = "Present only in snapshot A";
          Row.OldValue = It.value();
          Rows.push_back(std::move(Row));
          Stats.Removed++;
        }
      }
      for (auto It = NewMap.cbegin(); It != NewMap.cend(); ++It) {
        if (!OldMap.contains(It.key()))
          continue;
        const QJsonObject OldObject = OldMap.value(It.key());
        const QJsonObject NewObject = It.value();
        if (OldObject == NewObject)
          continue;
        DiffRow Row;
        Row.Category = "Callbacks";
        Row.State = "Modified";
        Row.Key = It.key();
        Row.PrimaryName = NewNames.value(It.key());
        Row.Summary = CallbackSummary(OldObject, NewObject, &Row.ChangedFields);
        Row.OldValue = OldObject;
        Row.NewValue = NewObject;
        Rows.push_back(std::move(Row));
        Stats.Modified++;
      }
      Stats.Warnings = Warnings.size();
      std::stable_sort(Rows.begin(), Rows.end(),
                       [](const DiffRow &Left, const DiffRow &Right) {
                         if (Left.State != Right.State)
                           return Left.State < Right.State;
                         return Left.Key < Right.Key;
                       });
      return Rows;
    }

    static SnapshotDiffResult BuildDiff(const SnapshotDocument &A,
                                        const SnapshotDocument &B) {
      SnapshotDiffResult Result;
      Result.Processes =
          BuildProcessDiffRows(A.Processes, B.Processes, Result.ProcessStats,
                               Result.Warnings);
      Result.Drivers =
          BuildDriverDiffRows(A.Drivers, B.Drivers, Result.DriverStats,
                              Result.Warnings);
      Result.Callbacks =
          BuildCallbackDiffRows(A.Callbacks, B.Callbacks, Result.CallbackStats,
                                Result.Warnings);
      return Result;
    }

    TableWidget *CreateDiffTable(const QStringList &Headers) {
      auto *Table = MakeTable(Headers);
      Table->setSelectionMode(QAbstractItemView::SingleSelection);
      Table->setSelectionBehavior(QAbstractItemView::SelectRows);
      Table->setSortingEnabled(true);
      Table->horizontalHeader()->setSectionResizeMode(
          0, QHeaderView::ResizeToContents);
      Table->horizontalHeader()->setSectionResizeMode(
          1, QHeaderView::ResizeToContents);
      Table->horizontalHeader()->setSectionResizeMode(
          2, QHeaderView::ResizeToContents);
      Table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
      return Table;
    }

    void InitializeSlotTableRow(int Row, const QString &Name) {
      for (int Column = 0; Column < SlotTable->columnCount(); ++Column)
        SlotTable->setItem(Row, Column, new QTableWidgetItem);
      SlotTable->item(Row, 0)->setText(Name);
      SlotTable->setRowHeight(Row, KCompactTableRowHeight);
    }

    void ConnectDiffDoubleClick(TableWidget *Table, DiffCategory Category) {
      QObject::connect(
          Table, &QTableWidget::cellDoubleClicked, this,
          [this, Table, Category](int Row, int) {
            if (Row < 0 || Row >= Table->rowCount())
              return;
            const QTableWidgetItem *Item = Table->item(Row, 0);
            if (!Item)
              return;
            const int Index = Item->data(Qt::UserRole).toInt();
            const std::vector<DiffRow> *Rows = nullptr;
            switch (Category) {
            case DiffCategory::Process:
              Rows = &LastDiff.Processes;
              break;
            case DiffCategory::Driver:
              Rows = &LastDiff.Drivers;
              break;
            case DiffCategory::Callback:
              Rows = &LastDiff.Callbacks;
              break;
            }
            if (!Rows)
              return;
            if (Index < 0 || Index >= static_cast<int>(Rows->size()))
              return;
            ShowDiffDetails((*Rows)[static_cast<size_t>(Index)]);
          });
    }

    void ShowDiffDetails(const DiffRow &Row) {
      auto *Dialog = new QDialog(this);
      Dialog->setAttribute(Qt::WA_DeleteOnClose);
      Dialog->setWindowTitle(Row.Category + " Diff Details");
      Dialog->resize(980, 640);
      auto *Layout = new QVBoxLayout(Dialog);
      auto *Summary = new BodyLabel(
          QString("%1 | %2 | %3").arg(Row.State, Row.Key, Row.PrimaryName));
      Layout->addWidget(Summary);
      auto *Fields = new BodyLabel("Changed fields: " +
                                   (Row.ChangedFields.isEmpty()
                                        ? QString("(none)")
                                        : Row.ChangedFields.join(", ")));
      Fields->setWordWrap(true);
      Layout->addWidget(Fields);
      auto *Splitter = new QSplitter(Qt::Horizontal);
      auto *OldText = new PlainTextEdit;
      auto *NewText = new PlainTextEdit;
      OldText->setReadOnly(true);
      NewText->setReadOnly(true);
      OldText->setFont(QFont("Cascadia Mono", 10));
      NewText->setFont(QFont("Cascadia Mono", 10));
      OldText->setPlainText(
          QString::fromUtf8(QJsonDocument(Row.OldValue).toJson(
                                QJsonDocument::Indented))
              .trimmed());
      NewText->setPlainText(
          QString::fromUtf8(QJsonDocument(Row.NewValue).toJson(
                                QJsonDocument::Indented))
              .trimmed());
      Splitter->addWidget(OldText);
      Splitter->addWidget(NewText);
      Layout->addWidget(Splitter, 1);
      auto *Close = MakeButton("Close", true);
      Layout->addWidget(Close, 0, Qt::AlignRight);
      QObject::connect(Close, &QPushButton::clicked, Dialog, &QDialog::accept);
      Dialog->show();
    }

    void UpdateSlotRow(int Row, const std::optional<SnapshotDocument> &Document) {
      if (!Document.has_value()) {
        SlotTable->item(Row, 1)->setText("-");
        SlotTable->item(Row, 2)->setText("-");
        SlotTable->item(Row, 3)->setText("Empty");
        return;
      }
      const SnapshotDocument &Value = *Document;
      SlotTable->item(Row, 1)->setText(Value.Meta.CapturedAtUtc);
      SlotTable->item(Row, 2)->setText(Value.Source);
      SlotTable->item(Row, 3)->setText(
          QString("P:%1 D:%2 C:%3")
              .arg(Value.Processes.size())
              .arg(Value.Drivers.size())
              .arg(Value.Callbacks.size()));
    }

    void RefreshUiState() {
      UpdateSlotRow(0, SnapshotA);
      UpdateSlotRow(1, SnapshotB);
      const bool HasA = SnapshotA.has_value();
      const bool HasB = SnapshotB.has_value();
      SaveButton->setEnabled(SelectedSnapshot().has_value());
      CompareButton->setEnabled(HasA && HasB);
      QStringList Parts;
      const auto AppendSnapshotState = [&Parts](const char *Name,
                                                const std::optional<SnapshotDocument> &Doc) {
        if (!Doc.has_value())
          return;
        Parts.append(QString("%1:%2 %3 P:%4 D:%5 C:%6")
                         .arg(Name)
                         .arg(Doc->Source)
                         .arg(Doc->Meta.CapturedAtUtc)
                         .arg(Doc->Processes.size())
                         .arg(Doc->Drivers.size())
                         .arg(Doc->Callbacks.size()));
      };
      AppendSnapshotState("A", SnapshotA);
      AppendSnapshotState("B", SnapshotB);
      if (HasDiff()) {
        Parts.append(QString("Diff Added:%1 Removed:%2 Modified:%3")
                         .arg(LastDiff.ProcessStats.Added +
                              LastDiff.DriverStats.Added +
                              LastDiff.CallbackStats.Added)
                         .arg(LastDiff.ProcessStats.Removed +
                              LastDiff.DriverStats.Removed +
                              LastDiff.CallbackStats.Removed)
                         .arg(LastDiff.ProcessStats.Modified +
                              LastDiff.DriverStats.Modified +
                              LastDiff.CallbackStats.Modified));
      }
      if (!Busy)
        StatusLabel->setText(Parts.isEmpty() ? "Ready" : Parts.join(" | "));
    }

    bool HasDiff() const {
      return !LastDiff.Processes.empty() || !LastDiff.Drivers.empty() ||
             !LastDiff.Callbacks.empty() || !LastDiff.Warnings.isEmpty();
    }

    std::optional<SnapshotDocument> SelectedSnapshot() const {
      const int Row = SlotTable->currentRow();
      if (Row == 0)
        return SnapshotA;
      if (Row == 1)
        return SnapshotB;
      return std::nullopt;
    }

    std::optional<SnapshotDocument> *SelectedSnapshotSlot() {
      const int Row = SlotTable->currentRow();
      if (Row == 0)
        return &SnapshotA;
      if (Row == 1)
        return &SnapshotB;
      return nullptr;
    }

    SlotKind ChooseReplacementSlot(const QString &Action) {
      if (!SnapshotA.has_value())
        return SlotKind::A;
      if (!SnapshotB.has_value())
        return SlotKind::B;
      QMessageBox Message(this);
      Message.setWindowTitle(Action);
      Message.setText("Snapshot A and B already exist. Choose a slot to overwrite.");
      QPushButton *OverwriteA = Message.addButton("Overwrite A",
                                                  QMessageBox::AcceptRole);
      QPushButton *OverwriteB = Message.addButton("Overwrite B",
                                                  QMessageBox::AcceptRole);
      Message.addButton("Cancel", QMessageBox::RejectRole);
      Message.exec();
      if (Message.clickedButton() == OverwriteB)
        return SlotKind::B;
      if (Message.clickedButton() == OverwriteA)
        return SlotKind::A;
      return SlotKind::A;
    }

    std::optional<SlotKind> DecideTargetSlot(const QString &Action) {
      if (!SnapshotA.has_value())
        return SlotKind::A;
      if (!SnapshotB.has_value())
        return SlotKind::B;
      QMessageBox Message(this);
      Message.setWindowTitle(Action);
      Message.setText("Snapshot A and B already exist. Choose a slot to overwrite.");
      QPushButton *OverwriteA = Message.addButton("Overwrite A",
                                                  QMessageBox::AcceptRole);
      QPushButton *OverwriteB = Message.addButton("Overwrite B",
                                                  QMessageBox::AcceptRole);
      Message.addButton("Cancel", QMessageBox::RejectRole);
      Message.exec();
      if (Message.clickedButton() == OverwriteA)
        return SlotKind::A;
      if (Message.clickedButton() == OverwriteB)
        return SlotKind::B;
      return std::nullopt;
    }

    void AssignSnapshot(SlotKind Slot, SnapshotDocument Document) {
      if (Slot == SlotKind::A)
        SnapshotA = std::move(Document);
      else
        SnapshotB = std::move(Document);
      ClearDiffViews();
      RefreshUiState();
    }

    void SetBusy(const QString &Text) {
      Busy = true;
      StatusLabel->setText(Text);
      ProgressRing->show();
      ProgressRing->start();
      CaptureButton->setEnabled(false);
      LoadButton->setEnabled(false);
      SaveButton->setEnabled(false);
      CompareButton->setEnabled(false);
      ClearButton->setEnabled(false);
    }

    void ClearBusy() {
      Busy = false;
      ProgressRing->stop();
      ProgressRing->hide();
      CaptureButton->setEnabled(true);
      LoadButton->setEnabled(true);
      ClearButton->setEnabled(true);
      RefreshUiState();
    }

    void CaptureIntoNextSlot() {
      if (Busy)
        return;
      const std::optional<SlotKind> Slot = DecideTargetSlot("Capture Snapshot");
      if (!Slot.has_value())
        return;
      SetBusy("Capturing snapshot...");
      QPointer<SnapshotLabPage> Page(this);
      std::thread([Page, Slot = *Slot] {
        CaptureResult Result = CaptureSnapshotDocument();
        QMetaObject::invokeMethod(
            qApp,
            [Page, Slot, Result = std::move(Result)]() mutable {
              if (!Page)
                return;
              Page->AssignSnapshot(Slot, std::move(Result.Document));
              Page->ClearBusy();
              QString Message =
                  QString("Captured snapshot. Processes:%1 Drivers:%2 Callbacks:%3")
                      .arg(Page->SnapshotFor(Slot)->value().Processes.size())
                      .arg(Page->SnapshotFor(Slot)->value().Drivers.size())
                      .arg(Page->SnapshotFor(Slot)->value().Callbacks.size());
              if (!Result.Failures.isEmpty()) {
                Message += "\nFailures:\n" + Result.Failures.join("\n");
                ShowWarningNotice(Page, "SnapshotLab", Message);
              } else {
                ShowSuccessNotice(Page, "SnapshotLab", Message);
              }
            },
            Qt::QueuedConnection);
      }).detach();
    }

    std::optional<SnapshotDocument> *SnapshotFor(SlotKind Slot) {
      return Slot == SlotKind::A ? &SnapshotA : &SnapshotB;
    }

    void LoadSnapshotFromJson() {
      if (Busy)
        return;
      const QString Path = QFileDialog::getOpenFileName(
          this, "Load Snapshot JSON", QString(),
          "Aegis Snapshot (*.aegis-snapshot.json);;JSON (*.json)");
      if (Path.isEmpty())
        return;
      const std::optional<SlotKind> Slot = DecideTargetSlot("Load Snapshot JSON");
      if (!Slot.has_value())
        return;
      QFile File(Path);
      if (!File.open(QIODevice::ReadOnly)) {
        ShowErrorNotice(this, "SnapshotLab",
                        "Unable to open file.\n" + QDir::toNativeSeparators(Path));
        return;
      }
      SnapshotDocument Document;
      QString Error;
      if (!ParseDocument(File.readAll(), Document, Error)) {
        ShowErrorNotice(this, "SnapshotLab", Error);
        return;
      }
      Document.LoadPath = QDir::toNativeSeparators(Path);
      AssignSnapshot(*Slot, std::move(Document));
      ShowSuccessNotice(this, "SnapshotLab",
                        "Snapshot JSON loaded.\n" +
                            QDir::toNativeSeparators(Path));
    }

    void SaveSelectedSnapshot() {
      const std::optional<SnapshotDocument> Document = SelectedSnapshot();
      if (!Document.has_value()) {
        ShowWarningNotice(this, "SnapshotLab",
                          "Select Snapshot A or B before saving.");
        return;
      }
      const QString DefaultName =
          QString("snapshot-%1.aegis-snapshot.json")
              .arg(QDateTime::currentDateTimeUtc().toString("yyyyMMdd-hhmmss"));
      const QString Path = QFileDialog::getSaveFileName(
          this, "Save Snapshot JSON", DefaultName,
          "Aegis Snapshot (*.aegis-snapshot.json)");
      if (Path.isEmpty())
        return;
      QSaveFile File(Path);
      if (!File.open(QIODevice::WriteOnly)) {
        ShowErrorNotice(this, "SnapshotLab",
                        "Unable to open file for writing.\n" +
                            QDir::toNativeSeparators(Path));
        return;
      }
      File.write(SerializeDocument(*Document));
      if (!File.commit()) {
        ShowErrorNotice(this, "SnapshotLab",
                        "Failed to save snapshot JSON.\n" +
                            QDir::toNativeSeparators(Path));
        return;
      }
      ShowSuccessNotice(this, "SnapshotLab",
                        "Snapshot JSON saved.\n" +
                            QDir::toNativeSeparators(Path));
    }

    void CompareSnapshots() {
      if (!SnapshotA.has_value() || !SnapshotB.has_value()) {
        ShowWarningNotice(this, "SnapshotLab",
                          "Compare requires both Snapshot A and Snapshot B.");
        return;
      }
      LastDiff = BuildDiff(*SnapshotA, *SnapshotB);
      PopulateDiffTable(ProcessDiffTable, LastDiff.Processes);
      PopulateDiffTable(DriverDiffTable, LastDiff.Drivers);
      PopulateDiffTable(CallbackDiffTable, LastDiff.Callbacks);
      SummaryView->setPlainText(BuildSummaryText());
      RefreshUiState();
      if (!LastDiff.Warnings.isEmpty()) {
        ShowWarningNotice(this, "SnapshotLab",
                          "Compare completed with warnings.\n" +
                              LastDiff.Warnings.join("\n"));
      } else {
        ShowSuccessNotice(this, "SnapshotLab", "Compare completed.");
      }
    }

    void PopulateDiffTable(TableWidget *Table, const std::vector<DiffRow> &Rows) {
      Table->setSortingEnabled(false);
      Table->clearContents();
      Table->setRowCount(0);
      for (int Index = 0; Index < static_cast<int>(Rows.size()); ++Index) {
        const DiffRow &Row = Rows[static_cast<size_t>(Index)];
        const int TableRow = Table->rowCount();
        Table->insertRow(TableRow);
        auto *State = new QTableWidgetItem(Row.State);
        State->setData(Qt::UserRole, Index);
        Table->setItem(TableRow, 0, State);
        Table->setItem(TableRow, 1, new QTableWidgetItem(Row.Key));
        Table->setItem(TableRow, 2, new QTableWidgetItem(Row.PrimaryName));
        Table->setItem(TableRow, 3, new QTableWidgetItem(Row.Summary));
        Table->setRowHeight(TableRow, KCompactTableRowHeight);
      }
      Table->setSortingEnabled(true);
    }

    QString BuildSummaryText() const {
      QString Text;
      QTextStream Stream(&Text);
      Stream << "Snapshot A\n";
      Stream << "  Source: "
             << (SnapshotA.has_value() ? SnapshotA->Source : "-") << "\n";
      Stream << "  CapturedAtUtc: "
             << (SnapshotA.has_value() ? SnapshotA->Meta.CapturedAtUtc : "-")
             << "\n";
      Stream << "Snapshot B\n";
      Stream << "  Source: "
             << (SnapshotB.has_value() ? SnapshotB->Source : "-") << "\n";
      Stream << "  CapturedAtUtc: "
             << (SnapshotB.has_value() ? SnapshotB->Meta.CapturedAtUtc : "-")
             << "\n\n";
      const auto AppendStats = [&Stream](const char *Name, const DiffStats &Stats,
                                         int TotalRows) {
        Stream << Name << "\n";
        Stream << "  Added: " << Stats.Added << "\n";
        Stream << "  Removed: " << Stats.Removed << "\n";
        Stream << "  Modified: " << Stats.Modified << "\n";
        Stream << "  Total diff rows: " << TotalRows << "\n";
      };
      AppendStats("Processes", LastDiff.ProcessStats,
                  static_cast<int>(LastDiff.Processes.size()));
      AppendStats("Drivers", LastDiff.DriverStats,
                  static_cast<int>(LastDiff.Drivers.size()));
      AppendStats("Callbacks", LastDiff.CallbackStats,
                  static_cast<int>(LastDiff.Callbacks.size()));
      if (!LastDiff.Warnings.isEmpty()) {
        Stream << "\nWarnings\n";
        for (const QString &Warning : LastDiff.Warnings)
          Stream << "  - " << Warning << "\n";
      }
      return Text.trimmed();
    }

    void ClearDiffViews() {
      LastDiff = SnapshotDiffResult{};
      ProcessDiffTable->clearContents();
      ProcessDiffTable->setRowCount(0);
      DriverDiffTable->clearContents();
      DriverDiffTable->setRowCount(0);
      CallbackDiffTable->clearContents();
      CallbackDiffTable->setRowCount(0);
      SummaryView->clear();
    }

    void ClearAll() {
      if (Busy)
        return;
      SnapshotA.reset();
      SnapshotB.reset();
      ClearDiffViews();
      RefreshUiState();
      ShowSuccessNotice(this, "SnapshotLab",
                        "Snapshot A, Snapshot B, and diff results cleared.");
    }

    PushButton *CaptureButton = nullptr;
    PushButton *LoadButton = nullptr;
    PushButton *SaveButton = nullptr;
    PushButton *CompareButton = nullptr;
    PushButton *ClearButton = nullptr;
    IndeterminateProgressRing *ProgressRing = nullptr;
    BodyLabel *StatusLabel = nullptr;
    TableWidget *SlotTable = nullptr;
    QListWidget *DiffViewList = nullptr;
    QStackedWidget *DiffPages = nullptr;
    TableWidget *ProcessDiffTable = nullptr;
    TableWidget *DriverDiffTable = nullptr;
    TableWidget *CallbackDiffTable = nullptr;
    PlainTextEdit *SummaryView = nullptr;
    bool Busy = false;
    std::optional<SnapshotDocument> SnapshotA;
    std::optional<SnapshotDocument> SnapshotB;
    SnapshotDiffResult LastDiff;
  };

  return new SnapshotLabPage;
}
