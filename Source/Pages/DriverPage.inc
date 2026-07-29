class DriverManagerPage final : public QWidget
{
    struct DriverRow
    {
        QString Name;
        QString DisplayName;
        QString Path;
        QString RegistryPath;
        QString SymbolNames;
        QString DeviceLinks;
        QString SearchText;
        DWORD State = 0;
        DWORD Type = 0;
        DWORD StartType = 0;
        DWORD ErrorControl = 0;
        ULONG_PTR DriverObject = 0;
        ULONG_PTR ImageBase = 0;
        DWORD ImageSize = 0;
        UserFileTrustInfo Trust;
    };
    struct DriverRefreshResult
    {
        std::vector<DriverRow> Rows;
        DWORD ErrorCode = ERROR_SUCCESS;
        NTSTATUS NtStatus = 0;
        bool Success = false;
    };
  public:
    explicit DriverManagerPage(QWidget *Parent = nullptr) : QWidget(Parent)
    {
        auto *Layout = new QVBoxLayout(this); ConfigurePageLayout(Layout);
        auto *LoadButton = MakeButton("Load", true);
        auto *FilterLayout = new QHBoxLayout;
        ConfigureToolbarLayout(FilterLayout);
        SearchEdit = new SearchLineEdit;
        ConfigureSearchLineEdit(SearchEdit, "Search service, display name, path, or state", KStandardWideSearchWidth);
        RefreshIndicator = new IndeterminateProgressRing(this, false);
        RefreshIndicator->setFixedSize(22, 22);
        RefreshIndicator->hide();
        ConfigureActionButton(LoadButton);
        RefreshButton = MakeButton("Refresh", true);
        ConfigureActionButton(RefreshButton);
        FilterLayout->addWidget(SearchEdit, 0, Qt::AlignLeft | Qt::AlignVCenter);
        FilterLayout->addStretch(1);
        FilterLayout->addWidget(RefreshIndicator, 0, Qt::AlignVCenter);
        FilterLayout->addWidget(LoadButton, 0, Qt::AlignRight | Qt::AlignVCenter);
        FilterLayout->addWidget(RefreshButton, 0, Qt::AlignRight | Qt::AlignVCenter);
        Layout->addLayout(FilterLayout);
        DriverTable = MakeTable({"Service", "Display name", "State", "Type", "Object", "Base", "Size", "Symbol", "Device links", "Signature", "SHA-256", "Path"});
        DriverTable->setSelectionMode(QAbstractItemView::SingleSelection); DriverTable->setContextMenuPolicy(Qt::CustomContextMenu);
        DriverTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        DriverTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
        DriverTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
        DriverTable->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
        DriverTable->horizontalHeader()->setSectionResizeMode(6, QHeaderView::ResizeToContents);
        DriverTable->horizontalHeader()->setSectionResizeMode(7, QHeaderView::Stretch);
        DriverTable->horizontalHeader()->setSectionResizeMode(8, QHeaderView::Stretch);
        DriverTable->horizontalHeader()->setSectionResizeMode(9, QHeaderView::ResizeToContents);
        DriverTable->horizontalHeader()->setSectionResizeMode(10, QHeaderView::Stretch);
        DriverTable->horizontalHeader()->setSectionResizeMode(11, QHeaderView::Stretch); Layout->addWidget(DriverTable, 1);
        QObject::connect(LoadButton, &QPushButton::clicked, this, [this] { ShowLoadDriverDialog(); });
        SearchDebounceTimer = new QTimer(this);
        SearchDebounceTimer->setSingleShot(true);
        SearchDebounceTimer->setInterval(KSearchDebounceMs);
        QObject::connect(RefreshButton, &QPushButton::clicked, this, [this] { StartRefresh(true); });
        QObject::connect(SearchDebounceTimer, &QTimer::timeout, this, [this] { ApplySearchFilter(); });
        QObject::connect(SearchEdit, &QLineEdit::textChanged, this, [this] { SearchDebounceTimer->start(); });
        QObject::connect(DriverTable, &QWidget::customContextMenuRequested, this, [this](const QPoint &Position) {
            const QModelIndex Index = DriverTable->indexAt(Position); if (!Index.isValid()) return; DriverTable->selectRow(Index.row());
            const QString Name = DriverTable->item(Index.row(), 0)->text();
            auto *Menu = new RoundMenu(QString(), this);
            auto *InspectAction = new QAction("Inspect", Menu); Menu->addAction(InspectAction);
            ConnectMenuAction(InspectAction, this, [this, Name] { ShowDriverInspector(Name); });
            auto *UnloadAction = new QAction("Unload", Menu); Menu->addAction(UnloadAction);
            ConnectMenuAction(UnloadAction, this, [this, Name] {
                if (QMessageBox::question(this, "Unload Driver", "Unload driver and remove service " + Name + " if possible?") != QMessageBox::Yes) return;
                const auto DescribeWin32Error = [](DWORD ErrorCode) {
                    QString Message = QString("Win32 error: %1").arg(ErrorCode);
                    LPWSTR Buffer = nullptr;
                    const DWORD Length = FormatMessageW(
                        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                        nullptr,
                        ErrorCode,
                        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                        reinterpret_cast<LPWSTR>(&Buffer),
                        0,
                        nullptr);
                    if (Length != 0 && Buffer != nullptr) {
                        QString Reason = QString::fromWCharArray(Buffer).trimmed();
                        if (!Reason.isEmpty())
                            Message += "\nReason: " + Reason;
                    }
                    if (Buffer != nullptr)
                        LocalFree(Buffer);
                    return Message;
                };
                const auto BuildUnloadDriverError = [&](const DRIVER_CONTROL_OUTPUT &Output) {
                    const bool HasKernelResult =
                        Output.NtStatus != 0 ||
                        Output.Message[0] != L'\0' ||
                        Output.RegistryPath[0] != L'\0' ||
                        Output.ImagePath[0] != L'\0' ||
                        Output.State != 0 ||
                        Output.Type != 0 ||
                        Output.StartType != 0 ||
                        Output.ErrorControl != 0 ||
                        Output.DriverObject != 0 ||
                        Output.ImageBase != 0 ||
                        Output.ImageSize != 0;
                    const QString DriverMessage = HasKernelResult
                        ? QString::fromWCharArray(Output.Message[0] ? Output.Message : L"Kernel driver unload failed.")
                        : "DeviceIoControl(IOCTL_UNLOAD_DRIVER) failed before the driver returned a result.";
                    QString Message = QString("%1\nService: %2\nWin32 error: %3")
                        .arg(DriverMessage)
                        .arg(Name)
                        .arg(G_LastMultiDrvError);
                    if (HasKernelResult)
                        Message += QString("\nNTSTATUS: 0x%1").arg(static_cast<quint32>(Output.NtStatus), 8, 16, QLatin1Char('0'));
                    else
                        Message += "\nNTSTATUS: unavailable (IOCTL failed)";
                    if (HasKernelResult && Output.RegistryPath[0] != L'\0')
                        Message += "\nRegistry: " + QString::fromWCharArray(Output.RegistryPath);
                    if (HasKernelResult && Output.ImagePath[0] != L'\0')
                        Message += "\nImagePath: " + QString::fromWCharArray(Output.ImagePath);
                    return Message;
                };

                DRIVER_CONTROL_OUTPUT Output{};
                const std::wstring ServiceName = Name.toStdWString();
                const bool IsMultiDrv = Name.compare("MultiDrv", Qt::CaseInsensitive) == 0;
                if (IsMultiDrv) {
                    if (UnloadDriverService(ServiceName.c_str()) == 0)
                        ShowSuccessNotice(this, "Driver", "Driver unloaded via SCM mode.");
                    else
                        ShowErrorNotice(this, "Driver", "SCM unload failed.\nService: " + Name + "\n" + DescribeWin32Error(GetLastError()));
                    StartRefresh(false);
                    return;
                }

                if (!UnloadDriverKernel(ServiceName.c_str(), FALSE, &Output)) {
                    const QString KernelUnloadError = BuildUnloadDriverError(Output);
                    if (UnloadDriverService(ServiceName.c_str()) == 0) {
                        ShowSuccessNotice(this, "Driver",
                                          "Kernel unload failed; unloaded via SCM fallback.\nService: " + Name);
                    } else {
                        const DWORD ScmError = GetLastError();
                        ShowErrorNotice(this, "Driver",
                                        KernelUnloadError +
                                        "\n\nSCM fallback failed.\nService: " + Name + "\n" +
                                        DescribeWin32Error(ScmError));
                    }
                } else {
                    QString SuccessMessage = QString::fromWCharArray(
                        Output.Message[0] ? Output.Message : L"Kernel driver unloaded.");
                    if (UnloadDriverService(ServiceName.c_str()) == 0)
                        SuccessMessage += "\nSCM cleanup completed.";
                    else
                        SuccessMessage += "\nSCM cleanup failed.\n" + DescribeWin32Error(GetLastError());
                    ShowSuccessNotice(this, "Driver", SuccessMessage);
                }
                StartRefresh(false);
            });
            ReleaseMenuAfterClose(Menu); Menu->exec(DriverTable->viewport()->mapToGlobal(Position));
        });
        StartRefresh(false);
    }
  private:
    void ShowLoadDriverDialog()
    {
        auto *Dialog = new QDialog(this);
        Dialog->setAttribute(Qt::WA_DeleteOnClose);
        Dialog->setWindowTitle("Load Driver");
        Dialog->setModal(true);
        Dialog->resize(560, 180);

        auto *Layout = new QVBoxLayout(Dialog);
        Layout->setContentsMargins(20, 18, 20, 18);
        Layout->setSpacing(14);

        auto *ServiceEdit = new LineEdit;
        ServiceEdit->setPlaceholderText("Service name");

        auto *PathEdit = new LineEdit;
        PathEdit->setPlaceholderText("Driver .sys path");
        auto *ModeCombo = new ComboBox;
        ModeCombo->addItems({"KernelMode", "SCMMode"});
        ModeCombo->setCurrentIndex(0);
        auto *BypassSignatureCheck = new CheckBox("Bypass Signature Verification (BSOD Warning)");
        auto *BrowseButton = MakeButton("Browse");
        auto *PathLayout = new QHBoxLayout;
        ConfigureToolbarLayout(PathLayout);
        PathLayout->addWidget(PathEdit, 1);
        PathLayout->addWidget(BrowseButton);

        auto *ButtonLayout = new QHBoxLayout;
        ConfigureToolbarLayout(ButtonLayout);
        ButtonLayout->addStretch(1);
        auto *CancelButton = MakeButton("Cancel");
        auto *ConfirmButton = MakeButton("Load", true);
        ButtonLayout->addWidget(CancelButton);
        ButtonLayout->addWidget(ConfirmButton);

        Layout->addWidget(MakeLabel("Service name", 11, KTextPrimary, QFont::DemiBold));
        Layout->addWidget(ServiceEdit);
        Layout->addWidget(MakeLabel("Driver path", 11, KTextPrimary, QFont::DemiBold));
        Layout->addLayout(PathLayout);
        Layout->addWidget(MakeLabel("Load mode", 11, KTextPrimary, QFont::DemiBold));
        Layout->addWidget(ModeCombo);
        Layout->addWidget(BypassSignatureCheck);
        Layout->addLayout(ButtonLayout);

        QObject::connect(ModeCombo, &ComboBox::currentTextChanged, Dialog, [BypassSignatureCheck](const QString &Text) {
            const bool KernelModeSelected = Text == "KernelMode";
            BypassSignatureCheck->setEnabled(KernelModeSelected);
            if (!KernelModeSelected)
                BypassSignatureCheck->setChecked(false);
        });

        QObject::connect(BrowseButton, &QPushButton::clicked, Dialog, [Dialog, PathEdit, ServiceEdit] {
            const QString Path = QFileDialog::getOpenFileName(Dialog, "Select Driver", PathEdit->text(), "Driver files (*.sys)");
            if (Path.isEmpty())
                return;
            PathEdit->setText(QDir::toNativeSeparators(Path));
            if (ServiceEdit->text().trimmed().isEmpty())
                ServiceEdit->setText(QFileInfo(Path).completeBaseName());
        });
        QObject::connect(CancelButton, &QPushButton::clicked, Dialog, &QDialog::reject);
        const auto BuildLoadDriverError = [](const DRIVER_CONTROL_OUTPUT &Output,
                                             const std::wstring &ServiceName,
                                             const std::wstring &RequestedPath,
                                             const std::wstring &KernelPath) {
            const bool HasKernelResult =
                Output.NtStatus != 0 ||
                Output.Message[0] != L'\0' ||
                Output.RegistryPath[0] != L'\0' ||
                Output.ImagePath[0] != L'\0' ||
                Output.State != 0 ||
                Output.Type != 0 ||
                Output.StartType != 0 ||
                Output.ErrorControl != 0 ||
                Output.DriverObject != 0 ||
                Output.ImageBase != 0 ||
                Output.ImageSize != 0;
            const QString DriverMessage = HasKernelResult
                ? QString::fromWCharArray(Output.Message[0] ? Output.Message : L"Kernel driver load failed.")
                : "DeviceIoControl(IOCTL_LOAD_DRIVER) failed before the driver returned a result.";
            const QString DriverDetails = QString::fromStdWString(G_LastMultiDrvDetails);
            const QString EffectiveKernelPath = QString::fromWCharArray(
                Output.ImagePath[0] ? Output.ImagePath : KernelPath.c_str());
            const QString EffectiveRegistryPath = QString::fromWCharArray(Output.RegistryPath);
            QString Message = QString("%1\nService: %2\nRequested path: %3\nKernel path: %4\nWin32 error: %5")
                .arg(DriverMessage)
                .arg(QString::fromStdWString(ServiceName))
                .arg(QString::fromStdWString(RequestedPath))
                .arg(EffectiveKernelPath)
                .arg(G_LastMultiDrvError);
            if (HasKernelResult)
                Message += QString("\nNTSTATUS: 0x%1").arg(static_cast<quint32>(Output.NtStatus), 8, 16, QLatin1Char('0'));
            else
                Message += "\nNTSTATUS: unavailable (IOCTL failed)";
            if (HasKernelResult && !EffectiveRegistryPath.isEmpty())
                Message += "\nRegistry: " + EffectiveRegistryPath;
            if (HasKernelResult && !DriverDetails.isEmpty())
                Message += "\nDetails: " + DriverDetails;
            return Message;
        };
        const auto DescribeWin32Error = [](DWORD ErrorCode) {
            QString Message = QString("Win32 error: %1").arg(ErrorCode);
            LPWSTR Buffer = nullptr;
            const DWORD Length = FormatMessageW(
                FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                nullptr,
                ErrorCode,
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                reinterpret_cast<LPWSTR>(&Buffer),
                0,
                nullptr);
            if (Length != 0 && Buffer != nullptr) {
                QString Reason = QString::fromWCharArray(Buffer).trimmed();
                if (!Reason.isEmpty())
                    Message += "\nReason: " + Reason;
            }
            if (Buffer != nullptr)
                LocalFree(Buffer);
            return Message;
        };
        QObject::connect(ConfirmButton, &QPushButton::clicked, Dialog, [this, Dialog, ServiceEdit, PathEdit, ModeCombo, BypassSignatureCheck, BuildLoadDriverError, DescribeWin32Error] {
            const QString RequestedPathText = QDir::toNativeSeparators(PathEdit->text().trimmed());
            const std::wstring Path = RequestedPathText.toStdWString();
            const std::wstring Name = ServiceEdit->text().trimmed().toStdWString();
            const bool BypassSignatureVerification = BypassSignatureCheck->isChecked();
            const bool UseKernelMode = ModeCombo->currentText() == "KernelMode";
            if (Path.empty() || Name.empty()) {
                ShowWarningNotice(Dialog, "Driver", "Enter a service name and driver path.");
                return;
            }
            if (!UseKernelMode) {
                if (LoadDriverService(Path.c_str(), Name.c_str()) == 0) {
                    ShowSuccessNotice(this, "Driver",
                                      "Driver loaded via SCM mode.\nRequested path: " + RequestedPathText);
                    Dialog->accept();
                    StartRefresh(false);
                    return;
                }

                ShowErrorNotice(Dialog, "Driver",
                                "SCM mode load failed.\nRequested path: " + RequestedPathText +
                                "\n" + DescribeWin32Error(GetLastError()));
                return;
            }
            QString KernelPathText;
            if (!ConvertDriverServiceImagePath(RequestedPathText, KernelPathText)) {
                ShowErrorNotice(Dialog, "Driver",
                                "Unable to convert path to kernel path.\nRequested path: " + RequestedPathText);
                return;
            }

            const std::wstring KernelPath = KernelPathText.toStdWString();
            DRIVER_CONTROL_OUTPUT Output{};
            const auto TryLoad = [&]() {
                return LoadDriverKernel(Name.c_str(), KernelPath.c_str(), &Output);
            };

            if (BypassSignatureVerification)
                DisableDse();

            if (!TryLoad()) {
                const QString KernelLoadError = BuildLoadDriverError(Output, Name, Path, KernelPath);
                if (BypassSignatureVerification)
                    RestoreDse();

                if (LoadDriverService(Path.c_str(), Name.c_str()) == 0) {
                    ShowSuccessNotice(this, "Driver",
                                      "Kernel load failed; loaded via SCM fallback.\n"
                                      "Requested path: " + RequestedPathText + "\n"
                                      "Kernel path: " + KernelPathText);
                    Dialog->accept();
                    StartRefresh(false);
                    return;
                }

                const DWORD ScmError = GetLastError();
                ShowErrorNotice(
                    Dialog,
                    "Driver",
                    KernelLoadError +
                    "\n\nSCM fallback failed.\nRequested path: " + RequestedPathText +
                    "\n" + DescribeWin32Error(ScmError));
                return;
            }

            ShowSuccessNotice(this, "Driver",
                              "Kernel driver loaded.\nKernel path: " + KernelPathText);
            if (BypassSignatureVerification)
                RestoreDse();
            Dialog->accept();
            StartRefresh(false);
        });

        Dialog->show();
    }

    void ShowDriverInspector(const QString &Name)
    {
        auto *Dialog = new QDialog(this); Dialog->setAttribute(Qt::WA_DeleteOnClose);
        Dialog->setWindowTitle("Driver Inspector - " + Name); Dialog->resize(1040, 680);
        auto *Layout = new QVBoxLayout(Dialog);
        ConfigurePageLayout(Layout);
        auto *Tabs = new TabBar;
        auto *Pages = new QStackedWidget;
        auto *Overview = MakeTable({"Kind", "Name", "Address", "Value", "Source"});
        auto *Dispatch = MakeTable({"Major function", "Address", "Source"});
        auto *Devices = MakeTable({"Device", "Attached", "Type", "Characteristics", "Flags", "Stack"});
        Tabs->addTab("overview", "Overview", Fluent::IconType::DOCUMENT);
        Tabs->addTab("dispatch", "Dispatch", Fluent::IconType::CODE);
        Tabs->addTab("devices", "Devices", Fluent::IconType::FOLDER);
        Pages->addWidget(Overview);
        Pages->addWidget(Dispatch);
        Pages->addWidget(Devices);
        QObject::connect(Tabs, &TabBar::currentChanged, Pages, &QStackedWidget::setCurrentIndex);
        QObject::connect(Pages, &QStackedWidget::currentChanged, Tabs, &TabBar::setCurrentIndex);
        Layout->addWidget(Tabs);
        Layout->addWidget(Pages, 1);

        auto *BottomLayout = new QHBoxLayout;
        ConfigureToolbarLayout(BottomLayout);
        auto *Loading = new IndeterminateProgressRing(Dialog, false);
        Loading->setFixedSize(22, 22);
        Loading->start();
        auto *Close = MakeButton("Close", true);
        BottomLayout->addWidget(Loading, 0, Qt::AlignVCenter);
        BottomLayout->addStretch(1);
        BottomLayout->addWidget(Close, 0, Qt::AlignRight | Qt::AlignVCenter);
        Layout->addLayout(BottomLayout);
        QObject::connect(Close, &QPushButton::clicked, Dialog, &QDialog::accept); Dialog->show();
        QPointer<QDialog> SafeDialog(Dialog);
        std::thread([SafeDialog, Name, Overview, Dispatch, Devices, Loading] {
            std::vector<MDV2_RECORD> Records; MDV2_LIST_HEADER Header{};
            QueryNamedDriverRecordsV2(Name.toStdWString(), Records, &Header);
            QMetaObject::invokeMethod(qApp, [SafeDialog, Overview, Dispatch, Devices, Loading, Records = std::move(Records), Header] {
                if (!SafeDialog) return;
                if (Loading) {
                    Loading->stop();
                    Loading->hide();
                }
                const auto Add = [](QTableWidget *Table, const QStringList &Values) {
                    const int Row = Table->rowCount(); Table->insertRow(Row);
                    for (int Column = 0; Column < Values.size(); ++Column) Table->setItem(Row, Column, new QTableWidgetItem(Values[Column]));
                    Table->setRowHeight(Row, 36);
                };
                for (const auto &Record : Records) {
                    const QString Address = QString("0x%1").arg(Record.Address, 0, 16).toUpper();
                    if (Record.Kind == 8) Add(Dispatch, {QString::fromWCharArray(Record.Name), Address, QString::number(Record.Source)});
                    else if (Record.Kind == 15) Add(Devices, {Address, QString("0x%1").arg(Record.Value[0], 0, 16).toUpper(),
                        QString::number(Record.Value[1]), QString("0x%1").arg(Record.Value[2], 0, 16).toUpper(),
                        QString("0x%1").arg(Record.Value[3], 0, 16).toUpper(), QString::number(Record.Value[4])});
                    else Add(Overview, {QString::number(Record.Kind), QString::fromWCharArray(Record.Name), Address,
                                        QString("0x%1").arg(Record.Value[0], 0, 16).toUpper(), QString::number(Record.Source)});
                }
                if (Records.empty()) Add(Overview, {"Unavailable", {}, {},
                    QString("0x%1").arg(static_cast<quint32>(Header.Status), 8, 16, QLatin1Char('0')).toUpper(), {}});
            }, Qt::QueuedConnection);
        }).detach();
    }

    static QString StateName(DWORD State)
    {
        switch (State) { case SERVICE_STOPPED: return "Stopped"; case SERVICE_START_PENDING: return "StartPending"; case SERVICE_STOP_PENDING: return "StopPending";
        case SERVICE_RUNNING: return "Running"; case SERVICE_CONTINUE_PENDING: return "ContinuePending"; case SERVICE_PAUSE_PENDING: return "PausePending"; case SERVICE_PAUSED: return "Paused"; default: return "Unknown"; }
    }
    static QString HexPtr(ULONG_PTR Value)
    {
        return QString("0x%1").arg(Value, sizeof(ULONG_PTR) * 2, 16, QLatin1Char('0')).toUpper();
    }
    static QString StartTypeName(DWORD Value)
    {
        switch (Value) { case 0: return "Boot"; case 1: return "System"; case 2: return "Auto"; case 3: return "Demand"; case 4: return "Disabled"; default: return QString::number(Value); }
    }
    static QString DriverRecordAddressText(const MDV2_RECORD &Record)
    {
        if (Record.Address != 0)
            return QString("0x%1").arg(Record.Address, 0, 16).toUpper();
        for (const ULONG64 Value : Record.Value)
        {
            if (Value != 0)
                return QString("0x%1").arg(Value, 0, 16).toUpper();
        }
        return "-";
    }
    void StartRefresh(bool ShowResult)
    {
        if (Refreshing.exchange(true))
            return;

        SetRefreshUiState(RefreshButton, RefreshIndicator, nullptr, true);
        QPointer<DriverManagerPage> SafeThis(this);
        std::thread([SafeThis, ShowResult] {
            DriverRefreshResult Result;
            DRIVER_ENUM_HEADER Header{};
            std::vector<DRIVER_ENUM_ENTRY> Entries;
            Result.Success = QueryDriverEntries(Entries, &Header);
            Result.ErrorCode = G_LastMultiDrvError;
            Result.NtStatus = Header.NtStatus;
            if (Result.Success || Header.NtStatus != 0)
            {
                Result.Success = true;
                for (const DRIVER_ENUM_ENTRY &Entry : Entries)
                {
                    DriverRow Row;
                    Row.Name = QString::fromWCharArray(Entry.ServiceName);
                    Row.DisplayName = QString::fromWCharArray(Entry.DisplayName);
                    Row.Path = QString::fromWCharArray(Entry.ImagePath);
                    Row.RegistryPath = QString::fromWCharArray(Entry.RegistryPath);
                    Row.State = Entry.State;
                    Row.Type = Entry.Type;
                    Row.StartType = Entry.StartType;
                    Row.ErrorControl = Entry.ErrorControl;
                    Row.DriverObject = Entry.DriverObject;
                    Row.ImageBase = Entry.ImageBase;
                    Row.ImageSize = Entry.ImageSize;
                    Row.Path = NormalizeUserDriverPath(Row.Path);
                    std::vector<MDV2_RECORD> DetailRecords;
                    MDV2_LIST_HEADER DetailHeader{};
                    const QStringList DetailCandidates{
                        Row.Name,
                        Row.Name.isEmpty() ? QString() : "\\Driver\\" + Row.Name,
                        Row.DisplayName,
                        QFileInfo(Row.Path).completeBaseName()
                    };
                    for (const QString &Candidate : DetailCandidates)
                    {
                        if (Candidate.isEmpty())
                            continue;
                        DetailRecords.clear();
                        if (QueryNamedDriverRecordsV2(Candidate.toStdWString(), DetailRecords, &DetailHeader) && !DetailRecords.empty())
                        {
                            QStringList Symbols;
                            QStringList Links;
                            const auto AppendUnique = [](QStringList &List, const QString &Text) {
                                if (!Text.isEmpty() && !List.contains(Text, Qt::CaseInsensitive))
                                    List.append(Text);
                            };
                            for (const MDV2_RECORD &Record : DetailRecords)
                            {
                                const QString RecordName = QString::fromWCharArray(Record.Name).trimmed();
                                const QString RecordType = QString::fromWCharArray(Record.TypeName).trimmed();
                                const QString RecordPath = QString::fromWCharArray(Record.Path).trimmed();
                                const QString RecordDetail = QString::fromWCharArray(Record.Detail).trimmed();
                                const QString RecordAddress = DriverRecordAddressText(Record);
                                const QString RecordLabel = !RecordName.isEmpty() ? RecordName :
                                    (!RecordPath.isEmpty() ? RecordPath : (!RecordDetail.isEmpty() ? RecordDetail : RecordAddress));
                                const bool LooksLikeDevice =
                                    Record.Kind == 15 ||
                                    RecordType.contains("Device", Qt::CaseInsensitive) ||
                                    RecordPath.contains("\\Device\\", Qt::CaseInsensitive) ||
                                    RecordDetail.contains("\\Device\\", Qt::CaseInsensitive);
                                const bool LooksLikeSymbol =
                                    Record.Kind == 8 ||
                                    RecordType.contains("Symbol", Qt::CaseInsensitive) ||
                                    RecordType.contains("Dispatch", Qt::CaseInsensitive) ||
                                    RecordPath.contains("Dispatch", Qt::CaseInsensitive) ||
                                    RecordDetail.contains("Dispatch", Qt::CaseInsensitive);
                                const bool LooksLikeLink =
                                    RecordType.contains("SymbolicLink", Qt::CaseInsensitive) ||
                                    RecordType.contains("Link", Qt::CaseInsensitive) ||
                                    RecordPath.contains("\\DosDevices\\", Qt::CaseInsensitive) ||
                                    RecordDetail.contains("\\DosDevices\\", Qt::CaseInsensitive);
                                if (LooksLikeLink)
                                {
                                    const QString TargetText = !RecordDetail.isEmpty() ? RecordDetail :
                                        (!RecordPath.isEmpty() ? RecordPath : RecordAddress);
                                    AppendUnique(Links, TargetText.isEmpty() ? RecordLabel : RecordLabel + " -> " + TargetText);
                                }
                                else if (LooksLikeDevice)
                                {
                                    AppendUnique(Links, RecordLabel.isEmpty() ? (RecordPath.isEmpty() ? RecordDetail : RecordPath) : RecordLabel);
                                }
                                else if (LooksLikeSymbol)
                                {
                                    AppendUnique(Symbols, RecordLabel + (RecordAddress.isEmpty() ? QString() : " @ " + RecordAddress));
                                }
                            }
                            if (Symbols.isEmpty() && Links.isEmpty())
                            {
                                for (const MDV2_RECORD &Record : DetailRecords)
                                {
                                    const QString RecordName = QString::fromWCharArray(Record.Name).trimmed();
                                    const QString RecordPath = QString::fromWCharArray(Record.Path).trimmed();
                                    const QString RecordDetail = QString::fromWCharArray(Record.Detail).trimmed();
                                    const QString RecordAddress = DriverRecordAddressText(Record);
                                    const QString Fallback = !RecordName.isEmpty() ? RecordName :
                                        (!RecordPath.isEmpty() ? RecordPath :
                                         (!RecordDetail.isEmpty() ? RecordDetail : RecordAddress));
                                    const bool LooksLikeNamedLink =
                                        RecordName.contains("\\Device\\", Qt::CaseInsensitive) ||
                                        RecordName.contains("\\DosDevices\\", Qt::CaseInsensitive) ||
                                        RecordPath.contains("\\Device\\", Qt::CaseInsensitive) ||
                                        RecordPath.contains("\\DosDevices\\", Qt::CaseInsensitive) ||
                                        RecordDetail.contains("\\Device\\", Qt::CaseInsensitive) ||
                                        RecordDetail.contains("\\DosDevices\\", Qt::CaseInsensitive);
                                    if (!Fallback.isEmpty())
                                        AppendUnique(Symbols, Fallback);
                                    if (LooksLikeNamedLink)
                                    {
                                        const QString LinkText =
                                            RecordPath.contains("\\Device\\", Qt::CaseInsensitive) || RecordPath.contains("\\DosDevices\\", Qt::CaseInsensitive)
                                                ? RecordPath
                                                : (RecordDetail.contains("\\Device\\", Qt::CaseInsensitive) || RecordDetail.contains("\\DosDevices\\", Qt::CaseInsensitive)
                                                    ? RecordDetail
                                                    : RecordName);
                                        AppendUnique(Links, LinkText);
                                    }
                                }
                            }
                            Row.SymbolNames = Symbols.join(" | ");
                            Row.DeviceLinks = Links.join(" | ");
                            break;
                        }
                    }
                    if (QFileInfo::exists(Row.Path)) Row.Trust = QueryUserFileTrustCached(Row.Path);
                    Row.SearchText = (Row.Name + ' ' + Row.DisplayName + ' ' + Row.Path + ' ' + Row.RegistryPath + ' ' +
                                      Row.SymbolNames + ' ' + Row.DeviceLinks + ' ' + StateName(Row.State) + ' ' +
                                      Row.Trust.Signer + ' ' + Row.Trust.Sha256 + ' ' + HexPtr(Row.DriverObject) + ' ' +
                                      HexPtr(Row.ImageBase)).toCaseFolded();
                    Result.Rows.push_back(std::move(Row));
                }
                std::sort(Result.Rows.begin(), Result.Rows.end(), [](const DriverRow &Left, const DriverRow &Right) {
                    if (Left.State != Right.State)
                        return Left.State == SERVICE_RUNNING;
                    return Left.Name.compare(Right.Name, Qt::CaseInsensitive) < 0;
                });
            }

            QMetaObject::invokeMethod(qApp, [SafeThis, ShowResult, Result = std::move(Result)]() mutable {
                if (!SafeThis)
                    return;
                SafeThis->Refreshing = false;
                SetRefreshUiState(SafeThis->RefreshButton, SafeThis->RefreshIndicator, nullptr, false);
                if (!Result.Success)
                {
                    SafeThis->Rows.clear();
                    SafeThis->Populate();
                    const QString Message =
                        QString("Kernel enumeration failed (error %1).").arg(Result.ErrorCode);
                    if (ShowResult)
                        ShowErrorNotice(SafeThis, "Driver", Message);
                    return;
                }

                SafeThis->Rows = std::move(Result.Rows);
                SafeThis->Populate();
                if (ShowResult)
                    ShowSuccessNotice(SafeThis, "Driver",
                                      QString("Enumerated %1 driver(s).").arg(SafeThis->Rows.size()));
            }, Qt::QueuedConnection);
        }).detach();
    }
    void Populate()
    {
        SetTableRefreshEnabled(DriverTable, false);
        QHash<QString, int> ExistingRows;
        ExistingRows.reserve(DriverTable->rowCount());
        for (int Row = 0; Row < DriverTable->rowCount(); ++Row)
        {
            if (const QTableWidgetItem *Item = DriverTable->item(Row, 0))
                ExistingRows.insert(Item->data(Qt::UserRole).toString(), Row);
        }
        for (int Row = DriverTable->rowCount() - 1; Row >= 0; --Row)
        {
            const QTableWidgetItem *Item = DriverTable->item(Row, 0);
            const QString Name = Item ? Item->data(Qt::UserRole).toString() : QString();
            const auto Match = std::find_if(Rows.begin(), Rows.end(), [&Name](const DriverRow &Driver) {
                return Driver.Name.compare(Name, Qt::CaseInsensitive) == 0;
            });
            if (Name.isEmpty() || Match == Rows.end())
                DriverTable->removeRow(Row);
        }
        for (const DriverRow &Driver : Rows)
        {
            int Row = FindDriverTableRow(Driver.Name);
            if (Row < 0)
            {
                Row = DriverTable->rowCount();
                DriverTable->insertRow(Row);
            }
            if (RowDataMatches(Row, Driver))
                continue;
            FillDriverTableRow(Row, Driver);
        }
        SetTableRefreshEnabled(DriverTable, true);
        ApplySearchFilter();
    }
    int FindDriverTableRow(const QString &Name) const
    {
        for (int Row = 0; Row < DriverTable->rowCount(); ++Row)
        {
            const QTableWidgetItem *Item = DriverTable->item(Row, 0);
            if (Item && Item->data(Qt::UserRole).toString().compare(Name, Qt::CaseInsensitive) == 0)
                return Row;
        }
        return -1;
    }
    bool RowDataMatches(int Row, const DriverRow &Driver) const
    {
        const QTableWidgetItem *NameItem = DriverTable->item(Row, 0);
        const QTableWidgetItem *DisplayItem = DriverTable->item(Row, 1);
        const QTableWidgetItem *StateItem = DriverTable->item(Row, 2);
        const QTableWidgetItem *TypeItem = DriverTable->item(Row, 3);
        const QTableWidgetItem *ObjectItem = DriverTable->item(Row, 4);
        const QTableWidgetItem *BaseItem = DriverTable->item(Row, 5);
        const QTableWidgetItem *SizeItem = DriverTable->item(Row, 6);
        const QTableWidgetItem *SymbolItem = DriverTable->item(Row, 7);
        const QTableWidgetItem *LinksItem = DriverTable->item(Row, 8);
        const QTableWidgetItem *SignatureItem = DriverTable->item(Row, 9);
        const QTableWidgetItem *ShaItem = DriverTable->item(Row, 10);
        const QTableWidgetItem *PathItem = DriverTable->item(Row, 11);
        if (!NameItem || !DisplayItem || !StateItem || !TypeItem || !ObjectItem || !BaseItem ||
            !SizeItem || !SymbolItem || !LinksItem || !SignatureItem || !ShaItem || !PathItem)
            return false;
        const QString SignatureText = Driver.Trust.Trusted
            ? Driver.Trust.SignatureKind + " | " + Driver.Trust.Signer
            : "Untrusted";
        return NameItem->data(Qt::UserRole).toString().compare(Driver.Name, Qt::CaseInsensitive) == 0 &&
               NameItem->data(Qt::UserRole + 1).toString() == Driver.SearchText &&
               NameItem->text() == Driver.Name &&
               DisplayItem->text() == Driver.DisplayName &&
               StateItem->text() == StateName(Driver.State) &&
               TypeItem->text() == QString("0x%1").arg(Driver.Type, 0, 16) &&
               ObjectItem->text() == HexPtr(Driver.DriverObject) &&
               BaseItem->text() == HexPtr(Driver.ImageBase) &&
               SizeItem->text() == QString("0x%1").arg(Driver.ImageSize, 0, 16) &&
               SymbolItem->text() == (Driver.SymbolNames.isEmpty() ? "-" : Driver.SymbolNames) &&
               LinksItem->text() == (Driver.DeviceLinks.isEmpty() ? "-" : Driver.DeviceLinks) &&
               SignatureItem->text() == SignatureText &&
               ShaItem->text() == Driver.Trust.Sha256 &&
               PathItem->text() == Driver.Path;
    }
    void FillDriverTableRow(int Row, const DriverRow &Driver)
    {
        const QString State = StateName(Driver.State);
        const QString SignatureText = Driver.Trust.Trusted
            ? Driver.Trust.SignatureKind + " | " + Driver.Trust.Signer
            : "Untrusted";
        auto EnsureItem = [this, Row](int Column) {
            QTableWidgetItem *Item = DriverTable->item(Row, Column);
            if (!Item)
            {
                Item = new QTableWidgetItem;
                DriverTable->setItem(Row, Column, Item);
            }
            return Item;
        };
        QTableWidgetItem *NameItem = EnsureItem(0);
        NameItem->setText(Driver.Name);
        NameItem->setData(Qt::UserRole, Driver.Name);
        NameItem->setData(Qt::UserRole + 1, Driver.SearchText);
        EnsureItem(1)->setText(Driver.DisplayName);
        EnsureItem(2)->setText(State);
        EnsureItem(3)->setText(QString("0x%1").arg(Driver.Type, 0, 16));
        EnsureItem(4)->setText(HexPtr(Driver.DriverObject));
        EnsureItem(5)->setText(HexPtr(Driver.ImageBase));
        EnsureItem(6)->setText(QString("0x%1").arg(Driver.ImageSize, 0, 16));
        EnsureItem(7)->setText(Driver.SymbolNames.isEmpty() ? "-" : Driver.SymbolNames);
        EnsureItem(8)->setText(Driver.DeviceLinks.isEmpty() ? "-" : Driver.DeviceLinks);
        EnsureItem(9)->setText(SignatureText);
        EnsureItem(10)->setText(Driver.Trust.Sha256);
        EnsureItem(11)->setText(Driver.Path);
        DriverTable->setRowHeight(Row, KCompactTableRowHeight);
    }
    void ApplySearchFilter()
    {
        if (!DriverTable)
            return;
        const QString Query = SearchEdit->text().trimmed().toCaseFolded();
        const bool HasQuery = !Query.isEmpty();
        SetTableRefreshEnabled(DriverTable, false);
        for (int Row = 0; Row < DriverTable->rowCount(); ++Row)
        {
            QTableWidgetItem *Item = DriverTable->item(Row, 0);
            const QString SearchText = Item ? Item->data(Qt::UserRole + 1).toString() : QString();
            DriverTable->setRowHidden(Row, HasQuery && !SearchText.contains(Query));
        }
        SetTableRefreshEnabled(DriverTable, true);
    }
    SearchLineEdit *SearchEdit = nullptr; QTimer *SearchDebounceTimer = nullptr; TableWidget *DriverTable = nullptr; PushButton *RefreshButton = nullptr; IndeterminateProgressRing *RefreshIndicator = nullptr; std::vector<DriverRow> Rows; std::atomic_bool Refreshing = false;
};

