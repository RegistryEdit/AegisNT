class DriverManagerPage final : public QWidget
{
    struct DriverRow
    {
        QString Name;
        QString DisplayName;
        QString Path;
        QString RegistryPath;
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
        SearchEdit = new SearchLineEdit; SearchEdit->setPlaceholderText("Search service, display name, path, or state"); SearchEdit->setClearButtonEnabled(true); SearchEdit->setMaximumWidth(380);
        RefreshIndicator = new IndeterminateProgressRing(this, false);
        RefreshIndicator->setFixedSize(22, 22);
        RefreshIndicator->hide();
        LoadButton->setMinimumWidth(92);
        LoadButton->setMaximumWidth(92);
        LoadButton->setFixedHeight(32);
        RefreshButton = MakeButton("Refresh", true);
        RefreshButton->setMinimumWidth(92);
        RefreshButton->setMaximumWidth(92);
        RefreshButton->setFixedHeight(32);
        FilterLayout->addWidget(SearchEdit, 0, Qt::AlignLeft | Qt::AlignVCenter);
        FilterLayout->addStretch(1);
        FilterLayout->addWidget(RefreshIndicator, 0, Qt::AlignVCenter);
        FilterLayout->addWidget(LoadButton, 0, Qt::AlignRight | Qt::AlignVCenter);
        FilterLayout->addWidget(RefreshButton, 0, Qt::AlignRight | Qt::AlignVCenter);
        Layout->addLayout(FilterLayout);
        DriverTable = MakeTable({"Service", "Display name", "State", "Type", "Object", "Base", "Size", "Signature", "SHA-256", "Path"});
        DriverTable->setSelectionMode(QAbstractItemView::SingleSelection); DriverTable->setContextMenuPolicy(Qt::CustomContextMenu);
        DriverTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        DriverTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
        DriverTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
        DriverTable->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
        DriverTable->horizontalHeader()->setSectionResizeMode(6, QHeaderView::ResizeToContents);
        DriverTable->horizontalHeader()->setSectionResizeMode(7, QHeaderView::ResizeToContents);
        DriverTable->horizontalHeader()->setSectionResizeMode(8, QHeaderView::Stretch);
        DriverTable->horizontalHeader()->setSectionResizeMode(9, QHeaderView::Stretch); Layout->addWidget(DriverTable, 1);
        QObject::connect(LoadButton, &QPushButton::clicked, this, [this] { ShowLoadDriverDialog(); });
        QObject::connect(RefreshButton, &QPushButton::clicked, this, [this] { StartRefresh(true); });
        QObject::connect(SearchEdit, &QLineEdit::textChanged, this, [this] { Populate(); });
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
        auto *Tabs = new QTabWidget;
        auto *Overview = MakeTable({"Kind", "Name", "Address", "Value", "Source"});
        auto *Dispatch = MakeTable({"Major function", "Address", "Source"});
        auto *Devices = MakeTable({"Device", "Attached", "Type", "Characteristics", "Flags", "Stack"});
        Tabs->addTab(Overview, "Overview"); Tabs->addTab(Dispatch, "Dispatch"); Tabs->addTab(Devices, "Devices"); Layout->addWidget(Tabs, 1);
        auto *Close = MakeButton("Close", true); Layout->addWidget(Close, 0, Qt::AlignRight);
        QObject::connect(Close, &QPushButton::clicked, Dialog, &QDialog::accept); Dialog->show();
        QPointer<QDialog> SafeDialog(Dialog);
        std::thread([SafeDialog, Name, Overview, Dispatch, Devices] {
            std::vector<MDV2_RECORD> Records; MDV2_LIST_HEADER Header{};
            QueryNamedDriverRecordsV2(Name.toStdWString(), Records, &Header);
            QMetaObject::invokeMethod(qApp, [SafeDialog, Overview, Dispatch, Devices, Records = std::move(Records), Header] {
                if (!SafeDialog) return;
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

    QString StateName(DWORD State) const
    {
        switch (State) { case SERVICE_STOPPED: return "Stopped"; case SERVICE_START_PENDING: return "StartPending"; case SERVICE_STOP_PENDING: return "StopPending";
        case SERVICE_RUNNING: return "Running"; case SERVICE_CONTINUE_PENDING: return "ContinuePending"; case SERVICE_PAUSE_PENDING: return "PausePending"; case SERVICE_PAUSED: return "Paused"; default: return "Unknown"; }
    }
    QString HexPtr(ULONG_PTR Value) const
    {
        return QString("0x%1").arg(Value, sizeof(ULONG_PTR) * 2, 16, QLatin1Char('0')).toUpper();
    }
    QString StartTypeName(DWORD Value) const
    {
        switch (Value) { case 0: return "Boot"; case 1: return "System"; case 2: return "Auto"; case 3: return "Demand"; case 4: return "Disabled"; default: return QString::number(Value); }
    }
    void StartRefresh(bool ShowResult)
    {
        if (Refreshing.exchange(true))
            return;

        if (RefreshButton)
        {
        RefreshButton->setEnabled(false);
        RefreshButton->setText("Refreshing...");
        }
        if (RefreshIndicator)
        {
            RefreshIndicator->show();
            RefreshIndicator->start();
        }
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
                    if (QFileInfo::exists(Row.Path)) Row.Trust = QueryUserFileTrustCached(Row.Path);
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
                if (SafeThis->RefreshIndicator)
                {
                    SafeThis->RefreshIndicator->stop();
                    SafeThis->RefreshIndicator->hide();
                }
                if (SafeThis->RefreshButton)
                {
                    SafeThis->RefreshButton->setText("Refresh");
                    SafeThis->RefreshButton->setEnabled(true);
                }
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
        const QString Query = SearchEdit->text().trimmed(); DriverTable->clearContents(); DriverTable->setRowCount(0);
        for (const DriverRow &Driver : Rows) { const QString State = StateName(Driver.State); const QString Text = Driver.Name + " " + Driver.DisplayName + " " + Driver.Path + " " + Driver.RegistryPath + " " + State + " " + Driver.Trust.Signer + " " + Driver.Trust.Sha256 + " " + HexPtr(Driver.DriverObject) + " " + HexPtr(Driver.ImageBase);
            if (!Query.isEmpty() && !Text.contains(Query, Qt::CaseInsensitive)) continue; const int Row = DriverTable->rowCount(); DriverTable->insertRow(Row);
            DriverTable->setItem(Row, 0, new QTableWidgetItem(Driver.Name)); DriverTable->setItem(Row, 1, new QTableWidgetItem(Driver.DisplayName)); DriverTable->setItem(Row, 2, new QTableWidgetItem(State));
            DriverTable->setItem(Row, 3, new QTableWidgetItem(QString("0x%1").arg(Driver.Type, 0, 16)));
            DriverTable->setItem(Row, 4, new QTableWidgetItem(HexPtr(Driver.DriverObject)));
            DriverTable->setItem(Row, 5, new QTableWidgetItem(HexPtr(Driver.ImageBase)));
            DriverTable->setItem(Row, 6, new QTableWidgetItem(QString("0x%1").arg(Driver.ImageSize, 0, 16)));
            DriverTable->setItem(Row, 7, new QTableWidgetItem(Driver.Trust.Trusted ? Driver.Trust.SignatureKind + " | " + Driver.Trust.Signer : "Untrusted"));
            DriverTable->setItem(Row, 8, new QTableWidgetItem(Driver.Trust.Sha256));
            DriverTable->setItem(Row, 9, new QTableWidgetItem(Driver.Path)); DriverTable->setRowHeight(Row, KCompactTableRowHeight); }
    }
    SearchLineEdit *SearchEdit = nullptr; TableWidget *DriverTable = nullptr; PushButton *RefreshButton = nullptr; IndeterminateProgressRing *RefreshIndicator = nullptr; std::vector<DriverRow> Rows; std::atomic_bool Refreshing = false;
};

