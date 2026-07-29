class FileExplorerPage final : public QWidget
{
    struct ProtectedFileEntry
    {
        QString DisplayPath;
        QString NtPath;
    };

    struct FileMonitorEntry
    {
        QString Timestamp;
        QString Operation;
        QString Process;
        QString Path;
        QString Detail;
        DWORD ProcessId = 0;
        DWORD ThreadId = 0;
    };

  public:
    explicit FileExplorerPage(QWidget *Parent = nullptr)
        : QWidget(Parent)
    {
        auto *Layout = new QVBoxLayout(this);
        ConfigurePageLayout(Layout, 8);

        auto *Tabs = new TabBar;
        Tabs->setAddButtonVisible(false);
        Tabs->setTabsClosable(false);
        Tabs->setMovable(false);
        Tabs->addTab("explorer", "Explorer", Fluent::IconType::FOLDER);
        Tabs->addTab("protected", "ProtectedFiles", Fluent::IconType::CERTIFICATE);
        Tabs->addTab("monitor", "Monitor", Fluent::IconType::COMMAND_PROMPT);
        Tabs->setCurrentIndex(0);
        Layout->addWidget(Tabs);
        TabBarWidget = Tabs;

        Pages = new QStackedWidget;
        auto *ExplorerPage = new QWidget;
        auto *ExplorerLayout = new QVBoxLayout(ExplorerPage);
        ConfigurePageLayout(ExplorerLayout, 8);

        auto *NavigationLayout = new QHBoxLayout;
        ConfigureToolbarLayout(NavigationLayout);
        BackButton = CreateNavigationButton(Fluent::IconType::LEFT_ARROW, "Back");
        ForwardButton = CreateNavigationButton(Fluent::IconType::RIGHT_ARROW, "Forward");
        UpButton = CreateNavigationButton(Fluent::IconType::UP, "Up one level");
        RefreshButton = CreateNavigationButton(Fluent::IconType::SYNC, "Refresh");
        AddressEdit = new LineEdit;
        ConfigureLineEdit(AddressEdit, "Path");
        SearchEdit = new SearchLineEdit;
        ConfigureSearchLineEdit(SearchEdit, "Search this folder", 240);
        NavigationLayout->addWidget(BackButton);
        NavigationLayout->addWidget(ForwardButton);
        NavigationLayout->addWidget(UpButton);
        NavigationLayout->addWidget(RefreshButton);
        NavigationLayout->addWidget(AddressEdit, 1);
        NavigationLayout->addWidget(SearchEdit);
        ExplorerLayout->addLayout(NavigationLayout);

        auto *CommandLayout = new QHBoxLayout;
        ConfigureToolbarLayout(CommandLayout);
        auto *HomeButton = new PushButton("Home", Fluent::IconType::HOME);
        auto *NewFolderButton = new PushButton("New folder", Fluent::IconType::FOLDER_ADD);
        CommandLayout->addWidget(HomeButton);
        CommandLayout->addWidget(NewFolderButton);
        CommandLayout->addStretch();
        StatusLabel = new BodyLabel;
        StatusLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        CommandLayout->addWidget(StatusLabel);
        ExplorerLayout->addLayout(CommandLayout);

        DirectoryModel = new QFileSystemModel(this);
        DirectoryModel->setFilter(QDir::AllDirs | QDir::NoDotAndDotDot | QDir::Drives);
        DirectoryModel->setRootPath(QString());

        FileModel = new QFileSystemModel(this);
        FileModel->setFilter(QDir::AllEntries | QDir::NoDotAndDotDot);
        FileModel->setReadOnly(false);
        FileModel->setNameFilterDisables(false);

        DirectoryTree = new QTreeView;
        DirectoryTree->setModel(DirectoryModel);
        DirectoryTree->setRootIndex(DirectoryModel->index(QString()));
        DirectoryTree->setHeaderHidden(true);
        DirectoryTree->setAnimated(true);
        DirectoryTree->setMinimumWidth(190);
        for (int Column = 1; Column < DirectoryModel->columnCount(); ++Column)
            DirectoryTree->hideColumn(Column);
        InstallFluentScrollBar(DirectoryTree, Qt::Vertical);

        FileView = new QTreeView;
        FileView->setModel(FileModel);
        FileView->setAlternatingRowColors(false);
        FileView->setRootIsDecorated(false);
        FileView->setItemsExpandable(false);
        FileView->setSortingEnabled(true);
        FileView->sortByColumn(0, Qt::AscendingOrder);
        FileView->setSelectionMode(QAbstractItemView::ExtendedSelection);
        FileView->setSelectionBehavior(QAbstractItemView::SelectRows);
        FileView->setEditTriggers(QAbstractItemView::NoEditTriggers);
        FileView->setContextMenuPolicy(Qt::CustomContextMenu);
        FileView->header()->setSectionResizeMode(0, QHeaderView::Stretch);
        FileView->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
        FileView->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
        FileView->header()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
        InstallFluentScrollBar(FileView, Qt::Vertical);
        InstallFluentScrollBar(FileView, Qt::Horizontal);

        auto *Splitter = new QSplitter;
        Splitter->setChildrenCollapsible(false);
        Splitter->addWidget(DirectoryTree);
        Splitter->addWidget(FileView);
        Splitter->setStretchFactor(0, 0);
        Splitter->setStretchFactor(1, 1);
        Splitter->setSizes({230, 760});
        ExplorerLayout->addWidget(Splitter, 1);

        auto *ProtectedPage = new QWidget;
        auto *ProtectedLayout = new QVBoxLayout(ProtectedPage);
        ConfigurePageLayout(ProtectedLayout, 8);
        auto *ProtectedToolbar = new QHBoxLayout;
        ConfigureToolbarLayout(ProtectedToolbar);
        UnprotectButton = MakeButton("Unprotect", true);
        ConfigureActionButton(UnprotectButton);
        UnprotectButton->setEnabled(false);
        ProtectedToolbar->addStretch();
        ProtectedToolbar->addWidget(UnprotectButton);
        ProtectedLayout->addLayout(ProtectedToolbar);
        ProtectedTable = MakeTable({"Name", "Protected path"});
        ProtectedTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
        ProtectedTable->setProperty("DetailDialogTitle", "Protected file details");
        ProtectedTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        ProtectedTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
        ProtectedLayout->addWidget(ProtectedTable, 1);

        auto *MonitorPage = new QWidget;
        auto *MonitorLayout = new QVBoxLayout(MonitorPage);
        ConfigurePageLayout(MonitorLayout, 8);
        auto *MonitorToolbar = new QHBoxLayout;
        ConfigureToolbarLayout(MonitorToolbar);
        auto *BrowseMonitorButton = MakeButton("Browse", true);
        auto *MonitorCurrentButton = MakeButton("Monitor current folder");
        MonitorStopButton = MakeButton("Stop");
        MonitorClearButton = MakeButton("Clear");
        ConfigureActionButton(BrowseMonitorButton);
        ConfigureActionButton(MonitorCurrentButton, 140, KStandardButtonHeight);
        ConfigureActionButton(MonitorStopButton);
        ConfigureActionButton(MonitorClearButton);
        MonitorStopButton->setEnabled(false);
        MonitorToolbar->addWidget(BrowseMonitorButton);
        MonitorToolbar->addWidget(MonitorCurrentButton);
        MonitorToolbar->addWidget(MonitorStopButton);
        MonitorToolbar->addWidget(MonitorClearButton);
        MonitorToolbar->addStretch();
        MonitorStatusLabel = new BodyLabel("Stopped");
        MonitorToolbar->addWidget(MonitorStatusLabel);
        MonitorLayout->addLayout(MonitorToolbar);

        auto *WatchInfoLayout = new QHBoxLayout;
        ConfigureToolbarLayout(WatchInfoLayout);
        MonitorDirectoryLabel = new BodyLabel("-");
        MonitorDirectoryLabel->setWordWrap(true);
        WatchInfoLayout->addWidget(MonitorDirectoryLabel, 1);
        MonitorLayout->addLayout(WatchInfoLayout);

        MonitorSearchEdit = new SearchLineEdit;
        ConfigureSearchLineEdit(MonitorSearchEdit, "Search time, operation, process, PID, or path");
        MonitorLayout->addWidget(MonitorSearchEdit);

        MonitorTable = MakeTable({"Time", "Operation", "Process", "PID", "Path"});
        MonitorTable->setSelectionMode(QAbstractItemView::SingleSelection);
        MonitorTable->setContextMenuPolicy(Qt::CustomContextMenu);
        MonitorTable->setProperty("UseGenericDetailDialog", false);
        MonitorTable->setWordWrap(false);
        MonitorTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        MonitorTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
        MonitorTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
        MonitorTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
        MonitorTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
        MonitorLayout->addWidget(MonitorTable, 1);

        Pages->addWidget(ExplorerPage);
        Pages->addWidget(ProtectedPage);
        Pages->addWidget(MonitorPage);
        Layout->addWidget(Pages, 1);
        QObject::connect(Tabs, &TabBar::currentChanged, Pages, &QStackedWidget::setCurrentIndex);
        QObject::connect(ProtectedTable, &QTableWidget::itemSelectionChanged, this, [this] {
            UnprotectButton->setEnabled(!ProtectedTable->selectionModel()->selectedRows(0).isEmpty());
        });
        QObject::connect(UnprotectButton, &QPushButton::clicked, this, [this] { UnprotectSelection(); });
        QObject::connect(BrowseMonitorButton, &QPushButton::clicked, this, [this] { BrowseMonitorDirectory(); });
        QObject::connect(MonitorCurrentButton, &QPushButton::clicked, this, [this] {
            StartMonitoringDirectory(CurrentPath, true, true);
        });
        QObject::connect(MonitorStopButton, &QPushButton::clicked, this, [this] { StopFileMonitor(true); });
        QObject::connect(MonitorClearButton, &QPushButton::clicked, this, [this] { ClearMonitorEvents(); });
        MonitorSearchDebounceTimer = new QTimer(this);
        MonitorSearchDebounceTimer->setSingleShot(true);
        MonitorSearchDebounceTimer->setInterval(KSearchDebounceMs);
        QObject::connect(MonitorSearchDebounceTimer, &QTimer::timeout, this, [this] { RefreshMonitorTable(); });
        QObject::connect(MonitorSearchEdit, &QLineEdit::textChanged, this, [this] { MonitorSearchDebounceTimer->start(); });
        QObject::connect(MonitorTable, &QTableWidget::cellDoubleClicked, this,
                         [this](int Row, int Column) {
                             if (Column == 4)
                                 ShowMonitorPath(Row);
                             else
                                 ShowMonitorDetails(Row);
                         });
        QObject::connect(MonitorTable, &QWidget::customContextMenuRequested, this,
                         [this](const QPoint &Position) { ShowMonitorContextMenu(Position); });

        QObject::connect(BackButton, &QPushButton::clicked, this, [this] { NavigateHistory(-1); });
        QObject::connect(ForwardButton, &QPushButton::clicked, this, [this] { NavigateHistory(1); });
        QObject::connect(UpButton, &QPushButton::clicked, this, [this] {
            const QDir Directory(CurrentPath);
            NavigateTo(QFileInfo(Directory.absolutePath()).dir().absolutePath());
        });
        QObject::connect(RefreshButton, &QPushButton::clicked, this, [this] {
            FileModel->setRootPath(QString());
            FileModel->setRootPath(CurrentPath);
            FileView->setRootIndex(FileModel->index(CurrentPath));
            UpdateStatus();
            ShowSuccessNotice(this, "File", "Folder refreshed.");
        });
        QObject::connect(AddressEdit, &QLineEdit::returnPressed, this, [this] {
            NavigateTo(QDir::fromNativeSeparators(AddressEdit->text().trimmed()));
        });
        QObject::connect(SearchEdit, &QLineEdit::textChanged, this, [this](const QString &Text) {
            FileModel->setNameFilters(Text.trimmed().isEmpty() ? QStringList() : QStringList{"*" + Text.trimmed() + "*"});
            UpdateStatus();
        });
        QObject::connect(DirectoryTree, &QTreeView::clicked, this, [this](const QModelIndex &Index) {
            NavigateTo(DirectoryModel->filePath(Index));
        });
        QObject::connect(FileView, &QTreeView::doubleClicked, this, [this](const QModelIndex &Index) {
            const QFileInfo Information = FileModel->fileInfo(Index);
            if (Information.isDir())
                NavigateTo(Information.absoluteFilePath());
            else
                QDesktopServices::openUrl(QUrl::fromLocalFile(Information.absoluteFilePath()));
        });
        QObject::connect(FileView->selectionModel(), &QItemSelectionModel::selectionChanged, this,
                         [this] { UpdateStatus(); });
        QObject::connect(HomeButton, &QPushButton::clicked, this, [this] {
            NavigateTo(QStandardPaths::writableLocation(QStandardPaths::HomeLocation));
        });
        QObject::connect(NewFolderButton, &QPushButton::clicked, this, [this] { CreateFolder(); });
        QObject::connect(FileView, &QWidget::customContextMenuRequested, this,
                         [this](const QPoint &Position) { ShowContextMenu(Position); });

        MonitorRefreshTimer = new QTimer(this);
        MonitorRefreshTimer->setInterval(150);
        QObject::connect(MonitorRefreshTimer, &QTimer::timeout, this, [this] {
            if (!isVisible() || !Pages || Pages->currentIndex() != 2)
                return;
            const uint64_t Version = MonitorVersion.load(std::memory_order_relaxed);
            if (DisplayedMonitorVersion != Version) {
                DisplayedMonitorVersion = Version;
                RefreshMonitorTable();
            }
        });
        MonitorRefreshTimer->start();

        NavigateTo(QStandardPaths::writableLocation(QStandardPaths::HomeLocation));
    }

    ~FileExplorerPage() override
    {
        StopFileMonitor(false);
    }

  private:
    static QString FileMajorOperation(ULONG Major)
    {
        switch (Major)
        {
        case 0x00: return "IRP_MJ_CREATE";
        case 0x04: return "IRP_MJ_WRITE";
        case 0x06: return "IRP_MJ_SET_INFORMATION";
        default: return QString("Major 0x%1").arg(Major, 0, 16).toUpper();
        }
    }

    static FileMonitorEntry BuildMonitorEntry(const MonitorEvent &Event)
    {
        const QString Extra = QString::fromWCharArray(Event.Extra);
        const QString Operation = Extra.contains(" | ") ? Extra.section(" | ", 0, 0) : Extra;
        const QString ProcessImage = Extra.contains(" | ") ? Extra.section(" | ", 1) : QString();
        const std::wstring ProcessName = GetProcessNameFromPid(Event.ProcessId);
        const QString Process = ProcessImage.isEmpty()
                                    ? (ProcessName.empty() ? "<unknown>" : QString::fromStdWString(ProcessName))
                                    : QString("%1 | %2")
                                          .arg(ProcessName.empty() ? "<unknown>" : QString::fromStdWString(ProcessName),
                                               ProcessImage);
        FileMonitorEntry Entry;
        Entry.Timestamp = MonitorTimestamp(Event.TimeStamp);
        Entry.Operation = Operation.isEmpty() ? "FileOp" : Operation;
        Entry.Process = Process;
        Entry.Path = QString::fromWCharArray(Event.Path);
        Entry.ProcessId = Event.ProcessId;
        Entry.ThreadId = Event.ThreadId;
        Entry.Detail = QString("%1\n\nProcess: %2\nPID: %3\nTID: %4\nOperation: %5\nPath: %6\nExtra: %7\nMajor: %8\nMinor: %9 (0x%10)")
                           .arg(Entry.Timestamp)
                           .arg(Entry.Process)
                           .arg(Entry.ProcessId)
                           .arg(Entry.ThreadId)
                           .arg(Entry.Operation)
                           .arg(Entry.Path)
                           .arg(Extra.isEmpty() ? "-" : Extra)
                           .arg(FileMajorOperation(Event.Data1))
                           .arg(Event.Data2)
                           .arg(QString::number(Event.Data2, 16).toUpper());
        return Entry;
    }

    ToolButton *CreateNavigationButton(Fluent::IconType Icon, const QString &ToolTip)
    {
        auto *Button = new ToolButton(Icon);
        Button->setFixedSize(36, 36);
        Button->setToolTip(ToolTip);
        Button->setCursor(Qt::PointingHandCursor);
        return Button;
    }

    void NavigateTo(const QString &Path, bool AddHistory = true)
    {
        const QFileInfo Information(Path);
        const QString AbsolutePath = QDir::cleanPath(Information.absoluteFilePath());
        if (!Information.exists() || !Information.isDir())
        {
            ShowErrorNotice(this, "File", "The folder does not exist or cannot be accessed.");
            AddressEdit->setText(QDir::toNativeSeparators(CurrentPath));
            return;
        }
        if (AddHistory && AbsolutePath != CurrentPath)
        {
            while (History.size() > HistoryIndex + 1)
                History.removeLast();
            History.append(AbsolutePath);
            HistoryIndex = History.size() - 1;
        }
        CurrentPath = AbsolutePath;
        AddressEdit->setText(QDir::toNativeSeparators(CurrentPath));
        FileModel->setRootPath(CurrentPath);
        FileView->setRootIndex(FileModel->index(CurrentPath));
        const QModelIndex DirectoryIndex = DirectoryModel->index(CurrentPath);
        DirectoryTree->setCurrentIndex(DirectoryIndex);
        DirectoryTree->scrollTo(DirectoryIndex);
        BackButton->setEnabled(HistoryIndex > 0);
        ForwardButton->setEnabled(HistoryIndex >= 0 && HistoryIndex + 1 < History.size());
        UpButton->setEnabled(QFileInfo(CurrentPath).dir().absolutePath() != CurrentPath);
        UpdateStatus();
    }

    void NavigateHistory(int Offset)
    {
        const int NextIndex = HistoryIndex + Offset;
        if (NextIndex < 0 || NextIndex >= History.size())
            return;
        HistoryIndex = NextIndex;
        NavigateTo(History.at(HistoryIndex), false);
    }

    QStringList SelectedPaths() const
    {
        QStringList Paths;
        for (const QModelIndex &Index : FileView->selectionModel()->selectedRows(0))
            Paths.append(FileModel->filePath(Index));
        return Paths;
    }

    void UpdateStatus()
    {
        const int VisibleItems = FileModel->rowCount(FileView->rootIndex());
        const int SelectedItems = SelectedPaths().size();
        StatusLabel->setText(SelectedItems > 0 ? QString("%1 items  |  %2 selected").arg(VisibleItems).arg(SelectedItems)
                                               : QString("%1 items").arg(VisibleItems));
    }

    void CreateFolder()
    {
        bool Accepted = false;
        const QString Name = QInputDialog::getText(this, "New folder", "Folder name:", QLineEdit::Normal,
                                                   "New folder", &Accepted).trimmed();
        if (!Accepted || Name.isEmpty())
            return;
        if (!QDir(CurrentPath).mkdir(Name))
            ShowErrorNotice(this, "File", "Failed to create the folder.");
        else
            ShowSuccessNotice(this, "File", "Folder created successfully.");
    }

    void RenameSelection()
    {
        const QStringList Paths = SelectedPaths();
        if (Paths.size() != 1)
        {
            ShowWarningNotice(this, "Rename", "Select exactly one item to rename.");
            return;
        }
        const QFileInfo Information(Paths.first());
        bool Accepted = false;
        const QString Name = QInputDialog::getText(this, "Rename", "New name:", QLineEdit::Normal,
                                                   Information.fileName(), &Accepted).trimmed();
        if (!Accepted || Name.isEmpty() || Name == Information.fileName())
            return;
        const QString Destination = Information.dir().absoluteFilePath(Name);
        if (!QDir().rename(Information.absoluteFilePath(), Destination))
            ShowErrorNotice(this, "Rename", "Failed to rename the selected item.");
        else
            ShowSuccessNotice(this, "Rename", "Item renamed successfully.");
    }

    void DeleteSelection()
    {
        const QStringList Paths = SelectedPaths();
        if (Paths.isEmpty())
            return;
        const QString Prompt = QString("Permanently delete %1 selected item(s)?").arg(Paths.size());
        if (QMessageBox::question(this, "Delete", Prompt) != QMessageBox::Yes)
            return;
        QStringList Failures;
        for (const QString &Path : Paths)
        {
            const QFileInfo Information(Path);
            const bool Removed = Information.isDir() ? QDir(Path).removeRecursively() : QFile::remove(Path);
            if (!Removed)
                Failures.append(Information.fileName());
        }
        if (!Failures.isEmpty())
            ShowErrorNotice(this, "Delete", "Failed to delete:\n" + Failures.join("\n"));
        else
            ShowSuccessNotice(this, "Delete", QString("Deleted %1 item(s).").arg(Paths.size()));
    }

    void DeleteSelectionR0()
    {
        const QStringList Paths = SelectedPaths();
        if (Paths.isEmpty())
            return;
        for (const QString &Path : Paths)
        {
            if (QFileInfo(Path).isDir())
            {
                ShowWarningNotice(this, "Delete (R0)", "Delete (R0) only supports files.");
                return;
            }
        }
        const QString Prompt = QString("Force delete %1 selected file(s) through the kernel driver?").arg(Paths.size());
        if (QMessageBox::warning(this, "Delete (R0)", Prompt, QMessageBox::Yes | QMessageBox::No,
                                 QMessageBox::No) != QMessageBox::Yes)
            return;
        QStringList Failures;
        for (const QString &Path : Paths)
        {
            const std::wstring WidePath = QDir::toNativeSeparators(Path).toStdWString();
            if (!ForceDeleteFile(WidePath.c_str()))
                Failures.append(QString("%1 (error %2)").arg(QFileInfo(Path).fileName()).arg(G_LastMultiDrvError));
        }
        if (!Failures.isEmpty())
            ShowErrorNotice(this, "Delete (R0)", "Failed to force delete:\n" + Failures.join("\n"));
        else
            ShowSuccessNotice(this, "Delete (R0)", QString("Force deleted %1 file(s).").arg(Paths.size()));
    }

    bool CopyRecursively(const QString &SourcePath, const QString &DestinationPath)
    {
        const QFileInfo SourceInformation(SourcePath);
        if (SourceInformation.isDir())
        {
            QDir DestinationDirectory;
            if (!DestinationDirectory.mkpath(DestinationPath))
                return false;
            const QDir SourceDirectory(SourcePath);
            for (const QFileInfo &Child : SourceDirectory.entryInfoList(QDir::AllEntries | QDir::NoDotAndDotDot))
            {
                if (!CopyRecursively(Child.absoluteFilePath(), QDir(DestinationPath).filePath(Child.fileName())))
                    return false;
            }
            return true;
        }
        if (QFileInfo::exists(DestinationPath))
            return false;
        return QFile::copy(SourcePath, DestinationPath);
    }

    void CopySelection()
    {
        const QStringList Paths = SelectedPaths();
        if (Paths.isEmpty())
            return;
        const QString DestinationDirectory = QFileDialog::getExistingDirectory(this, "Copy to", CurrentPath);
        if (DestinationDirectory.isEmpty())
            return;
        QStringList Failures;
        for (const QString &Path : Paths)
        {
            const QFileInfo Information(Path);
            const QString DestinationPath = QDir(DestinationDirectory).filePath(Information.fileName());
            if (!CopyRecursively(Information.absoluteFilePath(), DestinationPath))
                Failures.append(Information.fileName());
        }
        if (!Failures.isEmpty())
            ShowErrorNotice(this, "Copy", "Failed to copy:\n" + Failures.join("\n") +
                                           "\nThe destination item may already exist.");
        else
            ShowSuccessNotice(this, "Copy", QString("Copied %1 item(s).").arg(Paths.size()));
    }

    void CopySelectionPath()
    {
        const QStringList Paths = SelectedPaths();
        qApp->clipboard()->setText(Paths.isEmpty() ? QDir::toNativeSeparators(CurrentPath)
                                                   : Paths.join("\n"));
        ShowSuccessNotice(this, "Copy path", "Path copied to the clipboard.");
    }

    void BrowseMonitorDirectory()
    {
        const QString Directory = QFileDialog::getExistingDirectory(this, "Monitor directory", CurrentPath);
        if (Directory.isEmpty())
            return;
        StartMonitoringDirectory(Directory, true, true);
    }

    void EnsureFileMonitorWorker()
    {
        if (FileMonitor)
            return;

        FileMonitor = std::make_unique<KernelMonitor>(MonitorChannel::File);
        QPointer<FileExplorerPage> Page(this);
        FileMonitor->SetCallback([Page](const MonitorEvent &Event) {
            if (!Page)
                return;
            QMetaObject::invokeMethod(Page, [Page, Event] {
                if (Page)
                    Page->AppendMonitorEvent(Event);
            }, Qt::QueuedConnection);
        });
    }

    void StartMonitoringDirectory(const QString &DirectoryPath, bool SwitchToMonitorTab, bool ShowNotice)
    {
        const QFileInfo Information(DirectoryPath);
        const QString AbsoluteDirectory = Information.isDir() ? Information.absoluteFilePath() : Information.absolutePath();
        if (AbsoluteDirectory.isEmpty() || !QFileInfo(AbsoluteDirectory).isDir())
        {
            ShowErrorNotice(this, "File monitor", "Select a valid directory first.");
            return;
        }

        QString NtPath;
        if (!ConvertToNtPath(AbsoluteDirectory, NtPath))
        {
            ShowErrorNotice(this, "File monitor", "Unable to convert the directory to an NT path.");
            return;
        }

        try
        {
            EnsureFileMonitorWorker();
            if (!MonitorDrvSetWatchDirectory(NtPath.toStdWString().c_str()))
            {
                ShowErrorNotice(this, "File monitor",
                                QString("Kernel watch setup failed (error %1).").arg(GetLastError()));
                return;
            }

            if (!FileMonitor->IsRunning() && !FileMonitor->Start())
            {
                ShowErrorNotice(this, "File monitor", "Failed to start the file monitor worker.");
                return;
            }
        }
        catch (const std::exception &Error)
        {
            FileMonitor.reset();
            ShowErrorNotice(this, "File monitor", QString::fromLocal8Bit(Error.what()));
            return;
        }

        WatchedDisplayPath = QDir::toNativeSeparators(AbsoluteDirectory);
        WatchedNtPath = NtPath;
        ClearMonitorEvents();
        UpdateMonitorWatchUi(true);
        if (SwitchToMonitorTab && TabBarWidget)
            TabBarWidget->setCurrentIndex(2);
        if (ShowNotice)
            ShowSuccessNotice(this, "File monitor", "Directory monitoring started.");
    }

    void StopFileMonitor(bool ShowNotice)
    {
        if (FileMonitor)
        {
            FileMonitor->Stop();
            FileMonitor.reset();
        }

        MonitorDrvClearWatchDirectory();
        WatchedDisplayPath.clear();
        WatchedNtPath.clear();
        UpdateMonitorWatchUi(false);
        if (ShowNotice)
            ShowSuccessNotice(this, "File monitor", "Directory monitoring stopped.");
    }

    void UpdateMonitorWatchUi(bool Running)
    {
        if (MonitorStatusLabel)
            MonitorStatusLabel->setText(Running ? "Running" : "Stopped");
        if (MonitorDirectoryLabel)
            MonitorDirectoryLabel->setText(Running
                                              ? (WatchedDisplayPath.isEmpty() ? WatchedNtPath : WatchedDisplayPath)
                                              : "-");
        if (MonitorStopButton)
            MonitorStopButton->setEnabled(Running);
    }

    void AppendMonitorEvent(const MonitorEvent &Event)
    {
        std::lock_guard<std::mutex> Lock(MonitorMutex);
        MonitorEvents.insert(MonitorEvents.begin(), BuildMonitorEntry(Event));
        if (MonitorEvents.size() > 500)
            MonitorEvents.resize(500);
        MonitorVersion.fetch_add(1, std::memory_order_relaxed);
    }

    void ClearMonitorEvents()
    {
        {
            std::lock_guard<std::mutex> Lock(MonitorMutex);
            MonitorEvents.clear();
            MonitorVersion.fetch_add(1, std::memory_order_relaxed);
        }
        RefreshMonitorTable();
    }

    void RefreshMonitorTable()
    {
        if (!MonitorTable)
            return;

        std::vector<FileMonitorEntry> Rows;
        {
            std::lock_guard<std::mutex> Lock(MonitorMutex);
            Rows = MonitorEvents;
        }

        const QString Query = MonitorSearchEdit ? MonitorSearchEdit->text().trimmed() : QString();
        std::vector<const FileMonitorEntry *> VisibleRows;
        VisibleRows.reserve(Rows.size());
        for (const FileMonitorEntry &Entry : Rows)
        {
            const QString PidText = QString::number(Entry.ProcessId);
            if (!Query.isEmpty() &&
                !Entry.Timestamp.contains(Query, Qt::CaseInsensitive) &&
                !Entry.Operation.contains(Query, Qt::CaseInsensitive) &&
                !Entry.Process.contains(Query, Qt::CaseInsensitive) &&
                !Entry.Path.contains(Query, Qt::CaseInsensitive) &&
                !Entry.Detail.contains(Query, Qt::CaseInsensitive) &&
                !PidText.contains(Query, Qt::CaseInsensitive))
            {
                continue;
            }
            VisibleRows.push_back(&Entry);
        }
        SetTableRefreshEnabled(MonitorTable, false);
        MonitorTable->clearContents();
        MonitorTable->setRowCount(static_cast<int>(VisibleRows.size()));
        for (int Row = 0; Row < static_cast<int>(VisibleRows.size()); ++Row)
        {
            const FileMonitorEntry &Entry = *VisibleRows[Row];
            const QString PidText = QString::number(Entry.ProcessId);
            auto *TimeItem = new QTableWidgetItem(Entry.Timestamp);
            TimeItem->setData(Qt::UserRole, Entry.Detail);
            MonitorTable->setItem(Row, 0, TimeItem);
            MonitorTable->setItem(Row, 1, new QTableWidgetItem(Entry.Operation));
            MonitorTable->setItem(Row, 2, new QTableWidgetItem(Entry.Process));
            MonitorTable->setItem(Row, 3, new QTableWidgetItem(PidText));
            auto *PathItem = new QTableWidgetItem(Entry.Path);
            PathItem->setToolTip(Entry.Path);
            MonitorTable->setItem(Row, 4, PathItem);
            MonitorTable->setRowHeight(Row, KCompactTableRowHeight);
        }
        SetTableRefreshEnabled(MonitorTable, true);
    }

    void ShowMonitorDetails(int Row)
    {
        QTableWidgetItem *Item = MonitorTable->item(Row, 0);
        if (!Item)
            return;
        const QString Detail = Item->data(Qt::UserRole).toString();
        auto *Dialog = new QDialog(this);
        Dialog->setAttribute(Qt::WA_DeleteOnClose);
        Dialog->setWindowTitle("File monitor details");
        Dialog->resize(920, 620);
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

    void ShowMonitorPath(int Row)
    {
        QTableWidgetItem *Item = MonitorTable->item(Row, 4);
        if (!Item)
            return;

        auto *Dialog = new QDialog(this);
        Dialog->setAttribute(Qt::WA_DeleteOnClose);
        Dialog->setWindowTitle("File path");
        Dialog->resize(920, 220);
        auto *Layout = new QVBoxLayout(Dialog);
        auto *Text = new PlainTextEdit;
        Text->setReadOnly(true);
        Text->setFont(QFont("Cascadia Mono", 10));
        Text->setPlainText(Item->text());
        InstallFluentScrollBar(Text, Qt::Vertical);
        Layout->addWidget(Text, 1);
        auto *Close = MakeButton("Close", true);
        Layout->addWidget(Close, 0, Qt::AlignRight);
        QObject::connect(Close, &QPushButton::clicked, Dialog, &QDialog::accept);
        Dialog->show();
    }

    void ShowMonitorContextMenu(const QPoint &Position)
    {
        const QModelIndex Index = MonitorTable->indexAt(Position);
        if (!Index.isValid())
            return;
        MonitorTable->selectRow(Index.row());
        auto *Menu = new RoundMenu(QString(), this);
        auto *CopyAction = new QAction("Copy information", Menu);
        auto *DetailAction = new QAction("Detailed information", Menu);
        Menu->addAction(CopyAction);
        Menu->addAction(DetailAction);
        ConnectMenuAction(CopyAction, this, [this, Row = Index.row()] {
            if (auto *Item = MonitorTable->item(Row, 0))
            {
                qApp->clipboard()->setText(Item->data(Qt::UserRole).toString());
                ShowSuccessNotice(this, "File monitor", "Event information copied.");
            }
        });
        ConnectMenuAction(DetailAction, this, [this, Row = Index.row()] { ShowMonitorDetails(Row); });
        ReleaseMenuAfterClose(Menu);
        Menu->exec(MonitorTable->viewport()->mapToGlobal(Position));
    }

    void ProtectSelection()
    {
        const QStringList Paths = SelectedPaths();
        if (Paths.isEmpty())
            return;
        QStringList Failures;
        int ProtectedCount = 0;
        for (const QString &Path : Paths)
        {
            const QString NormalizedPath = QDir::toNativeSeparators(QFileInfo(Path).absoluteFilePath());
            QString NtPath;
            if (!ConvertToNtPath(NormalizedPath, NtPath))
            {
                Failures.append(QFileInfo(Path).fileName());
                continue;
            }
            const std::wstring WidePath = NtPath.toStdWString();
            if (!ProtectFile(WidePath.c_str()))
                Failures.append(QFileInfo(Path).fileName());
            else
            {
                const auto Match = std::find_if(ProtectedFiles.begin(), ProtectedFiles.end(),
                                                [&NormalizedPath](const ProtectedFileEntry &Entry) {
                    return Entry.DisplayPath.compare(NormalizedPath, Qt::CaseInsensitive) == 0;
                });
                if (Match == ProtectedFiles.end())
                    ProtectedFiles.append({NormalizedPath, NtPath});
                ++ProtectedCount;
            }
        }
        RefreshProtectedTable();
        if (Failures.isEmpty())
            ShowSuccessNotice(this, "Protect", QString("Protected %1 item(s).").arg(ProtectedCount));
        else
            ShowErrorNotice(this, "Protect", "Failed to protect:\n" + Failures.join("\n"));
    }

    void RefreshProtectedTable()
    {
        SetTableRefreshEnabled(ProtectedTable, false);
        ProtectedTable->clearContents();
        ProtectedTable->setRowCount(ProtectedFiles.size());
        for (int Row = 0; Row < ProtectedFiles.size(); ++Row)
        {
            const ProtectedFileEntry &Entry = ProtectedFiles.at(Row);
            auto *NameItem = new QTableWidgetItem(QFileInfo(Entry.DisplayPath).fileName());
            NameItem->setData(Qt::UserRole, Entry.DisplayPath);
            NameItem->setData(Qt::UserRole + 1, Entry.NtPath);
            ProtectedTable->setItem(Row, 0, NameItem);
            ProtectedTable->setItem(Row, 1, new QTableWidgetItem(Entry.DisplayPath));
            ProtectedTable->setRowHeight(Row, KCompactTableRowHeight);
        }
        SetTableRefreshEnabled(ProtectedTable, true);
        UnprotectButton->setEnabled(false);
    }

    void UnprotectSelection()
    {
        QList<ProtectedFileEntry> Entries;
        for (const QModelIndex &Index : ProtectedTable->selectionModel()->selectedRows(0))
            Entries.append({Index.data(Qt::UserRole).toString(), Index.data(Qt::UserRole + 1).toString()});
        if (Entries.isEmpty())
            return;
        QStringList Failures;
        for (const ProtectedFileEntry &Entry : Entries)
        {
            const std::wstring WidePath = Entry.NtPath.toStdWString();
            if (!UnprotectFile(WidePath.c_str()))
                Failures.append(QFileInfo(Entry.DisplayPath).fileName());
            else
            {
                const auto Match = std::find_if(ProtectedFiles.begin(), ProtectedFiles.end(),
                                                [&Entry](const ProtectedFileEntry &Item) {
                    return Item.DisplayPath.compare(Entry.DisplayPath, Qt::CaseInsensitive) == 0;
                });
                if (Match != ProtectedFiles.end())
                    ProtectedFiles.erase(Match);
            }
        }
        RefreshProtectedTable();
        if (!Failures.isEmpty())
            ShowErrorNotice(this, "Unprotect", "Failed to unprotect:\n" + Failures.join("\n"));
        else
            ShowSuccessNotice(this, "Unprotect", QString("Unprotected %1 item(s).").arg(Entries.size()));
    }

    bool ConvertToNtPath(const QString &Path, QString &NtPath) const
    {
        QString NativePath = QDir::toNativeSeparators(Path);
        if (NativePath.startsWith("\\Device\\", Qt::CaseInsensitive))
        {
            NtPath = NativePath;
            return true;
        }
        if (NativePath.startsWith("\\\\"))
        {
            NtPath = "\\Device\\Mup" + NativePath.mid(1);
            return true;
        }
        if (NativePath.size() < 3 || NativePath.at(1) != ':')
            return false;

        const QString Drive = NativePath.left(2);
        std::vector<wchar_t> DeviceBuffer(32768, L'\0');
        if (QueryDosDeviceW(reinterpret_cast<LPCWSTR>(Drive.utf16()), DeviceBuffer.data(),
                            static_cast<DWORD>(DeviceBuffer.size())) == 0)
            return false;
        NtPath = QString::fromWCharArray(DeviceBuffer.data()) + NativePath.mid(2);
        return NtPath.startsWith("\\Device\\", Qt::CaseInsensitive);
    }

    void ShowContextMenu(const QPoint &Position)
    {
        const QModelIndex Index = FileView->indexAt(Position);
        if (!Index.isValid())
            return;
        const QModelIndex NameIndex = Index.siblingAtColumn(0);
        if (!FileView->selectionModel()->isSelected(NameIndex))
        {
            FileView->selectionModel()->clearSelection();
            FileView->selectionModel()->select(NameIndex,
                QItemSelectionModel::Select | QItemSelectionModel::Rows);
            FileView->setCurrentIndex(NameIndex);
        }

        auto *Menu = new RoundMenu(QString(), this);
        auto *DeleteAction = new QAction("Delete", Menu);
        auto *DeleteR0Action = new QAction("Delete (R0)", Menu);
        auto *CopyAction = new QAction("Copy", Menu);
        auto *CopyPathAction = new QAction("Copy path", Menu);
        auto *RenameAction = new QAction("Rename", Menu);
        auto *ProtectAction = new QAction("Protect", Menu);
        auto *MonitorAction = new QAction("Monitor directory", Menu);
        const QStringList Paths = SelectedPaths();
        DeleteR0Action->setEnabled(std::all_of(Paths.begin(), Paths.end(),
                                               [](const QString &Path) { return QFileInfo(Path).isFile(); }));
        RenameAction->setEnabled(Paths.size() == 1);
        MonitorAction->setEnabled(Paths.size() == 1);
        Menu->addAction(DeleteAction);
        Menu->addAction(DeleteR0Action);
        Menu->addSeparator();
        Menu->addAction(CopyAction);
        Menu->addAction(CopyPathAction);
        Menu->addAction(RenameAction);
        Menu->addSeparator();
        Menu->addAction(ProtectAction);
        Menu->addAction(MonitorAction);
        ConnectMenuAction(DeleteAction, this, [this] { DeleteSelection(); });
        ConnectMenuAction(DeleteR0Action, this, [this] { DeleteSelectionR0(); });
        ConnectMenuAction(CopyAction, this, [this] { CopySelection(); });
        ConnectMenuAction(CopyPathAction, this, [this] { CopySelectionPath(); });
        ConnectMenuAction(RenameAction, this, [this] { RenameSelection(); });
        ConnectMenuAction(ProtectAction, this, [this] { ProtectSelection(); });
        ConnectMenuAction(MonitorAction, this, [this, Paths] {
            const QFileInfo Information(Paths.first());
            StartMonitoringDirectory(Information.isDir() ? Information.absoluteFilePath() : Information.absolutePath(),
                                     true, true);
        });
        ReleaseMenuAfterClose(Menu);
        Menu->exec(FileView->viewport()->mapToGlobal(Position));
    }

    TabBar *TabBarWidget = nullptr;
    QStackedWidget *Pages = nullptr;
    QFileSystemModel *DirectoryModel = nullptr;
    QFileSystemModel *FileModel = nullptr;
    QTreeView *DirectoryTree = nullptr;
    QTreeView *FileView = nullptr;
    ToolButton *BackButton = nullptr;
    ToolButton *ForwardButton = nullptr;
    ToolButton *UpButton = nullptr;
    ToolButton *RefreshButton = nullptr;
    LineEdit *AddressEdit = nullptr;
    SearchLineEdit *SearchEdit = nullptr;
    BodyLabel *StatusLabel = nullptr;
    TableWidget *ProtectedTable = nullptr;
    PushButton *UnprotectButton = nullptr;
    TableWidget *MonitorTable = nullptr;
    SearchLineEdit *MonitorSearchEdit = nullptr;
    QTimer *MonitorSearchDebounceTimer = nullptr;
    BodyLabel *MonitorStatusLabel = nullptr;
    BodyLabel *MonitorDirectoryLabel = nullptr;
    PushButton *MonitorStopButton = nullptr;
    PushButton *MonitorClearButton = nullptr;
    QTimer *MonitorRefreshTimer = nullptr;
    std::unique_ptr<KernelMonitor> FileMonitor;
    std::mutex MonitorMutex;
    std::vector<FileMonitorEntry> MonitorEvents;
    std::atomic_uint64_t MonitorVersion = 0;
    uint64_t DisplayedMonitorVersion = 0;
    QString WatchedDisplayPath;
    QString WatchedNtPath;
    QString CurrentPath;
    QStringList History;
    QList<ProtectedFileEntry> ProtectedFiles;
    int HistoryIndex = -1;

  protected:
    void showEvent(QShowEvent *Event) override
    {
        QWidget::showEvent(Event);
        if (MonitorRefreshTimer)
            MonitorRefreshTimer->start();
    }

    void hideEvent(QHideEvent *Event) override
    {
        if (MonitorRefreshTimer)
            MonitorRefreshTimer->stop();
        QWidget::hideEvent(Event);
    }
};

