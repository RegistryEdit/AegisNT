QWidget *CreateModuleManagerPage()
{
    auto *Page = new QWidget;
    auto *Layout = new QVBoxLayout(Page);
    ConfigurePageLayout(Layout, 10);

    auto *Paths = new BodyLabel;
    Paths->setWordWrap(true);
    Paths->setText("Modules: " + ConfigurationPaths("Modules", "./Modules").join("; ") +
                   "\nDrivers: " + ConfigurationPaths("Drivers", "./Drivers").join("; "));
    Layout->addWidget(Paths);

    auto *Toolbar = new QHBoxLayout;
    ConfigureToolbarLayout(Toolbar);
    auto *Search = new SearchLineEdit;
    Search->setPlaceholderText("Search");
    Search->setClearButtonEnabled(true);
    Search->setMaximumWidth(320);
    auto *Kind = new ComboBox;
    Kind->addItems({"All", "DLL modules", "System drivers"});
    Kind->setCurrentIndex(0);
    auto *Remove = MakeButton("Remove");
    auto *AddModule = MakeButton("Load DLL");
    auto *Refresh = MakeButton("Refresh", true);
    Toolbar->addWidget(Search);
    Toolbar->addWidget(Kind);
    Toolbar->addStretch();
    Toolbar->addWidget(Remove);
    Toolbar->addWidget(AddModule);
    Toolbar->addWidget(Refresh);
    Layout->addLayout(Toolbar);

    auto *Table = MakeTable({"Name", "Type", "Author", "State", "Path"});
    Table->setSelectionMode(QAbstractItemView::SingleSelection);
    Table->setContextMenuPolicy(Qt::CustomContextMenu);
    Table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    Table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    Table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    Table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    Table->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    Layout->addWidget(Table, 1);

    const auto SelectedPath = [Table] {
        const int Row = Table->currentRow();
        return Row < 0 || !Table->item(Row, 0) ? QString() : Table->item(Row, 0)->data(Qt::UserRole).toString();
    };
    const auto SelectedIsDriver = [Table] {
        const int Row = Table->currentRow();
        return Row >= 0 && Table->item(Row, 0) && Table->item(Row, 0)->data(Qt::UserRole + 1).toBool();
    };
    const auto RefreshActions = [Table, Remove] {
        const int Row = Table->currentRow();
        const bool HasSelection = Row >= 0 && Table->item(Row, 0);
        Remove->setEnabled(HasSelection && !ModuleRunning.load());
    };

    const auto Populate = [Kind, Search, Table, RefreshActions] {
        const QString Query = Search->text().trimmed();
        Table->clearContents();
        Table->setRowCount(0);
        const auto AppendModule = [Query, Table](ModuleEntry &Module, bool IsDriver) {
            const QString Name = QString::fromStdString(Module.Name);
            const QString Path = QString::fromStdString(Module.Path);
            const QString Category = QString::fromStdString(Module.Category);
            const QString Author = QString::fromStdString(Module.Author);
            if (IsDriver)
                Module.Loaded = QueryDriverLoadedState(Module);
            if (!Query.isEmpty() && !Name.contains(Query, Qt::CaseInsensitive) &&
                !Path.contains(Query, Qt::CaseInsensitive) && !Category.contains(Query, Qt::CaseInsensitive))
                return;
            const int Row = Table->rowCount();
            Table->insertRow(Row);
            auto *NameItem = new QTableWidgetItem(Name);
            NameItem->setData(Qt::UserRole, Path);
            NameItem->setData(Qt::UserRole + 1, IsDriver);
            Table->setItem(Row, 0, NameItem);
            Table->setItem(Row, 1, new QTableWidgetItem(Category));
            Table->setItem(Row, 2, new QTableWidgetItem(Author));
            Table->setItem(Row, 3, new QTableWidgetItem(Module.Valid ? (Module.Loaded ? "Active" : "Inactive") : "Skipped"));
            auto *PathItem = new QTableWidgetItem(Path);
            PathItem->setToolTip(QString::fromStdString(Module.Description));
            Table->setItem(Row, 4, PathItem);
            Table->setRowHeight(Row, KCompactTableRowHeight);
        };
        if (Kind->currentIndex() != 2)
        {
            for (ModuleEntry &Module : DllModules)
                AppendModule(Module, false);
        }
        if (Kind->currentIndex() != 1)
        {
            for (ModuleEntry &Driver : DriverModules)
                AppendModule(Driver, true);
        }
        RefreshActions();
    };

    QObject::connect(Search, &QLineEdit::textChanged, Page, [Populate](const QString &) { Populate(); });
    QObject::connect(Kind, &ComboBox::currentIndexChanged, Page, [Populate](int) { Populate(); });
    QObject::connect(Table, &QTableWidget::itemSelectionChanged, Page, RefreshActions);
    QObject::connect(Refresh, &QPushButton::clicked, Page, [Page, Populate] {
        if (ModuleRunning.load())
        {
            ShowWarningNotice(Page, "ModuleManager", "Wait for the running module to finish before reloading modules.");
            return;
        }
        ScanRuntimeModules();
        Populate();
        ShowSuccessNotice(Page, "ModuleManager", "Modules reloaded.");
    });
    QObject::connect(AddModule, &QPushButton::clicked, Page, [Page, Kind, Populate] {
        const QString Path = QFileDialog::getOpenFileName(Page, "Select DLL", QString(), "DLL files (*.dll)");
        if (Path.isEmpty())
            return;
        const QString AbsolutePath = QFileInfo(Path).absoluteFilePath();
        const bool Exists = std::any_of(DllModules.begin(), DllModules.end(), [&AbsolutePath](const ModuleEntry &Module) {
            return QString::fromStdString(Module.Path).compare(AbsolutePath, Qt::CaseInsensitive) == 0;
        });
        if (!Exists)
        {
            DllModules.push_back(ProbeModuleFile(AbsolutePath));
            ModuleEntry &Module = DllModules.back();
            if (Module.Valid && ConfigurationValue("Modules", "AutoLoad", true).toBool())
                LoadModuleInstance(Module);
        }
        Kind->setCurrentIndex(0);
        Populate();
        ShowSuccessNotice(Page, "ModuleManager", Exists ? "Module is already in the list." : "DLL module added.");
    });
    QObject::connect(Remove, &QPushButton::clicked, Page, [Page, SelectedPath, SelectedIsDriver, Populate] {
        const QString Path = SelectedPath();
        if (Path.isEmpty())
            return;
        const bool IsDriver = SelectedIsDriver();
        std::vector<ModuleEntry> &List = IsDriver ? DriverModules : DllModules;
        const auto Entry = std::find_if(List.begin(), List.end(), [&Path](const ModuleEntry &Module) {
            return QString::fromStdString(Module.Path) == Path;
        });
        if (Entry == List.end())
            return;
        if (Entry->Loaded)
        {
            QString Error;
            const bool Ok = IsDriver ? SetDriverLoaded(*Entry, false, &Error)
                                     : (DestroyModuleInstance(*Entry), true);
            if (!Ok)
            {
                ShowErrorNotice(Page, "ModuleManager", Error);
                return;
            }
        }
        List.erase(Entry);
        Populate();
        ShowSuccessNotice(Page, "ModuleManager", "Item removed from the module list.");
    });
    QObject::connect(Table, &QWidget::customContextMenuRequested, Page,
                     [Page, Table, Populate](const QPoint &Position) {
        const QModelIndex Index = Table->indexAt(Position);
        if (!Index.isValid() || ModuleRunning.load())
            return;
        Table->selectRow(Index.row());
        QTableWidgetItem *NameItem = Table->item(Index.row(), 0);
        if (!NameItem)
            return;
        const QString Path = NameItem->data(Qt::UserRole).toString();
        const bool IsDriver = NameItem->data(Qt::UserRole + 1).toBool();
        std::vector<ModuleEntry> &List = IsDriver ? DriverModules : DllModules;
        const auto Entry = std::find_if(List.begin(), List.end(), [&Path](const ModuleEntry &Module) {
            return QString::fromStdString(Module.Path) == Path;
        });
        if (Entry == List.end())
            return;

        auto *Menu = new RoundMenu(QString(), Page);
        auto *ToggleAction = new QAction(Entry->Loaded ? "Unload" : "Load", Menu);
        ToggleAction->setEnabled(Entry->Valid);
        Menu->addAction(ToggleAction);
        ConnectMenuAction(ToggleAction, Page,
                         [Page, Path, IsDriver, Populate] {
            std::vector<ModuleEntry> &TargetList = IsDriver ? DriverModules : DllModules;
            const auto Target = std::find_if(TargetList.begin(), TargetList.end(), [&Path](const ModuleEntry &Module) {
                return QString::fromStdString(Module.Path) == Path;
            });
            if (Target == TargetList.end())
                return;
            QString Error;
            bool Ok = false;
            if (IsDriver)
                Ok = SetDriverLoaded(*Target, !Target->Loaded, &Error);
            else if (Target->Loaded)
            {
                DestroyModuleInstance(*Target);
                Ok = true;
            }
            else
                Ok = LoadModuleInstance(*Target, &Error);
            if (!Ok)
                ShowErrorNotice(Page, "ModuleManager", Error.isEmpty() ? "The operation failed." : Error);
            else
                ShowSuccessNotice(Page, "ModuleManager", IsDriver ? "Driver state updated." : "Module state updated.");
            QTimer::singleShot(0, Page, Populate);
        });
        ReleaseMenuAfterClose(Menu);
        Menu->exec(Table->viewport()->mapToGlobal(Position));
    });

    EnsureRuntimeModulesScanned();
    Populate();
    return Page;
}

