QWidget *CreatePayloadPage()
{
    const auto PayloadChoiceNames = [](const QString &Key) {
        QStringList Names{"None"};
        for (const QJsonValue &Value : ConfigurationValue("Payload", Key, QJsonArray()).toArray())
        {
            const QString Name = Value.toString().trimmed();
            if (Name.isEmpty() || Name.compare("None", Qt::CaseInsensitive) == 0 ||
                Name.compare("(None)", Qt::CaseInsensitive) == 0)
                continue;
            bool Duplicate = false;
            for (const QString &Existing : Names)
            {
                if (Existing.compare(Name, Qt::CaseInsensitive) == 0)
                {
                    Duplicate = true;
                    break;
                }
            }
            if (!Duplicate)
                Names.append(Name);
        }
        return Names;
    };
    const auto SetPayloadOption = [](ModuleEntry *Entry, const QStringList &Aliases, const QString &Value) {
        if (!Entry)
            return;
        SetCachedModuleOptionValue(*Entry, Aliases, Value);
    };

    auto *Page = new QWidget;
    auto *Layout = new QVBoxLayout(Page);
    ConfigurePageLayout(Layout);

    auto *Tabs = new TabBar;
    Tabs->setAddButtonVisible(false);
    Tabs->setTabsClosable(false);
    Tabs->setMovable(false);
    Tabs->addTab("generate", "Generate", Fluent::IconType::SEND);
    Tabs->addTab("shell", "Shell", Fluent::IconType::COMMAND_PROMPT);
    Tabs->setCurrentIndex(0);
    Layout->addWidget(Tabs);

    auto *Pages = new QStackedWidget;
    Layout->addWidget(Pages, 1);

    auto *GeneratePage = new QWidget;
    auto *GenerateLayout = new QVBoxLayout(GeneratePage);
    ConfigurePageLayout(GenerateLayout, 10);

    auto *ModuleCard = new SimpleCardWidget;
    ModuleCard->setBorderRadius(5);
    auto *ModuleCardLayout = new QVBoxLayout(ModuleCard);
    ModuleCardLayout->setContentsMargins(14, 14, 14, 14);
    ModuleCardLayout->setSpacing(8);
    ModuleCardLayout->addWidget(MakeLabel("Payload module", 12, KTextMuted, QFont::Normal));
    auto *ModuleRow = new QHBoxLayout;
    ConfigureToolbarLayout(ModuleRow);
    auto *Modules = new ComboBox;
    Modules->setMinimumWidth(220);
    auto *RefreshModules = MakeButton("Refresh");
    ModuleRow->addWidget(Modules, 1);
    ModuleRow->addWidget(RefreshModules);
    ModuleCardLayout->addLayout(ModuleRow);
    auto *Information = new BodyLabel("Select a payload module to generate output.");
    Information->setWordWrap(true);
    Information->setMinimumHeight(46);
    ModuleCardLayout->addWidget(Information);
    auto *TopLayout = new QHBoxLayout;
    ConfigureToolbarLayout(TopLayout, 10);
    TopLayout->addWidget(ModuleCard, 1);

    auto *OptionsCard = new SimpleCardWidget;
    OptionsCard->setBorderRadius(5);
    auto *OptionsCardLayout = new QGridLayout(OptionsCard);
    OptionsCardLayout->setContentsMargins(14, 14, 14, 14);
    OptionsCardLayout->setHorizontalSpacing(8);
    OptionsCardLayout->setVerticalSpacing(10);
    auto *Browse = MakeButton("Browse");
    auto *Encoder = new ComboBox;
    auto *Nop = new ComboBox;
    auto *OutputPath = new LineEdit;
    auto *Generate = MakeButton("Generate", true);
    Encoder->addItems(PayloadChoiceNames("Encoder"));
    Nop->addItems(PayloadChoiceNames("Nop"));
    Encoder->setCurrentIndex(0);
    Nop->setCurrentIndex(0);
    OutputPath->setPlaceholderText("Path and filename");
    OptionsCardLayout->addWidget(MakeLabel("Encoder", 12, KTextMuted, QFont::Normal), 0, 0);
    OptionsCardLayout->addWidget(Encoder, 0, 1, 1, 2);
    OptionsCardLayout->addWidget(MakeLabel("Nop", 12, KTextMuted, QFont::Normal), 1, 0);
    OptionsCardLayout->addWidget(Nop, 1, 1, 1, 2);
    OptionsCardLayout->addWidget(MakeLabel("Output file", 12, KTextMuted, QFont::Normal), 2, 0);
    OptionsCardLayout->addWidget(OutputPath, 2, 1);
    OptionsCardLayout->addWidget(Browse, 2, 2);
    OptionsCardLayout->addWidget(Generate, 3, 2);
    OptionsCardLayout->setColumnStretch(1, 1);
    TopLayout->addWidget(OptionsCard, 1);
    GenerateLayout->addLayout(TopLayout);

    auto *OutputToolbar = new QHBoxLayout;
    ConfigureToolbarLayout(OutputToolbar);
    auto *OutputButton = MakeButton("Module Output");
    OutputButton->setSizePolicy(QSizePolicy::Maximum, QSizePolicy::Preferred);
    OutputToolbar->addStretch();
    OutputToolbar->addWidget(OutputButton);

    auto *ParametersToolbar = new QHBoxLayout;
    ConfigureToolbarLayout(ParametersToolbar);
    auto *ParametersLabel = MakeLabel("Parameters", 13, KTextPrimary, QFont::DemiBold);
    ParametersToolbar->addWidget(ParametersLabel);
    ParametersToolbar->addStretch();
    auto *Parameters = new TableWidget;
    InstallFluentScrollBar(Parameters, Qt::Vertical);
    InstallFluentScrollBar(Parameters, Qt::Horizontal);
    Parameters->setColumnCount(4);
    Parameters->setRowCount(0);
    Parameters->setHorizontalHeaderLabels({"Option", "Type", "Value", "Description"});
    Parameters->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    Parameters->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    Parameters->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    Parameters->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    Parameters->verticalHeader()->hide();
    Parameters->setSelectionMode(QAbstractItemView::NoSelection);
    Parameters->setEditTriggers(QAbstractItemView::NoEditTriggers);
    Parameters->setMinimumHeight(160);
    Parameters->verticalHeader()->setDefaultSectionSize(KCompactTableRowHeight);
    GenerateLayout->addLayout(ParametersToolbar);
    GenerateLayout->addWidget(Parameters);

    GenerateLayout->addLayout(OutputToolbar);
    Pages->addWidget(GeneratePage);

    auto *ShellPage = new QWidget;
    auto *ShellLayout = new QVBoxLayout(ShellPage);
    ConfigurePageLayout(ShellLayout, 10);
    const auto ShellState = std::make_shared<PayloadShellState>();
    ShellState->Page = ShellPage;

    auto *ConnectionCard = new SimpleCardWidget;
    ConnectionCard->setBorderRadius(5);
    ConnectionCard->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Maximum);
    auto *ConnectionLayout = new QHBoxLayout(ConnectionCard);
    ConnectionLayout->setContentsMargins(14, 14, 14, 14);
    ConnectionLayout->setSpacing(10);
    auto *HostListCard = new QWidget;
    HostListCard->setMinimumWidth(250);
    auto *HostListLayout = new QVBoxLayout(HostListCard);
    HostListLayout->setContentsMargins(0, 0, 0, 0);
    HostListLayout->setSpacing(8);
    HostListLayout->addWidget(MakeLabel("Hosts", 12, KTextMuted, QFont::Normal));
    auto *HostList = new QListWidget;
    HostList->setMinimumHeight(96);
    HostList->setMaximumHeight(160);
    HostList->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    HostList->setSelectionMode(QAbstractItemView::SingleSelection);
    HostList->setAlternatingRowColors(false);
    InstallFluentScrollBar(HostList, Qt::Vertical);
    HostListLayout->addWidget(HostList, 1);
    auto *ListButtons = new QHBoxLayout;
    ConfigureToolbarLayout(ListButtons, 8);
    auto *NewHostButton = MakeButton("New");
    auto *SaveHostButton = MakeButton("Save");
    auto *RemoveHostButton = MakeButton("Remove");
    ListButtons->addWidget(NewHostButton);
    ListButtons->addWidget(SaveHostButton);
    ListButtons->addWidget(RemoveHostButton);
    ListButtons->addStretch();
    HostListLayout->addLayout(ListButtons);
    ConnectionLayout->addWidget(HostListCard);

    auto *EditorHost = new QWidget;
    auto *EditorLayout = new QGridLayout(EditorHost);
    EditorLayout->setContentsMargins(0, 0, 0, 0);
    EditorLayout->setHorizontalSpacing(10);
    EditorLayout->setVerticalSpacing(12);
    auto *HostEdit = new LineEdit;
    HostEdit->setPlaceholderText("127.0.0.1");
    auto *PortEdit = new LineEdit;
    PortEdit->setPlaceholderText("4444");
    PortEdit->setMaximumWidth(100);
    auto *PasswordEdit = new LineEdit;
    PasswordEdit->setPlaceholderText("Password");
    PasswordEdit->setEchoMode(QLineEdit::Password);
    auto *CommandButton = MakeButton("Command");
    auto *ConnectButton = MakeButton("Connect", true);
    auto *DisconnectButton = MakeButton("Disconnect");
    EditorLayout->addWidget(MakeLabel("Host", 12, KTextMuted, QFont::Normal), 0, 0);
    EditorLayout->addWidget(HostEdit, 0, 1, 1, 3);
    EditorLayout->addWidget(MakeLabel("Port", 12, KTextMuted, QFont::Normal), 1, 0);
    EditorLayout->addWidget(PortEdit, 1, 1);
    EditorLayout->addWidget(MakeLabel("Password", 12, KTextMuted, QFont::Normal), 1, 2);
    EditorLayout->addWidget(PasswordEdit, 1, 3);
    EditorLayout->addWidget(CommandButton, 2, 1);
    EditorLayout->addWidget(ConnectButton, 2, 2);
    EditorLayout->addWidget(DisconnectButton, 2, 3);
    EditorLayout->setColumnStretch(1, 1);
    EditorLayout->setColumnStretch(3, 1);
    ConnectionLayout->addWidget(EditorHost, 1);
    ShellLayout->addWidget(ConnectionCard);

    Pages->addWidget(ShellPage);

    ShellState->HostList = HostList;
    ShellState->HostEdit = HostEdit;
    ShellState->PortEdit = PortEdit;
    ShellState->PasswordEdit = PasswordEdit;
    ShellState->CommandButton = CommandButton;
    ShellState->NewHostButton = NewHostButton;
    ShellState->SaveHostButton = SaveHostButton;
    ShellState->RemoveHostButton = RemoveHostButton;
    ShellState->ConnectButton = ConnectButton;
    ShellState->DisconnectButton = DisconnectButton;

    const auto CreateHostItem = [ShellState](const QString &Host, const QString &Port, const QString &Password = QString()) {
        auto *Item = new QListWidgetItem;
        PayloadShellCreateSession(ShellState, Item, Host, Port, Password);
        return Item;
    };
    std::function<void(QListWidgetItem *)> LoadHostToEditors;
    std::function<bool()> SaveSelectedHost;
    LoadHostToEditors = [ShellState](QListWidgetItem *Item) {
        const std::shared_ptr<PayloadShellSession> Session = PayloadShellSessionForItem(ShellState, Item);
        if (!Session)
            return;
        if (ShellState->HostEdit)
            ShellState->HostEdit->setText(Session->Host);
        if (ShellState->PortEdit)
            ShellState->PortEdit->setText(Session->Port);
        if (ShellState->PasswordEdit)
            ShellState->PasswordEdit->setText(Session->Password);
        PayloadShellRefreshHostList(ShellState);
    };
    SaveSelectedHost = [ShellState, ShellPage] {
        if (!ShellState->HostList || !ShellState->HostList->currentItem())
            return false;
        const std::shared_ptr<PayloadShellSession> Session = PayloadShellCurrentSession(ShellState);
        if (!Session)
            return false;

        const QString Host = ShellState->HostEdit ? ShellState->HostEdit->text().trimmed() : QString();
        const QString Port = ShellState->PortEdit ? ShellState->PortEdit->text().trimmed() : QString();
        if (Host.isEmpty())
        {
            ShowWarningNotice(ShellPage, "Payload Shell", "Host is required.");
            return false;
        }

        auto *Item = ShellState->HostList->currentItem();
        Session->Host = Host;
        Session->Port = Port;
        Session->Password = ShellState->PasswordEdit ? ShellState->PasswordEdit->text() : QString();
        Item->setData(KPayloadShellRoleHost, Session->Host);
        Item->setData(KPayloadShellRolePort, Session->Port);
        Item->setData(KPayloadShellRolePassword, Session->Password);
        PayloadShellRefreshHostList(ShellState);
        PayloadShellUpdateCommandWindowTitle(Session);
        PayloadShellPersistConfiguration(ShellState);
        return true;
    };

    const QJsonObject PayloadShellObject = ConfigurationSection("PayloadShell");
    const QJsonArray SavedHosts = PayloadShellObject.value("Hosts").toArray();
    if (SavedHosts.isEmpty())
    {
        HostList->addItem(CreateHostItem(ConfigurationValue("PayloadShell", "Host", "127.0.0.1").toString(),
                                         ConfigurationValue("PayloadShell", "Port", "4444").toString()));
    }
    else
    {
        for (const QJsonValue &Value : SavedHosts)
        {
            const QJsonObject HostObject = Value.toObject();
            const QString Host = HostObject.value("Host").toString().trimmed();
            if (Host.isEmpty())
                continue;
            HostList->addItem(CreateHostItem(Host, HostObject.value("Port").toString().trimmed()));
        }
        if (HostList->count() == 0)
            HostList->addItem(CreateHostItem("127.0.0.1", "4444"));
    }
    HostList->setCurrentRow(std::clamp(PayloadShellObject.value("SelectedHost").toInt(), 0, std::max(0, HostList->count() - 1)));
    LoadHostToEditors(HostList->currentItem());

    std::function<void(const std::shared_ptr<PayloadShellSession> &, const QString &, const QColor &)> FinalizeSession;
    std::function<void(bool)> DisconnectShell;
    std::function<void(const std::shared_ptr<PayloadShellSession> &, const QString &)> SendShellCommand;
    FinalizeSession = [ShellState](const std::shared_ptr<PayloadShellSession> &Session, const QString &StatusText,
                                   const QColor &Color) {
        if (!Session)
            return;
        QPointer<QTcpSocket> Socket = Session->Socket;
        if (Socket)
        {
            Socket->disconnect();
            Socket->deleteLater();
            if (Session->Socket == Socket)
                Session->Socket = nullptr;
        }
        PayloadShellResetConnectionState(Session);
        PayloadShellSetStatus(Session, StatusText, Color);
        PayloadShellUpdateControls(ShellState);
    };
    DisconnectShell = [ShellState, ShellPage, FinalizeSession](bool SendExit) {
        const std::shared_ptr<PayloadShellSession> Session = PayloadShellCurrentSession(ShellState);
        if (!Session || !Session->Socket)
        {
            FinalizeSession(Session, "Disconnected", QColor("#8A94A6"));
            return;
        }
        Session->DisconnectRequested = true;
        if (SendExit && !Session->SessionKey.isEmpty())
        {
            QString Error;
            PayloadShellSendEncrypted(Session, "exit", &Error);
        }
        QPointer<QTcpSocket> Socket = Session->Socket;
        Socket->disconnectFromHost();
        QTimer::singleShot(300, ShellPage, [Socket] {
            if (Socket && Socket->state() != QAbstractSocket::UnconnectedState)
                Socket->abort();
        });
    };
    SendShellCommand = [ShellState](const std::shared_ptr<PayloadShellSession> &Session, const QString &OverrideCommand) {
        if (!Session)
            return;
        const bool UseOverride = !OverrideCommand.isNull();
        const QString Command = (UseOverride
                                     ? OverrideCommand
                                     : (Session->CommandEdit ? Session->CommandEdit->text() : QString()))
                                    .trimmed();
        if (Command.isEmpty())
            return;
        if (Session->SessionKey.isEmpty())
        {
            PayloadShellLog(Session, "Not connected!", QColor("#FF5F56"));
            return;
        }
        if (Session->Authenticating || !Session->PendingCommand.isEmpty())
        {
            PayloadShellLog(Session, "Wait for the current command to finish.", QColor("#F4BF4F"));
            return;
        }
        if (!UseOverride && Session->CommandEdit)
            Session->CommandEdit->clear();
        PayloadShellLog(Session, "> " + Command, QColor("#F4BF4F"));
        QString Error;
        if (!PayloadShellSendEncrypted(Session, Command, &Error))
        {
            PayloadShellLog(Session, "Send failed: " + Error, QColor("#FF5F56"));
            if (Session->Socket)
                Session->Socket->disconnectFromHost();
            return;
        }
        Session->PendingCommand = Command;
        PayloadShellUpdateControls(ShellState);
    };

    for (const auto &[Id, Session] : ShellState->Sessions)
    {
        Q_UNUSED(Id);
        PayloadShellSetStatus(Session, "Disconnected", QColor("#8A94A6"));
        PayloadShellLog(Session, "Remote control client ready.", QColor("#4FC3F7"));
    }
    PayloadShellUpdateControls(ShellState);

    const auto PopulateModules = [Modules, Information] {
        const QString PreviousPath = Modules->currentData().toString();
        Modules->blockSignals(true);
        Modules->clear();
        int SelectedIndex = -1;
        int Index = 0;
        for (ModuleEntry *Module : ModulesByCategory("Payload", true))
        {
            const QString Path = QString::fromStdString(Module->Path);
            Modules->addItem(QString::fromStdString(Module->Name), Path);
            if (Path == PreviousPath)
                SelectedIndex = Index;
            ++Index;
        }
        if (Modules->count() == 0)
        {
            Modules->addItem("No payload module", QString());
            Modules->setEnabled(false);
            Information->setText("No payload module is available.");
        }
        else
        {
            Modules->setEnabled(true);
            Modules->setCurrentIndex(SelectedIndex >= 0 ? SelectedIndex : 0);
        }
        Modules->blockSignals(false);
    };
    const auto IsBuiltInPayloadOption = [](const std::string &Name) {
        return OptionNameMatches(Name, {"FilePath", "File_Path", "Output", "OutputPath", "Path", "File", "FileName",
                                        "Encoder", "Encoder_Module", "Nop", "Nop_Module"});
    };
    const auto PopulateAdditionalParameters = [Modules, Parameters, IsBuiltInPayloadOption, SetPayloadOption] {
        Parameters->setRowCount(0);
        ModuleEntry *Entry = FindDllModule(Modules->currentData().toString());
        if (!Entry)
            return;

        QString Error;
        if (!LoadModuleInstance(*Entry, &Error))
            return;

        auto *Instance = static_cast<ModuleBase *>(Entry->ModuleInstance);
        const auto &ModuleOptions = Instance->GetOptions();
        int VisibleCount = 0;
        for (const auto &[Name, OptionPointer] : ModuleOptions)
        {
            Q_UNUSED(OptionPointer);
            if (!IsBuiltInPayloadOption(Name))
                ++VisibleCount;
        }

        Parameters->setRowCount(VisibleCount);
        int Row = 0;
        const QString Path = Modules->currentData().toString();
        for (const auto &[Name, OptionPointer] : ModuleOptions)
        {
            if (IsBuiltInPayloadOption(Name))
                continue;

            const bool Required = OptionPointer->GetRequired() == OptionRequired::Required;
            auto *NameItem = new QTableWidgetItem(QString::fromStdString(Name) + (Required ? " *" : ""));
            NameItem->setToolTip(QString::fromStdString(OptionPointer->GetDescription()));
            Parameters->setItem(Row, 0, NameItem);
            Parameters->setItem(Row, 1, new QTableWidgetItem(QString::fromStdString(OptionPointer->TypeName())));
            Parameters->setItem(Row, 3, new QTableWidgetItem(QString::fromStdString(OptionPointer->GetDescription())));

            const QString InitialValue = QString::fromStdString(OptionPointer->GetValue());
            const QString OptionName = QString::fromStdString(Name);
            if (auto *EnumOption = dynamic_cast<OptEnum *>(OptionPointer.get()))
            {
                auto *Editor = new ComboBox;
                for (const std::string &Choice : EnumOption->GetChoices())
                    Editor->addItem(QString::fromStdString(Choice));
                Editor->setCurrentText(InitialValue);
                QObject::connect(Editor, &ComboBox::currentTextChanged, Editor,
                                 [Path, OptionName, SetPayloadOption](const QString &Value) {
                    if (ModuleEntry *Module = FindDllModule(Path))
                        SetPayloadOption(Module, {OptionName}, Value);
                });
                Parameters->setCellWidget(Row, 2, Editor);
            }
            else if (dynamic_cast<OptBool *>(OptionPointer.get()))
            {
                auto *Editor = new ComboBox;
                Editor->addItems({"true", "false"});
                Editor->setCurrentText(InitialValue.compare("false", Qt::CaseInsensitive) == 0 ? "false" : "true");
                QObject::connect(Editor, &ComboBox::currentTextChanged, Editor,
                                 [Path, OptionName, SetPayloadOption](const QString &Value) {
                    if (ModuleEntry *Module = FindDllModule(Path))
                        SetPayloadOption(Module, {OptionName}, Value);
                });
                Parameters->setCellWidget(Row, 2, Editor);
            }
            else
            {
                auto *Editor = new LineEdit;
                Editor->setText(InitialValue);
                Editor->setPlaceholderText(QString::fromStdString(OptionPointer->GetDefaultValue()));
                QObject::connect(Editor, &QLineEdit::textChanged, Editor,
                                 [Path, OptionName, SetPayloadOption](const QString &Value) {
                    if (ModuleEntry *Module = FindDllModule(Path))
                        SetPayloadOption(Module, {OptionName}, Value);
                });
                Parameters->setCellWidget(Row, 2, Editor);
            }

            Parameters->setRowHeight(Row, 42);
            ++Row;
        }
    };
    const auto UpdateInformation = [Modules, Information, OutputPath, PopulateAdditionalParameters] {
        ModuleEntry *Entry = FindDllModule(Modules->currentData().toString());
        if (!Entry)
        {
            Information->setText("No payload module is available.");
            OutputPath->clear();
            PopulateAdditionalParameters();
            return;
        }
        const QString FilePath = CachedModuleOptionValue(
            *Entry, {"FilePath", "File_Path", "Output", "OutputPath", "Path", "File", "FileName"});
        if (OutputPath->text() != FilePath)
            OutputPath->setText(FilePath);
        Information->setText(
            QString("Payload/%1  |  Author: %2\n%3")
                .arg(QString::fromStdString(Entry->Name), QString::fromStdString(Entry->Author),
                     QString::fromStdString(Entry->Description)));
        PopulateAdditionalParameters();
    };

    QObject::connect(Tabs, &TabBar::currentChanged, Pages, &QStackedWidget::setCurrentIndex);
    QObject::connect(Pages, &QStackedWidget::currentChanged, Tabs, &TabBar::setCurrentIndex);
    QObject::connect(Modules, &ComboBox::currentIndexChanged, Page, [UpdateInformation](int) { UpdateInformation(); });
    QObject::connect(RefreshModules, &QPushButton::clicked, Page, [Page, PopulateModules, UpdateInformation] {
        if (ModuleRunning.load())
        {
            ShowWarningNotice(Page, "Payload", "Wait for the running module to finish before refreshing.");
            return;
        }
        ScanRuntimeModules();
        PopulateModules();
        UpdateInformation();
        ShowSuccessNotice(Page, "Payload", "Payload module list refreshed.");
    });
    QObject::connect(Browse, &QPushButton::clicked, Page, [Page, OutputPath] {
        const QString Path = QFileDialog::getSaveFileName(Page, "Select output file", OutputPath->text(),
                                                          "All files (*.*)");
        if (!Path.isEmpty())
            OutputPath->setText(Path);
    });
    QObject::connect(OutputPath, &QLineEdit::textChanged, Page, [Modules, SetPayloadOption](const QString &Value) {
        ModuleEntry *Entry = FindDllModule(Modules->currentData().toString());
        SetPayloadOption(Entry, {"FilePath", "File_Path", "Output", "OutputPath", "Path", "File", "FileName"},
                         Value.trimmed());
    });
    QObject::connect(OutputButton, &QPushButton::clicked, Page, [Page] {
        ShowModuleOutputDialog(Page, "Payload Output");
    });
    QObject::connect(Generate, &QPushButton::clicked, Page, [Page, Modules, Encoder, Nop, OutputPath,
                                                             SetPayloadOption] {
        ModuleEntry *Entry = FindDllModule(Modules->currentData().toString());
        if (!Entry)
        {
            ShowWarningNotice(Page, "Payload", "No payload module is selected.");
            return;
        }
        QString Error;
        if (!LoadModuleInstance(*Entry, &Error))
        {
            ShowErrorNotice(Page, "Payload", Error);
            return;
        }
        const QString EncoderName = Encoder->currentIndex() > 0 ? Encoder->currentText().trimmed() : QString();
        const QString NopName = Nop->currentIndex() > 0 ? Nop->currentText().trimmed() : QString();
        SetPayloadOption(Entry, {"Encoder", "Encoder_Module"}, EncoderName);
        SetPayloadOption(Entry, {"Nop", "Nop_Module"}, NopName);
        SetPayloadOption(Entry, {"FilePath", "File_Path", "Output", "OutputPath", "Path", "File", "FileName"},
                         OutputPath->text().trimmed());
        if (StartModuleExecution(Entry, nullptr))
            ShowSuccessNotice(Page, "Payload", "Payload generation started.");
        else
            ShowWarningNotice(Page, "Payload", "A module is already running.");
    });
    QObject::connect(HostList, &QListWidget::currentItemChanged, ShellPage,
                     [LoadHostToEditors, ShellState](QListWidgetItem *Current, QListWidgetItem *) {
        LoadHostToEditors(Current);
        PayloadShellPersistConfiguration(ShellState);
        PayloadShellUpdateControls(ShellState);
    });
    QObject::connect(NewHostButton, &QPushButton::clicked, ShellPage, [ShellState, HostList, LoadHostToEditors] {
        auto *Item = new QListWidgetItem;
        PayloadShellCreateSession(ShellState, Item, "127.0.0.1", "4444", QString());
        HostList->addItem(Item);
        HostList->setCurrentItem(Item);
        PayloadShellRefreshHostList(ShellState);
        LoadHostToEditors(Item);
        PayloadShellPersistConfiguration(ShellState);
        PayloadShellUpdateControls(ShellState);
    });
    QObject::connect(SaveHostButton, &QPushButton::clicked, ShellPage, [SaveSelectedHost] {
        SaveSelectedHost();
    });
    QObject::connect(RemoveHostButton, &QPushButton::clicked, ShellPage,
                     [ShellState, HostList, LoadHostToEditors] {
        if (!HostList->currentItem() || HostList->count() <= 1)
            return;
        const int Row = HostList->currentRow();
        QListWidgetItem *Item = HostList->takeItem(Row);
        if (const std::shared_ptr<PayloadShellSession> Session = PayloadShellSessionForItem(ShellState, Item))
        {
            if (Session->Socket)
                Session->Socket->abort();
            if (Session->CommandDialog)
                Session->CommandDialog->close();
            ShellState->Sessions.erase(Session->Id);
        }
        delete Item;
        HostList->setCurrentRow(std::clamp(Row, 0, HostList->count() - 1));
        LoadHostToEditors(HostList->currentItem());
        PayloadShellPersistConfiguration(ShellState);
        PayloadShellUpdateControls(ShellState);
    });
    QObject::connect(HostEdit, &QLineEdit::editingFinished, ShellPage, [SaveSelectedHost] {
        SaveSelectedHost();
    });
    QObject::connect(PortEdit, &QLineEdit::editingFinished, ShellPage, [SaveSelectedHost] {
        SaveSelectedHost();
    });
    QObject::connect(PasswordEdit, &QLineEdit::editingFinished, ShellPage, [SaveSelectedHost] {
        SaveSelectedHost();
    });
    QObject::connect(CommandButton, &QPushButton::clicked, ShellPage, [ShellState, SendShellCommand] {
        const std::shared_ptr<PayloadShellSession> Session = PayloadShellCurrentSession(ShellState);
        ShowPayloadShellCommandDialog(Session, [Session, SendShellCommand](const QString &Command) {
            SendShellCommand(Session, Command);
        });
    });
    QObject::connect(ConnectButton, &QPushButton::clicked, ShellPage,
                     [ShellState, ShellPage, FinalizeSession, SaveSelectedHost] {
        const std::shared_ptr<PayloadShellSession> Session = PayloadShellCurrentSession(ShellState);
        if (!Session || Session->Socket)
            return;

        if (!SaveSelectedHost())
            return;

        const QString Host = Session->Host.trimmed();
        bool PortOk = false;
        const quint16 Port = Session->Port.trimmed().toUShort(&PortOk);
        if (Host.isEmpty())
        {
            ShowWarningNotice(ShellPage, "Payload Shell", "Host is required.");
            return;
        }
        if (!PortOk || Port == 0)
        {
            ShowWarningNotice(ShellPage, "Payload Shell", "Port must be between 1 and 65535.");
            return;
        }

        PayloadShellResetConnectionState(Session);
        auto *Socket = new QTcpSocket(ShellPage);
        Session->Socket = Socket;
        Session->ReadState = PayloadShellReadState::AwaitChallenge;
        PayloadShellSetStatus(Session, "Connecting...", QColor("#4FC3F7"));
        PayloadShellUpdateControls(ShellState);

        QObject::connect(Socket, &QTcpSocket::connected, ShellPage, [ShellState, Session, Host, Port] {
            PayloadShellLog(Session, QString("Connected to %1:%2, waiting for challenge.")
                                         .arg(Host)
                                         .arg(Port),
                            QColor("#4FC3F7"));
            PayloadShellSetStatus(Session, "Negotiating...", QColor("#4FC3F7"));
            PayloadShellUpdateControls(ShellState);
        });
        QObject::connect(Socket, &QTcpSocket::readyRead, ShellPage, [ShellState, Session, Socket] {
            if (Session->Socket != Socket)
                return;
            Session->ReceiveBuffer.append(Socket->readAll());
            PayloadShellProcessBuffer(ShellState, Session);
        });
        QObject::connect(Socket, &QTcpSocket::disconnected, ShellPage, [Session, Socket, FinalizeSession] {
            if (Session->Socket != Socket)
                return;
            FinalizeSession(Session, "Disconnected", QColor("#8A94A6"));
        });
        QObject::connect(Socket, &QTcpSocket::errorOccurred, ShellPage,
                         [Session, Socket, FinalizeSession](QAbstractSocket::SocketError Error) {
            if (Session->Socket != Socket)
                return;
            if (!Session->DisconnectRequested || Error != QAbstractSocket::RemoteHostClosedError)
                PayloadShellLog(Session, "Connection error: " + Socket->errorString(),
                                QColor("#FF5F56"));
            FinalizeSession(Session, Session->DisconnectRequested ? "Disconnected" : "Connection failed",
                            Session->DisconnectRequested ? QColor("#8A94A6")
                                                         : QColor("#FF5F56"));
        });
        Socket->connectToHost(Host, Port);
    });
    QObject::connect(DisconnectButton, &QPushButton::clicked, ShellPage, [DisconnectShell] {
        DisconnectShell(true);
    });
    QObject::connect(ShellPage, &QObject::destroyed, qApp, [ShellState] {
        for (auto &[Id, Session] : ShellState->Sessions)
        {
            Q_UNUSED(Id);
            if (Session->Socket)
                Session->Socket->abort();
            if (Session->CommandDialog)
                Session->CommandDialog->close();
        }
    });

    auto *StateTimer = new QTimer(Page);
    QObject::connect(StateTimer, &QTimer::timeout, Page, [Page, Modules, Generate] {
        if (!Page->isVisible())
            return;
        const QString Path = Modules->currentData().toString();
        Generate->setText(ModuleRunning.load() && RunningModulePath == Path ? "Running..." : "Generate");
        Generate->setEnabled(!Path.isEmpty() && !ModuleRunning.load());
    });
    StateTimer->start(150);

    PopulateModules();
    UpdateInformation();
    return Page;
}

