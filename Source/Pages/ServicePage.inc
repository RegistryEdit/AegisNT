class ServiceManagerPage final : public QWidget
{
    struct ServiceRow {
        QString Name, DisplayName, State, StartType, BinaryPath;
        DWORD Pid, Type;
    };

public:
    explicit ServiceManagerPage(QWidget *Parent = nullptr) : QWidget(Parent)
    {
        auto *Layout = new QVBoxLayout(this);
        ConfigurePageLayout(Layout);
        auto *Toolbar = new QHBoxLayout;
        ConfigureToolbarLayout(Toolbar);
        RefreshButton = MakeButton("Refresh", true);
        SearchEdit = new SearchLineEdit;
        SearchEdit->setPlaceholderText("Search service name, display, or path");
        SearchEdit->setClearButtonEnabled(true);
        SearchEdit->setMaximumWidth(360);
        Toolbar->addWidget(SearchEdit);
        Toolbar->addStretch();
        Toolbar->addWidget(RefreshButton);
        Layout->addLayout(Toolbar);
        Table = MakeTable({"Service", "Display Name", "State", "Start Type", "PID", "Path"});
        Table->setContextMenuPolicy(Qt::CustomContextMenu);
        Layout->addWidget(Table, 1);
        QObject::connect(SearchEdit, &QLineEdit::textChanged, this, [this] { Populate(); });
        QObject::connect(RefreshButton, &QPushButton::clicked, this, [this] { Refresh(); ShowSuccessNotice(this, "Service", "Service list refreshed."); });
        QObject::connect(Table, &QWidget::customContextMenuRequested, this, [this](const QPoint &P) { ShowMenu(P); });
        Refresh();
    }

private:
    void Refresh()
    {
        Rows.clear();
        SC_HANDLE Scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
        if (!Scm) return;
        DWORD Needed = 0, Count = 0, Resume = 0;
        EnumServicesStatusExW(Scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32 | SERVICE_DRIVER,
            SERVICE_STATE_ALL, NULL, 0, &Needed, &Count, &Resume, NULL);
        if (Needed == 0) { CloseServiceHandle(Scm); return; }
        std::vector<BYTE> Buf(Needed);
        if (EnumServicesStatusExW(Scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32 | SERVICE_DRIVER,
            SERVICE_STATE_ALL, Buf.data(), Needed, &Needed, &Count, &Resume, NULL))
        {
            auto *Services = reinterpret_cast<LPENUM_SERVICE_STATUS_PROCESSW>(Buf.data());
            for (DWORD i = 0; i < Count; i++)
            {
                ServiceRow Row;
                Row.Name = QString::fromWCharArray(Services[i].lpServiceName);
                Row.DisplayName = QString::fromWCharArray(Services[i].lpDisplayName);
                Row.Pid = Services[i].ServiceStatusProcess.dwProcessId;
                Row.Type = Services[i].ServiceStatusProcess.dwServiceType;

                switch (Services[i].ServiceStatusProcess.dwCurrentState)
                {
                case SERVICE_RUNNING: Row.State = "Running"; break;
                case SERVICE_STOPPED: Row.State = "Stopped"; break;
                case SERVICE_PAUSED: Row.State = "Paused"; break;
                case SERVICE_START_PENDING: Row.State = "Starting..."; break;
                case SERVICE_STOP_PENDING: Row.State = "Stopping..."; break;
                default: Row.State = QString("Unknown(%1)").arg(Services[i].ServiceStatusProcess.dwCurrentState); break;
                }

                SC_HANDLE Svc = OpenServiceW(Scm, Services[i].lpServiceName, SERVICE_QUERY_CONFIG);
                if (Svc)
                {
                    DWORD CfgSize = 0;
                    QueryServiceConfigW(Svc, NULL, 0, &CfgSize);
                    if (CfgSize >= sizeof(QUERY_SERVICE_CONFIGW))
                    {
                        std::vector<BYTE> CfgBuf(CfgSize);
                        auto *Cfg = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(CfgBuf.data());
                        DWORD CfgOutSize = static_cast<DWORD>(CfgBuf.size());
                        if (QueryServiceConfigW(Svc, Cfg, CfgOutSize, &CfgSize))
                        {
                            Row.BinaryPath = QString::fromWCharArray(Cfg->lpBinaryPathName);
                            switch (Cfg->dwStartType)
                            {
                            case SERVICE_BOOT_START: Row.StartType = "Boot"; break;
                            case SERVICE_SYSTEM_START: Row.StartType = "System"; break;
                            case SERVICE_AUTO_START: Row.StartType = "Auto"; break;
                            case SERVICE_DEMAND_START: Row.StartType = "Manual"; break;
                            case SERVICE_DISABLED: Row.StartType = "Disabled"; break;
                            default: Row.StartType = QString::number(Cfg->dwStartType); break;
                            }
                        }
                    }
                    CloseServiceHandle(Svc);
                }
                else
                {
                    Row.BinaryPath = "-";
                    Row.StartType = "-";
                }
                Rows.push_back(std::move(Row));
            }
        }
        CloseServiceHandle(Scm);
        Populate();
    }

    void Populate()
    {
        const QString Query = SearchEdit->text().trimmed();
        Table->clearContents();
        Table->setRowCount(0);
        for (const auto &Svc : Rows)
        {
            if (!Query.isEmpty() &&
                !Svc.Name.contains(Query, Qt::CaseInsensitive) &&
                !Svc.DisplayName.contains(Query, Qt::CaseInsensitive) &&
                !Svc.BinaryPath.contains(Query, Qt::CaseInsensitive))
                continue;
            int R = Table->rowCount();
            Table->insertRow(R);
            Table->setItem(R, 0, new QTableWidgetItem(Svc.Name));
            Table->setItem(R, 1, new QTableWidgetItem(Svc.DisplayName));
            Table->setItem(R, 2, new QTableWidgetItem(Svc.State));
            Table->setItem(R, 3, new QTableWidgetItem(Svc.StartType));
            Table->setItem(R, 4, new QTableWidgetItem(Svc.Pid ? QString::number(Svc.Pid) : "-"));
            Table->setItem(R, 5, new QTableWidgetItem(Svc.BinaryPath));
            Table->setRowHeight(R, KCompactTableRowHeight);
        }
    }

    void ShowMenu(const QPoint &Pos)
    {
        int Row = Table->indexAt(Pos).row();
        if (Row < 0 || Row >= static_cast<int>(Rows.size())) return;
        Table->selectRow(Row);
        const auto &Svc = Rows[Row];
        auto *Menu = new RoundMenu(QString(), this);

        auto AddAct = [this, Menu, &Svc](const QString &Text, std::function<void()> Fn) {
            auto *Item = new QAction(Text, Menu);
            Menu->addAction(Item);
            QObject::connect(Item, &QAction::triggered, this, [this, Text, Fn] {
                Fn();
                QTimer::singleShot(250, this, [this] { Refresh(); });
            });
        };

        if (Svc.State == "Stopped") AddAct("Start", [&Svc] {
            std::wstring Wide(reinterpret_cast<const wchar_t*>(Svc.Name.utf16()), Svc.Name.size());
            SC_HANDLE Scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
            if (Scm) {
                SC_HANDLE S = OpenServiceW(Scm, Wide.c_str(), SERVICE_START);
                if (S) { StartServiceW(S, 0, NULL); CloseServiceHandle(S); }
                CloseServiceHandle(Scm);
            }
        });
        if (Svc.State == "Running") AddAct("Stop", [&Svc] {
            std::wstring Wide(reinterpret_cast<const wchar_t*>(Svc.Name.utf16()), Svc.Name.size());
            SC_HANDLE Scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
            if (Scm) {
                SC_HANDLE S = OpenServiceW(Scm, Wide.c_str(), SERVICE_STOP);
                if (S) { SERVICE_STATUS St; ControlService(S, SERVICE_CONTROL_STOP, &St); CloseServiceHandle(S); }
                CloseServiceHandle(Scm);
            }
        });

        Menu->addSeparator();

        AddAct("Disable", [&Svc] {
            std::wstring Wide(reinterpret_cast<const wchar_t*>(Svc.Name.utf16()), Svc.Name.size());
            if (G_DeviceHandle != INVALID_HANDLE_VALUE && Svc.Type == SERVICE_KERNEL_DRIVER)
                ServiceDisable(Wide.c_str());
            else {
                SC_HANDLE Scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
                if (Scm) {
                    SC_HANDLE S = OpenServiceW(Scm, Wide.c_str(), SERVICE_CHANGE_CONFIG);
                    if (S) { ChangeServiceConfigW(S, SERVICE_NO_CHANGE, SERVICE_DISABLED, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL); CloseServiceHandle(S); }
                    CloseServiceHandle(Scm);
                }
            }
        });

        AddAct("Enable", [&Svc] {
            std::wstring Wide(reinterpret_cast<const wchar_t*>(Svc.Name.utf16()), Svc.Name.size());
            if (G_DeviceHandle != INVALID_HANDLE_VALUE && Svc.Type == SERVICE_KERNEL_DRIVER)
                ServiceEnable(Wide.c_str());
            else {
                SC_HANDLE Scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
                if (Scm) {
                    SC_HANDLE S = OpenServiceW(Scm, Wide.c_str(), SERVICE_CHANGE_CONFIG);
                    if (S) { ChangeServiceConfigW(S, SERVICE_NO_CHANGE, SERVICE_AUTO_START, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL); CloseServiceHandle(S); }
                    CloseServiceHandle(Scm);
                }
            }
        });

        ReleaseMenuAfterClose(Menu);
        Menu->exec(Table->viewport()->mapToGlobal(Pos));
    }

    SearchLineEdit *SearchEdit{};
    PushButton *RefreshButton{};
    TableWidget *Table{};
    std::vector<ServiceRow> Rows;
};

