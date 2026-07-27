class WindowManagerPage final : public QWidget
{
    struct WindowRow
    {
        HWND Handle = nullptr;
        DWORD Pid = 0;
        DWORD Tid = 0;
        QString Title;
        QString ClassName;
        QString ProcessPath;
        RECT Rect{};
        RECT ClientRect{};
        LONG Style = 0;
        LONG ExStyle = 0;
        HWND ParentHwnd = nullptr;
        HWND OwnerHwnd = nullptr;
        UINT Dpi = 0;
        bool Visible = false;
        bool Enabled = false;
        bool Minimized = false;
        bool Maximized = false;
        bool IsHung = false;
        bool IsTopmost = false;
        bool IsLayered = false;
        bool IsToolWindow = false;
        bool IsPopup = false;
        bool IsChild = false;
        bool IsUnicode = false;
        bool IsAppWindow = false;
        UCHAR Alpha = 255;
    };

  public:
    explicit WindowManagerPage(QWidget *Parent = nullptr) : QWidget(Parent)
    {
        auto *Layout = new QVBoxLayout(this);
        ConfigurePageLayout(Layout);

        
        auto *Tabs = new TabBar;
        Tabs->setAddButtonVisible(false);
        Tabs->setTabsClosable(false);
        Tabs->setMovable(false);
        Tabs->addTab("windows", "Windows", Fluent::IconType::BACK_TO_WINDOW);
        Tabs->addTab("protected", "Protected", Fluent::IconType::CERTIFICATE);
        Layout->addWidget(Tabs);
        auto *Pages = new QStackedWidget;
        Layout->addWidget(Pages, 1);

        
        auto *WinPage = new QWidget;
        auto *WinLayout = new QVBoxLayout(WinPage);
        ConfigurePageLayout(WinLayout);
        auto *Toolbar = new QHBoxLayout;
        ConfigureToolbarLayout(Toolbar);
        SearchEdit = new SearchLineEdit;
        SearchEdit->setPlaceholderText("Search title, class, process, PID, or HWND");
        SearchEdit->setClearButtonEnabled(true);
        SearchEdit->setMaximumWidth(360);
        RefreshIndicator = new IndeterminateProgressRing(this, false);
        RefreshIndicator->setFixedSize(22, 22);
        RefreshIndicator->hide();
        RefreshButton = MakeButton("Refresh", true);
        Toolbar->addWidget(SearchEdit);
        Toolbar->addStretch();
        Toolbar->addWidget(RefreshIndicator);
        Toolbar->addWidget(RefreshButton);
        WinLayout->addLayout(Toolbar);
        WindowTable = MakeTable({"HWND", "Title", "Class", "Process", "PID", "Style", "State", "Rect", "Dpi"});
        WindowTable->setSelectionMode(QAbstractItemView::SingleSelection);
        WindowTable->setContextMenuPolicy(Qt::CustomContextMenu);
        WindowTable->setProperty("DetailDialogTitle", "Window details");
        WindowTable->horizontalHeader()->setStretchLastSection(false);
        for (int Column = 0; Column < WindowTable->columnCount(); ++Column)
            WindowTable->horizontalHeader()->setSectionResizeMode(Column, QHeaderView::ResizeToContents);
        WindowTable->verticalHeader()->setDefaultSectionSize(KCompactTableRowHeight);
        WinLayout->addWidget(WindowTable, 1);

        
        auto *ProtPage = new QWidget;
        auto *ProtLayout = new QVBoxLayout(ProtPage);
        ConfigurePageLayout(ProtLayout, 8);
        auto *ProtToolbar = new QHBoxLayout;
        ConfigureToolbarLayout(ProtToolbar);
        auto *ProtTitle = MakeLabel("Protected Windows", 13, KTextPrimary, QFont::DemiBold);
        UnprotectButton = MakeButton("Unprotect", true);
        UnprotectButton->setEnabled(false);
        ProtToolbar->addWidget(ProtTitle);
        ProtToolbar->addStretch();
        ProtToolbar->addWidget(UnprotectButton);
        ProtLayout->addLayout(ProtToolbar);
        ProtectedTable = MakeTable({"HWND", "Title", "PID", "Flags"});
        ProtectedTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
        ProtectedTable->setProperty("DetailDialogTitle", "Protected window details");
        ProtectedTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        ProtectedTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
        ProtectedTable->verticalHeader()->setDefaultSectionSize(KCompactTableRowHeight);
        ProtLayout->addWidget(ProtectedTable, 1);

        Pages->addWidget(WinPage);
        Pages->addWidget(ProtPage);
        QObject::connect(Tabs, &TabBar::currentChanged, Pages, &QStackedWidget::setCurrentIndex);

        SearchDebounceTimer = new QTimer(this);
        SearchDebounceTimer->setSingleShot(true);
        SearchDebounceTimer->setInterval(KSearchDebounceMs);
        QObject::connect(SearchDebounceTimer, &QTimer::timeout, this, [this] { Populate(); });
        QObject::connect(SearchEdit, &QLineEdit::textChanged, this, [this] { SearchDebounceTimer->start(); });
        QObject::connect(RefreshButton, &QPushButton::clicked, this, [this] { Refresh(true); });
        QObject::connect(WindowTable, &QWidget::customContextMenuRequested, this,
                         [this](const QPoint &Position) { ShowMenu(Position); });
        QObject::connect(UnprotectButton, &QPushButton::clicked, this, &WindowManagerPage::UnprotectSelected);
        QObject::connect(ProtectedTable, &QTableWidget::itemSelectionChanged, this, [this] {
            UnprotectButton->setEnabled(!ProtectedTable->selectionModel()->selectedRows(0).isEmpty());
        });
        Refresh();
    }

  private:
    static QString ReadWindowText(HWND Handle)
    {
        const int Length = GetWindowTextLengthW(Handle);
        if (Length <= 0) return {};
        std::wstring Text(static_cast<size_t>(Length) + 1, L'\0');
        GetWindowTextW(Handle, Text.data(), static_cast<int>(Text.size()));
        return QString::fromWCharArray(Text.c_str());
    }

    void Refresh(bool ShowResult = false)
    {
        if (Refreshing.exchange(true))
            return;
        RefreshButton->setEnabled(false);
        RefreshButton->setText("Refreshing...");
        RefreshIndicator->show();
        RefreshIndicator->start();
        QPointer<WindowManagerPage> Page(this);
        std::thread([Page, ShowResult] {
            std::vector<WindowRow> Result;
            EnumWindows([](HWND Handle, LPARAM Parameter) -> BOOL {
                auto *Rows = reinterpret_cast<std::vector<WindowRow> *>(Parameter);
                WindowRow Row;
                Row.Handle = Handle;
                Row.Title = ReadWindowText(Handle);
                wchar_t ClassName[256]{};
                GetClassNameW(Handle, ClassName, 256);
                Row.ClassName = QString::fromWCharArray(ClassName);
                Row.Tid = GetWindowThreadProcessId(Handle, &Row.Pid);
                Row.Visible = IsWindowVisible(Handle) != FALSE;
                Row.Enabled = IsWindowEnabled(Handle) != FALSE;
                Row.Minimized = IsIconic(Handle) != FALSE;
                Row.Maximized = IsZoomed(Handle) != FALSE;
                Row.IsHung = IsHungAppWindow(Handle) != FALSE;
                Row.IsUnicode = IsWindowUnicode(Handle) != FALSE;
                Row.Style = GetWindowLongW(Handle, GWL_STYLE);
                Row.ExStyle = GetWindowLongW(Handle, GWL_EXSTYLE);
                Row.IsTopmost = (Row.ExStyle & WS_EX_TOPMOST) != 0;
                Row.IsLayered = (Row.ExStyle & WS_EX_LAYERED) != 0;
                Row.IsToolWindow = (Row.ExStyle & WS_EX_TOOLWINDOW) != 0;
                Row.IsAppWindow = (Row.ExStyle & WS_EX_APPWINDOW) != 0;
                Row.IsPopup = (Row.Style & WS_POPUP) != 0;
                Row.IsChild = (Row.Style & WS_CHILD) != 0;
                Row.ParentHwnd = GetParent(Handle);
                Row.OwnerHwnd = GetWindow(Handle, GW_OWNER);
                Row.Dpi = GetDpiForWindow(Handle);
                GetWindowRect(Handle, &Row.Rect);
                GetClientRect(Handle, &Row.ClientRect);
                HANDLE Process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Row.Pid);
                if (Process)
                {
                    wchar_t Path[32768]{};
                    DWORD Size = 32768;
                    if (QueryFullProcessImageNameW(Process, 0, Path, &Size))
                        Row.ProcessPath = QString::fromWCharArray(Path, static_cast<qsizetype>(Size));
                    CloseHandle(Process);
                }
                if (!Row.Title.isEmpty() || !Row.ClassName.isEmpty())
                    Rows->push_back(std::move(Row));
                return TRUE;
            }, reinterpret_cast<LPARAM>(&Result));
            std::sort(Result.begin(), Result.end(), [](const WindowRow &Left, const WindowRow &Right) {
                if (Left.Visible != Right.Visible) return Left.Visible > Right.Visible;
                return Left.Pid < Right.Pid;
            });
            QMetaObject::invokeMethod(qApp, [Page, Result = std::move(Result), ShowResult]() mutable {
                if (!Page)
                    return;
                Page->Refreshing = false;
                Page->Rows = std::move(Result);
                if (Page->RefreshIndicator)
                {
                    Page->RefreshIndicator->stop();
                    Page->RefreshIndicator->hide();
                }
                if (Page->RefreshButton)
                {
                    Page->RefreshButton->setText("Refresh");
                    Page->RefreshButton->setEnabled(true);
                }
                Page->Populate();
                if (ShowResult)
                    ShowSuccessNotice(Page, "Window", "Window list refreshed.");
            }, Qt::QueuedConnection);
        }).detach();
    }

    void Populate()
    {
        const QString Query = SearchEdit->text().trimmed();
        std::vector<const WindowRow *> VisibleRows;
        VisibleRows.reserve(Rows.size());
        for (const WindowRow &Window : Rows)
        {
            const QString HandleText = QString("0x%1").arg(reinterpret_cast<quintptr>(Window.Handle), 0, 16);
            const QString SearchText = Window.Title + " " + Window.ClassName + " " + Window.ProcessPath +
                                       " " + QString::number(Window.Pid) + " " + HandleText;
            if (!Query.isEmpty() && !SearchText.contains(Query, Qt::CaseInsensitive))
                continue;
            VisibleRows.push_back(&Window);
        }
        WindowTable->setUpdatesEnabled(false);
        WindowTable->clearContents();
        WindowTable->setRowCount(static_cast<int>(VisibleRows.size()));
        for (int Row = 0; Row < static_cast<int>(VisibleRows.size()); ++Row)
        {
            const WindowRow &Window = *VisibleRows[Row];
            const QString HandleText = QString("0x%1").arg(reinterpret_cast<quintptr>(Window.Handle), 0, 16);
            QStringList States{Window.Visible ? "Visible" : "Hidden", Window.Enabled ? "Enabled" : "Disabled"};
            if (Window.Minimized) States.append("Minimized");
            if (Window.Maximized) States.append("Maximized");
            if (Window.IsHung) States.append("HUNG");
            if (Window.IsTopmost) States.append("Topmost");
            auto *HandleItem = new QTableWidgetItem(HandleText);
            HandleItem->setData(Qt::UserRole, QVariant::fromValue<qulonglong>(reinterpret_cast<quintptr>(Window.Handle)));
            WindowTable->setItem(Row, 0, HandleItem);
            WindowTable->setItem(Row, 1, new QTableWidgetItem(Window.Title.isEmpty() ? "(untitled)" : Window.Title));
            WindowTable->setItem(Row, 2, new QTableWidgetItem(Window.ClassName));
            WindowTable->setItem(Row, 3, new QTableWidgetItem(Window.ProcessPath));
            WindowTable->setItem(Row, 4, new QTableWidgetItem(QString::number(Window.Pid)));
            WindowTable->setItem(Row, 5, new QTableWidgetItem(QString("0x%1 | Ex:0x%2")
                .arg(Window.Style, 8, 16, QChar('0')).arg(Window.ExStyle, 8, 16, QChar('0'))));
            WindowTable->setItem(Row, 6, new QTableWidgetItem(States.join(" | ")));
            WindowTable->setItem(Row, 7, new QTableWidgetItem(QString("(%1,%2)-(%3,%4) %5x%6")
                .arg(Window.Rect.left).arg(Window.Rect.top).arg(Window.Rect.right).arg(Window.Rect.bottom)
                .arg(Window.Rect.right - Window.Rect.left).arg(Window.Rect.bottom - Window.Rect.top)));
            WindowTable->setItem(Row, 8, new QTableWidgetItem(QString::number(Window.Dpi)));
            WindowTable->setRowHeight(Row, KCompactTableRowHeight);
        }
        WindowTable->setUpdatesEnabled(true);
    }

    void ShowMenu(const QPoint &Position)
    {
        const QModelIndex Index = WindowTable->indexAt(Position);
        if (!Index.isValid()) return;
        WindowTable->selectRow(Index.row());
        const HWND Handle = reinterpret_cast<HWND>(static_cast<quintptr>(
            WindowTable->item(Index.row(), 0)->data(Qt::UserRole).toULongLong()));
        if (!IsWindow(Handle)) return;
        DWORD TargetPid = 0;
        GetWindowThreadProcessId(Handle, &TargetPid);
        const bool IsOwnWindow = TargetPid == GetCurrentProcessId();
        const bool IsProtected = IsTrackedProtectedWindow((ULONG64)(ULONG_PTR)Handle);
        auto *Menu = new RoundMenu(QString(), this);
        const auto AddAction = [this, Menu, Handle, IsProtected](const QString &Text, const std::function<bool(HWND)> &Action) {
            auto *Item = new QAction(Text, Menu);
            Menu->addAction(Item);
            ConnectMenuAction(Item, this, [this, Handle, Text, Action] {
                if (IsTrackedProtectedWindow((ULONG64)(ULONG_PTR)Handle))
                {
                    ShowWarningNotice(this, "Window", "This window is protected. Unprotect it first.");
                    return;
                }
                if (Action(Handle)) ShowSuccessNotice(this, "Window", Text + " completed.");
                else ShowErrorNotice(this, "Window", Text + " failed.");
                QTimer::singleShot(150, this, [this] { Refresh(); });
            });
            if (IsProtected && Text != "Ping") Item->setEnabled(false);
        };
        AddAction("Show / Activate", [](HWND H) { ShowWindow(H, SW_SHOW); return SetForegroundWindow(H) != FALSE; });
        if (!IsOwnWindow) AddAction("Hide", [](HWND H) { ShowWindow(H, SW_HIDE); return IsWindow(H) != FALSE; });
        AddAction("Minimize", [](HWND H) { ShowWindow(H, SW_MINIMIZE); return IsWindow(H) != FALSE; });
        AddAction("Maximize", [](HWND H) { ShowWindow(H, SW_MAXIMIZE); return IsWindow(H) != FALSE; });
        AddAction("Restore", [](HWND H) { ShowWindow(H, SW_RESTORE); SetForegroundWindow(H); return IsWindow(H) != FALSE; });
        Menu->addSeparator();
        AddAction("Enable", [](HWND H) { return EnableWindow(H, TRUE) != FALSE || GetLastError() == ERROR_SUCCESS; });
        if (!IsOwnWindow) AddAction("Disable", [](HWND H) { return EnableWindow(H, FALSE) != FALSE || GetLastError() == ERROR_SUCCESS; });
        AddAction("Topmost", [](HWND H) { return SetWindowPos(H, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE) != FALSE; });
        AddAction("Remove topmost", [](HWND H) { return SetWindowPos(H, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE) != FALSE; });
        AddAction("Ping", [this](HWND H) {
            DWORD_PTR Result = 0;
            return SendMessageTimeoutW(H, WM_NULL, 0, 0, SMTO_ABORTIFHUNG, 1000, &Result) != 0;
        });
        Menu->addSeparator();
        if (!IsOwnWindow)
        {
            AddAction("Post WM_CLOSE", [](HWND H) { return PostMessageW(H, WM_CLOSE, 0, 0) != FALSE; });
            AddAction("Send SC_CLOSE", [](HWND H) { DWORD_PTR Result = 0; return SendMessageTimeoutW(H, WM_SYSCOMMAND, SC_CLOSE, 0, SMTO_ABORTIFHUNG, 1000, &Result) != 0; });
        }

        if (!IsOwnWindow && G_DeviceHandle != INVALID_HANDLE_VALUE)
        {
            Menu->addSeparator();
            auto *KernelMenu = new RoundMenu("Kernel Operations", Menu);

            auto AddKernelAction = [this, Menu, KernelMenu, Handle, TargetPid](
                const QString &Text,
                const std::function<BOOL()> &KernelOp,
                const std::function<BOOL(HWND)> &UserOp)
            {
                auto *Item = new QAction(Text, KernelMenu);
                KernelMenu->addAction(Item);
                ConnectMenuAction(Item, this, [this, Text, Handle, KernelOp, UserOp] {
                    BOOL Result = FALSE;
                    if (G_DeviceHandle != INVALID_HANDLE_VALUE)
                        Result = KernelOp();
                    else if (UserOp)
                        Result = UserOp(Handle);
                    if (Result) ShowSuccessNotice(this, "Window", Text + " completed.");
                    else ShowErrorNotice(this, "Window", Text + " failed.");
                    QTimer::singleShot(150, this, [this] { Refresh(); });
                });
            };

            AddKernelAction("Kill Window (Kernel)", [TargetPid, Handle]() -> BOOL {
                return WindowKill(TargetPid, (ULONG64)(ULONG_PTR)Handle);
            }, [](HWND H) -> BOOL {
                return PostMessageW(H, WM_CLOSE, 0, 0);
            });

            AddKernelAction("Force Hide", [TargetPid, Handle]() -> BOOL {
                return WindowHide(TargetPid, (ULONG64)(ULONG_PTR)Handle);
            }, [](HWND H) -> BOOL {
                return ShowWindow(H, SW_HIDE) != FALSE || TRUE;
            });

            AddKernelAction("Force Show", [TargetPid, Handle]() -> BOOL {
                return WindowShow(TargetPid, (ULONG64)(ULONG_PTR)Handle);
            }, [](HWND H) -> BOOL {
                return ShowWindow(H, SW_SHOW) != FALSE || TRUE;
            });

            AddKernelAction("Force Disable", [TargetPid, Handle]() -> BOOL {
                return WindowDisable(TargetPid, (ULONG64)(ULONG_PTR)Handle);
            }, [](HWND H) -> BOOL {
                return EnableWindow(H, FALSE);
            });

            AddKernelAction("Force Enable", [TargetPid, Handle]() -> BOOL {
                return WindowEnable(TargetPid, (ULONG64)(ULONG_PTR)Handle);
            }, [](HWND H) -> BOOL {
                return EnableWindow(H, TRUE);
            });

            AddKernelAction("Force Topmost", [TargetPid, Handle]() -> BOOL {
                return WindowSetTopmost(TargetPid, (ULONG64)(ULONG_PTR)Handle);
            }, [](HWND H) -> BOOL {
                return SetWindowPos(H, HWND_TOPMOST, 0, 0, 0, 0,
                    SWP_NOMOVE | SWP_NOSIZE);
            });

            AddKernelAction("Force Remove Topmost", [TargetPid, Handle]() -> BOOL {
                return WindowRemoveTopmost(TargetPid, (ULONG64)(ULONG_PTR)Handle);
            }, [](HWND H) -> BOOL {
                return SetWindowPos(H, HWND_NOTOPMOST, 0, 0, 0, 0,
                    SWP_NOMOVE | SWP_NOSIZE);
            });

            AddKernelAction("Set Title...", [TargetPid, Handle, this]() -> BOOL {
                bool Ok = false;
                QString NewTitle = QInputDialog::getText(WindowTable, "Set Window Title",
                    "New title:", QLineEdit::Normal, QString(), &Ok);
                if (!Ok || NewTitle.isEmpty()) return TRUE;
                std::wstring WideTitle(reinterpret_cast<const wchar_t*>(NewTitle.utf16()));
                return WindowSetTitle(TargetPid, (ULONG64)(ULONG_PTR)Handle,
                    WideTitle.c_str());
            }, [this](HWND H) -> BOOL {
                bool Ok = false;
                QString NewTitle = QInputDialog::getText(WindowTable, "Set Window Title (User)",
                    "New title:", QLineEdit::Normal, QString(), &Ok);
                if (!Ok || NewTitle.isEmpty()) return TRUE;
                std::wstring WideTitle(reinterpret_cast<const wchar_t*>(NewTitle.utf16()));
                return SetWindowTextW(H, WideTitle.c_str());
            });

            KernelMenu->addSeparator();
            AddKernelAction("Kill (Direct)", [TargetPid, Handle]() -> BOOL {
                return WindowKill(TargetPid, (ULONG64)(ULONG_PTR)Handle, WINDOW_FLAG_DIRECT);
            }, [](HWND H) -> BOOL {
                return PostMessageW(H, WM_CLOSE, 0, 0);
            });
            AddKernelAction("Hide (Direct)", [TargetPid, Handle]() -> BOOL {
                return WindowHide(TargetPid, (ULONG64)(ULONG_PTR)Handle, WINDOW_FLAG_DIRECT);
            }, [](HWND H) -> BOOL {
                return ShowWindow(H, SW_HIDE) != FALSE || TRUE;
            });
            Menu->addMenu(KernelMenu);
        }
        else if (!IsOwnWindow)
        {
            Menu->addSeparator();
            const auto AddActionWithCheck = [this, Menu](const QString &Text, const std::function<bool()> &Action) {
                auto *Item = new QAction(Text, Menu);
                Menu->addAction(Item);
                ConnectMenuAction(Item, this, [this, Text, Action] {
                    const QModelIndex Current = WindowTable->currentIndex();
                    if (Current.isValid())
                    {
                        const auto Hwnd = WindowTable->item(Current.row(), 0)->data(Qt::UserRole).toULongLong();
                        if (IsTrackedProtectedWindow(Hwnd))
                        {
                            ShowWarningNotice(this, "Window", "This window is protected. Unprotect it first.");
                            return;
                        }
                    }
                    if (Action()) ShowSuccessNotice(this, "Window", Text + " completed.");
                    else ShowErrorNotice(this, "Window", Text + " failed.");
                    QTimer::singleShot(150, this, [this] { Refresh(); });
                });
            };
            AddActionWithCheck("Change Title...", [this, Handle]() -> bool {
                bool Ok = false;
                QString NewTitle = QInputDialog::getText(WindowTable, "Set Window Title",
                    "New title:", QLineEdit::Normal, QString(), &Ok);
                if (!Ok || NewTitle.isEmpty()) return true;
                std::wstring WideTitle(reinterpret_cast<const wchar_t*>(NewTitle.utf16()));
                return SetWindowTextW(Handle, WideTitle.c_str()) != FALSE;
            });
        }

        
        if (!IsOwnWindow && TargetPid != 0)
        {
            Menu->addSeparator();
            auto *ProtectAction = new QAction("Protect Window", Menu);
            Menu->addAction(ProtectAction);
            ConnectMenuAction(ProtectAction, this, [this, Handle, TargetPid] {
                QString Title = ReadWindowText(Handle);
                ProtectWindowEntry(TargetPid, (ULONG64)(ULONG_PTR)Handle, Title.isEmpty() ? "(untitled)" : Title);
            });
        }

        ReleaseMenuAfterClose(Menu);
        Menu->exec(WindowTable->viewport()->mapToGlobal(Position));
    }

    SearchLineEdit *SearchEdit = nullptr;
    QTimer *SearchDebounceTimer = nullptr;
    IndeterminateProgressRing *RefreshIndicator = nullptr;
    PushButton *RefreshButton = nullptr;
    TableWidget *WindowTable = nullptr;
    TableWidget *ProtectedTable = nullptr;
    PushButton *UnprotectButton = nullptr;
    std::vector<WindowRow> Rows;

    struct ProtectedWin { ULONG64 Hwnd; ULONG Pid; QString Title; ULONG Flags; };
    std::vector<ProtectedWin> ProtectedWindows;
    std::atomic_bool Refreshing = false;

    bool IsTrackedProtectedWindow(ULONG64 Hwnd) const
    {
        return std::any_of(ProtectedWindows.begin(), ProtectedWindows.end(),
            [Hwnd](const ProtectedWin &Entry) { return Entry.Hwnd == Hwnd; });
    }

    void ProtectWindowEntry(ULONG Pid, ULONG64 Hwnd, const QString &Title)
    {
        if (IsTrackedProtectedWindow(Hwnd))
        {
            ShowWarningNotice(this, "Window", "This window is already protected.");
            return;
        }
        if (G_DeviceHandle == INVALID_HANDLE_VALUE && !OpenDeviceSilent())
        {
            const DWORD ErrorCode = GetLastError();
            G_LastMultiDrvError = ErrorCode;
            ShowErrorNotice(this, "Window",
                "Kernel driver is not available.\n" + DescribeWin32ErrorMessage(ErrorCode));
            return;
        }
        if (!ProtectWindowKernel(Pid, Hwnd, WINPROT_ALL))
        {
            ShowErrorNotice(this, "Window",
                QString("Protect failed.\n%1").arg(DescribeWin32ErrorMessage(G_LastMultiDrvError)));
            return;
        }
        ProtectedWindows.push_back({Hwnd, Pid, Title, WINPROT_ALL});
        RefreshProtectedTable();
        ShowSuccessNotice(this, "Window", "Window protected.");
    }

    void UnprotectSelected()
    {
        std::vector<ProtectedWin> ToRemove;
        QStringList Failures;
        for (const QModelIndex &Idx : ProtectedTable->selectionModel()->selectedRows(0))
        {
            ULONG64 Hwnd = Idx.data(Qt::UserRole).toULongLong();
            ULONG Pid = Idx.data(Qt::UserRole + 1).toUInt();
            for (const auto &P : ProtectedWindows)
                if (P.Hwnd == Hwnd) { ToRemove.push_back(P); break; }
            if ((G_DeviceHandle == INVALID_HANDLE_VALUE && !OpenDeviceSilent()) || !UnprotectWindowKernel(Pid, Hwnd))
                Failures.append(QString("0x%1 (error %2)").arg(Hwnd, 0, 16).arg(G_LastMultiDrvError));
        }
        for (const auto &P : ToRemove)
        {
            if (Failures.contains(QString("0x%1").arg(P.Hwnd, 0, 16), Qt::CaseInsensitive))
                continue;
            auto It = std::find_if(ProtectedWindows.begin(), ProtectedWindows.end(),
                [&P](const ProtectedWin &W) { return W.Hwnd == P.Hwnd; });
            if (It != ProtectedWindows.end()) ProtectedWindows.erase(It);
        }
        RefreshProtectedTable();
        if (Failures.isEmpty())
            ShowSuccessNotice(this, "Window", "Selected window protection removed.");
        else
            ShowErrorNotice(this, "Window", "Failed to unprotect:\n" + Failures.join('\n'));
    }

    void RefreshProtectedTable()
    {
        ProtectedTable->clearContents();
        ProtectedTable->setRowCount(static_cast<int>(ProtectedWindows.size()));
        for (int R = 0; R < static_cast<int>(ProtectedWindows.size()); ++R)
        {
            const auto &P = ProtectedWindows[R];
            auto *HwndItem = new QTableWidgetItem(QString("0x%1").arg(P.Hwnd, 0, 16));
            HwndItem->setData(Qt::UserRole, QVariant::fromValue<qulonglong>(P.Hwnd));
            HwndItem->setData(Qt::UserRole + 1, QVariant::fromValue<quint32>(P.Pid));
            ProtectedTable->setItem(R, 0, HwndItem);
            ProtectedTable->setItem(R, 1, new QTableWidgetItem(P.Title));
            ProtectedTable->setItem(R, 2, new QTableWidgetItem(QString::number(P.Pid)));
            ProtectedTable->setItem(R, 3, new QTableWidgetItem(QString("0x%1").arg(P.Flags, 8, 16, QLatin1Char('0'))));
            ProtectedTable->setRowHeight(R, KCompactTableRowHeight);
        }
        UnprotectButton->setEnabled(false);
    }
};

