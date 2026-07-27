QWidget *CreateCallbackPage()
{
    const auto DescribeCallbackType = [](ULONG Type) {
        switch (Type)
        {
        case CALLBACK_TYPE_OB_PROCESS:
            return QString("ObProcess");
        case CALLBACK_TYPE_OB_THREAD:
            return QString("ObThread");
        case CALLBACK_TYPE_REGISTRY:
            return QString("Registry");
        case CALLBACK_TYPE_FLT_PRE_CREATE:
            return QString("FltCreate");
        case CALLBACK_TYPE_FLT_PRE_SET_INFORMATION:
            return QString("FltSetInfo");
        case CALLBACK_TYPE_FLT_PRE_WRITE:
            return QString("FltWrite");
        case CALLBACK_TYPE_FLT_PRE_READ:
            return QString("FltRead");
        case CALLBACK_TYPE_FLT_PRE_QUERY_INFORMATION:
            return QString("FltQueryInfo");
        case CALLBACK_TYPE_FLT_PRE_DIRECTORY_CONTROL:
            return QString("FltDirCtrl");
        case CALLBACK_TYPE_FLT_PRE_CLEANUP:
            return QString("FltCleanup");
        case CALLBACK_TYPE_FLT_PRE_CLOSE:
            return QString("FltClose");
        case CALLBACK_TYPE_FLT_POST_CREATE:
            return QString("FltPostCreate");
        case CALLBACK_TYPE_FLT_POST_READ:
            return QString("FltPostRead");
        case CALLBACK_TYPE_FLT_POST_QUERY_INFORMATION:
            return QString("FltPostQuery");
        case CALLBACK_TYPE_FLT_POST_SET_INFORMATION:
            return QString("FltPostSet");
        case CALLBACK_TYPE_FLT_POST_DIRECTORY_CONTROL:
            return QString("FltPostDir");
        case CALLBACK_TYPE_FLT_POST_WRITE:
            return QString("FltPostWrite");
        case CALLBACK_TYPE_FLT_POST_CLEANUP:
            return QString("FltPostCleanup");
        case CALLBACK_TYPE_FLT_POST_CLOSE:
            return QString("FltPostClose");
        case CALLBACK_TYPE_PS_PROCESS_NOTIFY:
            return QString("PsProcess");
        case CALLBACK_TYPE_PS_THREAD_NOTIFY:
            return QString("PsThread");
        case CALLBACK_TYPE_PS_IMAGE_NOTIFY:
            return QString("PsImage");
        case CALLBACK_TYPE_BUGCHECK:
            return QString("BugCheck");
        case CALLBACK_TYPE_BUGCHECK_REASON:
            return QString("BugChkReason");
        case CALLBACK_TYPE_SHUTDOWN:
            return QString("Shutdown");
        default:
            return QString("Unknown");
        }
    };
    struct CallbackPageState
    {
        std::vector<CALLBACK_ENTRY> Rows;
        std::atomic_bool Refreshing = false;
        std::atomic_bool Removing = false;
    };

    auto *Page = new QWidget;
    auto *Layout = new QVBoxLayout(Page);
    ConfigurePageLayout(Layout);
    auto *Toolbar = new QHBoxLayout;
    ConfigureToolbarLayout(Toolbar);
    auto *TypeFilter = new ComboBox;
    TypeFilter->addItems({"All", "ObProcess", "ObThread", "Registry", "PsProcess", "PsThread", "PsImage",
                          "BugCheck", "BugChkReason", "Shutdown", "FltCreate", "FltRead", "FltQueryInfo",
                          "FltSetInfo", "FltDirCtrl", "FltWrite", "FltCleanup", "FltClose",
                          "FltPostCreate", "FltPostRead", "FltPostQuery", "FltPostSet", "FltPostDir",
                          "FltPostWrite", "FltPostCleanup", "FltPostClose"});
    TypeFilter->setCurrentIndex(0);
    auto *Search = new SearchLineEdit;
    Search->setPlaceholderText("Search type, source, module, or address");
    Search->setClearButtonEnabled(true);
    Search->setMaximumWidth(360);
    auto *Status = new BodyLabel("Not queried.");
    auto *RefreshIndicator = new IndeterminateProgressRing(Page, false);
    RefreshIndicator->setFixedSize(22, 22);
    RefreshIndicator->hide();
    auto *Refresh = MakeButton("Refresh", true);
    Toolbar->addWidget(TypeFilter);
    Toolbar->addWidget(Search);
    Toolbar->addStretch();
    Toolbar->addWidget(Status);
    Toolbar->addWidget(RefreshIndicator);
    Toolbar->addWidget(Refresh);
    Layout->addLayout(Toolbar);
    auto *Table = MakeTable({"Type", "Address", "Module", "Source"});
    Table->setSelectionMode(QAbstractItemView::SingleSelection);
    Table->setContextMenuPolicy(Qt::CustomContextMenu);
    Table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    Table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    Table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    Table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    Layout->addWidget(Table, 1);
    const auto State = std::make_shared<CallbackPageState>();
    const auto Populate = [Search, TypeFilter, Table, State, DescribeCallbackType] { const QString Query = Search->text().trimmed(); const QString TypeFilterText = TypeFilter->currentText(); Table->clearContents(); Table->setRowCount(0); for (const CALLBACK_ENTRY &Entry : State->Rows) { const QString Type = DescribeCallbackType(Entry.Type);
        const QString Address = QString("0x%1").arg(Entry.Address, sizeof(ULONG_PTR) * 2, 16, QLatin1Char('0')).toUpper(); const QString Module = Entry.ModuleName[0] ? QString::fromWCharArray(Entry.ModuleName) : "(unknown)"; const QString Source = Entry.SourceName[0] ? QString::fromWCharArray(Entry.SourceName) : "(unknown)";
        if (TypeFilterText != "All" && Type != TypeFilterText) continue;
        if (!Query.isEmpty() && !(Type + " " + Address + " " + Module + " " + Source).contains(Query, Qt::CaseInsensitive)) continue; const int Row = Table->rowCount(); Table->insertRow(Row); auto *TypeItem = new QTableWidgetItem(Type); TypeItem->setData(Qt::UserRole, QVariant::fromValue<qulonglong>(Entry.Address)); TypeItem->setData(Qt::UserRole + 1, QVariant::fromValue<qulonglong>(Entry.Type)); TypeItem->setData(Qt::UserRole + 2, QVariant::fromValue<qulonglong>(Entry.Flags)); Table->setItem(Row, 0, TypeItem); Table->setItem(Row, 1, new QTableWidgetItem(Address)); Table->setItem(Row, 2, new QTableWidgetItem(Module)); Table->setItem(Row, 3, new QTableWidgetItem(Source)); Table->setRowHeight(Row, KCompactTableRowHeight); } };
    const auto Query = [Page, Status, Refresh, RefreshIndicator, State, Populate, DescribeCallbackType](bool ShowResult) {
        if (State->Refreshing.exchange(true))
            return;
        Refresh->setEnabled(false);
        Refresh->setText("Refreshing...");
        RefreshIndicator->show();
        RefreshIndicator->start();
        Status->setText("Enumerating callbacks...");
        QPointer<QWidget> SafePage(Page);
        std::thread([SafePage, Status, Refresh, RefreshIndicator, State, Populate, DescribeCallbackType, ShowResult] {
            std::vector<CALLBACK_ENTRY> Rows;
            DWORD BytesReturned = 0;
            ULONG Count = 0;
            bool Success = SendIoctlWithOutput(IOCTL_ENUM_CALLBACKS, nullptr, 0, &Count, sizeof(Count),
                                               &BytesReturned) != FALSE;
            DWORD ErrorCode = G_LastMultiDrvError;
            if (Success && Count)
            {
                const DWORD Size = sizeof(CALLBACK_ENUM_OUTPUT) + (Count - 1) * sizeof(CALLBACK_ENTRY);
                std::vector<BYTE> Buffer(Size);
                auto *Output = reinterpret_cast<PCALLBACK_ENUM_OUTPUT>(Buffer.data());
                ZeroMemory(Output, Size);
                Success = SendIoctlWithOutput(IOCTL_ENUM_CALLBACKS, nullptr, 0, Output, Size,
                                              &BytesReturned) != FALSE;
                ErrorCode = G_LastMultiDrvError;
                if (Success)
                {
                    const size_t MaxEntries = Count;
                    const size_t ReturnedEntries = static_cast<size_t>(Output->Count);
                    const size_t RequiredBytes = sizeof(CALLBACK_ENUM_OUTPUT) +
                                                 (ReturnedEntries ? (ReturnedEntries - 1) * sizeof(CALLBACK_ENTRY) : 0);
                    if (ReturnedEntries > MaxEntries || BytesReturned < RequiredBytes)
                    {
                        Success = false;
                        ErrorCode = ERROR_INVALID_DATA;
                    }
                    else
                    {
                        Rows.assign(Output->Entries, Output->Entries + ReturnedEntries);
                    }
                }
            }
            QMetaObject::invokeMethod(qApp, [SafePage, Status, Refresh, RefreshIndicator, State, Populate,
                                             DescribeCallbackType, Rows = std::move(Rows), Success, ErrorCode,
                                             ShowResult]() mutable {
                State->Refreshing = false;
                RefreshIndicator->stop();
                RefreshIndicator->hide();
                Refresh->setText("Refresh");
                Refresh->setEnabled(true);
                if (!SafePage)
                    return;
                if (!Success)
                {
                    const QString Message = QString("Enumeration failed (error %1)").arg(ErrorCode);
                    Status->setText(Message);
                    if (ShowResult)
                        ShowErrorNotice(SafePage, "Callback", Message);
                }
                else
                {
                    State->Rows = std::move(Rows);
                    QMap<QString, int> Counts;
                    for (const CALLBACK_ENTRY &Entry : State->Rows)
                        Counts[DescribeCallbackType(Entry.Type)]++;
                    QStringList Summary;
                    for (auto It = Counts.cbegin(); It != Counts.cend(); ++It)
                        Summary.append(QString("%1:%2").arg(It.key()).arg(It.value()));
                    Status->setText(Summary.isEmpty()
                                        ? QString("0 callback(s)")
                                        : QString("%1 callback(s) | %2").arg(State->Rows.size()).arg(Summary.join(", ")));
                    if (ShowResult)
                        ShowSuccessNotice(SafePage, "Callback",
                                          QString("Enumerated %1 callback(s).").arg(State->Rows.size()));
                }
                Populate();
            }, Qt::QueuedConnection);
        }).detach();
    };
    QObject::connect(TypeFilter, &ComboBox::currentTextChanged, Page, [Populate](const QString &) { Populate(); });
    QObject::connect(Search, &QLineEdit::textChanged, Page, [Populate] { Populate(); }); QObject::connect(Refresh, &QPushButton::clicked, Page, [Query] { Query(true); });
    QObject::connect(Table, &QWidget::customContextMenuRequested, Page, [Page, Table, State, Query](const QPoint &Position) { const QModelIndex Index = Table->indexAt(Position); if (!Index.isValid()) return; Table->selectRow(Index.row()); auto *TypeItem = Table->item(Index.row(), 0); if (!TypeItem) return; const ULONG_PTR Address = static_cast<ULONG_PTR>(TypeItem->data(Qt::UserRole).toULongLong()); const ULONG Type = static_cast<ULONG>(TypeItem->data(Qt::UserRole + 1).toULongLong()); const ULONG Flags = static_cast<ULONG>(TypeItem->data(Qt::UserRole + 2).toULongLong());
        auto *Menu = new RoundMenu(QString(), Page); auto *Remove = new QAction("Remove callback", Menu); Remove->setEnabled((Flags & CALLBACK_FLAG_CAN_REMOVE) != 0 && !State->Removing.load()); Menu->addAction(Remove); ConnectMenuAction(Remove, Page, [Page = QPointer<QWidget>(Page), State, Address, Type, Flags, Query] { if (!Page) return; if ((Flags & CALLBACK_FLAG_CAN_REMOVE) == 0) { ShowWarningNotice(Page, "Callback", "This callback is not marked as removable."); return; } if (State->Removing.exchange(true)) { ShowWarningNotice(Page, "Callback", "A callback removal is already running."); return; } if (QMessageBox::warning(Page, "Callback", QString("Remove callback at 0x%1?").arg(Address, sizeof(ULONG_PTR) * 2, 16, QLatin1Char('0')).toUpper(), QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes) { State->Removing = false; return; } QPointer<QWidget> SafePage(Page); std::thread([SafePage, State, Address, Type, Query] { CALLBACK_REMOVE_INPUT Input = {}; Input.Type = Type; Input.Address = Address; const bool Success = SendIoctl(IOCTL_REMOVE_CALLBACK_BY_ADDRESS, &Input, sizeof(Input)) != FALSE; const DWORD ErrorCode = G_LastMultiDrvError; QMetaObject::invokeMethod(qApp, [SafePage, State, Success, ErrorCode, Query] { State->Removing = false; if (!SafePage) return; if (!Success || ErrorCode != ERROR_SUCCESS) ShowErrorNotice(SafePage, "Callback", QString("Operation failed (error %1)").arg(ErrorCode)); else ShowSuccessNotice(SafePage, "Callback", "Callback removed successfully."); Query(false); }, Qt::QueuedConnection); }).detach(); }); ReleaseMenuAfterClose(Menu); Menu->exec(Table->viewport()->mapToGlobal(Position)); });
    if (TypeFilter->count() > 0)
        TypeFilter->setCurrentIndex(0);
    Query(false);
    return Page;
}

