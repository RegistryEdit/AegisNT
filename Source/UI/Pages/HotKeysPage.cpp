// ============================================================
// 热键页：枚举系统级全局热键（RegisterHotKey），显示 PID、进程名、
// 按键组合、虚拟键码、修饰键、id 与内核对象地址，支持搜索与定时刷新。
// ============================================================
#include "../../../Platform/AegisCoreCall.h"
#include "HotKeyFormat.h"

// 一次性快照 PID -> 进程名映射（Toolhelp，遍历代价低）。
static std::unordered_map<quint32, QString> HotKeySnapshotProcessNames() {
  std::unordered_map<quint32, QString> Names;
  HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (Snapshot == INVALID_HANDLE_VALUE)
    return Names;
  PROCESSENTRY32W Entry{};
  Entry.dwSize = sizeof(Entry);
  if (Process32FirstW(Snapshot, &Entry)) {
    do {
      Names.try_emplace(Entry.th32ProcessID,
                        QString::fromWCharArray(Entry.szExeFile));
    } while (Process32NextW(Snapshot, &Entry));
  }
  CloseHandle(Snapshot);
  return Names;
}

QWidget *CreateHotKeysPage() {
  struct HotKeysState {
    std::shared_ptr<HOTKEY_ENUM_OUTPUT> Result =
        std::make_shared<HOTKEY_ENUM_OUTPUT>();
    std::shared_ptr<std::unordered_map<quint32, QString>> Names =
        std::make_shared<std::unordered_map<quint32, QString>>();
    std::atomic_bool Refreshing = false;
  };

  auto *Page = new AegisNT::PageBase(nullptr);
  auto *Layout = Page->GetMainLayout();
  ConfigurePageLayout(Layout);
  auto *Toolbar = new QHBoxLayout;
  ConfigureToolbarLayout(Toolbar);

  auto *Search = new SearchLineEdit;
  Search->setPlaceholderText("Search PID, process, or key");
  Search->setClearButtonEnabled(true);
  Search->setMaximumWidth(320);

  auto *Status = new BodyLabel("Not queried.");
  auto *RefreshIndicator = new IndeterminateProgressRing(Page, false);
  RefreshIndicator->setFixedSize(22, 22);
  RefreshIndicator->hide();
  auto *Refresh = MakeButton("Refresh", true);

  Toolbar->addWidget(Search);
  Toolbar->addStretch();
  Toolbar->addWidget(Status);
  Toolbar->addWidget(RefreshIndicator);
  Toolbar->addWidget(Refresh);
  Layout->addLayout(Toolbar);

  auto *Table = MakeTable(
      {"PID", "Process", "Hotkey", "Key", "Modifiers", "Flags", "ID", "Object"});
  Table->setContextMenuPolicy(Qt::CustomContextMenu);
  Table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
  Table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
  Layout->addWidget(Table, 1);

  const auto State = std::make_shared<HotKeysState>();

  const auto Populate = [Search, Table, State] {
    const std::shared_ptr<HOTKEY_ENUM_OUTPUT> Result = State->Result;
    const auto &Names = *State->Names;
    const QString SearchText = Search->text().trimmed();

    const bool Sorting = Table->isSortingEnabled();
    Table->setSortingEnabled(false);
    Table->clearContents();
    Table->setRowCount(0);

    const auto Hex = [](ULONG_PTR Value) {
      return QString("0x%1")
          .arg(Value, sizeof(ULONG_PTR) * 2, 16, QLatin1Char('0'))
          .toUpper();
    };
    const auto AddRow = [Table, SearchText](const QStringList &Columns, ULONG SourceIndex) {
      if (!SearchText.isEmpty() &&
          !Columns.join(' ').contains(SearchText, Qt::CaseInsensitive))
        return;
      const int Row = Table->rowCount();
      Table->insertRow(Row);
      for (int Col = 0; Col < Columns.size(); ++Col)
        Table->setItem(Row, Col, new QTableWidgetItem(Columns[Col]));
      Table->item(Row, 0)->setData(Qt::UserRole, static_cast<uint>(SourceIndex));
      Table->setRowHeight(Row, KCompactTableRowHeight);
    };

    for (ULONG Index = 0; Index < Result->Count && Index < HOTKEY_MAX_ENTRIES; ++Index) {
      const HOTKEY_ENUM_ENTRY &Entry = Result->Entries[Index];
      const QString Key = HotKeyFormat::VirtualKeyName(Entry.VirtualKey);
      const QString Mods = HotKeyFormat::ModifierName(Entry.Modifiers);
      const QString Combo = Mods.isEmpty() ? Key : (Mods + " + " + Key);
      const QString Process =
          Entry.ProcessId == 0
              ? "-"
              : (Entry.ProcessId == 4
                     ? "System"
                     : ([&] {
                         auto It = Names.find(Entry.ProcessId);
                         return It != Names.end() ? It->second
                                                  : QString("<%1>").arg(Entry.ProcessId);
                       })());
      const QString Vk = QString("%1 (0x%2)")
                             .arg(Key)
                             .arg(QString::number(Entry.VirtualKey, 16)
                                      .rightJustified(2, QLatin1Char('0')).toUpper());
      const QString Flags = HotKeyFormat::FlagsName(Entry.Flags);
      AddRow({QString::number(Entry.ProcessId), Process, Combo, Vk,
              QString("0x%1").arg(Entry.Modifiers, 4, 16, QLatin1Char('0')).toUpper(),
              Flags.isEmpty() ? "-" : Flags,
              QString::number(Entry.Id), Hex(Entry.HotKeyObject)}, Index);
    }
    Table->setSortingEnabled(Sorting);
  };

  const auto RefreshHotKeys = [Page, Search, Status, Refresh, RefreshIndicator,
                               State, Populate] {
    if (State->Refreshing.exchange(true))
      return;
    Refresh->setEnabled(false);
    Refresh->setText("Refreshing...");
    RefreshIndicator->show();
    RefreshIndicator->start();
    Status->setText("Enumerating global hotkeys...");

    QPointer<QWidget> SafePage(Page);
    std::thread([SafePage, Status, Refresh, RefreshIndicator, State, Populate] {
      auto Result = std::make_shared<HOTKEY_ENUM_OUTPUT>();
      const bool Success = EnumerateHotkeys(Result.get()) != FALSE;
      const DWORD ErrorCode = G_LastAegisCoreError;
      auto Names = std::make_shared<std::unordered_map<quint32, QString>>(
          HotKeySnapshotProcessNames());

      QMetaObject::invokeMethod(
          qApp,
          [SafePage, Status, Refresh, RefreshIndicator, State, Populate,
           Result = std::move(Result), Names = std::move(Names), Success,
           ErrorCode] {
            State->Result = Result;
            State->Names = Names;
            State->Refreshing = false;
            if (!SafePage)
              return;
            RefreshIndicator->stop();
            RefreshIndicator->hide();
            Refresh->setText("Refresh");
            Refresh->setEnabled(true);
            if (!Success) {
              Status->setText(QString("Enumeration failed (error %1)").arg(ErrorCode));
              Populate();
              return;
            }
            if (Result->Count == 0) {
              if (Result->TableAddress == 0) {
                // 表未定位：给出诊断数据，便于判断是扫描失败还是 win32k 版本差异
                Status->setText(
                    QString("Hotkey table not located (win32k base 0x%1, %2 candidate(s) "
                            "scanned)")
                        .arg(Result->Win32kBase, 0, 16)
                        .arg(Result->CandidateCount)
                        .toUpper());
              } else {
                Status->setText(
                    QString("0 hotkeys registered (table at 0x%1)")
                        .arg(Result->TableAddress, 0, 16)
                        .toUpper());
              }
            } else {
              Status->setText(QString("%1 hotkeys").arg(Result->Count));
            }
            Populate();
          },
          Qt::QueuedConnection);
    }).detach();
  };

  QObject::connect(Table, &QWidget::customContextMenuRequested, Page,
      [Page, Table, State, Status, Refresh, RefreshIndicator, RefreshHotKeys](const QPoint& Position) {
        if (State->Refreshing) return;
        const QModelIndex Index = Table->indexAt(Position);
        if (!Index.isValid()) return;
        const auto* Item = Table->item(Index.row(), 0);
        if (!Item) return;
        const ULONG SourceIndex = Item->data(Qt::UserRole).toUInt();
        if (SourceIndex >= State->Result->Count || SourceIndex >= HOTKEY_MAX_ENTRIES) return;
        // 捕获完整快照，菜单打开期间的过滤、排序和定时刷新不会改变删除目标。
        const HOTKEY_ENUM_ENTRY Entry = State->Result->Entries[SourceIndex];
        Table->selectRow(Index.row());
        auto* Menu = new RoundMenu(QString(), Page);
        auto* Remove = new QAction("Remove HotKey", Menu);
        Menu->addAction(Remove);
        ConnectMenuAction(Remove, Page,
            [Page, State, Status, Refresh, RefreshIndicator, RefreshHotKeys, Entry] {
              if (State->Refreshing.exchange(true)) return;
              Refresh->setEnabled(false);
              RefreshIndicator->show();
              RefreshIndicator->start();
              Status->setText("Removing hotkey...");
              QPointer<QWidget> SafePage(Page);
              std::thread([SafePage, State, Status, Refresh, RefreshIndicator, RefreshHotKeys, Entry] {
                NTSTATUS KernelStatus = 0;
                DWORD ErrorCode = 0;
                ULONG Detail = HOTKEY_REMOVE_DETAIL_NONE;
                HOTKEY_REMOVE_DIAGNOSTIC Diagnostic{};
                const bool Success = RemoveHotkey(Entry, &KernelStatus, &ErrorCode, &Detail, &Diagnostic) != FALSE;
                QMetaObject::invokeMethod(qApp,
                    [SafePage, State, Status, Refresh, RefreshIndicator, RefreshHotKeys,
                     Success, KernelStatus, ErrorCode, Detail, Diagnostic, Entry] {
                      State->Refreshing = false;
                      if (!SafePage) return;
                      RefreshIndicator->stop();
                      RefreshIndicator->hide();
                      Refresh->setEnabled(true);
                      if (Success) {
                        ShowSuccessNotice(SafePage, "HotKeys", "Hotkey removed.");
                        RefreshHotKeys();
                        return;
                      }
                      QString Message;
                      const ULONG Code = static_cast<ULONG>(KernelStatus);
                      if (ErrorCode == ERROR_INVALID_FUNCTION || ErrorCode == ERROR_REVISION_MISMATCH) {
                        Message = "The loaded driver does not support hotkey removal. Reload the updated driver.";
                      } else if (!ErrorCode && Code == 0xC00000BBu) {
                        Message = QString("Hotkey removal validation failed at %1 (stage %2).")
                                      .arg(HotKeyFormat::RemovalStageName(Detail)).arg(Detail);
                      } else if (!ErrorCode && (Code == 0xC0000225u || Code == 0xC000022Du)) {
                        Message = "The hotkey changed or was already removed. Refresh and select it again.";
                      } else {
                        Message = QString("Hotkey removal failed (error %1, kernel status 0x%2).")
                            .arg(ErrorCode).arg(Code, 8, 16, QLatin1Char('0'));
                      }
                      Message += QString(" [PID %1, ID %2, VK 0x%3, flags 0x%4, status 0x%5, stage %6]")
                          .arg(Entry.ProcessId).arg(Entry.Id).arg(Entry.VirtualKey, 2, 16, QLatin1Char('0'))
                          .arg(Entry.Flags, 4, 16, QLatin1Char('0'))
                          .arg(Code, 8, 16, QLatin1Char('0')).arg(Detail);
                      if (Diagnostic.Actual) {
                        Message += QString(" [target 0x%1, resolved 0x%2, expected 0x%3, alternate 0x%4, base 0x%5, full 0x%6, code %7]")
                            .arg(Diagnostic.Actual, 0, 16).arg(Diagnostic.Resolved, 0, 16)
                            .arg(Diagnostic.Expected, 0, 16).arg(Diagnostic.Alternate, 0, 16)
                            .arg(Diagnostic.BaseImage, 0, 16).arg(Diagnostic.FullImage, 0, 16)
                            .arg(QString::fromLatin1(QByteArray(
                                reinterpret_cast<const char*>(Diagnostic.Code),
                                int(qMin(Diagnostic.CodeSize, ULONG(sizeof(Diagnostic.Code))))).toHex()));
                      }
                      Status->setText(Message);
                      ShowErrorNotice(SafePage, "HotKeys", Message);
                      if (!ErrorCode && (Code == 0xC0000225u || Code == 0xC000022Du)) RefreshHotKeys();
                    }, Qt::QueuedConnection);
              }).detach();
            });
        ReleaseMenuAfterClose(Menu);
        Menu->exec(Table->viewport()->mapToGlobal(Position));
      });

  QObject::connect(Search, &QLineEdit::textChanged, Page, [Populate] { Populate(); });
  QObject::connect(Refresh, &QPushButton::clicked, Page, [RefreshHotKeys] { RefreshHotKeys(); });

  auto *RefreshTimer = new QTimer(Page);
  QObject::connect(RefreshTimer, &QTimer::timeout, Page, [Page, RefreshHotKeys] {
    if (Page->isVisible())
      RefreshHotKeys();
  });
  RefreshTimer->start(10000);

  RefreshHotKeys();
  return Page;
}
