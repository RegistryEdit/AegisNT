// ============================================================
// 热键页：枚举系统级全局热键（RegisterHotKey），显示 PID、进程名、
// 按键组合、虚拟键码、修饰键、id 与内核对象地址，支持搜索与定时刷新。
// ============================================================
#include "../../Platform/AegisCoreCall.h"

// 修饰键位（与 win32k MOD_* 一致）。
#define MOD_ALT_BIT 0x1
#define MOD_CONTROL_BIT 0x2
#define MOD_SHIFT_BIT 0x4
#define MOD_WIN_BIT 0x8

// 把虚拟键码翻译成人类可读的键名。
static QString HotKeyVkName(ULONG Vk) {
  if (Vk >= 'A' && Vk <= 'Z')
    return QString(QChar(static_cast<char>(Vk)));
  if (Vk >= '0' && Vk <= '9')
    return QString(QChar(static_cast<char>(Vk)));
  switch (Vk) {
  case 0x20: return "Space";
  case 0x0D: return "Enter";
  case 0x1B: return "Esc";
  case 0x09: return "Tab";
  case 0x08: return "Backspace";
  case 0x2E: return "Delete";
  case 0x2D: return "Insert";
  case 0x24: return "Home";
  case 0x23: return "End";
  case 0x21: return "PageUp";
  case 0x22: return "PageDown";
  case 0x25: return "Left";
  case 0x26: return "Up";
  case 0x27: return "Right";
  case 0x28: return "Down";
  default: break;
  }
  if (Vk >= 0x70 && Vk <= 0x87)
    return QString("F%1").arg(Vk - 0x6F);
  return QString("VK 0x%1").arg(Vk, 2, 16, QLatin1Char('0')).toUpper();
}

// 把修饰键组合翻译成 "Ctrl + Alt + Shift + Win" 形式的字符串。
static QString HotKeyModifierName(ULONG Modifiers) {
  QStringList Parts;
  if (Modifiers & MOD_CONTROL_BIT) Parts << "Ctrl";
  if (Modifiers & MOD_ALT_BIT) Parts << "Alt";
  if (Modifiers & MOD_SHIFT_BIT) Parts << "Shift";
  if (Modifiers & MOD_WIN_BIT) Parts << "Win";
  return Parts.join(" + ");
}

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

  auto *Page = new QWidget;
  auto *Layout = new QVBoxLayout(Page);
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
      {"PID", "Process", "Hotkey", "Key", "Modifiers", "ID", "Object"});
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
      const QString Key = HotKeyVkName(Entry.VirtualKey);
      const QString Mods = HotKeyModifierName(Entry.Modifiers);
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
      AddRow({QString::number(Entry.ProcessId), Process, Combo, Key,
              QString("0x%1").arg(Entry.Modifiers, 2, 16, QLatin1Char('0')).toUpper(),
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
                const bool Success = RemoveHotkey(Entry, &KernelStatus, &ErrorCode) != FALSE;
                QMetaObject::invokeMethod(qApp,
                    [SafePage, State, Status, Refresh, RefreshIndicator, RefreshHotKeys,
                     Success, KernelStatus, ErrorCode] {
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
                      if (ErrorCode == ERROR_INVALID_FUNCTION) {
                        Message = "The loaded driver does not support hotkey removal. Reload the updated driver.";
                      } else if (!ErrorCode && Code == 0xC00000BBu) {
                        Message = "This Windows hotkey layout or internal registration is not supported for removal.";
                      } else if (!ErrorCode && (Code == 0xC0000225u || Code == 0xC000022Du)) {
                        Message = "The hotkey changed or was already removed. Refresh and select it again.";
                      } else {
                        Message = QString("Hotkey removal failed (error %1, kernel status 0x%2).")
                            .arg(ErrorCode).arg(Code, 8, 16, QLatin1Char('0'));
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
