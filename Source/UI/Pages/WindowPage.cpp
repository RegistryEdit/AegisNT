// ============================================================
// 窗口管理页（WindowManagerPage）：枚举顶层窗口及其进程信息�?
// 支持置顶/激�?隐藏/关闭窗口与按条件筛选�?
// ============================================================
class WindowManagerPage final : public AegisNT::PageBase {
  struct WindowRow {
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
    int ZIndex = -1;
    DWORD Band = 0xFFFFFFFF;
    ULONG KernelFlags = 0;
    bool FromKernel = false;
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
  explicit WindowManagerPage(QWidget *Parent = nullptr) : AegisNT::PageBase(nullptr, Parent) {
    auto *Layout = GetMainLayout();
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

    auto *WinPage = new AegisNT::PageBase(nullptr);
    auto *WinLayout = WinPage->GetMainLayout();
    ConfigurePageLayout(WinLayout);
    auto *Toolbar = new QHBoxLayout;
    ConfigureToolbarLayout(Toolbar);
    SearchEdit = new SearchLineEdit;
    ConfigureSearchLineEdit(SearchEdit,
                            "Search title, class, process, PID, or HWND",
                            KStandardSearchWidth);
    RefreshIndicator = new IndeterminateProgressRing(this, false);
    RefreshIndicator->setFixedSize(22, 22);
    RefreshIndicator->hide();
    RefreshButton = MakeButton("Refresh", true);
    ConfigureActionButton(RefreshButton);
    Toolbar->addWidget(SearchEdit);
    Toolbar->addStretch();
    Toolbar->addWidget(RefreshIndicator);
    Toolbar->addWidget(RefreshButton);
    KernelModeCheck = new CheckBox("KernelMode");
    KernelModeCheck->setChecked(true);
    Toolbar->addWidget(KernelModeCheck);
    WinLayout->addLayout(Toolbar);
    WindowTree = new FluentTreeWidget;
    WindowTree->setColumnCount(13);
    WindowTree->setHeaderLabels({"HWND", "Z", "Band", "Title", "Class",
                                 "Process", "PID", "Style", "State", "Flags",
                                 "Properties", "Rect", "Dpi"});
    WindowTree->setSelectionMode(QAbstractItemView::SingleSelection);
    WindowTree->setSelectionBehavior(QAbstractItemView::SelectRows);
    WindowTree->setContextMenuPolicy(Qt::CustomContextMenu);
    WindowTree->setProperty("DetailDialogTitle", "Window details");
    WindowTree->setUniformRowHeights(true);
    WindowTree->setAnimated(false);
    WindowTree->setExpandsOnDoubleClick(false);
    WindowTree->setAlternatingRowColors(true);
    WindowTree->setRootIsDecorated(true);
    WindowTree->setIndentation(16);
    WindowTree->setIconSize(QSize(16, 16));
    WindowTree->header()->setFixedHeight(34);
    WindowTree->header()->setHighlightSections(false);
    InstallFluentScrollBar(WindowTree, Qt::Vertical);
    InstallFluentScrollBar(WindowTree, Qt::Horizontal);
    WindowTree->header()->setStretchLastSection(false);
    WindowTree->header()->setMinimumSectionSize(80);
    WindowTree->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    WindowTree->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    WindowTree->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    WindowTree->header()->setSectionResizeMode(3, QHeaderView::Stretch);
    WindowTree->header()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    WindowTree->header()->setSectionResizeMode(5, QHeaderView::Stretch);
    WindowTree->header()->setSectionResizeMode(6, QHeaderView::ResizeToContents);
    WindowTree->header()->setSectionResizeMode(7, QHeaderView::Interactive);
    WindowTree->header()->setSectionResizeMode(8, QHeaderView::Interactive);
    WindowTree->header()->setSectionResizeMode(9, QHeaderView::Interactive);
    WindowTree->header()->setSectionResizeMode(10, QHeaderView::Interactive);
    WindowTree->header()->setSectionResizeMode(11, QHeaderView::Interactive);
    WindowTree->header()->setSectionResizeMode(12, QHeaderView::ResizeToContents);
    WinLayout->addWidget(WindowTree, 1);

    auto *ProtPage = new AegisNT::PageBase(nullptr);
    auto *ProtLayout = ProtPage->GetMainLayout();
    ConfigurePageLayout(ProtLayout, 8);
    auto *ProtToolbar = new QHBoxLayout;
    ConfigureToolbarLayout(ProtToolbar);
    auto *ProtTitle =
        MakeLabel("Protected Windows", 13, KTextPrimary, QFont::DemiBold);
    UnprotectButton = MakeButton("Unprotect", true);
    UnprotectButton->setEnabled(false);
    ProtToolbar->addWidget(ProtTitle);
    ProtToolbar->addStretch();
    ProtToolbar->addWidget(UnprotectButton);
    ProtLayout->addLayout(ProtToolbar);
    ProtectedTable = MakeTable({"HWND", "Title", "PID", "Flags"});
    ProtectedTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
    ProtectedTable->setProperty("DetailDialogTitle",
                                "Protected window details");
    ProtectedTable->horizontalHeader()->setSectionResizeMode(
        0, QHeaderView::ResizeToContents);
    ProtectedTable->horizontalHeader()->setSectionResizeMode(
        1, QHeaderView::Stretch);
    ProtectedTable->verticalHeader()->setDefaultSectionSize(
        KCompactTableRowHeight);
    ProtLayout->addWidget(ProtectedTable, 1);

    Pages->addWidget(WinPage);
    Pages->addWidget(ProtPage);
    QObject::connect(Tabs, &TabBar::currentChanged, Pages,
                     &QStackedWidget::setCurrentIndex);

    SearchDebounceTimer = new QTimer(this);
    SearchDebounceTimer->setSingleShot(true);
    SearchDebounceTimer->setInterval(KSearchDebounceMs);
    QObject::connect(SearchDebounceTimer, &QTimer::timeout, this,
                     [this] { Populate(); });
    QObject::connect(SearchEdit, &QLineEdit::textChanged, this,
                     [this] { SearchDebounceTimer->start(); });
    QObject::connect(RefreshButton, &QPushButton::clicked, this,
                     [this] { Refresh(true); });
    QObject::connect(WindowTree, &QWidget::customContextMenuRequested, this,
                     [this](const QPoint &Position) { ShowMenu(Position); });
    QObject::connect(
        WindowTree, &QTreeWidget::itemDoubleClicked, this,
        [this](QTreeWidgetItem *Item, int) {
          if (!Item || Item->data(0, Qt::UserRole).toULongLong() == 0)
            return;
          QStringList Lines;
          for (int Column = 0; Column < WindowTree->columnCount(); ++Column) {
            const QString Header =
                WindowTree->headerItem() &&
                        !WindowTree->headerItem()->text(Column).isEmpty()
                    ? WindowTree->headerItem()->text(Column)
                    : QString("Column %1").arg(Column + 1);
            const QString Value = Item->text(Column);
            Lines.append(QString("%1: %2").arg(
                Header, Value.isEmpty() ? "(empty)" : Value));
          }
          auto *Dialog = new QDialog(WindowTree->window());
          Dialog->setAttribute(Qt::WA_DeleteOnClose);
          Dialog->resize(900, 610);
          Dialog->setWindowTitle(
              WindowTree->property("DetailDialogTitle").toString().isEmpty()
                  ? QString("Details")
                  : WindowTree->property("DetailDialogTitle").toString());
          auto *Layout = new QVBoxLayout(Dialog);
          Layout->setContentsMargins(14, 14, 14, 14);
          Layout->setSpacing(8);
          auto *Text = new PlainTextEdit;
          Text->setReadOnly(true);
          Text->setFont(QFont("Cascadia Mono", 10));
          Text->setPlainText(Lines.join("\n\n"));
          InstallFluentScrollBar(Text, Qt::Vertical);
          auto *Close = MakeButton("Close", true);
          Layout->addWidget(Text, 1);
          Layout->addWidget(Close, 0, Qt::AlignRight);
          QObject::connect(Close, &QPushButton::clicked, Dialog,
                           &QDialog::accept);
          ApplyDialogTheme(Dialog);
          Dialog->show();
        });
    QObject::connect(UnprotectButton, &QPushButton::clicked, this,
                     &WindowManagerPage::UnprotectSelected);
    QObject::connect(
        ProtectedTable, &QTableWidget::itemSelectionChanged, this, [this] {
          UnprotectButton->setEnabled(
              !ProtectedTable->selectionModel()->selectedRows(0).isEmpty());
        });
    Refresh();
  }

private:
  static QString ReadWindowText(HWND Handle) {
    const int Length = GetWindowTextLengthW(Handle);
    if (Length <= 0)
      return {};
    std::wstring Text(static_cast<size_t>(Length) + 1, L'\0');
    GetWindowTextW(Handle, Text.data(), static_cast<int>(Text.size()));
    return QString::fromWCharArray(Text.c_str());
  }

  static QString ReadWindowClassName(HWND Handle) {
    wchar_t ClassName[256]{};
    GetClassNameW(Handle, ClassName, 256);
    return QString::fromWCharArray(ClassName);
  }

  static QString FormatKernelFlags(ULONG Flags) {
    static const struct {
      ULONG Bit;
      const char *Name;
    } Names[] = {
        {WINDOW_FLAG_VISIBLE, "VISIBLE"},
        {WINDOW_FLAG_ENABLED, "ENABLED"},
        {WINDOW_FLAG_HUNG, "HUNG"},
        {WINDOW_FLAG_MINIMIZED, "MINIMIZED"},
        {WINDOW_FLAG_MAXIMIZED, "MAXIMIZED"},
        {WINDOW_FLAG_TOPMOST, "TOPMOST"},
        {WINDOW_FLAG_LAYERED, "LAYERED"},
        {WINDOW_FLAG_TOOLWINDOW, "TOOLWINDOW"},
        {WINDOW_FLAG_POPUP, "POPUP"},
        {WINDOW_FLAG_CHILD, "CHILD"},
        {WINDOW_FLAG_UNICODE, "UNICODE"},
        {WINDOW_FLAG_MDI, "MDI"},
        {WINDOW_FLAG_APPWINDOW, "APPWINDOW"},
        {WINDOW_FLAG_ACTIVE, "ACTIVE"},
        {WINDOW_FLAG_NOACTIVATE, "NOACTIVATE"},
        {WINDOW_FLAG_DISABLED_CLOSE, "DISABLED_CLOSE"},
        {WINDOW_FLAG_CLOAKED, "CLOAKED"},
        {WINDOW_FLAG_SKIPANIMATION, "SKIPANIMATION"},
        {WINDOW_FLAG_SKIPTHEME, "SKIPTHEME"},
        {WINDOW_FLAG_DESTROYED, "DESTROYED"},
    };
    QStringList Set;
    for (const auto &Entry : Names)
      if (Flags & Entry.Bit)
        Set.append(Entry.Name);
    return QString("0x%1").arg(Flags, 8, 16, QChar('0')) +
           (Set.isEmpty() ? QString() : " " + Set.join("|"));
  }

  static DWORD QueryWindowBand(HWND Handle) {
    using GetWindowBandFn = BOOL(WINAPI *)(HWND, PDWORD);
    static GetWindowBandFn GetWindowBand = []() -> GetWindowBandFn {
      HMODULE User32 = GetModuleHandleW(L"user32.dll");
      if (!User32)
        User32 = LoadLibraryW(L"user32.dll");
      if (!User32)
        return nullptr;
      return reinterpret_cast<GetWindowBandFn>(
          GetProcAddress(User32, "GetWindowBand"));
    }();
    if (!GetWindowBand)
      return 0xFFFFFFFF;
    DWORD Band = 0xFFFFFFFF;
    if (!GetWindowBand(Handle, &Band))
      return 0xFFFFFFFF;
    return Band;
  }

  static QString FormatBand(DWORD Band) {
    if (Band == 0xFFFFFFFF)
      return "-";
    static const char *const Names[] = {
        "ZBID_DEFAULT",
        "ZBID_DESKTOP",
        "ZBID_UIACCESS",
        "ZBID_IMMERSIVE_IHM",
        "ZBID_IMMERSIVE_NOTIFICATION",
        "ZBID_IMMERSIVE_APPCHROME",
        "ZBID_IMMERSIVE_MOLL",
        "ZBID_IMMERSIVE_EDGY",
        "ZBID_IMMERSIVE_INACTIVEMOBODY",
        "ZBID_IMMERSIVE_INACTIVEDOCK",
        "ZBID_IMMERSIVE_ACTIVEMOBODY",
        "ZBID_IMMERSIVE_ACTIVEDOCK",
        "ZBID_IMMERSIVE_BACKGROUND",
        "ZBID_IMMERSIVE_SEARCH",
        "ZBID_GENUINE_WINDOWS",
        "ZBID_IMMERSIVE_RESTRICTED",
        "ZBID_SYSTEM_TOOLS",
        "ZBID_LOCK",
        "ZBID_ABOVELOCK_UX",
    };
    if (Band < std::size(Names))
      return Names[Band];
    return QString("ZBID_0x%1").arg(Band, 0, 16);
  }

  void Refresh(bool ShowResult = false) {
    if (Refreshing.exchange(true))
      return;
    SetRefreshUiState(RefreshButton, RefreshIndicator, nullptr, true);
    const bool UseKernel = KernelModeCheck->isChecked();
    QPointer<WindowManagerPage> Page(this);
    std::thread([Page, ShowResult, UseKernel] {
      std::vector<WindowRow> Result;
      std::map<HWND, int> ZOrder;
      int ZPosition = 0;
      for (HWND Top = GetWindow(GetDesktopWindow(), GW_CHILD); Top;
           Top = GetWindow(Top, GW_HWNDNEXT))
        ZOrder.emplace(Top, ZPosition++);

      const auto ReadProcessPath = [](DWORD Pid) -> QString {
        HANDLE Process =
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
        QString Path;
        if (Process) {
          wchar_t Buffer[32768]{};
          DWORD Size = 32768;
          if (QueryFullProcessImageNameW(Process, 0, Buffer, &Size))
            Path = QString::fromWCharArray(Buffer,
                                           static_cast<qsizetype>(Size));
          CloseHandle(Process);
        }
        return Path;
      };

      bool KernelEnumerated = false;
      if (UseKernel) {
        if (G_DeviceHandle == INVALID_HANDLE_VALUE)
          OpenDeviceSilent();
        if (G_DeviceHandle != INVALID_HANDLE_VALUE) {
          const ULONG MaxEntryBytes =
              sizeof(KERNEL_WINDOW_ENUM_ENTRY) + 512;
          const ULONG Capacity = 8192;
          std::vector<unsigned char> Buffer(
              sizeof(KERNEL_WINDOW_ENUM_OUTPUT) + Capacity * MaxEntryBytes);
          ULONG Count = 0;
          if (EnumerateWindowsKernel(Buffer.data(),
                                     static_cast<ULONG>(Buffer.size()),
                                     &Count) &&
              Count > 0) {
            KernelEnumerated = true;
            const auto *Output =
                reinterpret_cast<const KERNEL_WINDOW_ENUM_OUTPUT *>(
                    Buffer.data());
            const unsigned char *Base =
                reinterpret_cast<const unsigned char *>(Output->Entries);
            for (ULONG Index = 0; Index < Count; ++Index) {
              const auto *Entry =
                  reinterpret_cast<const KERNEL_WINDOW_ENUM_ENTRY *>(Base);
              if (Entry->Hwnd == 0)
                break;
              WindowRow Row;
              Row.Handle = reinterpret_cast<HWND>(
                  static_cast<ULONG_PTR>(Entry->Hwnd));
              Row.Pid = Entry->ProcessId;
              Row.Tid = Entry->ThreadId;
              Row.Style = static_cast<LONG>(Entry->Style);
              Row.ExStyle = static_cast<LONG>(Entry->ExStyle);
              Row.ParentHwnd = reinterpret_cast<HWND>(
                  static_cast<ULONG_PTR>(Entry->ParentHwnd));
              Row.OwnerHwnd = reinterpret_cast<HWND>(
                  static_cast<ULONG_PTR>(Entry->OwnerHwnd));
              Row.Alpha = Entry->Alpha;
              Row.KernelFlags = Entry->Flags;
              Row.FromKernel = true;
              Row.Rect.left = Entry->Left;
              Row.Rect.top = Entry->Top;
              Row.Rect.right = Entry->Right;
              Row.Rect.bottom = Entry->Bottom;
              Row.ClientRect.left = Entry->ClientLeft;
              Row.ClientRect.top = Entry->ClientTop;
              Row.ClientRect.right = Entry->ClientRight;
              Row.ClientRect.bottom = Entry->ClientBottom;
              Row.Visible = (Entry->Flags & WINDOW_FLAG_VISIBLE) != 0;
              Row.Enabled = (Entry->Flags & WINDOW_FLAG_ENABLED) != 0;
              Row.Minimized = (Entry->Flags & WINDOW_FLAG_MINIMIZED) != 0;
              Row.Maximized = (Entry->Flags & WINDOW_FLAG_MAXIMIZED) != 0;
              Row.IsHung = (Entry->Flags & WINDOW_FLAG_HUNG) != 0;
              Row.IsTopmost = (Entry->Flags & WINDOW_FLAG_TOPMOST) != 0;
              Row.IsLayered = (Entry->Flags & WINDOW_FLAG_LAYERED) != 0;
              Row.IsToolWindow = (Entry->Flags & WINDOW_FLAG_TOOLWINDOW) != 0;
              Row.IsAppWindow = (Entry->Flags & WINDOW_FLAG_APPWINDOW) != 0;
              Row.IsPopup = (Entry->Flags & WINDOW_FLAG_POPUP) != 0;
              Row.IsChild = (Entry->Flags & WINDOW_FLAG_CHILD) != 0;
              Row.IsUnicode = (Entry->Flags & WINDOW_FLAG_UNICODE) != 0;
              if (Entry->TitleLength > 0 && Entry->TitleLength <= 510)
                Row.Title = QString::fromWCharArray(
                    reinterpret_cast<const wchar_t *>(Entry + 1),
                    Entry->TitleLength / sizeof(wchar_t));
              const auto ZIt = ZOrder.find(Row.Handle);
              Row.ZIndex = ZIt != ZOrder.end() ? ZIt->second : -1;
              Row.Band = QueryWindowBand(Row.Handle);
              const ULONG EntryBytes =
                  sizeof(KERNEL_WINDOW_ENUM_ENTRY) +
                  ((static_cast<ULONG>(Entry->TitleLength) + 1) & ~1u);
              Base += EntryBytes;
              Result.push_back(std::move(Row));
            }
          }
        }
      }

      if (!KernelEnumerated) {
        struct EnumContext {
          std::vector<WindowRow> *Rows;
          const std::map<HWND, int> *ZOrder;
        } Context{&Result, &ZOrder};
        EnumWindows(
            [](HWND Handle, LPARAM Parameter) -> BOOL {
              auto *Ctx = reinterpret_cast<EnumContext *>(Parameter);
              auto *Rows = Ctx->Rows;
              WindowRow Row;
              Row.Handle = Handle;
              const auto ZIt = Ctx->ZOrder->find(Handle);
              Row.ZIndex = ZIt != Ctx->ZOrder->end() ? ZIt->second : -1;
              Row.Band = QueryWindowBand(Handle);
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
              /* Kernel enumeration is optional.  Keep the same flag ABI for
                 the Win32 fallback so the Flags column remains useful when
                 the private win32k layout is unavailable. */
              Row.KernelFlags =
                  (Row.Visible ? WINDOW_FLAG_VISIBLE : 0u) |
                  (Row.Enabled ? WINDOW_FLAG_ENABLED : 0u) |
                  (Row.IsHung ? WINDOW_FLAG_HUNG : 0u) |
                  (Row.Minimized ? WINDOW_FLAG_MINIMIZED : 0u) |
                  (Row.Maximized ? WINDOW_FLAG_MAXIMIZED : 0u) |
                  (Row.IsTopmost ? WINDOW_FLAG_TOPMOST : 0u) |
                  (Row.IsLayered ? WINDOW_FLAG_LAYERED : 0u) |
                  (Row.IsToolWindow ? WINDOW_FLAG_TOOLWINDOW : 0u) |
                  (Row.IsPopup ? WINDOW_FLAG_POPUP : 0u) |
                  (Row.IsChild ? WINDOW_FLAG_CHILD : 0u) |
                  (Row.IsUnicode ? WINDOW_FLAG_UNICODE : 0u) |
                  ((Row.ExStyle & WS_EX_MDICHILD) ? WINDOW_FLAG_MDI : 0u) |
                  (Row.IsAppWindow ? WINDOW_FLAG_APPWINDOW : 0u) |
                  ((Row.ExStyle & WS_EX_NOACTIVATE) ? WINDOW_FLAG_NOACTIVATE
                                                    : 0u) |
                  ((Row.Style & WS_DISABLED) ? WINDOW_FLAG_DISABLED_CLOSE
                                             : 0u) |
                  ((GetForegroundWindow() == Handle) ? WINDOW_FLAG_ACTIVE
                                                      : 0u);
              Row.ParentHwnd = GetParent(Handle);
              Row.OwnerHwnd = GetWindow(Handle, GW_OWNER);
              Row.Dpi = GetDpiForWindow(Handle);
              GetWindowRect(Handle, &Row.Rect);
              GetClientRect(Handle, &Row.ClientRect);
              HANDLE Process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                           FALSE, Row.Pid);
              if (Process) {
                wchar_t Path[32768]{};
                DWORD Size = 32768;
                if (QueryFullProcessImageNameW(Process, 0, Path, &Size))
                  Row.ProcessPath = QString::fromWCharArray(
                      Path, static_cast<qsizetype>(Size));
                CloseHandle(Process);
              }
              if (!Row.Title.isEmpty() || !Row.ClassName.isEmpty())
                Rows->push_back(std::move(Row));
              return TRUE;
            },
            reinterpret_cast<LPARAM>(&Context));
      } else {
        for (WindowRow &Row : Result) {
          Row.ClassName = ReadWindowClassName(Row.Handle);
          if (Row.Dpi == 0)
            Row.Dpi = GetDpiForWindow(Row.Handle);
          if (Row.ProcessPath.isEmpty())
            Row.ProcessPath = ReadProcessPath(Row.Pid);
        }
      }

      if (KernelEnumerated) {
        Result.erase(std::remove_if(Result.begin(), Result.end(),
                                    [](const WindowRow &Row) {
                                      return Row.Title.isEmpty() &&
                                             Row.ClassName.isEmpty();
                                    }),
                     Result.end());
      }
      std::sort(Result.begin(), Result.end(),
                [](const WindowRow &Left, const WindowRow &Right) {
                  if (Left.Visible != Right.Visible)
                    return Left.Visible > Right.Visible;
                  return Left.Pid < Right.Pid;
                });
      QMetaObject::invokeMethod(
          qApp,
          [Page, Result = std::move(Result), ShowResult]() mutable {
            if (!Page)
              return;
            Page->Refreshing = false;
            Page->Rows = std::move(Result);
            SetRefreshUiState(Page->RefreshButton, Page->RefreshIndicator,
                              nullptr, false);
            Page->Populate();
            if (ShowResult)
              ShowSuccessNotice(Page, "Window", "Window list refreshed.");
          },
          Qt::QueuedConnection);
    }).detach();
  }

  void Populate() {
    const QString Query = SearchEdit->text().trimmed();
    std::vector<const WindowRow *> VisibleRows;
    VisibleRows.reserve(Rows.size());
    for (const WindowRow &Window : Rows) {
      const QString HandleText =
          QString("0x%1").arg(reinterpret_cast<quintptr>(Window.Handle), 0, 16);
      const QString SearchText = Window.Title + " " + Window.ClassName + " " +
                                 Window.ProcessPath + " " +
                                 QString::number(Window.Pid) + " " + HandleText;
      if (!Query.isEmpty() && !SearchText.contains(Query, Qt::CaseInsensitive))
        continue;
      VisibleRows.push_back(&Window);
    }

    WindowTree->setUpdatesEnabled(false);
    WindowTree->clear();

    const auto MakeWindowItem = [](const WindowRow &Window) {
      const QString HandleText = QString("0x%1").arg(
          reinterpret_cast<quintptr>(Window.Handle), 0, 16);
      QStringList States{Window.Visible ? "Visible" : "Hidden",
                         Window.Enabled ? "Enabled" : "Disabled"};
      if (Window.Minimized)
        States.append("Minimized");
      if (Window.Maximized)
        States.append("Maximized");
      if (Window.IsHung)
        States.append("HUNG");
      if (Window.IsTopmost)
        States.append("Topmost");
      QStringList Properties;
      if (Window.IsTopmost)
        Properties.append("Topmost");
      if (Window.IsLayered)
        Properties.append("Layered");
      if (Window.IsToolWindow)
        Properties.append("ToolWindow");
      if (Window.IsAppWindow)
        Properties.append("AppWindow");
      if (Window.IsPopup)
        Properties.append("Popup");
      if (Window.IsChild)
        Properties.append("Child");
      if (Window.IsUnicode)
        Properties.append("Unicode");
      Properties.append(QString("Alpha=%1").arg(Window.Alpha));
      if (Window.ParentHwnd)
        Properties.append(QString("Parent=0x%1")
                              .arg(reinterpret_cast<quintptr>(Window.ParentHwnd),
                                   0, 16));
      if (Window.OwnerHwnd)
        Properties.append(QString("Owner=0x%1")
                              .arg(reinterpret_cast<quintptr>(Window.OwnerHwnd),
                                   0, 16));
      auto *Item = new QTreeWidgetItem(QStringList{
          HandleText,
          Window.ZIndex >= 0 ? QString::number(Window.ZIndex) : QString("-"),
          FormatBand(Window.Band),
          Window.Title.isEmpty() ? "(untitled)" : Window.Title,
          Window.ClassName,
          Window.ProcessPath,
          QString::number(Window.Pid),
          QString("0x%1 | Ex:0x%2")
              .arg(Window.Style, 8, 16, QChar('0'))
              .arg(Window.ExStyle, 8, 16, QChar('0')),
          States.join(" | "),
          FormatKernelFlags(Window.KernelFlags),
          Properties.join(" | "),
          QString("(%1,%2)-(%3,%4) %5x%6")
              .arg(Window.Rect.left)
              .arg(Window.Rect.top)
              .arg(Window.Rect.right)
              .arg(Window.Rect.bottom)
              .arg(Window.Rect.right - Window.Rect.left)
              .arg(Window.Rect.bottom - Window.Rect.top),
          QString::number(Window.Dpi)});
      Item->setData(0, Qt::UserRole,
                    QVariant::fromValue<qulonglong>(
                        reinterpret_cast<quintptr>(Window.Handle)));
      Item->setSizeHint(0, QSize(0, KCompactTableRowHeight));
      return Item;
    };

    std::map<DWORD, std::vector<const WindowRow *>> ByProcess;
    for (const WindowRow *Window : VisibleRows)
      ByProcess[Window->Pid].push_back(Window);

    const auto ProcessName = [](const WindowRow &Window) -> QString {
      if (!Window.ProcessPath.isEmpty()) {
        const QString Name =
            QFileInfo(Window.ProcessPath).fileName();
        if (!Name.isEmpty())
          return Name;
      }
      return QString("PID %1").arg(Window.Pid);
    };

    for (const auto &[Pid, Group] : ByProcess) {
      Q_UNUSED(Pid);
      auto *ProcessItem = new QTreeWidgetItem(WindowTree);
      ProcessItem->setText(3, QString("%1  (PID %2)")
                                  .arg(ProcessName(*Group.front()))
                                  .arg(Group.front()->Pid));
      ProcessItem->setText(6, QString::number(Group.front()->Pid));
      ProcessItem->setText(5, Group.front()->ProcessPath);
      ProcessItem->setExpanded(true);
      ProcessItem->setSizeHint(0, QSize(0, KCompactTableRowHeight + 2));
      const QColor AccentColor = ConfiguredColor("AccentColor", KAccent);
      ProcessItem->setIcon(
          3, Fluent::coloredIcon(Fluent::IconType::APPLICATION, AccentColor,
                                 AccentColor));
      QFont ProcessFont = ProcessItem->font(3);
      ProcessFont.setBold(true);
      ProcessItem->setFont(3, ProcessFont);
      ProcessItem->setForeground(3, QBrush(AccentColor));

      std::map<HWND, QTreeWidgetItem *> ItemByHandle;
      for (const WindowRow *Window : Group)
        ItemByHandle.emplace(Window->Handle, MakeWindowItem(*Window));

      for (const WindowRow *Window : Group) {
        QTreeWidgetItem *Item = ItemByHandle[Window->Handle];
        QTreeWidgetItem *ParentItem = nullptr;
        if (Window->IsChild && Window->ParentHwnd &&
            Window->ParentHwnd != Window->Handle) {
          const auto ParentIt = ItemByHandle.find(Window->ParentHwnd);
          if (ParentIt != ItemByHandle.end())
            ParentItem = ParentIt->second;
        }
        if (!ParentItem && Window->OwnerHwnd &&
            Window->OwnerHwnd != Window->Handle) {
          const auto OwnerIt = ItemByHandle.find(Window->OwnerHwnd);
          if (OwnerIt != ItemByHandle.end())
            ParentItem = OwnerIt->second;
        }
        if (ParentItem && ParentItem != Item)
          ParentItem->addChild(Item);
        else
          ProcessItem->addChild(Item);
      }
    }

    WindowTree->setUpdatesEnabled(true);
  }

  void ShowMenu(const QPoint &Position) {
    QTreeWidgetItem *Clicked = WindowTree->itemAt(Position);
    if (!Clicked)
      return;
    WindowTree->setCurrentItem(Clicked);
    const HWND Handle = reinterpret_cast<HWND>(
        static_cast<quintptr>(Clicked->data(0, Qt::UserRole).toULongLong()));
    if (!Handle || !IsWindow(Handle))
      return;
    DWORD TargetPid = 0;
    GetWindowThreadProcessId(Handle, &TargetPid);
    const bool IsProtected =
        IsTrackedProtectedWindow((ULONG64)(ULONG_PTR)Handle);
    auto *Menu = new RoundMenu(QString(), this);
    const auto AddAction = [this, Menu, Handle, TargetPid, IsProtected](
                               const QString &Text,
                               const std::function<bool(HWND)> &Action,
                               const std::function<BOOL()> &KernelAction = {}) {
      auto *Item = new QAction(Text, Menu);
      Menu->addAction(Item);
      ConnectMenuAction(Item, this,
                        [this, Handle, TargetPid, Text, Action, KernelAction] {
        if (IsTrackedProtectedWindow((ULONG64)(ULONG_PTR)Handle)) {
          ShowWarningNotice(this, "Window",
                            "This window is protected. Unprotect it first.");
          return;
        }
        BOOL Result = FALSE;
        if (KernelModeCheck->isChecked() && KernelAction) {
          if (G_DeviceHandle == INVALID_HANDLE_VALUE)
            OpenDeviceSilent();
          if (G_DeviceHandle != INVALID_HANDLE_VALUE)
            Result = KernelAction();
        } else {
          Result = Action(Handle) ? TRUE : FALSE;
        }
        if (Result)
          ShowSuccessNotice(this, "Window", Text + " completed.");
        else
          ShowErrorNotice(this, "Window", Text + " failed.");
        QTimer::singleShot(150, this, [this] { Refresh(); });
      });
      if (IsProtected && Text != "Ping")
        Item->setEnabled(false);
    };
    AddAction("Show / Activate", [](HWND H) {
      ShowWindow(H, SW_SHOW);
      return SetForegroundWindow(H) != FALSE;
    }, [TargetPid, Handle] { return WindowShow(TargetPid, (ULONG64)(ULONG_PTR)Handle); });
    AddAction("Hide", [](HWND H) {
      ShowWindow(H, SW_HIDE);
      return IsWindow(H) != FALSE;
    }, [TargetPid, Handle] { return WindowHide(TargetPid, (ULONG64)(ULONG_PTR)Handle); });
    AddAction("Minimize", [](HWND H) {
      ShowWindow(H, SW_MINIMIZE);
      return IsWindow(H) != FALSE;
    }, [TargetPid, Handle] { return WindowMinimize(TargetPid, (ULONG64)(ULONG_PTR)Handle); });
    AddAction("Maximize", [](HWND H) {
      ShowWindow(H, SW_MAXIMIZE);
      return IsWindow(H) != FALSE;
    }, [TargetPid, Handle] { return WindowMaximize(TargetPid, (ULONG64)(ULONG_PTR)Handle); });
    AddAction("Restore", [](HWND H) {
      ShowWindow(H, SW_RESTORE);
      SetForegroundWindow(H);
      return IsWindow(H) != FALSE;
    }, [TargetPid, Handle] { return WindowRestore(TargetPid, (ULONG64)(ULONG_PTR)Handle); });
    Menu->addSeparator();
    AddAction("Enable", [](HWND H) {
      return EnableWindow(H, TRUE) != FALSE || GetLastError() == ERROR_SUCCESS;
    }, [TargetPid, Handle] { return WindowEnable(TargetPid, (ULONG64)(ULONG_PTR)Handle); });
    AddAction("Disable", [](HWND H) {
      return EnableWindow(H, FALSE) != FALSE ||
             GetLastError() == ERROR_SUCCESS;
    }, [TargetPid, Handle] { return WindowDisable(TargetPid, (ULONG64)(ULONG_PTR)Handle); });
    AddAction("Topmost", [](HWND H) {
      return SetWindowPos(H, HWND_TOPMOST, 0, 0, 0, 0,
                          SWP_NOMOVE | SWP_NOSIZE) != FALSE;
    }, [TargetPid, Handle] { return WindowSetTopmost(TargetPid, (ULONG64)(ULONG_PTR)Handle); });
    AddAction("Remove topmost", [](HWND H) {
      return SetWindowPos(H, HWND_NOTOPMOST, 0, 0, 0, 0,
                          SWP_NOMOVE | SWP_NOSIZE) != FALSE;
    }, [TargetPid, Handle] { return WindowRemoveTopmost(TargetPid, (ULONG64)(ULONG_PTR)Handle); });
    AddAction(
        "Set Title...",
        [this](HWND H) {
          bool Ok = false;
          const QString NewTitle = FluentInputDialog::getText(
              WindowTree, "Set Window Title", "New title:",
              QLineEdit::Normal, QString(), &Ok);
          if (!Ok || NewTitle.isEmpty())
            return true;
          const std::wstring WideTitle(
              reinterpret_cast<const wchar_t *>(NewTitle.utf16()));
          return SetWindowTextW(H, WideTitle.c_str()) != FALSE;
        },
        [this, TargetPid, Handle] {
          bool Ok = false;
          const QString NewTitle = FluentInputDialog::getText(
              WindowTree, "Set Window Title", "New title:",
              QLineEdit::Normal, QString(), &Ok);
          if (!Ok || NewTitle.isEmpty())
            return TRUE;
          const std::wstring WideTitle(
              reinterpret_cast<const wchar_t *>(NewTitle.utf16()));
          return WindowSetTitle(TargetPid, (ULONG64)(ULONG_PTR)Handle,
                                WideTitle.c_str());
        });
    AddAction("Ping", [this](HWND H) {
      DWORD_PTR Result = 0;
      return SendMessageTimeoutW(H, WM_NULL, 0, 0, SMTO_ABORTIFHUNG, 1000,
                                 &Result) != 0;
    }, [TargetPid, Handle] {
      return WindowPing(TargetPid, (ULONG64)(ULONG_PTR)Handle);
    });
    Menu->addSeparator();
    AddAction("Post WM_CLOSE", [](HWND H) {
      return PostMessageW(H, WM_CLOSE, 0, 0) != FALSE;
    }, [TargetPid, Handle] { return WindowKill(TargetPid, (ULONG64)(ULONG_PTR)Handle); });
    AddAction("Send SC_CLOSE", [](HWND H) {
      DWORD_PTR Result = 0;
      return SendMessageTimeoutW(H, WM_SYSCOMMAND, SC_CLOSE, 0,
                                 SMTO_ABORTIFHUNG, 1000, &Result) != 0;
    }, [TargetPid, Handle] { return WindowKill(TargetPid, (ULONG64)(ULONG_PTR)Handle); });

    if (KernelModeCheck->isChecked()) {
      Menu->addSeparator();
      auto *KernelMenu = new RoundMenu("Kernel Operations", Menu);

      auto AddKernelAction = [this, Menu, KernelMenu, Handle, TargetPid](
                                 const QString &Text,
                                 const std::function<BOOL()> &KernelOp,
                                 const std::function<BOOL(HWND)> &UserOp) {
        auto *Item = new QAction(Text, KernelMenu);
        KernelMenu->addAction(Item);
        ConnectMenuAction(Item, this, [this, Text, KernelOp, UserOp] {
          Q_UNUSED(UserOp);
          BOOL Result = FALSE;
          if (G_DeviceHandle == INVALID_HANDLE_VALUE)
            OpenDeviceSilent();
          if (G_DeviceHandle != INVALID_HANDLE_VALUE)
            Result = KernelOp();
          if (Result)
            ShowSuccessNotice(this, "Window", Text + " completed.");
          else
            ShowErrorNotice(this, "Window", Text + " failed.");
          QTimer::singleShot(150, this, [this] { Refresh(); });
        });
      };

      AddKernelAction(
          "Kill Window (Kernel)",
          [TargetPid, Handle]() -> BOOL {
            return WindowKill(TargetPid, (ULONG64)(ULONG_PTR)Handle);
          },
          [](HWND H) -> BOOL { return PostMessageW(H, WM_CLOSE, 0, 0); });

      AddKernelAction(
          "Force Hide",
          [TargetPid, Handle]() -> BOOL {
            return WindowHide(TargetPid, (ULONG64)(ULONG_PTR)Handle);
          },
          [](HWND H) -> BOOL {
            return ShowWindow(H, SW_HIDE) != FALSE || TRUE;
          });

      AddKernelAction(
          "Force Show",
          [TargetPid, Handle]() -> BOOL {
            return WindowShow(TargetPid, (ULONG64)(ULONG_PTR)Handle);
          },
          [](HWND H) -> BOOL {
            return ShowWindow(H, SW_SHOW) != FALSE || TRUE;
          });

      AddKernelAction(
          "Force Disable",
          [TargetPid, Handle]() -> BOOL {
            return WindowDisable(TargetPid, (ULONG64)(ULONG_PTR)Handle);
          },
          [](HWND H) -> BOOL { return EnableWindow(H, FALSE); });

      AddKernelAction(
          "Force Enable",
          [TargetPid, Handle]() -> BOOL {
            return WindowEnable(TargetPid, (ULONG64)(ULONG_PTR)Handle);
          },
          [](HWND H) -> BOOL { return EnableWindow(H, TRUE); });

      AddKernelAction(
          "Force Topmost",
          [TargetPid, Handle]() -> BOOL {
            return WindowSetTopmost(TargetPid, (ULONG64)(ULONG_PTR)Handle);
          },
          [](HWND H) -> BOOL {
            return SetWindowPos(H, HWND_TOPMOST, 0, 0, 0, 0,
                                SWP_NOMOVE | SWP_NOSIZE);
          });

      AddKernelAction(
          "Force Remove Topmost",
          [TargetPid, Handle]() -> BOOL {
            return WindowRemoveTopmost(TargetPid, (ULONG64)(ULONG_PTR)Handle);
          },
          [](HWND H) -> BOOL {
            return SetWindowPos(H, HWND_NOTOPMOST, 0, 0, 0, 0,
                                SWP_NOMOVE | SWP_NOSIZE);
          });

      KernelMenu->addSeparator();
      AddKernelAction(
          "Kill (Direct)",
          [TargetPid, Handle]() -> BOOL {
            return WindowKill(TargetPid, (ULONG64)(ULONG_PTR)Handle,
                              WINDOW_FLAG_DIRECT);
          },
          [](HWND H) -> BOOL { return PostMessageW(H, WM_CLOSE, 0, 0); });
      AddKernelAction(
          "Hide (Direct)",
          [TargetPid, Handle]() -> BOOL {
            return WindowHide(TargetPid, (ULONG64)(ULONG_PTR)Handle,
                              WINDOW_FLAG_DIRECT);
          },
          [](HWND H) -> BOOL {
            return ShowWindow(H, SW_HIDE) != FALSE || TRUE;
          });
      Menu->addMenu(KernelMenu);
    }

    if (TargetPid != 0) {
      Menu->addSeparator();
      auto *ProtectAction = new QAction("Protect Window", Menu);
      Menu->addAction(ProtectAction);
      ConnectMenuAction(ProtectAction, this, [this, Handle, TargetPid] {
        QString Title = ReadWindowText(Handle);
        ProtectWindowEntry(TargetPid, (ULONG64)(ULONG_PTR)Handle,
                           Title.isEmpty() ? "(untitled)" : Title);
      });
    }

    ReleaseMenuAfterClose(Menu);
    Menu->exec(WindowTree->viewport()->mapToGlobal(Position));
  }

  SearchLineEdit *SearchEdit = nullptr;
  CheckBox *KernelModeCheck = nullptr;
  QTimer *SearchDebounceTimer = nullptr;
  IndeterminateProgressRing *RefreshIndicator = nullptr;
  PushButton *RefreshButton = nullptr;
  QTreeWidget *WindowTree = nullptr;
  TableWidget *ProtectedTable = nullptr;
  PushButton *UnprotectButton = nullptr;
  std::vector<WindowRow> Rows;

  struct ProtectedWin {
    ULONG64 Hwnd;
    ULONG Pid;
    QString Title;
    ULONG Flags;
  };
  std::vector<ProtectedWin> ProtectedWindows;
  std::atomic_bool Refreshing = false;

  bool IsTrackedProtectedWindow(ULONG64 Hwnd) const {
    return std::any_of(
        ProtectedWindows.begin(), ProtectedWindows.end(),
        [Hwnd](const ProtectedWin &Entry) { return Entry.Hwnd == Hwnd; });
  }

  void ProtectWindowEntry(ULONG Pid, ULONG64 Hwnd, const QString &Title) {
    if (IsTrackedProtectedWindow(Hwnd)) {
      ShowWarningNotice(this, "Window", "This window is already protected.");
      return;
    }
    if (G_DeviceHandle == INVALID_HANDLE_VALUE && !OpenDeviceSilent()) {
      const DWORD ErrorCode = GetLastError();
      G_LastAegisCoreError = ErrorCode;
      ShowErrorNotice(this, "Window",
                      "Kernel driver is not available.\n" +
                          DescribeWin32ErrorMessage(ErrorCode));
      return;
    }
    if (!ProtectWindowKernel(Pid, Hwnd, WINPROT_ALL)) {
      ShowErrorNotice(this, "Window",
                      QString("Protect failed.\n%1")
                          .arg(DescribeWin32ErrorMessage(G_LastAegisCoreError)));
      return;
    }
    ProtectedWindows.push_back({Hwnd, Pid, Title, WINPROT_ALL});
    RefreshProtectedTable();
    ShowSuccessNotice(this, "Window", "Window protected.");
  }

  void UnprotectSelected() {
    std::vector<ProtectedWin> ToRemove;
    QStringList Failures;
    for (const QModelIndex &Idx :
         ProtectedTable->selectionModel()->selectedRows(0)) {
      ULONG64 Hwnd = Idx.data(Qt::UserRole).toULongLong();
      ULONG Pid = Idx.data(Qt::UserRole + 1).toUInt();
      for (const auto &P : ProtectedWindows)
        if (P.Hwnd == Hwnd) {
          ToRemove.push_back(P);
          break;
        }
      if ((G_DeviceHandle == INVALID_HANDLE_VALUE && !OpenDeviceSilent()) ||
          !UnprotectWindowKernel(Pid, Hwnd))
        Failures.append(QString("0x%1 (error %2)")
                            .arg(Hwnd, 0, 16)
                            .arg(G_LastAegisCoreError));
    }
    for (const auto &P : ToRemove) {
      if (Failures.contains(QString("0x%1").arg(P.Hwnd, 0, 16),
                            Qt::CaseInsensitive))
        continue;
      auto It = std::find_if(
          ProtectedWindows.begin(), ProtectedWindows.end(),
          [&P](const ProtectedWin &W) { return W.Hwnd == P.Hwnd; });
      if (It != ProtectedWindows.end())
        ProtectedWindows.erase(It);
    }
    RefreshProtectedTable();
    if (Failures.isEmpty())
      ShowSuccessNotice(this, "Window", "Selected window protection removed.");
    else
      ShowErrorNotice(this, "Window",
                      "Failed to unprotect:\n" + Failures.join('\n'));
  }

  void RefreshProtectedTable() {
    SetTableRefreshEnabled(ProtectedTable, false);
    ProtectedTable->clearContents();
    ProtectedTable->setRowCount(static_cast<int>(ProtectedWindows.size()));
    for (int R = 0; R < static_cast<int>(ProtectedWindows.size()); ++R) {
      const auto &P = ProtectedWindows[R];
      auto *HwndItem = new QTableWidgetItem(QString("0x%1").arg(P.Hwnd, 0, 16));
      HwndItem->setData(Qt::UserRole, QVariant::fromValue<qulonglong>(P.Hwnd));
      HwndItem->setData(Qt::UserRole + 1, QVariant::fromValue<quint32>(P.Pid));
      ProtectedTable->setItem(R, 0, HwndItem);
      ProtectedTable->setItem(R, 1, new QTableWidgetItem(P.Title));
      ProtectedTable->setItem(R, 2,
                              new QTableWidgetItem(QString::number(P.Pid)));
      ProtectedTable->setItem(R, 3,
                              new QTableWidgetItem(QString("0x%1").arg(
                                  P.Flags, 8, 16, QLatin1Char('0'))));
      ProtectedTable->setRowHeight(R, KCompactTableRowHeight);
    }
    SetTableRefreshEnabled(ProtectedTable, true);
    UnprotectButton->setEnabled(false);
  }
};
