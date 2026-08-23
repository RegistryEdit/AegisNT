class RegistryManagerPage final : public QWidget {
  struct RegistryLocation {
    HKEY Root = nullptr;
    QString RootName;
    QString SubKey;
  };

  struct RegistryValueRow {
    QString RootName;
    QString KeyPath;
    QString Location;
    QString Name;
    QString Data;
    DWORD Type = REG_NONE;
  };

  struct ProtectedRegistryEntry {
    QString DisplayPath;
    QString KernelPath;
  };

public:
  explicit RegistryManagerPage(QWidget *Parent = nullptr) : QWidget(Parent) {
    auto *Layout = new QVBoxLayout(this);
    ConfigurePageLayout(Layout, 8);

    auto *Tabs = new TabBar;
    Tabs->setAddButtonVisible(false);
    Tabs->setTabsClosable(false);
    Tabs->setMovable(false);
    Tabs->addTab("registry", "Browser", Fluent::IconType::DOCUMENT);
    Tabs->addTab("protected", "Protected", Fluent::IconType::CERTIFICATE);
    Layout->addWidget(Tabs);

    auto *Pages = new QStackedWidget;
    Pages->addWidget(CreateRegistryBrowser());
    Pages->addWidget(CreateProtectedPage());
    Layout->addWidget(Pages, 1);
    QObject::connect(Tabs, &TabBar::currentChanged, Pages,
                     &QStackedWidget::setCurrentIndex);
    RefreshValues();
  }

private:
  QWidget *CreateRegistryBrowser() {
    auto *Page = new QWidget;
    auto *Layout = new QVBoxLayout(Page);
    ConfigurePageLayout(Layout, 8);

    auto *ScopeLayout = new QHBoxLayout;
    ConfigureToolbarLayout(ScopeLayout);
    SourceCombo = new ComboBox;
    SourceCombo->addItems({"Startup items", "Image hijacks", "Selected path"});
    SourceCombo->setCurrentIndex(0);
    SourceCombo->setMinimumWidth(170);
    PathCombo = new ComboBox;
    PathCombo->setMinimumWidth(260);
    const auto AddPathOption = [this](const QString &Label,
                                      const QString &Path) {
      PathCombo->addItem(Label, Path);
    };
    AddPathOption("Current user | Run",
                  "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    AddPathOption(
        "Current user | RunOnce",
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
    AddPathOption(
        "Current user | RunServices",
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices");
    AddPathOption("Current user | Explorer policy",
                  "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies"
                  "\\Explorer\\Run");
    PathCombo->insertSeparator(PathCombo->count());
    AddPathOption("All users | Run",
                  "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
    AddPathOption(
        "All users | RunOnce",
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
    AddPathOption(
        "All users | RunServices",
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices");
    AddPathOption("All users | Explorer policy",
                  "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies"
                  "\\Explorer\\Run");
    PathCombo->insertSeparator(PathCombo->count());
    AddPathOption(
        "Default user | Run",
        "HKU\\.DEFAULT\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    AddPathOption(
        "Winlogon",
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon");
    PathCombo->setCurrentIndex(0);
    ValueCountLabel = new BodyLabel("0 values");
    ValueCountLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    ScopeLayout->addWidget(SourceCombo);
    ScopeLayout->addWidget(PathCombo, 1);
    ScopeLayout->addWidget(ValueCountLabel);
    Layout->addLayout(ScopeLayout);

    auto *AddressLayout = new QHBoxLayout;
    ConfigureToolbarLayout(AddressLayout);
    AddressEdit = new LineEdit;
    ConfigureLineEdit(AddressEdit,
                      "HKLM\\Software\\... or \\Registry\\Machine\\...");
    auto *BrowseButton = new PushButton("Browse", Fluent::IconType::FOLDER);
    auto *RefreshButton = new ToolButton(Fluent::IconType::SYNC);
    RefreshButton->setFixedSize(36, 36);
    RefreshButton->setToolTip("Refresh");
    auto *ProtectButton =
        new PushButton("Protect", Fluent::IconType::CERTIFICATE);
    AddressLayout->addWidget(AddressEdit, 1);
    AddressLayout->addWidget(BrowseButton);
    AddressLayout->addWidget(RefreshButton);
    AddressLayout->addWidget(ProtectButton);
    Layout->addLayout(AddressLayout);

    auto *ActionLayout = new QHBoxLayout;
    ConfigureToolbarLayout(ActionLayout);
    SearchEdit = new SearchLineEdit;
    ConfigureSearchLineEdit(SearchEdit, "Search key, value name, type, or data",
                            KStandardSearchWidth);
    auto *NewKeyButton =
        new PushButton("New key", Fluent::IconType::FOLDER_ADD);
    auto *NewValueButton =
        new PushButton("New value", Fluent::IconType::DOCUMENT);
    ModifyButton = new PushButton("Modify", Fluent::IconType::CODE);
    DeleteButton = MakeButton("Delete");
    ModifyButton->setEnabled(false);
    DeleteButton->setEnabled(false);
    ActionLayout->addWidget(SearchEdit, 1);
    ActionLayout->addWidget(NewKeyButton);
    ActionLayout->addWidget(NewValueButton);
    ActionLayout->addWidget(ModifyButton);
    ActionLayout->addWidget(DeleteButton);
    Layout->addLayout(ActionLayout);

    ValueTable =
        MakeTable({"Location", "Registry path", "Value name", "Type", "Data"});
    ValueTable->setSelectionMode(QAbstractItemView::SingleSelection);
    ValueTable->setProperty("UseGenericDetailDialog", false);
    ValueTable->setSortingEnabled(true);
    ValueTable->horizontalHeader()->setSectionResizeMode(
        0, QHeaderView::ResizeToContents);
    ValueTable->horizontalHeader()->setSectionResizeMode(1,
                                                         QHeaderView::Stretch);
    ValueTable->horizontalHeader()->setSectionResizeMode(
        2, QHeaderView::ResizeToContents);
    ValueTable->horizontalHeader()->setSectionResizeMode(
        3, QHeaderView::ResizeToContents);
    ValueTable->horizontalHeader()->setSectionResizeMode(4,
                                                         QHeaderView::Stretch);
    Layout->addWidget(ValueTable, 1);

    QObject::connect(
        SourceCombo, &ComboBox::currentIndexChanged, this, [this](int Index) {
          PathCombo->setEnabled(Index == 0);
          if (Index < 2) {
            if (Index == 0) {
              const QSignalBlocker PathBlocker(PathCombo);
              PathCombo->setCurrentIndex(0);
            }
            AddressEdit->setText(
                Index == 0
                    ? "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
                    : "HKLM\\SOFTWARE\\Microsoft\\Windows "
                      "NT\\CurrentVersion\\Image File Execution Options");
          }
          RefreshValues();
        });
    QObject::connect(
        PathCombo, &ComboBox::currentIndexChanged, this, [this](int Index) {
          const QString Path = PathCombo->itemData(Index).toString();
          if (Path.isEmpty())
            return;
          AddressEdit->setText(Path);
          const QSignalBlocker Blocker(SourceCombo);
          SourceCombo->setCurrentIndex(0);
          RefreshValues();
        });
    QObject::connect(BrowseButton, &QPushButton::clicked, this,
                     [this] { ShowRegistryPathDialog(); });
    QObject::connect(AddressEdit, &QLineEdit::returnPressed, this, [this] {
      const QSignalBlocker Blocker(SourceCombo);
      SourceCombo->setCurrentIndex(2);
      RefreshValues();
    });
    QObject::connect(RefreshButton, &QPushButton::clicked, this, [this] {
      RefreshValues();
      ShowSuccessNotice(this, "Registry", "Registry values refreshed.");
    });
    QObject::connect(ProtectButton, &QPushButton::clicked, this,
                     [this] { ProtectAddress(); });
    SearchDebounceTimer = new QTimer(this);
    SearchDebounceTimer->setSingleShot(true);
    SearchDebounceTimer->setInterval(KSearchDebounceMs);
    QObject::connect(SearchDebounceTimer, &QTimer::timeout, this,
                     [this] { PopulateValues(); });
    QObject::connect(SearchEdit, &QLineEdit::textChanged, this,
                     [this] { SearchDebounceTimer->start(); });
    QObject::connect(NewKeyButton, &QPushButton::clicked, this,
                     [this] { ShowCreateKeyDialog(); });
    QObject::connect(NewValueButton, &QPushButton::clicked, this,
                     [this] { ShowValueDialog(false); });
    QObject::connect(ModifyButton, &QPushButton::clicked, this,
                     [this] { ShowValueDialog(true); });
    QObject::connect(DeleteButton, &QPushButton::clicked, this,
                     [this] { DeleteSelectedValue(); });
    QObject::connect(
        ValueTable, &QTableWidget::itemSelectionChanged, this, [this] {
          const bool Selected = SelectedValue() != nullptr;
          ModifyButton->setEnabled(Selected);
          DeleteButton->setEnabled(Selected);
          if (const RegistryValueRow *Row = SelectedValue())
            AddressEdit->setText(Row->RootName + "\\" + Row->KeyPath);
        });
    QObject::connect(ValueTable, &QTableWidget::cellDoubleClicked, this,
                     [this](int, int) { ShowValueDialog(true); });
    AddressEdit->setText(
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    return Page;
  }

  QWidget *CreateProtectedPage() {
    auto *Page = new QWidget;
    auto *Layout = new QVBoxLayout(Page);
    ConfigurePageLayout(Layout, 8);
    auto *Toolbar = new QHBoxLayout;
    ConfigureToolbarLayout(Toolbar);
    ProtectedSearchEdit = new SearchLineEdit;
    ConfigureSearchLineEdit(ProtectedSearchEdit, "Search protected paths",
                            KStandardSearchWidth);
    ProtectedCountLabel = new BodyLabel("0 paths");
    UnprotectButton =
        new PushButton("Unprotect", Fluent::IconType::CERTIFICATE);
    UnprotectButton->setEnabled(false);
    Toolbar->addWidget(ProtectedSearchEdit, 1);
    Toolbar->addWidget(ProtectedCountLabel);
    Toolbar->addWidget(UnprotectButton);
    Layout->addLayout(Toolbar);
    ProtectedTable = MakeTable({"Registry path", "Kernel path"});
    ProtectedTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
    ProtectedTable->setProperty("DetailDialogTitle", "Registry details");
    ProtectedTable->horizontalHeader()->setSectionResizeMode(
        0, QHeaderView::ResizeToContents);
    ProtectedTable->horizontalHeader()->setSectionResizeMode(
        1, QHeaderView::Stretch);
    Layout->addWidget(ProtectedTable, 1);
    QObject::connect(
        ProtectedTable, &QTableWidget::itemSelectionChanged, this, [this] {
          UnprotectButton->setEnabled(
              !ProtectedTable->selectionModel()->selectedRows(0).isEmpty());
        });
    ProtectedSearchDebounceTimer = new QTimer(this);
    ProtectedSearchDebounceTimer->setSingleShot(true);
    ProtectedSearchDebounceTimer->setInterval(KSearchDebounceMs);
    QObject::connect(ProtectedSearchDebounceTimer, &QTimer::timeout, this,
                     [this] { RefreshProtectedTable(); });
    QObject::connect(ProtectedSearchEdit, &QLineEdit::textChanged, this,
                     [this] { ProtectedSearchDebounceTimer->start(); });
    QObject::connect(UnprotectButton, &QPushButton::clicked, this,
                     [this] { UnprotectSelection(); });
    return Page;
  }

  bool ParseLocation(const QString &Text, RegistryLocation &Location) const {
    QString Path =
        QDir::fromNativeSeparators(Text.trimmed()).replace('/', '\\');
    while (Path.startsWith('\\'))
      Path.remove(0, 1);
    const std::array<std::tuple<const char *, const char *, HKEY>, 10> Roots{
        {{"HKEY_LOCAL_MACHINE", "HKLM", HKEY_LOCAL_MACHINE},
         {"HKLM", "HKLM", HKEY_LOCAL_MACHINE},
         {"HKEY_CURRENT_USER", "HKCU", HKEY_CURRENT_USER},
         {"HKCU", "HKCU", HKEY_CURRENT_USER},
         {"HKEY_USERS", "HKU", HKEY_USERS},
         {"HKU", "HKU", HKEY_USERS},
         {"HKEY_CLASSES_ROOT", "HKCR", HKEY_CLASSES_ROOT},
         {"HKCR", "HKCR", HKEY_CLASSES_ROOT},
         {"HKEY_CURRENT_CONFIG", "HKCC", HKEY_CURRENT_CONFIG},
         {"HKCC", "HKCC", HKEY_CURRENT_CONFIG}}};
    for (const auto &[LongName, ShortName, Root] : Roots) {
      const QString Prefix = QString::fromLatin1(LongName);
      if (Path.compare(Prefix, Qt::CaseInsensitive) == 0 ||
          Path.startsWith(Prefix + "\\", Qt::CaseInsensitive)) {
        Location.Root = Root;
        Location.RootName = QString::fromLatin1(ShortName);
        Location.SubKey = Path.mid(Prefix.size());
        while (Location.SubKey.startsWith('\\'))
          Location.SubKey.remove(0, 1);
        return true;
      }
    }
    return false;
  }

  static QString TypeName(DWORD Type) {
    switch (Type) {
    case REG_SZ:
      return "REG_SZ";
    case REG_EXPAND_SZ:
      return "REG_EXPAND_SZ";
    case REG_DWORD:
      return "REG_DWORD";
    case REG_QWORD:
      return "REG_QWORD";
    case REG_MULTI_SZ:
      return "REG_MULTI_SZ";
    case REG_BINARY:
      return "REG_BINARY";
    case REG_NONE:
      return "REG_NONE";
    default:
      return QString("REG_%1").arg(Type);
    }
  }

  static QString ValueDataText(DWORD Type, const std::vector<BYTE> &Data) {
    if ((Type == REG_SZ || Type == REG_EXPAND_SZ) &&
        Data.size() >= sizeof(wchar_t)) {
      QString Value = QString::fromWCharArray(
          reinterpret_cast<const wchar_t *>(Data.data()),
          static_cast<qsizetype>(Data.size() / sizeof(wchar_t)));
      while (Value.endsWith(QChar::Null))
        Value.chop(1);
      return Value;
    }
    if (Type == REG_DWORD && Data.size() >= sizeof(DWORD)) {
      DWORD Value = 0;
      std::memcpy(&Value, Data.data(), sizeof(Value));
      return QString("%1 (0x%2)")
          .arg(Value)
          .arg(Value, 8, 16, QLatin1Char('0'))
          .toUpper();
    }
    if (Type == REG_QWORD && Data.size() >= sizeof(ULONGLONG)) {
      ULONGLONG Value = 0;
      std::memcpy(&Value, Data.data(), sizeof(Value));
      return QString("%1 (0x%2)")
          .arg(Value)
          .arg(Value, 16, 16, QLatin1Char('0'))
          .toUpper();
    }
    if (Type == REG_MULTI_SZ && Data.size() >= sizeof(wchar_t)) {
      QStringList Values;
      const wchar_t *Current = reinterpret_cast<const wchar_t *>(Data.data());
      const wchar_t *End = Current + Data.size() / sizeof(wchar_t);
      while (Current < End && *Current) {
        const size_t Length =
            wcsnlen_s(Current, static_cast<size_t>(End - Current));
        Values.append(
            QString::fromWCharArray(Current, static_cast<qsizetype>(Length)));
        Current += Length + 1;
      }
      return Values.join(" | ");
    }
    QStringList Bytes;
    for (BYTE Value : Data)
      Bytes.append(QString("%1").arg(Value, 2, 16, QLatin1Char('0')).toUpper());
    return Bytes.join(' ');
  }

  void ShowRegistryPathDialog() {
    QDialog Dialog(this);
    Dialog.setWindowTitle("Select registry path");
    Dialog.resize(1040, 680);

    auto *Layout = new QVBoxLayout(&Dialog);
    auto *PathLabel = MakeLabel("Computer", 11, KTextMuted);
    PathLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    Layout->addWidget(PathLabel);

    auto *Splitter = new QSplitter;
    Splitter->setChildrenCollapsible(false);
    auto *KeyTree = new QTreeWidget;
    KeyTree->setHeaderLabel("Computer");
    KeyTree->setAnimated(true);
    KeyTree->setMinimumWidth(330);
    InstallFluentScrollBar(KeyTree, Qt::Vertical);
    auto *Values = MakeTable({"Name", "Type", "Data"});
    Values->setSelectionMode(QAbstractItemView::SingleSelection);
    Values->horizontalHeader()->setSectionResizeMode(
        0, QHeaderView::ResizeToContents);
    Values->horizontalHeader()->setSectionResizeMode(
        1, QHeaderView::ResizeToContents);
    Values->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    Splitter->addWidget(KeyTree);
    Splitter->addWidget(Values);
    Splitter->setStretchFactor(0, 0);
    Splitter->setStretchFactor(1, 1);
    Splitter->setSizes({360, 680});
    Layout->addWidget(Splitter, 1);

    auto *Buttons =
        new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    Buttons->button(QDialogButtonBox::Ok)->setText("Select");
    Buttons->button(QDialogButtonBox::Ok)->setEnabled(false);
    Layout->addWidget(Buttons);

    const std::array<HKEY, 5> Roots{HKEY_CLASSES_ROOT, HKEY_CURRENT_USER,
                                    HKEY_LOCAL_MACHINE, HKEY_USERS,
                                    HKEY_CURRENT_CONFIG};
    const std::array<QString, 5> RootNames{"HKCR", "HKCU", "HKLM", "HKU",
                                           "HKCC"};
    constexpr int RootRole = Qt::UserRole;
    constexpr int PathRole = Qt::UserRole + 1;
    constexpr int LoadedRole = Qt::UserRole + 2;
    constexpr int PlaceholderRole = Qt::UserRole + 3;

    const auto AddPlaceholder = [PlaceholderRole](QTreeWidgetItem *Parent) {
      auto *Placeholder =
          new QTreeWidgetItem(Parent, QStringList{"Loading..."});
      Placeholder->setData(0, PlaceholderRole, true);
    };

    std::function<void(QTreeWidgetItem *)> LoadChildren;
    LoadChildren = [&, AddPlaceholder](QTreeWidgetItem *Parent) {
      if (!Parent || Parent->data(0, LoadedRole).toBool())
        return;
      Parent->setData(0, LoadedRole, true);
      while (Parent->childCount() > 0)
        delete Parent->takeChild(0);

      const int RootIndex = Parent->data(0, RootRole).toInt();
      if (RootIndex < 0 || RootIndex >= static_cast<int>(Roots.size()))
        return;
      const QString ParentPath = Parent->data(0, PathRole).toString();
      HKEY Key = nullptr;
      const LSTATUS OpenStatus = RegOpenKeyExW(
          Roots[RootIndex], reinterpret_cast<LPCWSTR>(ParentPath.utf16()), 0,
          KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_WOW64_64KEY, &Key);
      if (OpenStatus != ERROR_SUCCESS)
        return;

      DWORD SubKeyCount = 0;
      DWORD MaximumNameLength = 0;
      RegQueryInfoKeyW(Key, nullptr, nullptr, nullptr, &SubKeyCount,
                       &MaximumNameLength, nullptr, nullptr, nullptr, nullptr,
                       nullptr, nullptr);
      std::vector<wchar_t> Name(static_cast<size_t>(MaximumNameLength) + 2);
      for (DWORD Index = 0; Index < SubKeyCount; ++Index) {
        DWORD NameLength = static_cast<DWORD>(Name.size());
        if (RegEnumKeyExW(Key, Index, Name.data(), &NameLength, nullptr,
                          nullptr, nullptr, nullptr) != ERROR_SUCCESS)
          continue;
        const QString ChildName =
            QString::fromWCharArray(Name.data(), NameLength);
        auto *Child = new QTreeWidgetItem(Parent, QStringList{ChildName});
        Child->setData(0, RootRole, RootIndex);
        Child->setData(0, PathRole,
                       ParentPath.isEmpty() ? ChildName
                                            : ParentPath + "\\" + ChildName);
        Child->setData(0, LoadedRole, false);
        AddPlaceholder(Child);
      }
      RegCloseKey(Key);
    };

    const auto PopulateDialogValues = [&](QTreeWidgetItem *Item) {
      Values->setSortingEnabled(false);
      Values->clearContents();
      Values->setRowCount(0);
      if (!Item || Item->data(0, PlaceholderRole).toBool())
        return;
      const int RootIndex = Item->data(0, RootRole).toInt();
      const QString KeyPath = Item->data(0, PathRole).toString();
      const QString DisplayPath =
          RootNames[RootIndex] +
          (KeyPath.isEmpty() ? QString() : "\\" + KeyPath);
      PathLabel->setText(DisplayPath);
      Buttons->button(QDialogButtonBox::Ok)->setEnabled(true);

      HKEY Key = nullptr;
      if (RegOpenKeyExW(
              Roots[RootIndex], reinterpret_cast<LPCWSTR>(KeyPath.utf16()), 0,
              KEY_QUERY_VALUE | KEY_WOW64_64KEY, &Key) != ERROR_SUCCESS)
        return;
      DWORD ValueCount = 0, MaximumNameLength = 0, MaximumDataLength = 0;
      RegQueryInfoKeyW(Key, nullptr, nullptr, nullptr, nullptr, nullptr,
                       nullptr, &ValueCount, &MaximumNameLength,
                       &MaximumDataLength, nullptr, nullptr);
      std::vector<wchar_t> Name(static_cast<size_t>(MaximumNameLength) + 2);
      std::vector<BYTE> Data(static_cast<size_t>(MaximumDataLength) +
                             sizeof(wchar_t) * 2);
      Values->setRowCount(static_cast<int>(ValueCount));
      int Row = 0;
      for (DWORD Index = 0; Index < ValueCount; ++Index) {
        DWORD NameLength = static_cast<DWORD>(Name.size());
        DWORD DataLength = static_cast<DWORD>(Data.size());
        DWORD Type = REG_NONE;
        if (RegEnumValueW(Key, Index, Name.data(), &NameLength, nullptr, &Type,
                          Data.data(), &DataLength) != ERROR_SUCCESS)
          continue;
        const QString ValueName =
            NameLength ? QString::fromWCharArray(Name.data(), NameLength)
                       : "(Default)";
        const std::vector<BYTE> ValueData(Data.begin(),
                                          Data.begin() + DataLength);
        Values->setItem(Row, 0, new QTableWidgetItem(ValueName));
        Values->setItem(Row, 1, new QTableWidgetItem(TypeName(Type)));
        Values->setItem(Row, 2,
                        new QTableWidgetItem(ValueDataText(Type, ValueData)));
        Values->setRowHeight(Row, 36);
        ++Row;
      }
      Values->setRowCount(Row);
      Values->setSortingEnabled(true);
      RegCloseKey(Key);
    };

    for (int Index = 0; Index < static_cast<int>(Roots.size()); ++Index) {
      auto *RootItem =
          new QTreeWidgetItem(KeyTree, QStringList{RootNames[Index]});
      RootItem->setData(0, RootRole, Index);
      RootItem->setData(0, PathRole, QString());
      RootItem->setData(0, LoadedRole, false);
      AddPlaceholder(RootItem);
    }
    QObject::connect(
        KeyTree, &QTreeWidget::itemExpanded, &Dialog,
        [&LoadChildren](QTreeWidgetItem *Item) { LoadChildren(Item); });
    QObject::connect(
        KeyTree, &QTreeWidget::currentItemChanged, &Dialog,
        [PopulateDialogValues](QTreeWidgetItem *Current, QTreeWidgetItem *) {
          PopulateDialogValues(Current);
        });
    QObject::connect(Buttons, &QDialogButtonBox::accepted, &Dialog,
                     &QDialog::accept);
    QObject::connect(Buttons, &QDialogButtonBox::rejected, &Dialog,
                     &QDialog::reject);

    RegistryLocation InitialLocation;
    int InitialRootIndex = 2;
    QString InitialSubKey;
    if (ParseLocation(AddressEdit->text(), InitialLocation)) {
      InitialSubKey = InitialLocation.SubKey;
      for (int Index = 0; Index < static_cast<int>(Roots.size()); ++Index)
        if (Roots[Index] == InitialLocation.Root)
          InitialRootIndex = Index;
    }
    QTreeWidgetItem *Current = KeyTree->topLevelItem(InitialRootIndex);
    LoadChildren(Current);
    Current->setExpanded(true);
    for (const QString &Part : InitialSubKey.split('\\', Qt::SkipEmptyParts)) {
      QTreeWidgetItem *Match = nullptr;
      for (int Index = 0; Index < Current->childCount(); ++Index)
        if (Current->child(Index)->text(0).compare(Part, Qt::CaseInsensitive) ==
            0)
          Match = Current->child(Index);
      if (!Match)
        break;
      Current = Match;
      LoadChildren(Current);
      Current->setExpanded(true);
    }
    KeyTree->setCurrentItem(Current);
    KeyTree->scrollToItem(Current);

    if (Dialog.exec() != QDialog::Accepted)
      return;
    const QTreeWidgetItem *Selected = KeyTree->currentItem();
    if (!Selected || Selected->data(0, PlaceholderRole).toBool())
      return;
    const int RootIndex = Selected->data(0, RootRole).toInt();
    const QString KeyPath = Selected->data(0, PathRole).toString();
    const QString SelectedPath =
        RootNames[RootIndex] + (KeyPath.isEmpty() ? QString() : "\\" + KeyPath);
    AddressEdit->setText(SelectedPath);
    const int ComboIndex = PathCombo->findData(SelectedPath);
    if (ComboIndex >= 0) {
      const QSignalBlocker SourceBlocker(SourceCombo);
      const QSignalBlocker PathBlocker(PathCombo);
      SourceCombo->setCurrentIndex(0);
      PathCombo->setCurrentIndex(ComboIndex);
    } else {
      const QSignalBlocker SourceBlocker(SourceCombo);
      SourceCombo->setCurrentIndex(2);
    }
    RefreshValues();
  }

  void EnumerateKeyValues(HKEY Root, const QString &RootName,
                          const QString &KeyPath, const QString &Location) {
    HKEY Key = nullptr;
    if (RegOpenKeyExW(Root, reinterpret_cast<LPCWSTR>(KeyPath.utf16()), 0,
                      KEY_READ | KEY_WOW64_64KEY, &Key) != ERROR_SUCCESS)
      return;
    DWORD ValueCount = 0, MaximumNameLength = 0, MaximumDataLength = 0;
    RegQueryInfoKeyW(Key, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                     &ValueCount, &MaximumNameLength, &MaximumDataLength,
                     nullptr, nullptr);
    std::vector<wchar_t> Name(static_cast<size_t>(MaximumNameLength) + 2);
    std::vector<BYTE> Data(static_cast<size_t>(MaximumDataLength) +
                           sizeof(wchar_t) * 2);
    for (DWORD Index = 0; Index < ValueCount; ++Index) {
      DWORD NameLength = static_cast<DWORD>(Name.size());
      DWORD DataLength = static_cast<DWORD>(Data.size());
      DWORD Type = REG_NONE;
      const LSTATUS Status =
          RegEnumValueW(Key, Index, Name.data(), &NameLength, nullptr, &Type,
                        Data.data(), &DataLength);
      if (Status != ERROR_SUCCESS)
        continue;
      std::vector<BYTE> ValueData(Data.begin(), Data.begin() + DataLength);
      Rows.push_back({RootName, KeyPath, Location,
                      QString::fromWCharArray(Name.data(), NameLength),
                      ValueDataText(Type, ValueData), Type});
    }
    RegCloseKey(Key);
  }

  void RefreshValues() {
    Rows.clear();
    if (SourceCombo->currentIndex() == 0) {
      const QString SelectedStartupPath = PathCombo->currentData().toString();
      RegistryLocation SelectedLocation;
      if (!SelectedStartupPath.isEmpty() &&
          ParseLocation(SelectedStartupPath, SelectedLocation)) {
        EnumerateKeyValues(SelectedLocation.Root, SelectedLocation.RootName,
                           SelectedLocation.SubKey, PathCombo->currentText());
      } else {
        const auto Add = [this](HKEY Root, const char *RootName,
                                const char *Path, const char *Location) {
          EnumerateKeyValues(Root, QString::fromLatin1(RootName),
                             QString::fromLatin1(Path),
                             QString::fromLatin1(Location));
        };
        Add(HKEY_CURRENT_USER, "HKCU",
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "Current user / Run");
        Add(HKEY_CURRENT_USER, "HKCU",
            "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "Current user / RunOnce");
        Add(HKEY_CURRENT_USER, "HKCU",
            "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
            "Current user / RunServices");
        Add(HKEY_CURRENT_USER, "HKCU",
            "Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
            "Current user / RunServicesOnce");
        Add(HKEY_LOCAL_MACHINE, "HKLM",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "All users / Run");
        Add(HKEY_LOCAL_MACHINE, "HKLM",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "All users / RunOnce");
        Add(HKEY_LOCAL_MACHINE, "HKLM",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices",
            "All users / RunServices");
        Add(HKEY_LOCAL_MACHINE, "HKLM",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
            "All users / RunServicesOnce");
        Add(HKEY_CURRENT_USER, "HKCU",
            "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\"
            "Run",
            "Current user / Explorer policy");
        Add(HKEY_LOCAL_MACHINE, "HKLM",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\"
            "Run",
            "All users / Explorer policy");
        Add(HKEY_USERS, "HKU",
            ".DEFAULT\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "Default user / Run");
        Add(HKEY_LOCAL_MACHINE, "HKLM",
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            "Winlogon");
      }
    } else if (SourceCombo->currentIndex() == 1) {
      const QString BasePath =
          "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File "
          "Execution Options";
      HKEY BaseKey = nullptr;
      if (RegOpenKeyExW(
              HKEY_LOCAL_MACHINE, reinterpret_cast<LPCWSTR>(BasePath.utf16()),
              0, KEY_READ | KEY_WOW64_64KEY, &BaseKey) == ERROR_SUCCESS) {
        DWORD SubKeyCount = 0, MaximumNameLength = 0;
        RegQueryInfoKeyW(BaseKey, nullptr, nullptr, nullptr, &SubKeyCount,
                         &MaximumNameLength, nullptr, nullptr, nullptr, nullptr,
                         nullptr, nullptr);
        std::vector<wchar_t> Name(static_cast<size_t>(MaximumNameLength) + 2);
        for (DWORD Index = 0; Index < SubKeyCount; ++Index) {
          DWORD NameLength = static_cast<DWORD>(Name.size());
          if (RegEnumKeyExW(BaseKey, Index, Name.data(), &NameLength, nullptr,
                            nullptr, nullptr, nullptr) == ERROR_SUCCESS)
            EnumerateKeyValues(
                HKEY_LOCAL_MACHINE, "HKLM",
                BasePath + "\\" +
                    QString::fromWCharArray(Name.data(), NameLength),
                "Image hijack");
        }
        RegCloseKey(BaseKey);
      }
    } else {
      RegistryLocation Location;
      if (ParseLocation(AddressEdit->text(), Location))
        EnumerateKeyValues(Location.Root, Location.RootName, Location.SubKey,
                           "Selected path");
    }
    std::sort(
        Rows.begin(), Rows.end(),
        [](const RegistryValueRow &Left, const RegistryValueRow &Right) {
          const int LocationCompare =
              Left.Location.compare(Right.Location, Qt::CaseInsensitive);
          if (LocationCompare != 0)
            return LocationCompare < 0;
          const int KeyCompare =
              (Left.RootName + Left.KeyPath)
                  .compare(Right.RootName + Right.KeyPath, Qt::CaseInsensitive);
          return KeyCompare == 0
                     ? Left.Name.compare(Right.Name, Qt::CaseInsensitive) < 0
                     : KeyCompare < 0;
        });
    PopulateValues();
  }

  void PopulateValues() {
    const QString Query = SearchEdit->text().trimmed();
    std::vector<int> VisibleRows;
    VisibleRows.reserve(Rows.size());
    for (int Index = 0; Index < static_cast<int>(Rows.size()); ++Index) {
      const RegistryValueRow &Value = Rows[Index];
      const QString SearchText = Value.RootName + " " + Value.Location + " " +
                                 Value.KeyPath + " " + Value.Name + " " +
                                 TypeName(Value.Type) + " " + Value.Data;
      if (!Query.isEmpty() && !SearchText.contains(Query, Qt::CaseInsensitive))
        continue;
      VisibleRows.push_back(Index);
    }
    SetTableRefreshEnabled(ValueTable, false);
    ValueTable->clearContents();
    ValueTable->setRowCount(static_cast<int>(VisibleRows.size()));
    for (int Row = 0; Row < static_cast<int>(VisibleRows.size()); ++Row) {
      const int Index = VisibleRows[Row];
      const RegistryValueRow &Value = Rows[Index];
      auto *LocationItem = new QTableWidgetItem(Value.Location);
      LocationItem->setData(Qt::UserRole, Index);
      ValueTable->setItem(Row, 0, LocationItem);
      ValueTable->setItem(
          Row, 1, new QTableWidgetItem(Value.RootName + "\\" + Value.KeyPath));
      ValueTable->setItem(Row, 2,
                          new QTableWidgetItem(
                              Value.Name.isEmpty() ? "(Default)" : Value.Name));
      ValueTable->setItem(Row, 3, new QTableWidgetItem(TypeName(Value.Type)));
      ValueTable->setItem(Row, 4, new QTableWidgetItem(Value.Data));
      ValueTable->setRowHeight(Row, KCompactTableRowHeight);
    }
    SetTableRefreshEnabled(ValueTable, true, true);
    ValueCountLabel->setText(
        Query.isEmpty()
            ? QString("%1 value%2")
                  .arg(Rows.size())
                  .arg(Rows.size() == 1 ? "" : "s")
            : QString("%1 of %2").arg(VisibleRows.size()).arg(Rows.size()));
    ModifyButton->setEnabled(false);
    DeleteButton->setEnabled(false);
  }

  const RegistryValueRow *SelectedValue() const {
    const QModelIndexList Selection =
        ValueTable->selectionModel()->selectedRows(0);
    if (Selection.isEmpty())
      return nullptr;
    const int Index = Selection.first().data(Qt::UserRole).toInt();
    return Index >= 0 && Index < static_cast<int>(Rows.size()) ? &Rows[Index]
                                                               : nullptr;
  }

  void ShowCreateKeyDialog() {
    RegistryLocation Location;
    if (!ParseLocation(AddressEdit->text(), Location)) {
      ShowErrorNotice(this, "Registry",
                      "Enter a valid HKLM, HKCU, HKU, HKCR, or HKCC path.");
      return;
    }
    auto *Dialog = new MessageBoxBase(window());
    Dialog->setAttribute(Qt::WA_DeleteOnClose);
    auto *Name = new LineEdit;
    Name->setPlaceholderText("Child key name");
    Dialog->viewLayout()->addWidget(
        MakeLabel("New registry key", 18, KTextPrimary, QFont::DemiBold));
    Dialog->viewLayout()->addWidget(
        MakeLabel(Location.RootName + "\\" + Location.SubKey, 11, KTextMuted));
    Dialog->viewLayout()->addWidget(Name);
    Dialog->yesButton()->setText("Create");
    QObject::connect(
        Dialog->yesButton(), &QPushButton::clicked, Dialog,
        [this, Dialog, Name, Location] {
          const QString ChildName = Name->text().trimmed();
          if (ChildName.isEmpty()) {
            ShowWarningNotice(this, "Registry", "Enter a key name.");
            return;
          }
          const QString Path = Location.SubKey.isEmpty()
                                   ? ChildName
                                   : Location.SubKey + "\\" + ChildName;
          DWORD Status = ERROR_GEN_FAILURE;
          const bool Success =
              CreateRegistryKeyWithFallback(Location, Path, Status);
          Dialog->accept();
          if (Success) {
            AddressEdit->setText(Location.RootName + "\\" + Path);
            RefreshValues();
            ShowSuccessNotice(this, "Registry", "Registry key created.");
          } else
            ShowErrorNotice(
                this, "Registry",
                QString("Unable to create key (error %1).").arg(Status));
        });
    QObject::connect(Dialog->cancelButton(), &QPushButton::clicked, Dialog,
                     &QDialog::reject);
    Dialog->show();
  }

  static int TypeIndex(DWORD Type) {
    switch (Type) {
    case REG_SZ:
      return 0;
    case REG_EXPAND_SZ:
      return 1;
    case REG_DWORD:
      return 2;
    case REG_QWORD:
      return 3;
    case REG_MULTI_SZ:
      return 4;
    case REG_BINARY:
      return 5;
    default:
      return 0;
    }
  }

  static DWORD TypeFromIndex(int Index) {
    static const std::array<DWORD, 6> Types{
        REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_QWORD, REG_MULTI_SZ, REG_BINARY};
    return Index >= 0 && Index < static_cast<int>(Types.size()) ? Types[Index]
                                                                : REG_SZ;
  }

  bool EncodeValueData(DWORD Type, const QString &Text,
                       std::vector<BYTE> &Data) const {
    if (Type == REG_SZ || Type == REG_EXPAND_SZ) {
      const std::wstring Value = Text.toStdWString();
      Data.resize((Value.size() + 1) * sizeof(wchar_t));
      std::memcpy(Data.data(), Value.c_str(), Data.size());
      return true;
    }
    if (Type == REG_DWORD || Type == REG_QWORD) {
      bool Ok = false;
      const qulonglong Value = Text.trimmed().toULongLong(&Ok, 0);
      if (!Ok)
        return false;
      if (Type == REG_DWORD) {
        const DWORD Number = static_cast<DWORD>(Value);
        Data.resize(sizeof(Number));
        std::memcpy(Data.data(), &Number, sizeof(Number));
      } else {
        const ULONGLONG Number = Value;
        Data.resize(sizeof(Number));
        std::memcpy(Data.data(), &Number, sizeof(Number));
      }
      return true;
    }
    if (Type == REG_MULTI_SZ) {
      const QStringList Values = Text.split('\n', Qt::SkipEmptyParts);
      std::vector<wchar_t> Buffer;
      for (const QString &Value : Values) {
        const std::wstring Wide = Value.trimmed().toStdWString();
        Buffer.insert(Buffer.end(), Wide.begin(), Wide.end());
        Buffer.push_back(L'\0');
      }
      Buffer.push_back(L'\0');
      Data.resize(Buffer.size() * sizeof(wchar_t));
      std::memcpy(Data.data(), Buffer.data(), Data.size());
      return true;
    }
    QString Hex = Text;
    Hex.remove(' ');
    Hex.remove(',');
    Hex.remove('-');
    Hex.replace("0x", "", Qt::CaseInsensitive);
    if (Hex.size() % 2 != 0)
      return false;
    Data.clear();
    for (qsizetype Index = 0; Index < Hex.size(); Index += 2) {
      bool Ok = false;
      const int Value = Hex.mid(Index, 2).toInt(&Ok, 16);
      if (!Ok)
        return false;
      Data.push_back(static_cast<BYTE>(Value));
    }
    return true;
  }

  void ShowValueDialog(bool Editing) {
    RegistryLocation Location;
    QString InitialName, InitialData;
    DWORD InitialType = REG_SZ;
    if (Editing) {
      const RegistryValueRow *Selected = SelectedValue();
      if (!Selected)
        return;
      if (!ParseLocation(Selected->RootName + "\\" + Selected->KeyPath,
                         Location))
        return;
      InitialName = Selected->Name;
      InitialData = Selected->Data;
      InitialType = Selected->Type;
      if (InitialType == REG_DWORD || InitialType == REG_QWORD)
        InitialData = InitialData.section(' ', 0, 0);
    } else if (!ParseLocation(AddressEdit->text(), Location)) {
      ShowErrorNotice(this, "Registry",
                      "Enter a valid registry key path first.");
      return;
    }
    auto *Dialog = new MessageBoxBase(window());
    Dialog->setAttribute(Qt::WA_DeleteOnClose);
    auto *Name = new LineEdit;
    Name->setPlaceholderText("Value name (empty for Default)");
    Name->setText(InitialName);
    Name->setEnabled(!Editing);
    auto *Type = new ComboBox;
    Type->addItems({"String (REG_SZ)", "Expandable string", "DWORD", "QWORD",
                    "Multi-string", "Binary"});
    Type->setCurrentIndex(Editing ? TypeIndex(InitialType) : 0);
    auto *Data = new PlainTextEdit;
    Data->setPlaceholderText("Value data");
    Data->setPlainText(InitialData);
    Data->setMinimumHeight(120);
    Dialog->viewLayout()->addWidget(
        MakeLabel(Editing ? "Modify registry value" : "New registry value", 18,
                  KTextPrimary, QFont::DemiBold));
    Dialog->viewLayout()->addWidget(
        MakeLabel(Location.RootName + "\\" + Location.SubKey, 11, KTextMuted));
    Dialog->viewLayout()->addWidget(Name);
    Dialog->viewLayout()->addWidget(Type);
    Dialog->viewLayout()->addWidget(Data);
    Dialog->yesButton()->setText(Editing ? "Save" : "Create");
    QObject::connect(
        Dialog->yesButton(), &QPushButton::clicked, Dialog,
        [this, Dialog, Name, Type, Data, Location] {
          std::vector<BYTE> Buffer;
          const DWORD ValueType = TypeFromIndex(Type->currentIndex());
          if (!EncodeValueData(ValueType, Data->toPlainText(), Buffer)) {
            ShowWarningNotice(this, "Registry",
                              "The value data format is invalid.");
            return;
          }
          DWORD Status = ERROR_GEN_FAILURE;
          const bool Success = SetRegistryValueWithFallback(
              Location, Name->text(), ValueType, Buffer, Status);
          Dialog->accept();
          if (Success) {
            RefreshValues();
            ShowSuccessNotice(this, "Registry", "Registry value saved.");
          } else
            ShowErrorNotice(
                this, "Registry",
                QString("Unable to save value (error %1).").arg(Status));
        });
    QObject::connect(Dialog->cancelButton(), &QPushButton::clicked, Dialog,
                     &QDialog::reject);
    Dialog->show();
  }

  void DeleteSelectedValue() {
    const RegistryValueRow *Selected = SelectedValue();
    if (!Selected)
      return;
    const RegistryValueRow Value = *Selected;
    if (QMessageBox::warning(
            this, "Registry",
            QString("Delete value '%1' from %2\\%3?")
                .arg(Value.Name.isEmpty() ? "(Default)" : Value.Name,
                     Value.RootName, Value.KeyPath),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No) != QMessageBox::Yes)
      return;
    RegistryLocation Location;
    if (!ParseLocation(Value.RootName + "\\" + Value.KeyPath, Location))
      return;
    DWORD Status = ERROR_GEN_FAILURE;
    if (DeleteRegistryValueWithFallback(Location, Value.Name, Status)) {
      RefreshValues();
      ShowSuccessNotice(this, "Registry", "Registry value deleted.");
    } else
      ShowErrorNotice(
          this, "Registry",
          QString("Unable to delete value (error %1).").arg(Status));
  }

  QString CurrentUserSid() const {
    HANDLE Token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token))
      return {};
    DWORD Size = 0;
    GetTokenInformation(Token, TokenUser, nullptr, 0, &Size);
    std::vector<BYTE> Buffer(Size);
    QString Sid;
    if (GetTokenInformation(Token, TokenUser, Buffer.data(), Size, &Size)) {
      LPWSTR Text = nullptr;
      if (ConvertSidToStringSidW(
              reinterpret_cast<TOKEN_USER *>(Buffer.data())->User.Sid, &Text)) {
        Sid = QString::fromWCharArray(Text);
        LocalFree(Text);
      }
    }
    CloseHandle(Token);
    return Sid;
  }

  bool ToKernelRegistryPath(const QString &Input, QString &KernelPath) const {
    QString Path = Input.trimmed().replace('/', '\\');
    if (Path.startsWith("\\Registry\\", Qt::CaseInsensitive)) {
      KernelPath = Path;
      return true;
    }
    RegistryLocation Location;
    if (!ParseLocation(Path, Location))
      return false;
    if (Location.Root == HKEY_LOCAL_MACHINE)
      KernelPath = "\\Registry\\Machine";
    else if (Location.Root == HKEY_CURRENT_USER) {
      const QString Sid = CurrentUserSid();
      if (Sid.isEmpty())
        return false;
      KernelPath = "\\Registry\\User\\" + Sid;
    } else if (Location.Root == HKEY_USERS)
      KernelPath = "\\Registry\\User";
    else if (Location.Root == HKEY_CLASSES_ROOT)
      KernelPath = "\\Registry\\Machine\\Software\\Classes";
    else if (Location.Root == HKEY_CURRENT_CONFIG)
      KernelPath = "\\Registry\\Machine\\System\\CurrentControlSet\\Hardware "
                   "Profiles\\Current";
    else
      return false;
    if (!Location.SubKey.isEmpty())
      KernelPath += "\\" + Location.SubKey;
    return true;
  }

  bool CreateRegistryKeyWithFallback(const RegistryLocation &Location,
                                     const QString &Path, DWORD &Status) {
    QString KernelPath;
    if (ToKernelRegistryPath(Location.RootName + "\\" + Path, KernelPath)) {
      const std::wstring WidePath = KernelPath.toStdWString();
      if (RegCreateKeyKernel(WidePath.c_str())) {
        Status = ERROR_SUCCESS;
        return true;
      }
      Status = G_LastAegisCoreError;
    }
    HKEY Key = nullptr;
    DWORD Disposition = 0;
    const LSTATUS UserStatus = RegCreateKeyExW(
        Location.Root, reinterpret_cast<LPCWSTR>(Path.utf16()), 0, nullptr, 0,
        KEY_READ | KEY_WRITE | KEY_WOW64_64KEY, nullptr, &Key, &Disposition);
    if (Key)
      RegCloseKey(Key);
    Status = UserStatus;
    return UserStatus == ERROR_SUCCESS;
  }

  bool SetRegistryValueWithFallback(const RegistryLocation &Location,
                                    const QString &ValueName, DWORD ValueType,
                                    const std::vector<BYTE> &Buffer,
                                    DWORD &Status) {
    QString KernelPath;
    if (ToKernelRegistryPath(Location.RootName + "\\" + Location.SubKey,
                             KernelPath)) {
      const std::wstring WidePath = KernelPath.toStdWString();
      const std::wstring WideName = ValueName.toStdWString();
      if (RegSetValueKernel(WidePath.c_str(), WideName.c_str(), ValueType,
                            const_cast<BYTE *>(Buffer.data()),
                            static_cast<ULONG>(Buffer.size()))) {
        Status = ERROR_SUCCESS;
        return true;
      }
      Status = G_LastAegisCoreError;
    }
    HKEY Key = nullptr;
    const LSTATUS OpenStatus = RegOpenKeyExW(
        Location.Root, reinterpret_cast<LPCWSTR>(Location.SubKey.utf16()), 0,
        KEY_SET_VALUE | KEY_WOW64_64KEY, &Key);
    if (OpenStatus != ERROR_SUCCESS) {
      Status = OpenStatus;
      return false;
    }
    const LSTATUS UserStatus = RegSetValueExW(
        Key, reinterpret_cast<LPCWSTR>(ValueName.utf16()), 0, ValueType,
        Buffer.data(), static_cast<DWORD>(Buffer.size()));
    RegCloseKey(Key);
    Status = UserStatus;
    return UserStatus == ERROR_SUCCESS;
  }

  bool DeleteRegistryValueWithFallback(const RegistryLocation &Location,
                                       const QString &ValueName,
                                       DWORD &Status) {
    QString KernelPath;
    if (ToKernelRegistryPath(Location.RootName + "\\" + Location.SubKey,
                             KernelPath)) {
      const std::wstring WidePath = KernelPath.toStdWString();
      const std::wstring WideName = ValueName.toStdWString();
      if (RegDeleteValueKernel(WidePath.c_str(), WideName.c_str())) {
        Status = ERROR_SUCCESS;
        return true;
      }
      Status = G_LastAegisCoreError;
    }
    HKEY Key = nullptr;
    const LSTATUS OpenStatus = RegOpenKeyExW(
        Location.Root, reinterpret_cast<LPCWSTR>(Location.SubKey.utf16()), 0,
        KEY_SET_VALUE | KEY_WOW64_64KEY, &Key);
    if (OpenStatus != ERROR_SUCCESS) {
      Status = OpenStatus;
      return false;
    }
    const LSTATUS UserStatus =
        RegDeleteValueW(Key, reinterpret_cast<LPCWSTR>(ValueName.utf16()));
    RegCloseKey(Key);
    Status = UserStatus;
    return UserStatus == ERROR_SUCCESS;
  }

  void ProtectAddress() {
    const QString DisplayPath = AddressEdit->text().trimmed();
    QString KernelPath;
    if (!ToKernelRegistryPath(DisplayPath, KernelPath)) {
      ShowErrorNotice(
          this, "Registry",
          "Unable to convert the registry address to a kernel path.");
      return;
    }
    const std::wstring WidePath = KernelPath.toStdWString();
    ProtectRegistryKey(WidePath.c_str());
    if (G_LastAegisCoreError != ERROR_SUCCESS) {
      ShowErrorNotice(
          this, "Registry",
          QString("Protection failed (error %1).").arg(G_LastAegisCoreError));
      return;
    }
    const auto Match = std::find_if(
        ProtectedEntries.begin(), ProtectedEntries.end(),
        [&KernelPath](const ProtectedRegistryEntry &Entry) {
          return Entry.KernelPath.compare(KernelPath, Qt::CaseInsensitive) == 0;
        });
    if (Match == ProtectedEntries.end())
      ProtectedEntries.append({DisplayPath, KernelPath});
    RefreshProtectedTable();
    ShowSuccessNotice(this, "Registry", "Registry path protected.");
  }

  void RefreshProtectedTable() {
    const QString Query =
        ProtectedSearchEdit ? ProtectedSearchEdit->text().trimmed() : QString();
    std::vector<const ProtectedRegistryEntry *> VisibleRows;
    VisibleRows.reserve(ProtectedEntries.size());
    for (const ProtectedRegistryEntry &Entry : ProtectedEntries) {
      if (!Query.isEmpty() && !(Entry.DisplayPath + " " + Entry.KernelPath)
                                   .contains(Query, Qt::CaseInsensitive))
        continue;
      VisibleRows.push_back(&Entry);
    }
    SetTableRefreshEnabled(ProtectedTable, false);
    ProtectedTable->clearContents();
    ProtectedTable->setRowCount(static_cast<int>(VisibleRows.size()));
    for (int Row = 0; Row < static_cast<int>(VisibleRows.size()); ++Row) {
      const ProtectedRegistryEntry &Entry = *VisibleRows[Row];
      auto *Item = new QTableWidgetItem(Entry.DisplayPath);
      Item->setData(Qt::UserRole, Entry.KernelPath);
      ProtectedTable->setItem(Row, 0, Item);
      ProtectedTable->setItem(Row, 1, new QTableWidgetItem(Entry.KernelPath));
      ProtectedTable->setRowHeight(Row, KCompactTableRowHeight);
    }
    SetTableRefreshEnabled(ProtectedTable, true, true);
    if (ProtectedCountLabel)
      ProtectedCountLabel->setText(
          Query.isEmpty() ? QString("%1 path%2")
                                .arg(ProtectedEntries.size())
                                .arg(ProtectedEntries.size() == 1 ? "" : "s")
                          : QString("%1 of %2")
                                .arg(VisibleRows.size())
                                .arg(ProtectedEntries.size()));
    UnprotectButton->setEnabled(false);
  }

  void UnprotectSelection() {
    QList<QString> KernelPaths;
    for (const QModelIndex &Index :
         ProtectedTable->selectionModel()->selectedRows(0))
      KernelPaths.append(Index.data(Qt::UserRole).toString());
    if (KernelPaths.isEmpty())
      return;
    QStringList Failures;
    for (const QString &KernelPath : KernelPaths) {
      const std::wstring WidePath = KernelPath.toStdWString();
      UnprotectRegistryKey(WidePath.c_str());
      if (G_LastAegisCoreError != ERROR_SUCCESS)
        Failures.append(KernelPath);
      else {
        const auto Match =
            std::find_if(ProtectedEntries.begin(), ProtectedEntries.end(),
                         [&KernelPath](const ProtectedRegistryEntry &Entry) {
                           return Entry.KernelPath.compare(
                                      KernelPath, Qt::CaseInsensitive) == 0;
                         });
        if (Match != ProtectedEntries.end())
          ProtectedEntries.erase(Match);
      }
    }
    RefreshProtectedTable();
    if (Failures.isEmpty())
      ShowSuccessNotice(
          this, "Registry",
          QString("Unprotected %1 registry path(s).").arg(KernelPaths.size()));
    else
      ShowErrorNotice(this, "Registry",
                      "Failed to unprotect:\n" + Failures.join('\n'));
  }

  ComboBox *SourceCombo = nullptr;
  ComboBox *PathCombo = nullptr;
  LineEdit *AddressEdit = nullptr;
  SearchLineEdit *SearchEdit = nullptr;
  QTimer *SearchDebounceTimer = nullptr;
  BodyLabel *ValueCountLabel = nullptr;
  TableWidget *ValueTable = nullptr;
  PushButton *ModifyButton = nullptr;
  PushButton *DeleteButton = nullptr;
  TableWidget *ProtectedTable = nullptr;
  SearchLineEdit *ProtectedSearchEdit = nullptr;
  QTimer *ProtectedSearchDebounceTimer = nullptr;
  BodyLabel *ProtectedCountLabel = nullptr;
  PushButton *UnprotectButton = nullptr;
  std::vector<RegistryValueRow> Rows;
  QList<ProtectedRegistryEntry> ProtectedEntries;
};
