#include <mutex>

QWidget *CreateHookLabPage() {
  auto *Page = new QWidget;
  const auto IoMutex = std::make_shared<std::mutex>();
  auto *Layout = new QVBoxLayout(Page);
  ConfigurePageLayout(Layout);

  auto *Toolbar = new QHBoxLayout;
  ConfigureToolbarLayout(Toolbar);
  auto *Install = MakeButton("Add hook", true);
  auto *Enable = MakeButton("Enable");
  auto *Disable = MakeButton("Disable");
  auto *Verify = MakeButton("Verify");
  auto *Remove = MakeButton("Remove");
  auto *Refresh = MakeButton("Refresh");
  auto *Restore = MakeButton("Restore all");
  auto *Status = new BodyLabel("Not queried.");
  Status->setProperty("TextRole", "Muted");
  Toolbar->addWidget(Install);
  Toolbar->addWidget(Enable);
  Toolbar->addWidget(Disable);
  Toolbar->addWidget(Verify);
  Toolbar->addWidget(Remove);
  Toolbar->addWidget(Refresh);
  Toolbar->addWidget(Restore);
  Toolbar->addStretch();
  Toolbar->addWidget(Status);
  Layout->addLayout(Toolbar);

  auto *Capabilities = new BodyLabel("Capabilities: querying...");
  Capabilities->setWordWrap(true);
  Layout->addWidget(Capabilities);
  auto *Banner = new BodyLabel(
      "DriverDispatch, FastIO.CheckIfPossible, SSDT, IDT (current CPU), and "
      "x64 Inline are available. Use Add hook to show only the fields required "
      "by the selected target; SSDT/IDT/Inline require a kernel proxy address.");
  Banner->setWordWrap(true);
  Banner->setProperty("TextRole", "Warning");
  Layout->addWidget(Banner);
  auto *Table = MakeTable({"ID", "State", "Target", "Index", "Vector",
                           "Driver", "Original", "Proxy", "Hits", "Active",
                           "Status", "Detail"});
  Table->setSelectionMode(QAbstractItemView::SingleSelection);
  Table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
  Table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
  Table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
  Table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
  Table->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
  Table->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
  Table->horizontalHeader()->setSectionResizeMode(6, QHeaderView::ResizeToContents);
  Table->horizontalHeader()->setSectionResizeMode(7, QHeaderView::ResizeToContents);
  Table->horizontalHeader()->setSectionResizeMode(8, QHeaderView::ResizeToContents);
  Table->horizontalHeader()->setSectionResizeMode(9, QHeaderView::ResizeToContents);
  Table->horizontalHeader()->setSectionResizeMode(10, QHeaderView::ResizeToContents);
  Table->horizontalHeader()->setSectionResizeMode(11, QHeaderView::Stretch);
  Layout->addWidget(Table, 1);

  const auto Hex = [](quint64 Value) {
    return Value == 0 ? QString("-")
                      : QString("0x%1").arg(Value, 0, 16).toUpper();
  };
  const auto StateText = [](ULONG State) {
    switch (State) {
    case HOOK_STATE_PREPARED: return QString("Prepared");
    case HOOK_STATE_ACTIVE: return QString("Active");
    case HOOK_STATE_DISABLED: return QString("Disabled");
    case HOOK_STATE_RESTORED: return QString("Restored");
    case HOOK_STATE_FAILED: return QString("Failed");
    default: return QString("Empty");
    }
  };
  const auto TargetText = [](ULONG TargetKind) {
    switch (TargetKind) {
    case HOOK_TARGET_DRIVER_DISPATCH: return QString("DriverDispatch");
    case HOOK_TARGET_FAST_IO: return QString("FastIO");
    case HOOK_TARGET_SSDT: return QString("SSDT");
    case HOOK_TARGET_IDT: return QString("IDT");
    case HOOK_TARGET_INLINE: return QString("Inline");
    case HOOK_TARGET_VT_EPT: return QString("VT/EPT");
    default: return QString("Other");
    }
  };
  const auto RefreshTable = [Page, Table, Status, StateText, TargetText, Hex,
                             IoMutex] {
    QPointer<QWidget> SafePage(Page);
    std::thread([SafePage, Table, Status, StateText, TargetText, Hex, IoMutex] {
      std::lock_guard<std::mutex> IoLock(*IoMutex);
      std::vector<HOOK_RECORD> Records;
      const bool Ok = QueryHooks(Records);
      const DWORD Error = G_LastAegisCoreError;
      QMetaObject::invokeMethod(qApp, [SafePage, Table, Status, Records = std::move(Records),
                                        Ok, Error, StateText, TargetText, Hex] {
        if (!SafePage)
          return;
        SetTableRefreshEnabled(Table, false);
        Table->clearContents();
        Table->setRowCount(0);
        if (!Ok) {
          Status->setText(QString("Hook query failed (%1)").arg(Error));
          SetTableRefreshEnabled(Table, true);
          return;
        }
        Table->setRowCount(static_cast<int>(Records.size()));
        for (int Row = 0; Row < static_cast<int>(Records.size()); ++Row) {
          const auto &Item = Records[static_cast<size_t>(Row)];
          const QStringList Values{
              QString::number(Item.HookId), StateText(Item.State),
              TargetText(Item.TargetKind), QString::number(Item.TableIndex),
              QString::number(Item.Vector), QString::fromWCharArray(Item.DriverName),
              Hex(Item.OriginalAddress), Hex(Item.ProxyAddress), QString::number(Item.HitCount),
              QString::number(Item.ActiveCalls),
              QString("0x%1").arg(static_cast<quint32>(Item.Status), 8, 16,
                                   QLatin1Char('0')).toUpper(),
              QString::fromWCharArray(Item.Detail)};
          for (int Column = 0; Column < Values.size(); ++Column)
            Table->setItem(Row, Column, new QTableWidgetItem(Values[Column]));
          Table->setRowHeight(Row, KCompactTableRowHeight);
        }
        Status->setText(QString("%1 hook(s)").arg(Records.size()));
        SetTableRefreshEnabled(Table, true);
      }, Qt::QueuedConnection);
    }).detach();
  };

  const auto RefreshCapabilities = [Page, Capabilities, IoMutex] {
    QPointer<QWidget> SafePage(Page);
    std::thread([SafePage, Capabilities, IoMutex] {
      std::lock_guard<std::mutex> IoLock(*IoMutex);
      HOOK_CAPABILITIES_OUTPUT Output{};
      Output.Size = sizeof(Output);
      const bool Ok = QueryHookCapabilities(&Output);
      const DWORD Error = G_LastAegisCoreError;
      QMetaObject::invokeMethod(qApp, [SafePage, Capabilities, Output, Ok, Error] {
        if (!SafePage)
          return;
        if (!Ok) {
          Capabilities->setText(QString("Capabilities unavailable (%1)").arg(Error));
          return;
        }
        QStringList Targets;
        if (Output.SupportedTargets & (1u << HOOK_TARGET_DRIVER_DISPATCH))
          Targets << "DriverDispatch";
        if (Output.SupportedTargets & (1u << HOOK_TARGET_FAST_IO))
          Targets << "FastIO";
        if (Output.SupportedTargets & (1u << HOOK_TARGET_SSDT))
          Targets << "SSDT";
        if (Output.SupportedTargets & (1u << HOOK_TARGET_IDT))
          Targets << "IDT";
        if (Output.SupportedTargets & (1u << HOOK_TARGET_INLINE))
          Targets << "Inline";
        if (Output.SupportedTargets & (1u << HOOK_TARGET_VT_EPT))
          Targets << "VT/EPT";
        Capabilities->setText(QString("Targets: %1 | Active: %2/%3")
                                  .arg(Targets.join(", "))
                                  .arg(Output.ActiveHooks)
                                  .arg(Output.MaxHooks));
      }, Qt::QueuedConnection);
    }).detach();
  };

  const auto OperateSelected = [Page, Table, Status, RefreshTable, IoMutex](
                                  ULONG Operation, DWORD Ioctl,
                                  QString Action) {
    const int Row = Table->currentRow();
    if (Row < 0 || Table->item(Row, 0) == nullptr) {
      ShowWarningNotice(Page, "Hook", "Select a hook row first.");
      return;
    }
    bool Parsed = false;
    const ULONG HookId = Table->item(Row, 0)->text().toUInt(&Parsed);
    if (!Parsed || HookId == 0) {
      ShowWarningNotice(Page, "Hook", "The selected hook ID is invalid.");
      return;
    }
    Status->setText(Action + "...");
    QPointer<QWidget> SafePage(Page);
    std::thread([SafePage, Status, RefreshTable, Operation, Ioctl, HookId,
                 Action, IoMutex] {
      std::lock_guard<std::mutex> IoLock(*IoMutex);
      HOOK_RECORD Result{};
      const bool Ok = OperateHookById(Ioctl, Operation, HookId, &Result);
      const DWORD Error = G_LastAegisCoreError;
      QMetaObject::invokeMethod(
          qApp,
          [SafePage, Status, RefreshTable, Ok, Error, HookId, Action] {
            if (!SafePage)
              return;
            if (!Ok) {
              Status->setText(QString("%1 failed (%2)").arg(Action).arg(Error));
              ShowErrorNotice(SafePage, "Hook",
                              QString("Hook %1 %2 failed (%3).")
                                  .arg(HookId)
                                  .arg(Action.toLower())
                                  .arg(Error));
              return;
            }
            Status->setText(QString("Hook %1 %2.")
                                .arg(HookId)
                                .arg(Action.toLower()));
            RefreshTable();
          },
          Qt::QueuedConnection);
    }).detach();
  };

  QObject::connect(Refresh, &QPushButton::clicked, Page, RefreshTable);
  QObject::connect(Install, &QPushButton::clicked, Page,
                   [Page, Status, RefreshTable, IoMutex] {
    QDialog Dialog(Page);
    Dialog.setWindowTitle("Add Hook");
    Dialog.setModal(true);
    Dialog.setMinimumWidth(560);
    auto *Form = new QGridLayout(&Dialog);
    Form->setColumnStretch(1, 1);

    auto *TargetLabel = new BodyLabel("Target type");
    auto *Target = new ComboBox;
    Target->addItem("DriverDispatch", QVariant::fromValue<quint32>(HOOK_TARGET_DRIVER_DISPATCH));
    Target->addItem("FastIO.CheckIfPossible", QVariant::fromValue<quint32>(HOOK_TARGET_FAST_IO));
    Target->addItem("SSDT", QVariant::fromValue<quint32>(HOOK_TARGET_SSDT));
    Target->addItem("IDT", QVariant::fromValue<quint32>(HOOK_TARGET_IDT));
    Target->addItem("Inline", QVariant::fromValue<quint32>(HOOK_TARGET_INLINE));
    Form->addWidget(TargetLabel, 0, 0);
    Form->addWidget(Target, 0, 1);

    auto *DriverLabel = new BodyLabel("Driver");
    auto *Driver = new LineEdit;
    ConfigureLineEdit(Driver, "Driver service or \\Driver\\Name", 0);
    Form->addWidget(DriverLabel, 1, 0);
    Form->addWidget(Driver, 1, 1);

    auto *MajorLabel = new BodyLabel("Major function");
    auto *Major = new ComboBox;
    constexpr ULONG KMaxMajorFunction = 0x1B;
    for (ULONG Index = 0; Index <= KMaxMajorFunction; ++Index)
      Major->addItem(QString("MajorFunction %1").arg(Index),
                     QVariant::fromValue<quint32>(Index));
    Form->addWidget(MajorLabel, 2, 0);
    Form->addWidget(Major, 2, 1);

    auto *IndexLabel = new BodyLabel("Table index / vector");
    auto *IndexOrVector = new LineEdit;
    ConfigureLineEdit(IndexOrVector, "Decimal or 0x...", 0);
    Form->addWidget(IndexLabel, 3, 0);
    Form->addWidget(IndexOrVector, 3, 1);

    auto *TargetAddressLabel = new BodyLabel("Target address");
    auto *TargetAddress = new LineEdit;
    ConfigureLineEdit(TargetAddress, "Kernel address (0x...)", 0);
    Form->addWidget(TargetAddressLabel, 4, 0);
    Form->addWidget(TargetAddress, 4, 1);

    auto *ProxyAddressLabel = new BodyLabel("Proxy address");
    auto *ProxyAddress = new LineEdit;
    ConfigureLineEdit(ProxyAddress, "Kernel address (0x...)", 0);
    Form->addWidget(ProxyAddressLabel, 5, 0);
    Form->addWidget(ProxyAddress, 5, 1);

    auto *ShadowSsdt = new CheckBox("Use Shadow SSDT");
    Form->addWidget(ShadowSsdt, 6, 1);
    auto *Hint = new BodyLabel;
    Hint->setWordWrap(true);
    Hint->setProperty("TextRole", "Muted");
    Form->addWidget(Hint, 7, 0, 1, 2);

    auto *Buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    Buttons->button(QDialogButtonBox::Ok)->setText("Install");
    Form->addWidget(Buttons, 8, 0, 1, 2);

    const auto UpdateFields = [Target, DriverLabel, Driver, MajorLabel, Major,
                               IndexLabel, IndexOrVector, TargetAddressLabel,
                               TargetAddress, ProxyAddressLabel, ProxyAddress,
                               ShadowSsdt, Hint] {
      const ULONG Kind = Target->currentData().toUInt();
      const bool IsDispatch = Kind == HOOK_TARGET_DRIVER_DISPATCH;
      const bool IsFastIo = Kind == HOOK_TARGET_FAST_IO;
      const bool IsSsdt = Kind == HOOK_TARGET_SSDT;
      const bool IsIdt = Kind == HOOK_TARGET_IDT;
      const bool IsInline = Kind == HOOK_TARGET_INLINE;
      const bool NeedsDriver = IsDispatch || IsFastIo;
      const bool NeedsIndex = IsFastIo || IsSsdt || IsIdt;
      const bool NeedsProxy = IsSsdt || IsIdt || IsInline;
      DriverLabel->setVisible(NeedsDriver);
      Driver->setVisible(NeedsDriver);
      MajorLabel->setVisible(IsDispatch);
      Major->setVisible(IsDispatch);
      IndexLabel->setVisible(NeedsIndex);
      IndexOrVector->setVisible(NeedsIndex);
      TargetAddressLabel->setVisible(IsInline);
      TargetAddress->setVisible(IsInline);
      ProxyAddressLabel->setVisible(NeedsProxy);
      ProxyAddress->setVisible(NeedsProxy);
      ShadowSsdt->setVisible(IsSsdt);
      if (IsFastIo) {
        IndexLabel->setText("Fast I/O slot");
        IndexOrVector->setText("0");
        IndexOrVector->setReadOnly(true);
        Hint->setText("Installs a pass-through FastIoCheckIfPossible wrapper.");
      } else if (IsSsdt) {
        IndexLabel->setText("SSDT table index");
        IndexOrVector->setReadOnly(false);
        Hint->setText("Use an index from the Table page. Proxy must be kernel code; Shadow SSDT changes the shadow table.");
      } else if (IsIdt) {
        IndexLabel->setText("IDT vector");
        IndexOrVector->setReadOnly(false);
        Hint->setText("The vector is patched on the current CPU only. Proxy must be a valid interrupt entry.");
      } else if (IsInline) {
        IndexOrVector->setReadOnly(false);
        Hint->setText("The target is overwritten with a 12-byte x64 absolute jump. Check instruction boundaries before installing.");
      } else {
        IndexOrVector->setReadOnly(false);
        Hint->setText("Installs a pass-through dispatch wrapper for the selected driver MajorFunction.");
      }
    };
    QObject::connect(Target, &ComboBox::currentIndexChanged, &Dialog,
                     [UpdateFields](int) { UpdateFields(); });
    UpdateFields();

    QObject::connect(Buttons, &QDialogButtonBox::accepted, &Dialog, [&] {
      const ULONG Kind = Target->currentData().toUInt();
      const QString Name = Driver->text().trimmed();
      if ((Kind == HOOK_TARGET_DRIVER_DISPATCH || Kind == HOOK_TARGET_FAST_IO) &&
          Name.isEmpty()) {
        ShowWarningNotice(&Dialog, "Hook", "Enter a driver name for this target.");
        return;
      }
      bool IndexOk = true;
      const QString IndexText = IndexOrVector->text().trimmed();
      const ULONG Index = IndexText.isEmpty() ? 0 : IndexText.toUInt(&IndexOk, 0);
      if (!IndexOk || (Kind == HOOK_TARGET_IDT && Index > 255)) {
        ShowWarningNotice(&Dialog, "Hook", "Enter a valid decimal or hexadecimal index/vector.");
        return;
      }
      auto ParseAddress = [](const QString &Text, bool *Ok) -> ULONG64 {
        QString Value = Text.trimmed();
        if (Value.startsWith("0x", Qt::CaseInsensitive))
          Value.remove(0, 2);
        return Value.toULongLong(Ok, 16);
      };
      bool TargetOk = true;
      bool ProxyOk = true;
      const ULONG64 TargetValue = ParseAddress(TargetAddress->text(), &TargetOk);
      const ULONG64 ProxyValue = ParseAddress(ProxyAddress->text(), &ProxyOk);
      if ((Kind == HOOK_TARGET_SSDT || Kind == HOOK_TARGET_IDT || Kind == HOOK_TARGET_INLINE) &&
          (!ProxyOk || ProxyValue == 0)) {
        ShowWarningNotice(&Dialog, "Hook", "Enter a kernel proxy address (0x...).");
        return;
      }
      if (Kind == HOOK_TARGET_INLINE && (!TargetOk || TargetValue == 0)) {
        ShowWarningNotice(&Dialog, "Hook", "Enter an inline target address (0x...).");
        return;
      }
      Dialog.accept();
    });
    QObject::connect(Buttons, &QDialogButtonBox::rejected, &Dialog, &QDialog::reject);
    if (Dialog.exec() != QDialog::Accepted)
      return;

    const ULONG TargetKind = Target->currentData().toUInt();
    const QString Name = Driver->text().trimmed();
    const ULONG MajorFunction = Major->currentData().toUInt();
    const ULONG Index = IndexOrVector->text().trimmed().isEmpty()
                            ? 0
                            : IndexOrVector->text().trimmed().toUInt(nullptr, 0);
    auto ParseAddress = [](const QString &Text) -> ULONG64 {
      QString Value = Text.trimmed();
      if (Value.startsWith("0x", Qt::CaseInsensitive))
        Value.remove(0, 2);
      return Value.toULongLong(nullptr, 16);
    };
    const ULONG64 TargetValue = ParseAddress(TargetAddress->text());
    const ULONG64 ProxyValue = ParseAddress(ProxyAddress->text());
    const ULONG Flags = ShadowSsdt->isChecked() ? HOOK_FLAG_SHADOW_SSDT : 0;
    Status->setText("Installing hook...");
    QPointer<QWidget> SafePage(Page);
    std::thread([SafePage, Name, TargetKind, MajorFunction, Index, TargetValue,
                 ProxyValue, Flags, Status, RefreshTable, IoMutex] {
      std::lock_guard<std::mutex> IoLock(*IoMutex);
      HOOK_REQUEST Request{};
      Request.Operation = HOOK_OP_INSTALL;
      Request.TargetKind = TargetKind;
      Request.MajorFunction = MajorFunction;
      Request.TableIndex = Index;
      Request.Vector = Index;
      Request.TargetAddress = TargetValue;
      Request.ProxyAddress = ProxyValue;
      Request.Flags = Flags;
      wcsncpy_s(Request.DriverName, Name.toStdWString().c_str(), _TRUNCATE);
      HOOK_RECORD Result{};
      const bool Ok = OperateHook(Request, &Result);
      const DWORD Error = G_LastAegisCoreError;
      QMetaObject::invokeMethod(qApp, [SafePage, Status, Ok, Error, Result,
                                       RefreshTable] {
        if (!SafePage)
          return;
        if (!Ok) {
          Status->setText(QString("Install failed (%1)").arg(Error));
          ShowErrorNotice(SafePage, "Hook",
                          QString("Hook install failed (%1).").arg(Error));
          return;
        }
        Status->setText(QString("Hook %1 active.").arg(Result.HookId));
        RefreshTable();
      }, Qt::QueuedConnection);
    }).detach();
  });
  QObject::connect(Restore, &QPushButton::clicked, Page,
                   [Page, Status, RefreshTable, IoMutex] {
    Status->setText("Restoring hooks...");
    QPointer<QWidget> SafePage(Page);
    std::thread([SafePage, Status, RefreshTable, IoMutex] {
      std::lock_guard<std::mutex> IoLock(*IoMutex);
      const bool Ok = SendIoctl(IOCTL_HOOK_RESTORE_ALL, nullptr, 0);
      const DWORD Error = G_LastAegisCoreError;
      QMetaObject::invokeMethod(qApp, [SafePage, Status, Ok, Error, RefreshTable] {
        if (!SafePage)
          return;
        Status->setText(Ok ? "All hooks restored." : QString("Restore failed (%1)").arg(Error));
        RefreshTable();
      }, Qt::QueuedConnection);
    }).detach();
  });

  QObject::connect(Enable, &QPushButton::clicked, Page,
                   [OperateSelected] {
                     OperateSelected(HOOK_OP_ENABLE, IOCTL_HOOK_ENABLE, "Enable");
                   });
  QObject::connect(Disable, &QPushButton::clicked, Page,
                   [OperateSelected] {
                     OperateSelected(HOOK_OP_DISABLE, IOCTL_HOOK_DISABLE, "Disable");
                   });
  QObject::connect(Verify, &QPushButton::clicked, Page,
                   [OperateSelected] {
                     OperateSelected(HOOK_OP_VERIFY, IOCTL_HOOK_VERIFY, "Verify");
                   });
  QObject::connect(Remove, &QPushButton::clicked, Page,
                   [OperateSelected] {
                     OperateSelected(HOOK_OP_REMOVE, IOCTL_HOOK_REMOVE, "Remove");
                   });

  QTimer::singleShot(0, Page, [RefreshCapabilities, RefreshTable] {
    RefreshCapabilities();
    RefreshTable();
  });
  return Page;
}
