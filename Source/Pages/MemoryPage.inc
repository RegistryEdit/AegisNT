QWidget *CreateMemoryPage() {
  auto *Page = new QWidget;
  auto *Layout = new QVBoxLayout(Page);
  ConfigurePageLayout(Layout);
  auto *Hint =
      MakeLabel("Process ID accepts 0. `0` means kernel mode memory access.",
                11, KTextMuted);
  Hint->setWordWrap(true);
  Layout->addWidget(Hint);
  auto *TargetLayout = new QHBoxLayout;
  ConfigureToolbarLayout(TargetLayout);
  auto *Pid = new LineEdit;
  auto *Address = new LineEdit;
  Pid->setPlaceholderText("Process ID (0 = kernel mode)");
  Address->setPlaceholderText("Address, for example 0x7FF612340000");
  Pid->setMaximumWidth(190);
  TargetLayout->addWidget(Pid);
  TargetLayout->addWidget(Address, 1);
  Layout->addLayout(TargetLayout);
  auto *ReadLayout = new QHBoxLayout;
  ConfigureToolbarLayout(ReadLayout);
  auto *ReadSize = new LineEdit;
  ReadSize->setText("256");
  ReadSize->setPlaceholderText("Read size (1-4096)");
  auto *ReadButton = MakeButton("Read", true);
  ReadLayout->addWidget(ReadSize, 1);
  ReadLayout->addWidget(ReadButton);
  Layout->addLayout(ReadLayout);
  auto *MemoryTabs = new TabBar;
  MemoryTabs->setAddButtonVisible(false);
  MemoryTabs->setTabsClosable(false);
  MemoryTabs->setMovable(false);
  MemoryTabs->addTab("editor", "Memory Editor", Fluent::IconType::EDIT);
  MemoryTabs->addTab("physical", "Physical Ranges",
                     Fluent::IconType::COMMAND_PROMPT);
  Layout->addWidget(MemoryTabs);
  auto *MemoryPages = new QStackedWidget;
  auto *ViewerPage = new QWidget;
  auto *ViewerLayout = new QHBoxLayout(ViewerPage);
  ConfigureToolbarLayout(ViewerLayout);
  auto *HexPanel = new QVBoxLayout;
  auto *AsciiPanel = new QVBoxLayout;
  HexPanel->setContentsMargins(0, 0, 0, 0);
  HexPanel->setSpacing(6);
  AsciiPanel->setContentsMargins(0, 0, 0, 0);
  AsciiPanel->setSpacing(6);
  auto *HexLabel = MakeLabel("HEX", 11, KTextMuted);
  auto *AsciiLabel = MakeLabel("ASCII", 11, KTextMuted);
  auto *HexView = new PlainTextEdit;
  auto *AsciiView = new PlainTextEdit;
  HexView->setPlaceholderText(
      "Hex bytes for read/write, for example: 48 8B 05 00 FF");
  AsciiView->setPlaceholderText("ASCII view of the latest read result");
  HexView->setFont(QFont("Cascadia Mono", 10));
  AsciiView->setFont(QFont("Cascadia Mono", 10));
  AsciiView->setReadOnly(true);
  InstallFluentScrollBar(HexView, Qt::Vertical);
  InstallFluentScrollBar(AsciiView, Qt::Vertical);
  HexPanel->addWidget(HexLabel);
  HexPanel->addWidget(HexView, 1);
  AsciiPanel->addWidget(AsciiLabel);
  AsciiPanel->addWidget(AsciiView, 1);
  ViewerLayout->addLayout(HexPanel, 3);
  ViewerLayout->addLayout(AsciiPanel, 2);
  MemoryPages->addWidget(ViewerPage);
  auto *PhysicalTable = MakeTable({"Range", "Base", "End", "Bytes", "Size"});
  PhysicalTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
  PhysicalTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
  PhysicalTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
  PhysicalTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
  PhysicalTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
  MemoryPages->addWidget(PhysicalTable);
  Layout->addWidget(MemoryPages, 1);
  QObject::connect(MemoryTabs, &TabBar::currentChanged, MemoryPages,
                   &QStackedWidget::setCurrentIndex);
  QObject::connect(MemoryPages, &QStackedWidget::currentChanged, MemoryTabs,
                   &TabBar::setCurrentIndex);
  auto *WriteLayout = new QHBoxLayout;
  ConfigureToolbarLayout(WriteLayout);
  auto *Status = new BodyLabel("Ready");
  auto *RollbackButton = MakeButton("Rollback Last");
  auto *WriteButton = MakeButton("Write");
  WriteLayout->addWidget(Status, 1);
  WriteLayout->addWidget(RollbackButton);
  WriteLayout->addWidget(WriteButton);
  Layout->addLayout(WriteLayout);
  auto LastTransaction =
      std::make_shared<std::optional<AegisNT::KernelResearch::WriteTransaction>>();
  RollbackButton->setEnabled(false);
  const auto ParseTarget = [Page, Pid, Address](ULONG &ProcessId,
                                                ULONG_PTR &TargetAddress) {
    bool PidOk = false, AddressOk = false;
    const qulonglong PidValue = Pid->text().trimmed().toULongLong(&PidOk, 0);
    const qulonglong AddressValue =
        Address->text().trimmed().toULongLong(&AddressOk, 0);
    if (!PidOk || PidValue > std::numeric_limits<ULONG>::max() || !AddressOk ||
        AddressValue == 0) {
      ShowWarningNotice(
          Page, "Memory",
          "Enter a valid PID and address. PID 0 means kernel mode.");
      return false;
    }
    ProcessId = static_cast<ULONG>(PidValue);
    TargetAddress = static_cast<ULONG_PTR>(AddressValue);
    return true;
  };
  QObject::connect(
      ReadButton, &QPushButton::clicked, Page,
      [Page, ReadSize, HexView, AsciiView, Status, ParseTarget] {
        ULONG ProcessId = 0;
        ULONG_PTR TargetAddress = 0;
        if (!ParseTarget(ProcessId, TargetAddress))
          return;
        bool SizeOk = false;
        const uint Size = ReadSize->text().trimmed().toUInt(&SizeOk, 0);
        if (!SizeOk || Size == 0 || Size > 4096) {
          ShowWarningNotice(Page, "Memory",
                            "Read size must be between 1 and 4096.");
          return;
        }
        std::vector<unsigned char> Buffer(Size);
        ULONG BytesRead = 0;
        if (!ReadMemory(ProcessId, TargetAddress, Buffer.data(), Size,
                        &BytesRead)) {
          const QString Message =
              QString("Read failed (error %1)").arg(G_LastMultiDrvError);
          Status->setText(Message);
          ShowErrorNotice(Page, "Memory", Message);
          return;
        }
        Buffer.resize(std::min<size_t>(BytesRead, Buffer.size()));
        QString HexOutput;
        QString AsciiOutput;
        for (size_t Offset = 0; Offset < Buffer.size(); Offset += 16) {
          QString HexLine =
              QString("%1  ")
                  .arg(TargetAddress + Offset, sizeof(ULONG_PTR) * 2, 16,
                       QLatin1Char('0'))
                  .toUpper();
          QString AsciiLine =
              QString("%1  ")
                  .arg(TargetAddress + Offset, sizeof(ULONG_PTR) * 2, 16,
                       QLatin1Char('0'))
                  .toUpper();
          for (size_t Index = 0; Index < 16; ++Index) {
            if (Offset + Index < Buffer.size()) {
              const unsigned char Value = Buffer[Offset + Index];
              HexLine +=
                  QString("%1 ").arg(Value, 2, 16, QLatin1Char('0')).toUpper();
              AsciiLine += std::isprint(static_cast<int>(Value)) ? QChar(Value)
                                                                 : QChar('.');
            } else {
              HexLine += "   ";
            }
            if (Index == 7)
              HexLine += ' ';
          }
          HexOutput += HexLine.trimmed() + '\n';
          AsciiOutput += AsciiLine + '\n';
        }
        HexView->setPlainText(HexOutput.trimmed());
        AsciiView->setPlainText(AsciiOutput.trimmed());
        const QString Message = QString("Read %1 byte(s).").arg(Buffer.size());
        Status->setText(Message);
        ShowSuccessNotice(Page, "Memory", Message);
      });
  QObject::connect(
      WriteButton, &QPushButton::clicked, Page,
      [Page, HexView, Status, ParseTarget, LastTransaction, RollbackButton] {
        ULONG ProcessId = 0;
        ULONG_PTR TargetAddress = 0;
        if (!ParseTarget(ProcessId, TargetAddress))
          return;
        QString Text = HexView->toPlainText();
        Text.replace(',', ' ')
            .replace(';', ' ')
            .replace('\n', ' ')
            .replace('\t', ' ')
            .replace('\r', ' ');
        QRegularExpression AddressPrefix("(?i)\\b[0-9a-f]+\\s{2,}");
        Text.replace(AddressPrefix, "");
        const QStringList Tokens = Text.split(' ', Qt::SkipEmptyParts);
        if (Tokens.isEmpty() || Tokens.size() > 4096) {
          ShowWarningNotice(Page, "Memory",
                            "Enter between 1 and 4096 hexadecimal bytes.");
          return;
        }
        std::vector<unsigned char> Bytes;
        Bytes.reserve(Tokens.size());
        for (QString Token : Tokens) {
          if (Token.startsWith("0x", Qt::CaseInsensitive))
            Token.remove(0, 2);
          bool Ok = false;
          const uint Value = Token.toUInt(&Ok, 16);
          if (!Ok || Token.size() > 2 || Value > 0xFF) {
            ShowWarningNotice(Page, "Memory", "Invalid hex byte: " + Token);
            return;
          }
          Bytes.push_back(static_cast<unsigned char>(Value));
        }
        std::vector<unsigned char> Before(Bytes.size());
        ULONG BeforeRead = 0;
        if (!ReadMemory(ProcessId, TargetAddress, Before.data(),
                        static_cast<ULONG>(Before.size()), &BeforeRead) ||
            BeforeRead != Before.size()) {
          ShowErrorNotice(Page, "Memory", "Pre-write read failed; no write was attempted.");
          return;
        }
        Before.resize(BeforeRead);
        const auto Modules = ProcessId == 0
            ? AegisNT::KernelResearch::QueryAll(IOCTL_ENUM_KERNEL_MODULES_V2)
            : std::vector<MDV2_RECORD>{};
        const auto Owner = AegisNT::KernelResearch::ResolveAddress(TargetAddress, Modules);
        QStringList Diff;
        for (size_t I = 0; I < Bytes.size(); ++I) {
          if (Before[I] != Bytes[I])
            Diff << QString("+0x%1: %2 -> %3")
                        .arg(I, 0, 16).arg(Before[I], 2, 16, QLatin1Char('0'))
                        .arg(Bytes[I], 2, 16, QLatin1Char('0')).toUpper();
          if (Diff.size() == 16) { Diff << "..."; break; }
        }
        if (Diff.isEmpty()) {
          ShowWarningNotice(Page, "Memory", "The staged bytes are identical to memory.");
          return;
        }
        Status->setText(QString("Applying %1 staged change(s) at %2 (%3).")
                            .arg(Diff.size())
                            .arg(AegisNT::KernelResearch::Hex(TargetAddress))
                            .arg(Owner.Module.isEmpty() ? "unresolved" : Owner.Module));
        if (!WriteMemory(ProcessId, TargetAddress, Bytes.data(),
                         static_cast<ULONG>(Bytes.size()))) {
          const QString Message =
              QString("Write failed (error %1)").arg(G_LastMultiDrvError);
          Status->setText(Message);
          ShowErrorNotice(Page, "Memory", Message);
        } else {
          std::vector<unsigned char> Verify(Bytes.size());
          ULONG VerifiedRead = 0;
          const bool Verified = ReadMemory(ProcessId, TargetAddress, Verify.data(),
              static_cast<ULONG>(Verify.size()), &VerifiedRead) &&
              VerifiedRead == Bytes.size() && Verify == Bytes;
          if (!Verified) {
            const bool Restored = WriteMemory(ProcessId, TargetAddress, Before.data(),
                                               static_cast<ULONG>(Before.size()));
            const QString Message = QString("Write verification failed; automatic restore %1.")
                                        .arg(Restored ? "succeeded" : "failed");
            Status->setText(Message); ShowErrorNotice(Page, "Memory", Message); return;
          }
          AegisNT::KernelResearch::WriteTransaction Tx;
          Tx.Id = QUuid::createUuid().toString(QUuid::WithoutBraces);
          Tx.CreatedUtc = QDateTime::currentDateTimeUtc(); Tx.Address = TargetAddress;
          Tx.Before = QByteArray(reinterpret_cast<const char *>(Before.data()), Before.size());
          Tx.After = QByteArray(reinterpret_cast<const char *>(Bytes.data()), Bytes.size());
          Tx.Owner = Owner; Tx.Verified = true;
          *LastTransaction = Tx; RollbackButton->setEnabled(true);
          QDir AuditDir(QCoreApplication::applicationDirPath());
          AuditDir.mkpath("Data/Audit");
          QFile Audit(AuditDir.filePath("Data/Audit/kernel-write-" +
              QDate::currentDate().toString("yyyyMMdd") + ".jsonl"));
          if (Audit.open(QIODevice::WriteOnly | QIODevice::Append)) {
            const QJsonObject Record{{"id", Tx.Id}, {"createdUtc", Tx.CreatedUtc.toString(Qt::ISODate)},
              {"address", AegisNT::KernelResearch::Hex(Tx.Address)},
              {"size", static_cast<int>(Bytes.size())}, {"verified", true},
              {"owner", AegisNT::KernelResearch::AddressJson(Tx.Owner)}};
            Audit.write(QJsonDocument(Record).toJson(QJsonDocument::Compact) + '\n');
          }
          const QString Message = QString("Wrote and verified %1 byte(s). Transaction %2")
                                      .arg(Bytes.size()).arg(Tx.Id.left(8));
          Status->setText(Message);
          ShowSuccessNotice(Page, "Memory", Message);
        }
      });
  QObject::connect(RollbackButton, &QPushButton::clicked, Page,
      [Page, Status, ParseTarget, LastTransaction, RollbackButton] {
        if (!LastTransaction->has_value()) return;
        ULONG ProcessId = 0; ULONG_PTR TargetAddress = 0;
        if (!ParseTarget(ProcessId, TargetAddress)) return;
        auto &Tx = LastTransaction->value();
        if (TargetAddress != Tx.Address) {
          ShowWarningNotice(Page, "Memory", "Current address does not match the last transaction."); return;
        }
        std::vector<unsigned char> Current(Tx.After.size()); ULONG Read = 0;
        if (!ReadMemory(ProcessId, Tx.Address, Current.data(), static_cast<ULONG>(Current.size()), &Read) ||
            QByteArray(reinterpret_cast<const char *>(Current.data()), Read) != Tx.After) {
          ShowWarningNotice(Page, "Memory", "Memory changed after the transaction; rollback refused."); return;
        }
        QByteArray RestoreBytes = Tx.Before;
        if (!WriteMemory(ProcessId, Tx.Address, RestoreBytes.data(), static_cast<ULONG>(RestoreBytes.size()))) {
          ShowErrorNotice(Page, "Memory", "Rollback write failed."); return;
        }
        Tx.RolledBack = true; RollbackButton->setEnabled(false);
        Status->setText("Last transaction rolled back and verified on next read.");
        ShowSuccessNotice(Page, "Memory", "Last write transaction rolled back.");
      });
  QObject::connect(MemoryTabs, &TabBar::currentChanged, Page,
      [PhysicalTable](int Index) {
        if (Index != 1) return;
        const auto Records = AegisNT::KernelResearch::QueryAll(IOCTL_QUERY_MEMORY_V2);
        PhysicalTable->setSortingEnabled(false); PhysicalTable->setRowCount(0);
        for (const auto &Record : Records) {
          const int Row = PhysicalTable->rowCount(); PhysicalTable->insertRow(Row);
          const quint64 End = Record.Address + Record.SizeBytes;
          const QStringList Values{QString::number(Record.Value[0]),
            AegisNT::KernelResearch::Hex(Record.Address),
            AegisNT::KernelResearch::Hex(End), QString::number(Record.SizeBytes),
            QString::number(Record.SizeBytes / (1024 * 1024)) + " MiB"};
          for (int Column = 0; Column < Values.size(); ++Column)
            PhysicalTable->setItem(Row, Column, new QTableWidgetItem(Values[Column]));
        }
        PhysicalTable->setSortingEnabled(true);
      });
  return Page;
}

#include "Source/Pages/DriverPage.inc"

QWidget *CreateDriverPage() { return new DriverManagerPage; }

#include "Source/Pages/ServicePage.inc"

QWidget *CreateServiceManagerPage() { return new ServiceManagerPage; }
