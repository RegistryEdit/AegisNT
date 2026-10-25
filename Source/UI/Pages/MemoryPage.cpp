// 进程内存扩展功能(AOB 扫描 / 模块转储)的辅助定义�?
namespace {

struct PatternByte {
  unsigned char Value = 0;
  bool Wildcard = false;
};

struct PatternScanHit {
  ULONG_PTR Address = 0;
  ULONG_PTR RegionBase = 0;
  ULONG Protect = 0;
  ULONG Type = 0;
  unsigned char Context[16] = {};
};

bool MemoryProtectReadable(ULONG Protect) {
  if (Protect & PAGE_GUARD)
    return false;
  switch (Protect & 0xFF) {
  case PAGE_READONLY:
  case PAGE_READWRITE:
  case PAGE_WRITECOPY:
  case PAGE_EXECUTE_READ:
  case PAGE_EXECUTE_READWRITE:
  case PAGE_EXECUTE_WRITECOPY:
    return true;
  default:
    return false;  // �?PAGE_NOACCESS / PAGE_EXECUTE(不可�?
  }
}

// 在缓冲区内按通配符模式查�?返回匹配起始下标,无匹配返�?npos�?
size_t MemoryPatternFind(const unsigned char *Data, size_t Size,
                         const std::vector<PatternByte> &Pattern) {
  if (Pattern.empty() || Size < Pattern.size())
    return static_cast<size_t>(-1);
  const size_t Last = Size - Pattern.size();
  for (size_t Offset = 0; Offset <= Last; ++Offset) {
    size_t Index = 0;
    for (; Index < Pattern.size(); ++Index) {
      if (!Pattern[Index].Wildcard && Data[Offset + Index] != Pattern[Index].Value)
        break;
    }
    if (Index == Pattern.size())
      return Offset;
  }
  return static_cast<size_t>(-1);
}

} // namespace

QWidget *CreateMemoryPage() {
  auto *Page = new AegisNT::PageBase(nullptr);
  auto *Layout = Page->GetMainLayout();
  ConfigurePageLayout(Layout);
  auto *Hint =
      MakeLabel("Process ID accepts 0. `0` means kernel mode memory access; "
                "the method box selects the kernel access path.",
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
  auto *MethodBox = new ComboBox;
  MethodBox->addItems({"Auto", "MDL map", "CR0 WP-off", "Direct map"});
  MethodBox->setToolTip(
      "Kernel-mode access method, used when PID is 0.");
  auto *ReadButton = MakeButton("Read", true);
  ReadLayout->addWidget(ReadSize, 1);
  ReadLayout->addWidget(MethodBox);
  ReadLayout->addWidget(ReadButton);
  Layout->addLayout(ReadLayout);
  auto *MemoryTabs = new TabBar;
  MemoryTabs->setAddButtonVisible(false);
  MemoryTabs->setTabsClosable(false);
  MemoryTabs->setMovable(false);
  MemoryTabs->addTab("editor", "Memory Editor", Fluent::IconType::EDIT);
  MemoryTabs->addTab("physical", "Physical Ranges",
                     Fluent::IconType::COMMAND_PROMPT);
  MemoryTabs->addTab("suspect", "Suspicious Memory",
                     Fluent::IconType::SEARCH);
  Layout->addWidget(MemoryTabs);
  auto *MemoryPages = new QStackedWidget;
  auto *ViewerPage = new AegisNT::PageBase(nullptr);
  auto *ViewerLayout = new QHBoxLayout;
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
  ViewerPage->GetMainLayout()->addLayout(ViewerLayout);
  MemoryPages->addWidget(ViewerPage);
  auto *PhysicalTable = MakeTable({"Range", "Base", "End", "Bytes", "Size"});
  PhysicalTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
  PhysicalTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
  PhysicalTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
  PhysicalTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
  PhysicalTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
  MemoryPages->addWidget(PhysicalTable);
  auto *SuspectPage = new AegisNT::PageBase(nullptr);
  auto *SuspectLayout = SuspectPage->GetMainLayout();
  SuspectLayout->setContentsMargins(0, 0, 0, 0);
  SuspectLayout->setSpacing(KCompactPageSpacing);
  auto *SuspectToolbar = new QHBoxLayout;
  ConfigureToolbarLayout(SuspectToolbar);
  auto *ScanButton = MakeButton("Scan Process", true);
  auto *SuspectStatus = new BodyLabel(
      "Scans committed private executable regions (unbacked memory).");
  SuspectToolbar->addWidget(ScanButton);
  SuspectToolbar->addWidget(SuspectStatus, 1);
  SuspectLayout->addLayout(SuspectToolbar);
  auto *SuspectTable = MakeTable({"Base", "Size", "Protect", "Type", "Flags"});
  SuspectTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
  SuspectTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
  SuspectTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
  SuspectTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
  SuspectTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
  SuspectLayout->addWidget(SuspectTable, 1);
  MemoryPages->addWidget(SuspectPage);

  // ---- Pattern Scan / Dump / PTE Walk / Region Ops ----
  auto ParsePidOnly = [Page, Pid](ULONG &ProcessId, bool Notify = true) {
    bool Ok = false;
    const qulonglong PidValue = Pid->text().trimmed().toULongLong(&Ok, 0);
    if (!Ok || PidValue == 0 || PidValue > 0xFFFFFFFFull) {
      if (Notify)
        ShowWarningNotice(Page, "Memory",
                          "Enter a valid non-zero target process ID.");
      return false;
    }
    ProcessId = static_cast<ULONG>(PidValue);
    return true;
  };

  MemoryTabs->addTab("scan", "Pattern Scan", Fluent::IconType::SEARCH);
  auto *ScanTab = new AegisNT::PageBase(nullptr);
  auto *ScanLayout = ScanTab->GetMainLayout();
  ScanLayout->setContentsMargins(0, 0, 0, 0);
  ScanLayout->setSpacing(KCompactPageSpacing);
  auto *ScanCtrl = new QHBoxLayout;
  ConfigureToolbarLayout(ScanCtrl);
  auto *PatternEdit = new LineEdit;
  PatternEdit->setPlaceholderText(
      "Pattern with ?? wildcards, e.g. 48 8B ?? 05 ?? ?? ?? ??");
  auto *ScanGo = MakeButton("Scan", true);
  auto *ScanStatus = new BodyLabel(
      "Scans committed readable regions of the target process "
      "(max 1000 hits, 512 MiB).");
  ScanCtrl->addWidget(PatternEdit, 1);
  ScanCtrl->addWidget(ScanGo);
  ScanLayout->addLayout(ScanCtrl);
  ScanLayout->addWidget(ScanStatus, 1);
  auto *ScanTable = MakeTable({"Address", "Region Base", "Protect", "Type",
                               "Context"});
  ScanTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
  ScanTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
  ScanTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
  ScanTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
  ScanTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
  ScanLayout->addWidget(ScanTable, 1);
  MemoryPages->addWidget(ScanTab);

  QObject::connect(
      ScanGo, &QPushButton::clicked, Page,
      [Page, PatternEdit, ScanGo, ScanStatus, ScanTable, ParsePidOnly] {
        ULONG ProcessId = 0;
        if (!ParsePidOnly(ProcessId))
          return;
        std::vector<PatternByte> Pattern;
        const QStringList Tokens =
            PatternEdit->text().split(QRegularExpression("[\\s,]+"),
                                      Qt::SkipEmptyParts);
        if (Tokens.isEmpty() || Tokens.size() > 256) {
          ShowWarningNotice(Page, "Memory",
                            "Enter 1-256 pattern bytes.");
          return;
        }
        for (const QString &Token : Tokens) {
          if (Token == "??" || Token == "*" || Token == "?") {
            Pattern.push_back({0, true});
            continue;
          }
          QString Hex = Token;
          if (Hex.startsWith("0x", Qt::CaseInsensitive))
            Hex.remove(0, 2);
          bool Ok = false;
          const uint Value = Hex.toUInt(&Ok, 16);
          if (!Ok || Hex.size() > 2 || Value > 0xFF) {
            ShowWarningNotice(Page, "Memory",
                              "Invalid pattern byte: " + Token);
            return;
          }
          Pattern.push_back({static_cast<unsigned char>(Value), false});
        }
        bool AnyByte = false;
        for (const PatternByte &Byte : Pattern)
          if (!Byte.Wildcard)
            AnyByte = true;
        if (!AnyByte) {
          ShowWarningNotice(Page, "Memory",
                            "Pattern must contain at least one concrete byte.");
          return;
        }

        ScanGo->setEnabled(false);
        ScanStatus->setText("Scanning...");
        QPointer<QWidget> Guard(Page);
        std::thread(
            [Guard, ProcessId, Pattern = std::move(Pattern), ScanGo,
             ScanStatus, ScanTable] {
              std::vector<PatternScanHit> Hits;
              ULONG64 Scanned = 0;
              ULONG Skipped = 0;
              constexpr ULONG64 ScanLimit = 512ull << 20;
              constexpr size_t MaxHits = 1000;
              const HANDLE Handle = OpenProcess(
                  PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE,
                  ProcessId);
              if (Handle != INVALID_HANDLE_VALUE && Handle != nullptr) {
                ULONG_PTR Region = 0;
                MEMORY_BASIC_INFORMATION Mbi{};
                while (VirtualQueryEx(Handle, (LPCVOID)Region, &Mbi,
                                      sizeof(Mbi)) &&
                       Hits.size() < MaxHits && Scanned < ScanLimit) {
                  const ULONG_PTR RegionBase = (ULONG_PTR)Mbi.BaseAddress;
                  const ULONG_PTR RegionSize = Mbi.RegionSize;
                  if (Mbi.State == MEM_COMMIT && RegionSize > 0 &&
                      MemoryProtectReadable(Mbi.Protect)) {
                    constexpr ULONG ChunkSize = 1u << 20;
                    ULONG_PTR Offset = 0;
                    std::vector<unsigned char> Tail;
                    while (Offset < RegionSize && Hits.size() < MaxHits &&
                           Scanned < ScanLimit) {
                      ULONG Take = ChunkSize;
                      if (Offset + Take > RegionSize)
                        Take = static_cast<ULONG>(RegionSize - Offset);
                      std::vector<unsigned char> Buffer(Tail.size() + Take);
                      if (!Tail.empty())
                        memcpy(Buffer.data(), Tail.data(), Tail.size());
                      SIZE_T ReadBytes = 0;
                      if (!ReadProcessMemory(
                              Handle,
                              (LPCVOID)(RegionBase + Offset),
                              Buffer.data() + Tail.size(), Take,
                              &ReadBytes) ||
                          ReadBytes == 0) {
                        ++Skipped;
                        break;
                      }
                      Buffer.resize(Tail.size() + ReadBytes);
                      Scanned += ReadBytes;
                      const ULONG_PTR BufferBase =
                          RegionBase + Offset - Tail.size();
                      size_t Position = 0;
                      while (Hits.size() < MaxHits) {
                        const size_t Found = MemoryPatternFind(
                            Buffer.data() + Position, Buffer.size() - Position,
                            Pattern);
                        if (Found == static_cast<size_t>(-1))
                          break;
                        const size_t Match = Position + Found;
                        PatternScanHit Hit;
                        Hit.Address = BufferBase + Match;
                        Hit.RegionBase = RegionBase;
                        Hit.Protect = Mbi.Protect;
                        Hit.Type = Mbi.Type;
                        const size_t ContextStart =
                            Match >= 8 ? Match - 8 : 0;
                        const size_t ContextLength =
                            std::min<size_t>(16, Buffer.size() - ContextStart);
                        ZeroMemory(Hit.Context, sizeof(Hit.Context));
                        memcpy(Hit.Context, Buffer.data() + ContextStart,
                               ContextLength);
                        Hits.push_back(Hit);
                        Position = Match + 1;
                        if (Position >= Buffer.size())
                          break;
                      }
                      Tail.assign(Buffer.end() -
                                      std::min<size_t>(Buffer.size(),
                                                       Pattern.size() - 1),
                                  Buffer.end());
                      Offset += ReadBytes;
                    }
                  }
                  Region = RegionBase + RegionSize;
                  if (Region < RegionBase)  // wrapped past user space
                    break;
                }
                CloseHandle(Handle);
              }
              QMetaObject::invokeMethod(
                  qApp,
                  [Guard, ProcessId, Hits, Scanned, Skipped, ScanGo,
                   ScanStatus, ScanTable] {
                    if (!Guard)
                      return;
                    ScanGo->setEnabled(true);
                    ScanTable->setRowCount(0);
                    for (const PatternScanHit &Hit : Hits) {
                      const int Row = ScanTable->rowCount();
                      ScanTable->insertRow(Row);
                      QString Context;
                      for (unsigned char Byte : Hit.Context)
                        Context += QString("%1 ")
                                       .arg(Byte, 2, 16, QLatin1Char('0'))
                                       .toUpper();
                      const QStringList Values{
                          AegisNT::KernelResearch::Hex(Hit.Address),
                          AegisNT::KernelResearch::Hex(Hit.RegionBase),
                          QString("0x%1").arg(Hit.Protect, 8, 16,
                                              QLatin1Char('0')).toUpper(),
                          Hit.Type == MEM_PRIVATE
                              ? "Private"
                              : Hit.Type == MEM_MAPPED
                                    ? "Mapped"
                                    : Hit.Type == MEM_IMAGE ? "Image" : "-",
                          Context.trimmed()};
                      for (int Column = 0; Column < Values.size(); ++Column)
                        ScanTable->setItem(Row, Column,
                                           new QTableWidgetItem(Values[Column]));
                    }
                    ScanStatus->setText(
                        QString("%1 hit(s), %2 MiB scanned, %3 unreadable "
                                "region(s).")
                            .arg(Hits.size())
                            .arg(Scanned >> 20)
                            .arg(Skipped));
                  });
            })
            .detach();
      });
  QObject::connect(
      ScanTable, &QTableWidget::cellDoubleClicked, Page,
      [ScanTable, Address, ReadButton](int Row, int) {
        if (auto *Item = ScanTable->item(Row, 0)) {
          Address->setText(Item->text());
          ReadButton->click();
        }
      });

  MemoryTabs->addTab("dump", "Dump", Fluent::IconType::SAVE);
  auto *DumpTab = new AegisNT::PageBase(nullptr);
  auto *DumpLayout = DumpTab->GetMainLayout();
  DumpLayout->setContentsMargins(0, 0, 0, 0);
  DumpLayout->setSpacing(KCompactPageSpacing);
  auto *ModuleRow = new QHBoxLayout;
  ConfigureToolbarLayout(ModuleRow);
  auto *ModuleBox = new ComboBox;
  auto *RefreshModulesButton = MakeButton("Refresh Modules");
  ModuleRow->addWidget(ModuleBox, 1);
  ModuleRow->addWidget(RefreshModulesButton);
  DumpLayout->addLayout(ModuleRow);
  auto *FileRow = new QHBoxLayout;
  ConfigureToolbarLayout(FileRow);
  auto *DumpFileEdit = new LineEdit;
  DumpFileEdit->setPlaceholderText(
      "Output file, empty = Data/Dumps/<module>_<pid>.bin");
  auto *DumpBrowse = MakeButton("Browse...");
  FileRow->addWidget(DumpFileEdit, 1);
  FileRow->addWidget(DumpBrowse);
  DumpLayout->addLayout(FileRow);
  auto *DumpRow = new QHBoxLayout;
  ConfigureToolbarLayout(DumpRow);
  auto *DumpModuleButton = MakeButton("Dump Module", true);
  auto *DumpBaseEdit = new LineEdit;
  DumpBaseEdit->setPlaceholderText("Base, e.g. 0x7FF612340000");
  auto *DumpSizeEdit = new LineEdit;
  DumpSizeEdit->setPlaceholderText("Size (bytes)");
  auto *DumpRangeButton = MakeButton("Dump Range");
  DumpRow->addWidget(DumpModuleButton);
  DumpRow->addWidget(DumpBaseEdit, 1);
  DumpRow->addWidget(DumpSizeEdit, 1);
  DumpRow->addWidget(DumpRangeButton);
  DumpLayout->addLayout(DumpRow);
  auto *DumpStatus = new BodyLabel(
      "Dumps module memory through the kernel read path "
      "(max 64 MiB per dump).");
  DumpLayout->addWidget(DumpStatus, 1);
  MemoryPages->addWidget(DumpTab);

  const auto ModuleRecords = std::make_shared<std::vector<INVENTORY_RECORD>>();
  const auto RefreshModules = [Page, ParsePidOnly, ModuleBox,
                               RefreshModulesButton, ModuleRecords] {
    ULONG ProcessId = 0;
    if (!ParsePidOnly(ProcessId))
      return;
    RefreshModulesButton->setEnabled(false);
    QPointer<QWidget> Guard(Page);
    std::thread([Guard, ProcessId, ModuleBox, RefreshModulesButton,
                 ModuleRecords] {
      const auto Modules =
          AegisNT::KernelResearch::QueryAll(IOCTL_ENUM_MODULES, {}, ProcessId);
      QMetaObject::invokeMethod(
          qApp, [Guard, Modules, ModuleBox, RefreshModulesButton,
                 ModuleRecords] {
            if (!Guard)
              return;
            RefreshModulesButton->setEnabled(true);
            ModuleBox->clear();
            *ModuleRecords = Modules;
            for (const INVENTORY_RECORD &Record : Modules) {
              ModuleBox->addItem(
                  QString("%1 @ %2 (%3 KB)")
                      .arg(QString::fromWCharArray(Record.Name))
                      .arg(AegisNT::KernelResearch::Hex(Record.Address))
                      .arg(Record.SizeBytes / 1024));
            }
            if (Modules.empty())
              ModuleBox->addItem("(no modules enumerated)");
          });
    }).detach();
  };
  QObject::connect(RefreshModulesButton, &QPushButton::clicked, Page,
                   RefreshModules);
  QObject::connect(MemoryTabs, &TabBar::currentChanged, Page,
                   [Page, RefreshModules](int Index) {
                     if (Index == 4)
                       RefreshModules();
                   });

  const auto RunDump = [Page, ParsePidOnly, DumpFileEdit, DumpStatus](
                           ULONG_PTR Base, ULONG64 Size, const QString &Name) {
    ULONG ProcessId = 0;
    if (!ParsePidOnly(ProcessId))
      return;
    if (Base == 0) {
      ShowWarningNotice(Page, "Memory", "Enter a valid dump base address.");
      return;
    }
    QString Path = DumpFileEdit->text().trimmed();
    if (Path.isEmpty()) {
      QDir DumpDir(QCoreApplication::applicationDirPath());
      DumpDir.mkpath("Data/Dumps");
      Path = DumpDir.filePath(QString("Data/Dumps/%1_%2.bin")
                                  .arg(Name.isEmpty() ? "range" : Name)
                                  .arg(ProcessId));
    }
    DumpStatus->setText(QString("Dumping %1 byte(s) from %2 ...")
                            .arg(Size)
                            .arg(AegisNT::KernelResearch::Hex(Base)));
    QPointer<QWidget> Guard(Page);
    std::thread([Guard, ProcessId, Base, Size, Path, DumpStatus] {
      QDir().mkpath(QFileInfo(Path).absolutePath());
      QFile Output(Path);
      ULONG64 Written = 0;
      NTSTATUS LastError = 0;
      if (Output.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        unsigned char Buffer[4096];
        while (Written < Size) {
          ULONG Take = static_cast<ULONG>(
              std::min<ULONG64>(sizeof(Buffer), Size - Written));
          ULONG Read = 0;
          if (!ReadMemory(ProcessId, Base + Written, Buffer, Take, &Read) ||
              Read == 0) {
            LastError = G_LastAegisCoreError;
            break;
          }
          if (Output.write(reinterpret_cast<const char *>(Buffer), Read) !=
              Read) {
            LastError = -1;
            break;
          }
          Written += Read;
        }
        Output.close();
      }
      QMetaObject::invokeMethod(
          qApp, [Guard, Path, Written, Size, LastError, DumpStatus] {
            if (!Guard)
              return;
            if (Written == 0) {
              DumpStatus->setText(
                  QString("Dump failed (error %1).").arg(LastError));
              ShowErrorNotice(Guard, "Memory",
                              QString("Dump failed (error %1).")
                                  .arg(LastError));
              return;
            }
            const QString Message =
                Written == Size
                    ? QString("Dumped %1 byte(s) to %2.")
                          .arg(Written)
                          .arg(QDir::toNativeSeparators(Path))
                    : QString("Partial dump: %1 of %2 byte(s) to %3 "
                              "(error %4).")
                          .arg(Written)
                          .arg(Size)
                          .arg(QDir::toNativeSeparators(Path))
                          .arg(LastError);
            DumpStatus->setText(Message);
            if (Written == Size)
              ShowSuccessNotice(Guard, "Memory", Message);
            else
              ShowWarningNotice(Guard, "Memory", Message);
          });
    }).detach();
  };
  QObject::connect(DumpBrowse, &QPushButton::clicked, Page,
                   [Page, DumpFileEdit] {
                     const QString Path = FluentFileDialog::getSaveFileName(
                         Page, "Dump output file", QString(),
                         "Binary files (*.bin);;All files (*)");
                     if (!Path.isEmpty())
                       DumpFileEdit->setText(Path);
                   });
  QObject::connect(
      DumpModuleButton, &QPushButton::clicked, Page,
      [Page, ModuleBox, ModuleRecords, DumpStatus, RunDump] {
        const int Index = ModuleBox->currentIndex();
        if (Index < 0 || Index >= static_cast<int>(ModuleRecords->size())) {
          ShowWarningNotice(Page, "Memory",
                            "Refresh and select a module first.");
          return;
        }
        const INVENTORY_RECORD &Record = ModuleRecords->at(Index);
        RunDump(Record.Address, std::min<ULONG64>(Record.SizeBytes,
                                                  64ull << 20),
                QString::fromWCharArray(Record.Name));
      });
  QObject::connect(
      DumpRangeButton, &QPushButton::clicked, Page,
      [DumpBaseEdit, DumpSizeEdit, DumpStatus, RunDump] {
        const ULONG_PTR Base =
            DumpBaseEdit->text().trimmed().toULongLong(nullptr, 0);
        const ULONG64 Size =
            DumpSizeEdit->text().trimmed().toULongLong(nullptr, 0);
        RunDump(Base, Size, QString());
      });

  MemoryTabs->addTab("pte", "PTE Walk", Fluent::IconType::COMMAND_PROMPT);
  auto *PteTab = new AegisNT::PageBase(nullptr);
  auto *PteLayout = PteTab->GetMainLayout();
  PteLayout->setContentsMargins(0, 0, 0, 0);
  PteLayout->setSpacing(KCompactPageSpacing);
  auto *PteRow = new QHBoxLayout;
  ConfigureToolbarLayout(PteRow);
  auto *WalkButton = MakeButton("Walk Page Tables", true);
  auto *WalkStatus = new BodyLabel(
      "Walks CR3 -> PML4E -> PDPTE -> PDE -> PTE for the address above "
      "(PID 0 = System).");
  PteRow->addWidget(WalkButton);
  PteRow->addWidget(WalkStatus, 1);
  PteLayout->addLayout(PteRow);
  auto *WalkTable = MakeTable({"Level", "Entry Physical", "Entry Value",
                               "Next Physical", "Flags"});
  WalkTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
  WalkTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
  WalkTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
  WalkTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
  WalkTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
  PteLayout->addWidget(WalkTable, 1);
  MemoryPages->addWidget(PteTab);

  QObject::connect(
      WalkButton, &QPushButton::clicked, Page,
      [Page, Pid, Address, WalkButton, WalkStatus, WalkTable] {
        bool PidOk = false, AddressOk = false;
        const qulonglong PidValue = Pid->text().trimmed().toULongLong(&PidOk, 0);
        const qulonglong AddressValue =
            Address->text().trimmed().toULongLong(&AddressOk, 0);
        if (!PidOk || PidValue > 0xFFFFFFFFull || !AddressOk ||
            AddressValue == 0) {
          ShowWarningNotice(Page, "Memory",
                            "Enter a valid PID and address above.");
          return;
        }
        WalkButton->setEnabled(false);
        WalkStatus->setText("Walking page tables...");
        QPointer<QWidget> Guard(Page);
        std::thread([Guard, Pid = static_cast<ULONG>(PidValue), AddressValue,
                     WalkButton, WalkStatus, WalkTable] {
          std::vector<INVENTORY_RECORD> Records;
          INVENTORY_LIST_HEADER Header{};
          const bool Success =
              QueryPteWalk(Pid, AddressValue, Records, &Header);
          QMetaObject::invokeMethod(
              qApp, [Guard, Success, Records, WalkButton, WalkStatus,
                     WalkTable] {
                if (!Guard)
                  return;
                WalkButton->setEnabled(true);
                WalkTable->setRowCount(0);
                if (!Success || Records.empty()) {
                  const QString Message =
                      QString("Page-table walk failed (error %1).")
                          .arg(G_LastAegisCoreError);
                  WalkStatus->setText(Message);
                  ShowErrorNotice(Guard, "Memory", Message);
                  return;
                }
                for (const INVENTORY_RECORD &Record : Records) {
                  const int Row = WalkTable->rowCount();
                  WalkTable->insertRow(Row);
                  const QStringList Values{
                      QString::fromWCharArray(Record.Name),
                      AegisNT::KernelResearch::Hex(Record.Address),
                      AegisNT::KernelResearch::Hex(Record.Value[0]),
                      Record.Value[1]
                          ? AegisNT::KernelResearch::Hex(Record.Value[1])
                          : "-",
                      QString::fromWCharArray(Record.Detail)};
                  for (int Column = 0; Column < Values.size(); ++Column)
                    WalkTable->setItem(Row, Column,
                                       new QTableWidgetItem(Values[Column]));
                }
                WalkStatus->setText(QString("%1 level(s) walked.").arg(Records.size()));
              });
        }).detach();
      });

  MemoryTabs->addTab("region", "Region Ops", Fluent::IconType::EDIT);
  auto *OpsTab = new AegisNT::PageBase(nullptr);
  auto *OpsLayout = OpsTab->GetMainLayout();
  OpsLayout->setContentsMargins(0, 0, 0, 0);
  OpsLayout->setSpacing(KCompactPageSpacing);
  auto *ProtectRow = new QHBoxLayout;
  ConfigureToolbarLayout(ProtectRow);
  auto *OpsAddrEdit = new LineEdit;
  OpsAddrEdit->setPlaceholderText("Address, e.g. 0x7FF612340000");
  auto *OpsSizeEdit = new LineEdit;
  OpsSizeEdit->setPlaceholderText("Size (bytes)");
  auto *OpsProtectBox = new ComboBox;
  OpsProtectBox->addItems({"PAGE_NOACCESS", "PAGE_READONLY",
                           "PAGE_READWRITE", "PAGE_EXECUTE_READ",
                           "PAGE_EXECUTE_READWRITE"});
  OpsProtectBox->setCurrentIndex(2);
  auto *OpsApplyButton = MakeButton("Change Protect");
  ProtectRow->addWidget(OpsAddrEdit, 1);
  ProtectRow->addWidget(OpsSizeEdit, 1);
  ProtectRow->addWidget(OpsProtectBox);
  ProtectRow->addWidget(OpsApplyButton);
  OpsLayout->addLayout(ProtectRow);
  auto *AllocRow = new QHBoxLayout;
  ConfigureToolbarLayout(AllocRow);
  auto *OpsAllocSizeEdit = new LineEdit;
  OpsAllocSizeEdit->setPlaceholderText("Alloc size (bytes)");
  auto *OpsAllocProtectBox = new ComboBox;
  OpsAllocProtectBox->addItems({"PAGE_READWRITE", "PAGE_EXECUTE_READWRITE",
                                "PAGE_EXECUTE_READ"});
  auto *OpsAllocReserveCheck = new CheckBox("Reserve only");
  auto *OpsAllocButton = MakeButton("Allocate");
  auto *OpsFreeEdit = new LineEdit;
  OpsFreeEdit->setPlaceholderText("Free base address");
  auto *OpsFreeButton = MakeButton("Free");
  AllocRow->addWidget(OpsAllocSizeEdit, 1);
  AllocRow->addWidget(OpsAllocProtectBox);
  AllocRow->addWidget(OpsAllocReserveCheck);
  AllocRow->addWidget(OpsAllocButton);
  AllocRow->addWidget(OpsFreeEdit, 1);
  AllocRow->addWidget(OpsFreeButton);
  OpsLayout->addLayout(AllocRow);
  auto *OpsStatus = new BodyLabel(
      "Kernel-mode region control: protection changes, allocation, and "
      "release in the target process (PID above).");
  OpsStatus->setWordWrap(true);
  OpsLayout->addWidget(OpsStatus, 1);
  MemoryPages->addWidget(OpsTab);

  QObject::connect(
      OpsApplyButton, &QPushButton::clicked, Page,
      [Page, ParsePidOnly, OpsAddrEdit, OpsSizeEdit, OpsProtectBox,
       OpsStatus] {
        ULONG ProcessId = 0;
        if (!ParsePidOnly(ProcessId))
          return;
        const ULONG_PTR Target =
            OpsAddrEdit->text().trimmed().toULongLong(nullptr, 0);
        const ULONG64 Size =
            OpsSizeEdit->text().trimmed().toULongLong(nullptr, 0);
        if (Target == 0 || Size == 0) {
          ShowWarningNotice(Page, "Memory",
                            "Enter a valid address and size.");
          return;
        }
        const ULONG ProtectTable[] = {PAGE_NOACCESS, PAGE_READONLY,
                                      PAGE_READWRITE, PAGE_EXECUTE_READ,
                                      PAGE_EXECUTE_READWRITE};
        ULONG OldProtect = 0;
        if (!KernelProtectMemory(ProcessId, Target, Size,
                                 ProtectTable[OpsProtectBox->currentIndex()],
                                 &OldProtect)) {
          const QString Message =
              QString("Change protect failed (error %1).")
                  .arg(G_LastAegisCoreError);
          OpsStatus->setText(Message);
          ShowErrorNotice(Page, "Memory", Message);
          return;
        }
        const QString Message =
            QString("Protection changed; old protect 0x%1.")
                .arg(OldProtect, 8, 16, QLatin1Char('0'))
                .toUpper();
        OpsStatus->setText(Message);
        ShowSuccessNotice(Page, "Memory", Message);
      });
  QObject::connect(
      OpsAllocButton, &QPushButton::clicked, Page,
      [Page, ParsePidOnly, OpsAllocSizeEdit, OpsAllocProtectBox,
       OpsAllocReserveCheck, OpsStatus] {
        ULONG ProcessId = 0;
        if (!ParsePidOnly(ProcessId))
          return;
        const ULONG64 Size =
            OpsAllocSizeEdit->text().trimmed().toULongLong(nullptr, 0);
        if (Size == 0 || Size > (256ull << 20)) {
          ShowWarningNotice(Page, "Memory",
                            "Alloc size must be 1 byte - 256 MiB.");
          return;
        }
        const ULONG ProtectTable[] = {PAGE_READWRITE,
                                      PAGE_EXECUTE_READWRITE,
                                      PAGE_EXECUTE_READ};
        ULONG_PTR Base = 0;
        if (!KernelAllocMemory(ProcessId, Size,
                               ProtectTable[OpsAllocProtectBox->currentIndex()],
                               OpsAllocReserveCheck->isChecked(), &Base)) {
          const QString Message =
              QString("Allocate failed (error %1).")
                  .arg(G_LastAegisCoreError);
          OpsStatus->setText(Message);
          ShowErrorNotice(Page, "Memory", Message);
          return;
        }
        const QString Message =
            QString("Allocated at %1.")
                .arg(AegisNT::KernelResearch::Hex(Base));
        OpsStatus->setText(Message);
        ShowSuccessNotice(Page, "Memory", Message);
      });
  QObject::connect(
      OpsFreeButton, &QPushButton::clicked, Page,
      [Page, ParsePidOnly, OpsFreeEdit, OpsStatus] {
        ULONG ProcessId = 0;
        if (!ParsePidOnly(ProcessId))
          return;
        const ULONG_PTR Base =
            OpsFreeEdit->text().trimmed().toULongLong(nullptr, 0);
        if (Base == 0) {
          ShowWarningNotice(Page, "Memory", "Enter a valid base address.");
          return;
        }
        if (!KernelFreeMemory(ProcessId, Base)) {
          const QString Message =
              QString("Free failed (error %1).").arg(G_LastAegisCoreError);
          OpsStatus->setText(Message);
          ShowErrorNotice(Page, "Memory", Message);
          return;
        }
        const QString Message = QString("Region at %1 released.")
                                    .arg(AegisNT::KernelResearch::Hex(Base));
        OpsStatus->setText(Message);
        ShowSuccessNotice(Page, "Memory", Message);
      });

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
  // PID 0 时走专用内核读写 IOCTL(0x83C/0x83D,支持 MDL/CR0/直写方式),
  // 否则保持普通进程内存读写�?
  const auto ReadTarget = [MethodBox](ULONG ProcessId, ULONG_PTR Address,
                                      void *Buffer, ULONG Size,
                                      ULONG *BytesRead) {
    if (ProcessId == 0)
      return KernelReadMemory(Address, Buffer, Size, BytesRead,
                              static_cast<KRNL_MEMRW_METHOD>(
                                  MethodBox->currentIndex()));
    return ReadMemory(ProcessId, Address, Buffer, Size, BytesRead);
  };
  const auto WriteTarget = [MethodBox](ULONG ProcessId, ULONG_PTR Address,
                                       void *Buffer, ULONG Size) {
    if (ProcessId == 0)
      return KernelWriteMemory(Address, Buffer, Size,
                               static_cast<KRNL_MEMRW_METHOD>(
                                   MethodBox->currentIndex()));
    return WriteMemory(ProcessId, Address, Buffer, Size);
  };
  QObject::connect(
      ReadButton, &QPushButton::clicked, Page,
      [Page, ReadSize, HexView, AsciiView, Status, ParseTarget, ReadTarget] {
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
        if (!ReadTarget(ProcessId, TargetAddress, Buffer.data(), Size,
                        &BytesRead)) {
          const QString Message =
              QString("Read failed (error %1)").arg(G_LastAegisCoreError);
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
      ScanButton, &QPushButton::clicked, Page,
      [Page, Pid, ScanButton, SuspectTable, SuspectStatus] {
        bool Ok = false;
        const qulonglong PidValue = Pid->text().trimmed().toULongLong(&Ok);
        if (!Ok || PidValue == 0 || PidValue > 0xFFFFFFFFull) {
          ShowWarningNotice(Page, "Memory",
                            "Enter a valid target process ID for the scan.");
          return;
        }
        ScanButton->setEnabled(false);
        SuspectStatus->setText("Scanning...");
        QPointer<QWidget> Guard(Page);
        std::thread([Guard, PidValue, ScanButton, SuspectTable, SuspectStatus] {
          SUSPECT_MEMORY_OUTPUT Output{};
          const bool Success = SuspiciousMemoryScan(
              static_cast<ULONG>(PidValue), &Output);
          QMetaObject::invokeMethod(
              qApp,
              [Guard, PidValue, ScanButton, SuspectTable, SuspectStatus,
               Success, Output]() {
                if (!Guard)
                  return;
                ScanButton->setEnabled(true);
                SuspectTable->setRowCount(0);
                if (!Success) {
                  const QString Message =
                      QString("Scan failed (error %1)")
                          .arg(G_LastAegisCoreError);
                  SuspectStatus->setText(Message);
                  ShowErrorNotice(Guard, "Memory", Message);
                  return;
                }
                for (ULONG Index = 0; Index < Output.Count; ++Index) {
                  const SUSPECT_MEMORY_REGION &Region =
                      Output.Regions[Index];
                  const int Row = SuspectTable->rowCount();
                  SuspectTable->insertRow(Row);
                  SuspectTable->setItem(
                      Row, 0,
                      new QTableWidgetItem(
                          QString("0x%1")
                              .arg(Region.Base, 16, 16, QLatin1Char('0'))
                              .toUpper()));
                  SuspectTable->setItem(
                      Row, 1,
                      new QTableWidgetItem(
                          QString("%1 bytes").arg(Region.Size)));
                  SuspectTable->setItem(
                      Row, 2,
                      new QTableWidgetItem(QString("0x%1")
                                               .arg(Region.Protect, 8, 16,
                                                    QLatin1Char('0'))
                                               .toUpper()));
                  SuspectTable->setItem(
                      Row, 3,
                      new QTableWidgetItem(
                          Region.Type == 0x00020000 /* MEM_PRIVATE */
                              ? "Private"
                              : QString("0x%1")
                                    .arg(Region.Type, 8, 16,
                                         QLatin1Char('0'))));
                  SuspectTable->setItem(
                      Row, 4,
                      new QTableWidgetItem(
                          Region.Flags & SUSPECT_FLAG_UNBACKED_EXEC
                              ? "Unbacked executable"
                              : "-"));
                }
                const QString Message =
                    QString("%1 suspect region(s) in PID %2 "
                            "(%3 total scanned)")
                        .arg(Output.Count)
                        .arg(PidValue)
                        .arg(Output.TotalCount);
                SuspectStatus->setText(Message);
              });
        }).detach();
      });
  QObject::connect(
      WriteButton, &QPushButton::clicked, Page,
      [Page, HexView, Status, ParseTarget, LastTransaction, RollbackButton,
       ReadTarget, WriteTarget] {
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
        if (!ReadTarget(ProcessId, TargetAddress, Before.data(),
                        static_cast<ULONG>(Before.size()), &BeforeRead) ||
            BeforeRead != Before.size()) {
          ShowErrorNotice(Page, "Memory", "Pre-write read failed; no write was attempted.");
          return;
        }
        Before.resize(BeforeRead);
        const auto Modules = ProcessId == 0
            ? AegisNT::KernelResearch::QueryAll(IOCTL_ENUM_KERNEL_MODULES)
            : std::vector<INVENTORY_RECORD>{};
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
        if (!WriteTarget(ProcessId, TargetAddress, Bytes.data(),
                         static_cast<ULONG>(Bytes.size()))) {
          const QString Message =
              QString("Write failed (error %1)").arg(G_LastAegisCoreError);
          Status->setText(Message);
          ShowErrorNotice(Page, "Memory", Message);
        } else {
          std::vector<unsigned char> Verify(Bytes.size());
          ULONG VerifiedRead = 0;
          const bool Verified =
              ReadTarget(ProcessId, TargetAddress, Verify.data(),
                         static_cast<ULONG>(Verify.size()), &VerifiedRead) &&
              VerifiedRead == Bytes.size() && Verify == Bytes;
          if (!Verified) {
            const bool Restored =
                WriteTarget(ProcessId, TargetAddress, Before.data(),
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
            const QByteArray AuditLine =
                QJsonDocument(Record).toJson(QJsonDocument::Compact) + '\n';
            if (Audit.write(AuditLine) != AuditLine.size())
              AppendConsoleOutput("[WARN] Memory: Kernel write succeeded, but "
                                  "the audit record could not be written: " +
                                  Audit.errorString() + "\n");
          } else
            AppendConsoleOutput("[WARN] Memory: Kernel write succeeded, but "
                                "the audit log could not be opened: " +
                                Audit.errorString() + "\n");
          const QString Message = QString("Wrote and verified %1 byte(s). Transaction %2")
                                      .arg(Bytes.size()).arg(Tx.Id.left(8));
          Status->setText(Message);
          ShowSuccessNotice(Page, "Memory", Message);
        }
      });
  QObject::connect(RollbackButton, &QPushButton::clicked, Page,
      [Page, Status, ParseTarget, LastTransaction, RollbackButton, ReadTarget,
       WriteTarget] {
        if (!LastTransaction->has_value()) return;
        ULONG ProcessId = 0; ULONG_PTR TargetAddress = 0;
        if (!ParseTarget(ProcessId, TargetAddress)) return;
        auto &Tx = LastTransaction->value();
        if (TargetAddress != Tx.Address) {
          ShowWarningNotice(Page, "Memory", "Current address does not match the last transaction."); return;
        }
        std::vector<unsigned char> Current(Tx.After.size()); ULONG Read = 0;
        if (!ReadTarget(ProcessId, Tx.Address, Current.data(), static_cast<ULONG>(Current.size()), &Read) ||
            QByteArray(reinterpret_cast<const char *>(Current.data()), Read) != Tx.After) {
          ShowWarningNotice(Page, "Memory", "Memory changed after the transaction; rollback refused."); return;
        }
        QByteArray RestoreBytes = Tx.Before;
        if (!WriteTarget(ProcessId, Tx.Address, RestoreBytes.data(), static_cast<ULONG>(RestoreBytes.size()))) {
          ShowErrorNotice(Page, "Memory", "Rollback write failed."); return;
        }
        Tx.RolledBack = true; RollbackButton->setEnabled(false);
        Status->setText("Last transaction rolled back and verified on next read.");
        ShowSuccessNotice(Page, "Memory", "Last write transaction rolled back.");
      });
  QObject::connect(MemoryTabs, &TabBar::currentChanged, Page,
      [PhysicalTable](int Index) {
        if (Index != 1) return;
        const auto Records = AegisNT::KernelResearch::QueryAll(IOCTL_QUERY_MEMORY);
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

#include "Source/UI/Pages/DriverPage.cpp"

QWidget *CreateDriverPage() { return new DriverManagerPage; }

#include "Source/UI/Pages/ServicePage.cpp"

QWidget *CreateServiceManagerPage() { return new ServiceManagerPage; }
