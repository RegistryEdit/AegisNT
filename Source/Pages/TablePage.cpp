// ============================================================
// 系统表页：查看内核系统表（IDT/GDT/Hal 调度/DPC/IO Timer/
// PiDDB 等）槽位内容，支持缓存移除与定时刷新。
// ============================================================
#include "../../Platform/AegisCoreCall.h"

QWidget *CreateTablePage() {
  struct TableQueryResult {
    SYSTEM_TABLES_OUTPUT Summary{};
    std::array<SYSTEM_TABLE_ENTRIES_OUTPUT, 5> Entries{};
    std::array<bool, 5> Available{};
    PIDDB_CACHE_ENUM_OUTPUT PiDDB{};
    bool PiDDBAvailable = false;
    bool PiDDBQueried = false;
    MSR_QUERY_OUTPUT Msr{};
    bool MsrQueried = false;
    SYSTEM_TABLE_ENTRIES_OUTPUT HalDisp{};
    bool HalDispAvailable = false;
    bool HalDispQueried = false;
    DPC_ENUM_OUTPUT Dpc{};
    bool DpcAvailable = false;
    bool DpcQueried = false;
    DWORD ErrorCode = ERROR_SUCCESS;
    bool Success = false;
  };
  struct TablePageState {
    std::shared_ptr<TableQueryResult> Result =
        std::make_shared<TableQueryResult>();
    std::atomic_bool Refreshing = false;
    std::atomic_bool TabLoading = false;
    std::vector<INVENTORY_RECORD> Modules;
    // 与表格显示行同步的可移除目标；0 表示该行不可移除
    QVector<quintptr> RemoveTargets;
  };

  auto *Page = new QWidget;
  auto *Layout = new QVBoxLayout(Page);
  ConfigurePageLayout(Layout);
  auto *Toolbar = new QHBoxLayout;
  ConfigureToolbarLayout(Toolbar);
  auto *Kind = new ComboBox;
  Kind->addItems({"InterruptDescriptorTable", "I/O Timer", "SSDT", "ShadowSSDT",
                  "GlobalDescriptorTable", "PiDDBCacheTable", "CPU Registers",
                  "MSR Watch", "HalDispatchTable", "HalPrivateDispatchTable",
                  "DPC"});
  Kind->setCurrentIndex(0);
  Kind->setMinimumWidth(300);
  auto *Search = new SearchLineEdit;
  Search->setPlaceholderText("Search index, name, address, or metadata");
  Search->setClearButtonEnabled(true);
  Search->setMaximumWidth(320);
  auto *Status = new BodyLabel("Not queried.");
  auto *RefreshIndicator = new IndeterminateProgressRing(Page, false);
  RefreshIndicator->setFixedSize(22, 22);
  RefreshIndicator->hide();
  auto *Refresh = MakeButton("Refresh", true);
  auto *MsrEnable = MakeButton("Enable Watch");
  auto *MsrDisable = MakeButton("Disable Watch");
  MsrDisable->setEnabled(false);
  Toolbar->addWidget(Kind);
  Toolbar->addWidget(Search);
  Toolbar->addStretch();
  Toolbar->addWidget(Status);
  Toolbar->addWidget(RefreshIndicator);
  Toolbar->addWidget(MsrEnable);
  Toolbar->addWidget(MsrDisable);
  Toolbar->addWidget(Refresh);
  Layout->addLayout(Toolbar);
  auto *Table = MakeTable({"Index", "Name", "Address", "Module / Symbol", "State", "Metadata"});
  Table->setContextMenuPolicy(Qt::CustomContextMenu);
  Table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
  Table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
  Layout->addWidget(Table, 1);
  const auto State = std::make_shared<TablePageState>();
  const auto Populate = [Kind, Search, Table, State] {
    auto TableState = State;
    Table->clearContents();
    Table->setRowCount(0);
    State->RemoveTargets.clear();
    const int Tab = Kind->currentIndex();
    const std::shared_ptr<TableQueryResult> Result = State->Result;
    const SYSTEM_TABLES_OUTPUT &Summary = Result->Summary;
    const QString SearchText = Search->text().trimmed();
    const auto AddRow = [Table, State,
                         SearchText](const QString &Index, const QString &Name,
                                     const QString &Address,
                                     const QString &Metadata = QString(),
                                     quint64 TargetAddress = 0,
                                     quintptr RemoveTarget = 0) {
      AegisNT::KernelResearch::AddressInfo Owner;
      if (TargetAddress)
        Owner = AegisNT::KernelResearch::ResolveAddress(TargetAddress, State->Modules);
      const QString Ownership = TargetAddress
          ? (Owner.Module.isEmpty() ? QString("-") : Owner.Module + QString("+0x%1").arg(Owner.Rva, 0, 16).toUpper()) +
                (Owner.Symbol.isEmpty() ? QString() : " | " + Owner.Symbol)
          : QString("-");
      const QString OwnershipState = TargetAddress ? Owner.Status : QString("-");
      if (!SearchText.isEmpty() &&
          !(Index + " " + Name + " " + Address + " " + Ownership + " " + OwnershipState + " " + Metadata)
               .contains(SearchText, Qt::CaseInsensitive))
        return;
      const int Row = Table->rowCount();
      Table->insertRow(Row);
      Table->setItem(Row, 0, new QTableWidgetItem(Index));
      Table->setItem(Row, 1, new QTableWidgetItem(Name));
      Table->setItem(Row, 2, new QTableWidgetItem(Address));
      Table->setItem(Row, 3, new QTableWidgetItem(Ownership));
      auto *StateItem = new QTableWidgetItem(OwnershipState);
      if (OwnershipState == "OutsideModule")
        StateItem->setForeground(QColor(220, 70, 70));
      Table->setItem(Row, 4, StateItem);
      Table->setItem(Row, 5, new QTableWidgetItem(Metadata));
      Table->setRowHeight(Row, KCompactTableRowHeight);
      State->RemoveTargets.push_back(RemoveTarget);
    };
    if (Tab < 5 && Result->Available[Tab]) {
      const auto &Output = Result->Entries[Tab];
      AddRow(
          "-", "Table Base",
          QString("0x%1")
              .arg(Output.TableBase, sizeof(ULONG_PTR) * 2, 16,
                   QLatin1Char('0'))
              .toUpper(),
          QString("%1 of %2 entries").arg(Output.Count).arg(Output.TotalCount), Output.TableBase);
      for (ULONG Index = 0; Index < Output.Count; ++Index) {
        const SYSTEM_TABLE_ENTRY &Entry = Output.Entries[Index];
        AddRow(
            QString::number(Entry.Index), SystemTableEntryName(Tab, Entry),
            QString("0x%1")
                .arg(Entry.Address, sizeof(ULONG_PTR) * 2, 16, QLatin1Char('0'))
                .toUpper(),
            QString::number(Entry.ArgumentBytes), Entry.Address);
      }
      return;
    }
    if (Tab == 5 && Result->PiDDBQueried && Result->PiDDBAvailable) {
      AddRow("-", "PiDDBCacheTable",
             QString("0x%1")
                 .arg(Result->PiDDB.TableAddress, sizeof(ULONG_PTR) * 2, 16,
                      QLatin1Char('0'))
                 .toUpper(),
             QString("%1 of %2 entries")
                 .arg(Result->PiDDB.Count)
                 .arg(Result->PiDDB.TotalCount));
      AddRow("-", "Table Discovery", "-",
             QString("LEA %1/%2  LIST %3/%4  SIG %5/%6")
                 .arg(Result->PiDDB.LeaScore)
                 .arg(Result->PiDDB.LeaCandidates)
                 .arg(Result->PiDDB.ListScore)
                 .arg(Result->PiDDB.ListCandidates)
                 .arg(Result->PiDDB.SigScore)
                 .arg(Result->PiDDB.SigCandidates));
      if (Result->PiDDB.Count == 0) {
        const bool Found = Result->PiDDB.TableAddress != 0;
        AddRow("-", Found ? "(no entries)" : "(not found)", "-",
               Found ? "No entries were returned; the cache may be empty or "
                       "may have changed during enumeration."
                     : "No validated AVL or LIST candidate was found.");
      }
      for (ULONG Index = 0; Index < Result->PiDDB.Count; ++Index) {
        const PIDDB_CACHE_ENTRY_INFO &Entry = Result->PiDDB.Entries[Index];
        const QString Name = Entry.DriverName[0]
                                 ? QString::fromWCharArray(Entry.DriverName)
                                 : "(unknown)";
        const QString Address =
            QString("0x%1")
                .arg(Entry.Address, sizeof(ULONG_PTR) * 2, 16, QLatin1Char('0'))
                .toUpper();
        const QString Metadata =
            QString("TimeDateStamp: %1 | LoadStatus: 0x%2")
                .arg(FormatPeTimeDateStamp(Entry.TimeDateStamp))
                .arg(static_cast<quint32>(Entry.LoadStatus), 8, 16,
                     QLatin1Char('0'))
                .toUpper();
        AddRow(QString::number(Entry.Index), Name, Address, Metadata, 0,
               static_cast<quintptr>(Entry.Address));
      }
      return;
    }
    const auto Hex = [](ULONG_PTR Value) {
      return QString("0x%1")
          .arg(Value, sizeof(ULONG_PTR) * 2, 16, QLatin1Char('0'))
          .toUpper();
    };
    // HalDispatchTable(8) / HalPrivateDispatchTable(9)：先加 Table Base 行，
    // 再逐条渲染槽位；槽位名参考 WinUI 的 SystemTableEntryName，公开表的前两个
    // 槽位有可读名，其余显示 Slot 编号。
    if ((Tab == 8 || Tab == 9) && Result->HalDispQueried &&
        Result->HalDispAvailable) {
      const auto &Output = Result->HalDisp;
      const int NameKind = Tab == 8 ? HAL_DISPATCH_TABLE_KIND_PUBLIC
                                    : HAL_DISPATCH_TABLE_KIND_PRIVATE;
      const auto HalSlotName = [](int Kind, ULONG Index) {
        if (Kind == HAL_DISPATCH_TABLE_KIND_PUBLIC) {
          static const std::array<const char *, 2> PublicSlots{
              "HaliQuerySystemInformation", "HalSetSystemInformation"};
          if (Index < PublicSlots.size())
            return QString::fromLatin1(PublicSlots[Index]);
          return QString("HalDispatchSlot %1").arg(Index, 0, 16).toUpper();
        }
        return QString("PrivateSlot %1").arg(Index, 0, 16).toUpper();
      };
      AddRow("-", "Table Base", Hex(Output.TableBase),
             QString("%1 of %2 entries")
                 .arg(Output.Count)
                 .arg(Output.TotalCount),
             Output.TableBase);
      for (ULONG Index = 0; Index < Output.Count; ++Index) {
        const SYSTEM_TABLE_ENTRY &Entry = Output.Entries[Index];
        AddRow(QString::number(Entry.Index), HalSlotName(NameKind, Entry.Index),
               Hex(Entry.Address), QString(), Entry.Address);
      }
      return;
    }
    // CPU 是定时器表/队列的归属，不是执行目标；输出是最多 256 条的样本。
    // DpcSource 为 TimerTable 时附带原始到期时间（KiWait 解码 DPC 指针），为窗口扫描
    // 兜底路径时没有到期时间。
    if (Tab == 10 && Result->DpcQueried && Result->DpcAvailable) {
      const auto &Dpc = Result->Dpc;
      const ULONG RowCount = std::min<ULONG>(Dpc.Count, DPC_MAX_ENTRIES);
      const bool HasDiagnostics = (Dpc.SnapshotFlags & DPC_SNAPSHOT_DIAGNOSTICS_VALID) != 0;
      const bool TimerSource = Dpc.DpcSource == DPC_SOURCE_TIMER_TABLE;
      ULONG RepresentedCpus = 0;
      for (ULONG Index = 0; Index < RowCount; ++Index) {
        bool Seen = false;
        for (ULONG Previous = 0; Previous < Index; ++Previous)
          if (Dpc.Entries[Previous].Cpu == Dpc.Entries[Index].Cpu) { Seen = true; break; }
        if (!Seen) ++RepresentedCpus;
      }
      AddRow("-", TimerSource ? "Timer-associated DPCs" : "DPC Queue", "-",
             QString("%1 shown | %2 CPUs represented | %3 active CPUs")
                 .arg(RowCount)
                 .arg(RepresentedCpus)
                 .arg(Dpc.CpuCount));
      AddRow("-", "CPU Coverage", "-",
             QString("PRCBs read %1/%2 | %3 | CPU labels identify the owning table/queue")
                 .arg(Dpc.DpcPrcbCount).arg(Dpc.CpuCount)
                 .arg(HasDiagnostics && TimerSource
                          ? QString("TimerTables located %1/%2").arg(Dpc.DpcAcceptedCount).arg(Dpc.CpuCount)
                          : QString("table coverage unavailable")));
      if (HasDiagnostics) {
        AddRow("-", "Snapshot", "-",
               QString("%1 valid references observed before deduplication | %2 | %3")
                   .arg(Dpc.TotalCount)
                   .arg(Dpc.SnapshotFlags & DPC_SNAPSHOT_TRUNCATED
                            ? QString("truncated: CPU-balanced sample, limit %1").arg(DPC_MAX_ENTRIES)
                            : QString("within output capacity"))
                   .arg(Dpc.SnapshotFlags & DPC_SNAPSHOT_SCAN_INCOMPLETE
                            ? QString("some reads or walks incomplete; see driver log")
                            : QString("bounded scan finished")));
      } else {
        AddRow("-", "Snapshot", "-", "Legacy driver: CPU coverage/truncation diagnostics unavailable");
      }
      AddRow("-", "TimerTable", "-",
             Dpc.DpcSource == DPC_SOURCE_TIMER_TABLE
                 ? QString("KPRCB+0x%1 | entry+0x%2 | %3 buckets | decoded %4 | "
                           "undecodable %5")
                       .arg(Dpc.TimerTableOffset, 0, 16)
                       .arg(Dpc.TimerTableEntryOffset, 0, 16)
                       .arg(Dpc.TimerTableBuckets)
                       .arg(Dpc.TimerDecodedCount)
                       .arg(Dpc.TimerDecodeFailCount)
                       .toUpper()
                 : QString("not located — window-scan fallback in use"));
      AddRow("-", "KiWait Keys", "-",
             Dpc.KeyResolveSource == 1
                 ? QString("Never 0x%1 @ %2 | Always 0x%3 @ %4")
                       .arg(Dpc.KiWaitNeverValue, 0, 16)
                       .arg(Hex(Dpc.KiWaitNeverAddress))
                       .arg(Dpc.KiWaitAlwaysValue, 0, 16)
                       .arg(Hex(Dpc.KiWaitAlwaysAddress))
                       .toUpper()
                 : QString("not resolved — encoded timer DPCs unavailable"));
      AddRow("-", "PRCB Source", "-",
             Dpc.PrcbResolveSource == 1
                 ? QString("KiProcessorBlock export")
                 : (Dpc.PrcbResolveSource == 2
                        ? QString("KiProcessorBlock via verified accessor")
                        : QString("unresolved")));
      if (Dpc.DpcSource == DPC_SOURCE_WINDOW_SCAN) {
        AddRow("-", "DPC Scan", "-",
               QString("PRCBs %1 | candidates %2 | accepted heads %3 | "
                       "window 0x%4")
                   .arg(Dpc.DpcPrcbCount)
                   .arg(Dpc.DpcCandidateCount)
                   .arg(Dpc.DpcAcceptedCount)
                   .arg(Dpc.DpcScanWindow, 0, 16)
                   .toUpper());
      }
      if (Dpc.Count == 0)
        AddRow("-", "(idle)", "-",
               Dpc.DpcSource == DPC_SOURCE_TIMER_TABLE
                   ? QString("No usable timer DPCs found; TimerTable at "
                             "KPRCB+0x%1. Check key resolution and skipped entries")
                         .arg(Dpc.TimerTableOffset, 0, 16)
                         .toUpper()
                   : QString("No DPCs currently queued — normal when the CPU "
                             "is idle; accepted heads > 0 confirms the queue "
                             "scan works"));
      for (ULONG Index = 0; Index < RowCount; ++Index) {
        const DPC_ENUM_ENTRY &Entry = Dpc.Entries[Index];
        const QString Due = Entry.DueTime
            ? QString("Due: 0x%1").arg(Entry.DueTime, 0, 16).toUpper()
            : QString("Due: -");
        AddRow(QString::number(Entry.Index),
               QString(TimerSource ? "Timer CPU %1" : "Queue CPU %1").arg(Entry.Cpu),
               Hex(Entry.Routine),
               QString("Context: %1 | %2").arg(Hex(Entry.Context)).arg(Due),
               Entry.Routine, static_cast<quintptr>(Entry.DpcObject));
      }
      return;
    }
    if (Tab == 0) {
      AddRow("-", "IDT Base", Hex(Summary.IdtBase));
      AddRow("-", "IDT Limit", QString::number(Summary.IdtLimit));
    } else if (Tab == 1) {
      AddRow("-", "KUSER_SHARED_DATA", Hex(Summary.KuserSharedData));
      AddRow("-", "System Time",
             QString("0x%1")
                 .arg(Summary.SystemTime, 16, 16, QLatin1Char('0'))
                 .toUpper());
      AddRow("-", "Interrupt Time",
             QString("0x%1")
                 .arg(Summary.InterruptTime, 16, 16, QLatin1Char('0'))
                 .toUpper());
      AddRow("-", "Tick Count", QString::number(Summary.TickCount));
    } else if (Tab == 2) {
      AddRow("-", "SSDT Base", Hex(Summary.SsdtBase));
      AddRow("-", "Service Count", QString::number(Summary.SsdtCount));
      AddRow("-", "Argument Table", Hex(Summary.SsdtArgTable));
    } else if (Tab == 3) {
      AddRow("-", "Shadow SSDT Base", Hex(Summary.ShadowSsdtBase));
      AddRow("-", "Service Count", QString::number(Summary.ShadowSsdtCount));
      AddRow("-", "Argument Table", Hex(Summary.ShadowSsdtArgTable));
    } else if (Tab == 4) {
      AddRow("-", "GDT Base", Hex(Summary.GdtBase));
      AddRow("-", "GDT Limit", QString::number(Summary.GdtLimit));
    } else if (Tab == 5)
      AddRow("-", "PiDDBCacheTable", Hex(Summary.PiDDBCacheTable));
    else if (Tab == 7 && Result->MsrQueried) {
      const auto &Msr = Result->Msr;
      const auto Hex64 = [](ULONG64 Value) {
        return QString("0x%1")
            .arg(Value, 16, 16, QLatin1Char('0'))
            .toUpper();
      };
      const auto AddMsrRow = [&](const QString &Name, ULONG64 Value,
                                 const QString &Metadata,
                                 const QString &State = QString()) {
        auto *StateItem = new QTableWidgetItem(State.isEmpty() ? "-" : State);
        if (State == "Changed")
          StateItem->setForeground(QColor(220, 70, 70));
        else if (State == "Hooked")
          StateItem->setForeground(QColor(220, 70, 70));
        else if (State == "OK")
          StateItem->setForeground(QColor(40, 160, 40));
        if (!SearchText.isEmpty() &&
            !(Name + " " + Hex64(Value) + " " + Metadata + " " + State)
                 .contains(SearchText, Qt::CaseInsensitive))
          return;
        const int Row = Table->rowCount();
        Table->insertRow(Row);
        Table->setItem(Row, 0, new QTableWidgetItem("-"));
        Table->setItem(Row, 1, new QTableWidgetItem(Name));
        Table->setItem(Row, 2, new QTableWidgetItem(Hex64(Value)));
        Table->setItem(Row, 3, new QTableWidgetItem("-"));
        Table->setItem(Row, 4, StateItem);
        Table->setItem(Row, 5, new QTableWidgetItem(Metadata));
        Table->setRowHeight(Row, KCompactTableRowHeight);
        TableState->RemoveTargets.push_back(0);
      };
      AddMsrRow("KiSystemCall64", Msr.KiSystemCall64, "Expected LSTAR target",
                Msr.KiSystemCall64 ? "OK" : "Unknown");
      AddMsrRow("IA32_LSTAR", Msr.LstarValue,
                Msr.LstarHooked ? "Mismatch vs KiSystemCall64"
                                : "Matches KiSystemCall64",
                Msr.LstarHooked ? "Hooked" : (Msr.LstarUnknown ? "Unknown" : "OK"));
      AddMsrRow("IA32_EFER", Msr.EferValue, "Extended feature enable");
      AddMsrRow("IA32_STAR", Msr.StarValue, "Syscall segment selectors");
      AddMsrRow("IA32_FMASK", Msr.FmaskValue, "Syscall RFLAGS mask");
      AddMsrRow("IA32_SYSENTER_EIP", Msr.SysenterEip, "x86 SYSENTER entry");
      AddRow("-", "Watch Status",
             Msr.WatchActive ? "Active" : "Inactive",
             "Baseline captured on Enable Watch");
      for (ULONG I = 0; I < MSR_WATCH_COUNT; ++I) {
        const auto &Watch = Msr.WatchValues[I];
        AddMsrRow(QString::fromWCharArray(Watch.Name),
                  Watch.Value,
                  QString("Baseline: 0x%1")
                      .arg(Watch.Baseline, 16, 16, QLatin1Char('0'))
                      .toUpper(),
                  Watch.Changed ? "Changed" : "OK");
      }
    }
    else {
      AddRow("-", "CR0", Hex(Summary.Cr0), "Protection and paging controls");
      AddRow("-", "CR2", Hex(Summary.Cr2), "Last page-fault linear address");
      AddRow("-", "CR3", Hex(Summary.Cr3), "Current page-table root");
      AddRow("-", "CR4", Hex(Summary.Cr4), "Extended processor controls");
      AddRow("-", "IA32_LSTAR", Hex(Summary.MsrLstar), "64-bit syscall entry");
      AddRow("-", "IA32_STAR", Hex(Summary.MsrStar), "Syscall segment selectors");
      AddRow("-", "IA32_FMASK", Hex(Summary.MsrFmask), "Syscall RFLAGS mask");
      AddRow("-", "IA32_EFER", Hex(Summary.MsrEfer), "Extended feature enable");
    }
  };
  const auto LoadTabAsync = std::make_shared<std::function<void(int, bool)>>();
  *LoadTabAsync = [Page, Kind, Status, Refresh, RefreshIndicator, State,
                   Populate](int Tab, bool ShowResult) {
    if (Tab < 0 || State->Refreshing.load())
      return;

    const std::shared_ptr<TableQueryResult> Result = State->Result;
    const bool AlreadyLoaded =
        Tab == 6 || (Tab < 5 && Result->Available[Tab]) ||
        (Tab == 5 && Result->PiDDBQueried) || (Tab == 7 && Result->MsrQueried) ||
        ((Tab == 8 || Tab == 9) && Result->HalDispQueried) ||
        (Tab == 10 && Result->DpcQueried);
    if (AlreadyLoaded) {
      Populate();
      return;
    }

    if (State->TabLoading.exchange(true))
      return;

    Refresh->setEnabled(false);
    RefreshIndicator->show();
    RefreshIndicator->start();
    Status->setText(QString("Loading %1...")
                        .arg(Kind->itemText(Tab)));

    QPointer<QWidget> SafePage(Page);
    std::thread([SafePage, Kind, Status, Refresh, RefreshIndicator, State,
                 Populate, Tab, ShowResult] {
      DWORD ErrorCode = ERROR_SUCCESS;
      bool Success = false;
      if (Tab >= 0 && Tab < 5) {
        Success = QuerySystemTableEntries(static_cast<ULONG>(Tab),
                                          &State->Result->Entries[Tab]) != FALSE;
        State->Result->Available[Tab] = Success;
        if (Success) {
          if (Tab == 2)
            ServiceNamesForTable(SYSTEM_TABLE_KIND_SSDT);
          else if (Tab == 3)
            ServiceNamesForTable(SYSTEM_TABLE_KIND_SHADOW_SSDT);
        }
      } else if (Tab == 5) {
        Success = QueryPiDDBCacheEntries(&State->Result->PiDDB) != FALSE;
        ErrorCode = G_LastAegisCoreError;
        State->Result->PiDDBQueried = true;
        State->Result->PiDDBAvailable =
            Success || ErrorCode == ERROR_NOT_FOUND;
      } else if (Tab == 6) {
        Success = true;
      } else if (Tab == 7) {
        Success = MsrQueryValues(&State->Result->Msr) != FALSE;
        ErrorCode = G_LastAegisCoreError;
        State->Result->MsrQueried = true;
      } else if (Tab == 8 || Tab == 9) {
        Success = QueryHalDispatchEntries(
            Tab == 8 ? HAL_DISPATCH_TABLE_KIND_PUBLIC
                     : HAL_DISPATCH_TABLE_KIND_PRIVATE,
            &State->Result->HalDisp) != FALSE;
        ErrorCode = G_LastAegisCoreError;
        State->Result->HalDispQueried = true;
        State->Result->HalDispAvailable =
            Success || ErrorCode == ERROR_NOT_FOUND;
      } else if (Tab == 10) {
        Success = EnumerateDpcQueue(&State->Result->Dpc) != FALSE;
        ErrorCode = G_LastAegisCoreError;
        State->Result->DpcQueried = true;
        State->Result->DpcAvailable = Success || ErrorCode == ERROR_NOT_FOUND;
      }
      // ERROR_NOT_FOUND 视为"表存在但为空"而非加载失败
      if (!(Tab == 5 && ErrorCode == ERROR_NOT_FOUND) &&
          !((Tab == 8 || Tab == 9) && ErrorCode == ERROR_NOT_FOUND) &&
          !(Tab == 10 && ErrorCode == ERROR_NOT_FOUND))
        ErrorCode = G_LastAegisCoreError;

      QMetaObject::invokeMethod(
          qApp,
          [SafePage, Kind, Status, Refresh, RefreshIndicator, State, Populate,
           Tab, ShowResult, Success, ErrorCode] {
            State->TabLoading = false;
            RefreshIndicator->stop();
            RefreshIndicator->hide();
            Refresh->setEnabled(true);
            if (!SafePage)
              return;

            if (!Success &&
                !(Tab == 5 && State->Result->PiDDBQueried &&
                  State->Result->PiDDBAvailable) &&
                !((Tab == 8 || Tab == 9) && State->Result->HalDispQueried &&
                  State->Result->HalDispAvailable) &&
                !(Tab == 10 && State->Result->DpcQueried &&
                  State->Result->DpcAvailable)) {
              const QString Message =
                  QString("Load failed (error %1)").arg(ErrorCode);
              Status->setText(Message);
              if (ShowResult)
                ShowErrorNotice(SafePage, "Table", Message);
              return;
            }

            if (Kind->currentIndex() == Tab)
              Populate();
            Status->setText(QString("Loaded %1").arg(Kind->itemText(Tab)));
            if (ShowResult)
              ShowSuccessNotice(SafePage, "Table", "Selected table loaded.");
          },
          Qt::QueuedConnection);
    }).detach();
  };
  const auto Query = [Page, Status, Refresh, RefreshIndicator, State,
                      Populate, Kind, LoadTabAsync](bool ShowResult) {
    if (State->Refreshing.exchange(true))
      return;
    Refresh->setEnabled(false);
    Refresh->setText("Refreshing...");
    RefreshIndicator->show();
    RefreshIndicator->start();
    Status->setText("Reading system tables...");
    QPointer<QWidget> SafePage(Page);
    const int SelectedTab = Kind->currentIndex();
    std::thread([SafePage, Status, Refresh, RefreshIndicator, State, Populate,
                 ShowResult, SelectedTab, LoadTabAsync] {
      auto Result = std::make_shared<TableQueryResult>();
      Result->Success = QuerySystemTables(&Result->Summary) != FALSE;
      Result->ErrorCode = G_LastAegisCoreError;
      const auto Modules = AegisNT::KernelResearch::QueryAll(IOCTL_ENUM_KERNEL_MODULES);
      auto &Symbols = AegisNT::KernelResearch::SymbolService::Instance();
      Symbols.Initialize();
      Symbols.ReloadModules(Modules);
      QMetaObject::invokeMethod(
          qApp,
          [SafePage, Status, Refresh, RefreshIndicator, State, Populate,
           Result = std::move(Result), Modules, ShowResult, SelectedTab, LoadTabAsync] {
            State->Result = Result;
            State->Modules = Modules;
            State->Refreshing = false;
            RefreshIndicator->stop();
            RefreshIndicator->hide();
            Refresh->setText("Refresh");
            Refresh->setEnabled(true);
            if (!SafePage)
              return;
            if (!Result->Success) {
              const QString Message =
                  QString("Query failed (error %1)").arg(Result->ErrorCode);
              Status->setText(Message);
              if (ShowResult)
                ShowErrorNotice(SafePage, "Table", Message);
            } else {
              Status->setText("System table summary updated.");
              if (ShowResult)
                ShowSuccessNotice(SafePage, "Table",
                                  "System tables updated from AegisCore.");
              if (SelectedTab >= 0)
                (*LoadTabAsync)(SelectedTab, false);
            }
            Populate();
          },
          Qt::QueuedConnection);
    }).detach();
  };
  // 右键菜单：PiDDB(5) 移除缓存条目、DPC(10) 移除 DPC、IO Timer(1) 提示不可移除；
  // 其余标签页按 RemoveTarget 是否非零决定是否显示 Remove。
  QObject::connect(Table, &QWidget::customContextMenuRequested, Page,
                   [Page, Table, Kind, State, Query](const QPoint &Position) {
                     const QModelIndex Index = Table->indexAt(Position);
                     if (!Index.isValid())
                       return;
                     const int Row = Index.row();
                     if (Row < 0 || Row >= State->RemoveTargets.size())
                       return;
                     Table->selectRow(Row);
                     const int Tab = Kind->currentIndex();
                     const quintptr Target = State->RemoveTargets[Row];
                     auto *Menu = new RoundMenu(QString(), Page);
                     auto *RemoveAction = new QAction("Remove", Menu);
                     Menu->addAction(RemoveAction);
                     ConnectMenuAction(RemoveAction, Page,
                                       [Page, Tab, Target, Query] {
                                         if (Tab == 1) {
                                           ShowErrorNotice(
                                               Page, "Table",
                                               "KUSER_SHARED_DATA fields are "
                                               "fixed system values and cannot "
                                               "be removed.");
                                           return;
                                         }
                                         if (Target == 0) {
                                           ShowErrorNotice(
                                               Page, "Table",
                                               "This table entry cannot be "
                                               "removed.");
                                           return;
                                         }
                                         bool Ok = false;
                                         QString Description;
                                         if (Tab == 5) {
                                           Ok = RemovePiDDBCacheEntry(
                                                    Target) != FALSE;
                                           Description = "PiDDBCacheTable entry";
                                         } else if (Tab == 10) {
                                           Ok = RemoveDpcEntry(Target, 0) !=
                                                FALSE;
                                           Description = "DPC entry";
                                         } else {
                                           ShowErrorNotice(
                                               Page, "Table",
                                               "Removal is not supported for "
                                               "this table.");
                                           return;
                                         }
                                         if (Ok) {
                                           ShowSuccessNotice(Page, "Table",
                                                             Description +
                                                                 " removed.");
                                           Query(false);
                                         } else {
                                           ShowErrorNotice(
                                               Page, "Table",
                                               "Failed to remove " +
                                                   Description +
                                                   ".\nWin32 error: " +
                                                   QString::number(
                                                       G_LastAegisCoreError));
                                         }
                                       });
                     ReleaseMenuAfterClose(Menu);
                     Menu->exec(Table->viewport()->mapToGlobal(Position));
                   });
  QObject::connect(Kind, &ComboBox::currentIndexChanged, Page,
                   [Populate, LoadTabAsync](int Index) {
                     Populate();
                     (*LoadTabAsync)(Index, false);
                   });
  QObject::connect(Search, &QLineEdit::textChanged, Page,
                   [Populate] { Populate(); });
  QObject::connect(Refresh, &QPushButton::clicked, Page,
                   [Query] { Query(true); });
  QObject::connect(MsrEnable, &QPushButton::clicked, Page, [=] {
    if (MsrWatchEnable()) {
      MsrEnable->setEnabled(false);
      MsrDisable->setEnabled(true);
      ShowSuccessNotice(Page, "MSR Watch", "Watch enabled, baseline captured.");
      (*LoadTabAsync)(7, false);
    } else {
      ShowErrorNotice(Page, "MSR Watch",
                      QString("Failed to enable watch (error %1).")
                          .arg(G_LastAegisCoreError));
    }
  });
  QObject::connect(MsrDisable, &QPushButton::clicked, Page, [=] {
    if (MsrWatchDisable()) {
      MsrDisable->setEnabled(false);
      MsrEnable->setEnabled(true);
      ShowSuccessNotice(Page, "MSR Watch", "Watch disabled.");
      (*LoadTabAsync)(7, false);
    } else {
      ShowErrorNotice(Page, "MSR Watch",
                      QString("Failed to disable watch (error %1).")
                          .arg(G_LastAegisCoreError));
    }
  });
  Query(false);
  return Page;
}
