// Source/Tui/TuiPagesInfo.cpp
// ============================================================
// 索引 0：Information —— 运行环境 / 硬件 / 软件 / 性能总览。
// ------------------------------------------------------------
// 与 GUI 的 InformationOverviewPage 对齐：完全只读，所有取值都来自
// AegisNT.cpp 中已有的自由函数（QueryTestSigning/QueryNpcap/...），
// 不直接访问驱动，因此驱动未加载时页面照常渲染。
// 唯一命令：refresh；OnTick 每 1000 ms 重采样一次（仅当页面可见时）。
// ============================================================

#include "TuiPages.h"

namespace AegisNT::Tui {
namespace {

// 与 GUI 的 InformationOverviewPage::CpuTimes 相同：GetSystemTimes 的
// FILETIME 累计值（kernel 时间已包含 idle 时间，属于 Win32 语义）。
struct InfoCpuTimes {
  uint64_t Idle = 0;
  uint64_t Kernel = 0;
  uint64_t User = 0;
};

uint64_t InfoFileTimeToUInt64(const FILETIME &Value) {
  ULARGE_INTEGER Integer{};
  Integer.LowPart = Value.dwLowDateTime;
  Integer.HighPart = Value.dwHighDateTime;
  return static_cast<uint64_t>(Integer.QuadPart);
}

InfoCpuTimes QueryInfoCpuTimes() {
  FILETIME IdleTime{}, KernelTime{}, UserTime{};
  if (!GetSystemTimes(&IdleTime, &KernelTime, &UserTime))
    return {};
  return {InfoFileTimeToUInt64(IdleTime), InfoFileTimeToUInt64(KernelTime),
          InfoFileTimeToUInt64(UserTime)};
}

std::string InfoPageText(const QString &Text) { return Text.toStdString(); }

// GUI 中所有取值在构造时读取一次（硬件/软件），性能四项每秒刷新。
struct InfoPageStaticValues {
  bool RequirementsOk = false;
  std::string TestSigning;
  std::string Npcap;
  std::string Certificate;
  std::string Computer;
  std::string Manufacturer;
  std::string Model;
  std::string Processor;
  std::string LogicalProcessors;
  std::string Graphics;
  std::string InstalledMemory;
  std::string Mainboard;
  std::string Bios;
  std::string SystemDrive;
  std::string OperatingSystem;
  std::string Kernel;
  std::string Runtime;
  std::string Process;
  std::string ApplicationPath;

  void Load() {
    const QString Computer =
        QProcessEnvironment::systemEnvironment().value("COMPUTERNAME",
                                                       "Unknown");
    const QString TestSigning = QueryTestSigning();
    const QString Npcap = QueryNpcap();
    const QString Certificate = CertificateState();
    const QString Manufacturer = QuerySystemManufacturer();
    const QString Model = QuerySystemModel();
    const QString Cpu = QueryCpuName();
    const QString Board = QueryBoardName();
    const QString Bios = QueryBiosName();
    const QString Graphics = QueryGraphicsAdapters();
    const QString MemoryInstalled = QueryMemoryInstalled();
    const QString SystemDrive = QuerySystemDriveSummary();
    const QString Kernel = QString("%1  |  %2").arg(
        QSysInfo::kernelVersion(), QSysInfo::currentCpuArchitecture());
    SYSTEM_INFO SystemInfo{};
    GetNativeSystemInfo(&SystemInfo);

    RequirementsOk = TestSigning == QLatin1String("Enabled") &&
                     Npcap == QLatin1String("Running") &&
                     Certificate == QLatin1String("Certificate available");

    this->TestSigning = InfoPageText(TestSigning);
    this->Npcap = InfoPageText(Npcap);
    this->Certificate = InfoPageText(Certificate);
    this->Computer = InfoPageText(Computer);
    this->Manufacturer =
        InfoPageText(Manufacturer.isEmpty() ? "Unknown" : Manufacturer);
    this->Model = InfoPageText(Model.isEmpty() ? "Unknown" : Model);
    this->Processor = InfoPageText(Cpu.isEmpty() ? "Unknown" : Cpu);
    this->LogicalProcessors = std::to_string(SystemInfo.dwNumberOfProcessors);
    this->Graphics = InfoPageText(Graphics.isEmpty() ? "Unknown" : Graphics);
    this->InstalledMemory = InfoPageText(MemoryInstalled);
    this->Mainboard = InfoPageText(Board.isEmpty() ? "Unknown" : Board);
    this->Bios = InfoPageText(Bios.isEmpty() ? "Unknown" : Bios);
    this->SystemDrive = InfoPageText(SystemDrive);
    this->OperatingSystem = InfoPageText(QueryWindowsVersionText());
    this->Kernel = InfoPageText(Kernel);
    this->Runtime = InfoPageText(
        QString("Qt %1  |  v%2").arg(QT_VERSION_STR, KApplicationVersion));
    this->Process =
        InfoPageText(QString("%1  |  PID %2")
                       .arg(QFileInfo(QCoreApplication::applicationFilePath())
                                .fileName())
                       .arg(QCoreApplication::applicationPid()));
    this->ApplicationPath = InfoPageText(QDir::toNativeSeparators(
        QCoreApplication::applicationDirPath()));
  }
};

// 单条仪表盘行的值格式："<percent>% | <摘要> | <明细 1> | <明细 2> | <明细 3>"
std::string InfoPageJoinPercent(const QString &Center, const QString &First,
                                const QString &Second, const QString &Third) {
  QStringList Parts;
  Parts << Center << First << Second << Third;
  return InfoPageText(Parts.join(" | "));
}

} // namespace

class TuiInformationPage final : public TuiPage {
public:
  explicit TuiInformationPage(int Index) {
    (void)Index;
    Table_.Headers = {"Item", "Value"};
    Table_.RightAlign = {false, false};
    OwnedCommands.push_back(TuiCommand{
        "refresh", "refresh  (reload system information)",
        [this](std::vector<std::string>) {
          ReloadStatics();
          RefreshNow();
        }});
  }

  std::string Title() const override { return "Information"; }

  std::string Subtitle() const override {
    return "runtime environment, hardware/software profile, performance";
  }

  void OnEnter() override {
    // `use` / `refresh` 都走这里：重读硬件与软件信息并重置采样基准。
    ReloadStatics();
    RefreshNow();
  }

  void OnTick(int64_t NowMs) override {
    if (LastRefreshMs_ != 0 && NowMs - LastRefreshMs_ < 1000)
      return;
    LastRefreshMs_ = NowMs;
    RefreshNow(NowMs);
  }

  TuiTable *ActiveTable() override { return &Table_; }

  std::string RenderText() override {
    if (!Loaded_)
      ReloadStatics();
    RefreshNow();
    std::string Text;
    if (!Values_.RequirementsOk)
      Text +=
          "[!] Runtime requirements incomplete - TestSigning, Npcap, and the "
          "HTTP certificate should all be available before using kernel and "
          "monitor features.\n";
    Text += TuiTableToText(Table_, 200);
    return Text;
  }

private:
  // 硬件/软件取值只在页面显示或 refresh 时重读；性能四项每秒采样。
  void ReloadStatics() {
    Loaded_ = true;
    Values_.Load();
    // 采样基准随之重置，避免跨显示间隔的巨大差值。
    const InfoCpuTimes Current = QueryInfoCpuTimes();
    PreviousIdle_ = Current.Idle;
    PreviousKernel_ = Current.Kernel;
    PreviousUser_ = Current.User;
    PreviousNetwork_ = QueryNetworkTrafficSnapshot();
    PreviousSampleTime_ = QDateTime::currentMSecsSinceEpoch();
    BootTime_ = InfoPageText(QDateTime::currentDateTime()
                                 .addMSecs(-static_cast<qint64>(
                                     GetTickCount64()))
                                 .toString("yyyy-MM-dd HH:mm:ss"));
  }

  // GUI 的四个仪表盘共用 1000 ms 采样：先算差值，再更新基准。
  void RefreshNow(int64_t Now = 0) {
    if (!Loaded_)
      ReloadStatics();
    LastRefreshMs_ = Now != 0 ? Now : NowMs();
    BuildRows();
    SetStatus(Values_.RequirementsOk ? "Runtime requirements satisfied"
                                     : "Runtime requirements incomplete");
  }

  void BuildRows() {
    const InfoCpuTimes Current = QueryInfoCpuTimes();
    const uint64_t IdleDelta = Current.Idle - PreviousIdle_;
    const uint64_t KernelDelta = Current.Kernel - PreviousKernel_;
    const uint64_t UserDelta = Current.User - PreviousUser_;
    const uint64_t TotalDelta = KernelDelta + UserDelta;
    const int CpuUsage =
        TotalDelta == 0
            ? 0
            : static_cast<int>(std::clamp(
                  qRound(((TotalDelta - IdleDelta) * 100.0) / TotalDelta), 0,
                  100));
    PreviousIdle_ = Current.Idle;
    PreviousKernel_ = Current.Kernel;
    PreviousUser_ = Current.User;

    SYSTEM_INFO CpuInfo{};
    GetNativeSystemInfo(&CpuInfo);
    const std::string CpuValue = InfoPageJoinPercent(
        QString::number(CpuUsage) + "%",
        QString("%1 logical processor(s)").arg(CpuInfo.dwNumberOfProcessors),
        QString("Architecture: %1").arg(QSysInfo::currentCpuArchitecture()),
        QueryCpuName().isEmpty() ? QString("CPU name unavailable")
                                 : QueryCpuName());

    std::string MemoryValue = "Unavailable";
    MEMORYSTATUSEX Memory{};
    Memory.dwLength = sizeof(Memory);
    if (GlobalMemoryStatusEx(&Memory)) {
      const quint64 UsedPhysical =
          Memory.ullTotalPhys > Memory.ullAvailPhys
              ? Memory.ullTotalPhys - Memory.ullAvailPhys
              : 0;
      const quint64 UsedCommit =
          Memory.ullTotalPageFile > Memory.ullAvailPageFile
              ? Memory.ullTotalPageFile - Memory.ullAvailPageFile
              : 0;
      MemoryValue = InfoPageJoinPercent(
          QString::number(Memory.dwMemoryLoad) + "%",
          QString("Physical: %1 / %2").arg(FormatBytes(UsedPhysical),
                                           FormatBytes(Memory.ullTotalPhys)),
          QString("Available: %1").arg(FormatBytes(Memory.ullAvailPhys)),
          QString("Committed: %1 / %2").arg(FormatBytes(UsedCommit),
                                            FormatBytes(Memory.ullTotalPageFile)));
    }

    std::string DiskValue = "Unavailable";
    const QStorageInfo Storage(QCoreApplication::applicationDirPath());
    if (Storage.isValid() && Storage.isReady()) {
      const quint64 Total = static_cast<quint64>(Storage.bytesTotal());
      const quint64 Free = static_cast<quint64>(Storage.bytesAvailable());
      const quint64 Used = Total > Free ? Total - Free : 0;
      const int DiskUsage =
          Total == 0 ? 0
                     : static_cast<int>(
                           std::clamp(qRound((Used * 100.0) / Total), 0, 100));
      DiskValue = InfoPageJoinPercent(
          QString::number(DiskUsage) + "%",
          QString("Drive: %1").arg(QDir::toNativeSeparators(Storage.rootPath())),
          QString("Used: %1 / %2").arg(FormatBytes(Used), FormatBytes(Total)),
          QString("Free: %1").arg(FormatBytes(Free)));
    }

    const NetworkTrafficSnapshot Network = QueryNetworkTrafficSnapshot();
    const qint64 CurrentSampleTime = QDateTime::currentMSecsSinceEpoch();
    const qint64 ElapsedMs =
        std::max<qint64>(1, CurrentSampleTime - PreviousSampleTime_);
    const quint64 DownloadRate =
        Network.InBytes >= PreviousNetwork_.InBytes
            ? static_cast<quint64>((Network.InBytes - PreviousNetwork_.InBytes) *
                                   1000ull / static_cast<quint64>(ElapsedMs))
            : 0;
    const quint64 UploadRate =
        Network.OutBytes >= PreviousNetwork_.OutBytes
            ? static_cast<quint64>(
                  (Network.OutBytes - PreviousNetwork_.OutBytes) * 1000ull /
                  static_cast<quint64>(ElapsedMs))
            : 0;
    // GUI 的网速仪表盘百分比 min(100, round(log2(peak+1)*8))；
    // 终端没有仪表盘，百分比只用于摘要行前缀，与 CPU/内存/磁盘同构。
    const quint64 PeakRate = std::max<quint64>(DownloadRate, UploadRate);
    const int NetworkUsage =
        PeakRate == 0
            ? 0
            : std::min(100,
                       static_cast<int>(qRound(std::log2(PeakRate + 1) * 8.0)));
    PreviousNetwork_ = Network;
    PreviousSampleTime_ = CurrentSampleTime;

    const std::string NetworkValue = InfoPageJoinPercent(
        QString::number(NetworkUsage) + "% | D " + FormatRate(DownloadRate) +
            " | U " + FormatRate(UploadRate),
        QString("Received: %1").arg(FormatBytes(Network.InBytes)),
        QString("Sent: %1").arg(FormatBytes(Network.OutBytes)),
        QString("Sample interval: %1 ms").arg(ElapsedMs));

    std::vector<TuiRow> Rows;
    Rows.reserve(32);
    const auto Section = [&Rows](const std::string &Title) {
      Rows.push_back(TuiRow{{"── " + Title + " ──", ""}, ""});
    };
    const auto Add = [&Rows](std::string Label, std::string Value) {
      Rows.push_back(TuiRow{{std::move(Label), std::move(Value)}, ""});
    };

    Section("Runtime environment");
    Add("TestSigning", Values_.TestSigning);
    Add("Npcap Service", Values_.Npcap);
    Add("HTTP Certificate", Values_.Certificate);

    Section("Hardware profile");
    Add("Computer", Values_.Computer);
    Add("Manufacturer", Values_.Manufacturer);
    Add("Model", Values_.Model);
    Add("Processor", Values_.Processor);
    Add("Logical Processors", Values_.LogicalProcessors);
    Add("Graphics", Values_.Graphics);
    Add("Installed Memory", Values_.InstalledMemory);
    Add("Mainboard", Values_.Mainboard);
    Add("BIOS", Values_.Bios);
    Add("System Drive", Values_.SystemDrive);

    Section("Software profile");
    Add("Operating System", Values_.OperatingSystem);
    Add("Kernel", Values_.Kernel);
    Add("Boot Time", BootTime_);
    Add("Uptime", InfoPageText(FormatDuration(GetTickCount64())));
    Add("Runtime", Values_.Runtime);
    Add("Process", Values_.Process);
    Add("Application Path", Values_.ApplicationPath);

    Section("Performance");
    Add("CPU", CpuValue);
    Add("Memory", MemoryValue);
    Add("Disk", DiskValue);
    Add("Network", NetworkValue);

    Table_.Filter = Filter;
    Table_.Rows = std::move(Rows);
    Table_.Rebuild();
    if (Table_.Selected >= static_cast<int>(Table_.Visible.size()))
      Table_.Selected =
          std::max(0, static_cast<int>(Table_.Visible.size()) - 1);
  }

  bool Loaded_ = false;
  int64_t LastRefreshMs_ = 0;
  InfoPageStaticValues Values_;
  std::string BootTime_;
  TuiTable Table_;
  uint64_t PreviousIdle_ = 0;
  uint64_t PreviousKernel_ = 0;
  uint64_t PreviousUser_ = 0;
  NetworkTrafficSnapshot PreviousNetwork_;
  qint64 PreviousSampleTime_ = 0;
};

std::unique_ptr<TuiPage> MakeInformationPage(int Index) {
  return std::make_unique<TuiInformationPage>(Index);
}

} // namespace AegisNT::Tui
