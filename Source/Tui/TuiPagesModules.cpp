// Source/Tui/TuiPagesModules.cpp
// ============================================================
// 索引 10..14 / 18 / 19：
//   Payload / ModuleRun / ModuleManager / Console / Chat / Network / Snapshot
// ------------------------------------------------------------
// 本文件与 GUI 的 PayloadPage / ModuleRunPage / ModuleManagerPage /
// ConsolePage / ChatPage / NetworkPage / SnapshotLabPage 一一对应，
// 复用同一批后端函数与同一份共享状态（ApplicationContext、配置、
// 模块运行时、快照模型 SnapshotModel）。所有重活走 TuiAsync，回调
// 回到 UI 线程；页面自身只持有表格/光标等前端状态。
//
// 说明：所有页面类与本地助手都放在 AegisNT::Tui::ModPages 内，避免与
// 其他 TuiPages*.cpp 的匿名命名空间助手重名（unity 构建下同一 TU）。
// ============================================================

#include "TuiAsync.h"
#include "TuiPages.h"
#include "TuiSync.h"

namespace AegisNT::Tui {
namespace ModPages {

// 本文件运行在 namespace AegisNT::Tui 内，无限定名 `ModuleEntry` 会先命中
// AegisNT 里同名（但不同）的类型；显式引入 unity TU 里的文件作用域类型，
// 让 DllModules / FindDllModule / LoadModuleInstance / ModulesByCategory
// 这些助手与别名指向同一个类型。
using ::ModuleEntry;
using ::ModuleInfo;

// ------------------------------------------------------------
// 公用小工具
// ------------------------------------------------------------

std::string U8(const QString &Text) { return Text.toStdString(); }
QString Qs(const std::string &Text) { return QString::fromStdString(Text); }

// 有 QApplication 才有 QWidget：--console 独占模式只有 QCoreApplication，
// 任何 QWidget/QDialog/QFileDialog 都会致命，必须先判断。
bool HasQtWidgets() {
  return qobject_cast<QApplication *>(QCoreApplication::instance()) != nullptr;
}

std::optional<QString> BrowseSaveFile(const QString &Title,
                                      const QString &Initial) {
  if (!HasQtWidgets())
    return std::nullopt;
  const QString Path = QFileDialog::getSaveFileName(
      nullptr, Title, Initial, QStringLiteral("All files (*.*)"));
  if (Path.isEmpty())
    return std::nullopt;
  return Path;
}

std::optional<QString> BrowseOpenFile(const QString &Title,
                                      const QString &Filter) {
  if (!HasQtWidgets())
    return std::nullopt;
  const QString Path =
      QFileDialog::getOpenFileName(nullptr, Title, QString(), Filter);
  if (Path.isEmpty())
    return std::nullopt;
  return Path;
}

// 文本路径输入（无 GUI 也能用）：回车提交。
void PromptPath(TuiDialogStack &Stack, const std::string &Title,
                const std::string &Label, const QString &Initial,
                std::function<void(QString)> OnSubmit,
                std::string Hint = {}) {
  PromptTextDialog(
      Stack, Title, Label, U8(Initial),
      [OnSubmit = std::move(OnSubmit)](std::string Value) {
        if (OnSubmit)
          OnSubmit(Qs(TrimAscii(Value)));
      },
      std::move(Hint));
}

TuiField TextField(const std::string &Label, const std::string &Value,
                   std::string Placeholder = {}) {
  TuiField Field;
  Field.Label = Label;
  Field.Kind = TuiFieldKind::Text;
  Field.Value = Value;
  Field.Placeholder = std::move(Placeholder);
  return Field;
}

TuiField ComboField(const std::string &Label,
                    const std::vector<std::string> &Choices, int Choice) {
  TuiField Field;
  Field.Label = Label;
  Field.Kind = TuiFieldKind::Combo;
  Field.Choices = Choices;
  Field.Choice = std::clamp(Choice, 0, std::max(0,
                                                static_cast<int>(
                                                    Choices.size()) - 1));
  return Field;
}

std::string ChoiceValue(const TuiField &Field) {
  if (Field.Choices.empty())
    return Field.Value;
  const int Index = std::clamp(Field.Choice, 0,
                               static_cast<int>(Field.Choices.size()) - 1);
  return Field.Choices[static_cast<size_t>(Index)];
}

// ------------------------------------------------------------
// 10 · Payload —— 负载生成 + 反弹 Shell
// ------------------------------------------------------------

struct PayloadHostEntry {
  QString Host;
  QString Port;
  QString Password;
  qulonglong SessionId = 0;
  QListWidgetItem *Item = nullptr;
};

class PayloadPage final : public TuiPage {
public:
  explicit PayloadPage(int Index) : Index_(Index) {
    ShellState_ = std::make_shared<PayloadShellState>();
    Hosts_.Headers = {"Host", "Port", "Status"};
    Params_.Headers = {"Option", "Type", "Value", "Description"};
    RegisterCommands();
  }

  ~PayloadPage() override {
    AbortAllSessions();
    for (PayloadHostEntry &Entry : HostEntries_)
      delete Entry.Item;
    HostEntries_.clear();
  }

  std::string Title() const override { return "Payload"; }

  std::string Subtitle() const override {
    return "payload generation (module/encoder/nop/output) and reverse shell";
  }

  void OnEnter() override {
    // `use` / `refresh`：首次进入拉主机列表并重扫 payload 模块，
    // 之后只重扫模块（静默，保留当前选择）。
    if (!Loaded_) {
      Loaded_ = true;
      LoadSavedHosts();
      RefreshModules();
    } else {
      RepopulateModules();
    }
    RefreshHostTable();
    SetStatus(Tab_ == 0 ? ModuleStatus() : HostStatus());
  }

  void OnTick(int64_t NowMs) override {
    if (LastTickMs_ != 0 && NowMs - LastTickMs_ < 150)
      return;
    LastTickMs_ = NowMs;
    RefreshHostTable();
    SetStatus(Tab_ == 0 ? ModuleStatus() : HostStatus());
  }

  TuiTable *ActiveTable() override { return Tab_ == 0 ? &Params_ : &Hosts_; }

  std::string RenderText() override {
    // `show` 是查看操作：首次进入时拉主机列表，随后只重读当前模块的选项，
    // 不打断已选的模块/主机。
    if (!Loaded_) {
      Loaded_ = true;
      LoadSavedHosts();
    }
    if (PayloadModules_.empty())
      RepopulateModules();
    else
      UpdateInformation();
    RefreshHostTable();
    SetStatus(Tab_ == 0 ? ModuleStatus() : HostStatus());

    std::string Text = TabStrip();
    Text += '\n';
    if (Tab_ == 0) {
      Text += ModuleLabel_ + '\n';
      for (const std::string &Line : ModuleInfoLines_)
        Text += "  " + Line + '\n';
      Text += "  Encoder: " + Encoder_ + "   Nop: " + Nop_ +
              "   Output: " + OutputPath_ + '\n';
      Text += TuiTableToText(Params_, 200);
    } else {
      Text += "  Encoder/Nop/Output are set by `generate`; this tab lists the "
              "shell endpoints.\n";
      Text += TuiTableToText(Hosts_, 200);
    }
    return Text;
  }

private:
  std::string TabStrip() const {
    std::string Text;
    Text += Tab_ == 0 ? "[Generate]  Shell" : "Generate  [Shell]";
    Text += "   (view generate|shell)";
    return Text;
  }

  void RegisterCommands() {
    OwnedCommands.push_back(
        {"refresh", "refresh  (rescan payload modules)",
         [this](std::vector<std::string>) { RefreshModules(); }});
    OwnedCommands.push_back(
        {"browse", "browse  (choose the output file)",
         [this](std::vector<std::string>) { Browse(); }});
    OwnedCommands.push_back(
        {"generate", "generate  (module / encoder / nop / output)",
         [this](std::vector<std::string>) { ShowGenerateDialog(); }});
    OwnedCommands.push_back(
        {"module-output", "module-output [clear]",
         [this](std::vector<std::string> Args) { ShowModuleOutput(Args); }});
    OwnedCommands.push_back(
        {"module", "module <index|name>  (select payload module)",
         [this](std::vector<std::string> Args) { SelectModule(Args); }});
    OwnedCommands.push_back(
        {"new", "new  (add a shell host entry)",
         [this](std::vector<std::string>) { NewHost(); }});
    OwnedCommands.push_back(
        {"save", "save  (persist the shell host list)",
         [this](std::vector<std::string>) { SaveSelectedHost(); }});
    OwnedCommands.push_back(
        {"remove", "remove  (delete the selected shell host)",
         [this](std::vector<std::string>) { RemoveHost(); }});
    OwnedCommands.push_back(
        {"connect", "connect  (connect the selected shell host)",
         [this](std::vector<std::string>) { ConnectHost(); }});
    OwnedCommands.push_back(
        {"disconnect", "disconnect  (close the shell session)",
         [this](std::vector<std::string>) { DisconnectHost(); }});
    OwnedCommands.push_back(
        {"command", "command  (show the session transcript)",
         [this](std::vector<std::string>) { ShowTranscript(); }});
    OwnedCommands.push_back(
        {"send", "send <command>  (send a remote command)",
         [this](std::vector<std::string> Args) { SendCommand(JoinArgs(Args)); }});
    OwnedCommands.push_back(
        {"screen", "screen  (request a remote screenshot)",
         [this](std::vector<std::string>) { SendCommand("screenshot"); }});
    OwnedCommands.push_back(
        {"upload", "upload [path]  (base64 upload a local file)",
         [this](std::vector<std::string> Args) { UploadFile(JoinArgs(Args)); }});
    OwnedCommands.push_back(
        {"download", "download <path>  (fetch a remote file)",
         [this](std::vector<std::string> Args) {
           SendCommand("download " + JoinArgs(Args));
         }});
    OwnedCommands.push_back(
        {"clear", "clear  (clear the session transcript)",
         [this](std::vector<std::string>) {
           if (auto Session = CurrentSession())
             Session->Transcript.clear();
           Notify("Session transcript cleared.", NoticeKind::Success);
         }});
    OwnedCommands.push_back(
        {"view", "view [generate|shell]  (switch tab)",
         [this](std::vector<std::string> Args) { SetView(Args); }});
  }

  static std::string JoinArgs(const std::vector<std::string> &Args) {
    std::string Text;
    for (const std::string &Arg : Args) {
      if (!Text.empty())
        Text += ' ';
      Text += Arg;
    }
    return Text;
  }

  // 无键盘事件后，标签页切换只能经由 `view` 命令（等价于原 F7/F8）。
  void SetView(const std::vector<std::string> &Args) {
    if (Args.empty()) {
      SwitchTab(Tab_ + 1);
      return;
    }
    const std::string Needle = LowerAscii(TrimAscii(Args.front()));
    if (Needle == "generate" || Needle == "params" || Needle == "1") {
      SwitchTab(0);
      return;
    }
    if (Needle == "shell" || Needle == "hosts" || Needle == "2") {
      SwitchTab(1);
      return;
    }
    Notify("Unknown view: " + Args.front(), NoticeKind::Warning);
  }

  void SwitchTab(int Index) {
    Tab_ = ((Index % 2) + 2) % 2;
    SetStatus(Tab_ == 0 ? ModuleStatus() : HostStatus());
  }

  // ---- 生成标签页 ----

  // 静默重扫（切页/跨前端刷新时用，不弹警告）。
  void RepopulateModules() {
    PayloadModules_ = ModulesByCategory("Payload", true);
    PayloadLabels_.clear();
    ModuleIndex_ = 0;
    for (size_t Index = 0; Index < PayloadModules_.size(); ++Index)
      PayloadLabels_.push_back(PayloadModules_[Index]->Name);
    UpdateInformation();
  }

  void RefreshModules() {
    if (ModuleRunning.load()) {
      Notify("Wait for the running module to finish before refreshing.",
             NoticeKind::Warning);
      return;
    }
    const std::string Previous = CurrentModulePath();
    PayloadModules_ = ModulesByCategory("Payload", true);
    PayloadLabels_.clear();
    ModuleIndex_ = 0;
    for (size_t Index = 0; Index < PayloadModules_.size(); ++Index) {
      ModuleEntry *Entry = PayloadModules_[Index];
      PayloadLabels_.push_back(Entry->Name);
      if (Entry->Path == Previous)
        ModuleIndex_ = static_cast<int>(Index);
    }
    UpdateInformation();
    SetStatus(ModuleStatus());
  }

  std::string CurrentModulePath() const {
    if (ModuleIndex_ < 0 ||
        ModuleIndex_ >= static_cast<int>(PayloadModules_.size()))
      return {};
    return PayloadModules_[static_cast<size_t>(ModuleIndex_)]->Path;
  }

  ModuleEntry *CurrentModule() {
    if (ModuleIndex_ < 0 ||
        ModuleIndex_ >= static_cast<int>(PayloadModules_.size()))
      return nullptr;
    return PayloadModules_[static_cast<size_t>(ModuleIndex_)];
  }

  static QStringList OutputAliases() {
    return {"FilePath", "File_Path", "Output", "OutputPath",
            "Path",     "File",      "FileName"};
  }

  void SetPayloadOption(ModuleEntry *Entry, const QStringList &Aliases,
                        const QString &Value) {
    if (!Entry)
      return;
    SetCachedModuleOptionValue(*Entry, Aliases, Value);
  }

  static bool IsBuiltInPayloadOption(const std::string &Name) {
    return OptionNameMatches(
        Name, {"FilePath", "File_Path", "Output", "OutputPath", "Path", "File",
               "FileName", "Encoder", "Encoder_Module", "Nop", "Nop_Module"});
  }

  void UpdateInformation() {
    ModuleInfoLines_.clear();
    Params_.Rows.clear();
    ParamOptionNames_.clear();
    Params_.Filter = Filter;
    ModuleEntry *Entry = CurrentModule();
    if (!Entry) {
      ModuleLabel_ = "No payload module";
      ModuleInfoLines_.push_back("No payload module is available.");
      OutputPath_.clear();
      Params_.Rebuild();
      return;
    }
    ModuleLabel_ = std::string("Payload/") + Entry->Name +
                   "  |  Author: " + Entry->Author;
    ModuleInfoLines_.push_back(Entry->Description);
    OutputPath_ = U8(CachedModuleOptionValue(*Entry, OutputAliases()));
    if (OutputPath_.empty())
      OutputPath_ = "Path and filename";

    QString Error;
    if (!LoadModuleInstance(*Entry, &Error)) {
      ModuleInfoLines_.push_back("Module load failed: " + U8(Error));
      Params_.Rebuild();
      return;
    }
    auto *Instance = static_cast<ModuleBase *>(Entry->ModuleInstance);
    for (const auto &[Name, OptionPointer] : Instance->GetOptions()) {
      if (IsBuiltInPayloadOption(Name))
        continue;
      const bool Required =
          OptionPointer->GetRequired() == OptionRequired::Required;
      Params_.Rows.push_back(TuiRow{{Name + (Required ? " *" : ""),
                                     OptionPointer->TypeName(),
                                     OptionPointer->GetValue(),
                                     OptionPointer->GetDescription()},
                                    {}});
      ParamOptionNames_.push_back(Name);
    }
    Params_.Rebuild();
    if (Params_.Selected >= static_cast<int>(Params_.Visible.size()))
      Params_.Selected = std::max(0, static_cast<int>(Params_.Visible.size()) - 1);
  }

  void SelectModule(const std::vector<std::string> &Args) {
    if (!Args.empty()) {
      const std::string Needle = LowerAscii(Args.front());
      for (size_t Index = 0; Index < PayloadModules_.size(); ++Index) {
        if (LowerAscii(PayloadModules_[Index]->Name) == Needle) {
          ModuleIndex_ = static_cast<int>(Index);
          UpdateInformation();
          SetStatus(ModuleStatus());
          return;
        }
      }
      for (size_t Index = 0; Index < PayloadModules_.size(); ++Index) {
        if (LowerAscii(PayloadModules_[Index]->Name).find(Needle) !=
            std::string::npos) {
          ModuleIndex_ = static_cast<int>(Index);
          UpdateInformation();
          SetStatus(ModuleStatus());
          return;
        }
      }
      Notify("Unknown payload module: " + Args.front(), NoticeKind::Warning);
      return;
    }
    if (!Dialogs)
      return;
    TuiDialog Dialog;
    Dialog.Title = "Payload module";
    Dialog.Fields.push_back(ComboField("Module", PayloadLabels_, ModuleIndex_));
    Dialog.PrimaryLabel = "Select";
    Dialog.OnSubmit = [this](TuiDialog &Submitted) {
      if (Submitted.Fields.empty())
        return;
      ModuleIndex_ = Submitted.Fields.front().Choice;
      UpdateInformation();
      SetStatus(ModuleStatus());
    };
    Dialogs->Push(std::move(Dialog));
  }

  void EditParameter() {
    if (!Dialogs)
      return;
    const int RowIndex = Params_.CurrentRowIndex();
    if (RowIndex < 0 || RowIndex >= static_cast<int>(ParamOptionNames_.size()))
      return;
    ModuleEntry *Entry = CurrentModule();
    if (!Entry || !Entry->ModuleInstance)
      return;
    auto *Instance = static_cast<ModuleBase *>(Entry->ModuleInstance);
    const std::string Name = ParamOptionNames_[static_cast<size_t>(RowIndex)];
    const auto &Options = Instance->GetOptions();
    const auto It = Options.find(Name);
    if (It == Options.end())
      return;
    Option *OptionPointer = It->second.get();
    const std::string Current = OptionPointer->GetValue();

    TuiDialog Dialog;
    Dialog.Title = "Parameter: " + Name;
    Dialog.Body = OptionPointer->GetDescription();
    if (auto *EnumOption = dynamic_cast<OptEnum *>(OptionPointer)) {
      const auto &Choices = EnumOption->GetChoices();
      int Choice = 0;
      for (size_t Index = 0; Index < Choices.size(); ++Index) {
        if (Choices[Index] == Current)
          Choice = static_cast<int>(Index);
      }
      Dialog.Fields.push_back(ComboField("Value", Choices, Choice));
    } else if (dynamic_cast<OptBool *>(OptionPointer)) {
      const bool True =
          LowerAscii(Current) != "false" && LowerAscii(Current) != "0";
      Dialog.Fields.push_back(ComboField("Value", {"true", "false"},
                                        True ? 0 : 1));
    } else {
      Dialog.Fields.push_back(TextField("Value", Current,
                                        OptionPointer->GetDefaultValue()));
    }
    const QString Path = Qs(Entry->Path);
    Dialog.OnSubmit = [this, Path, Name](TuiDialog &Submitted) {
      if (Submitted.Fields.empty())
        return;
      const std::string Value = ChoiceValue(Submitted.Fields.front());
      if (ModuleEntry *Module = FindDllModule(Path))
        SetPayloadOption(Module, {Qs(Name)}, Qs(Value));
      UpdateInformation();
    };
    Dialogs->Push(std::move(Dialog));
  }

  std::vector<std::string> ChoiceNames(const QString &Key) {
    std::vector<std::string> Names{"None"};
    for (const QJsonValue &Value :
         ConfigurationValue("Payload", Key, QJsonArray()).toArray()) {
      const QString Name = Value.toString().trimmed();
      if (Name.isEmpty() || Name.compare("None", Qt::CaseInsensitive) == 0 ||
          Name.compare("(None)", Qt::CaseInsensitive) == 0)
        continue;
      bool Duplicate = false;
      for (const std::string &Existing : Names) {
        if (Qs(Existing).compare(Name, Qt::CaseInsensitive) == 0) {
          Duplicate = true;
          break;
        }
      }
      if (!Duplicate)
        Names.push_back(U8(Name));
    }
    return Names;
  }

  void ShowGenerateDialog() {
    if (!Dialogs)
      return;
    ModuleEntry *Entry = CurrentModule();
    if (!Entry) {
      Notify("No payload module is selected.", NoticeKind::Warning);
      return;
    }
    const std::vector<std::string> ModuleLabels = PayloadLabels_;
    const std::vector<std::string> Encoders = ChoiceNames("Encoder");
    const std::vector<std::string> Nops = ChoiceNames("Nop");
    const std::string Encoder = U8(CachedModuleOptionValue(
        *Entry, {"Encoder", "Encoder_Module"}));
    const std::string Nop =
        U8(CachedModuleOptionValue(*Entry, {"Nop", "Nop_Module"}));
    const auto IndexOf = [](const std::vector<std::string> &Values,
                            const std::string &Needle) {
      for (size_t Index = 0; Index < Values.size(); ++Index) {
        if (Values[Index] == Needle)
          return static_cast<int>(Index);
      }
      return 0;
    };

    TuiDialog Dialog;
    Dialog.Title = "Generate payload";
    Dialog.Body = "Payload/" + Entry->Name + "  |  Author: " + Entry->Author;
    Dialog.Fields.push_back(ComboField("Module", ModuleLabels, ModuleIndex_));
    Dialog.Fields.push_back(
        ComboField("Encoder", Encoders, IndexOf(Encoders, Encoder)));
    Dialog.Fields.push_back(ComboField("Nop", Nops, IndexOf(Nops, Nop)));
    Dialog.Fields.push_back(TextField("Output file", OutputPath_,
                                      "Path and filename"));
    Dialog.PrimaryLabel = "Generate";
    Dialog.OnSubmit = [this](TuiDialog &Submitted) {
      if (Submitted.Fields.size() < 4)
        return;
      ModuleIndex_ = Submitted.Fields[0].Choice;
      UpdateInformation();
      ModuleEntry *Target = CurrentModule();
      if (!Target) {
        Notify("No payload module is selected.", NoticeKind::Warning);
        return;
      }
      QString Error;
      if (!LoadModuleInstance(*Target, &Error)) {
        Notify(U8(Error), NoticeKind::Error);
        return;
      }
      const std::string EncoderName =
          Submitted.Fields[1].Choice > 0
              ? Submitted.Fields[1]
                    .Choices[static_cast<size_t>(Submitted.Fields[1].Choice)]
              : std::string();
      const std::string NopName =
          Submitted.Fields[2].Choice > 0
              ? Submitted.Fields[2]
                    .Choices[static_cast<size_t>(Submitted.Fields[2].Choice)]
              : std::string();
      const QString Path = Qs(TrimAscii(Submitted.Fields[3].Value));
      SetPayloadOption(Target, {"Encoder", "Encoder_Module"}, Qs(EncoderName));
      SetPayloadOption(Target, {"Nop", "Nop_Module"}, Qs(NopName));
      SetPayloadOption(Target, OutputAliases(), Path);
      OutputPath_ = U8(Path);
      Encoder_ = EncoderName.empty() ? "None" : EncoderName;
      Nop_ = NopName.empty() ? "None" : NopName;
      if (StartModuleExecution(Target, nullptr)) {
        MarkMutated();
        Notify("Payload generation started.", NoticeKind::Success);
      } else {
        Notify("A module is already running.", NoticeKind::Warning);
      }
      SetStatus(ModuleStatus());
    };
    Dialogs->Push(std::move(Dialog));
  }

  void Browse() {
    if (auto Path = BrowseSaveFile("Select output file", Qs(OutputPath_))) {
      OutputPath_ = U8(*Path);
      if (ModuleEntry *Entry = CurrentModule())
        SetPayloadOption(Entry, OutputAliases(), *Path);
      return;
    }
    if (!Dialogs)
      return;
    PromptPath(*Dialogs, "Select output file", "Output file", Qs(OutputPath_),
               [this](QString Value) {
                 OutputPath_ = U8(Value);
                 if (ModuleEntry *Entry = CurrentModule())
                   SetPayloadOption(Entry, OutputAliases(), Value);
               },
               "Enter the full path and file name.");
  }

  void ShowModuleOutput(const std::vector<std::string> &Args) {
    if (!Dialogs)
      return;
    if (!Args.empty() && LowerAscii(Args.front()) == "clear") {
      ClearModuleOutput();
      Notify("Module output cleared.", NoticeKind::Success);
      return;
    }
    std::vector<TuiRow> Rows;
    const QString Snapshot = ModuleOutputSnapshot();
    const QStringList Lines = Snapshot.split('\n');
    for (const QString &Line : Lines)
      Rows.push_back(TuiRow{{U8(Line)}, {}});
    if (Rows.empty())
      Rows.push_back(TuiRow{{"(no module output)"}, {}});
    DetailDialog(*Dialogs, "Payload Output", Rows);
  }

  std::string ModuleStatus() const {
    if (ModuleRunning.load() && RunningModulePath == Qs(CurrentModulePath()))
      return "Running " + Qs(CurrentModulePath()).toStdString() + " ...";
    return std::to_string(PayloadModules_.size()) + " payload module(s)";
  }

  // ---- Shell 标签页 ----

  std::string HostStatus() {
    auto Session = CurrentSession();
    return Session ? (U8(Session->Host) + ":" + U8(Session->Port) + "  |  " +
                      U8(Session->Status))
                   : std::string("no host selected");
  }

  void LoadSavedHosts() {
    const QJsonObject Object = ConfigurationSection("PayloadShell");
    const QJsonArray SavedHosts = Object.value("Hosts").toArray();
    HostEntries_.clear();
    if (SavedHosts.isEmpty()) {
      AddHostEntry(ConfigurationValue("PayloadShell", "Host", "127.0.0.1")
                       .toString(),
                   ConfigurationValue("PayloadShell", "Port", "4444")
                       .toString(),
                   QString());
    } else {
      for (const QJsonValue &Value : SavedHosts) {
        const QJsonObject HostObject = Value.toObject();
        const QString Host = HostObject.value("Host").toString().trimmed();
        if (Host.isEmpty())
          continue;
        AddHostEntry(Host, HostObject.value("Port").toString().trimmed(),
                     QString());
      }
      if (HostEntries_.empty())
        AddHostEntry("127.0.0.1", "4444", QString());
    }
    SelectedHost_ = std::clamp(Object.value("SelectedHost").toInt(), 0,
                               std::max(0, static_cast<int>(
                                                HostEntries_.size()) - 1));
    RefreshHostTable();
  }

  void AddHostEntry(const QString &Host, const QString &Port,
                    const QString &Password) {
    // PayloadShellCreateSession 需要 QListWidgetItem；TUI 没有 QListWidget，
    // 因此用一个独立的 item 仅承载角色数据（与 GUI 的角色键完全一致），
    // 其余握手/加密帧逻辑仍走 .inc 的同一套实现。
    auto *Item = new QListWidgetItem;
    const auto Session =
        PayloadShellCreateSession(ShellState_, Item, Host, Port, Password);
    if (!Session) {
      delete Item;
      return;
    }
    PayloadShellSetStatus(Session, "Disconnected", QColor("#8A94A6"));
    PayloadShellLog(Session, "Remote control client ready.",
                    QColor("#4FC3F7"));
    HostEntries_.push_back(PayloadHostEntry{Session->Host, Session->Port,
                                           Session->Password, Session->Id,
                                           Item});
  }

  void RefreshHostTable() {
    Hosts_.Rows.clear();
    Hosts_.Filter = Filter;
    for (const PayloadHostEntry &Entry : HostEntries_) {
      QString Status = "Disconnected";
      const auto It = ShellState_->Sessions.find(Entry.SessionId);
      if (It != ShellState_->Sessions.end())
        Status = It->second->Status;
      Hosts_.Rows.push_back(
          TuiRow{{U8(Entry.Host), U8(Entry.Port), U8(Status)}, {}});
    }
    Hosts_.Rebuild();
    // SelectedHost_ 是原始行号；经 filter 后要换算成 Visible 下标。
    if (!Hosts_.Visible.empty()) {
      const auto It = std::find(Hosts_.Visible.begin(), Hosts_.Visible.end(),
                                SelectedHost_);
      Hosts_.Selected =
          It == Hosts_.Visible.end()
              ? std::min(SelectedHost_,
                         static_cast<int>(Hosts_.Visible.size()) - 1)
              : static_cast<int>(std::distance(Hosts_.Visible.begin(), It));
    }
  }

  std::shared_ptr<PayloadShellSession> CurrentSession() {
    if (SelectedHost_ < 0 ||
        SelectedHost_ >= static_cast<int>(HostEntries_.size()))
      return nullptr;
    const qulonglong Id = HostEntries_[static_cast<size_t>(SelectedHost_)]
                              .SessionId;
    const auto It = ShellState_->Sessions.find(Id);
    return It == ShellState_->Sessions.end() ? nullptr : It->second;
  }

  void PersistHosts() {
    QJsonObject Object = ConfigurationSection("PayloadShell");
    QJsonArray Hosts;
    for (const PayloadHostEntry &Entry : HostEntries_) {
      if (Entry.Host.trimmed().isEmpty())
        continue;
      QJsonObject HostObject;
      HostObject.insert("Host", Entry.Host);
      HostObject.insert("Port", Entry.Port);
      Hosts.append(HostObject);
    }
    Object.insert("Hosts", Hosts);
    Object.insert("SelectedHost", std::max(0, SelectedHost_));
    if (SelectedHost_ >= 0 &&
        SelectedHost_ < static_cast<int>(HostEntries_.size())) {
      Object.insert("Host", HostEntries_[static_cast<size_t>(SelectedHost_)]
                                .Host);
      Object.insert("Port", HostEntries_[static_cast<size_t>(SelectedHost_)]
                                .Port);
    }
    Configuration.insert("PayloadShell", Object);
    SaveConfiguration();
    MarkMutated();
  }

  bool SaveSelectedHost() {
    if (SelectedHost_ < 0 ||
        SelectedHost_ >= static_cast<int>(HostEntries_.size()))
      return false;
    auto Session = CurrentSession();
    if (!Session)
      return false;
    const QString Host = Session->Host.trimmed();
    const QString Port = Session->Port.trimmed();
    if (Host.isEmpty()) {
      Notify("Host is required.", NoticeKind::Warning);
      return false;
    }
    PayloadHostEntry &Entry = HostEntries_[static_cast<size_t>(SelectedHost_)];
    Entry.Host = Host;
    Entry.Port = Port;
    Entry.Password = Session->Password;
    if (Entry.Item) {
      Entry.Item->setData(KPayloadShellRoleHost, Host);
      Entry.Item->setData(KPayloadShellRolePort, Port);
      Entry.Item->setData(KPayloadShellRolePassword, Session->Password);
    }
    PayloadShellSetStatus(Session, Session->Status, Session->StatusColor);
    PersistHosts();
    RefreshHostTable();
    return true;
  }

  void EditSelectedHost() {
    if (!Dialogs)
      return;
    auto Session = CurrentSession();
    if (!Session)
      return;
    TuiDialog Dialog;
    Dialog.Title = "Host";
    Dialog.Fields.push_back(TextField("Host", U8(Session->Host), "127.0.0.1"));
    Dialog.Fields.push_back(TextField("Port", U8(Session->Port), "4444"));
    TuiField Password = TextField("Password", U8(Session->Password),
                                  "Password");
    Password.Kind = TuiFieldKind::Password;
    Dialog.Fields.push_back(std::move(Password));
    Dialog.OnSubmit = [this](TuiDialog &Submitted) {
      if (Submitted.Fields.size() < 3)
        return;
      auto Target = CurrentSession();
      if (!Target)
        return;
      const QString Host = Qs(TrimAscii(Submitted.Fields[0].Value));
      if (Host.isEmpty()) {
        Notify("Host is required.", NoticeKind::Warning);
        return;
      }
      Target->Host = Host;
      Target->Port = Qs(TrimAscii(Submitted.Fields[1].Value));
      Target->Password = Qs(Submitted.Fields[2].Value);
      PersistHosts();
      RefreshHostTable();
      SetStatus(HostStatus());
    };
    Dialogs->Push(std::move(Dialog));
  }

  void NewHost() {
    AddHostEntry("127.0.0.1", "4444", QString());
    SelectedHost_ = static_cast<int>(HostEntries_.size()) - 1;
    PersistHosts();
    RefreshHostTable();
    SetStatus(HostStatus());
  }

  void RemoveHost() {
    if (HostEntries_.size() <= 1) {
      Notify("At least one host entry is required.", NoticeKind::Warning);
      return;
    }
    auto Session = CurrentSession();
    if (!Session)
      return;
    if (Session->Socket)
      Session->Socket->abort();
    ShellState_->Sessions.erase(Session->Id);
    delete HostEntries_[static_cast<size_t>(SelectedHost_)].Item;
    HostEntries_.erase(HostEntries_.begin() + SelectedHost_);
    SelectedHost_ = std::clamp(SelectedHost_, 0,
                               static_cast<int>(HostEntries_.size()) - 1);
    PersistHosts();
    RefreshHostTable();
    SetStatus(HostStatus());
  }

  void FinalizeSession(const std::shared_ptr<PayloadShellSession> &Session,
                       const QString &StatusText, const QColor &Color) {
    if (!Session)
      return;
    QPointer<QTcpSocket> Socket = Session->Socket;
    if (Socket) {
      Socket->disconnect();
      Socket->deleteLater();
      if (Session->Socket == Socket)
        Session->Socket = nullptr;
    }
    PayloadShellResetConnectionState(Session);
    PayloadShellSetStatus(Session, StatusText, Color);
    RefreshHostTable();
    SetStatus(HostStatus());
  }

  void ConnectHost() {
    auto Session = CurrentSession();
    if (!Session || Session->Socket)
      return;
    if (!SaveSelectedHost())
      return;
    const QString Host = Session->Host.trimmed();
    bool PortOk = false;
    const quint16 Port = Session->Port.trimmed().toUShort(&PortOk);
    if (Host.isEmpty()) {
      Notify("Host is required.", NoticeKind::Warning);
      return;
    }
    if (!PortOk || Port == 0) {
      Notify("Port must be between 1 and 65535.", NoticeKind::Warning);
      return;
    }

    PayloadShellResetConnectionState(Session);
    auto *Socket = new QTcpSocket();
    Session->Socket = Socket;
    Session->ReadState = PayloadShellReadState::AwaitChallenge;
    PayloadShellSetStatus(Session, "Connecting...", QColor("#4FC3F7"));
    RefreshHostTable();

    auto SessionCopy = Session;
    PayloadPage *Page = this;
    QObject::connect(Socket, &QTcpSocket::connected, Socket,
                     [Page, SessionCopy, Host, Port] {
                       PayloadShellLog(SessionCopy,
                                       QString("Connected to %1:%2, waiting "
                                               "for challenge.")
                                           .arg(Host)
                                           .arg(Port),
                                       QColor("#4FC3F7"));
                       PayloadShellSetStatus(SessionCopy, "Negotiating...",
                                             QColor("#4FC3F7"));
                       Page->RefreshHostTable();
                     });
    QObject::connect(Socket, &QTcpSocket::readyRead, Socket,
                     [Page, SessionCopy, Socket] {
                       if (SessionCopy->Socket != Socket)
                         return;
                       SessionCopy->ReceiveBuffer.append(Socket->readAll());
                       Page->ProcessBuffer(SessionCopy);
                     });
    QObject::connect(Socket, &QTcpSocket::disconnected, Socket,
                     [Page, SessionCopy, Socket] {
                       if (SessionCopy->Socket != Socket)
                         return;
                       Page->FinalizeSession(SessionCopy, "Disconnected",
                                             QColor("#8A94A6"));
                     });
    QObject::connect(
        Socket, &QTcpSocket::errorOccurred, Socket,
        [Page, SessionCopy, Socket](QAbstractSocket::SocketError Error) {
          if (SessionCopy->Socket != Socket)
            return;
          if (!SessionCopy->DisconnectRequested ||
              Error != QAbstractSocket::RemoteHostClosedError)
            PayloadShellLog(SessionCopy,
                            "Connection error: " + Socket->errorString(),
                            QColor("#FF5F56"));
          Page->FinalizeSession(
              SessionCopy,
              SessionCopy->DisconnectRequested ? "Disconnected"
                                               : "Connection failed",
              SessionCopy->DisconnectRequested ? QColor("#8A94A6")
                                               : QColor("#FF5F56"));
        });
    Socket->connectToHost(Host, Port);
  }

  void DisconnectHost() {
    auto Session = CurrentSession();
    if (!Session) {
      Notify("No host is selected.", NoticeKind::Warning);
      return;
    }
    if (!Session->Socket) {
      FinalizeSession(Session, "Disconnected", QColor("#8A94A6"));
      return;
    }
    Session->DisconnectRequested = true;
    if (!Session->SessionKey.isEmpty()) {
      QString Error;
      PayloadShellSendEncrypted(Session, "exit", &Error);
    }
    QPointer<QTcpSocket> Socket = Session->Socket;
    Socket->disconnectFromHost();
    QTimer::singleShot(300, qApp, [Socket] {
      if (Socket && Socket->state() != QAbstractSocket::UnconnectedState)
        Socket->abort();
    });
  }

  void SendCommand(const std::string &CommandText) {
    auto Session = CurrentSession();
    if (!Session)
      return;
    const QString Command = Qs(TrimAscii(CommandText));
    if (Command.isEmpty())
      return;
    if (Session->SessionKey.isEmpty()) {
      PayloadShellLog(Session, "Not connected!", QColor("#FF5F56"));
      return;
    }
    if (Session->Authenticating || !Session->PendingCommand.isEmpty()) {
      PayloadShellLog(Session, "Wait for the current command to finish.",
                      QColor("#F4BF4F"));
      return;
    }
    PayloadShellLog(Session, "> " + Command, QColor("#F4BF4F"));
    QString Error;
    if (!PayloadShellSendEncrypted(Session, Command, &Error)) {
      PayloadShellLog(Session, "Send failed: " + Error, QColor("#FF5F56"));
      if (Session->Socket)
        Session->Socket->disconnectFromHost();
      return;
    }
    Session->PendingCommand = Command;
  }

  void UploadFile(const std::string &Argument) {
    auto Session = CurrentSession();
    if (!Session)
      return;
    if (Session->SessionKey.isEmpty()) {
      PayloadShellLog(Session, "Not connected!", QColor("#FF5F56"));
      return;
    }
    QString Path = Qs(TrimAscii(Argument));
    if (Path.isEmpty()) {
      if (auto Selected = BrowseOpenFile("Select file to upload",
                                         "All files (*.*)"))
        Path = *Selected;
      if (Path.isEmpty()) {
        if (!Dialogs)
          return;
        PromptPath(*Dialogs, "Upload file", "File path", QString(),
                   [this](QString Value) { UploadFile(U8(Value)); },
                   "The file is base64 encoded and sent as "
                   "'upload <name> <data>'.");
        return;
      }
    }
    QFile File(Path);
    if (!File.open(QIODevice::ReadOnly)) {
      PayloadShellLog(Session,
                      "Upload error: failed to read file: " +
                          File.errorString(),
                      QColor("#FF5F56"));
      return;
    }
    const QByteArray Data = File.readAll();
    SendCommand(U8(QString("upload %1 %2")
                       .arg(QFileInfo(Path).fileName(),
                            QString::fromLatin1(Data.toBase64()))));
  }

  void ShowTranscript() {
    if (!Dialogs)
      return;
    auto Session = CurrentSession();
    std::vector<TuiRow> Rows;
    if (Session) {
      const QStringList Lines = Session->Transcript.split('\n');
      for (const QString &Line : Lines)
        Rows.push_back(TuiRow{{U8(Line)}, {}});
    }
    if (Rows.empty())
      Rows.push_back(TuiRow{{"(no session output)"}, {}});
    DetailDialog(*Dialogs, "Shell Session Output", Rows);
  }

  void ProcessBuffer(const std::shared_ptr<PayloadShellSession> &Session) {
    if (!Session)
      return;
    // GUI 模式（存在 QApplication）直接复用 GUI 处理的完整实现，行为逐字
    // 一致；--console 独占模式没有 QWidget 能力，截屏/下载分支改存到
    // Data/Screenshots 与 Data/Downloads，其余握手/加密帧逻辑完全相同。
    if (HasQtWidgets()) {
      PayloadShellProcessBuffer(ShellState_, Session);
    } else {
      ProcessBufferFileSafe(ShellState_, Session);
    }
    RefreshHostTable();
    SetStatus(HostStatus());
  }

  static void ProcessBufferFileSafe(
      const std::shared_ptr<PayloadShellState> &State,
      const std::shared_ptr<PayloadShellSession> &Session) {
    if (!State || !Session)
      return;
    while (true) {
      if (Session->ReadState == PayloadShellReadState::AwaitChallenge) {
        const int NewLineIndex = Session->ReceiveBuffer.indexOf('\n');
        if (NewLineIndex < 0)
          return;
        const QByteArray Message =
            Session->ReceiveBuffer.left(NewLineIndex).trimmed();
        Session->ReceiveBuffer.remove(0, NewLineIndex + 1);
        if (!Message.startsWith("CHALLENGE:") || Message.size() < 74) {
          PayloadShellLog(Session, "Error: invalid handshake",
                          QColor("#FF5F56"));
          PayloadShellSetStatus(Session, "Handshake failed", QColor("#FF5F56"));
          if (Session->Socket)
            Session->Socket->disconnectFromHost();
          return;
        }
        const QByteArray Challenge = Message.mid(10);
        const QByteArray PasswordHash =
            PayloadShellSha256Hex(Session->Password.toUtf8());
        const QByteArray SessionKeyHex =
            PayloadShellSha256Hex(PasswordHash + Challenge);
        Session->SessionKey = QByteArray::fromHex(SessionKeyHex);
        PayloadShellLog(Session,
                        "Challenge received: " +
                            QString::fromLatin1(Challenge),
                        QColor("#4FC3F7"));
        PayloadShellLog(Session,
                        "PasswordHash: " + QString::fromLatin1(PasswordHash),
                        QColor("#4FC3F7"));
        PayloadShellLog(Session,
                        "SessionKey: " + QString::fromLatin1(SessionKeyHex),
                        QColor("#4FC3F7"));
        QString Error;
        if (!PayloadShellSendEncrypted(
                Session, "AUTH:" + QString::fromLatin1(PasswordHash), &Error)) {
          PayloadShellLog(Session, "Auth send failed: " + Error,
                          QColor("#FF5F56"));
          PayloadShellSetStatus(Session, "Auth send failed",
                                QColor("#FF5F56"));
          if (Session->Socket)
            Session->Socket->disconnectFromHost();
          return;
        }
        Session->Authenticating = true;
        Session->ReadState = PayloadShellReadState::AwaitLength;
        continue;
      }

      if (Session->ReadState == PayloadShellReadState::AwaitLength) {
        if (Session->ReceiveBuffer.size() < 4)
          return;
        const quint32 Length =
            (static_cast<unsigned char>(Session->ReceiveBuffer[0]) << 24) |
            (static_cast<unsigned char>(Session->ReceiveBuffer[1]) << 16) |
            (static_cast<unsigned char>(Session->ReceiveBuffer[2]) << 8) |
            static_cast<unsigned char>(Session->ReceiveBuffer[3]);
        Session->ReceiveBuffer.remove(0, 4);
        if (Length == 0 || Length > 100u * 1024u * 1024u) {
          PayloadShellLog(Session, "Receive failed: invalid packet length.",
                          QColor("#FF5F56"));
          if (Session->Socket)
            Session->Socket->disconnectFromHost();
          return;
        }
        Session->ExpectedPayloadLength = static_cast<int>(Length);
        Session->ReadState = PayloadShellReadState::AwaitPayload;
        continue;
      }

      if (Session->ReadState == PayloadShellReadState::AwaitPayload) {
        if (Session->ReceiveBuffer.size() < Session->ExpectedPayloadLength)
          return;
        const QByteArray Packet =
            Session->ReceiveBuffer.left(Session->ExpectedPayloadLength);
        Session->ReceiveBuffer.remove(0, Session->ExpectedPayloadLength);
        Session->ExpectedPayloadLength = 0;
        Session->ReadState = PayloadShellReadState::AwaitLength;

        QByteArray Plaintext;
        QString Error;
        if (!PayloadShellDecrypt(Packet, Session->SessionKey, &Plaintext,
                                 &Error)) {
          PayloadShellLog(Session, "Receive failed: " + Error,
                          QColor("#FF5F56"));
          if (Session->Socket)
            Session->Socket->disconnectFromHost();
          return;
        }

        const QString Response = QString::fromUtf8(Plaintext);
        if (Session->Authenticating) {
          Session->Authenticating = false;
          if (Response == "AUTH_OK") {
            PayloadShellLog(Session, "Connected!", QColor("#27C93F"));
            PayloadShellSetStatus(Session, "Connected", QColor("#27C93F"));
          } else {
            PayloadShellLog(Session, "Auth failed: " + Response,
                            QColor("#FF5F56"));
            PayloadShellSetStatus(Session, "Auth failed", QColor("#FF5F56"));
            if (Session->Socket)
              Session->Socket->disconnectFromHost();
          }
          continue;
        }

        const QString PendingCommand = Session->PendingCommand;
        Session->PendingCommand.clear();
        if (Response == "BYE") {
          PayloadShellLog(Session, "Server closed connection.",
                          QColor("#4FC3F7"));
          if (Session->Socket)
            Session->Socket->disconnectFromHost();
          return;
        }
        HandleResponseFileSafe(Session, PendingCommand, Response);
        continue;
      }
      return;
    }
  }

  static QString DataSubdirectory(const QString &Name) {
    const QString Directory =
        QDir(QCoreApplication::applicationDirPath()).filePath("Data/" + Name);
    QDir().mkpath(Directory);
    return Directory;
  }

  static void HandleResponseFileSafe(
      const std::shared_ptr<PayloadShellSession> &Session,
      const QString &Command, const QString &Response) {
    const QString NormalizedCommand = Command.trimmed().toLower();
    if (Response.startsWith("ERR:")) {
      PayloadShellLog(Session, Response, QColor("#FF5F56"));
      return;
    }

    if (NormalizedCommand == "screenshot") {
      const QString Data = Response.startsWith("OK\n") ? Response.mid(3).trimmed()
                                                      : Response.trimmed();
      const QByteArray ImageBytes = QByteArray::fromHex(Data.toLatin1());
      if (ImageBytes.isEmpty()) {
        PayloadShellLog(Session, "Failed to decode screenshot payload.",
                        QColor("#FF5F56"));
        return;
      }
      const QString Directory = DataSubdirectory("Screenshots");
      const QString Path = QDir(Directory).filePath(
          QString("screenshot-%1.png")
              .arg(QDateTime::currentDateTimeUtc().toString(
                  "yyyyMMdd-hhmmss")));
      QSaveFile File(Path);
      if (!File.open(QIODevice::WriteOnly) ||
          File.write(ImageBytes) != ImageBytes.size() || !File.commit()) {
        PayloadShellLog(Session,
                        "Failed to save screenshot: " + File.errorString(),
                        QColor("#FF5F56"));
        return;
      }
      PayloadShellLog(Session,
                      QString("Screenshot received (%1 bytes)")
                          .arg(ImageBytes.size()),
                      QColor("#27C93F"));
      PayloadShellLog(Session,
                      "Saved to: " + QDir::toNativeSeparators(Path),
                      QColor("#27C93F"));
      AppendConsoleOutput("[*] PayloadShell screenshot: " +
                          QDir::toNativeSeparators(Path) + "\n");
      return;
    }

    if (NormalizedCommand.startsWith("download ")) {
      const QString Data = Response.startsWith("OK\n") ? Response.mid(3).trimmed()
                                                      : Response.trimmed();
      const QByteArray FileBytes = QByteArray::fromBase64(Data.toLatin1());
      if (FileBytes.isEmpty() && !Data.isEmpty()) {
        PayloadShellLog(Session, "ERR: failed to decode file data",
                        QColor("#FF5F56"));
        return;
      }
      QString FileName = QFileInfo(NormalizedCommand.mid(9).trimmed()).fileName();
      if (FileName.isEmpty())
        FileName = "download.bin";
      const QString Directory = DataSubdirectory("Downloads");
      const QString Path = QDir(Directory).filePath(FileName);
      QSaveFile File(Path);
      if (!File.open(QIODevice::WriteOnly) ||
          File.write(FileBytes) != FileBytes.size() || !File.commit()) {
        PayloadShellLog(Session,
                        "ERR: failed to save downloaded file: " +
                            File.errorString(),
                        QColor("#FF5F56"));
        return;
      }
      PayloadShellLog(Session,
                      QString("Saved to: %1 (%2 bytes)")
                          .arg(QDir::toNativeSeparators(Path))
                          .arg(FileBytes.size()),
                      QColor("#27C93F"));
      return;
    }

    const QString Text = Response.startsWith("OK\n") ? Response.mid(3) : Response;
    PayloadShellLog(Session, Text, QColor("#7CFC00"));
  }

  void AbortAllSessions() {
    for (auto &[Id, Session] : ShellState_->Sessions) {
      Q_UNUSED(Id);
      if (Session->Socket) {
        Session->Socket->abort();
        Session->Socket->deleteLater();
      }
    }
    ShellState_->Sessions.clear();
  }

  int Index_ = 0;
  bool Loaded_ = false;
  int Tab_ = 0;
  int64_t LastTickMs_ = 0;

  std::shared_ptr<PayloadShellState> ShellState_;
  std::vector<PayloadHostEntry> HostEntries_;
  int SelectedHost_ = 0;

  std::vector<ModuleEntry *> PayloadModules_;
  std::vector<std::string> PayloadLabels_;
  int ModuleIndex_ = 0;
  std::string ModuleLabel_ = "No payload module";
  std::vector<std::string> ModuleInfoLines_;
  std::string Encoder_ = "None";
  std::string Nop_ = "None";
  std::string OutputPath_;

  TuiTable Params_;
  std::vector<std::string> ParamOptionNames_;
  TuiTable Hosts_;
};

// ------------------------------------------------------------
// 11 · ModuleRun —— 模块选择 / 选项 / 检查 / 运行 / 停止
// ------------------------------------------------------------

class ModuleRunPage final : public TuiPage {
public:
  explicit ModuleRunPage(int Index) : Index_(Index) {
    Options_.Headers = {"Option", "Type", "Value", "Description"};
    Modules_.Headers = {"Module", "Path"};
    RegisterCommands();
  }

  std::string Title() const override { return "ModuleRun"; }

  std::string Subtitle() const override {
    return "run a module: category, module, options, check, start/stop";
  }

  void OnEnter() override {
    Loaded_ = true;
    PopulateModules();
  }

  void OnTick(int64_t NowMs) override {
    if (LastTickMs_ != 0 && NowMs - LastTickMs_ < 150)
      return;
    LastTickMs_ = NowMs;
    SetStatus(StatusText());
  }

  TuiTable *ActiveTable() override { return &Modules_; }

  std::string RenderText() override {
    // 与原来的双表主体一致：模块表在上、选项表在下，一次 show 全给出。
    PopulateModules();
    std::string Text =
        "Category: " + Categories_[static_cast<size_t>(CategoryIndex_)] +
        "   Module: " + ModuleLabel_ + "   State: " +
        (ModuleRunning.load() ? "running" : "idle") + '\n';
    for (const std::string &Line : InfoLines_)
      Text += "  " + Line + '\n';
    Text += "Modules  (select <module>, category <name>)\n";
    Text += TuiTableToText(Modules_, 200);
    Text += "Options  (option <name>)\n";
    Text += TuiTableToText(Options_, 200);
    return Text;
  }

private:
  void RegisterCommands() {
    OwnedCommands.push_back(
        {"refresh", "refresh  (rescan modules)",
         [this](std::vector<std::string>) { RefreshModules(); }});
    OwnedCommands.push_back(
        {"check", "check  (run the compatibility check)",
         [this](std::vector<std::string>) { CheckModule(); }});
    OwnedCommands.push_back({"run", "run  (start the selected module)",
                             [this](std::vector<std::string>) { RunModule(); }});
    OwnedCommands.push_back({"stop", "stop  (signal the running module)",
                             [this](std::vector<std::string>) { StopModule(); }});
    OwnedCommands.push_back(
        {"module-output", "module-output [clear]",
         [this](std::vector<std::string> Args) { ShowModuleOutput(Args); }});
    OwnedCommands.push_back(
        {"category", "category [all|exploit|auxiliary|post]",
         [this](std::vector<std::string> Args) { SetCategory(Args); }});
    OwnedCommands.push_back(
        {"select", "select [module]  (choose a module)",
         [this](std::vector<std::string> Args) { SelectModule(Args); }});
    OwnedCommands.push_back(
        {"option", "option [name]  (edit a module option)",
         [this](std::vector<std::string> Args) { EditOptionByName(Args); }});
  }

  void SetCategory(const std::vector<std::string> &Args) {
    if (!Args.empty()) {
      const std::string Needle = LowerAscii(Args.front());
      for (size_t Index = 0; Index < Categories_.size(); ++Index) {
        if (LowerAscii(Categories_[Index]) == Needle) {
          CategoryIndex_ = static_cast<int>(Index);
          PopulateModules();
          return;
        }
      }
      Notify("Unknown category: " + Args.front(), NoticeKind::Warning);
      return;
    }
    if (!Dialogs)
      return;
    TuiDialog Dialog;
    Dialog.Title = "Module category";
    Dialog.Fields.push_back(ComboField("Category", Categories_, CategoryIndex_));
    Dialog.OnSubmit = [this](TuiDialog &Submitted) {
      if (Submitted.Fields.empty())
        return;
      CategoryIndex_ = Submitted.Fields.front().Choice;
      PopulateModules();
    };
    Dialogs->Push(std::move(Dialog));
  }

  void RefreshModules() {
    if (ModuleRunning.load()) {
      Notify("Wait for the running module to finish before refreshing.",
             NoticeKind::Warning);
      return;
    }
    ScanRuntimeModules();
    PopulateModules();
    Notify("Module list refreshed.", NoticeKind::Success);
  }

  void PopulateModules() {
    const std::string PreviousPath = CurrentPath();
    ModulesModulePaths_.clear();
    ModuleEntries_.clear();
    Modules_.Rows.clear();
    for (ModuleEntry *Module :
         ModulesByCategory(Qs(Categories_[static_cast<size_t>(CategoryIndex_)]))) {
      ModuleEntries_.push_back(Module);
      ModulesModulePaths_.push_back(Module->Path);
      Modules_.Rows.push_back(TuiRow{{Module->Category + "/" + Module->Name,
                                      Module->Path},
                                     {}});
    }
    Modules_.Filter = Filter;
    Modules_.Rebuild();
    int Restored = -1;
    for (size_t Index = 0; Index < ModulesModulePaths_.size(); ++Index) {
      if (ModulesModulePaths_[Index] == PreviousPath) {
        Restored = static_cast<int>(Index);
        break;
      }
    }
    SelectedModule_ = Restored >= 0 ? Restored : 0;
    // SelectedModule_ 是原始行号；filter 后换算成 Visible 下标。
    if (!Modules_.Visible.empty()) {
      const auto It = std::find(Modules_.Visible.begin(), Modules_.Visible.end(),
                                SelectedModule_);
      Modules_.Selected =
          It == Modules_.Visible.end()
              ? std::min(SelectedModule_,
                         static_cast<int>(Modules_.Visible.size()) - 1)
              : static_cast<int>(std::distance(Modules_.Visible.begin(), It));
    }
    PopulateOptions();
  }

  std::string CurrentPath() const {
    if (SelectedModule_ < 0 ||
        SelectedModule_ >= static_cast<int>(ModuleEntries_.size()))
      return {};
    return ModuleEntries_[static_cast<size_t>(SelectedModule_)]->Path;
  }

  ModuleEntry *CurrentEntry() {
    if (SelectedModule_ < 0 ||
        SelectedModule_ >= static_cast<int>(ModuleEntries_.size()))
      return nullptr;
    return ModuleEntries_[static_cast<size_t>(SelectedModule_)];
  }

  void SelectFromTable() {
    const int Row = Modules_.CurrentRowIndex();
    if (Row < 0 || Row >= static_cast<int>(ModuleEntries_.size()))
      return;
    if (Row == SelectedModule_)
      return;
    SelectedModule_ = Row;
    PopulateOptions();
  }

  void SelectModule(const std::vector<std::string> &Args) {
    if (!Args.empty()) {
      const std::string Needle = LowerAscii(Args.front());
      for (size_t Index = 0; Index < ModuleEntries_.size(); ++Index) {
        const std::string Label =
            LowerAscii(ModuleEntries_[Index]->Name);
        const std::string Full = LowerAscii(
            ModuleEntries_[Index]->Category + "/" + ModuleEntries_[Index]->Name);
        if (Label == Needle || Full == Needle ||
            Full.find(Needle) != std::string::npos) {
          SelectedModule_ = static_cast<int>(Index);
          if (!Modules_.Visible.empty())
            Modules_.Selected = std::min<int>(SelectedModule_,
                                             static_cast<int>(Modules_.Visible.size()) - 1);
          PopulateOptions();
          return;
        }
      }
      Notify("Unknown module: " + Args.front(), NoticeKind::Warning);
      return;
    }
    if (!Dialogs)
      return;
    std::vector<std::string> Labels;
    for (ModuleEntry *Entry : ModuleEntries_)
      Labels.push_back(Entry->Category + "/" + Entry->Name);
    if (Labels.empty()) {
      Notify("No module is available for this category.",
             NoticeKind::Warning);
      return;
    }
    TuiDialog Dialog;
    Dialog.Title = "Select module";
    Dialog.Fields.push_back(ComboField("Module", Labels, SelectedModule_));
    Dialog.PrimaryLabel = "Select";
    Dialog.OnSubmit = [this](TuiDialog &Submitted) {
      if (Submitted.Fields.empty())
        return;
      SelectedModule_ = Submitted.Fields.front().Choice;
      if (!Modules_.Visible.empty())
        Modules_.Selected = std::min<int>(SelectedModule_,
                                         static_cast<int>(Modules_.Visible.size()) - 1);
      PopulateOptions();
    };
    Dialogs->Push(std::move(Dialog));
  }

  void PopulateOptions() {
    Options_.Rows.clear();
    OptionNames_.clear();
    InfoLines_.clear();
    Options_.Filter = Filter;
    ModuleEntry *Entry = CurrentEntry();
    if (!Entry) {
      ModuleLabel_ = "Select module";
      InfoLines_.push_back("Select a module to configure its call controls.");
      Options_.Rebuild();
      SetStatus(StatusText());
      return;
    }
    QString Error;
    if (!LoadModuleInstance(*Entry, &Error)) {
      ModuleLabel_ = Entry->Category + "/" + Entry->Name;
      InfoLines_.push_back("Failed to load module: " + U8(Error));
      InfoLines_.push_back(Entry->Path);
      AppendConsoleOutput("[!] ModuleRun: " + Qs(InfoLines_.back()) + "\n");
      Options_.Rebuild();
      SetStatus(StatusText());
      return;
    }
    auto *Instance = static_cast<ModuleBase *>(Entry->ModuleInstance);
    const ModuleInfo Info = Instance->Info();
    ModuleLabel_ = std::string(ModuleTypeToString(Info.Type)) + "/" +
                   Info.Name;
    InfoLines_.push_back(
        std::string(ModuleTypeToString(Info.Type)) + "/" + Info.Name +
        "  |  Author: " +
        (Info.Author.empty() ? Entry->Author : Info.Author) +
        "  |  Target: " +
        (Info.DefaultTarget.empty() ? std::string("Unknown")
                                    : Info.DefaultTarget));
    InfoLines_.push_back(Info.Description.empty() ? Entry->Description
                                                 : Info.Description);

    for (const auto &[Name, OptionPointer] : Instance->GetOptions()) {
      const bool Required =
          OptionPointer->GetRequired() == OptionRequired::Required;
      Options_.Rows.push_back(TuiRow{{Name + (Required ? " *" : ""),
                                      OptionPointer->TypeName(),
                                      OptionPointer->GetValue(),
                                      OptionPointer->GetDescription()},
                                     {}});
      OptionNames_.push_back(Name);
    }
    Options_.Rebuild();
    if (Options_.Selected >= static_cast<int>(Options_.Visible.size()))
      Options_.Selected =
          std::max(0, static_cast<int>(Options_.Visible.size()) - 1);
    SetStatus(StatusText());
  }

  void EditOption() {
    const int Row = Options_.CurrentRowIndex();
    if (Row < 0 || Row >= static_cast<int>(OptionNames_.size()))
      return;
    EditOptionByName({OptionNames_[static_cast<size_t>(Row)]});
  }

  void EditOptionByName(const std::vector<std::string> &Args) {
    if (!Dialogs)
      return;
    ModuleEntry *Entry = CurrentEntry();
    if (!Entry || !Entry->ModuleInstance)
      return;
    auto *Instance = static_cast<ModuleBase *>(Entry->ModuleInstance);
    const auto &Options = Instance->GetOptions();
    if (Options.empty())
      return;
    std::string Name;
    if (!Args.empty())
      Name = Args.front();
    else if (Options_.CurrentRowIndex() >= 0 &&
             Options_.CurrentRowIndex() < static_cast<int>(OptionNames_.size()))
      Name = OptionNames_[static_cast<size_t>(Options_.CurrentRowIndex())];
    if (Name.empty())
      return;
    const auto It = Options.find(Name);
    if (It == Options.end()) {
      Notify("Unknown option: " + Name, NoticeKind::Warning);
      return;
    }
    Option *OptionPointer = It->second.get();
    const std::string Current = OptionPointer->GetValue();
    const QString Path = Qs(Entry->Path);

    TuiDialog Dialog;
    Dialog.Title = "Option: " + Name;
    Dialog.Body = OptionPointer->GetDescription();
    if (auto *EnumOption = dynamic_cast<OptEnum *>(OptionPointer)) {
      const auto &Choices = EnumOption->GetChoices();
      int Choice = 0;
      for (size_t Index = 0; Index < Choices.size(); ++Index) {
        if (Choices[Index] == Current)
          Choice = static_cast<int>(Index);
      }
      Dialog.Fields.push_back(ComboField("Value", Choices, Choice));
    } else if (dynamic_cast<OptBool *>(OptionPointer)) {
      const bool True =
          LowerAscii(Current) != "false" && LowerAscii(Current) != "0";
      Dialog.Fields.push_back(
          ComboField("Value", {"true", "false"}, True ? 0 : 1));
    } else {
      Dialog.Fields.push_back(
          TextField("Value", Current, OptionPointer->GetDefaultValue()));
    }
    Dialog.OnSubmit = [this, Path, Name](TuiDialog &Submitted) {
      if (Submitted.Fields.empty())
        return;
      const std::string Value = ChoiceValue(Submitted.Fields.front());
      if (ModuleEntry *Module = FindDllModule(Path))
        if (Module->ModuleInstance)
          static_cast<ModuleBase *>(Module->ModuleInstance)
              ->SetOption(Name, Value);
      PopulateOptions();
    };
    Dialogs->Push(std::move(Dialog));
  }

  void CheckModule() {
    ModuleEntry *Entry = CurrentEntry();
    if (!Entry)
      return;
    if (ModuleRunning.load()) {
      Notify("Wait for the running module to finish before checking "
             "compatibility.",
             NoticeKind::Warning);
      return;
    }
    if (!Entry->ModuleInstance) {
      QString Error;
      if (!LoadModuleInstance(*Entry, &Error)) {
        Notify(U8(Error), NoticeKind::Error);
        return;
      }
    }
    AppendModuleOutput("[*] Checking module compatibility: " +
                       Qs(Entry->Name) + "\n");
    ModuleEntry *Captured = Entry;
    TuiAsyncVoid(
        [Captured] {
          bool Compatible = false;
          DWORD SehCode = ERROR_SUCCESS;
          QString CheckError;
          Module::CaptureOutputStreaming(
              [&] {
                try {
                  if (!InvokeModuleCheckWithSeh(
                          static_cast<ModuleBase *>(Captured->ModuleInstance),
                          &Compatible, &SehCode))
                    CheckError = QString("Module raised SEH exception 0x%1.")
                                     .arg(static_cast<qulonglong>(SehCode), 8,
                                          16, QLatin1Char('0'))
                                     .toUpper();
                } catch (const std::exception &Error) {
                  CheckError = "Module raised a C++ exception: " +
                               QString::fromLocal8Bit(Error.what());
                } catch (...) {
                  CheckError = "Module raised an unknown C++ exception.";
                }
              },
              [](const std::string &Chunk) {
                static thread_local QByteArray Carry;
                AppendModuleOutput(DecodeConsoleChunk(
                    Carry, QByteArray(Chunk.data(),
                                      static_cast<qsizetype>(Chunk.size()))));
              });
          const QString Text =
              !CheckError.isEmpty()
                  ? QString("[!] Compatibility check failed: ") + CheckError
                  : QString(Compatible ? "[+] Compatibility check passed."
                                       : "[!] Compatibility check failed.");
          TuiPost([Text, Compatible, CheckError] {
            AppendModuleOutput(Text + "\n");
            if (!CheckError.isEmpty())
              return;
            if (Compatible)
              AppendConsoleOutput("[+] ModuleRun: Compatibility check "
                                  "passed.\n");
            else
              AppendConsoleOutput("[!] ModuleRun: Compatibility check "
                                  "failed.\n");
          });
        },
        [this] {
          // 结果已经写进模块输出/控制台；UI 侧只刷新状态。
          SetStatus(StatusText());
        });
    SetStatus("Checking compatibility...");
  }

  void RunModule() {
    ModuleEntry *Entry = CurrentEntry();
    if (!Entry)
      return;
    if (!Entry->ModuleInstance) {
      QString Error;
      if (!LoadModuleInstance(*Entry, &Error)) {
        Notify(U8(Error), NoticeKind::Error);
        return;
      }
    }
    if (StartModuleExecution(Entry, nullptr))
      Notify("Module execution started.", NoticeKind::Success);
  }

  void StopModule() {
    ModuleEntry *Entry = CurrentEntry();
    if (!Entry || !Entry->Handle ||
        RunningModulePath != Qs(Entry->Path)) {
      AppendModuleOutput("[!] No running module.\n");
      return;
    }
    const auto Stop = reinterpret_cast<void (*)()>(
        GetProcAddress(Entry->Handle, "StopModule"));
    if (!Stop) {
      AppendModuleOutput(
          "[!] StopModule export not found; cannot signal module.\n");
      return;
    }
    Stop();
    AppendModuleOutput("[*] Stop requested.\n");
    Notify("Stop request sent.", NoticeKind::Success);
  }

  void ShowModuleOutput(const std::vector<std::string> &Args) {
    if (!Dialogs)
      return;
    if (!Args.empty() && LowerAscii(Args.front()) == "clear") {
      ClearModuleOutput();
      Notify("Module output cleared.", NoticeKind::Success);
      return;
    }
    std::vector<TuiRow> Rows;
    const QStringList Lines = ModuleOutputSnapshot().split('\n');
    for (const QString &Line : Lines)
      Rows.push_back(TuiRow{{U8(Line)}, {}});
    if (Rows.empty())
      Rows.push_back(TuiRow{{"(no module output)"}, {}});
    DetailDialog(*Dialogs, "Module Output", Rows);
  }

  std::string StatusText() const {
    std::string Text = std::to_string(ModuleEntries_.size()) + " module(s)";
    if (ModuleRunning.load())
      Text += "  |  running: " + U8(RunningModulePath);
    return Text;
  }

  int Index_ = 0;
  bool Loaded_ = false;
  int64_t LastTickMs_ = 0;
  std::vector<std::string> Categories_{"All", "Exploit", "Auxiliary", "Post"};
  int CategoryIndex_ = 0;
  std::vector<ModuleEntry *> ModuleEntries_;
  std::vector<std::string> ModulesModulePaths_;
  int SelectedModule_ = 0;
  std::string ModuleLabel_ = "Select module";
  std::vector<std::string> InfoLines_;
  TuiTable Modules_;
  TuiTable Options_;
  std::vector<std::string> OptionNames_;
};

// ------------------------------------------------------------
// 12 · ModuleManager —— 模块列表 / 加载 / 移除 / 切换状态
// ------------------------------------------------------------

class ModuleManagerPage final : public TuiPage {
public:
  explicit ModuleManagerPage(int Index) : Index_(Index) {
    Table_.Headers = {"Name", "Type", "Author", "State", "Path"};
    RegisterCommands();
  }

  std::string Title() const override { return "ModuleManager"; }

  std::string Subtitle() const override {
    return "module inventory: load/unload, add a DLL, remove, details";
  }

  void OnEnter() override {
    EnsureRuntimeModulesScanned();
    Populate();
  }

  TuiTable *ActiveTable() override { return &Table_; }

  std::string RenderText() override {
    EnsureRuntimeModulesScanned();
    Populate();
    std::string Text;
    for (const std::string &Line : PathsLines_)
      Text += "  " + Line + '\n';
    Text += "  Kind: " + Kinds_[static_cast<size_t>(KindIndex_)] +
            "   (toggle, details, load-dll, remove)\n";
    Text += TuiTableToText(Table_, 200);
    // 选中行详情：原 F10 / `details` 对话框的内容直接跟在表格后面。
    if (const TuiRow *Row = Table_.Current()) {
      Text += "Detail:\n";
      for (size_t Index = 0;
           Index < Row->Cells.size() && Index < Table_.Headers.size();
           ++Index)
        Text += "  " + Table_.Headers[Index] + ": " + Row->Cells[Index] + '\n';
      if (!Row->Detail.empty())
        Text += "  Description: " + Row->Detail + '\n';
    }
    return Text;
  }

private:
  void RegisterCommands() {
    OwnedCommands.push_back(
        {"refresh", "refresh  (rescan module directories)",
         [this](std::vector<std::string>) { Refresh(); }});
    OwnedCommands.push_back(
        {"load-dll", "load-dll [path]  (add a DLL module)",
         [this](std::vector<std::string> Args) { LoadDll(Args); }});
    OwnedCommands.push_back(
        {"remove", "remove  (remove the selected item)",
         [this](std::vector<std::string>) { RemoveSelected(); }});
    OwnedCommands.push_back(
        {"toggle", "toggle  (load or unload the selected item)",
         [this](std::vector<std::string>) { ToggleSelected(); }});
    OwnedCommands.push_back({"details", "details  (show the selected row)",
                             [this](std::vector<std::string>) {
                               ShowDetails();
                             }});
    OwnedCommands.push_back(
        {"kind", "kind [all|dll|driver]",
         [this](std::vector<std::string> Args) { SetKind(Args); }});
  }

  void SetKind(const std::vector<std::string> &Args) {
    if (!Args.empty()) {
      const std::string Needle = LowerAscii(Args.front());
      for (size_t Index = 0; Index < Kinds_.size(); ++Index) {
        if (LowerAscii(Kinds_[Index]).find(Needle) == 0 ||
            (Needle == "dll" && Index == 1) ||
            (Needle == "driver" && Index == 2)) {
          KindIndex_ = static_cast<int>(Index);
          Populate();
          return;
        }
      }
      Notify("Unknown kind: " + Args.front(), NoticeKind::Warning);
      return;
    }
    if (!Dialogs)
      return;
    TuiDialog Dialog;
    Dialog.Title = "Module kind";
    Dialog.Fields.push_back(ComboField("Kind", Kinds_, KindIndex_));
    Dialog.OnSubmit = [this](TuiDialog &Submitted) {
      if (Submitted.Fields.empty())
        return;
      KindIndex_ = Submitted.Fields.front().Choice;
      Populate();
    };
    Dialogs->Push(std::move(Dialog));
  }

  void Refresh() {
    if (ModuleRunning.load()) {
      Notify("Wait for the running module to finish before reloading "
             "modules.",
             NoticeKind::Warning);
      return;
    }
    ScanRuntimeModules();
    Populate();
    Notify("Modules reloaded.", NoticeKind::Success);
  }

  void Populate() {
    PathsLines_.clear();
    PathsLines_.push_back(
        "Modules: " + U8(ConfigurationPaths("Modules", "./Modules")
                             .join("; ")));
    PathsLines_.push_back(
        "Drivers: " + U8(ConfigurationPaths("Drivers", "./Drivers")
                             .join("; ")));

    const std::string PreviousPath = SelectedPath();
    Table_.Rows.clear();
    RowPaths_.clear();
    RowIsDriver_.clear();

    const auto Append = [this](ModuleEntry &Module, bool IsDriver) {
      if (IsDriver)
        Module.Loaded = QueryDriverLoadedState(Module);
      const std::string State = Module.Valid
                                    ? (Module.Loaded ? "Active" : "Inactive")
                                    : "Skipped";
      Table_.Rows.push_back(TuiRow{{Module.Name, Module.Category,
                                    Module.Author, State, Module.Path},
                                   Module.Description});
      RowPaths_.push_back(Module.Path);
      RowIsDriver_.push_back(IsDriver);
    };

    if (KindIndex_ != 2)
      for (ModuleEntry &Module : DllModules)
        Append(Module, false);
    if (KindIndex_ != 1)
      for (ModuleEntry &Driver : DriverModules)
        Append(Driver, true);

    Table_.Filter = Filter;
    Table_.Rebuild();
    int Restored = -1;
    for (size_t Index = 0; Index < RowPaths_.size(); ++Index) {
      if (RowPaths_[Index] == PreviousPath) {
        Restored = static_cast<int>(Index);
        break;
      }
    }
    if (Restored >= 0) {
      const auto It = std::find(Table_.Visible.begin(), Table_.Visible.end(),
                                Restored);
      if (It != Table_.Visible.end())
        Table_.Selected =
            static_cast<int>(std::distance(Table_.Visible.begin(), It));
    }
    SetStatus(std::to_string(Table_.Rows.size()) + " module(s), kind " +
              Kinds_[static_cast<size_t>(KindIndex_)]);
  }

  std::string SelectedPath() const {
    const int Row = Table_.CurrentRowIndex();
    if (Row < 0 || Row >= static_cast<int>(RowPaths_.size()))
      return {};
    return RowPaths_[static_cast<size_t>(Row)];
  }

  bool SelectedIsDriver() const {
    const int Row = Table_.CurrentRowIndex();
    if (Row < 0 || Row >= static_cast<int>(RowIsDriver_.size()))
      return false;
    return RowIsDriver_[static_cast<size_t>(Row)];
  }

  ModuleEntry *FindModule(const std::string &Path, bool IsDriver) {
    std::vector<ModuleEntry> &List = IsDriver ? DriverModules : DllModules;
    const auto It = std::find_if(
        List.begin(), List.end(), [&Path](const ModuleEntry &Module) {
          return Module.Path == Path;
        });
    return It == List.end() ? nullptr : &*It;
  }

  void LoadDll(const std::vector<std::string> &Args) {
    QString Path = Qs(TrimAscii(Args.empty() ? std::string()
                                             : Args.front()));
    if (Path.isEmpty()) {
      if (auto Selected = BrowseOpenFile("Select DLL", "DLL files (*.dll)"))
        Path = *Selected;
      if (Path.isEmpty()) {
        if (!Dialogs)
          return;
        PromptPath(*Dialogs, "Load DLL", "DLL path", QString(),
                   [this](QString Value) { LoadDll({U8(Value)}); });
        return;
      }
    }
    const QString AbsolutePath = QFileInfo(Path).absoluteFilePath();
    const bool Exists =
        std::any_of(DllModules.begin(), DllModules.end(),
                    [&AbsolutePath](const ModuleEntry &Module) {
                      return Qs(Module.Path).compare(AbsolutePath,
                                                     Qt::CaseInsensitive) == 0;
                    });
    if (!Exists) {
      EnsureRuntimeModulesScanned();
      DllModules.push_back(ProbeModuleFile(AbsolutePath));
      ModuleEntry &Module = DllModules.back();
      if (Module.Valid &&
          ConfigurationValue("Modules", "AutoLoad", true).toBool())
        LoadModuleInstance(Module);
      MarkMutated();
    }
    KindIndex_ = 0;
    Populate();
    Notify(Exists ? "Module is already in the list." : "DLL module added.",
           NoticeKind::Success);
  }

  void RemoveSelected() {
    const std::string Path = SelectedPath();
    if (Path.empty())
      return;
    const bool IsDriver = SelectedIsDriver();
    ModuleEntry *Entry = FindModule(Path, IsDriver);
    if (!Entry)
      return;
    if (Entry->Loaded) {
      QString Error;
      const bool Ok = IsDriver ? SetDriverLoaded(*Entry, false, &Error)
                               : (DestroyModuleInstance(*Entry), true);
      if (!Ok) {
        Notify(U8(Error), NoticeKind::Error);
        return;
      }
    }
    std::vector<ModuleEntry> &List = IsDriver ? DriverModules : DllModules;
    List.erase(std::remove_if(List.begin(), List.end(),
                              [&Path](const ModuleEntry &Module) {
                                return Module.Path == Path;
                              }),
               List.end());
    MarkMutated();
    Populate();
    Notify("Item removed from the module list.", NoticeKind::Success);
  }

  void ToggleSelected() {
    if (ModuleRunning.load()) {
      Notify("Wait for the running module to finish before changing module "
             "state.",
             NoticeKind::Warning);
      return;
    }
    const std::string Path = SelectedPath();
    if (Path.empty())
      return;
    const bool IsDriver = SelectedIsDriver();
    ModuleEntry *Entry = FindModule(Path, IsDriver);
    if (!Entry)
      return;
    QString Error;
    bool Ok = false;
    if (IsDriver) {
      Ok = SetDriverLoaded(*Entry, !Entry->Loaded, &Error);
    } else if (Entry->Loaded) {
      DestroyModuleInstance(*Entry);
      Ok = true;
    } else {
      Ok = LoadModuleInstance(*Entry, &Error);
    }
    if (!Ok) {
      Notify(U8(Error.isEmpty() ? QString("The operation failed.") : Error),
             NoticeKind::Error);
    } else {
      Notify(IsDriver ? "Driver state updated." : "Module state updated.",
             NoticeKind::Success);
    }
    MarkMutated();
    Populate();
  }

  void ShowDetails() {
    if (!Dialogs)
      return;
    const TuiRow *Row = Table_.Current();
    if (!Row)
      return;
    std::vector<TuiRow> Rows;
    for (size_t Index = 0; Index < Row->Cells.size() &&
                            Index < Table_.Headers.size();
         ++Index)
      Rows.push_back(TuiRow{{Table_.Headers[Index], Row->Cells[Index]}, {}});
    if (!Row->Detail.empty())
      Rows.push_back(TuiRow{{"Description", Row->Detail}, {}});
    DetailDialog(*Dialogs, "Module Details", Rows);
  }

  int Index_ = 0;
  std::vector<std::string> Kinds_{"All", "DLL modules", "System drivers"};
  int KindIndex_ = 0;
  std::vector<std::string> PathsLines_;
  std::vector<std::string> RowPaths_;
  std::vector<bool> RowIsDriver_;
  TuiTable Table_;
};

// ------------------------------------------------------------
// 13 · Console —— 转录视图 + cmd.exe 命令执行
// ------------------------------------------------------------

class ConsolePage final : public TuiPage {
public:
  explicit ConsolePage(int Index) : Index_(Index) { RegisterCommands(); }

  ~ConsolePage() override {
    if (ActiveConsoleProcess &&
        ActiveConsoleProcess->state() != QProcess::NotRunning) {
      ActiveConsoleProcess->kill();
      ActiveConsoleProcess->waitForFinished(1000);
    }
  }

  std::string Title() const override { return "Console"; }

  std::string Subtitle() const override {
    return "application transcript plus cmd.exe command execution";
  }

  std::string RenderText() override {
    // 整份转录原样输出（ApplicationContext().ConsoleTranscript 的全部内容，
    // 经 ConsoleOutputSnapshot() 在同一把转录互斥量下读取；行式前端不再
    // 只取尾部 500 行）。
    const QString Transcript = ConsoleOutputSnapshot();
    std::string Text = U8(Transcript);
    if (Text.empty() || Text.back() != '\n')
      Text += '\n';
    Text += ActiveConsoleProcess ? "state: running\n" : "state: idle\n";
    return Text;
  }

private:
  void RegisterCommands() {
    OwnedCommands.push_back({"clear", "clear  (clear the console transcript)",
                             [this](std::vector<std::string>) { Clear(); }});
    OwnedCommands.push_back(
        {"copy", "copy  (copy the transcript to the clipboard)",
         [this](std::vector<std::string>) { Copy(); }});
    OwnedCommands.push_back(
        {"interrupt", "interrupt  (Ctrl+C on the running command)",
         [this](std::vector<std::string>) { Interrupt(); }});
    OwnedCommands.push_back(
        {"run", "run <command>  (execute a shell command)",
         [this](std::vector<std::string> Args) {
           std::string Text;
           for (const std::string &Arg : Args) {
             if (!Text.empty())
               Text += ' ';
             Text += Arg;
           }
           ExecuteText(Qs(Text));
         }});
  }

  void ExecuteText(const QString &RawText) {
    const QString Text = RawText.trimmed();
    if (Text.isEmpty() || ActiveConsoleProcess)
      return;
    AppendConsoleOutput("console> " + Text + "\n");
    auto *Process = new QProcess();
    ActiveConsoleProcess = Process;
    Process->setProcessChannelMode(QProcess::SeparateChannels);
    Process->setProgram("cmd.exe");
    Process->setArguments(
        {"/d", "/s", "/c", QStringLiteral("chcp 65001>nul & ") + Text});

    QObject::connect(Process, &QProcess::readyReadStandardOutput, Process,
                     [this, Process] {
                       const QByteArray Bytes = Process->readAllStandardOutput();
                       if (!Bytes.isEmpty())
                         AppendConsoleOutput(
                             DecodeConsoleChunk(Carry_, Bytes));
                     });
    QObject::connect(Process, &QProcess::readyReadStandardError, Process,
                     [this, Process] {
                       const QByteArray Bytes = Process->readAllStandardError();
                       if (!Bytes.isEmpty())
                         AppendConsoleOutput(
                             DecodeConsoleChunk(Carry_, Bytes));
                     });
    QObject::connect(Process, &QProcess::errorOccurred, Process,
                     [Process](QProcess::ProcessError) {
                       AppendConsoleOutput("[!] " + Process->errorString() +
                                           "\n");
                     });
    QObject::connect(
        Process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
        Process,
        [this, Process](int ExitCode, QProcess::ExitStatus ExitStatus) {
          const QByteArray RemainingStdout = Process->readAllStandardOutput();
          if (!RemainingStdout.isEmpty())
            AppendConsoleOutput(DecodeConsoleChunk(Carry_, RemainingStdout));
          const QByteArray RemainingStderr = Process->readAllStandardError();
          if (!RemainingStderr.isEmpty())
            AppendConsoleOutput(DecodeConsoleChunk(Carry_, RemainingStderr));
          if (ExitStatus == QProcess::CrashExit) {
            AppendConsoleOutput(
                QString("[!] Command process terminated (exit code %1).\n")
                    .arg(ExitCode));
            Notify(QString("Command terminated with exit code %1.")
                       .arg(ExitCode)
                       .toStdString(),
                   NoticeKind::Error);
          } else if (ExitCode == 0) {
            Notify("Command completed successfully.", NoticeKind::Success);
          } else {
            AppendConsoleOutput(
                QString("[!] Command exited with code %1.\n").arg(ExitCode));
            Notify(QString("Command completed with exit code %1.")
                       .arg(ExitCode)
                       .toStdString(),
                   NoticeKind::Error);
          }
          if (ActiveConsoleProcess == Process)
            ActiveConsoleProcess = nullptr;
          Process->deleteLater();
        });
    Process->start();
    SetStatus("console: running");
  }

  void Clear() {
    ClearConsoleOutput();
    Notify("Console cleared.", NoticeKind::Success);
  }

  void Copy() {
    TuiClipboard::Set(U8(ConsoleOutputSnapshot()));
    AppendConsoleOutput("[*] Copied transcript to clipboard.\n");
    Notify("Transcript copied to the clipboard.", NoticeKind::Success);
  }

  void Interrupt() {
    if (!ActiveConsoleProcess) {
      AppendConsoleOutput("[!] No command is running.\n");
      return;
    }
    AppendConsoleOutput("[*] Ctrl+C requested.\n");
    Notify("Interrupt request sent.", NoticeKind::Success);
    ActiveConsoleProcess->terminate();
    QPointer<QProcess> Process = ActiveConsoleProcess;
    QTimer::singleShot(1000, qApp, [Process] {
      if (Process && Process->state() != QProcess::NotRunning)
        Process->kill();
    });
  }

  int Index_ = 0;
  QByteArray Carry_;
};

// ------------------------------------------------------------
// 14 · Chat —— 聊天客户端（协议复用 Server/ChatProtocol.h）
// ------------------------------------------------------------

struct ChatShared {
  std::atomic_bool Alive{true};
  QPointer<QTcpSocket> Socket;
  QByteArray ReceiveBuffer;
  QString ClientName;
  std::int32_t LastMessageId = 0;
  QString SessionUserName;
  QString SessionTitle;
  QString ConnectionLabel = "Disconnected";
  std::vector<std::string> Transcript;
  std::vector<std::string> OnlineUsers;
  std::vector<std::string> Targets{"All Users"};
  int TargetIndex = 0;
};

class ChatPage final : public TuiPage {
public:
  explicit ChatPage(int Index) : Index_(Index) {
    Shared_ = std::make_shared<ChatShared>();
    DebugEnabled_ =
        ConfigurationValue("Chat", "DebugOutput", false).toBool();
    RegisterCommands();
    ChatAppend("[System] Chat client ready.");
  }

  ~ChatPage() override {
    Shared_->Alive = false;
    if (Shared_->Socket) {
      Shared_->Socket->abort();
      Shared_->Socket->deleteLater();
    }
  }

  std::string Title() const override { return "Chat"; }

  std::string Subtitle() const override {
    return "chat client: server, online users, targets, transcript";
  }

  void OnEnter() override {
    RegisterListeners();
    BuildTranscriptTable();
    SetStatus(StatusText());
  }

  void OnTick(int64_t NowMs) override {
    if (LastTickMs_ != 0 && NowMs - LastTickMs_ < 2000)
      return;
    LastTickMs_ = NowMs;
    if (!Shared_->Socket ||
        Shared_->Socket->state() != QAbstractSocket::ConnectedState)
      return;
    const ChatPacketHeader Header{
        static_cast<std::uint32_t>(ChatPacketType::QueryOnlineUsers), 0};
    if (Shared_->Socket->write(reinterpret_cast<const char *>(&Header),
                               sizeof(Header)) !=
        static_cast<qint64>(sizeof(Header))) {
      ChatAppend("[Error] Failed to query online users.");
      AppendConsoleOutput("[!] Chat: Failed to query online users.\n");
    }
    SetStatus(StatusText());
  }

  TuiTable *ActiveTable() override { return &Transcript_; }

  std::string RenderText() override {
    RegisterListeners();
    BuildTranscriptTable();
    SetStatus(StatusText());
    std::string Text;
    if (!Account.IsLoggedIn)
      Text += "Sign in to use this page.\n";
    Text += "  Server: " + ServerText() + "   Connection: " +
            U8(Shared_->ConnectionLabel) + "   To: " + CurrentTarget() + '\n';
    Text += "  Online Users (" + std::to_string(Shared_->OnlineUsers.size()) +
            "): " + OnlineUsersText() + '\n';
    Text += TuiTableToText(Transcript_, 200);
    return Text;
  }

private:
  // 转录条目是 "From: text" / "[From -> To]: text" / "[System] text" 三种
  // 形式；表格化时按前缀拆成 Who / Text 两列，正文一字不改。
  static void SplitTranscriptEntry(const std::string &Entry, std::string &Who,
                                   std::string &Text) {
    for (const char *Tag : {"Error", "System", "Debug"}) {
      const std::string Prefix = std::string("[") + Tag + "]";
      if (StartsWithCi(Entry, Prefix)) {
        Who = Tag;
        Text = TrimAscii(Entry.substr(Prefix.size()));
        return;
      }
    }
    const size_t Close = Entry.find("]:");
    if (!Entry.empty() && Entry.front() == '[' && Close != std::string::npos) {
      Who = Entry.substr(1, Close - 1);
      Text = TrimAscii(Entry.substr(Close + 2));
      return;
    }
    const size_t Colon = Entry.find(": ");
    if (Colon != std::string::npos) {
      Who = Entry.substr(0, Colon);
      Text = Entry.substr(Colon + 2);
      return;
    }
    Who = "System";
    Text = Entry;
  }

  void BuildTranscriptTable() {
    Transcript_.Headers = {"Who", "Text"};
    Transcript_.Filter = Filter;
    Transcript_.Rows.clear();
    Transcript_.Rows.reserve(Shared_->Transcript.size());
    for (const std::string &Entry : Shared_->Transcript) {
      std::string Who;
      std::string Body;
      SplitTranscriptEntry(Entry, Who, Body);
      Transcript_.Rows.push_back(TuiRow{{std::move(Who), std::move(Body)}, {}});
    }
    if (Transcript_.Rows.empty())
      Transcript_.Rows.push_back(TuiRow{{"System", "(no messages yet)"}, {}});
    Transcript_.Rebuild();
    if (Transcript_.Selected >= static_cast<int>(Transcript_.Visible.size()))
      Transcript_.Selected =
          std::max(0, static_cast<int>(Transcript_.Visible.size()) - 1);
  }

  void RegisterCommands() {
    OwnedCommands.push_back({"connect", "connect  (connect to the chat server)",
                             [this](std::vector<std::string>) { Connect(); }});
    OwnedCommands.push_back({"send", "send <text>  (send a chat message)",
                             [this](std::vector<std::string> Args) {
                               SendMessage(JoinArgs(Args));
                             }});
    OwnedCommands.push_back(
        {"disconnect", "disconnect  (close the chat connection)",
         [this](std::vector<std::string>) { Disconnect(); }});
    OwnedCommands.push_back(
        {"debug", "debug  (toggle Chat/DebugOutput)",
         [this](std::vector<std::string>) { ToggleDebug(); }});
    OwnedCommands.push_back(
        {"target", "target <name|all>  (private message target)",
         [this](std::vector<std::string> Args) { SetTarget(Args); }});
    OwnedCommands.push_back(
        {"users", "users  (list online users)",
         [this](std::vector<std::string>) {
           Notify(OnlineUsersText(), NoticeKind::Info);
         }});
  }

  static std::string JoinArgs(const std::vector<std::string> &Args) {
    std::string Text;
    for (const std::string &Arg : Args) {
      if (!Text.empty())
        Text += ' ';
      Text += Arg;
    }
    return Text;
  }

  void ChatAppend(const QString &Text) {
    Shared_->Transcript.push_back(U8(Text));
    if (Shared_->Transcript.size() > 2000)
      Shared_->Transcript.erase(Shared_->Transcript.begin(),
                                Shared_->Transcript.begin() + 1000);
  }

  std::string ServerText() const {
    const QString Host =
        ConfigurationValue("Chat", "ServerIP", "127.0.0.1").toString();
    const QString Port =
        ConfigurationValue("Chat", "ServerPort", "1145").toString();
    const QString Display =
        Account.UserName.isEmpty()
            ? QString("-")
            : (Account.Title.trimmed().isEmpty()
                   ? Account.UserName
                   : QString("[%1]%2").arg(Account.Title.trimmed(),
                                           Account.UserName));
    return U8(QString("%1:%2 | User: %3").arg(Host, Port, Display));
  }

  std::string OnlineUsersText() const {
    std::string Text;
    for (const std::string &User : Shared_->OnlineUsers) {
      if (!Text.empty())
        Text += ", ";
      Text += User;
    }
    return Text.empty() ? std::string("-") : Text;
  }

  std::string CurrentTarget() const {
    if (Shared_->TargetIndex <= 0 ||
        Shared_->TargetIndex >= static_cast<int>(Shared_->Targets.size()))
      return "All Users";
    return Shared_->Targets[static_cast<size_t>(Shared_->TargetIndex)];
  }

  std::string StatusText() const {
    return U8(Shared_->ConnectionLabel) + " | " +
           std::to_string(Shared_->OnlineUsers.size()) + " online";
  }

  void RegisterListeners() {
    if (ListenersRegistered_)
      return;
    ListenersRegistered_ = true;
    auto Shared = Shared_;
    AegisNT::ApplicationContext().AccountSessionListeners.push_back(
        [this, Shared]() -> bool {
          if (!Shared->Alive)
            return false;
          ChatPage *Page = this;
          if (!Account.IsLoggedIn) {
            if (Shared->Socket &&
                Shared->Socket->state() != QAbstractSocket::UnconnectedState)
              Shared->Socket->disconnectFromHost();
          }
          const QString CurrentUser = Account.UserName.trimmed();
          const QString CurrentTitle = Account.Title.trimmed();
          const bool SessionChanged =
              !Shared->SessionUserName.isEmpty() &&
              (Shared->SessionUserName != CurrentUser ||
               Shared->SessionTitle != CurrentTitle);
          if (Account.IsLoggedIn && SessionChanged && Shared->Socket &&
              Shared->Socket->state() == QAbstractSocket::ConnectedState) {
            ClientInfo Info{};
            Info.Type = Account.UserType;
            const QByteArray Name =
                CurrentUser.toUtf8().left(ChatNameCapacity - 1);
            const QByteArray Title =
                CurrentTitle.toUtf8().left(ChatNameCapacity - 1);
            std::memcpy(Info.ClientName, Name.constData(), Name.size());
            std::memcpy(Info.Title, Title.constData(), Title.size());
            if (SendFrame(*Shared, ChatPacketType::ClientInfo, &Info,
                          sizeof(Info)))
              Shared->Socket->flush();
          }
          Shared->SessionUserName = CurrentUser;
          Shared->SessionTitle = CurrentTitle;
          Shared->ConnectionLabel = Page->ConnectionText();
          return true;
        });
    AegisNT::ApplicationContext().UserTitleChangedListeners.push_back(
        [Shared](const QString &UserName, const QString &Title) -> bool {
          if (!Shared->Alive)
            return false;
          if (Shared->Socket &&
              Shared->Socket->state() == QAbstractSocket::ConnectedState) {
            UserTitleUpdate Update{};
            const QByteArray Name =
                UserName.toUtf8().left(ChatNameCapacity - 1);
            const QByteArray NewTitle =
                Title.toUtf8().left(ChatNameCapacity - 1);
            std::memcpy(Update.UserName, Name.constData(), Name.size());
            std::memcpy(Update.Title, NewTitle.constData(), NewTitle.size());
            if (SendFrame(*Shared, ChatPacketType::UpdateUserTitle, &Update,
                          sizeof(Update)))
              Shared->Socket->flush();
          }
          return true;
        });
    Shared->SessionUserName = Account.UserName.trimmed();
    Shared->SessionTitle = Account.Title.trimmed();
  }

  QString ConnectionText() const {
    if (!Shared_->Socket)
      return QStringLiteral("Disconnected");
    switch (Shared_->Socket->state()) {
    case QAbstractSocket::ConnectedState:
      return QStringLiteral("Connected");
    case QAbstractSocket::ConnectingState:
    case QAbstractSocket::HostLookupState:
      return QStringLiteral("Connecting");
    case QAbstractSocket::UnconnectedState:
      return QStringLiteral("Disconnected");
    default:
      return QStringLiteral("Connection error");
    }
  }

  static bool SendFrame(ChatShared &Shared, ChatPacketType Type,
                        const void *Payload, qsizetype PayloadSize) {
    if (!Shared.Socket)
      return false;
    const ChatPacketHeader Header{static_cast<std::uint32_t>(Type),
                                  static_cast<std::uint32_t>(PayloadSize)};
    QByteArray Frame;
    Frame.reserve(static_cast<qsizetype>(sizeof(Header)) + PayloadSize);
    Frame.append(reinterpret_cast<const char *>(&Header), sizeof(Header));
    if (PayloadSize > 0)
      Frame.append(reinterpret_cast<const char *>(Payload), PayloadSize);
    return Shared.Socket->write(Frame) == Frame.size();
  }

  void Connect() {
    if (Account.UserName.trimmed().isEmpty() || !Account.IsLoggedIn) {
      ChatAppend("[Error] No logged-in user.");
      AppendConsoleOutput("[!] Chat: No logged-in user.\n");
      return;
    }
    if (!Shared_->Socket) {
      Shared_->Socket = new QTcpSocket();
      WireSocket();
    }
    bool PortValid = false;
    quint16 Port = ConfigurationValue("Chat", "ServerPort", "1145")
                       .toString()
                       .toUShort(&PortValid);
    if (!PortValid || Port == 0)
      Port = 1145;
    const QString Host =
        ConfigurationValue("Chat", "ServerIP", "127.0.0.1").toString();
    Shared_->ClientName = Account.UserName.trimmed();
    Shared_->ConnectionLabel = "Connecting";
    ChatAppend(QString("[System] Connecting to %1:%2 as %3")
                   .arg(Host)
                   .arg(Port)
                   .arg(Shared_->ClientName));
    Shared_->Socket->connectToHost(Host, Port);
    SetStatus(StatusText());
  }

  void WireSocket() {
    auto Shared = Shared_;
    ChatPage *Page = this;
    QObject::connect(Shared->Socket, &QTcpSocket::connected, Shared->Socket,
                     [Page, Shared] {
                       ClientInfo Info{};
                       Info.Type = Account.UserType;
                       const QByteArray Name = Shared->ClientName.toUtf8().left(
                           ChatNameCapacity - 1);
                       const QByteArray Title =
                           Account.Title.toUtf8().left(ChatNameCapacity - 1);
                       std::memcpy(Info.ClientName, Name.constData(),
                                   Name.size());
                       std::memcpy(Info.Title, Title.constData(),
                                   Title.size());
                       if (!SendFrame(*Shared, ChatPacketType::ClientInfo,
                                      &Info, sizeof(Info))) {
                         Page->ChatAppend("[Error] Failed to send handshake.");
                         AppendConsoleOutput(
                             "[!] Chat: Failed to send handshake.\n");
                         Shared->Socket->abort();
                         return;
                       }
                       Shared->Socket->flush();
                       Shared->ConnectionLabel = "Connected";
                       Page->ChatAppend(QString("[System] Connected as %1")
                                            .arg(Shared->ClientName));
                       Page->SetStatus(Page->StatusText());
                     });
    QObject::connect(Shared->Socket, &QTcpSocket::readyRead, Shared->Socket,
                     [Page, Shared] { Page->HandleReadyRead(); });
    QObject::connect(Shared->Socket, &QTcpSocket::disconnected,
                     Shared->Socket, [Page, Shared] {
                       Shared->ConnectionLabel = "Disconnected";
                       Shared->OnlineUsers.clear();
                       Shared->Targets.assign(1, "All Users");
                       Shared->TargetIndex = 0;
                       Shared->ReceiveBuffer.clear();
                       Shared->LastMessageId = 0;
                       Shared->ClientName.clear();
                       Page->ChatAppend("[System] Disconnected from server.");
                       Page->SetStatus(Page->StatusText());
                     });
    QObject::connect(
        Shared->Socket, &QTcpSocket::errorOccurred, Shared->Socket,
        [Page, Shared](QAbstractSocket::SocketError) {
          Shared->ConnectionLabel = "Connection error";
          const QString Message = Shared->Socket->errorString();
          Page->ChatAppend(QString("[Error] %1").arg(Message));
          AppendConsoleOutput("[!] Chat: " + Message + "\n");
          Page->SetStatus(Page->StatusText());
        });
  }

  void HandleReadyRead() {
    Shared_->ReceiveBuffer += Shared_->Socket->readAll();
    while (Shared_->ReceiveBuffer.size() >=
           static_cast<qsizetype>(sizeof(ChatPacketHeader))) {
      ChatPacketHeader Header{};
      std::memcpy(&Header, Shared_->ReceiveBuffer.constData(), sizeof(Header));
      if (Header.Size > 1024 * 1024) {
        ChatAppend("[Error] Invalid packet size.");
        AppendConsoleOutput(QString("[!] Chat: Invalid packet size %1.\n")
                                .arg(Header.Size));
        Shared_->Socket->abort();
        return;
      }
      const qsizetype FrameSize =
          static_cast<qsizetype>(sizeof(Header)) + Header.Size;
      if (Shared_->ReceiveBuffer.size() < FrameSize)
        return;
      const QByteArray Payload =
          Shared_->ReceiveBuffer.mid(sizeof(Header), Header.Size);
      Shared_->ReceiveBuffer.remove(0, FrameSize);

      if (Header.Type == static_cast<std::uint32_t>(ChatPacketType::Message) &&
          Payload.size() == static_cast<qsizetype>(sizeof(Msg))) {
        Msg Message{};
        std::memcpy(&Message, Payload.constData(), sizeof(Message));
        if (Message.FromType != 0 && Message.FromType == Shared_->LastMessageId)
          continue;
        if (Message.FromType != 0)
          Shared_->LastMessageId = Message.FromType;
        const QString From = QString::fromUtf8(Message.From);
        const QString To = QString::fromUtf8(Message.To);
        const QString Content = QString::fromUtf8(Message.Content);
        ChatAppend(To == "0" ? QString("%1: %2").arg(From, Content)
                             : QString("[%1 -> %2]: %3").arg(From, To, Content));
      } else if (Header.Type ==
                     static_cast<std::uint32_t>(ChatPacketType::ClientInfo) &&
                 Payload.size() == static_cast<qsizetype>(sizeof(ClientInfo))) {
        ClientInfo Info{};
        std::memcpy(&Info, Payload.constData(), sizeof(Info));
        if (QString::fromUtf8(Info.ClientName) == Account.UserName) {
          Account.Title = QString::fromUtf8(Info.Title);
          SetConfigurationValue("Account", "Title", Account.Title);
          AegisNT::NotifyAccountSessionChanged();
        }
      } else if (Header.Type ==
                     static_cast<std::uint32_t>(ChatPacketType::OnlineUsers) &&
                 Payload.size() == static_cast<qsizetype>(sizeof(EnumMsg))) {
        EnumMsg Users{};
        std::memcpy(&Users, Payload.constData(), sizeof(Users));
        const int Count = std::clamp(Users.OnlineNumber, 0,
                                     static_cast<int>(ChatMaxOnlineUsers));
        const std::string PreviousTarget = CurrentTarget();
        Shared_->OnlineUsers.clear();
        Shared_->Targets.assign(1, "All Users");
        for (int Index = 0; Index < Count; ++Index) {
          const QString Name = QString::fromUtf8(Users.OnlineUsers[Index]);
          if (Name.isEmpty())
            continue;
          Shared_->OnlineUsers.push_back(U8(Name));
          if (!Name.endsWith(Shared_->ClientName))
            Shared_->Targets.push_back(U8(Name));
        }
        Shared_->TargetIndex = 0;
        for (size_t Index = 1; Index < Shared_->Targets.size(); ++Index) {
          if (Shared_->Targets[Index] == PreviousTarget) {
            Shared_->TargetIndex = static_cast<int>(Index);
            break;
          }
        }
      } else if (Header.Type ==
                 static_cast<std::uint32_t>(ChatPacketType::Notice)) {
        ChatAppend(QString("[System] %1").arg(QString::fromUtf8(Payload)));
      }
    }
    SetStatus(StatusText());
  }

  void SendMessage(const std::string &Text) {
    if (DebugEnabled_)
      ChatAppend("[Debug] Send invoked");
    const QString Content = Qs(TrimAscii(Text));
    if (Content.isEmpty()) {
      ChatAppend("[Error] Message is empty.");
      AppendConsoleOutput("[!] Chat: Message is empty.\n");
      return;
    }
    if (!Shared_->Socket ||
        Shared_->Socket->state() != QAbstractSocket::ConnectedState) {
      ChatAppend("[Error] Chat is not connected.");
      AppendConsoleOutput("[!] Chat: Chat is not connected.\n");
      return;
    }
    Msg Message{};
    const QByteArray From =
        Shared_->ClientName.toUtf8().left(ChatNameCapacity - 1);
    const QByteArray Body = Content.toUtf8().left(ChatContentCapacity - 1);
    const QByteArray To =
        (Shared_->TargetIndex <= 0 ? QByteArray("0")
                                   : Qs(CurrentTarget()).toUtf8())
            .left(ChatNameCapacity - 1);
    std::memcpy(Message.From, From.constData(), From.size());
    std::memcpy(Message.To, To.constData(), To.size());
    std::memcpy(Message.Content, Body.constData(), Body.size());
    if (!SendFrame(*Shared_, ChatPacketType::Message, &Message,
                   sizeof(Message))) {
      const QString Error = Shared_->Socket->errorString();
      ChatAppend(QString("[Error] Send failed: %1").arg(Error));
      AppendConsoleOutput("[!] Chat: Send failed: " + Error + "\n");
      return;
    }
    Shared_->Socket->flush();
  }

  void Disconnect() {
    if (Shared_->Socket)
      Shared_->Socket->disconnectFromHost();
  }

  void ToggleDebug() {
    DebugEnabled_ = !DebugEnabled_;
    SetConfigurationValue("Chat", "DebugOutput", DebugEnabled_);
    Notify(DebugEnabled_ ? "Debug output enabled." : "Debug output disabled.",
           NoticeKind::Success);
  }

  void SetTarget(const std::vector<std::string> &Args) {
    if (!Args.empty()) {
      const std::string Needle = LowerAscii(Args.front());
      if (Needle == "all" || Needle == "all users") {
        Shared_->TargetIndex = 0;
        return;
      }
      for (size_t Index = 1; Index < Shared_->Targets.size(); ++Index) {
        if (LowerAscii(Shared_->Targets[Index]).find(Needle) !=
            std::string::npos) {
          Shared_->TargetIndex = static_cast<int>(Index);
          return;
        }
      }
      Notify("Unknown target: " + Args.front(), NoticeKind::Warning);
      return;
    }
    if (!Dialogs)
      return;
    TuiDialog Dialog;
    Dialog.Title = "Message target";
    Dialog.Fields.push_back(
        ComboField("To", Shared_->Targets, Shared_->TargetIndex));
    Dialog.OnSubmit = [this](TuiDialog &Submitted) {
      if (Submitted.Fields.empty())
        return;
      Shared_->TargetIndex = Submitted.Fields.front().Choice;
    };
    Dialogs->Push(std::move(Dialog));
  }

  int Index_ = 0;
  int64_t LastTickMs_ = 0;
  bool DebugEnabled_ = false;
  bool ListenersRegistered_ = false;
  std::shared_ptr<ChatShared> Shared_;
  TuiTable Transcript_;
};

// ------------------------------------------------------------
// 18 · Network —— 连接表 + 内核 WFP 防火墙规则
// ------------------------------------------------------------

struct ConnEntry {
  std::string Protocol;
  std::string Local;
  std::string Remote;
  std::string State;
  std::string Process;
  quint32 Pid = 0;
  int RemotePort = 0;
  std::string RemoteAddress;
  std::string BaseProtocol;
  bool RemoteV6 = false;

  bool Matches(const std::string &Needle, int ProtocolIndex) const {
    if (ProtocolIndex == 1 && !StartsWithCi(Protocol, "TCP"))
      return false;
    if (ProtocolIndex == 2 && !StartsWithCi(Protocol, "UDP"))
      return false;
    if (Needle.empty())
      return true;
    const std::string Folded = LowerAscii(Needle);
    return LowerAscii(Local).find(Folded) != std::string::npos ||
           LowerAscii(Remote).find(Folded) != std::string::npos ||
           LowerAscii(State).find(Folded) != std::string::npos ||
           LowerAscii(Process).find(Folded) != std::string::npos ||
           std::to_string(Pid) == Needle;
  }
};

std::string TcpStateText(DWORD State) {
  switch (State) {
  case MIB_TCP_STATE_CLOSED:
    return "Closed";
  case MIB_TCP_STATE_LISTEN:
    return "Listen";
  case MIB_TCP_STATE_SYN_SENT:
    return "SYN Sent";
  case MIB_TCP_STATE_SYN_RCVD:
    return "SYN Received";
  case MIB_TCP_STATE_ESTAB:
    return "Established";
  case MIB_TCP_STATE_FIN_WAIT1:
    return "FIN Wait 1";
  case MIB_TCP_STATE_FIN_WAIT2:
    return "FIN Wait 2";
  case MIB_TCP_STATE_CLOSE_WAIT:
    return "Close Wait";
  case MIB_TCP_STATE_CLOSING:
    return "Closing";
  case MIB_TCP_STATE_LAST_ACK:
    return "Last ACK";
  case MIB_TCP_STATE_TIME_WAIT:
    return "Time Wait";
  case MIB_TCP_STATE_DELETE_TCB:
    return "Delete TCB";
  default:
    return "Unknown";
  }
}

std::string NetIpv4(DWORD NetworkOrder) {
  const in_addr Address{NetworkOrder};
  char Text[INET_ADDRSTRLEN] = {};
  if (inet_ntop(AF_INET, &Address, Text, sizeof(Text)))
    return Text;
  return "0.0.0.0";
}

std::string NetIpv6(const UCHAR *Bytes) {
  in6_addr Address{};
  memcpy(&Address, Bytes, 16);
  char Text[INET6_ADDRSTRLEN] = {};
  if (inet_ntop(AF_INET6, &Address, Text, sizeof(Text)))
    return Text;
  return {};
}

std::string NetEndpoint(const std::string &Address, DWORD PortNetworkOrder,
                        bool Remote) {
  const quint16 Port = ntohs(static_cast<u_short>(PortNetworkOrder));
  if (Remote && Address.empty())
    return "*:*";
  return "[" + Address + "]:" + std::to_string(Port);
}

std::map<quint32, std::string> NetProcessNames() {
  std::map<quint32, std::string> Names;
  const HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (Snapshot == INVALID_HANDLE_VALUE)
    return Names;
  PROCESSENTRY32W Entry{};
  Entry.dwSize = sizeof(Entry);
  if (Process32FirstW(Snapshot, &Entry)) {
    do {
      Names.try_emplace(Entry.th32ProcessID,
                        U8(QString::fromWCharArray(Entry.szExeFile)));
    } while (Process32NextW(Snapshot, &Entry));
  }
  CloseHandle(Snapshot);
  return Names;
}

std::vector<ConnEntry> CollectConnections() {
  std::vector<ConnEntry> Rows;
  const auto Names = NetProcessNames();
  const auto ProcessOf = [&Names](quint32 Pid) {
    const auto It = Names.find(Pid);
    return It == Names.end() ? std::string() : It->second;
  };

  for (const int Family : {AF_INET, AF_INET6}) {
    const bool V6 = Family == AF_INET6;
    std::vector<char> Buffer;
    DWORD Size = 0;
    if (GetExtendedTcpTable(nullptr, &Size, FALSE, Family,
                            TCP_TABLE_OWNER_PID_ALL, 0) ==
            ERROR_INSUFFICIENT_BUFFER &&
        Size > 0) {
      Buffer.resize(Size);
      if (GetExtendedTcpTable(Buffer.data(), &Size, FALSE, Family,
                              TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
        Buffer.clear();
    }
    if (Buffer.empty())
      continue;
    if (!V6) {
      const auto *Table =
          reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(Buffer.data());
      for (DWORD Index = 0; Index < Table->dwNumEntries; ++Index) {
        const MIB_TCPROW_OWNER_PID &Row = Table->table[Index];
        ConnEntry Entry;
        Entry.Protocol = "TCP";
        Entry.BaseProtocol = "TCP";
        Entry.Local = NetEndpoint(NetIpv4(Row.dwLocalAddr), Row.dwLocalPort,
                                  false);
        Entry.RemoteAddress = NetIpv4(Row.dwRemoteAddr);
        Entry.Remote = NetEndpoint(Entry.RemoteAddress, Row.dwRemotePort, true);
        Entry.State = TcpStateText(Row.dwState);
        Entry.Pid = Row.dwOwningPid;
        Entry.Process = ProcessOf(Row.dwOwningPid);
        Entry.RemotePort = ntohs(static_cast<u_short>(Row.dwRemotePort));
        Rows.push_back(std::move(Entry));
      }
    } else {
      const auto *Table =
          reinterpret_cast<PMIB_TCP6TABLE_OWNER_PID>(Buffer.data());
      for (DWORD Index = 0; Index < Table->dwNumEntries; ++Index) {
        const MIB_TCP6ROW_OWNER_PID &Row = Table->table[Index];
        ConnEntry Entry;
        Entry.Protocol = "TCP6";
        Entry.BaseProtocol = "TCP";
        Entry.Local = NetEndpoint(NetIpv6(Row.ucLocalAddr), Row.dwLocalPort,
                                  false);
        Entry.RemoteAddress = NetIpv6(Row.ucRemoteAddr);
        Entry.Remote = NetEndpoint(Entry.RemoteAddress, Row.dwRemotePort, true);
        Entry.State = TcpStateText(Row.dwState);
        Entry.Pid = Row.dwOwningPid;
        Entry.Process = ProcessOf(Row.dwOwningPid);
        Entry.RemotePort = ntohs(static_cast<u_short>(Row.dwRemotePort));
        Entry.RemoteV6 = true;
        Rows.push_back(std::move(Entry));
      }
    }
  }

  for (const int Family : {AF_INET, AF_INET6}) {
    const bool V6 = Family == AF_INET6;
    std::vector<char> Buffer;
    DWORD Size = 0;
    if (GetExtendedUdpTable(nullptr, &Size, FALSE, Family,
                            UDP_TABLE_OWNER_PID, 0) ==
            ERROR_INSUFFICIENT_BUFFER &&
        Size > 0) {
      Buffer.resize(Size);
      if (GetExtendedUdpTable(Buffer.data(), &Size, FALSE, Family,
                              UDP_TABLE_OWNER_PID, 0) != NO_ERROR)
        Buffer.clear();
    }
    if (Buffer.empty())
      continue;
    if (!V6) {
      const auto *Table =
          reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(Buffer.data());
      for (DWORD Index = 0; Index < Table->dwNumEntries; ++Index) {
        const MIB_UDPROW_OWNER_PID &Row = Table->table[Index];
        ConnEntry Entry;
        Entry.Protocol = "UDP";
        Entry.BaseProtocol = "UDP";
        Entry.Local = NetEndpoint(NetIpv4(Row.dwLocalAddr), Row.dwLocalPort,
                                  false);
        Entry.Remote = "*:*";
        Entry.State = "-";
        Entry.Pid = Row.dwOwningPid;
        Entry.Process = ProcessOf(Row.dwOwningPid);
        Rows.push_back(std::move(Entry));
      }
    } else {
      const auto *Table =
          reinterpret_cast<PMIB_UDP6TABLE_OWNER_PID>(Buffer.data());
      for (DWORD Index = 0; Index < Table->dwNumEntries; ++Index) {
        const MIB_UDP6ROW_OWNER_PID &Row = Table->table[Index];
        ConnEntry Entry;
        Entry.Protocol = "UDP6";
        Entry.BaseProtocol = "UDP";
        Entry.Local = NetEndpoint(NetIpv6(Row.ucLocalAddr), Row.dwLocalPort,
                                  false);
        Entry.Remote = "*:*";
        Entry.State = "-";
        Entry.Pid = Row.dwOwningPid;
        Entry.Process = ProcessOf(Row.dwOwningPid);
        Entry.RemoteV6 = true;
        Rows.push_back(std::move(Entry));
      }
    }
  }
  return Rows;
}

class NetworkPage final : public TuiPage {
public:
  explicit NetworkPage(int Index) : Index_(Index) {
    ConnTable_.Headers = {"Protocol", "Local Address", "Remote Address",
                          "State", "PID", "Process"};
    ConnTable_.RightAlign = {false, false, false, false, true, false};
    RulesTable_.Headers = {"Name", "Action", "Protocol", "Remote Port",
                           "Remote Address", "Direction", "State",
                           "Filter ID"};
    RegisterCommands();
  }

  std::string Title() const override { return "Network"; }

  std::string Subtitle() const override {
    return "TCP/UDP connections and kernel WFP firewall rules";
  }

  void OnEnter() override {
    if (!Loaded_) {
      Loaded_ = true;
      RefreshConnections();
      RefreshRules();
    } else {
      RepopulateConnections();
    }
    LastAutoMs_ = 0;
  }

  void OnTick(int64_t NowMs) override {
    if (Tab_ == 0 && AutoRefresh_) {
      if (LastAutoMs_ == 0)
        LastAutoMs_ = NowMs;
      else if (NowMs - LastAutoMs_ >= 3000) {
        LastAutoMs_ = NowMs;
        RefreshConnections();
      }
    }
  }

  TuiTable *ActiveTable() override {
    return Tab_ == 0 ? &ConnTable_ : &RulesTable_;
  }

  std::string RenderText() override {
    if (!Loaded_) {
      Loaded_ = true;
      RefreshConnections();
      RefreshRules();
    } else if (ConnRows_.empty()) {
      RefreshConnections();
    }
    RepopulateConnections();
    SetStatus(Tab_ == 0 ? ConnectionStatus() : U8(RulesStatus_));

    std::string Text = TabStrip();
    Text += '\n';
    if (Tab_ == 0) {
      Text += "  Protocol filter: " +
              ProtocolLabels_[static_cast<size_t>(ProtocolIndex_)] +
              "   auto refresh " +
              (AutoRefresh_ ? "on" : "off") + "\n";
      Text += TuiTableToText(ConnTable_, 200);
    } else {
      Text += "  " + U8(RulesStatus_) + '\n';
      Text += TuiTableToText(RulesTable_, 200);
    }
    return Text;
  }

private:
  std::string TabStrip() const {
    return ::AegisNT::Tui::TabStrip({"Connections", "Firewall Rules"}, Tab_) +
           Paint("   (view connections|rules)", TuiTone::Muted);
  }

  void RegisterCommands() {
    OwnedCommands.push_back(
        {"refresh", "refresh  (enumerate TCP/UDP connections)",
         [this](std::vector<std::string>) { RefreshConnections(); }});
    OwnedCommands.push_back(
        {"auto", "auto  (toggle 3 s auto refresh)",
         [this](std::vector<std::string>) {
           AutoRefresh_ = !AutoRefresh_;
           LastAutoMs_ = 0;
           Notify(AutoRefresh_ ? "Auto refresh on." : "Auto refresh off.",
                  NoticeKind::Success);
         }});
    OwnedCommands.push_back(
        {"kill", "kill  (end the selected connection's process)",
         [this](std::vector<std::string>) { KillSelected(); }});
    OwnedCommands.push_back(
        {"block-port", "block-port  (firewall rule for the selected remote "
                       "port)",
         [this](std::vector<std::string>) { BlockRemotePort(); }});
    OwnedCommands.push_back(
        {"copy", "copy  (copy the selected connection row)",
         [this](std::vector<std::string>) {
           ConnTable_.CopyCurrentToClipboard();
           Notify("Row copied to the clipboard.", NoticeKind::Success);
         }});
    OwnedCommands.push_back(
        {"refresh-rules", "refresh-rules  (query kernel firewall rules)",
         [this](std::vector<std::string>) { RefreshRules(); }});
    OwnedCommands.push_back(
        {"add-rule", "add-rule  (create a firewall rule)",
         [this](std::vector<std::string>) { ShowAddRule(-1, {}, false, {}); }});
    OwnedCommands.push_back(
        {"remove-rule", "remove-rule  (remove the selected rule)",
         [this](std::vector<std::string>) { RemoveSelectedRule(); }});
    OwnedCommands.push_back(
        {"clear-rules", "clear-rules  (remove all AegisNT filters)",
         [this](std::vector<std::string>) { ClearRules(); }});
    OwnedCommands.push_back(
        {"proto", "proto [all|tcp|udp]",
         [this](std::vector<std::string> Args) { SetProtocol(Args); }});
    OwnedCommands.push_back(
        {"view", "view [connections|rules]  (switch tab)",
         [this](std::vector<std::string> Args) { SetView(Args); }});
  }

  // 无键盘事件后，标签页切换只能经由 `view` 命令（等价于原 F7/F8）。
  void SetView(const std::vector<std::string> &Args) {
    if (Args.empty()) {
      SwitchTab(Tab_ + 1);
      return;
    }
    const std::string Needle = LowerAscii(TrimAscii(Args.front()));
    if (Needle == "connections" || Needle == "conn" || Needle == "1") {
      SwitchTab(0);
      return;
    }
    if (Needle == "rules" || Needle == "firewall" || Needle == "2") {
      SwitchTab(1);
      return;
    }
    Notify("Unknown view: " + Args.front(), NoticeKind::Warning);
  }

  void SwitchTab(int Index) {
    Tab_ = ((Index % 2) + 2) % 2;
    SetStatus(Tab_ == 0 ? ConnectionStatus() : U8(RulesStatus_));
  }

  void SetProtocol(const std::vector<std::string> &Args) {
    if (!Args.empty()) {
      const std::string Needle = LowerAscii(Args.front());
      if (Needle == "all")
        ProtocolIndex_ = 0;
      else if (Needle == "tcp")
        ProtocolIndex_ = 1;
      else if (Needle == "udp")
        ProtocolIndex_ = 2;
      else {
        Notify("Unknown protocol: " + Args.front(), NoticeKind::Warning);
        return;
      }
      RepopulateConnections();
      return;
    }
    if (!Dialogs)
      return;
    TuiDialog Dialog;
    Dialog.Title = "Protocol filter";
    Dialog.Fields.push_back(
        ComboField("Protocol", ProtocolLabels_, ProtocolIndex_));
    Dialog.OnSubmit = [this](TuiDialog &Submitted) {
      if (Submitted.Fields.empty())
        return;
      ProtocolIndex_ = Submitted.Fields.front().Choice;
      RepopulateConnections();
    };
    Dialogs->Push(std::move(Dialog));
  }

  void RefreshConnections() {
    if (RefreshPending_)
      return;
    RefreshPending_ = true;
    SetStatus("Enumerating connections...");
    TuiAsync<std::vector<ConnEntry>>(
        [] { return CollectConnections(); },
        [this](std::vector<ConnEntry> Rows) {
          RefreshPending_ = false;
          ConnRows_ = std::move(Rows);
          RepopulateConnections();
        });
  }

  void RepopulateConnections() {
    ConnTable_.Rows.clear();
    ConnRowSource_.clear();
    const std::string Needle = TrimAscii(Filter);
    for (size_t Index = 0; Index < ConnRows_.size(); ++Index) {
      const ConnEntry &Row = ConnRows_[Index];
      if (!Row.Matches(Needle, ProtocolIndex_))
        continue;
      ConnTable_.Rows.push_back(
          TuiRow{{Row.Protocol, Row.Local, Row.Remote, Row.State,
                  std::to_string(Row.Pid), Row.Process},
                 {}});
      ConnRowSource_.push_back(Index);
    }
    ConnTable_.Rebuild();
    SetStatus(ConnectionStatus());
  }

  std::string ConnectionStatus() const {
    return std::to_string(ConnTable_.Rows.size()) + " connection(s) of " +
           std::to_string(ConnRows_.size());
  }

  const ConnEntry *SelectedConnection() const {
    const int Row = ConnTable_.CurrentRowIndex();
    if (Row < 0 || Row >= static_cast<int>(ConnRowSource_.size()))
      return nullptr;
    return &ConnRows_[ConnRowSource_[static_cast<size_t>(Row)]];
  }

  void KillSelected() {
    const ConnEntry *Entry = SelectedConnection();
    if (!Entry || Entry->Pid == 0)
      return;
    const ConnEntry Copy = *Entry;
    if (!Dialogs)
      return;
    ConfirmDialog(
        *Dialogs, "End Process",
        "Kill " +
            (Copy.Process.empty() ? std::string("this process") : Copy.Process) +
            " (PID " + std::to_string(Copy.Pid) + ")?",
        [this, Copy] {
          if (!KillProcessForce(Copy.Pid)) {
            Notify("Failed to kill PID " + std::to_string(Copy.Pid) + ".",
                   NoticeKind::Error);
          } else {
            MarkMutated();
            Notify("PID " + std::to_string(Copy.Pid) + " terminated.",
                   NoticeKind::Success);
            RefreshConnections();
          }
        },
        "Kill", "Cancel");
  }

  void BlockRemotePort() {
    const ConnEntry *Entry = SelectedConnection();
    if (!Entry)
      return;
    if (Entry->RemoteAddress.empty() || Entry->RemotePort <= 0) {
      Notify("UDP rows have no remote endpoint to block.",
             NoticeKind::Warning);
      return;
    }
    ShowAddRule(Entry->RemotePort, Entry->BaseProtocol, Entry->RemoteV6, {});
  }

  void RefreshRules() {
    if (RulesPending_)
      return;
    RulesPending_ = true;
    RulesStatus_ = "Querying kernel firewall rules...";
    RulesStatusIsError_ = false;
    SetStatus(U8(RulesStatus_));

    struct RuleFetch {
      std::shared_ptr<FIREWALL_RULE_OUTPUT> Output;
      bool Success = false;
      DWORD Error = ERROR_SUCCESS;
      ULONG KernelStatus = 0;
      ULONG Count = 0;
      std::vector<std::tuple<QString, ULONG, ULONG, ULONG, QString>> Fallback;
    };
    auto Fetch = std::make_shared<RuleFetch>();
    TuiAsyncVoid(
        [Fetch] {
          Fetch->Output = std::make_shared<FIREWALL_RULE_OUTPUT>();
          Fetch->Success = EnumerateFirewallRulesKernel(Fetch->Output.get()) != FALSE;
          Fetch->Error = G_LastAegisCoreError;
          // 驱动在 IOCTL 失败前就会写 KernelStatus，因此即使
          // DeviceIoControl 返回 FALSE，该字段依然有效。
          Fetch->KernelStatus = Fetch->Success ? 0 : Fetch->Output->KernelStatus;
          Fetch->Count = Fetch->Success ? Fetch->Output->Count : 0;
          if (!Fetch->Success)
            EnumerateFirewallRulesFallback(Fetch->Fallback);
        },
        [this, Fetch] {
          RulesPending_ = false;
          RulesTable_.Rows.clear();
          RulesTable_.Marked.clear();
          RulesKernelBacked_ = Fetch->Success;
          if (!Fetch->Success) {
            for (const auto &Entry : Fetch->Fallback) {
              RulesTable_.Rows.push_back(
                  TuiRow{{U8(std::get<0>(Entry)),
                          std::get<1>(Entry) == FIREWALL_ACTION_BLOCK
                              ? "Block"
                              : "Permit",
                          U8(FirewallProtocolText(std::get<2>(Entry))),
                          std::get<3>(Entry)
                              ? std::to_string(std::get<3>(Entry))
                              : std::string("Any"),
                          "-", "-", U8(std::get<4>(Entry)), "-"},
                         {}});
            }
            RulesStatus_ =
                Fetch->Fallback.empty()
                    ? QString("Firewall query failed (error %1, kernel status "
                              "0x%2).")
                          .arg(Fetch->Error)
                          .arg(Fetch->KernelStatus, 8, 16, QChar('0'))
                    : QString("Kernel query failed (error %1, kernel status "
                              "0x%2); showing %3 user-mode rule(s).")
                          .arg(Fetch->Error)
                          .arg(Fetch->KernelStatus, 8, 16, QChar('0'))
                          .arg(Fetch->Fallback.size());
            RulesStatusIsError_ = true;
            Notify(U8(RulesStatus_), Fetch->Fallback.empty()
                                        ? NoticeKind::Error
                                        : NoticeKind::Warning);
          } else {
            const auto &Output = *Fetch->Output;
            for (ULONG Index = 0; Index < Fetch->Count && Index < Output.Count;
                 ++Index) {
              const FIREWALL_RULE_ENTRY &Rule = Output.Entries[Index];
              RulesTable_.Rows.push_back(
                  TuiRow{{U8(QString::fromWCharArray(Rule.RuleName)),
                          Rule.Action == FIREWALL_ACTION_BLOCK
                              ? "Block"
                              : (Rule.Action == FIREWALL_ACTION_PERMIT
                                     ? "Permit"
                                     : U8(QString("WFP action 0x%1")
                                              .arg(Rule.Action, 0, 16))),
                          U8(FirewallProtocolText(Rule.Protocol)),
                          Rule.RemotePort ? std::to_string(Rule.RemotePort)
                                          : std::string("Any"),
                          U8(FirewallAddressText(Rule)),
                          U8(FirewallDirectionText(Rule.Direction)),
                          Rule.Enabled ? "Enabled" : "Disabled",
                          std::to_string(Rule.FilterId)},
                         {}});
            }
            RulesStatus_ =
                Output.TotalCount > Fetch->Count
                    ? QString("Showing %1 of %2 kernel filters (output limit "
                              "reached).")
                          .arg(Fetch->Count)
                          .arg(Output.TotalCount)
                    : QString("%1 kernel filter(s) across ALE layers.")
                          .arg(Fetch->Count);
            RulesStatusIsError_ = false;
          }
          RulesTable_.Rebuild();
          SetStatus(Tab_ == 0 ? ConnectionStatus() : U8(RulesStatus_));
        });
  }

  void RemoveSelectedRule() {
    const int Row = RulesTable_.CurrentRowIndex();
    if (Row < 0) {
      Notify("Select a rule to remove.", NoticeKind::Warning);
      return;
    }
    if (!RulesKernelBacked_) {
      Notify("Removal requires the kernel driver; these rows came from the "
             "user-mode fallback.",
             NoticeKind::Warning);
      return;
    }
    const std::string Name = RulesTable_.Rows[static_cast<size_t>(Row)].Cells[0];
    if (Name.empty()) {
      Notify("This rule has no name; use Clear All to remove unnamed filters.",
             NoticeKind::Warning);
      return;
    }
    if (!FirewallKernelOpEx(
            reinterpret_cast<const WCHAR *>(Qs(Name).utf16()),
            FIREWALL_OP_REMOVE, 0, 0, 0, 0, nullptr, 0, 0)) {
      Notify(U8(QString("Remove failed (error %1).").arg(G_LastAegisCoreError)),
             NoticeKind::Error);
      return;
    }
    MarkMutated();
    RulesStatus_ = QString("Rule '%1' removed.").arg(Qs(Name));
    Notify(U8(RulesStatus_), NoticeKind::Success);
    RefreshRules();
  }

  void ClearRules() {
    if (!Dialogs)
      return;
    ConfirmDialog(
        *Dialogs, "Clear Firewall Rules",
        "Remove ALL filters created by AegisNT on its sublayer? Rules from "
        "other vendors are not touched.",
        [this] {
          if (!FirewallKernelOpEx(L"", FIREWALL_OP_CLEAR, 0, 0, 0, 0, nullptr,
                                  0, 0)) {
            Notify(U8(QString("Clear failed (error %1).")
                          .arg(G_LastAegisCoreError)),
                   NoticeKind::Error);
            return;
          }
          MarkMutated();
          Notify("All AegisNT firewall rules cleared.", NoticeKind::Success);
          RefreshRules();
        },
        "Clear", "Cancel");
  }

  void ShowAddRule(int PrefillPort, const std::string &PrefillBaseProtocol,
                   bool PrefillV6, const std::function<void()> &Then) {
    if (!Dialogs)
      return;
    TuiDialog Dialog;
    Dialog.Title = "Add Firewall Rule";
    Dialog.PrimaryLabel = "Add Rule";
    std::string Name;
    if (PrefillPort > 0)
      Name = "Block " + PrefillBaseProtocol + " port " +
             std::to_string(PrefillPort);
    int ProtocolChoice = 0;
    if (PrefillBaseProtocol == "TCP")
      ProtocolChoice = 1;
    else if (PrefillBaseProtocol == "UDP")
      ProtocolChoice = 2;
    Dialog.Fields.push_back(TextField("Name", Name, "Rule name (required)"));
    Dialog.Fields.push_back(ComboField("Action", {"Block", "Permit"}, 0));
    Dialog.Fields.push_back(
        ComboField("Protocol", {"Any", "TCP", "UDP"}, ProtocolChoice));
    Dialog.Fields.push_back(
        TextField("Remote Port", PrefillPort > 0 ? std::to_string(PrefillPort)
                                                 : std::string("0"),
                  "Remote port, 0 = any"));
    Dialog.Fields.push_back(
        ComboField("Scope", {"Both directions", "Outbound only",
                             "Inbound only"},
                   0));
    Dialog.Fields.push_back(ComboField(
        "Family", {"IPv4 + IPv6", "IPv4 only", "IPv6 only"},
        PrefillV6 ? 2 : 0));
    Dialog.Fields.push_back(
        TextField("IPv4", "", "Remote IPv4, empty = any (e.g. 1.2.3.4)"));
    Dialog.Fields.push_back(
        TextField("IPv6", "", "Remote IPv6, empty = any (e.g. ::1)"));
    Dialog.OnSubmit = [this, Then](TuiDialog &Submitted) {
      if (Submitted.Fields.size() < 8)
        return;
      const std::string NameValue = TrimAscii(Submitted.Fields[0].Value);
      const std::string PortText = TrimAscii(Submitted.Fields[3].Value);
      bool PortOk =
          !PortText.empty() &&
          PortText.find_first_not_of("0123456789") == std::string::npos;
      unsigned long PortValue = 0;
      if (PortOk) {
        try {
          PortValue = std::stoul(PortText);
        } catch (...) {
          PortOk = false;
        }
      }
      if (!PortOk || PortValue > 65535) {
        Notify("Remote port must be 0-65535.", NoticeKind::Warning);
        return;
      }
      ULONG RemoteIpv4 = 0;
      const std::string Ipv4Text = TrimAscii(Submitted.Fields[6].Value);
      if (!Ipv4Text.empty()) {
        in_addr Address{};
        if (inet_pton(AF_INET, Ipv4Text.c_str(), &Address) != 1) {
          Notify("Invalid IPv4 address.", NoticeKind::Warning);
          return;
        }
        RemoteIpv4 = Address.s_addr;
      }
      UCHAR RemoteIpv6[16] = {};
      const std::string Ipv6Text = TrimAscii(Submitted.Fields[7].Value);
      if (!Ipv6Text.empty()) {
        in6_addr Address{};
        if (inet_pton(AF_INET6, Ipv6Text.c_str(), &Address) != 1) {
          Notify("Invalid IPv6 address.", NoticeKind::Warning);
          return;
        }
        memcpy(RemoteIpv6, &Address, 16);
      }
      const ULONG Action = Submitted.Fields[1].Choice == 1
                               ? FIREWALL_ACTION_PERMIT
                               : FIREWALL_ACTION_BLOCK;
      const ULONG Protocol = Submitted.Fields[2].Choice == 1
                                 ? 6ul
                                 : (Submitted.Fields[2].Choice == 2 ? 17ul
                                                                    : 0ul);
      const ULONG DirectionMask =
          Submitted.Fields[4].Choice == 1
              ? FIREWALL_DIRBIT_OUT
              : (Submitted.Fields[4].Choice == 2 ? FIREWALL_DIRBIT_IN : 0ul);
      const ULONG FamilyMask =
          Submitted.Fields[5].Choice == 1
              ? FIREWALL_FAMILYBIT_V4
              : (Submitted.Fields[5].Choice == 2 ? FIREWALL_FAMILYBIT_V6
                                                 : 0ul);
      if (!FirewallKernelOpEx(
              reinterpret_cast<const WCHAR *>(Qs(NameValue).utf16()),
              FIREWALL_OP_ADD, Action, static_cast<ULONG>(PortValue), Protocol,
              RemoteIpv4, Ipv6Text.empty() ? nullptr : RemoteIpv6,
              DirectionMask, FamilyMask)) {
        Notify(U8(QString("Add rule failed (error %1).")
                      .arg(G_LastAegisCoreError)),
               NoticeKind::Error);
        return;
      }
      MarkMutated();
      Notify("Rule '" + NameValue + "' added.", NoticeKind::Success);
      RefreshRules();
      if (Then)
        Then();
    };
    Dialog.Validate = [](const TuiDialog &Submitted) -> std::string {
      if (Submitted.Fields.empty() ||
          TrimAscii(Submitted.Fields[0].Value).empty())
        return "Enter a rule name.";
      return {};
    };
    Dialogs->Push(std::move(Dialog));
  }

  int Index_ = 0;
  bool Loaded_ = false;
  int Tab_ = 0;
  bool AutoRefresh_ = false;
  bool RefreshPending_ = false;
  bool RulesPending_ = false;
  bool RulesKernelBacked_ = false;
  bool RulesStatusIsError_ = false;
  int64_t LastAutoMs_ = 0;
  int ProtocolIndex_ = 0;
  std::vector<std::string> ProtocolLabels_{"All protocols", "TCP", "UDP"};
  std::vector<ConnEntry> ConnRows_;
  std::vector<size_t> ConnRowSource_;
  TuiTable ConnTable_;
  TuiTable RulesTable_;
  QString RulesStatus_ = "Ready";
};

// ------------------------------------------------------------
// 19 · Snapshot —— 捕获 / 导入导出 / 比对 / 基线监视
// ------------------------------------------------------------

class SnapshotPage final : public TuiPage {
public:
  explicit SnapshotPage(int Index) : Index_(Index) {
    Slots_.Headers = {"Slot", "Captured At", "Source", "Objects"};
    Diff_.Headers = {"State", "Key", "Primary Name", "Change Summary"};
    RegisterCommands();
    RefreshSlotTable();
  }

  std::string Title() const override { return "Snapshot"; }

  std::string Subtitle() const override {
    return "system snapshots A/B: capture, import/export, compare, baseline";
  }

  void OnEnter() override {
    Loaded_ = true;
    RefreshSlotTable();
    RepopulateDiff();
    SetStatus(StatusText());
  }

  void OnTick(int64_t NowMs) override {
    if (WatchMinutes_ <= 0 || !Baseline_.has_value())
      return;
    if (LastWatchMs_ == 0) {
      LastWatchMs_ = NowMs;
      return;
    }
    if (NowMs - LastWatchMs_ < static_cast<int64_t>(WatchMinutes_) * 60000)
      return;
    LastWatchMs_ = NowMs;
    RunBaselineCheck();
  }

  TuiTable *ActiveTable() override {
    // Summary 视图没有表格（只有 A/B 的统计文本）。
    return CategoryIndex_ == 3 ? nullptr : &Diff_;
  }

  std::string RenderText() override {
    RefreshSlotTable();
    RepopulateDiff();
    std::string Text = ViewStrip();
    Text += '\n';
    Text += "  baseline: " +
            std::string(Baseline_.has_value() ? "loaded" : "none") +
            "   watch: " +
            (WatchMinutes_ > 0 ? std::to_string(WatchMinutes_) + " min"
                               : std::string("off")) + '\n';
    Text += "Slots\n";
    Text += TuiTableToText(Slots_, 0);
    if (CategoryIndex_ == 3) {
      const std::string Summary = U8(BuildSummaryText());
      Text += Summary.empty() ? std::string("Compare A and B to view summary.")
                              : Summary;
      Text += '\n';
    } else {
      Text += TuiTableToText(Diff_, 200);
    }
    return Text;
  }

private:
  // 视图切换沿用页面的 `view` 命令（等价于原 F7/F8）。
  std::string ViewStrip() const {
    return ::AegisNT::Tui::TabStrip(Categories_,
                                    static_cast<int>(CategoryIndex_));
  }

  void RegisterCommands() {
    OwnedCommands.push_back(
        {"capture", "capture [a|b]  (capture a live snapshot)",
         [this](std::vector<std::string> Args) { Capture(Args); }});
    OwnedCommands.push_back(
        {"load-json", "load-json [path]  (load a snapshot JSON)",
         [this](std::vector<std::string> Args) { LoadJson(Args); }});
    OwnedCommands.push_back(
        {"save-json", "save-json [path]  (save the selected snapshot)",
         [this](std::vector<std::string> Args) { SaveJson(Args); }});
    OwnedCommands.push_back(
        {"compare", "compare  (diff snapshot A against B)",
         [this](std::vector<std::string>) { Compare(); }});
    OwnedCommands.push_back({"clear", "clear  (drop both snapshots and diffs)",
                             [this](std::vector<std::string>) { ClearAll(); }});
    OwnedCommands.push_back(
        {"set-baseline", "set-baseline [path]  (load a baseline JSON)",
         [this](std::vector<std::string> Args) { SetBaseline(Args); }});
    OwnedCommands.push_back(
        {"watch", "watch <off|5|15|60>  (baseline watch interval)",
         [this](std::vector<std::string> Args) { SetWatch(Args); }});
    OwnedCommands.push_back(
        {"details", "details  (old/new JSON for the selected diff row)",
         [this](std::vector<std::string>) { ShowDiffDetails(); }});
    OwnedCommands.push_back(
        {"view", "view <processes|drivers|callbacks|summary>",
         [this](std::vector<std::string> Args) { SetView(Args); }});
  }

  void SetView(const std::vector<std::string> &Args) {
    if (Args.empty()) {
      CategoryIndex_ = (CategoryIndex_ + 1) % 4;
      RepopulateDiff();
      return;
    }
    const std::string Needle = LowerAscii(Args.front());
    for (size_t Index = 0; Index < Categories_.size(); ++Index) {
      if (LowerAscii(Categories_[Index]).find(Needle) == 0) {
        CategoryIndex_ = static_cast<int>(Index);
        RepopulateDiff();
        return;
      }
    }
    Notify("Unknown view: " + Args.front(), NoticeKind::Warning);
  }

  void RefreshSlotTable() {
    Slots_.Rows.clear();
    const auto Describe = [](const std::optional<SnapshotModel::SnapshotDocument>
                                 &Document) {
      if (!Document.has_value())
        return std::vector<std::string>{"-", "-", "0"};
      return std::vector<std::string>{
          Document->Meta.CapturedAtUtc.toStdString(),
          Document->Source.toStdString(),
          std::to_string(Document->Processes.size() +
                         Document->Drivers.size() +
                         Document->Callbacks.size())};
    };
    const auto A = Describe(SnapshotA_);
    const auto B = Describe(SnapshotB_);
    Slots_.Rows.push_back(TuiRow{{"Snapshot A", A[0], A[1], A[2]}, {}});
    Slots_.Rows.push_back(TuiRow{{"Snapshot B", B[0], B[1], B[2]}, {}});
    Slots_.Rebuild();
  }

  std::optional<SnapshotModel::SnapshotDocument> *SlotFor(
      SnapshotModel::SlotKind Kind) {
    return Kind == SnapshotModel::SlotKind::A ? &SnapshotA_ : &SnapshotB_;
  }

  bool SlotTaken(SnapshotModel::SlotKind Kind) {
    return SlotFor(Kind)->has_value();
  }

  void ChooseSlot(const std::string &Action,
                  std::function<void(SnapshotModel::SlotKind)> OnChosen) {
    if (!SnapshotA_.has_value()) {
      OnChosen(SnapshotModel::SlotKind::A);
      return;
    }
    if (!SnapshotB_.has_value()) {
      OnChosen(SnapshotModel::SlotKind::B);
      return;
    }
    if (!Dialogs)
      return;
    TuiDialog Dialog;
    Dialog.Title = Action;
    Dialog.Body =
        "Snapshot A and B already exist. Choose a slot to overwrite.";
    Dialog.Fields.push_back(
        ComboField("Slot", {"Snapshot A", "Snapshot B"}, 0));
    Dialog.PrimaryLabel = "Overwrite";
    Dialog.OnSubmit = [OnChosen](TuiDialog &Submitted) {
      const int Choice = Submitted.Fields.empty()
                             ? 0
                             : Submitted.Fields.front().Choice;
      OnChosen(Choice == 1 ? SnapshotModel::SlotKind::B
                           : SnapshotModel::SlotKind::A);
    };
    Dialogs->Push(std::move(Dialog));
  }

  void Capture(const std::vector<std::string> &Args) {
    if (Busy_) {
      Notify("A snapshot operation is already running.", NoticeKind::Info);
      return;
    }
    if (!Args.empty()) {
      const std::string Needle = LowerAscii(TrimAscii(Args.front()));
      const bool WantB = Needle == "b" || Needle == "snapshotb";
      if (WantB || Needle == "a" || Needle == "snapshota") {
        const auto Kind = WantB ? SnapshotModel::SlotKind::B
                                : SnapshotModel::SlotKind::A;
        if (SlotTaken(Kind)) {
          ChooseSlot("Capture Snapshot",
                     [this](SnapshotModel::SlotKind Chosen) {
                       StartCapture(Chosen);
                     });
        } else {
          StartCapture(Kind);
        }
        return;
      }
    }
    ChooseSlot("Capture Snapshot",
               [this](SnapshotModel::SlotKind Chosen) { StartCapture(Chosen); });
  }

  void StartCapture(SnapshotModel::SlotKind Kind) {
    Busy_ = true;
    SetStatus("Capturing snapshot...");
    TuiAsync<SnapshotModel::CaptureResult>(
        [] { return SnapshotModel::CaptureSnapshotDocument(); },
        [this, Kind](SnapshotModel::CaptureResult Result) {
          Busy_ = false;
          *SlotFor(Kind) = Result.Document;
          LastDiff_ = SnapshotModel::SnapshotDiffResult{};
          RefreshSlotTable();
          RepopulateDiff();
          const auto *Document = &*SlotFor(Kind);
          std::string Message =
              "Captured snapshot. Processes:" +
              std::to_string(Document->value().Processes.size()) +
              " Drivers:" + std::to_string(Document->value().Drivers.size()) +
              " Callbacks:" +
              std::to_string(Document->value().Callbacks.size());
          if (!Result.Failures.isEmpty()) {
            Message += "\nFailures:\n" + U8(Result.Failures.join("\n"));
            Notify(Message, NoticeKind::Warning);
          } else {
            Notify(Message, NoticeKind::Success);
          }
          SetStatus(StatusText());
          MarkMutated();
        });
  }

  void LoadJson(const std::vector<std::string> &Args) {
    if (Busy_)
      return;
    QString Path = Qs(TrimAscii(Args.empty() ? std::string() : Args.front()));
    if (Path.isEmpty()) {
      if (auto Selected = BrowseOpenFile(
              "Load Snapshot JSON",
              "Aegis Snapshot (*.aegis-snapshot.json);;JSON (*.json)"))
        Path = *Selected;
      if (Path.isEmpty()) {
        if (!Dialogs)
          return;
        PromptPath(*Dialogs, "Load Snapshot JSON", "JSON path", QString(),
                   [this](QString Value) { LoadJson({U8(Value)}); });
        return;
      }
    }
    QFile File(Path);
    if (!File.open(QIODevice::ReadOnly)) {
      Notify("Unable to open file.\n" + U8(QDir::toNativeSeparators(Path)),
             NoticeKind::Error);
      return;
    }
    SnapshotModel::SnapshotDocument Document;
    QString Error;
    if (!SnapshotModel::ParseDocument(File.readAll(), Document, Error)) {
      Notify(U8(Error), NoticeKind::Error);
      return;
    }
    Document.LoadPath = QDir::toNativeSeparators(Path);
    const QString Loaded = QDir::toNativeSeparators(Path);
    ChooseSlot("Load Snapshot JSON",
               [this, Document, Loaded](SnapshotModel::SlotKind Kind) {
                 *SlotFor(Kind) = Document;
                 LastDiff_ = SnapshotModel::SnapshotDiffResult{};
                 RefreshSlotTable();
                 RepopulateDiff();
                 Notify("Snapshot JSON loaded.\n" + U8(Loaded),
                        NoticeKind::Success);
                 SetStatus(StatusText());
                 MarkMutated();
               });
  }

  void SaveJson(const std::vector<std::string> &Args) {
    SnapshotModel::SlotKind Kind = SnapshotModel::SlotKind::A;
    if (!Args.empty() && !TrimAscii(Args.front()).empty()) {
      const std::string Needle = LowerAscii(TrimAscii(Args.front()));
      if (Needle == "b")
        Kind = SnapshotModel::SlotKind::B;
    } else if (Slots_.Selected == 1) {
      Kind = SnapshotModel::SlotKind::B;
    }
    const auto &Slot = *SlotFor(Kind);
    if (!Slot.has_value()) {
      Notify("Select Snapshot A or B before saving.", NoticeKind::Warning);
      return;
    }
    const QString DefaultName = QString("snapshot-%1.aegis-snapshot.json")
                                    .arg(QDateTime::currentDateTimeUtc()
                                             .toString("yyyyMMdd-hhmmss"));
    QString Path;
    if (Args.size() > 1)
      Path = Qs(TrimAscii(Args[1]));
    if (Path.isEmpty()) {
      if (auto Selected = BrowseSaveFile("Save Snapshot JSON", DefaultName))
        Path = *Selected;
      if (Path.isEmpty()) {
        if (!Dialogs)
          return;
        const std::string SlotLetter =
            Kind == SnapshotModel::SlotKind::B ? "b" : "a";
        PromptPath(*Dialogs, "Save Snapshot JSON", "JSON path",
                   QDir(QCoreApplication::applicationDirPath())
                       .filePath(DefaultName),
                   [this, SlotLetter](QString Value) {
                     SaveJson({SlotLetter, U8(Value)});
                   });
        return;
      }
    }
    QSaveFile File(Path);
    if (!File.open(QIODevice::WriteOnly)) {
      Notify("Unable to open file for writing.\n" +
                 U8(QDir::toNativeSeparators(Path)),
             NoticeKind::Error);
      return;
    }
    const QByteArray Data = SnapshotModel::SerializeDocument(*Slot);
    if (File.write(Data) != Data.size() || !File.commit()) {
      Notify("Failed to save snapshot JSON.\n" +
                 U8(QDir::toNativeSeparators(Path)),
             NoticeKind::Error);
      return;
    }
    Notify("Snapshot JSON saved.\n" + U8(QDir::toNativeSeparators(Path)),
           NoticeKind::Success);
  }

  void SetBaseline(const std::vector<std::string> &Args) {
    QString Path = Qs(TrimAscii(Args.empty() ? std::string() : Args.front()));
    if (Path.isEmpty()) {
      if (auto Selected =
              BrowseOpenFile("Load baseline snapshot", "JSON (*.json)"))
        Path = *Selected;
      if (Path.isEmpty()) {
        if (!Dialogs)
          return;
        PromptPath(*Dialogs, "Load baseline snapshot", "JSON path", QString(),
                   [this](QString Value) { SetBaseline({U8(Value)}); });
        return;
      }
    }
    QFile File(Path);
    if (!File.open(QIODevice::ReadOnly)) {
      Notify("Failed to open baseline: " + U8(File.errorString()),
             NoticeKind::Error);
      return;
    }
    SnapshotModel::SnapshotDocument Document;
    QString Error;
    if (!SnapshotModel::ParseDocument(File.readAll(), Document, Error)) {
      Notify(U8(Error), NoticeKind::Error);
      return;
    }
    Baseline_ = std::move(Document);
    LastWatchMs_ = 0;
    const std::string Status =
        "Baseline loaded (" + std::to_string(Baseline_->Processes.size()) +
        " processes, " + std::to_string(Baseline_->Drivers.size()) +
        " drivers, " + std::to_string(Baseline_->Callbacks.size()) +
        " callbacks)";
    SetStatus(Status);
    Notify(Status, NoticeKind::Success);
  }

  void SetWatch(const std::vector<std::string> &Args) {
    if (Args.empty()) {
      Notify("watch <off|5|15|60>", NoticeKind::Info);
      return;
    }
    const std::string Value = LowerAscii(TrimAscii(Args.front()));
    int Minutes = 0;
    if (Value == "off" || Value == "0")
      Minutes = 0;
    else if (Value == "5")
      Minutes = 5;
    else if (Value == "15")
      Minutes = 15;
    else if (Value == "60")
      Minutes = 60;
    else {
      Notify("watch <off|5|15|60>", NoticeKind::Warning);
      return;
    }
    if (Minutes > 0 && !Baseline_.has_value()) {
      Notify("Load a baseline JSON first (Set Baseline).",
             NoticeKind::Error);
      return;
    }
    WatchMinutes_ = Minutes;
    LastWatchMs_ = 0;
    SetConfigurationValue("Snapshot", "WatchIntervalMinutes", Minutes);
    SetStatus(Minutes > 0 ? "Baseline watch active (" +
                                std::to_string(Minutes) + " min)"
                          : std::string("Baseline watch off"));
  }

  void RunBaselineCheck() {
    if (Busy_ || !Baseline_.has_value())
      return;
    Busy_ = true;
    SetStatus("Checking baseline...");
    auto Baseline = *Baseline_;
    TuiAsync<SnapshotModel::CaptureResult>(
        [] { return SnapshotModel::CaptureSnapshotDocument(); },
        [this, Baseline](SnapshotModel::CaptureResult Result) {
          Busy_ = false;
          const SnapshotModel::SnapshotDiffResult Diff =
              SnapshotModel::BuildDiff(Baseline, Result.Document);
          const int Changes = static_cast<int>(Diff.Processes.size() +
                                               Diff.Drivers.size() +
                                               Diff.Callbacks.size());
          if (Changes > 0) {
            Notify("Baseline drift detected: " + std::to_string(Changes) +
                       " change(s) (processes " +
                       std::to_string(Diff.Processes.size()) + ", drivers " +
                       std::to_string(Diff.Drivers.size()) + ", callbacks " +
                       std::to_string(Diff.Callbacks.size()) + ").",
                   NoticeKind::Warning);
            SetStatus("Baseline drift: " + std::to_string(Changes) +
                      " change(s)");
          } else {
            SetStatus("Baseline check: no drift");
          }
        });
  }

  void Compare() {
    if (!SnapshotA_.has_value() || !SnapshotB_.has_value()) {
      Notify("Compare requires both Snapshot A and Snapshot B.",
             NoticeKind::Warning);
      return;
    }
    LastDiff_ = SnapshotModel::BuildDiff(*SnapshotA_, *SnapshotB_);
    RepopulateDiff();
    SetStatus(StatusText());
    if (!LastDiff_.Warnings.isEmpty())
      Notify("Compare completed with warnings.\n" +
                 U8(LastDiff_.Warnings.join("\n")),
             NoticeKind::Warning);
    else
      Notify("Compare completed.", NoticeKind::Success);
  }

  void ClearAll() {
    if (Busy_)
      return;
    SnapshotA_.reset();
    SnapshotB_.reset();
    LastDiff_ = SnapshotModel::SnapshotDiffResult{};
    RefreshSlotTable();
    RepopulateDiff();
    Notify("Snapshot A, Snapshot B, and diff results cleared.",
           NoticeKind::Success);
    SetStatus(StatusText());
  }

  const std::vector<SnapshotModel::DiffRow> *CurrentRows() const {
    switch (CategoryIndex_) {
    case 0:
      return &LastDiff_.Processes;
    case 1:
      return &LastDiff_.Drivers;
    case 2:
      return &LastDiff_.Callbacks;
    default:
      return nullptr;
    }
  }

  void RepopulateDiff() {
    Diff_.Rows.clear();
    DiffRowSource_.clear();
    Diff_.Filter = Filter;
    const std::vector<SnapshotModel::DiffRow> *Rows = CurrentRows();
    if (Rows) {
      for (size_t Index = 0; Index < Rows->size(); ++Index) {
        const SnapshotModel::DiffRow &Row = (*Rows)[Index];
        Diff_.Rows.push_back(TuiRow{{U8(Row.State), U8(Row.Key),
                                     U8(Row.PrimaryName),
                                     U8(Row.Summary)},
                                    {}});
        DiffRowSource_.push_back(Index);
      }
    }
    Diff_.Rebuild();
    SetStatus(StatusText());
  }

  std::string StatusText() const {
    const size_t Processes =
        SnapshotA_.has_value() ? SnapshotA_->Processes.size() : 0;
    const size_t Drivers =
        SnapshotA_.has_value() ? SnapshotA_->Drivers.size() : 0;
    const size_t Callbacks =
        SnapshotA_.has_value() ? SnapshotA_->Callbacks.size() : 0;
    return std::string("A: ") + (SnapshotA_.has_value() ? "set" : "-") +
           "  B: " + (SnapshotB_.has_value() ? "set" : "-") + "  |  A(" +
           std::to_string(Processes) + "/" + std::to_string(Drivers) + "/" +
           std::to_string(Callbacks) + ")  |  diff rows " +
           std::to_string(LastDiff_.Processes.size() +
                          LastDiff_.Drivers.size() +
                          LastDiff_.Callbacks.size());
  }

  QString BuildSummaryText() const {
    QString Text;
    QTextStream Stream(&Text);
    Stream << "Snapshot A\n";
    Stream << "  Source: " << (SnapshotA_.has_value() ? SnapshotA_->Source : "-")
           << "\n";
    Stream << "  CapturedAtUtc: "
           << (SnapshotA_.has_value() ? SnapshotA_->Meta.CapturedAtUtc : "-")
           << "\n";
    Stream << "Snapshot B\n";
    Stream << "  Source: " << (SnapshotB_.has_value() ? SnapshotB_->Source : "-")
           << "\n";
    Stream << "  CapturedAtUtc: "
           << (SnapshotB_.has_value() ? SnapshotB_->Meta.CapturedAtUtc : "-")
           << "\n\n";
    const auto AppendStats = [&Stream](
                                 const char *Name,
                                 const SnapshotModel::DiffStats &Stats,
                                 int TotalRows) {
      Stream << Name << "\n";
      Stream << "  Added: " << Stats.Added << "\n";
      Stream << "  Removed: " << Stats.Removed << "\n";
      Stream << "  Modified: " << Stats.Modified << "\n";
      Stream << "  Total diff rows: " << TotalRows << "\n";
    };
    AppendStats("Processes", LastDiff_.ProcessStats,
                static_cast<int>(LastDiff_.Processes.size()));
    AppendStats("Drivers", LastDiff_.DriverStats,
                static_cast<int>(LastDiff_.Drivers.size()));
    AppendStats("Callbacks", LastDiff_.CallbackStats,
                static_cast<int>(LastDiff_.Callbacks.size()));
    if (!LastDiff_.Warnings.isEmpty()) {
      Stream << "\nWarnings\n";
      for (const QString &Warning : LastDiff_.Warnings)
        Stream << "  - " << Warning << "\n";
    }
    return Text.trimmed();
  }

  void ShowDiffDetails() {
    if (!Dialogs)
      return;
    const int Row = Diff_.CurrentRowIndex();
    const std::vector<SnapshotModel::DiffRow> *Rows = CurrentRows();
    if (!Rows || Row < 0 || Row >= static_cast<int>(Rows->size()))
      return;
    const SnapshotModel::DiffRow &Entry = (*Rows)[static_cast<size_t>(Row)];
    std::vector<TuiRow> Detail;
    Detail.push_back(TuiRow{{"Category", U8(Entry.Category)}, {}});
    Detail.push_back(TuiRow{{"State", U8(Entry.State)}, {}});
    Detail.push_back(TuiRow{{"Key", U8(Entry.Key)}, {}});
    Detail.push_back(TuiRow{{"Name", U8(Entry.PrimaryName)}, {}});
    Detail.push_back(TuiRow{{"Summary", U8(Entry.Summary)}, {}});
    Detail.push_back(TuiRow{{"Changed",
                             U8(Entry.ChangedFields.join(", "))},
                            {}});
    Detail.push_back(
        TuiRow{{"Old",
                U8(QString::fromUtf8(QJsonDocument(Entry.OldValue)
                                        .toJson(QJsonDocument::Compact)))},
               {}});
    Detail.push_back(
        TuiRow{{"New",
                U8(QString::fromUtf8(QJsonDocument(Entry.NewValue)
                                        .toJson(QJsonDocument::Compact)))},
               {}});
    DetailDialog(*Dialogs, "Diff Details", Detail);
  }

  int Index_ = 0;
  bool Loaded_ = false;
  bool Busy_ = false;
  int CategoryIndex_ = 0;
  int WatchMinutes_ = 0;
  int64_t LastWatchMs_ = 0;
  std::vector<std::string> Categories_{"Processes", "Drivers", "Callbacks",
                                       "Summary"};
  std::optional<SnapshotModel::SnapshotDocument> SnapshotA_;
  std::optional<SnapshotModel::SnapshotDocument> SnapshotB_;
  std::optional<SnapshotModel::SnapshotDocument> Baseline_;
  SnapshotModel::SnapshotDiffResult LastDiff_;
  std::vector<size_t> DiffRowSource_;
  TuiTable Slots_;
  TuiTable Diff_;
};

} // namespace ModPages

// ------------------------------------------------------------
// 工厂（索引与 PageDefinitions()/CreatePageBody 一致）
// ------------------------------------------------------------

std::unique_ptr<TuiPage> MakePayloadPage(int Index) {
  return std::make_unique<ModPages::PayloadPage>(Index);
}

std::unique_ptr<TuiPage> MakeModuleRunPage(int Index) {
  return std::make_unique<ModPages::ModuleRunPage>(Index);
}

std::unique_ptr<TuiPage> MakeModuleManagerPage(int Index) {
  return std::make_unique<ModPages::ModuleManagerPage>(Index);
}

std::unique_ptr<TuiPage> MakeConsolePage(int Index) {
  return std::make_unique<ModPages::ConsolePage>(Index);
}

std::unique_ptr<TuiPage> MakeChatPage(int Index) {
  return std::make_unique<ModPages::ChatPage>(Index);
}

std::unique_ptr<TuiPage> MakeNetworkPage(int Index) {
  return std::make_unique<ModPages::NetworkPage>(Index);
}

std::unique_ptr<TuiPage> MakeSnapshotPage(int Index) {
  return std::make_unique<ModPages::SnapshotPage>(Index);
}

} // namespace AegisNT::Tui
