// ============================================================
// 控制台设置页与账号页。
// ------------------------------------------------------------
// 与 GUI 的 CreateSettingsPage / CreateAccountPage 一一对应：
//   - Settings：Language / Theme / Module paths / Application /
//     Console / About / Software update 七组逐行编辑，写入同一批
//     配置键（主题走 SetConfigurationValueTransient + SaveConfiguration）。
//   - Account ：登录状态、注册、改密、改用户类型；端点与信封
//     {success,message,data} 与 GUI 完全相同。
// 两个页面都用 TuiAsync 执行网络请求，结果回到 UI 线程。
//
// 输出约定：页面只产出纯文本（RenderText）+ 一张 TuiTable（ActiveTable），
// `show` 打印文本、`detail <n>` 打印选中行、`filter` 走 Table 的 Filter；
// 页面不再直接渲染，交互全部经由 OwnedCommands 里的命令触发。
//
// 交互约定：TuiDialogStack 的 Tab 焦点切换被外壳占用，且 Combo/Check
// 字段不会用 Enter 提交，因此这里所有编辑都走“单字段对话框”：
// 多字段流程拆成连续的单字段输入（Enter 确认当前项、Esc 取消整条流程），
// 枚举值用文本输入 + 校验（错误文案与 GUI 一致）。
// ============================================================

#include "TuiAsync.h"
#include "TuiCore.h"
#include "TuiPages.h"
#include "TuiSync.h"
#include "TuiWidgets.h"

namespace AegisNT::Tui {

namespace {

// ------------------------------------------------------------
// 共用小工具
// ------------------------------------------------------------

std::string MiscUtf8(const QString &Text) { return Text.toStdString(); }
QString MiscFromUtf8(const std::string &Text) { return QString::fromStdString(Text); }

// --console 独占模式下没有窗口可隐藏：Console 行退化为只读。
bool MiscConsoleOnlyProcess() {
  QCoreApplication *App = QCoreApplication::instance();
  if (!App)
    return false;
  for (const QString &Argument : App->arguments()) {
    if (Argument.compare(QLatin1String("--console"), Qt::CaseInsensitive) == 0)
      return true;
  }
  return false;
}

// "#RRGGBB" 校验（与设置页颜色对话框的取色结果同一格式）。
bool MiscParseHexColor(const std::string &Text, QColor *Out) {
  const QString Value = MiscFromUtf8(Text).trimmed().toUpper();
  if (Value.size() != 7 || !Value.startsWith(QLatin1Char('#')))
    return false;
  for (int Index = 1; Index < 7; ++Index) {
    const QChar C = Value.at(Index);
    if (!C.isDigit() && (C < QLatin1Char('A') || C > QLatin1Char('F')))
      return false;
  }
  const QColor Color(Value);
  if (!Color.isValid())
    return false;
  if (Out)
    *Out = Color;
  return true;
}

std::string MiscHexColorText(const QColor &Color) {
  return MiscUtf8(Color.name(QColor::HexRgb).toUpper());
}

// 预设 id <-> 显示名（顺序与 GUI 的 ComboBox 一致）。
const char *const MiscKPresetIds[] = {"default_blue", "cyan", "indigo",
                                  "graphite", "custom"};
const char *const MiscKPresetLabels[] = {"Default Blue", "Cyan", "Indigo",
                                     "Graphite", "Custom"};

int MiscPresetIndexForId(const QString &Id) {
  for (int Index = 0; Index < 5; ++Index) {
    if (Id.compare(QLatin1String(MiscKPresetIds[Index]), Qt::CaseInsensitive) == 0)
      return Index;
  }
  return 4; // Custom
}

// ------------------------------------------------------------
// 单字段链式对话框
// ------------------------------------------------------------

struct MiscFieldSpec {
  std::string Label;
  TuiFieldKind Kind = TuiFieldKind::Text;
  std::string Value;
  std::string Placeholder;
  std::string Hint;
  // 返回空字符串表示通过；否则是该字段的错误文案。
  std::function<std::string(const std::string &)> Validate;
};

using MiscFieldList = std::shared_ptr<std::vector<MiscFieldSpec>>;
using MiscValueList = std::shared_ptr<std::vector<std::string>>;

void MiscPushSequence(TuiDialogStack *Stack, const std::string &Title,
                  MiscFieldList Fields, MiscValueList Values, size_t Step,
                  std::function<void(const std::vector<std::string> &)> Done);

void MiscPushSequenceStep(TuiDialogStack *Stack, const std::string &Title,
                      MiscFieldList Fields, MiscValueList Values, size_t Step,
                      std::function<void(const std::vector<std::string> &)> Done) {
  if (!Stack || !Fields || !Values || !Done)
    return;
  if (Step >= Fields->size()) {
    Done(*Values);
    return;
  }
  const MiscFieldSpec Spec = (*Fields)[Step];
  TuiDialog Dialog;
  Dialog.Title =
      Title + "  (" + std::to_string(Step + 1) + "/" +
      std::to_string(Fields->size()) + ")";
  TuiField Field;
  Field.Label = Spec.Label;
  Field.Kind = Spec.Kind;
  Field.Value = Spec.Value;
  Field.Placeholder = Spec.Placeholder;
  Field.Hint = Spec.Hint;
  Dialog.Fields.push_back(Field);
  if (Spec.Validate) {
    auto Validate = Spec.Validate;
    Dialog.Validate = [Validate](const TuiDialog &Input) -> std::string {
      return Validate(Input.Fields.empty() ? std::string()
                                           : Input.Fields.front().Value);
    };
  }
  Dialog.OnSubmit = [Stack, Title, Fields, Values, Step,
                     Done](TuiDialog &Submitted) {
    (*Values)[Step] = Submitted.Fields.empty()
                          ? std::string()
                          : Submitted.Fields.front().Value;
    MiscPushSequenceStep(Stack, Title, Fields, Values, Step + 1, Done);
  };
  Stack->Push(std::move(Dialog));
}

void MiscPushSequence(TuiDialogStack *Stack, const std::string &Title,
                  MiscFieldList Fields, MiscValueList Values, size_t Step,
                  std::function<void(const std::vector<std::string> &)> Done) {
  MiscPushSequenceStep(Stack, Title, std::move(Fields), std::move(Values), Step,
                   std::move(Done));
}

// 便捷入口：从字段描述开始一条流程。
void MiscPushForm(TuiDialogStack *Stack, const std::string &Title,
              std::vector<MiscFieldSpec> Fields,
              std::function<void(const std::vector<std::string> &)> Done) {
  if (!Stack)
    return;
  auto List = std::make_shared<std::vector<MiscFieldSpec>>(std::move(Fields));
  auto Values = std::make_shared<std::vector<std::string>>(List->size());
  MiscPushSequence(Stack, Title, List, Values, 0, std::move(Done));
}

// 纯确认框（无字段 → Enter 直接提交）。
void MiscPushConfirm(TuiDialogStack *Stack, const std::string &Title,
                 const std::string &Text, std::function<void()> OnYes) {
  if (!Stack)
    return;
  ConfirmDialog(*Stack, Title, Text, std::move(OnYes), "Yes", "No");
}

// 枚举文本校验：接受显示名、id 或序号，返回规范化索引；失败返回 -1。
int MiscMatchChoice(const std::string &Text, const char *const *Labels,
                const char *const *Ids, int Count) {
  const std::string Needle = LowerAscii(TrimAscii(Text));
  if (Needle.empty())
    return -1;
  for (int Index = 0; Index < Count; ++Index) {
    if (Needle == LowerAscii(Labels[Index]))
      return Index;
  }
  if (Ids) {
    for (int Index = 0; Index < Count; ++Index) {
      if (Needle == LowerAscii(Ids[Index]))
        return Index;
    }
  }
  bool Ok = false;
  const int Number = MiscFromUtf8(Needle).toInt(&Ok);
  if (Ok && Number >= 1 && Number <= Count)
    return Number - 1;
  return -1;
}

} // namespace

// ============================================================
// Settings
// ============================================================

class SettingsPage final : public TuiPage {
public:
  explicit SettingsPage(int Index) : Index_(Index) {
    OwnedCommands = {
        {"refresh", "refresh  (reload configuration values)",
         [this](std::vector<std::string>) { Refresh(); }},
        {"language", "language <en_US|zh_CN>  (interface language)",
         [this](std::vector<std::string> Args) {
           if (Args.empty()) {
             Notify("Usage: language <en_US|zh_CN>", NoticeKind::Warning);
             return;
           }
           ApplyLanguage(MiscFromUtf8(Args.front()));
         }},
        {"theme", "theme <default_blue|cyan|indigo|graphite>  (apply preset)",
         [this](std::vector<std::string> Args) { CommandTheme(Args); }},
        {"color", "color <Key> <#RRGGBB>  (one of the 18 theme colors)",
         [this](std::vector<std::string> Args) { CommandColor(Args); }},
        {"set", "set <Section>.<Key> <value>  (raw configuration write)",
         [this](std::vector<std::string> Args) { CommandSet(Args); }},
        {"toggle-console", "toggle-console  (show or hide the console window)",
         [this](std::vector<std::string>) {
           SetConsoleVisible(!ConfigurationValue("Application",
                                                 "ConsoleVisible", false)
                                  .toBool());
         }},
        {"restore-theme", "restore-theme  (reset theme colors to defaults)",
         [this](std::vector<std::string>) { RestoreDefaultColors(); }},
        {"check-update", "check-update  (query the update server)",
         [this](std::vector<std::string>) { CheckForUpdates(); }},
        {"update", "update  (download and install the newest release)",
         [this](std::vector<std::string>) { BeginUpdate(); }},
    };
  }

  std::string Title() const override { return "Settings"; }

  std::string Subtitle() const override {
    return "language, theme, module paths, console and software update";
  }

  void OnEnter() override {
    ConsoleOnly_ = MiscConsoleOnlyProcess();
    BuildRows();
    if (ConsoleOnly_)
      Notify("The console is already the active front-end.", NoticeKind::Info);
  }

  TuiTable *ActiveTable() override { return &Table_; }

  std::string RenderText() override {
    // `filter` 命令把条件写进 Filter：这里按组名/标题/描述/当前值过滤。
    RowFilter_ = Filter;
    BuildRows();
    std::string Text = TuiTableToText(Table_, 200);
    return Text;
  }

private:
  struct SettingRow {
    std::string Group;
    std::string Title;
    std::string Description;
    std::function<std::string()> Value;
    std::function<void()> Edit; // 空 = 只读
  };

  // ----------------------------------------------------------
  // 行构建
  // ----------------------------------------------------------

  void Row(std::string Title, std::string Description,
           std::function<std::string()> Value, std::function<void()> Edit) {
    SettingRow Entry;
    Entry.Group = CurrentGroup_;
    Entry.Title = std::move(Title);
    Entry.Description = std::move(Description);
    Entry.Value = std::move(Value);
    Entry.Edit = std::move(Edit);
    Rows_.push_back(std::move(Entry));
  }

  void Group(const char *Name) { CurrentGroup_ = Name; }

  void AddColorRow(const char *Key, const char *Title, const char *Description,
                   QColor ThemePalette::*Member) {
    const QString KeyText = QString::fromLatin1(Key);
    auto Fallback = [Member]() -> QColor {
      const ThemePalette Palette = CurrentThemePalette();
      return Palette.*Member;
    };
    Row(Title, Description,
        [KeyText, Fallback]() {
          return MiscHexColorText(ConfiguredColor(KeyText, Fallback()));
        },
        [this, KeyText, Title, Fallback]() {
          PushColorDialog(KeyText, Title,
                          ConfiguredColor(KeyText, Fallback()));
        });
  }

  void AddIntRow(const char *Key, const char *Title, const char *Description,
                 int Minimum, int Maximum, int DefaultValue,
                 const char *Suffix) {
    const QString KeyText = QString::fromLatin1(Key);
    Row(Title, std::string(Description) + "  (" + Suffix + ")",
        [KeyText, DefaultValue, Minimum, Maximum, Suffix]() {
          const int Value = std::clamp(
              ConfigurationValue("Theme", KeyText, DefaultValue).toInt(),
              Minimum, Maximum);
          return std::to_string(Value) + Suffix;
        },
        [this, KeyText, Title, Minimum, Maximum, DefaultValue]() {
          const int Value = std::clamp(
              ConfigurationValue("Theme", KeyText, DefaultValue).toInt(),
              Minimum, Maximum);
          MiscPushForm(
              Dialogs, Title,
              {MiscFieldSpec{KeyText.toStdString(), TuiFieldKind::Int,
                         std::to_string(Value), {},
                         "Range " + std::to_string(Minimum) + ".." +
                             std::to_string(Maximum),
                         [Minimum, Maximum](const std::string &Text) -> std::string {
                           bool Ok = false;
                           const int Parsed = MiscFromUtf8(Text).trimmed().toInt(&Ok);
                           if (!Ok || Parsed < Minimum || Parsed > Maximum)
                             return "Enter a number between " +
                                    std::to_string(Minimum) + " and " +
                                    std::to_string(Maximum) + ".";
                           return std::string();
                         }}},
              [this, KeyText](const std::vector<std::string> &Values) {
                bool Ok = false;
                const int Picked = MiscFromUtf8(Values.at(0)).trimmed().toInt(&Ok);
                if (!Ok)
                  return;
                SetConfigurationValueTransient("Theme", KeyText, Picked);
                SaveConfiguration();
                MarkMutated();
                NotifyStatus("Theme updated.");
              });
        });
  }

  // 布尔行：确认框翻转。Write 返回非空字符串表示失败（照原样作为 Warning）。
  void AddToggleRow(const char *Title, const char *Description,
                    std::function<bool()> Read,
                    std::function<std::string(bool)> Write,
                    std::function<std::string(bool)> SuccessText) {
    Row(Title, Description,
        [Read]() { return Read() ? std::string("On") : std::string("Off"); },
        [this, Title, Read, Write, SuccessText]() {
          const bool Enabled = Read();
          MiscPushConfirm(Dialogs, Title,
                      Enabled ? "Disable this option?" : "Enable this option?",
                      [this, Write, SuccessText, Enabled]() {
                        const std::string Error = Write(!Enabled);
                        if (!Error.empty()) {
                          Notify(Error, NoticeKind::Warning);
                        } else {
                          Notify(SuccessText(!Enabled), NoticeKind::Success);
                        }
                        RefreshStatus();
                      });
        });
  }

  void BuildRows() {
    Rows_.clear();

    // ---- Language ----
    Group("Language");
    Row("Display language",
        "Choose the language used by the application interface.",
        [] {
          return ConfigurationValue("Application", "Language", "en_US")
                         .toString() == "zh_CN"
                     ? std::string("Chinese")
                     : std::string("English");
        },
        [this]() {
          const int Current =
              ConfigurationValue("Application", "Language", "en_US")
                          .toString() == "zh_CN"
                  ? 1
                  : 0;
          static const char *const Labels[] = {"English", "Chinese"};
          static const char *const Ids[] = {"en_US", "zh_CN"};
          MiscPushForm(
              Dialogs, "Display language",
              {MiscFieldSpec{"Language",
                         TuiFieldKind::Text,
                         Labels[Current],
                         "English / Chinese",
                         "Values: English, Chinese (or en_US, zh_CN)",
                         [](const std::string &Text) -> std::string {
                           if (MiscMatchChoice(Text, Labels, Ids, 2) < 0)
                             return "Choose English or Chinese.";
                           return std::string();
                         }}},
              [this](const std::vector<std::string> &Values) {
                const int Picked =
                    MiscMatchChoice(Values.at(0), Labels, Ids, 2);
                if (Picked < 0)
                  return;
                ApplyLanguage(QString::fromLatin1(Ids[Picked]));
              });
        });

    // ---- Theme ----
    Group("Theme");
    AddToggleRow(
        "Dark mode", "Switch between the light and dark QFluent themes.",
        [] {
          return ConfigurationValue("Theme", "DarkMode", KDefaultThemeDarkMode)
              .toBool();
        },
        [](bool Enabled) {
          QJsonObject ThemeObject = ConfigurationSection("Theme");
          SyncThemeDefaultsForMode(ThemeObject, Enabled);
          Configuration.insert("Theme", ThemeObject);
          SaveConfiguration();
          MarkMutated();
          return std::string();
        },
        [](bool Enabled) {
          return Enabled ? std::string("Dark mode enabled.")
                         : std::string("Light mode enabled.");
        });

    Row("Preset theme", "Apply a predefined color theme.",
        [] {
          QString Id = NormalizeThemePresetId(
              ConfigurationValue("Theme", "Preset", KDefaultThemePreset)
                  .toString());
          if (Id.isEmpty())
            Id = QString::fromLatin1(KDefaultThemePreset);
          return std::string(MiscKPresetLabels[MiscPresetIndexForId(Id)]);
        },
        [this]() {
          QString Id = NormalizeThemePresetId(
              ConfigurationValue("Theme", "Preset", KDefaultThemePreset)
                  .toString());
          if (Id.isEmpty())
            Id = QString::fromLatin1(KDefaultThemePreset);
          MiscPushForm(
              Dialogs, "Preset theme",
              {MiscFieldSpec{"Preset",
                         TuiFieldKind::Text,
                         MiscKPresetLabels[MiscPresetIndexForId(Id)],
                         "Default Blue / Cyan / Indigo / Graphite",
                         "Values: Default Blue, Cyan, Indigo, Graphite",
                         [](const std::string &Text) -> std::string {
                           if (MiscMatchChoice(Text, MiscKPresetLabels, MiscKPresetIds, 4) <
                               0)
                             return "Choose a preset theme name.";
                           return std::string();
                         }}},
              [this](const std::vector<std::string> &Values) {
                const int Picked =
                    MiscMatchChoice(Values.at(0), MiscKPresetLabels, MiscKPresetIds, 4);
                if (Picked < 0)
                  return;
                QJsonObject ThemeObject = ConfigurationSection("Theme");
                ApplyThemePreset(
                    ThemeObject, QString::fromLatin1(MiscKPresetIds[Picked]),
                    ConfigurationValue("Theme", "DarkMode",
                                       KDefaultThemeDarkMode)
                        .toBool());
                Configuration.insert("Theme", ThemeObject);
                SaveConfiguration();
                MarkMutated();
                NotifyStatus("Theme preset applied.");
              });
        });

    Row("Background material",
        "Use the Windows Mica or Acrylic backdrop behind the theme.",
        [] {
          static const char *const Names[] = {"Off", "Mica", "Acrylic"};
          const int Index =
              std::clamp(ConfigurationValue("Theme", "BackgroundMaterial",
                                            KDefaultThemeBackgroundMaterial)
                             .toInt(),
                         0, 2);
          return std::string(Names[Index]);
        },
        [this]() {
          static const char *const Names[] = {"Off", "Mica", "Acrylic"};
          const int Index =
              std::clamp(ConfigurationValue("Theme", "BackgroundMaterial",
                                            KDefaultThemeBackgroundMaterial)
                             .toInt(),
                         0, 2);
          MiscPushForm(
              Dialogs, "Background material",
              {MiscFieldSpec{"Material", TuiFieldKind::Text, Names[Index],
                         "Off / Mica / Acrylic", "Values: Off, Mica, Acrylic",
                         [](const std::string &Text) -> std::string {
                           if (MiscMatchChoice(Text, Names, nullptr, 3) < 0)
                             return "Choose Off, Mica or Acrylic.";
                           return std::string();
                         }}},
              [this](const std::vector<std::string> &Values) {
                const int Picked =
                    MiscMatchChoice(Values.at(0), Names, nullptr, 3);
                if (Picked < 0)
                  return;
                SetConfigurationValueTransient("Theme", "BackgroundMaterial",
                                               Picked);
                SaveConfiguration();
                MarkMutated();
                NotifyStatus("Background material updated.");
              });
        });

    Row("Wallpaper",
        "Display a local image behind the window background and panels.",
        [] {
          const QString Path =
              ConfigurationValue("Theme", "WallpaperPath", "").toString();
          return Path.isEmpty() ? std::string("No wallpaper selected")
                                : MiscUtf8(QDir::toNativeSeparators(Path));
        },
        [this]() {
          MiscPushForm(
              Dialogs, "Select wallpaper",
              {MiscFieldSpec{"Path", TuiFieldKind::Text,
                         MiscUtf8(ConfigurationValue("Theme", "WallpaperPath", "")
                                  .toString()),
                         "C:\\path\\to\\image.png",
                         "Leave empty to clear the wallpaper."}},
              [this](const std::vector<std::string> &Values) {
                SetConfigurationValueTransient(
                    "Theme", "WallpaperPath", MiscFromUtf8(TrimAscii(Values.at(0))));
                SaveConfiguration();
                MarkMutated();
                NotifyStatus("Wallpaper updated.");
              });
        });

    Row("Wallpaper mode",
        "Choose how the image is fitted to the application window.",
        [] {
          static const char *const Names[] = {"Fill", "Fit", "Stretch", "Tile"};
          const int Index = std::clamp(
              ConfigurationValue("Theme", "WallpaperMode", 0).toInt(), 0, 3);
          return std::string(Names[Index]);
        },
        [this]() {
          static const char *const Names[] = {"Fill", "Fit", "Stretch", "Tile"};
          const int Index = std::clamp(
              ConfigurationValue("Theme", "WallpaperMode", 0).toInt(), 0, 3);
          MiscPushForm(
              Dialogs, "Wallpaper mode",
              {MiscFieldSpec{"Mode", TuiFieldKind::Text, Names[Index],
                         "Fill / Fit / Stretch / Tile",
                         "Values: Fill, Fit, Stretch, Tile",
                         [](const std::string &Text) -> std::string {
                           if (MiscMatchChoice(Text, Names, nullptr, 4) < 0)
                             return "Choose Fill, Fit, Stretch or Tile.";
                           return std::string();
                         }}},
              [this](const std::vector<std::string> &Values) {
                const int Picked =
                    MiscMatchChoice(Values.at(0), Names, nullptr, 4);
                if (Picked < 0)
                  return;
                SetConfigurationValueTransient("Theme", "WallpaperMode", Picked);
                SaveConfiguration();
                MarkMutated();
                NotifyStatus("Wallpaper mode updated.");
              });
        });

    Group("Brand colors");
    AddColorRow("AccentColor", "Accent",
                "Primary brand color for selected navigation and main actions.",
                &ThemePalette::Accent);
    AddColorRow("AccentHoverColor", "Accent hover",
                "Hover state for primary interactive elements.",
                &ThemePalette::AccentHover);
    AddColorRow("AccentPressedColor", "Accent pressed",
                "Pressed state for primary interactive elements.",
                &ThemePalette::AccentPressed);

    Group("Background layers");
    AddColorRow("PageBackgroundColor", "Page background",
                "Window content background under panels.",
                &ThemePalette::PageBackground);
    AddColorRow("CardSurfaceColor", "Card background",
                "Primary card and panel surface.", &ThemePalette::CardSurface);
    AddColorRow("SurfaceElevatedColor", "Elevated surface",
                "Dialogs, previews, and higher-level panels.",
                &ThemePalette::ElevatedSurface);
    AddColorRow("SurfaceSunkenColor", "Sunken surface",
                "Header, separators, and recessed layers.",
                &ThemePalette::SunkenSurface);
    AddColorRow("InputSurfaceColor", "Input background",
                "Line edit, combo, and editor backgrounds.",
                &ThemePalette::InputSurface);
    AddColorRow("TableSurfaceColor", "Table background",
                "List and table rows without wallpaper bleed.",
                &ThemePalette::TableSurface);
    AddColorRow("PopupSurfaceColor", "Popup background",
                "Menu, preview, and floating surface background.",
                &ThemePalette::PopupSurface);
    AddColorRow("BorderColor", "Border",
                "Primary outline for cards and controls.",
                &ThemePalette::Border);
    AddColorRow("DividerColor", "Divider",
                "Subtle separators and table grid lines.",
                &ThemePalette::Divider);

    Group("Text layers");
    AddColorRow("TextColor", "Primary text",
                "Main labels, values, and control text.", &ThemePalette::Text);
    AddColorRow("MutedTextColor", "Secondary text",
                "Descriptions, status text, and placeholders.",
                &ThemePalette::MutedText);
    AddColorRow("SelectionTextColor", "Selected text",
                "Text color shown over accent selections.",
                &ThemePalette::SelectionText);

    Group("Feedback colors");
    AddColorRow("DangerColor", "Danger",
                "Destructive operations and alert states.",
                &ThemePalette::Danger);
    AddColorRow("WarningColor", "Warning",
                "Caution states and degraded status.", &ThemePalette::Warning);
    AddColorRow("SuccessColor", "Success",
                "Healthy state and successful actions.", &ThemePalette::Success);

    Group("Theme metrics");
    AddIntRow("CornerRadius", "Corner radius",
              "Roundness of panels and setting rows.", 0, 12,
              KDefaultThemeCornerRadius, " px");
    AddIntRow("FontScale", "Font scale",
              "Scale application text without changing window dimensions.", 85,
              125, KDefaultThemeFontScale, "%");
    AddIntRow("Density", "Interface density",
              "Adjust menu and table header spacing.", 80, 120,
              KDefaultThemeDensity, "%");
    AddIntRow("WallpaperOpacity", "Wallpaper opacity",
              "Control wallpaper visibility behind panels and content.", 5, 100,
              KDefaultThemeWallpaperOpacity, "%");

    Row("Restore defaults", "Reset theme mode and all custom colors.",
        [] { return std::string("Restore default theme"); },
        [this]() {
          MiscPushConfirm(Dialogs, "Restore defaults",
                      "Reset theme mode and all custom colors?",
                      [this]() { RestoreDefaultColors(); });
        });

    // ---- Module paths ----
    Group("Module paths");
    Row("Modules", "Select the DLL module directory.",
        [] {
          return MiscUtf8(ConfigurationPaths("Modules", "./Modules").join("; "));
        },
        [this]() {
          MiscPushForm(
              Dialogs, "Select module directory",
              {MiscFieldSpec{"Directory", TuiFieldKind::Text,
                         MiscUtf8(ConfigurationPaths("Modules", "./Modules").first())}},
              [this](const std::vector<std::string> &Values) {
                const std::string Path = TrimAscii(Values.at(0));
                if (Path.empty()) {
                  Notify("The folder does not exist or cannot be accessed.",
                         NoticeKind::Error);
                  return;
                }
                SetConfigurationPath("Modules",
                                     QDir::toNativeSeparators(MiscFromUtf8(Path)));
                MarkMutated();
                Notify("Module path updated.", NoticeKind::Success);
                RefreshStatus();
              });
        });

    AddToggleRow(
        "Load modules after scan",
        "Automatically enable discovered DLL modules.",
        [] { return ConfigurationValue("Modules", "AutoLoad", true).toBool(); },
        [](bool Enabled) {
          SetConfigurationValue("Modules", "AutoLoad", Enabled);
          MarkMutated();
          return std::string();
        },
        [](bool Enabled) {
          return Enabled ? std::string("Module auto-load enabled.")
                         : std::string("Module auto-load disabled.");
        });

    Row("Drivers", "Select the kernel driver directory.",
        [] {
          return MiscUtf8(ConfigurationPaths("Drivers", "./Drivers").join("; "));
        },
        [this]() {
          MiscPushForm(
              Dialogs, "Select driver directory",
              {MiscFieldSpec{"Directory", TuiFieldKind::Text,
                         MiscUtf8(ConfigurationPaths("Drivers", "./Drivers")
                                  .first())}},
              [this](const std::vector<std::string> &Values) {
                const std::string Path = TrimAscii(Values.at(0));
                if (Path.empty()) {
                  Notify("The folder does not exist or cannot be accessed.",
                         NoticeKind::Error);
                  return;
                }
                SetConfigurationPath("Drivers",
                                     QDir::toNativeSeparators(MiscFromUtf8(Path)));
                MarkMutated();
                Notify("Driver path updated.", NoticeKind::Success);
                RefreshStatus();
              });
        });

    AddToggleRow(
        "Load drivers after scan",
        "Automatically enable discovered kernel drivers.",
        [] { return ConfigurationValue("Drivers", "AutoLoad", true).toBool(); },
        [](bool Enabled) {
          SetConfigurationValue("Drivers", "AutoLoad", Enabled);
          MarkMutated();
          return std::string();
        },
        [](bool Enabled) {
          return Enabled ? std::string("Driver auto-load enabled.")
                         : std::string("Driver auto-load disabled.");
        });

    // ---- Application ----
    Group("Application");
    Row("Window size", "Configured startup dimensions.",
        [] {
          return std::to_string(
                     ConfigurationValue("Application", "Width", 1600).toInt()) +
                 " x " +
                 std::to_string(
                     ConfigurationValue("Application", "Height", 1000).toInt());
        },
        nullptr);
    Row("Frame rate", "Configured rendering frame rate.",
        [] {
          const int Fps = static_cast<int>(
              ConfigurationValue("Application", "FPS", 90.0).toDouble() + 0.5);
          return std::to_string(Fps) + " FPS";
        },
        nullptr);

    Row("Toggle window hotkey",
        "Global shortcut that shows or hides the window. Only takes effect in "
        "windowed mode.",
        [] {
          const QString Sequence =
              ConfigurationValue("Application", "HotkeyToggle", "").toString();
          return Sequence.isEmpty() ? std::string("(none)") : MiscUtf8(Sequence);
        },
        [this]() {
          MiscPushForm(
              Dialogs, "Toggle window hotkey",
              {MiscFieldSpec{"Shortcut", TuiFieldKind::Text,
                         MiscUtf8(ConfigurationValue("Application", "HotkeyToggle",
                                                 "")
                                  .toString()),
                         "Ctrl+Alt+A",
                         "Portable text. Requires at least one modifier. Leave "
                         "empty to clear."}},
              [this](const std::vector<std::string> &Values) {
                const QString Sequence = MiscFromUtf8(TrimAscii(Values.at(0)));
                SetConfigurationValue("Application", "HotkeyToggle", Sequence);
                const QString Error = ApplyRuntimeHotkeyConfiguration();
                if (!Error.isEmpty()) {
                  Notify(MiscUtf8(Error), NoticeKind::Warning);
                  return;
                }
                Notify(Sequence.isEmpty()
                           ? std::string("Toggle hotkey cleared.")
                           : MiscUtf8(QString("Toggle hotkey set to %1.")
                                      .arg(Sequence)),
                       NoticeKind::Success);
                RefreshStatus();
              });
        });

    AddToggleRow(
        "Enable toggle hotkey",
        "Register the shortcut above as a system-wide hotkey.",
        [] { return IsToggleHotkeyEnabled(); },
        [](bool Enabled) {
          SetConfigurationValue("Application", "HotkeyToggleEnabled", Enabled);
          MarkMutated();
          // GUI 模式下由主窗口重新注册；控制台里重新注册通常返回
          // "The main window is not ready to register a hotkey."，按要求
          // 以 Warning 呈现（配置本身已正确落盘）。
          return MiscUtf8(ApplyRuntimeHotkeyConfiguration());
        },
        [](bool Enabled) {
          return Enabled ? std::string("Toggle hotkey enabled.")
                         : std::string("Toggle hotkey disabled.");
        });

    Row("Window opacity",
        "Adjust the current window transparency from 35% to 100%.",
        [] {
          const int Percent = static_cast<int>(
              ConfigurationValue("Application", "Opacity", 1.0).toDouble() *
                  100.0 +
              0.5);
          return std::to_string(std::clamp(Percent, 35, 100)) + "%";
        },
        [this]() {
          const int Percent = std::clamp(
              static_cast<int>(
                  ConfigurationValue("Application", "Opacity", 1.0)
                          .toDouble() *
                      100.0 +
                  0.5),
              35, 100);
          MiscPushForm(
              Dialogs, "Window opacity",
              {MiscFieldSpec{"Opacity", TuiFieldKind::Int,
                         std::to_string(Percent), {},
                         "Range 35..100 (percent)",
                         [](const std::string &Text) -> std::string {
                           bool Ok = false;
                           const int Parsed = MiscFromUtf8(Text).trimmed().toInt(&Ok);
                           if (!Ok || Parsed < 35 || Parsed > 100)
                             return "Enter a number between 35 and 100.";
                           return std::string();
                         }}},
              [this](const std::vector<std::string> &Values) {
                bool Ok = false;
                const int Picked = MiscFromUtf8(Values.at(0)).trimmed().toInt(&Ok);
                if (!Ok)
                  return;
                SetConfigurationValueTransient("Application", "Opacity",
                                               Picked / 100.0);
                SaveConfiguration();
                MarkMutated();
                NotifyStatus("Window opacity updated.");
              });
        });

    // ---- Console（本次新增）----
    Group("Console");
    // --console 独占模式下没有窗口可显隐：行保持只读。
    ConsoleEdit_ = ConsoleOnly_
                       ? std::function<void()>()
                       : std::function<void()>([this]() {
                           SetConsoleVisible(
                               !ConfigurationValue("Application",
                                                   "ConsoleVisible", false)
                                    .toBool());
                         });
    Row("Show console window",
        ConsoleOnly_ ? "The console is already the active front-end."
                     : "Show the built-in console window for this process.",
        [] {
          return ConfigurationValue("Application", "ConsoleVisible", false)
                         .toBool()
                     ? std::string("On")
                     : std::string("Off");
        },
        ConsoleEdit_);

    // ---- About ----
    Group("About");
    Row("Version", "Current AegisNT release.",
        [] { return MiscUtf8(KApplicationVersion); }, nullptr);
    Row("Author", "Application author.",
        [] { return std::string("RegistryEdit"); }, nullptr);
    Row("Cloud version", "Latest release available on the update server.",
        [this]() {
          return CloudVersion_.empty() ? std::string("-") : CloudVersion_;
        },
        nullptr);

    // ---- Software update ----
    Group("Software update");
    Row("Check for updates", "Query the update server for the newest release.",
        [] { return std::string("CheckUpdate"); },
        [this]() { CheckForUpdates(); });
    Row("Install update",
        "Download and restart AegisNT with the newest release.",
        [this]() {
          return UpdateAvailable_ ? std::string("Update")
                                  : std::string("Check for updates first");
        },
        [this]() { BeginUpdate(); });

    RebuildView();
    RefreshStatus();
  }

  // ----------------------------------------------------------
  // 写配置的动作
  // ----------------------------------------------------------

  void ApplyLanguage(const QString &Code) {
    const QString LanguageCode =
        LanguageResources.contains(Code) ? Code : QStringLiteral("en_US");
    SetConfigurationValue("Application", "Language", LanguageCode);
    // 不能调用 ApplyApplicationLanguage（它遍历 QApplication 顶层窗口），
    // 这里只做它真正产生的状态变更。
    ActiveLanguage = LanguageCode;
    MarkMutated();
    Notify("Display language updated.", NoticeKind::Success);
    RefreshStatus();
  }

  void PushColorDialog(const QString &Key, const std::string &Title,
                       const QColor &Current) {
    MiscPushForm(
        Dialogs, std::string("Select ") + Title,
        {MiscFieldSpec{"Color", TuiFieldKind::Text, MiscHexColorText(Current),
                   "#RRGGBB", "Format: #RRGGBB",
                   [](const std::string &Value) -> std::string {
                     QColor Parsed;
                     if (!MiscParseHexColor(Value, &Parsed))
                       return "Enter a color as #RRGGBB.";
                     return std::string();
                   }}},
        [this, Key](const std::vector<std::string> &Values) {
          QColor Parsed;
          if (!MiscParseHexColor(Values.at(0), &Parsed))
            return;
          QJsonObject ThemeObject = ConfigurationSection("Theme");
          ThemeObject.insert(Key, MiscFromUtf8(MiscHexColorText(Parsed)));
          ThemeObject.insert("Preset", QString::fromLatin1(KCustomThemePreset));
          Configuration.insert("Theme", ThemeObject);
          SaveConfiguration();
          MarkMutated();
          Notify("Theme color updated.", NoticeKind::Success);
          RefreshStatus();
        });
  }

  void RestoreDefaultColors() {
    QJsonObject ThemeObject = ConfigurationSection("Theme");
    ApplyDefaultThemeValues(ThemeObject,
                            ConfigurationValue("Theme", "DarkMode",
                                               KDefaultThemeDarkMode)
                                .toBool());
    ThemeObject.insert("WallpaperPath", "");
    ThemeObject.insert("WallpaperMode", 0);
    Configuration.insert("Theme", ThemeObject);
    SaveConfiguration();
    MarkMutated();
    Notify("Default theme restored.", NoticeKind::Success);
    RefreshStatus();
  }

  void SetConsoleVisible(bool Visible) {
    SetConfigurationValue("Application", "ConsoleVisible", Visible);
    MarkMutated();
    if (G_ConsoleVisibilityApplier) {
      G_ConsoleVisibilityApplier();
      Notify(Visible ? "Console shown." : "Console hidden.",
             NoticeKind::Success);
    } else {
      Notify("The main window is not ready.", NoticeKind::Warning);
    }
    RefreshStatus();
  }

  // ----------------------------------------------------------
  // 更新流程（消息字符串与 GUI 一致）
  // ----------------------------------------------------------

  void CheckForUpdates() {
    if (CheckingUpdate_) {
      Notify("Already refreshing, please wait.", NoticeKind::Info);
      return;
    }
    CheckingUpdate_ = true;
    CheckSucceeded_ = false;
    UpdateAvailable_ = false;
    CloudVersion_.clear();
    SetStatus("Settings | checking for updates...");
    TuiAsync<QJsonObject>(
        [] {
          QJsonObject Response;
          QString Error;
          const bool Ok = HttpGetJson(QStringLiteral("/GetLatestVersion"),
                                      QString(), 15000, &Response, &Error);
          QJsonObject Result;
          Result.insert("ok", Ok);
          Result.insert("error", Error);
          Result.insert("response", Response);
          return Result;
        },
        [this](QJsonObject Result) {
          CheckingUpdate_ = false;
          if (!Result.value("ok").toBool()) {
            Notify(MiscUtf8(QString("Failed to query the update server: %1")
                            .arg(Result.value("error").toString())),
                   NoticeKind::Error);
            RefreshStatus();
            return;
          }
          const QJsonObject Response = Result.value("response").toObject();
          if (!Response.value("success").toBool() ||
              !Response.value("data").isObject()) {
            Notify(MiscUtf8(Response.value("message")
                            .toString(QStringLiteral("Invalid response."))),
                   NoticeKind::Error);
            RefreshStatus();
            return;
          }
          const QJsonObject UpdateData = Response.value("data").toObject();
          const QString CloudVersion =
              UpdateData.value("version").toString().trimmed();
          QString DownloadText =
              UpdateData.value("DownloadURL").toString().trimmed();
          if (DownloadText.isEmpty())
            DownloadText =
                UpdateData.value("downloadUrl").toString().trimmed();
          if (CloudVersion.isEmpty()) {
            Notify("The update server returned an empty version.",
                   NoticeKind::Error);
            RefreshStatus();
            return;
          }
          if (DownloadText.isEmpty()) {
            Notify("The update server returned no download address.",
                   NoticeKind::Error);
            RefreshStatus();
            return;
          }
          QUrl DownloadUrl(DownloadText);
          if (DownloadUrl.isRelative())
            DownloadUrl = QUrl(AuthServerAddress()).resolved(DownloadUrl);
          const QString Scheme = DownloadUrl.scheme().toLower();
          if (!DownloadUrl.isValid() || DownloadUrl.host().isEmpty() ||
              (Scheme != QLatin1String("http") &&
               Scheme != QLatin1String("https"))) {
            Notify("The update server returned an invalid download address.",
                   NoticeKind::Error);
            RefreshStatus();
            return;
          }
          CloudVersion_ = MiscUtf8(CloudVersion);
          DownloadUrl_ = DownloadUrl;
          const QVersionNumber Local =
              QVersionNumber::fromString(KApplicationVersion);
          const QVersionNumber Cloud = QVersionNumber::fromString(CloudVersion);
          UpdateAvailable_ = Cloud > Local && Cloud > QVersionNumber{};
          CheckSucceeded_ = true;
          if (UpdateAvailable_)
            Notify(MiscUtf8(QString("A new version %1 is available.")
                            .arg(CloudVersion)),
                   NoticeKind::Warning);
          else
            Notify("You are running the latest version.", NoticeKind::Success);
          RefreshStatus();
        });
  }

  void BeginUpdate() {
    if (!CheckSucceeded_) {
      Notify("Check for updates first.", NoticeKind::Warning);
      return;
    }
    if (!UpdateAvailable_) {
      Notify("You are running the latest version.", NoticeKind::Success);
      return;
    }
    MiscPushConfirm(Dialogs, "Update",
                MiscUtf8(QString("Version %1 is available. Download and restart "
                             "AegisNT now?")
                         .arg(MiscFromUtf8(CloudVersion_))),
                [this]() { StartDownload(); });
  }

  void StartDownload() {
    if (!DownloadUrl_.isValid()) {
      Notify("No valid download address is available. Check for updates again.",
             NoticeKind::Error);
      return;
    }
    const QString ArchivePath =
        QDir(QStandardPaths::writableLocation(QStandardPaths::TempLocation))
            .filePath("AegisNT.update.zip");
    QFile::remove(ArchivePath);
    SetStatus("Settings | downloading update...");
    const QUrl Url = DownloadUrl_;
    TuiAsync<QJsonObject>(
        [Url, ArchivePath] {
          QJsonObject Result;
          QNetworkAccessManager Manager;
          QNetworkRequest Request(Url);
          Request.setTransferTimeout(120000);
          QNetworkReply *Reply = Manager.get(Request);
          QEventLoop Loop;
          QObject::connect(Reply, &QNetworkReply::finished, &Loop,
                           &QEventLoop::quit);
          Loop.exec();
          if (Reply->error() != QNetworkReply::NoError) {
            Result.insert("downloaded", false);
            Reply->deleteLater();
            return Result;
          }
          const QByteArray Data = Reply->readAll();
          Reply->deleteLater();
          QSaveFile File(ArchivePath);
          const bool Saved = File.open(QIODevice::WriteOnly) &&
                             File.write(Data) == Data.size() && File.commit();
          Result.insert("downloaded", Saved);
          return Result;
        },
        [this, ArchivePath](QJsonObject Result) {
          if (!Result.value("downloaded").toBool()) {
            Notify("Failed to save the downloaded package.",
                   NoticeKind::Error);
            RefreshStatus();
            return;
          }
          LaunchUpdater(ArchivePath);
        });
  }

  void LaunchUpdater(const QString &UpdateArchive) {
    const QString TempPath =
        QStandardPaths::writableLocation(QStandardPaths::TempLocation);
    const QString Executable = QCoreApplication::applicationFilePath();
    const QString ExecutableName = QFileInfo(Executable).fileName();
    const QString BatchPath = QDir(TempPath).filePath("AegisNT_updater.bat");
    const QString ExtractDirectory = QDir(TempPath).filePath("AegisNT_update");
    const QString DriverDirectory =
        QFileInfo(Executable).dir().filePath("Drivers");
    QString Batch;
    QTextStream Stream(&Batch);
    Stream << "@echo off\r\n";
    Stream << "setlocal\r\n";
    Stream << "set \"ARCHIVE=" << UpdateArchive << "\"\r\n";
    Stream << "set \"EXTRACT_DIR=" << ExtractDirectory << "\"\r\n";
    Stream << "set \"EXECUTABLE=" << Executable << "\"\r\n";
    Stream << "set \"EXECUTABLE_NAME=" << ExecutableName << "\"\r\n";
    Stream << "set \"DRIVER_DIR=" << DriverDirectory << "\"\r\n";
    Stream << "set \"APP_STOPPED=0\"\r\n";
    Stream << "ping 127.0.0.1 -n 4 > nul\r\n";
    Stream << "powershell.exe -NoProfile -NonInteractive "
              "-ExecutionPolicy Bypass -Command \""
              "$ErrorActionPreference='Stop'; "
              "if (Test-Path -LiteralPath $env:EXTRACT_DIR) "
              "{ Remove-Item -LiteralPath $env:EXTRACT_DIR -Recurse -Force }; "
              "Expand-Archive -LiteralPath $env:ARCHIVE "
              "-DestinationPath $env:EXTRACT_DIR -Force\"\r\n";
    Stream << "if errorlevel 1 goto :update_failed\r\n";
    Stream << "if not exist \"%EXTRACT_DIR%\\AegisNT.exe\" "
              "goto :update_failed\r\n";
    Stream << "if not exist \"%EXTRACT_DIR%\\*.sys\" "
              "if not exist \"%EXTRACT_DIR%\\Drivers\\*.sys\" "
              "goto :update_failed\r\n";
    Stream << "taskkill /f /im \"%EXECUTABLE_NAME%\" > nul 2>&1\r\n";
    Stream << "set \"APP_STOPPED=1\"\r\n";
    Stream << "for %%D in (\"%EXTRACT_DIR%\\*.sys\") "
              "do sc.exe stop \"%%~nD\" > nul 2>&1\r\n";
    Stream << "for %%D in (\"%EXTRACT_DIR%\\Drivers\\*.sys\") "
              "do sc.exe stop \"%%~nD\" > nul 2>&1\r\n";
    Stream << "ping 127.0.0.1 -n 3 > nul\r\n";
    Stream << "copy /Y \"%EXTRACT_DIR%\\AegisNT.exe\" "
              "\"%EXECUTABLE%\" > nul\r\n";
    Stream << "if errorlevel 1 goto :update_failed\r\n";
    Stream << "if not exist \"%DRIVER_DIR%\" mkdir \"%DRIVER_DIR%\"\r\n";
    Stream << "powershell.exe -NoProfile -NonInteractive "
              "-ExecutionPolicy Bypass -Command \""
              "$ErrorActionPreference='Stop'; "
              "$drivers=@(Get-ChildItem -LiteralPath "
              "$env:EXTRACT_DIR -Filter '*.sys' -File); "
              "$nested=Join-Path $env:EXTRACT_DIR 'Drivers'; "
              "if (Test-Path -LiteralPath $nested) "
              "{ $drivers += @(Get-ChildItem -LiteralPath $nested "
              "-Filter '*.sys' -File) }; "
              "if ($drivers.Count -eq 0) { throw 'No drivers' }; "
              "foreach ($driver in $drivers) "
              "{ Copy-Item -LiteralPath $driver.FullName "
              "-Destination $env:DRIVER_DIR -Force }\"\r\n";
    Stream << "if errorlevel 1 goto :update_failed\r\n";
    Stream << "rmdir /s /q \"%EXTRACT_DIR%\" > nul 2>&1\r\n";
    Stream << "del /q \"%ARCHIVE%\" > nul 2>&1\r\n";
    Stream << "start \"\" \"%EXECUTABLE%\"\r\n";
    Stream << "goto :cleanup\r\n";
    Stream << ":update_failed\r\n";
    Stream << "rmdir /s /q \"%EXTRACT_DIR%\" > nul 2>&1\r\n";
    Stream << "del /q \"%ARCHIVE%\" > nul 2>&1\r\n";
    Stream << "if \"%APP_STOPPED%\"==\"1\" start \"\" "
              "\"%EXECUTABLE%\"\r\n";
    Stream << ":cleanup\r\n";
    Stream << "del \"%~f0\"\r\n";

    QFile BatchFile(BatchPath);
    const QByteArray BatchData = Batch.toLocal8Bit();
    if (!BatchFile.open(QIODevice::WriteOnly) ||
        BatchFile.write(BatchData) != BatchData.size()) {
      Notify("Failed to prepare the updater script.", NoticeKind::Error);
      RefreshStatus();
      return;
    }
    BatchFile.close();
    if (!QProcess::startDetached(BatchPath)) {
      Notify("Failed to launch the updater.", NoticeKind::Error);
      RefreshStatus();
      return;
    }
    SetStatus("Settings | updater launched, restarting...");
    QCoreApplication::quit();
  }

  // ----------------------------------------------------------
  // 命令
  // ----------------------------------------------------------

  void CommandTheme(const std::vector<std::string> &Args) {
    if (Args.empty()) {
      Notify("Usage: theme <default_blue|cyan|indigo|graphite>",
             NoticeKind::Warning);
      return;
    }
    const QString PresetId = NormalizeThemePresetId(MiscFromUtf8(Args.front()));
    if (PresetId.isEmpty() || PresetId == QLatin1String(KCustomThemePreset)) {
      Notify("Unknown theme preset: " + Args.front(), NoticeKind::Warning);
      return;
    }
    QJsonObject ThemeObject = ConfigurationSection("Theme");
    ApplyThemePreset(ThemeObject, PresetId,
                     ConfigurationValue("Theme", "DarkMode",
                                        KDefaultThemeDarkMode)
                         .toBool());
    Configuration.insert("Theme", ThemeObject);
    SaveConfiguration();
    MarkMutated();
    Notify("Theme preset applied.", NoticeKind::Success);
    RefreshStatus();
  }

  void CommandColor(const std::vector<std::string> &Args) {
    if (Args.size() < 2) {
      Notify("Usage: color <Key> <#RRGGBB>", NoticeKind::Warning);
      return;
    }
    static const char *const Keys[] = {
        "AccentColor",        "AccentHoverColor",  "AccentPressedColor",
        "PageBackgroundColor","CardSurfaceColor",  "SurfaceElevatedColor",
        "SurfaceSunkenColor", "InputSurfaceColor", "TableSurfaceColor",
        "PopupSurfaceColor",  "BorderColor",       "DividerColor",
        "TextColor",          "MutedTextColor",    "SelectionTextColor",
        "DangerColor",        "WarningColor",      "SuccessColor"};
    const std::string Key = TrimAscii(Args[0]);
    bool Known = false;
    for (const char *Candidate : Keys) {
      if (Key == Candidate) {
        Known = true;
        break;
      }
    }
    if (!Known) {
      Notify("Unknown theme color key: " + Key, NoticeKind::Warning);
      return;
    }
    QColor Parsed;
    if (!MiscParseHexColor(Args[1], &Parsed)) {
      Notify("Enter a color as #RRGGBB.", NoticeKind::Error);
      return;
    }
    QJsonObject ThemeObject = ConfigurationSection("Theme");
    ThemeObject.insert(MiscFromUtf8(Key), MiscFromUtf8(MiscHexColorText(Parsed)));
    ThemeObject.insert("Preset", QString::fromLatin1(KCustomThemePreset));
    Configuration.insert("Theme", ThemeObject);
    SaveConfiguration();
    MarkMutated();
    Notify("Theme color updated.", NoticeKind::Success);
    RefreshStatus();
  }

  void CommandSet(const std::vector<std::string> &Args) {
    if (Args.size() < 2) {
      Notify("Usage: set <Section>.<Key> <value>", NoticeKind::Warning);
      return;
    }
    const std::string Path = TrimAscii(Args[0]);
    const size_t Dot = Path.find('.');
    if (Dot == std::string::npos || Dot == 0 || Dot + 1 >= Path.size()) {
      Notify("Usage: set <Section>.<Key> <value>", NoticeKind::Warning);
      return;
    }
    std::string Joined;
    for (size_t Index = 1; Index < Args.size(); ++Index) {
      if (Index > 1)
        Joined += ' ';
      Joined += Args[Index];
    }
    const QString Section = MiscFromUtf8(Path.substr(0, Dot));
    const QString Key = MiscFromUtf8(Path.substr(Dot + 1));
    const QString Value = MiscFromUtf8(Joined);
    QJsonValue Stored(Value);
    if (Value.compare(QLatin1String("true"), Qt::CaseInsensitive) == 0)
      Stored = QJsonValue(true);
    else if (Value.compare(QLatin1String("false"), Qt::CaseInsensitive) == 0)
      Stored = QJsonValue(false);
    else {
      bool Ok = false;
      const int Number = Value.toInt(&Ok);
      if (Ok)
        Stored = QJsonValue(Number);
    }
    SetConfigurationValue(Section, Key, Stored);
    MarkMutated();
    Notify("Configuration updated: " + Path, NoticeKind::Success);
    RefreshStatus();
  }

  // ----------------------------------------------------------
  // 视图
  // ----------------------------------------------------------

  void NotifyStatus(const std::string &Text) {
    Notify(Text, NoticeKind::Success);
    RefreshStatus();
  }

  void RefreshStatus() {
    std::string Status = "Settings | " + std::to_string(Rows_.size()) +
                         " rows | console: " +
                         (ConfigurationValue("Application", "ConsoleVisible",
                                             false)
                                  .toBool()
                              ? "shown"
                              : "hidden");
    if (!RowFilter_.empty())
      Status += " | filter: " + RowFilter_;
    SetStatus(Status);
  }

  void Refresh() {
    Notify("Settings reloaded.", NoticeKind::Info);
    RebuildView();
    RefreshStatus();
  }

  // RowFilter_（大小写不敏感子串，匹配组名/标题/描述/当前值）→ View_。
  void RebuildView() {
    View_.clear();
    const std::string Needle = LowerAscii(RowFilter_);
    for (size_t Index = 0; Index < Rows_.size(); ++Index) {
      if (!Needle.empty()) {
        const SettingRow &Entry = Rows_[Index];
        std::string Haystack =
            Entry.Group + ' ' + Entry.Title + ' ' + Entry.Description + ' ';
        if (Entry.Value)
          Haystack += Entry.Value();
        if (LowerAscii(Haystack).find(Needle) == std::string::npos)
          continue;
      }
      View_.push_back(static_cast<int>(Index));
    }
    SyncTable();
  }

  // View_ → Table_：`detail <n>` 走的就是这张表，说明文字放在 Detail。
  void SyncTable() {
    Table_.Headers = {"Group", "Setting", "Value"};
    Table_.Rows.clear();
    Table_.Rows.reserve(View_.size());
    for (int RowIndex : View_) {
      const SettingRow &Entry = Rows_[static_cast<size_t>(RowIndex)];
      TuiRow Row;
      Row.Cells = {Entry.Group, Entry.Title,
                   Entry.Value ? Entry.Value() : std::string()};
      if (!Entry.Description.empty())
        Row.Detail = "    " + Entry.Description + "\n";
      Table_.Rows.push_back(std::move(Row));
    }
    // 过滤已在 RebuildView 里按“组名/标题/描述/当前值”做完，这里不再二次过滤。
    Table_.Filter.clear();
    Table_.Rebuild();
  }


  int Index_ = -1;
  bool ConsoleOnly_ = false;
  std::string CurrentGroup_;
  std::string RowFilter_;
  std::vector<SettingRow> Rows_;
  std::vector<int> View_;             // Rows_ 经 RowFilter_ 过滤后的可见行
  TuiTable Table_;                    // View_ 的表格视图（detail 用）
  std::function<void()> ConsoleEdit_; // 空 = --console 模式下的只读行

  bool CheckingUpdate_ = false;
  bool CheckSucceeded_ = false;
  bool UpdateAvailable_ = false;
  std::string CloudVersion_;
  QUrl DownloadUrl_;
};

// ============================================================
// Account
// ============================================================

class AccountPage final : public TuiPage {
public:
  explicit AccountPage(int Index) : Index_(Index) {
    Alive_ = std::make_shared<std::atomic_bool>(true);
    Status_.Headers = {"Field", "Value"};
    Status_.Rebuild();
    OwnedCommands = {
        {"refresh", "refresh  (re-query the session state)",
         [this](std::vector<std::string>) { RefreshSession(); }},
        {"sign-out", "sign-out  (clear the session and stored credentials)",
         [this](std::vector<std::string>) { SignOut(); }},
        {"register", "register  (create a new account)",
         [this](std::vector<std::string>) { PushRegisterDialog(); }},
        {"change-password", "change-password  (change an account password)",
         [this](std::vector<std::string>) { PushChangePasswordDialog(); }},
        {"change-type", "change-type  (administrator: change a user type)",
         [this](std::vector<std::string>) { PushChangeTypeDialog(); }},
    };
  }

  ~AccountPage() override {
    if (Alive_)
      Alive_->store(false);
  }

  std::string Title() const override { return "Account"; }

  std::string Subtitle() const override {
    return "session state, registration, password and user type";
  }

  void OnEnter() override {
    RegisterListeners();
    RefreshSession();
  }

  TuiTable *ActiveTable() override { return &Status_; }

  std::string RenderText() override {
    RefreshStatus();
    std::string Text = TuiTableToText(Status_, 0);
    if (ReadOnlyMode || !Account.IsLoggedIn)
      Text += "[!] Sign in to use this page.\n";
    else
      Text += "[+] Signed in as " + DisplayUserName() + "\n";
    Text += "Commands: register, change-password, change-type, sign-out\n";
    if (Account.IsLoggedIn && Account.UserType != 1)
      Text += "change-type requires an administrator account\n";
    Text += "Server: " + MiscUtf8(AuthServerAddress()) + "\n";
    return Text;
  }

private:
  // ----------------------------------------------------------
  // 会话状态
  // ----------------------------------------------------------

  void RegisterListeners() {
    if (Listening_)
      return;
    Listening_ = true;
    auto Alive = Alive_;
    AegisNT::ApplicationContext().AccountSessionListeners.push_back(
        [this, Alive]() -> bool {
          if (!Alive->load())
            return false;
          RefreshStatus();
          if (Account.IsLoggedIn && !Account.Token.isEmpty()) {
            if (LastQueriedUser_ != Account.UserName) {
              LastQueriedUser_ = Account.UserName;
              QueryUserType();
            }
          } else {
            LastQueriedUser_.clear();
          }
          return true;
        });
  }

  std::string DisplayUserName() const {
    if (!Account.IsLoggedIn)
      return std::string("-");
    const QString Title = Account.Title.trimmed();
    if (Title.isEmpty())
      return MiscUtf8(Account.UserName);
    return MiscUtf8(QString("[%1]%2").arg(Title, Account.UserName));
  }

  std::string UserTypeText(int UserType) const {
    switch (UserType) {
    case 0:
      return std::string("Regular User");
    case 1:
      return std::string("Administrator");
    default:
      return std::string("Unknown (") + std::to_string(UserType) + ")";
    }
  }

  void RefreshStatus() {
    // `filter` 命令把条件写进 Filter：表格按“字段名 + 值”过滤。
    Status_.Filter = Filter;
    Status_.Rows.clear();
    Status_.Rows.push_back(TuiRow{{"Status", Account.IsLoggedIn
                                                  ? "● Logged In"
                                                  : "● Not Logged In"},
                                  {}});
    Status_.Rows.push_back(TuiRow{{"User", DisplayUserName()}, {}});
    Status_.Rows.push_back(
        TuiRow{{"Type", Account.IsLoggedIn ? UserTypeText(Account.UserType)
                                          : std::string("-")},
               {}});
    Status_.Rows.push_back(
        TuiRow{{"Last Login",
                Account.IsLoggedIn
                    ? MiscUtf8(ConfigurationValue("Account", "LastLoginTime", "-")
                               .toString())
                    : std::string("-")},
               {}});
    Status_.Rebuild();
    SetStatus(std::string("Account | ") +
              (Account.IsLoggedIn ? "signed in" : "not signed in") +
              (Account.IsLoggedIn && Account.UserType == 1 ? " | administrator"
                                                           : ""));
  }

  void RefreshSession() {
    RefreshStatus();
    if (Account.IsLoggedIn && !Account.Token.isEmpty() &&
        LastQueriedUser_ != Account.UserName) {
      LastQueriedUser_ = Account.UserName;
      QueryUserType();
    }
    if (!Account.IsLoggedIn)
      LastQueriedUser_.clear();
  }

  void QueryUserType() {
    const QString Token = Account.Token;
    if (Token.isEmpty() || Querying_.exchange(true))
      return;
    TuiAsync<QJsonObject>(
        [Token] {
          QJsonObject Response;
          QString Error;
          const bool Ok = HttpGetJson(QStringLiteral("/QueryUserType"), Token,
                                      4000, &Response, &Error);
          QJsonObject Result;
          Result.insert("ok", Ok);
          Result.insert("error", Error);
          Result.insert("response", Response);
          return Result;
        },
        [this, Token](QJsonObject Result) {
          Querying_ = false;
          // 与 GUI 的 SameLoginSession 一致：请求期间会话变了就丢弃结果。
          if (!(Account.IsLoggedIn && Account.Token == Token) ||
              !Result.value("ok").toBool())
            return;
          const QJsonObject Response = Result.value("response").toObject();
          if (!Response.value("success").toBool())
            return;
          const QJsonObject Data = Response.value("data").toObject();
          const QString UserName = Data.value("UserName").toString();
          const QString Title = Data.value("Title").toString();
          const int UserType = Data.value("UserType").toInt(-1);
          if (UserName.isEmpty() || UserType < 0)
            return;
          if (ConfigurationValue("Account", "UserName", "").toString() !=
              UserName)
            SetConfigurationValue("Account", "UserName", UserName);
          if (ConfigurationValue("Account", "UserType", -1).toInt() != UserType)
            SetConfigurationValue("Account", "UserType", UserType);
          if (ConfigurationValue("Account", "Title", "").toString() != Title)
            SetConfigurationValue("Account", "Title", Title);
          Account.UserName = UserName;
          Account.Title = Title;
          Account.UserType = UserType;
          AegisNT::NotifyAccountSessionChanged();
          MarkMutated();
          RefreshStatus();
        });
  }

  // ----------------------------------------------------------
  // 命令
  // ----------------------------------------------------------

  void SignOut() {
    if (!Account.IsLoggedIn) {
      Notify("Sign in to use this page.", NoticeKind::Warning);
      return;
    }
    MiscPushConfirm(Dialogs, "Sign out",
                MiscUtf8(QString("Sign out of '%1'?").arg(Account.UserName)),
                [this]() {
                  HandleLogout();
                  MarkMutated();
                  LastQueriedUser_.clear();
                  RefreshStatus();
                  Notify("Signed out. Restart the console front-end to sign in "
                         "again.",
                         NoticeKind::Success);
                });
  }

  void PushRegisterDialog() {
    MiscPushForm(
        Dialogs, "Register",
        {MiscFieldSpec{"Username", TuiFieldKind::Text, {}, "account name"},
         MiscFieldSpec{"Password", TuiFieldKind::Password, {},
                   "at least 6 characters",
                   "The server creates regular user accounts.",
                   [](const std::string &Value) -> std::string {
                     if (Value.size() < 6)
                       return "Password must be at least 6 characters";
                     return std::string();
                   }}},
        [this](const std::vector<std::string> &Values) {
          const QString UserName = MiscFromUtf8(Values.at(0)).trimmed();
          const QString Password = MiscFromUtf8(Values.at(1));
          if (UserName.isEmpty() || Password.isEmpty()) {
            Notify("Username and password cannot be empty",
                   NoticeKind::Error);
            return;
          }
          SubmitRegister(UserName, Password);
        });
  }

  void SubmitRegister(const QString &UserName, const QString &Password) {
    SetStatus("Account | registering...");
    TuiAsync<QJsonObject>(
        [UserName, Password] {
          QJsonObject Body;
          Body.insert("UserName", UserName);
          Body.insert("Password", Sha256Hex(Password));
          QJsonObject Response;
          QString Error;
          const bool Ok = HttpPostJson(QStringLiteral("/Register"), Body, 6000,
                                       &Response, &Error);
          QJsonObject Result;
          Result.insert("ok", Ok);
          Result.insert("error", Error);
          Result.insert("response", Response);
          return Result;
        },
        [this, UserName](QJsonObject Result) {
          if (!Result.value("ok").toBool()) {
            AppendConsoleOutput("[!] Account registration: Network error: " +
                                Result.value("error").toString() + "\n");
            Notify(MiscUtf8(QString("Network error: %1")
                            .arg(Result.value("error").toString())),
                   NoticeKind::Error);
            RefreshStatus();
            return;
          }
          const QJsonObject Response = Result.value("response").toObject();
          if (!Response.value("success").toBool()) {
            AppendConsoleOutput("[!] Account registration: " +
                                Response.value("message").toString() + "\n");
            Notify(MiscUtf8(Response.value("message").toString()),
                   NoticeKind::Error);
            RefreshStatus();
            return;
          }
          Notify(MiscUtf8(QString("User '%1' registered successfully!")
                          .arg(UserName)),
                 NoticeKind::Success);
          MarkMutated();
          RefreshStatus();
        });
  }

  void PushChangePasswordDialog() {
    MiscPushForm(
        Dialogs, "Change Password",
        {MiscFieldSpec{"Username", TuiFieldKind::Text, {}, "account name"},
         MiscFieldSpec{"Old Password", TuiFieldKind::Password, {}, "current password"},
         MiscFieldSpec{"New Password", TuiFieldKind::Password, {},
                   "at least 6 characters",
                   "The saved credential is updated when this is the current "
                   "user.",
                   [](const std::string &Value) -> std::string {
                     if (Value.size() < 6)
                       return "New password must be at least 6 characters";
                     return std::string();
                   }}},
        [this](const std::vector<std::string> &Values) {
          const QString UserName = MiscFromUtf8(Values.at(0)).trimmed();
          const QString OldPassword = MiscFromUtf8(Values.at(1));
          const QString NewPassword = MiscFromUtf8(Values.at(2));
          if (UserName.isEmpty() || OldPassword.isEmpty() ||
              NewPassword.isEmpty()) {
            Notify("All fields are required", NoticeKind::Error);
            return;
          }
          SubmitChangePassword(UserName, OldPassword, NewPassword);
        });
  }

  void SubmitChangePassword(const QString &UserName,
                            const QString &OldPassword,
                            const QString &NewPassword) {
    SetStatus("Account | changing password...");
    TuiAsync<QJsonObject>(
        [UserName, OldPassword, NewPassword] {
          QJsonObject Body;
          Body.insert("UserName", UserName);
          Body.insert("OldPassword", Sha256Hex(OldPassword));
          Body.insert("NewPassword", Sha256Hex(NewPassword));
          QJsonObject Response;
          QString Error;
          const bool Ok = HttpPostJson(QStringLiteral("/ChangePassword"), Body,
                                       6000, &Response, &Error);
          QJsonObject Result;
          Result.insert("ok", Ok);
          Result.insert("error", Error);
          Result.insert("response", Response);
          return Result;
        },
        [this, UserName, NewPassword](QJsonObject Result) {
          if (!Result.value("ok").toBool()) {
            AppendConsoleOutput("[!] Change password: Network error: " +
                                Result.value("error").toString() + "\n");
            Notify(MiscUtf8(QString("Network error: %1")
                            .arg(Result.value("error").toString())),
                   NoticeKind::Error);
            RefreshStatus();
            return;
          }
          const QJsonObject Response = Result.value("response").toObject();
          if (!Response.value("success").toBool()) {
            AppendConsoleOutput("[!] Change password: " +
                                Response.value("message").toString() + "\n");
            Notify(MiscUtf8(Response.value("message").toString()),
                   NoticeKind::Error);
            RefreshStatus();
            return;
          }
          Notify(MiscUtf8(QString("Password changed successfully for '%1'!")
                          .arg(UserName)),
                 NoticeKind::Success);
          // 与 GUI 一致：当前用户且勾选了保存凭证时重写本机加密密码。
          const QString CurrentUser =
              ConfigurationValue("Account", "UserName", "").toString();
          if (UserName == CurrentUser &&
              ConfigurationValue("Account", "SaveCredentials", false).toBool())
            SetConfigurationValue("Account", "Password",
                                  EncryptPassword(NewPassword));
          MarkMutated();
          RefreshStatus();
        });
  }

  void PushChangeTypeDialog() {
    if (!Account.IsLoggedIn) {
      Notify("Sign in to use this page.", NoticeKind::Warning);
      return;
    }
    if (Account.UserType != 1) {
      Notify("Administrator rights are required.", NoticeKind::Warning);
      return;
    }
    static const char *const Labels[] = {"Regular User", "Administrator"};
    MiscPushForm(
        Dialogs, "Change User Type (Admin Only)",
        {MiscFieldSpec{"Admin Username", TuiFieldKind::Text, {}, "admin account"},
         MiscFieldSpec{"Admin Password", TuiFieldKind::Password, {},
                   "admin password"},
         MiscFieldSpec{"Target Username", TuiFieldKind::Text, {},
                   "account to change"},
         MiscFieldSpec{"New Type", TuiFieldKind::Text, "Regular User",
                   "Regular User / Administrator",
                   "Values: Regular User, Administrator",
                   [](const std::string &Value) -> std::string {
                     if (MiscMatchChoice(Value, Labels, nullptr, 2) < 0)
                       return "Choose Regular User or Administrator.";
                     return std::string();
                   }},
         MiscFieldSpec{"Title", TuiFieldKind::Text, {},
                   "optional, max 48 characters"}},
        [this](const std::vector<std::string> &Values) {
          const QString AdminName = MiscFromUtf8(Values.at(0)).trimmed();
          const QString AdminPassword = MiscFromUtf8(Values.at(1));
          const QString TargetUser = MiscFromUtf8(Values.at(2)).trimmed();
          const int NewUserType = MiscMatchChoice(Values.at(3), Labels, nullptr, 2);
          const QString NewTitle = MiscFromUtf8(Values.at(4)).trimmed();
          if (AdminName.isEmpty() || AdminPassword.isEmpty() ||
              TargetUser.isEmpty() || NewUserType < 0) {
            Notify("All fields are required", NoticeKind::Error);
            return;
          }
          SubmitChangeType(AdminName, AdminPassword, TargetUser, NewUserType,
                           NewTitle);
        });
  }

  void SubmitChangeType(const QString &AdminName, const QString &AdminPassword,
                        const QString &TargetUser, int NewUserType,
                        const QString &NewTitle) {
    SetStatus("Account | changing user type...");
    TuiAsync<QJsonObject>(
        [AdminName, AdminPassword, TargetUser, NewUserType, NewTitle] {
          QJsonObject Body;
          Body.insert("AdminName", AdminName);
          Body.insert("AdminPassword", Sha256Hex(AdminPassword));
          Body.insert("TargetUserName", TargetUser);
          Body.insert("NewUserType", NewUserType);
          Body.insert("Title", NewTitle);
          QJsonObject Response;
          QString Error;
          const bool Ok = HttpPostJson(QStringLiteral("/ChangeUserType"), Body,
                                       6000, &Response, &Error);
          QJsonObject Result;
          Result.insert("ok", Ok);
          Result.insert("error", Error);
          Result.insert("response", Response);
          return Result;
        },
        [this, TargetUser, NewUserType, NewTitle](QJsonObject Result) {
          if (!Result.value("ok").toBool()) {
            AppendConsoleOutput("[!] Change user type: Network error: " +
                                Result.value("error").toString() + "\n");
            Notify(MiscUtf8(QString("Network error: %1")
                            .arg(Result.value("error").toString())),
                   NoticeKind::Error);
            RefreshStatus();
            return;
          }
          const QJsonObject Response = Result.value("response").toObject();
          if (!Response.value("success").toBool()) {
            AppendConsoleOutput("[!] Change user type: " +
                                Response.value("message").toString() + "\n");
            Notify(MiscUtf8(Response.value("message").toString()),
                   NoticeKind::Error);
            RefreshStatus();
            return;
          }
          AegisNT::NotifyUserTitleChanged(TargetUser, NewTitle);
          Notify(MiscUtf8(QString("User '%1' changed to %2!")
                          .arg(TargetUser,
                               NewUserType == 1 ? QStringLiteral("Administrator")
                                                : QStringLiteral(
                                                      "Regular User"))),
                 NoticeKind::Success);
          const QString CurrentUser =
              ConfigurationValue("Account", "UserName", "").toString();
          if (TargetUser == CurrentUser) {
            SetConfigurationValue("Account", "UserType", NewUserType);
            SetConfigurationValue("Account", "Title", NewTitle);
            Account.UserName = CurrentUser;
            Account.UserType = NewUserType;
            Account.Title = NewTitle;
            AegisNT::NotifyAccountSessionChanged();
          }
          MarkMutated();
          RefreshStatus();
        });
  }

  int Index_ = -1;
  TuiTable Status_;
  std::shared_ptr<std::atomic_bool> Alive_;
  bool Listening_ = false;
  std::atomic_bool Querying_{false};
  QString LastQueriedUser_;
};

// ============================================================
// 工厂
// ============================================================

std::unique_ptr<TuiPage> MakeSettingsPage(int Index) {
  return std::make_unique<SettingsPage>(Index);
}

std::unique_ptr<TuiPage> MakeAccountPage(int Index) {
  return std::make_unique<AccountPage>(Index);
}

} // namespace AegisNT::Tui
