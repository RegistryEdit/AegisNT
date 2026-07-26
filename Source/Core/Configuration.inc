void LoadConfiguration()
{
    QFile File(ConfigurationPath());
    if (!File.open(QIODevice::ReadOnly))
        return;
    const QJsonDocument Document = QJsonDocument::fromJson(File.readAll());
    if (Document.isObject())
        Configuration = Document.object();
}

void SaveConfiguration()
{
    QDir().mkpath(QFileInfo(ConfigurationPath()).absolutePath());
    QSaveFile File(ConfigurationPath());
    if (!File.open(QIODevice::WriteOnly))
        return;
    File.write(QJsonDocument(Configuration).toJson(QJsonDocument::Indented));
    File.commit();
}

QJsonValue ConfigurationValue(const QString &Section, const QString &Key, const QJsonValue &Fallback);
QColor ConfiguredColor(const QString &Key, const QColor &Fallback);
PushButton *MakeButton(const QString &Text, bool Primary = false);
FluentLabelBase *MakeLabel(const QString &Text, int PixelSize, const QColor &Color,
                           QFont::Weight Weight = QFont::Normal);
void ConfigureToolbarLayout(QHBoxLayout *Layout, int Spacing = 6);
void InstallFluentScrollBar(QAbstractScrollArea *Area, Qt::Orientation Orientation);
QString ApplicationStyleSheet(int MaterialOverride = -1);
void ShowSuccessNotice(QWidget *Parent, const QString &Title, const QString &Content);
void QueueThemeApply(QWidget *Window, bool SaveChanges = false, bool UpdateWindow = false);

struct ThemePalette
{
    QColor Accent;
    QColor AccentHover;
    QColor AccentPressed;
    QColor PageBackground;
    QColor CardSurface;
    QColor ElevatedSurface;
    QColor SunkenSurface;
    QColor InputSurface;
    QColor TableSurface;
    QColor PopupSurface;
    QColor Border;
    QColor Divider;
    QColor Text;
    QColor MutedText;
    QColor SelectionText;
    QColor Danger;
    QColor Warning;
    QColor Success;
};

constexpr bool KDefaultThemeDarkMode = false;
constexpr int KCompactToolbarSpacing = 6;
constexpr int KCompactPageSpacing = 10;
constexpr int KCompactTableRowHeight = 32;
constexpr int KSearchDebounceMs = 150;
constexpr int KDefaultThemeCornerRadius = 8;
constexpr int KDefaultThemeDensity = 98;
constexpr int KDefaultThemeFontScale = 100;
constexpr int KDefaultThemeWallpaperOpacity = 28;
constexpr int KDefaultThemeBackgroundMaterial = 1;

const ThemePalette &DefaultThemePalette()
{
    static const ThemePalette Palette{
        QColor("#2E6CFF"),
        QColor("#3E7BFF"),
        QColor("#2458D9"),
        QColor("#F4F6FA"),
        QColor("#FFFFFF"),
        QColor("#F8FAFD"),
        QColor("#EDF1F7"),
        QColor("#FFFFFF"),
        QColor("#FFFFFF"),
        QColor("#FFFFFF"),
        QColor("#D7DDE8"),
        QColor("#E6EBF2"),
        QColor("#18212F"),
        QColor("#667287"),
        QColor("#FFFFFF"),
        QColor("#C53D32"),
        QColor("#D98A14"),
        QColor("#1E8A5D")};
    return Palette;
}

void ApplyDefaultThemeValues(QJsonObject &ThemeObject)
{
    const ThemePalette &Palette = DefaultThemePalette();
    ThemeObject.insert("DarkMode", KDefaultThemeDarkMode);
    ThemeObject.insert("BackgroundMaterial", KDefaultThemeBackgroundMaterial);
    ThemeObject.insert("WallpaperOpacity", KDefaultThemeWallpaperOpacity);
    ThemeObject.insert("AccentColor", Palette.Accent.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("AccentHoverColor", Palette.AccentHover.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("AccentPressedColor", Palette.AccentPressed.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("PageBackgroundColor", Palette.PageBackground.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("CardSurfaceColor", Palette.CardSurface.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("SurfaceElevatedColor", Palette.ElevatedSurface.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("SurfaceSunkenColor", Palette.SunkenSurface.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("InputSurfaceColor", Palette.InputSurface.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("TableSurfaceColor", Palette.TableSurface.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("PopupSurfaceColor", Palette.PopupSurface.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("BorderColor", Palette.Border.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("DividerColor", Palette.Divider.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("TextColor", Palette.Text.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("MutedTextColor", Palette.MutedText.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("SelectionTextColor", Palette.SelectionText.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("DangerColor", Palette.Danger.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("WarningColor", Palette.Warning.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("SuccessColor", Palette.Success.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("CornerRadius", KDefaultThemeCornerRadius);
    ThemeObject.insert("FontScale", KDefaultThemeFontScale);
    ThemeObject.insert("Density", KDefaultThemeDensity);
    ThemeObject.insert("BackgroundColor", Palette.PageBackground.name(QColor::HexRgb).toUpper());
    ThemeObject.insert("SurfaceColor", Palette.CardSurface.name(QColor::HexRgb).toUpper());
}

QColor BlendColors(const QColor &Base, const QColor &Overlay, qreal Amount)
{
    const qreal Ratio = std::clamp(Amount, 0.0, 1.0);
    return QColor::fromRgbF(
        Base.redF() * (1.0 - Ratio) + Overlay.redF() * Ratio,
        Base.greenF() * (1.0 - Ratio) + Overlay.greenF() * Ratio,
        Base.blueF() * (1.0 - Ratio) + Overlay.blueF() * Ratio,
        Base.alphaF() * (1.0 - Ratio) + Overlay.alphaF() * Ratio);
}

QColor WithAlpha(const QColor &Color, int Alpha)
{
    QColor Result = Color;
    Result.setAlpha(std::clamp(Alpha, 0, 255));
    return Result;
}

ThemePalette CurrentThemePalette()
{
    const ThemePalette &Defaults = DefaultThemePalette();
    ThemePalette Palette;
    Palette.Accent = ConfiguredColor("AccentColor", Defaults.Accent);
    Palette.AccentHover = ConfiguredColor("AccentHoverColor", Defaults.AccentHover);
    Palette.AccentPressed = ConfiguredColor("AccentPressedColor", Defaults.AccentPressed);
    Palette.PageBackground = ConfiguredColor("PageBackgroundColor",
                                             ConfiguredColor("BackgroundColor", Defaults.PageBackground));
    Palette.CardSurface = ConfiguredColor("CardSurfaceColor",
                                          ConfiguredColor("SurfaceColor", Defaults.CardSurface));
    Palette.ElevatedSurface = ConfiguredColor("SurfaceElevatedColor", Defaults.ElevatedSurface);
    Palette.SunkenSurface = ConfiguredColor("SurfaceSunkenColor", Defaults.SunkenSurface);
    Palette.InputSurface = ConfiguredColor("InputSurfaceColor",
                                           ConfiguredColor("SurfaceColor", Defaults.InputSurface));
    Palette.TableSurface = ConfiguredColor("TableSurfaceColor",
                                           ConfiguredColor("SurfaceColor", Defaults.TableSurface));
    Palette.PopupSurface = ConfiguredColor("PopupSurfaceColor", Defaults.PopupSurface);
    Palette.Border = ConfiguredColor("BorderColor", Defaults.Border);
    Palette.Divider = ConfiguredColor("DividerColor", Defaults.Divider);
    Palette.Text = ConfiguredColor("TextColor", Defaults.Text);
    Palette.MutedText = ConfiguredColor("MutedTextColor", Defaults.MutedText);
    Palette.SelectionText = ConfiguredColor("SelectionTextColor", Defaults.SelectionText);
    Palette.Danger = ConfiguredColor("DangerColor", Defaults.Danger);
    Palette.Warning = ConfiguredColor("WarningColor", Defaults.Warning);
    Palette.Success = ConfiguredColor("SuccessColor", Defaults.Success);
    return Palette;
}

void EnsureThemeConfiguration()
{
    QJsonObject ThemeObject = Configuration.value("Theme").toObject();
    const ThemePalette &Defaults = DefaultThemePalette();
    const std::array<std::pair<const char *, QJsonValue>, 23> DefaultEntries{{
        {"DarkMode", KDefaultThemeDarkMode},
        {"BackgroundMaterial", KDefaultThemeBackgroundMaterial},
        {"WallpaperPath", ""},
        {"WallpaperMode", 0},
        {"WallpaperOpacity", KDefaultThemeWallpaperOpacity},
        {"AccentColor", Defaults.Accent.name(QColor::HexRgb).toUpper()},
        {"AccentHoverColor", Defaults.AccentHover.name(QColor::HexRgb).toUpper()},
        {"AccentPressedColor", Defaults.AccentPressed.name(QColor::HexRgb).toUpper()},
        {"PageBackgroundColor", Defaults.PageBackground.name(QColor::HexRgb).toUpper()},
        {"CardSurfaceColor", Defaults.CardSurface.name(QColor::HexRgb).toUpper()},
        {"SurfaceElevatedColor", Defaults.ElevatedSurface.name(QColor::HexRgb).toUpper()},
        {"SurfaceSunkenColor", Defaults.SunkenSurface.name(QColor::HexRgb).toUpper()},
        {"InputSurfaceColor", Defaults.InputSurface.name(QColor::HexRgb).toUpper()},
        {"TableSurfaceColor", Defaults.TableSurface.name(QColor::HexRgb).toUpper()},
        {"PopupSurfaceColor", Defaults.PopupSurface.name(QColor::HexRgb).toUpper()},
        {"TextColor", Defaults.Text.name(QColor::HexRgb).toUpper()},
        {"MutedTextColor", Defaults.MutedText.name(QColor::HexRgb).toUpper()},
        {"BorderColor", Defaults.Border.name(QColor::HexRgb).toUpper()},
        {"DividerColor", Defaults.Divider.name(QColor::HexRgb).toUpper()},
        {"SelectionTextColor", Defaults.SelectionText.name(QColor::HexRgb).toUpper()},
        {"DangerColor", Defaults.Danger.name(QColor::HexRgb).toUpper()},
        {"WarningColor", Defaults.Warning.name(QColor::HexRgb).toUpper()},
        {"SuccessColor", Defaults.Success.name(QColor::HexRgb).toUpper()}}};
    bool Changed = false;
    for (const auto &[Key, Value] : DefaultEntries)
    {
        if (!ThemeObject.contains(Key))
        {
            ThemeObject.insert(Key, Value);
            Changed = true;
        }
    }
    if (ThemeObject.contains("Preset"))
    {
        ThemeObject.remove("Preset");
        Changed = true;
    }
    if (ThemeObject.contains("MenuCornerRadius"))
    {
        ThemeObject.remove("MenuCornerRadius");
        Changed = true;
    }
    if (!ThemeObject.contains("Density"))
    {
        ThemeObject.insert("Density", KDefaultThemeDensity);
        Changed = true;
    }
    if (!ThemeObject.contains("CornerRadius"))
    {
        ThemeObject.insert("CornerRadius", KDefaultThemeCornerRadius);
        Changed = true;
    }
    if (!ThemeObject.contains("FontScale"))
    {
        ThemeObject.insert("FontScale", KDefaultThemeFontScale);
        Changed = true;
    }
    if (ThemeObject.value("BackgroundColor").toString().isEmpty())
    {
        ThemeObject.insert("BackgroundColor", ThemeObject.value("PageBackgroundColor").toString());
        Changed = true;
    }
    if (ThemeObject.value("SurfaceColor").toString().isEmpty())
    {
        ThemeObject.insert("SurfaceColor", ThemeObject.value("CardSurfaceColor").toString());
        Changed = true;
    }
    if (Changed || !Configuration.contains("Theme"))
    {
        Configuration.insert("Theme", ThemeObject);
        SaveConfiguration();
    }
}

QJsonObject ConfigurationSection(const QString &Section)
{
    return Configuration.value(Section).toObject();
}

QJsonValue ConfigurationValue(const QString &Section, const QString &Key, const QJsonValue &Fallback)
{
    return ConfigurationSection(Section).value(Key).isUndefined() ? Fallback : ConfigurationSection(Section).value(Key);
}

void SetConfigurationValue(const QString &Section, const QString &Key, const QJsonValue &Value)
{
    QJsonObject Object = ConfigurationSection(Section);
    Object.insert(Key, Value);
    Configuration.insert(Section, Object);
    SaveConfiguration();
}

void SetConfigurationValueTransient(const QString &Section, const QString &Key, const QJsonValue &Value)
{
    QJsonObject Object = ConfigurationSection(Section);
    Object.insert(Key, Value);
    Configuration.insert(Section, Object);
}

QStringList ConfigurationPaths(const QString &Section, const QString &Fallback)
{
    QStringList Paths;
    for (const QJsonValue &Value : ConfigurationValue(Section, "Paths", QJsonArray()).toArray())
        Paths.append(Value.toString());
    if (Paths.isEmpty())
        Paths.append(Fallback);
    return Paths;
}

void SetConfigurationPath(const QString &Section, const QString &Path)
{
    QJsonArray Paths;
    Paths.append(Path);
    SetConfigurationValue(Section, "Paths", Paths);
}

QColor ConfiguredColor(const QString &Key, const QColor &Fallback)
{
    const QColor Color(ConfigurationValue("Theme", Key, "").toString());
    return Color.isValid() ? Color : Fallback;
}

QColor PrimaryTextColor()
{
    return CurrentThemePalette().Text;
}

QColor MutedTextColor()
{
    return CurrentThemePalette().MutedText;
}

QString CssColor(const QColor &Color)
{
    return QString("rgba(%1, %2, %3, %4)")
        .arg(Color.red()).arg(Color.green()).arg(Color.blue()).arg(Color.alpha());
}


bool ApplyWindowBackdrop(QWidget *Window, int Material)
{
    if (!Window)
        return false;
    Window->winId();
    auto *WindowAgent = Window->findChild<QWK::WidgetWindowAgent *>();
    if (!WindowAgent)
    {
        Window->setProperty("ThemeBackdropSupported", false);
        return false;
    }

    WindowAgent->setWindowAttribute("dark-mode", ConfigurationValue("Theme", "DarkMode", KDefaultThemeDarkMode).toBool());
    for (const QString &Attribute : {QStringLiteral("dwm-blur"), QStringLiteral("acrylic-material"),
                                     QStringLiteral("mica"), QStringLiteral("mica-alt")})
        WindowAgent->setWindowAttribute(Attribute, false);

    bool Supported = Material == 0;
    int EffectiveMaterial = 0;
    if (Material == 1)
    {
        Supported = WindowAgent->setWindowAttribute("mica", true);
        if (Supported)
            EffectiveMaterial = 1;
    }
    else if (Material == 2)
    {
        Supported = WindowAgent->setWindowAttribute("acrylic-material", true);
        if (!Supported)
            Supported = WindowAgent->setWindowAttribute("dwm-blur", true);
        if (Supported)
            EffectiveMaterial = 2;
    }
    Window->setAttribute(Qt::WA_StyledBackground, true);
    Window->setAttribute(Qt::WA_NoSystemBackground, EffectiveMaterial != 0);
    Window->setAutoFillBackground(EffectiveMaterial == 0);
    Window->setProperty("ThemeBackdropSupported", Supported);
    Window->setProperty("ThemeBackdropEffectiveMaterial", EffectiveMaterial);
    Window->update();
    if (Window->isVisible())
        DwmFlush();
    return Supported;
}

void ScheduleBackdropRefresh(QWidget *Window)
{
    if (!Window || Window->property("ThemeBackdropRefreshPending").toBool() ||
        Window->property("ThemeAppearanceFinalizePending").toBool() ||
        Window->property("ThemeBackdropApplying").toBool() ||
        Window->property("ThemeApplyQueued").toBool())
        return;

    Window->setProperty("ThemeBackdropRefreshPending", true);
    QPointer<QWidget> Guard(Window);
    QTimer::singleShot(30, Window, [Guard] {
        if (!Guard)
            return;
        Guard->setProperty("ThemeBackdropRefreshPending", false);
        const int Material = std::clamp(ConfigurationValue("Theme", "BackgroundMaterial", KDefaultThemeBackgroundMaterial).toInt(), 0, 2);
        ApplyWindowBackdrop(Guard, Material);
        Guard->update();
    });
}

void ScheduleAppearanceFinalize(QWidget *Window, int RequestedMaterial)
{
    if (!Window)
        return;

    Window->setProperty("ThemeRequestedMaterial", RequestedMaterial);
    if (Window->property("ThemeAppearanceFinalizePending").toBool())
        return;

    Window->setProperty("ThemeAppearanceFinalizePending", true);
    QPointer<QWidget> Guard(Window);
    QTimer::singleShot(180, Window, [Guard] {
        if (!Guard)
            return;
        const int Material = std::clamp(Guard->property("ThemeRequestedMaterial").toInt(), 0, 2);
        const int CurrentMaterial = Guard->property("ThemeBackdropEffectiveMaterial").toInt();
        Guard->setProperty("ThemeBackdropApplying", true);
        const auto FinishApply = [Guard](int EffectiveMaterial) {
            if (!Guard)
                return;
            Guard->setStyleSheet(ApplicationStyleSheet(EffectiveMaterial));
            Guard->setProperty("ThemeBackdropApplying", false);
            Guard->setProperty("ThemeAppearanceFinalizePending", false);
            Guard->update();
        };
        if (Material != 0 && CurrentMaterial != 0 && CurrentMaterial != Material)
        {
            ApplyWindowBackdrop(Guard, 0);
            QTimer::singleShot(80, Guard, [Guard, Material, FinishApply] {
                if (!Guard)
                    return;
                ApplyWindowBackdrop(Guard, Material);
                FinishApply(Guard->property("ThemeBackdropEffectiveMaterial").toInt());
            });
            return;
        }

        ApplyWindowBackdrop(Guard, Material);
        FinishApply(Guard->property("ThemeBackdropEffectiveMaterial").toInt());
    });
}

QString ApplicationStyleSheet(int MaterialOverride)
{
    ThemePalette Palette = CurrentThemePalette();
    QColor PageBackground = Palette.PageBackground;
    QColor CardSurface = Palette.CardSurface;
    QColor ElevatedSurface = Palette.ElevatedSurface;
    QColor SunkenSurface = Palette.SunkenSurface;
    QColor InputSurface = Palette.InputSurface;
    QColor TableSurface = Palette.TableSurface;
    QColor PopupSurface = Palette.PopupSurface;
    const QColor Text = Palette.Text;
    const QColor MutedText = Palette.MutedText;
    const QColor Border = Palette.Border;
    const QColor Divider = Palette.Divider;
    const QColor Accent = Palette.Accent;
    const QColor AccentHover = Palette.AccentHover;
    const QColor AccentPressed = Palette.AccentPressed;
    const QColor SelectionText = Palette.SelectionText;
    const QColor Danger = Palette.Danger;
    const QColor Warning = Palette.Warning;
    const QColor Success = Palette.Success;
    const int CornerRadius = std::clamp(ConfigurationValue("Theme", "CornerRadius", KDefaultThemeCornerRadius).toInt(), 0, 12);
    const int Density = std::clamp(ConfigurationValue("Theme", "Density", KDefaultThemeDensity).toInt(), 80, 120);
    const int Material = MaterialOverride >= 0
        ? std::clamp(MaterialOverride, 0, 2)
        : std::clamp(ConfigurationValue("Theme", "BackgroundMaterial", KDefaultThemeBackgroundMaterial).toInt(), 0, 2);
    const bool WallpaperEnabled = !ConfigurationValue("Theme", "WallpaperPath", "").toString().isEmpty();
    if (Material == 1)
        PageBackground = WithAlpha(PageBackground, 214);
    else if (Material == 2)
        PageBackground = WithAlpha(PageBackground, 184);
    if (WallpaperEnabled)
        PageBackground.setAlpha(std::min(PageBackground.alpha(), 168));
    const int HeaderPadding = std::clamp(qRound(6.0 * Density / 100.0), 4, 8);
    const int MenuVerticalPadding = std::clamp(qRound(7.0 * Density / 100.0), 5, 9);
    const QColor HoverOverlay = BlendColors(CardSurface, AccentHover, 0.12);
    const QColor PressedOverlay = BlendColors(CardSurface, AccentPressed, 0.18);
    const QColor InputBorder = BlendColors(Border, Accent, 0.18);
    const QColor SidebarSurface = BlendColors(CardSurface, ElevatedSurface, 0.35);
    QString Style = R"QSS(
        QFrame#Sidebar, QWidget#Brand { background: {{SIDEBAR_SURFACE}}; border: none; }
        QWidget#WindowBody { background: transparent; }
        QFrame#TitleBar { background: transparent; border: none; }
        QPushButton#TitleBarIcon,
        QPushButton#TitleBarMinimize,
        QPushButton#TitleBarMaximize,
        QPushButton#TitleBarClose {
            background: transparent;
            border: none;
            border-radius: 0;
            padding: 0;
        }
        QPushButton#TitleBarIcon:hover,
        QPushButton#TitleBarMinimize:hover,
        QPushButton#TitleBarMaximize:hover { background: rgba(128, 128, 128, 32); }
        QPushButton#TitleBarClose:hover { background: #C42B1C; color: white; }
        QPushButton#TitleBarClose:pressed { background: #A4261A; color: white; }
        QWidget#Content { background: {{PAGE_BACKGROUND}}; }
        QWidget#InformationContent,
        QWidget#SettingsContent,
        QScrollArea#InformationScroll,
        QScrollArea#SettingsScroll {
            background: {{PAGE_BACKGROUND}};
            border: none;
        }
        QFrame#toolPanel, QFrame#settingRow {
            background: {{CARD_SURFACE}};
            border: 1px solid {{BORDER}};
            border-radius: {{CARD_RADIUS}}px;
        }
        QFrame#ThemePreviewCard {
            background: {{POPUP_SURFACE}};
            border: 1px solid {{BORDER}};
            border-radius: {{CARD_RADIUS}}px;
        }
        QFrame#ThemePreviewNavItem,
        QFrame#ThemePreviewTableRow,
        QFrame#ThemePreviewStatusGood,
        QFrame#ThemePreviewStatusWarn,
        QFrame#ThemePreviewStatusDanger {
            border-radius: {{SMALL_RADIUS}}px;
        }
        QFrame#ThemePreviewNavItem {
            background: {{HOVER_SURFACE}};
            border: 1px solid {{PRESSED_SURFACE}};
        }
        QFrame#ThemePreviewTableRow {
            background: {{TABLE_SURFACE}};
            border: 1px solid {{DIVIDER}};
        }
        QFrame#ThemePreviewStatusGood { background: {{SUCCESS_TINT}}; }
        QFrame#ThemePreviewStatusWarn { background: {{WARNING_TINT}}; }
        QFrame#ThemePreviewStatusDanger { background: {{DANGER_TINT}}; }
        QFrame#settingRow QLabel { color: {{TEXT}}; }
        QLabel[TextRole="Muted"] { color: {{MUTED_TEXT}}; }
        QLabel, QAbstractButton, QLineEdit, QTextEdit, QPlainTextEdit,
        QTreeView, QTableView, QTableWidget { color: {{TEXT}}; }
        QTreeView, QTableView, QTableWidget, QLineEdit, QTextEdit, QPlainTextEdit {
            selection-background-color: {{ACCENT}};
            selection-color: {{SELECTION_TEXT}};
        }
        QLineEdit, QTextEdit, QPlainTextEdit, QAbstractSpinBox, QComboBox {
            background: {{INPUT_SURFACE}};
            border: 1px solid {{INPUT_BORDER}};
            border-radius: {{SMALL_RADIUS}}px;
            padding: 5px 8px;
        }
        QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QAbstractSpinBox:focus, QComboBox:focus {
            border: 1px solid {{ACCENT}};
        }
        QTreeView, QTableView, QTableWidget {
            background: {{TABLE_SURFACE}};
            alternate-background-color: {{TABLE_ALT_SURFACE}};
            border: 1px solid {{DIVIDER}};
            border-radius: {{SMALL_RADIUS}}px;
            gridline-color: {{DIVIDER}};
        }
        QHeaderView::section {
            color: {{TEXT}};
            background: {{HEADER_SURFACE}};
            border: none;
            border-bottom: 1px solid {{DIVIDER}};
            padding: {{HEADER_PADDING}}px;
        }
        QMenu {
            color: {{TEXT}};
            background: {{POPUP_SURFACE}};
            border: 1px solid {{BORDER}};
            border-radius: 6px;
        }
        QMenu::item { padding: {{MENU_PADDING}}px 24px; }
        QMenu::item:selected { background: {{ACCENT}}; color: {{SELECTION_TEXT}}; }
        QPushButton {
            border-radius: {{SMALL_RADIUS}}px;
            border: 1px solid {{BORDER}};
            background: {{CARD_SURFACE}};
            padding: 6px 12px;
        }
        QPushButton:hover { background: {{HOVER_SURFACE}}; }
        QPushButton:pressed { background: {{PRESSED_SURFACE}}; }
        PrimaryPushButton {
            border-radius: {{SMALL_RADIUS}}px;
            border: 1px solid {{ACCENT}};
            background: {{ACCENT}};
            color: {{SELECTION_TEXT}};
            padding: 6px 12px;
        }
        PrimaryPushButton:hover { background: {{ACCENT_HOVER}}; border-color: {{ACCENT_HOVER}}; }
        PrimaryPushButton:pressed { background: {{ACCENT_PRESSED}}; border-color: {{ACCENT_PRESSED}}; }
        QAbstractScrollArea::corner { background: transparent; }
    )QSS";
    const std::array<std::pair<QString, QString>, 21> Tokens{{
        {QStringLiteral("{{SIDEBAR_SURFACE}}"), CssColor(SidebarSurface)},
        {QStringLiteral("{{PAGE_BACKGROUND}}"), CssColor(PageBackground)},
        {QStringLiteral("{{CARD_SURFACE}}"), CssColor(CardSurface)},
        {QStringLiteral("{{BORDER}}"), CssColor(Border)},
        {QStringLiteral("{{CARD_RADIUS}}"), QString::number(CornerRadius)},
        {QStringLiteral("{{POPUP_SURFACE}}"), CssColor(PopupSurface)},
        {QStringLiteral("{{SMALL_RADIUS}}"), QString::number(std::max(4, CornerRadius - 2))},
        {QStringLiteral("{{HOVER_SURFACE}}"), CssColor(HoverOverlay)},
        {QStringLiteral("{{PRESSED_SURFACE}}"), CssColor(PressedOverlay)},
        {QStringLiteral("{{TABLE_SURFACE}}"), CssColor(TableSurface)},
        {QStringLiteral("{{DIVIDER}}"), CssColor(Divider)},
        {QStringLiteral("{{SUCCESS_TINT}}"), CssColor(WithAlpha(Success, 34))},
        {QStringLiteral("{{WARNING_TINT}}"), CssColor(WithAlpha(Warning, 34))},
        {QStringLiteral("{{DANGER_TINT}}"), CssColor(WithAlpha(Danger, 34))},
        {QStringLiteral("{{MUTED_TEXT}}"), MutedText.name()},
        {QStringLiteral("{{TEXT}}"), CssColor(Text)},
        {QStringLiteral("{{SELECTION_TEXT}}"), SelectionText.name()},
        {QStringLiteral("{{INPUT_SURFACE}}"), CssColor(InputSurface)},
        {QStringLiteral("{{INPUT_BORDER}}"), CssColor(InputBorder)},
        {QStringLiteral("{{TABLE_ALT_SURFACE}}"), CssColor(BlendColors(TableSurface, SunkenSurface, 0.55))},
        {QStringLiteral("{{HEADER_SURFACE}}"), CssColor(SunkenSurface)},
    }};
    for (const auto &[Token, Value] : Tokens)
        Style.replace(Token, Value);
    Style.replace(QStringLiteral("{{ACCENT}}"), CssColor(Accent));
    Style.replace(QStringLiteral("{{ACCENT_HOVER}}"), CssColor(AccentHover));
    Style.replace(QStringLiteral("{{ACCENT_PRESSED}}"), CssColor(AccentPressed));
    Style.replace(QStringLiteral("{{HEADER_PADDING}}"), QString::number(HeaderPadding));
    Style.replace(QStringLiteral("{{MENU_PADDING}}"), QString::number(MenuVerticalPadding));
    return Style;
}

void ApplyConfiguredAppearance(QWidget *Window)
{
    const bool DarkMode = ConfigurationValue("Theme", "DarkMode", KDefaultThemeDarkMode).toBool();
    const ThemePalette PaletteColors = CurrentThemePalette();
    const int RequestedMaterial = std::clamp(ConfigurationValue("Theme", "BackgroundMaterial", KDefaultThemeBackgroundMaterial).toInt(), 0, 2);
    Theme::setThemeMode(DarkMode ? Fluent::ThemeMode::DARK : Fluent::ThemeMode::LIGHT);
    Theme::setThemeColor(PaletteColors.Accent);
    static const qreal DefaultFontPointSize = QApplication::font().pointSizeF() > 0
                                                   ? QApplication::font().pointSizeF()
                                                   : 9.0;
    const int FontScale = std::clamp(ConfigurationValue("Theme", "FontScale", KDefaultThemeFontScale).toInt(), 85, 125);
    QFont ApplicationFont = qApp->font();
    ApplicationFont.setPointSizeF(DefaultFontPointSize * FontScale / 100.0);
    qApp->setFont(ApplicationFont);
    if (Window)
    {
        QPalette Palette = Window->palette();
        Palette.setColor(QPalette::Window, PaletteColors.PageBackground);
        Palette.setColor(QPalette::WindowText, PrimaryTextColor());
        Palette.setColor(QPalette::Text, PrimaryTextColor());
        Palette.setColor(QPalette::ButtonText, PrimaryTextColor());
        Palette.setColor(QPalette::PlaceholderText, MutedTextColor());
        Palette.setColor(QPalette::Base, PaletteColors.InputSurface);
        Palette.setColor(QPalette::Button, PaletteColors.CardSurface);
        Palette.setColor(QPalette::Highlight, PaletteColors.Accent);
        Palette.setColor(QPalette::HighlightedText, PaletteColors.SelectionText);
        qApp->setPalette(Palette);
        Window->setPalette(Palette);
        Window->setStyleSheet(ApplicationStyleSheet(0));
        for (FluentLabelBase *Label : Window->findChildren<FluentLabelBase *>())
        {
            const QString Role = Label->property("TextRole").toString();
            if (Role == "Primary")
                Label->setTextColor(PrimaryTextColor(), PrimaryTextColor());
            else if (Role == "Muted")
                Label->setTextColor(MutedTextColor(), MutedTextColor());
            else if (Role == "Accent")
                Label->setTextColor(ConfiguredColor("AccentColor", KAccent),
                                    ConfiguredColor("AccentColor", KAccent));
            const int BasePixelSize = Label->property("ThemeBasePixelSize").toInt();
            if (BasePixelSize > 0)
            {
                QFont Font = Label->font();
                Font.setPixelSize(std::max(8, qRound(BasePixelSize * FontScale / 100.0)));
                Label->setFont(Font);
            }
        }
        Window->setWindowOpacity(std::clamp(ConfigurationValue("Application", "Opacity", 1.0).toDouble(), 0.35, 1.0));
        ScheduleAppearanceFinalize(Window, RequestedMaterial);
    }
}

void QueueThemeApply(QWidget *Window, bool SaveChanges, bool UpdateWindow)
{
    if (!Window)
        return;

    Window->setProperty("ThemeApplyNeedsSave", Window->property("ThemeApplyNeedsSave").toBool() || SaveChanges);
    Window->setProperty("ThemeApplyNeedsUpdate", Window->property("ThemeApplyNeedsUpdate").toBool() || UpdateWindow);
    if (Window->property("ThemeApplyQueued").toBool())
        return;

    Window->setProperty("ThemeApplyQueued", true);
    QPointer<QWidget> Guard(Window);
    QTimer::singleShot(0, Window, [Guard] {
        if (!Guard)
            return;
        const bool Save = Guard->property("ThemeApplyNeedsSave").toBool();
        const bool Update = Guard->property("ThemeApplyNeedsUpdate").toBool();
        Guard->setProperty("ThemeApplyQueued", false);
        Guard->setProperty("ThemeApplyNeedsSave", false);
        Guard->setProperty("ThemeApplyNeedsUpdate", false);
        if (Save)
            SaveConfiguration();
        ApplyConfiguredAppearance(Guard);
        if (Update)
            Guard->update();
    });
}

std::vector<ModuleEntry> DllModules;
std::vector<ModuleEntry> DriverModules;
QPointer<PlainTextEdit> ConsoleOutputWidget;
QPointer<PlainTextEdit> ModuleOutputWidget;
QPointer<QProcess> ActiveConsoleProcess;
std::mutex OutputMutex;

QString ResolveRuntimePath(const QString &Path)
{
    const QFileInfo Info(Path);
    return QDir::cleanPath(Info.isAbsolute() ? Info.absoluteFilePath()
                                             : QDir(QCoreApplication::applicationDirPath()).absoluteFilePath(Path));
}

QString Utf8Text(const std::string &Text)
{
    return QString::fromUtf8(Text.data(), static_cast<qsizetype>(Text.size()));
}

std::string Utf8Bytes(const QString &Text)
{
    const QByteArray Bytes = Text.toUtf8();
    return std::string(Bytes.constData(), static_cast<size_t>(Bytes.size()));
}

QString TranslationPath(const QString &FileName)
{
    const QString InstalledPath = QCoreApplication::applicationDirPath() + "/Data/" + FileName;
    if (QFileInfo::exists(InstalledPath))
        return InstalledPath;
    return QDir(QCoreApplication::applicationDirPath()).absoluteFilePath("../Data/" + FileName);
}

void LoadLanguageResources()
{
    ChineseTranslations = {};
    QFile File(TranslationPath("zh_CN.json"));
    if (!File.open(QIODevice::ReadOnly))
        return;
    const QJsonDocument Document = QJsonDocument::fromJson(File.readAll());
    if (Document.isObject())
        ChineseTranslations = Document.object().value("translations").toObject();
}

QString TranslateText(const QString &English)
{
    if (ActiveLanguage != "zh_CN" || English.isEmpty())
        return English;
    const QJsonValue Value = ChineseTranslations.value(English);
    return Value.isString() ? Value.toString() : English;
}

void TranslateObjectTree(QObject *Root);
bool LanguageTranslationActive = false;

void ScheduleLanguageRefresh(QObject *Object)
{
    if (LanguageTranslationActive || !Object)
        return;
    QWidget *Widget = qobject_cast<QWidget *>(Object);
    if (!Widget)
        Widget = qobject_cast<QWidget *>(Object->parent());
    QObject *Root = Widget ? static_cast<QObject *>(Widget->window()) : Object;
    if (!Root || Root->property("LanguageRefreshPending").toBool())
        return;
    Root->setProperty("LanguageRefreshPending", true);
    QPointer<QObject> SafeRoot(Root);
    QTimer::singleShot(0, Root, [SafeRoot] {
        if (!SafeRoot)
            return;
        SafeRoot->setProperty("LanguageRefreshPending", false);
        TranslateObjectTree(SafeRoot);
    });
}

class RuntimeLanguageFilter final : public QObject
{
  public:
    using QObject::QObject;

  protected:
    bool eventFilter(QObject *Watched, QEvent *Event) override
    {
        if (Event->type() == QEvent::ChildAdded || Event->type() == QEvent::Show)
            ScheduleLanguageRefresh(Watched);
        return QObject::eventFilter(Watched, Event);
    }
};

RuntimeLanguageFilter *LanguageFilter = nullptr;

QString OriginalText(QObject *Object, const char *PropertyName, const QString &Current)
{
    const QByteArray Key = QByteArray("LanguageOriginal_") + PropertyName;
    const QVariant Stored = Object->property(Key.constData());
    if (Stored.isValid())
        return Stored.toString();
    Object->setProperty(Key.constData(), Current);
    return Current;
}

void TranslateObject(QObject *Object)
{
    bool TextHandled = false;
    if (auto *Label = qobject_cast<QLabel *>(Object))
    {
        const QString Original = OriginalText(Label, "text", Label->text());
        const QString Translated = ActiveLanguage == "zh_CN" ? TranslateText(Original) : Original;
        if (Label->text() != Translated) Label->setText(Translated);
        TextHandled = true;
    }
    if (auto *Combo = qobject_cast<ComboBox *>(Object))
    {
        QVariant Stored = Combo->property("LanguageOriginal_items");
        QStringList Originals = Stored.toStringList();
        if (Originals.size() != Combo->count())
        {
            Originals.clear();
            for (int Index = 0; Index < Combo->count(); ++Index)
                Originals.append(Combo->itemText(Index));
            Combo->setProperty("LanguageOriginal_items", Originals);
        }
        const int CurrentIndex = Combo->currentIndex();
        const QSignalBlocker Blocker(Combo);
        for (int Index = 0; Index < Originals.size(); ++Index)
        {
            const QString Translated = ActiveLanguage == "zh_CN" ? TranslateText(Originals[Index]) : Originals[Index];
            if (Combo->itemText(Index) != Translated)
                Combo->setItemText(Index, Translated);
        }
        int TargetIndex = CurrentIndex;
        if (Combo->property("ApplicationLanguageSelector").toBool())
            TargetIndex = Combo->findData(ActiveLanguage, Qt::UserRole);
        if (TargetIndex >= 0 && TargetIndex < Combo->count())
        {
            Combo->setCurrentIndex(-1);
            Combo->setCurrentIndex(TargetIndex);
        }
        Combo->update();
        TextHandled = true;
    }
    if (!TextHandled && qobject_cast<QAbstractButton *>(Object))
    {
        auto *Button = qobject_cast<QAbstractButton *>(Object);
        const QString Original = OriginalText(Button, "text", Button->text());
        const QString Translated = ActiveLanguage == "zh_CN" ? TranslateText(Original) : Original;
        if (Button->text() != Translated) Button->setText(Translated);
        TextHandled = true;
    }
    // A writable text property on an editor is user data, not a translatable label.
    // Do not rewrite it during the runtime language refresh.
    const bool IsEditableText = qobject_cast<QLineEdit *>(Object) != nullptr ||
                                qobject_cast<QTextEdit *>(Object) != nullptr ||
                                qobject_cast<QPlainTextEdit *>(Object) != nullptr;
    const int TextPropertyIndex = Object->metaObject()->indexOfProperty("text");
    if (!TextHandled && !IsEditableText && TextPropertyIndex >= 0 &&
        Object->metaObject()->property(TextPropertyIndex).isWritable())
    {
        const QString Current = Object->property("text").toString();
        const QString Original = OriginalText(Object, "text", Current);
        const QString Translated = ActiveLanguage == "zh_CN" ? TranslateText(Original) : Original;
        if (Current != Translated) Object->setProperty("text", Translated);
    }
    if (auto *Edit = qobject_cast<QLineEdit *>(Object))
    {
        const QString Original = OriginalText(Edit, "placeholder", Edit->placeholderText());
        const QString Translated = ActiveLanguage == "zh_CN" ? TranslateText(Original) : Original;
        if (Edit->placeholderText() != Translated) Edit->setPlaceholderText(Translated);
    }
    if (auto *Combo = qobject_cast<QComboBox *>(Object))
    {
        QVariant Stored = Combo->property("LanguageOriginal_items");
        QStringList Originals = Stored.toStringList();
        if (Originals.size() != Combo->count())
        {
            Originals.clear();
            for (int Index = 0; Index < Combo->count(); ++Index)
                Originals.append(Combo->itemText(Index));
            Combo->setProperty("LanguageOriginal_items", Originals);
        }
        const QSignalBlocker Blocker(Combo);
        for (int Index = 0; Index < Originals.size(); ++Index)
        {
            const QString Translated = ActiveLanguage == "zh_CN" ? TranslateText(Originals[Index]) : Originals[Index];
            if (Combo->itemText(Index) != Translated) Combo->setItemText(Index, Translated);
        }
        if (Combo->property("ApplicationLanguageSelector").toBool())
        {
            const int ActiveIndex = Combo->findData(ActiveLanguage, Qt::UserRole);
            if (ActiveIndex >= 0)
            {
                QSignalBlocker StateBlocker(Combo);
                Combo->setCurrentIndex(-1);
                Combo->setCurrentIndex(ActiveIndex);
            }
            Combo->update();
        }
    }
    if (auto *Action = qobject_cast<QAction *>(Object))
    {
        const QString Original = OriginalText(Action, "text", Action->text());
        const QString Translated = ActiveLanguage == "zh_CN" ? TranslateText(Original) : Original;
        if (Action->text() != Translated) Action->setText(Translated);
    }
    if (auto *Table = qobject_cast<QTableWidget *>(Object))
    {
        for (int Column = 0; Column < Table->columnCount(); ++Column)
        {
            QTableWidgetItem *Item = Table->horizontalHeaderItem(Column);
            if (!Item) continue;
            QString Original = Item->data(Qt::UserRole + 100).toString();
            if (Original.isEmpty()) {
                Original = Item->text();
                Item->setData(Qt::UserRole + 100, Original);
            }
            const QString Translated = ActiveLanguage == "zh_CN" ? TranslateText(Original) : Original;
            if (Item->text() != Translated) Item->setText(Translated);
        }
    }
}

void TranslateObjectTree(QObject *Root)
{
    if (!Root) return;
    if (LanguageTranslationActive) return;
    LanguageTranslationActive = true;
    TranslateObject(Root);
    const auto Children = Root->findChildren<QObject *>();
    for (QObject *Child : Children)
        TranslateObject(Child);
    LanguageTranslationActive = false;
}

void ApplyApplicationLanguage(const QString &Language)
{
    ActiveLanguage = Language == "zh_CN" ? "zh_CN" : "en_US";
    for (QWidget *Window : QApplication::topLevelWidgets())
        TranslateObjectTree(Window);
}

QString DecodeMultiByteText(UINT CodePage, DWORD Flags, const QByteArray &Bytes)
{
    if (Bytes.isEmpty())
        return {};
    const int WideLength = MultiByteToWideChar(CodePage, Flags, Bytes.constData(), Bytes.size(), nullptr, 0);
    if (WideLength <= 0)
        return {};
    std::wstring Wide(static_cast<size_t>(WideLength), L'\0');
    if (MultiByteToWideChar(CodePage, Flags, Bytes.constData(), Bytes.size(), Wide.data(), WideLength) <= 0)
        return {};
    return QString::fromWCharArray(Wide.data(), WideLength);
}

QString DecodeConsoleProcessOutput(const QByteArray &Bytes)
{
    if (Bytes.isEmpty())
        return {};

    if (Bytes.size() >= 2)
    {
        const uchar B0 = static_cast<uchar>(Bytes[0]);
        const uchar B1 = static_cast<uchar>(Bytes[1]);
        if ((B0 == 0xFF && B1 == 0xFE) || (B0 == 0xFE && B1 == 0xFF))
            return QString::fromUtf16(reinterpret_cast<const char16_t *>(Bytes.constData() + 2),
                                      (Bytes.size() - 2) / 2);
    }

    int ZeroCount = 0;
    for (char Byte : Bytes)
        ZeroCount += (Byte == '\0');
    if (ZeroCount >= Bytes.size() / 4)
        return QString::fromUtf16(reinterpret_cast<const char16_t *>(Bytes.constData()), Bytes.size() / 2);

    if (const QString Utf8 = DecodeMultiByteText(CP_UTF8, MB_ERR_INVALID_CHARS, Bytes); !Utf8.isEmpty())
        return Utf8;
    if (const QString Oem = DecodeMultiByteText(CP_OEMCP, 0, Bytes); !Oem.isEmpty())
        return Oem;
    if (const QString Ansi = DecodeMultiByteText(CP_ACP, 0, Bytes); !Ansi.isEmpty())
        return Ansi;
    return QString::fromLatin1(Bytes);
}

