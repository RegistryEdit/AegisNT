QWidget *CreateSettingsPage()
{
    auto *Content = new QWidget;
    Content->setObjectName("SettingsContent");
    auto *Layout = new QVBoxLayout(Content);
    Layout->setContentsMargins(0, 0, 0, 0);
    Layout->setSpacing(12);
    const auto ThemeUiSyncing = std::make_shared<bool>(false);

    const auto AddSection = [Layout](const QString &Title) {
        auto *Label = MakeLabel(Title, 15, KAccent, QFont::DemiBold);
        Label->setContentsMargins(2, 10, 0, 2);
        Layout->addWidget(Label);
    };

    const auto AddSetting = [Layout](const QString &Title, const QString &Description, QWidget *Control) {
        auto *Row = new QFrame;
        Row->setObjectName("settingRow");
        Row->setMinimumHeight(64);
        auto *RowLayout = new QHBoxLayout(Row);
        RowLayout->setContentsMargins(16, 8, 16, 8);
        auto *TextLayout = new QVBoxLayout;
        TextLayout->setSpacing(2);
        TextLayout->addWidget(MakeLabel(Title, 10, KTextPrimary, QFont::DemiBold));
        TextLayout->addWidget(MakeLabel(Description, 9, KTextMuted));
        RowLayout->addLayout(TextLayout, 1);
        RowLayout->addWidget(Control);
        Layout->addWidget(Row);
    };

    AddSection("Language");

    auto *Language = new ComboBox;
    Language->addItems({"English", "Chinese"});
    Language->setItemData(0, "en_US", Qt::UserRole);
    Language->setItemData(1, "zh_CN", Qt::UserRole);
    Language->setProperty("LanguageOriginal_items",
                          QStringList{"English", "Chinese"});
    Language->setProperty("ApplicationLanguageSelector", true);
    Language->setItemText(0, TranslateText("English"));
    Language->setItemText(1, TranslateText("Chinese"));
    Language->setCurrentIndex(ActiveLanguage == "zh_CN" ? 1 : 0);
    Language->setMinimumWidth(154);
    AddSetting("Display language", "Choose the language used by the application interface.", Language);
    QObject::connect(Language, &ComboBox::currentIndexChanged, Content, [Content, Language](int Index) {
        const QString LanguageCode = Language->itemData(Index, Qt::UserRole).toString() == "zh_CN"
            ? "zh_CN" : "en_US";
        SetConfigurationValue("Application", "Language", LanguageCode);
        ApplyApplicationLanguage(LanguageCode);
        {
            const QSignalBlocker Blocker(Language);
            Language->setItemText(0, TranslateText("English"));
            Language->setItemText(1, TranslateText("Chinese"));
            Language->setCurrentIndex(-1);
            Language->setCurrentIndex(LanguageCode == "zh_CN" ? 1 : 0);
            Language->update();
        }
        ShowSuccessNotice(Content, TranslateText("Settings"), TranslateText("Display language updated."));
    });

    AddSection("Theme");

    auto *DarkMode = new SwitchButton;
    DarkMode->setChecked(ConfigurationValue("Theme", "DarkMode", KDefaultThemeDarkMode).toBool());
    AddSetting("Dark mode", "Switch between the light and dark QFluent themes.", DarkMode);
    QObject::connect(DarkMode, &SwitchButton::checkedChanged, Content, [Content, ThemeUiSyncing](bool Checked) {
        if (*ThemeUiSyncing)
            return;
        SetConfigurationValueTransient("Theme", "DarkMode", Checked);
        QueueThemeApply(Content->window(), true, true);
    });

    auto *BackgroundMaterial = new ComboBox;
    BackgroundMaterial->addItems({"Off", "Mica", "Acrylic"});
    BackgroundMaterial->setCurrentIndex(std::clamp(
        ConfigurationValue("Theme", "BackgroundMaterial", KDefaultThemeBackgroundMaterial).toInt(), 0, 2));
    BackgroundMaterial->setMinimumWidth(154);
    AddSetting("Background material", "Use the Windows Mica or Acrylic backdrop behind the theme.",
               BackgroundMaterial);
    QObject::connect(BackgroundMaterial, &ComboBox::currentIndexChanged, Content,
                     [Content, ThemeUiSyncing](int Index) {
        if (*ThemeUiSyncing)
            return;
        SetConfigurationValueTransient("Theme", "BackgroundMaterial", Index);
        QueueThemeApply(Content->window(), true, true);
    });

    auto *WallpaperControl = new QWidget;
    auto *WallpaperLayout = new QHBoxLayout(WallpaperControl);
    WallpaperLayout->setContentsMargins(0, 0, 0, 0);
    auto *WallpaperPath = new LineEdit;
    WallpaperPath->setReadOnly(true);
    WallpaperPath->setMinimumWidth(280);
    WallpaperPath->setPlaceholderText("No wallpaper selected");
    WallpaperPath->setText(ConfigurationValue("Theme", "WallpaperPath", "").toString());
    auto *SelectWallpaper = new PushButton("Browse", Fluent::IconType::FOLDER);
    auto *ClearWallpaper = MakeButton("Clear");
    ClearWallpaper->setEnabled(!WallpaperPath->text().isEmpty());
    WallpaperLayout->addWidget(WallpaperPath, 1);
    WallpaperLayout->addWidget(SelectWallpaper);
    WallpaperLayout->addWidget(ClearWallpaper);
    AddSetting("Wallpaper", "Display a local image behind the window background and large panel layers.", WallpaperControl);
    QObject::connect(SelectWallpaper, &QPushButton::clicked, Content,
                     [Content, WallpaperPath, ClearWallpaper] {
        const QString Path = QFileDialog::getOpenFileName(
            Content->window(), "Select wallpaper", WallpaperPath->text(),
            "Images (*.png *.jpg *.jpeg *.bmp *.webp);;All files (*.*)");
        if (Path.isEmpty())
            return;
        const QString AbsolutePath = QDir::toNativeSeparators(QFileInfo(Path).absoluteFilePath());
        SetConfigurationValueTransient("Theme", "WallpaperPath", AbsolutePath);
        WallpaperPath->setText(AbsolutePath);
        ClearWallpaper->setEnabled(true);
        QueueThemeApply(Content->window(), true, true);
    });
    QObject::connect(ClearWallpaper, &QPushButton::clicked, Content,
                     [Content, WallpaperPath, ClearWallpaper] {
        SetConfigurationValueTransient("Theme", "WallpaperPath", "");
        WallpaperPath->clear();
        ClearWallpaper->setEnabled(false);
        QueueThemeApply(Content->window(), true, true);
    });

    auto *WallpaperMode = new ComboBox;
    WallpaperMode->addItems({"Fill", "Fit", "Stretch", "Tile"});
    WallpaperMode->setCurrentIndex(std::clamp(ConfigurationValue("Theme", "WallpaperMode", 0).toInt(), 0, 3));
    WallpaperMode->setMinimumWidth(154);
    AddSetting("Wallpaper mode", "Choose how the image is fitted to the application window.", WallpaperMode);
    QObject::connect(WallpaperMode, &ComboBox::currentIndexChanged, Content, [Content, ThemeUiSyncing](int Index) {
        if (*ThemeUiSyncing)
            return;
        SetConfigurationValueTransient("Theme", "WallpaperMode", Index);
        QueueThemeApply(Content->window(), true, true);
    });

    const auto UpdateColorButton = [](PushButton *Button, const QColor &Color) {
        QPixmap Swatch(16, 16);
        Swatch.fill(Color);
        Button->setIcon(QIcon(Swatch));
        Button->setIconSize(QSize(16, 16));
        Button->setText(Color.name(QColor::HexRgb).toUpper());
    };
    const auto ResolveThemeColor = [](const QString &Key) -> QColor {
        const ThemePalette Palette = CurrentThemePalette();
        if (Key == "AccentColor") return Palette.Accent;
        if (Key == "AccentHoverColor") return Palette.AccentHover;
        if (Key == "AccentPressedColor") return Palette.AccentPressed;
        if (Key == "PageBackgroundColor") return Palette.PageBackground;
        if (Key == "CardSurfaceColor") return Palette.CardSurface;
        if (Key == "SurfaceElevatedColor") return Palette.ElevatedSurface;
        if (Key == "SurfaceSunkenColor") return Palette.SunkenSurface;
        if (Key == "InputSurfaceColor") return Palette.InputSurface;
        if (Key == "TableSurfaceColor") return Palette.TableSurface;
        if (Key == "PopupSurfaceColor") return Palette.PopupSurface;
        if (Key == "BorderColor") return Palette.Border;
        if (Key == "DividerColor") return Palette.Divider;
        if (Key == "TextColor") return Palette.Text;
        if (Key == "MutedTextColor") return Palette.MutedText;
        if (Key == "SelectionTextColor") return Palette.SelectionText;
        if (Key == "DangerColor") return Palette.Danger;
        if (Key == "WarningColor") return Palette.Warning;
        if (Key == "SuccessColor") return Palette.Success;
        return QColor();
    };
    QMap<QString, PushButton *> ThemeColorButtons;
    const auto AddColorSetting = [AddSetting, Content, UpdateColorButton, ThemeUiSyncing](const QString &Title, const QString &Description,
                                                                                           const QString &Key, const QColor &Fallback) {
        const QColor CurrentColor = ConfiguredColor(Key, Fallback);
        auto *ColorButton = new PushButton(CurrentColor.name(QColor::HexRgb).toUpper());
        ColorButton->setMinimumWidth(154);
        ColorButton->setMinimumHeight(36);
        ColorButton->setStyleSheet("PushButton { padding-left: 12px; padding-right: 14px; }");
        UpdateColorButton(ColorButton, CurrentColor);
        AddSetting(Title, Description, ColorButton);
        QObject::connect(ColorButton, &QPushButton::clicked, Content, [Content, ColorButton, UpdateColorButton, Key, Fallback, Title, ThemeUiSyncing] {
            if (*ThemeUiSyncing)
                return;
            ColorDialog Dialog(ConfiguredColor(Key, Fallback), "Select " + Title, Content->window(), true);
            const QMap<QString, QString> ColorDialogTranslations{
                {QStringLiteral("\u7f16\u8f91\u989c\u8272"), "Edit color"},
                {QStringLiteral("\u65b0\u989c\u8272"), "New color"},
                {QStringLiteral("\u539f\u989c\u8272"), "Original color"},
                {QStringLiteral("\u5f53\u524d\u989c\u8272"), "Current color"},
                {QStringLiteral("\u7ea2\u8272"), "Red"},
                {QStringLiteral("\u7eff\u8272"), "Green"},
                {QStringLiteral("\u84dd\u8272"), "Blue"},
                {QStringLiteral("\u4e0d\u900f\u660e\u5ea6"), "Opacity"},
                {QStringLiteral("\u900f\u660e\u5ea6"), "Opacity"},
                {QStringLiteral("\u900f\u660e"), "Opacity"},
                {QStringLiteral("\u786e\u5b9a"), "OK"},
                {QStringLiteral("\u53d6\u6d88"), "Cancel"},
            };
            const auto TranslateColorDialog = [&Dialog, &ColorDialogTranslations] {
                for (QLabel *Label : Dialog.findChildren<QLabel *>())
                {
                    const auto It = ColorDialogTranslations.constFind(Label->text().trimmed());
                    if (It != ColorDialogTranslations.cend())
                        Label->setText(*It);
                }
                for (QAbstractButton *Button : Dialog.findChildren<QAbstractButton *>())
                {
                    const auto It = ColorDialogTranslations.constFind(Button->text().trimmed());
                    if (It != ColorDialogTranslations.cend())
                        Button->setText(*It);
                }
            };
            TranslateColorDialog();
            QTimer::singleShot(0, &Dialog, TranslateColorDialog);
            if (Dialog.exec() != QDialog::Accepted)
                return;
            const QColor Selected = Dialog.color();
            SetConfigurationValueTransient("Theme", Key, Selected.name(QColor::HexRgb).toUpper());
            UpdateColorButton(ColorButton, Selected);
            QueueThemeApply(Content->window(), true, true);
        });
        return ColorButton;
    };

    AddSection("Theme preview");
    auto *PreviewCard = new QFrame;
    PreviewCard->setObjectName("ThemePreviewCard");
    auto *PreviewLayout = new QVBoxLayout(PreviewCard);
    PreviewLayout->setContentsMargins(16, 16, 16, 16);
    PreviewLayout->setSpacing(12);
    auto *PreviewNav = new QFrame;
    PreviewNav->setObjectName("ThemePreviewNavItem");
    auto *PreviewNavLayout = new QHBoxLayout(PreviewNav);
    PreviewNavLayout->setContentsMargins(12, 8, 12, 8);
    PreviewNavLayout->addWidget(MakeLabel("Navigation item", 11, KTextPrimary, QFont::DemiBold));
    PreviewNavLayout->addStretch();
    PreviewNavLayout->addWidget(MakeLabel("Active", 10, KTextMuted));
    PreviewLayout->addWidget(PreviewNav);
    auto *PreviewRow = new QFrame;
    PreviewRow->setObjectName("ThemePreviewTableRow");
    auto *PreviewRowLayout = new QHBoxLayout(PreviewRow);
    PreviewRowLayout->setContentsMargins(12, 8, 12, 8);
    PreviewRowLayout->addWidget(MakeLabel("Table row / entry", 10, KTextPrimary, QFont::Normal), 1);
    auto *Good = new QFrame; Good->setObjectName("ThemePreviewStatusGood"); Good->setFixedSize(44, 24);
    auto *Warn = new QFrame; Warn->setObjectName("ThemePreviewStatusWarn"); Warn->setFixedSize(44, 24);
    auto *Danger = new QFrame; Danger->setObjectName("ThemePreviewStatusDanger"); Danger->setFixedSize(44, 24);
    PreviewRowLayout->addWidget(Good);
    PreviewRowLayout->addWidget(Warn);
    PreviewRowLayout->addWidget(Danger);
    PreviewLayout->addWidget(PreviewRow);
    auto *PreviewControls = new QHBoxLayout;
    PreviewControls->setContentsMargins(0, 0, 0, 0);
    PreviewControls->setSpacing(8);
    auto *PreviewInput = new LineEdit;
    PreviewInput->setPlaceholderText("Input field");
    auto *PreviewButton = MakeButton("Primary", true);
    auto *PreviewGhost = MakeButton("Secondary");
    PreviewControls->addWidget(PreviewInput, 1);
    PreviewControls->addWidget(PreviewGhost);
    PreviewControls->addWidget(PreviewButton);
    PreviewLayout->addLayout(PreviewControls);
    Layout->addWidget(PreviewCard);

    const auto RegisterColorSetting = [&](const QString &Title, const QString &Description,
                                          const QString &Key, const QColor &Fallback) -> PushButton * {
        PushButton *Button = AddColorSetting(Title, Description, Key, Fallback);
        ThemeColorButtons.insert(Key, Button);
        return Button;
    };
    const auto SyncThemeColorButtons = [&ThemeColorButtons, UpdateColorButton, ResolveThemeColor] {
        for (auto It = ThemeColorButtons.begin(); It != ThemeColorButtons.end(); ++It)
            UpdateColorButton(It.value(), ResolveThemeColor(It.key()));
    };

    AddSection("Brand colors");
    auto *AccentColor = RegisterColorSetting("Accent", "Primary brand color for selected navigation and main actions.",
                                             "AccentColor", ResolveThemeColor("AccentColor"));
    auto *AccentHoverColor = RegisterColorSetting("Accent hover", "Hover state for primary interactive elements.",
                                                  "AccentHoverColor", ResolveThemeColor("AccentHoverColor"));
    auto *AccentPressedColor = RegisterColorSetting("Accent pressed", "Pressed state for primary interactive elements.",
                                                    "AccentPressedColor", ResolveThemeColor("AccentPressedColor"));

    AddSection("Background layers");
    auto *PageBackgroundColor = RegisterColorSetting("Page background", "Window content background under panels.",
                                                     "PageBackgroundColor", ResolveThemeColor("PageBackgroundColor"));
    auto *CardSurfaceColor = RegisterColorSetting("Card background", "Primary card and panel surface.",
                                                  "CardSurfaceColor", ResolveThemeColor("CardSurfaceColor"));
    auto *ElevatedSurfaceColor = RegisterColorSetting("Elevated surface", "Dialogs, previews, and higher-level panels.",
                                                      "SurfaceElevatedColor", ResolveThemeColor("SurfaceElevatedColor"));
    auto *SunkenSurfaceColor = RegisterColorSetting("Sunken surface", "Header, separators, and recessed layers.",
                                                    "SurfaceSunkenColor", ResolveThemeColor("SurfaceSunkenColor"));
    auto *InputSurfaceColor = RegisterColorSetting("Input background", "Line edit, combo, and editor backgrounds.",
                                                   "InputSurfaceColor", ResolveThemeColor("InputSurfaceColor"));
    auto *TableSurfaceColor = RegisterColorSetting("Table background", "List and table rows without wallpaper bleed.",
                                                   "TableSurfaceColor", ResolveThemeColor("TableSurfaceColor"));
    auto *PopupSurfaceColor = RegisterColorSetting("Popup background", "Menu, preview, and floating surface background.",
                                                   "PopupSurfaceColor", ResolveThemeColor("PopupSurfaceColor"));
    auto *BorderColor = RegisterColorSetting("Border", "Primary outline for cards and controls.",
                                             "BorderColor", ResolveThemeColor("BorderColor"));
    auto *DividerColor = RegisterColorSetting("Divider", "Subtle separators and table grid lines.",
                                              "DividerColor", ResolveThemeColor("DividerColor"));

    AddSection("Text layers");
    auto *TextColor = RegisterColorSetting("Primary text", "Main labels, values, and control text.",
                                           "TextColor", ResolveThemeColor("TextColor"));
    auto *MutedColor = RegisterColorSetting("Secondary text", "Descriptions, status text, and placeholders.",
                                            "MutedTextColor", ResolveThemeColor("MutedTextColor"));
    auto *SelectionTextColor = RegisterColorSetting("Selected text", "Text color shown over accent selections.",
                                                    "SelectionTextColor", ResolveThemeColor("SelectionTextColor"));

    AddSection("Feedback colors");
    auto *DangerColor = RegisterColorSetting("Danger", "Destructive operations and alert states.",
                                             "DangerColor", ResolveThemeColor("DangerColor"));
    auto *WarningColor = RegisterColorSetting("Warning", "Caution states and degraded status.",
                                              "WarningColor", ResolveThemeColor("WarningColor"));
    auto *SuccessColor = RegisterColorSetting("Success", "Healthy state and successful actions.",
                                              "SuccessColor", ResolveThemeColor("SuccessColor"));
    const auto AddThemeSlider = [AddSetting, Content, ThemeUiSyncing](const QString &Title, const QString &Description,
                                                                      const QString &Key, int Minimum, int Maximum,
                                                                      int DefaultValue, const QString &Suffix) {
        auto *Control = new QWidget;
        auto *ControlLayout = new QHBoxLayout(Control);
        ControlLayout->setContentsMargins(0, 0, 0, 0);
        auto *ValueSlider = new Slider(Qt::Horizontal);
        ValueSlider->setRange(Minimum, Maximum);
        ValueSlider->setValue(std::clamp(ConfigurationValue("Theme", Key, DefaultValue).toInt(), Minimum, Maximum));
        ValueSlider->setMinimumWidth(220);
        auto *ValueLabel = new StrongBodyLabel(QString::number(ValueSlider->value()) + Suffix);
        ValueLabel->setMinimumWidth(58);
        ValueLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        ControlLayout->addWidget(ValueSlider);
        ControlLayout->addWidget(ValueLabel);
        AddSetting(Title, Description, Control);
        auto *PreviewTimer = new QTimer(ValueSlider);
        PreviewTimer->setSingleShot(true);
        PreviewTimer->setInterval(60);
        auto *SaveTimer = new QTimer(ValueSlider);
        SaveTimer->setSingleShot(true);
        SaveTimer->setInterval(250);
        QObject::connect(PreviewTimer, &QTimer::timeout, Content,
                         [Content, ThemeUiSyncing] {
            if (*ThemeUiSyncing)
                return;
            QueueThemeApply(Content->window(), false, true);
        });
        QObject::connect(SaveTimer, &QTimer::timeout, Content, [] { SaveConfiguration(); });
        QObject::connect(ValueSlider, &QSlider::valueChanged, Content,
                         [ValueLabel, Key, Suffix, PreviewTimer, SaveTimer, ThemeUiSyncing](int Value) {
            ValueLabel->setText(QString::number(Value) + Suffix);
            if (*ThemeUiSyncing)
                return;
            SetConfigurationValueTransient("Theme", Key, Value);
            PreviewTimer->start();
            SaveTimer->start();
        });
        return ValueSlider;
    };

    auto *CornerRadius = AddThemeSlider("Corner radius", "Roundness of panels and setting rows.",
                                        "CornerRadius", 0, 12, KDefaultThemeCornerRadius, " px");
    auto *FontScale = AddThemeSlider("Font scale", "Scale application text without changing window dimensions.",
                                     "FontScale", 85, 125, KDefaultThemeFontScale, "%");
    auto *Density = AddThemeSlider("Interface density", "Adjust menu and table header spacing.",
                                   "Density", 80, 120, KDefaultThemeDensity, "%");
    auto *WallpaperOpacity = AddThemeSlider("Wallpaper opacity", "Control wallpaper visibility behind panels and content.",
                                            "WallpaperOpacity", 5, 100, KDefaultThemeWallpaperOpacity, "%");

    auto *ResetTheme = new PushButton("Restore default theme", Fluent::IconType::RETURN);
    AddSetting("Restore defaults", "Reset theme mode and all custom colors.", ResetTheme);
    QObject::connect(ResetTheme, &QPushButton::clicked, Content,
                     [Content, DarkMode, BackgroundMaterial, WallpaperPath, ClearWallpaper, WallpaperMode,
                      CornerRadius, FontScale, Density, WallpaperOpacity, SyncThemeColorButtons, ThemeUiSyncing] {
        QJsonObject ThemeObject = ConfigurationSection("Theme");
        ApplyDefaultThemeValues(ThemeObject);
        ThemeObject.insert("WallpaperPath", "");
        ThemeObject.insert("WallpaperMode", 0);
        Configuration.insert("Theme", ThemeObject);
        *ThemeUiSyncing = true;
        const QSignalBlocker BlockDarkMode(DarkMode);
        const QSignalBlocker BlockBackgroundMaterial(BackgroundMaterial);
        const QSignalBlocker BlockWallpaperMode(WallpaperMode);
        const QSignalBlocker BlockCornerRadius(CornerRadius);
        const QSignalBlocker BlockFontScale(FontScale);
        const QSignalBlocker BlockDensity(Density);
        const QSignalBlocker BlockWallpaperOpacity(WallpaperOpacity);
        DarkMode->setChecked(ConfigurationValue("Theme", "DarkMode", KDefaultThemeDarkMode).toBool());
        BackgroundMaterial->setCurrentIndex(ConfigurationValue("Theme", "BackgroundMaterial", KDefaultThemeBackgroundMaterial).toInt());
        WallpaperPath->clear();
        ClearWallpaper->setEnabled(false);
        WallpaperMode->setCurrentIndex(0);
        SyncThemeColorButtons();
        CornerRadius->setValue(ConfigurationValue("Theme", "CornerRadius", KDefaultThemeCornerRadius).toInt());
        FontScale->setValue(ConfigurationValue("Theme", "FontScale", KDefaultThemeFontScale).toInt());
        Density->setValue(ConfigurationValue("Theme", "Density", KDefaultThemeDensity).toInt());
        WallpaperOpacity->setValue(ConfigurationValue("Theme", "WallpaperOpacity", KDefaultThemeWallpaperOpacity).toInt());
        *ThemeUiSyncing = false;
        QueueThemeApply(Content->window(), true, true);
    });

    AddSection("Module paths");

    auto *ModulePath = new BodyLabel(ConfigurationPaths("Modules", "./Modules").join("; "));
    ModulePath->setMinimumWidth(260);
    ModulePath->setWordWrap(true);
    auto *BrowseModules = new PushButton("Browse", Fluent::IconType::FOLDER);
    auto *ModulePathControl = new QWidget;
    auto *ModulePathLayout = new QHBoxLayout(ModulePathControl);
    ModulePathLayout->setContentsMargins(0, 0, 0, 0);
    ModulePathLayout->addWidget(ModulePath, 1);
    ModulePathLayout->addWidget(BrowseModules);
    AddSetting("Modules", "Select the DLL module directory.", ModulePathControl);
    QObject::connect(BrowseModules, &QPushButton::clicked, Content, [Content, ModulePath] {
        const QString Directory = QFileDialog::getExistingDirectory(Content->window(), "Select module directory",
                                                                    ConfigurationPaths("Modules", "./Modules").first());
        if (Directory.isEmpty())
            return;
        SetConfigurationPath("Modules", QDir::toNativeSeparators(Directory));
        ModulePath->setText(QDir::toNativeSeparators(Directory));
        ShowSuccessNotice(Content, "Settings", "Module path updated.");
    });

    auto *ModuleAutoLoad = new SwitchButton;
    ModuleAutoLoad->setChecked(ConfigurationValue("Modules", "AutoLoad", true).toBool());
    AddSetting("Load modules after scan", "Automatically enable discovered DLL modules.", ModuleAutoLoad);
    QObject::connect(ModuleAutoLoad, &SwitchButton::checkedChanged, Content,
                     [Content](bool Checked) { SetConfigurationValue("Modules", "AutoLoad", Checked); ShowSuccessNotice(Content, "Settings", Checked ? "Module auto-load enabled." : "Module auto-load disabled."); });

    auto *DriverPath = new BodyLabel(ConfigurationPaths("Drivers", "./Drivers").join("; "));
    DriverPath->setMinimumWidth(260);
    DriverPath->setWordWrap(true);
    auto *BrowseDrivers = new PushButton("Browse", Fluent::IconType::FOLDER);
    auto *DriverPathControl = new QWidget;
    auto *DriverPathLayout = new QHBoxLayout(DriverPathControl);
    DriverPathLayout->setContentsMargins(0, 0, 0, 0);
    DriverPathLayout->addWidget(DriverPath, 1);
    DriverPathLayout->addWidget(BrowseDrivers);
    AddSetting("Drivers", "Select the kernel driver directory.", DriverPathControl);
    QObject::connect(BrowseDrivers, &QPushButton::clicked, Content, [Content, DriverPath] {
        const QString Directory = QFileDialog::getExistingDirectory(Content->window(), "Select driver directory",
                                                                    ConfigurationPaths("Drivers", "./Drivers").first());
        if (Directory.isEmpty())
            return;
        SetConfigurationPath("Drivers", QDir::toNativeSeparators(Directory));
        DriverPath->setText(QDir::toNativeSeparators(Directory));
        ShowSuccessNotice(Content, "Settings", "Driver path updated.");
    });

    auto *DriverAutoLoad = new SwitchButton;
    DriverAutoLoad->setChecked(ConfigurationValue("Drivers", "AutoLoad", true).toBool());
    AddSetting("Load drivers after scan", "Automatically enable discovered kernel drivers.", DriverAutoLoad);
    QObject::connect(DriverAutoLoad, &SwitchButton::checkedChanged, Content,
                     [Content](bool Checked) { SetConfigurationValue("Drivers", "AutoLoad", Checked); ShowSuccessNotice(Content, "Settings", Checked ? "Driver auto-load enabled." : "Driver auto-load disabled."); });

    AddSection("Application");

    const int Width = ConfigurationValue("Application", "Width", 1600).toInt();
    const int Height = ConfigurationValue("Application", "Height", 1000).toInt();
    const int Fps = qRound(ConfigurationValue("Application", "FPS", 90.0).toDouble());
    AddSetting("Window size", "Configured startup dimensions.",
               new StrongBodyLabel(QString("%1 x %2").arg(Width).arg(Height)));
    AddSetting("Frame rate", "Configured rendering frame rate.", new StrongBodyLabel(QString::number(Fps) + " FPS"));

    auto *OpacityControl = new QWidget;
    auto *OpacityLayout = new QHBoxLayout(OpacityControl);
    OpacityLayout->setContentsMargins(0, 0, 0, 0);
    auto *Opacity = new Slider(Qt::Horizontal);
    Opacity->setRange(35, 100);
    Opacity->setValue(qRound(ConfigurationValue("Application", "Opacity", 1.0).toDouble() * 100.0));
    Opacity->setMinimumWidth(220);
    auto *OpacityValue = new StrongBodyLabel(QString::number(Opacity->value()) + "%");
    OpacityValue->setMinimumWidth(48);
    OpacityValue->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    OpacityLayout->addWidget(Opacity);
    OpacityLayout->addWidget(OpacityValue);
    AddSetting("Window opacity", "Adjust the current window transparency from 35% to 100%.", OpacityControl);
    auto *OpacitySaveTimer = new QTimer(Opacity);
    OpacitySaveTimer->setSingleShot(true);
    OpacitySaveTimer->setInterval(250);
    QObject::connect(OpacitySaveTimer, &QTimer::timeout, Content, [] { SaveConfiguration(); });
    QObject::connect(Opacity, &QSlider::valueChanged, Content, [Content, OpacityValue, OpacitySaveTimer](int Value) {
        OpacityValue->setText(QString::number(Value) + "%");
        SetConfigurationValueTransient("Application", "Opacity", Value / 100.0);
        Content->window()->setWindowOpacity(Value / 100.0);
        OpacitySaveTimer->start();
    });

    AddSection("About");
    AddSetting("Version", "Current AegisNT release.",
               new StrongBodyLabel(ConfigurationValue("Application", "Version", "1.0.0").toString()));
    AddSetting("Author", "Application author.", new StrongBodyLabel("RegistryEdit"));

    Layout->addStretch();
    auto *Scroll = new ScrollArea;
    InstallFluentScrollBar(Scroll, Qt::Vertical);
    Scroll->setObjectName("SettingsScroll");
    Scroll->setWidgetResizable(true);
    Scroll->setFrameShape(QFrame::NoFrame);
    Scroll->viewport()->setAutoFillBackground(false);
    Scroll->setWidget(Content);
    return WrapPage(Scroll);
}

