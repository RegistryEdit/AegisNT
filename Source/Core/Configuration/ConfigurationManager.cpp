#include "ConfigurationManager.h"
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QSaveFile>
#include <QStandardPaths>

namespace AegisNT {

namespace {

QString GetConfigPath() {
    return QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
        + "/Data/Config.json";
}

const char *KDefaultConfigJson = R"({
    "Application": {
        "FPS": 90,
        "Height": 1000,
        "Language": "en_US",
        "Opacity": 1,
        "Title": "AegisNT",
        "Width": 1600
    },
    "Chat": {
        "ServerIP": "127.0.0.1",
        "ServerPort": "1145",
        "UserName": ""
    },
    "Drivers": {
        "AutoLoad": true,
        "Paths": ["./Drivers"]
    },
    "LicenseServer": {
        "Address": "http://localhost:8888"
    },
    "Modules": {
        "AutoLoad": true,
        "Paths": ["./Modules"]
    },
    "Payload": {
        "Encoder": [],
        "Nop": []
    },
    "PayloadShell": {
        "Host": "127.0.0.1",
        "Hosts": [{"Host": "127.0.0.1", "Port": "4444"}],
        "Port": "4444",
        "SelectedHost": 0
    },
    "Theme": {
        "AccentColor": "#2E6CFF",
        "AccentHoverColor": "#3E7BFF",
        "AccentPressedColor": "#2458D9",
        "BackgroundColor": "#F4F6FA",
        "BackgroundMaterial": 0,
        "BorderColor": "#D7DDE8",
        "CardSurfaceColor": "#FFFFFF",
        "CornerRadius": 4,
        "DangerColor": "#C53D32",
        "DarkMode": false,
        "Density": 99,
        "DividerColor": "#E6EBF2",
        "EnablePageTransition": true,
        "FontScale": 100,
        "InputSurfaceColor": "#FFFFFF",
        "MutedTextColor": "#667287",
        "PageBackgroundColor": "#F4F6FA",
        "Preset": "default_blue",
        "PopupSurfaceColor": "#FFFFFF",
        "SelectionTextColor": "#FFFFFF",
        "SuccessColor": "#1E8A5D",
        "SurfaceColor": "#FFFFFF",
        "SurfaceElevatedColor": "#F8FAFD",
        "SurfaceSunkenColor": "#EDF1F7",
        "TableSurfaceColor": "#FFFFFF",
        "TextColor": "#18212F",
        "UseMonoForTechnicalFields": true,
        "WallpaperMode": 0,
        "WallpaperOpacity": 28,
        "WallpaperPath": "",
        "WarningColor": "#D98A14"
    }
})";

} // anonymous namespace

ConfigurationManager::ConfigurationManager() {
    LoadConfiguration();
}

ConfigurationManager::~ConfigurationManager() = default;

QString ConfigurationManager::ConfigurationPath() const {
    return GetConfigPath();
}

void ConfigurationManager::LoadConfiguration() {
    const QString Path = ConfigurationPath();

    if (QFile::exists(Path)) {
        QFile File(Path);
        if (!File.open(QIODevice::ReadOnly)) {
            qWarning("Failed to open config file: %s", qPrintable(File.errorString()));
            LoadDefaults();
            return;
        }

        QJsonParseError ParseError;
        QJsonDocument Doc = QJsonDocument::fromJson(File.readAll(), &ParseError);

        if (Doc.isObject()) {
            Configuration = Doc.object();
            BumpGeneration();
        } else {
            qWarning("Invalid JSON in config at offset %d: %s",
                     ParseError.offset, qPrintable(ParseError.errorString()));
            LoadDefaults();
        }
    } else {
        LoadDefaults();
        SaveConfiguration(); // Create default config file
    }
}

void ConfigurationManager::LoadDefaults() {
    QJsonDocument Doc = QJsonDocument::fromJson(QByteArray(KDefaultConfigJson));
    if (Doc.isObject()) {
        Configuration = Doc.object();
        BumpGeneration();
    }
}

void ConfigurationManager::SaveConfiguration() {
    BumpGeneration();

    const QString Path = ConfigurationPath();
    QDir().mkpath(QFileInfo(Path).absolutePath());

    QSaveFile File(Path);
    if (!File.open(QIODevice::WriteOnly)) {
        qWarning("Failed to save config: %s", qPrintable(File.errorString()));
        return;
    }

    QByteArray Bytes = QJsonDocument(Configuration).toJson(QJsonDocument::Indented);
    if (File.write(Bytes) != Bytes.size() || !File.commit()) {
        qWarning("Failed to write config: %s", qPrintable(File.errorString()));
    }
}

QJsonValue ConfigurationManager::GetValue(const QString &Section, const QString &Key,
                                          const QJsonValue &Fallback) const {
    if (!Configuration.contains(Section))
        return Fallback;

    QJsonObject SectionObj = Configuration[Section].toObject();
    return SectionObj.value(Key, Fallback);
}

void ConfigurationManager::SetValue(const QString &Section, const QString &Key,
                                    const QJsonValue &Value) {
    QJsonObject SectionObj = Configuration[Section].toObject();
    SectionObj[Key] = Value;
    Configuration[Section] = SectionObj;
    BumpGeneration();
}

QJsonObject ConfigurationManager::GetSection(const QString &Section) const {
    return Configuration[Section].toObject();
}

void ConfigurationManager::SetSection(const QString &Section, const QJsonObject &Values) {
    Configuration[Section] = Values;
    BumpGeneration();
}

void ConfigurationManager::BumpGeneration() {
    Generation.fetch_add(1, std::memory_order_relaxed);
}

// Application settings
int ConfigurationManager::FPS() const {
    return GetValue("Application", "FPS", 90).toInt();
}

int ConfigurationManager::WindowWidth() const {
    return GetValue("Application", "Width", 1600).toInt();
}

int ConfigurationManager::WindowHeight() const {
    return GetValue("Application", "Height", 1000).toInt();
}

QString ConfigurationManager::Language() const {
    return GetValue("Application", "Language", "en_US").toString();
}

double ConfigurationManager::Opacity() const {
    return GetValue("Application", "Opacity", 1.0).toDouble();
}

QString ConfigurationManager::AppTitle() const {
    return GetValue("Application", "Title", "AegisNT").toString();
}

// Theme settings
QString ConfigurationManager::ThemePreset() const {
    return GetValue("Theme", "Preset", "default_blue").toString();
}

bool ConfigurationManager::DarkMode() const {
    return GetValue("Theme", "DarkMode", false).toBool();
}

int ConfigurationManager::CornerRadius() const {
    return GetValue("Theme", "CornerRadius", 4).toInt();
}

int ConfigurationManager::Density() const {
    return GetValue("Theme", "Density", 99).toInt();
}

int ConfigurationManager::FontScale() const {
    return GetValue("Theme", "FontScale", 100).toInt();
}

bool ConfigurationManager::UseMonoForTechnicalFields() const {
    return GetValue("Theme", "UseMonoForTechnicalFields", true).toBool();
}

// Colors
QString ConfigurationManager::AccentColor() const {
    return GetValue("Theme", "AccentColor", "#2E6CFF").toString();
}

QString ConfigurationManager::BackgroundColor() const {
    return GetValue("Theme", "BackgroundColor", "#F4F6FA").toString();
}

QString ConfigurationManager::TextColor() const {
    return GetValue("Theme", "TextColor", "#18212F").toString();
}

QString ConfigurationManager::DangerColor() const {
    return GetValue("Theme", "DangerColor", "#C53D32").toString();
}

QString ConfigurationManager::SuccessColor() const {
    return GetValue("Theme", "SuccessColor", "#1E8A5D").toString();
}

QString ConfigurationManager::WarningColor() const {
    return GetValue("Theme", "WarningColor", "#D98A14").toString();
}

// Wallpaper
int ConfigurationManager::WallpaperMode() const {
    return GetValue("Theme", "WallpaperMode", 0).toInt();
}

QString ConfigurationManager::WallpaperPath() const {
    return GetValue("Theme", "WallpaperPath", "").toString();
}

int ConfigurationManager::WallpaperOpacity() const {
    return GetValue("Theme", "WallpaperOpacity", 28).toInt();
}

int ConfigurationManager::BackgroundMaterial() const {
    return GetValue("Theme", "BackgroundMaterial", 0).toInt();
}

// Drivers and Modules
bool ConfigurationManager::DriversAutoLoad() const {
    return GetValue("Drivers", "AutoLoad", true).toBool();
}

QStringList ConfigurationManager::DriverPaths() const {
    QJsonArray Arr = GetValue("Drivers", "Paths").toArray();
    QStringList Result;
    for (const auto &Val : Arr)
        Result.append(Val.toString());
    return Result;
}

bool ConfigurationManager::ModulesAutoLoad() const {
    return GetValue("Modules", "AutoLoad", true).toBool();
}

QStringList ConfigurationManager::ModulePaths() const {
    QJsonArray Arr = GetValue("Modules", "Paths").toArray();
    QStringList Result;
    for (const auto &Val : Arr)
        Result.append(Val.toString());
    return Result;
}

// Server settings
QString ConfigurationManager::LicenseServerAddress() const {
    return GetValue("LicenseServer", "Address", "http://localhost:8888").toString();
}

QString ConfigurationManager::ChatServerIP() const {
    return GetValue("Chat", "ServerIP", "127.0.0.1").toString();
}

QString ConfigurationManager::ChatServerPort() const {
    return GetValue("Chat", "ServerPort", "1145").toString();
}

// Global instance
ConfigurationManager &GlobalConfiguration() {
    static ConfigurationManager Instance;
    return Instance;
}

} // namespace AegisNT
