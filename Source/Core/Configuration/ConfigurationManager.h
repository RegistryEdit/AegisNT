#pragma once

#include <QJsonObject>
#include <QString>
#include <atomic>

namespace AegisNT {

/**
 * ConfigurationManager - 配置文件管理器
 *
 * 职责：
 * - 从 Data/Config.json 加载和保存配置
 * - 按 Section/Key 访问配置值
 * - 主题配置管理（预设、壁纸、Backdrop 材质）
 * - 配置变更通知（通过配置代数）
 */
class ConfigurationManager {
public:
    ConfigurationManager();
    ~ConfigurationManager();

    // 配置加载/保存
    void LoadConfiguration();
    void SaveConfiguration();
    QString ConfigurationPath() const;

    // 配置访问
    QJsonValue GetValue(const QString &Section, const QString &Key,
                        const QJsonValue &Fallback = QJsonValue()) const;
    void SetValue(const QString &Section, const QString &Key,
                  const QJsonValue &Value);

    QJsonObject GetSection(const QString &Section) const;
    void SetSection(const QString &Section, const QJsonObject &Values);

    // 配置代数（用于缓存失效）
    uint64_t CurrentGeneration() const { return Generation.load(); }

    // 便捷访问器 - Application
    int FPS() const;
    int WindowWidth() const;
    int WindowHeight() const;
    QString Language() const;
    double Opacity() const;
    QString AppTitle() const;

    // 主题相关
    QString ThemePreset() const;
    bool DarkMode() const;
    int CornerRadius() const;
    int Density() const;
    int FontScale() const;
    bool UseMonoForTechnicalFields() const;

    // 颜色访问
    QString AccentColor() const;
    QString BackgroundColor() const;
    QString TextColor() const;
    QString DangerColor() const;
    QString SuccessColor() const;
    QString WarningColor() const;

    // 壁纸设置
    int WallpaperMode() const;
    QString WallpaperPath() const;
    int WallpaperOpacity() const;

    // 材质设置（Mica/Acrylic）
    int BackgroundMaterial() const;

    // 驱动/模块路径
    bool DriversAutoLoad() const;
    QStringList DriverPaths() const;
    bool ModulesAutoLoad() const;
    QStringList ModulePaths() const;

    // 服务器配置
    QString LicenseServerAddress() const;
    QString ChatServerIP() const;
    QString ChatServerPort() const;

private:
    QJsonObject Configuration;
    std::atomic<uint64_t> Generation{0};

    void BumpGeneration();
    void LoadDefaults();
};

// 全局实例访问
ConfigurationManager &GlobalConfiguration();

} // namespace AegisNT
