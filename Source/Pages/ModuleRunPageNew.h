#pragma once

#include "../UI/Common/Base/PageBase.h"
#include "../Services/IDriverService.h"
#include <QComboBox>
#include <QLabel>
#include <QTableWidget>
#include <QPushButton>
#include <QVBoxLayout>

namespace AegisNT {

/**
 * ModuleRunPage - 模块运行页面（重构版）
 *
 * 使用新架构：
 * - 继承 PageBase
 * - 依赖注入 IDriverService
 * - 清晰的职责分离
 */
class ModuleRunPage : public PageBase {
    Q_OBJECT

public:
    explicit ModuleRunPage(IDriverService *driverService, QWidget *parent = nullptr);
    ~ModuleRunPage() override;

    // 页面生命周期
    void OnPageShow() override;
    void OnPageRefresh() override;

private slots:
    void OnCategoryChanged(int index);
    void OnModuleChanged(int index);
    void OnRefreshClicked();
    void OnCheckClicked();
    void OnRunClicked();
    void OnStopClicked();
    void OnShowOutputClicked();

private:
    // UI 初始化
    void InitializeUI();
    void CreateToolbar();
    void CreateInformationLabel();
    void CreateOptionsTable();
    void CreateOutputToolbar();

    // 业务逻辑
    void LoadModuleList();
    void PopulateModules(const QString &category);
    void PopulateOptions();
    void RunModule();
    void StopModule();

    // UI 组件
    QComboBox *m_categoryCombo;
    QComboBox *m_moduleCombo;
    QPushButton *m_refreshBtn;
    QPushButton *m_checkBtn;
    QPushButton *m_runBtn;
    QPushButton *m_stopBtn;
    QLabel *m_informationLabel;
    QTableWidget *m_optionsTable;
    QPushButton *m_outputBtn;

    // 状态
    bool m_moduleRunning;
};

// 工厂函数（保持向后兼容）
QWidget *CreateModuleRunPage();

} // namespace AegisNT
