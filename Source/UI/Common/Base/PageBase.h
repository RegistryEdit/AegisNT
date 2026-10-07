#pragma once

#include "../../../Services/IDriverService.h"
#include <QWidget>
#include <QVBoxLayout>
#include <atomic>
#include <memory>

namespace AegisNT {

/**
 * PageBase - 所有页面的基类
 *
 * 提供：
 * - 服务注入
 * - 生命周期管理
 * - 统一的错误处理
 */
class PageBase : public QWidget {
    Q_OBJECT

public:
    explicit PageBase(IDriverService *driverService, QWidget *parent = nullptr)
        : QWidget(parent), m_driverService(driverService) {
        m_mainLayout = new QVBoxLayout(this);
        m_mainLayout->setContentsMargins(20, 20, 20, 20);
        m_mainLayout->setSpacing(12);
    }

    virtual ~PageBase() = default;

    // 页面生命周期
    virtual void OnPageShow() {}
    virtual void OnPageHide() {}
    virtual void OnPageRefresh() {}

public:
    // 访问服务
    IDriverService *GetDriverService() const { return m_driverService; }

    // 主布局
    QVBoxLayout *GetMainLayout() const { return m_mainLayout; }

    // 错误处理
    void ShowError(const QString &message);
    void ShowSuccess(const QString &message);
    void ShowWarning(const QString &message);

private:
    IDriverService *m_driverService;
    QVBoxLayout *m_mainLayout;
};

/**
 * RefreshablePageBase - 支持后台刷新的页面基类
 */
class RefreshablePageBase : public PageBase {
    Q_OBJECT

public:
    explicit RefreshablePageBase(IDriverService *driverService,
                                QWidget *parent = nullptr)
        : PageBase(driverService, parent), m_refreshing(false) {}

    virtual ~RefreshablePageBase() {
        StopRefresh();
    }

    // 刷新控制
    void StartRefresh();
    void StopRefresh();
    bool IsRefreshing() const { return m_refreshing.load(); }

protected:
    // 子类实现具体刷新逻辑
    virtual void DoRefresh() = 0;

    // 刷新完成后在 UI 线程调用
    virtual void OnRefreshComplete() {}

signals:
    void RefreshStarted();
    void RefreshFinished();

private:
    std::atomic_bool m_refreshing;
};

} // namespace AegisNT
