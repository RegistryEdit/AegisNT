#pragma once

#include <QHBoxLayout>
#include <QPushButton>
#include <QWidget>

namespace AegisNT {

/**
 * RefreshControl - 刷新控制组件
 *
 * 包含刷新按钮和进度指示
 */
class RefreshControl : public QWidget {
    Q_OBJECT

public:
    explicit RefreshControl(QWidget *parent = nullptr);

    void SetRefreshing(bool refreshing);
    bool IsRefreshing() const { return m_refreshing; }

signals:
    void RefreshClicked();

private:
    QPushButton *m_refreshButton;
    bool m_refreshing = false;
};

} // namespace AegisNT
