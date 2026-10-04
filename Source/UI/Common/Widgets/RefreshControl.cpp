#include "RefreshControl.h"
#include <QProgressBar>

namespace AegisNT {

RefreshControl::RefreshControl(QWidget *parent) : QWidget(parent) {
    auto *layout = new QHBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);

    m_refreshButton = new QPushButton(tr("Refresh"), this);
    layout->addWidget(m_refreshButton);

    connect(m_refreshButton, &QPushButton::clicked, this, [this]() {
        if (!m_refreshing)
            emit RefreshClicked();
    });
}

void RefreshControl::SetRefreshing(bool refreshing) {
    m_refreshing = refreshing;
    m_refreshButton->setEnabled(!refreshing);
    m_refreshButton->setText(refreshing ? tr("Refreshing...") : tr("Refresh"));
}

} // namespace AegisNT
