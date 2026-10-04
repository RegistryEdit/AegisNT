#include "PageBase.h"
#include <QMessageBox>
#include <QMetaObject>
#include <thread>

namespace AegisNT {

void PageBase::ShowError(const QString &message) {
    QMessageBox::critical(this, tr("Error"), message);
}

void PageBase::ShowSuccess(const QString &message) {
    QMessageBox::information(this, tr("Success"), message);
}

void PageBase::ShowWarning(const QString &message) {
    QMessageBox::warning(this, tr("Warning"), message);
}

void RefreshablePageBase::StartRefresh() {
    if (m_refreshing.exchange(true))
        return;

    emit RefreshStarted();

    std::thread([this]() {
        DoRefresh();

        QMetaObject::invokeMethod(this, [this]() {
            m_refreshing = false;
            OnRefreshComplete();
            emit RefreshFinished();
        }, Qt::QueuedConnection);
    }).detach();
}

void RefreshablePageBase::StopRefresh() {
    m_refreshing = false;
}

} // namespace AegisNT
