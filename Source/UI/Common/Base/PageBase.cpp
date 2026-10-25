#include "PageBase.h"
#include "../Widgets/FluentCompatibility.h"
#include <QMetaObject>
#include <thread>

namespace AegisNT {

void PageBase::ShowError(const QString &message) {
    ShowFluentMessage(this, tr("Error"), message);
}

void PageBase::ShowSuccess(const QString &message) {
    ShowFluentMessage(this, tr("Success"), message);
}

void PageBase::ShowWarning(const QString &message) {
    ShowFluentMessage(this, tr("Warning"), message);
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
