#pragma once

#include <QLineEdit>
#include <QTimer>

namespace AegisNT {

/**
 * DebouncedSearchEdit - 带防抖的搜索框
 */
class DebouncedSearchEdit : public QLineEdit {
    Q_OBJECT

public:
    explicit DebouncedSearchEdit(int delayMs = 300, QWidget *parent = nullptr)
        : QLineEdit(parent), m_delayMs(delayMs) {

        m_debounceTimer = new QTimer(this);
        m_debounceTimer->setSingleShot(true);

        connect(this, &QLineEdit::textChanged, this, [this](const QString &text) {
            m_debounceTimer->stop();
            m_debounceTimer->start(m_delayMs);
            m_pendingText = text;
        });

        connect(m_debounceTimer, &QTimer::timeout, this, [this]() {
            emit DebouncedTextChanged(m_pendingText);
        });
    }

    void SetDelay(int delayMs) {
        m_delayMs = delayMs;
    }

signals:
    void DebouncedTextChanged(const QString &text);

private:
    QTimer *m_debounceTimer;
    int m_delayMs;
    QString m_pendingText;
};

} // namespace AegisNT
