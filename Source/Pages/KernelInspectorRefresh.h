#pragma once

#include <QAbstractButton>
#include <QEvent>
#include <QObject>
#include <QPointer>
#include <QTimer>
#include <QWidget>

// All scheduling runs on the GUI thread. A single timer coalesces page/tab
// changes and defers requests while the refresh button is disabled.
class KernelInspectorRefresh final : public QObject {
public:
  KernelInspectorRefresh(QWidget *Page, QAbstractButton *Refresh)
      : QObject(Page), Page(Page), Refresh(Refresh), Timer(new QTimer(this)) {
    Timer->setSingleShot(true);
    Page->installEventFilter(this);
    connect(Timer, &QTimer::timeout, this, [this] {
      if (!this->Page || !this->Page->isVisible() || !this->Refresh)
        return;
      if (!this->Refresh->isEnabled()) {
        Timer->start(250);
        return;
      }
      Dispatching = true;
      this->Refresh->click();
      Dispatching = false;
    });
    connect(Refresh, &QAbstractButton::clicked, this, [this] {
      if (!Dispatching) {
        RetriesRemaining = MaxRetries;
        Timer->stop();
      }
    });
  }

  void RequestRefresh() {
    RetriesRemaining = MaxRetries;
    if (Page && Page->isVisible())
      Timer->start(0);
  }

  bool RefreshCompleted(bool Incomplete) {
    if (!Incomplete || !Page || !Page->isVisible())
      return false;
    if (Timer->isActive())
      return true;
    if (RetriesRemaining == 0)
      return false;
    const int DelayMs = 1000 << (MaxRetries - RetriesRemaining);
    --RetriesRemaining;
    Timer->start(DelayMs);
    return true;
  }

protected:
  bool eventFilter(QObject *Watched, QEvent *Event) override {
    if (Watched == Page) {
      if (Event->type() == QEvent::Show)
        RequestRefresh();
      else if (Event->type() == QEvent::Hide)
        Timer->stop();
    }
    return QObject::eventFilter(Watched, Event);
  }

private:
  static constexpr int MaxRetries = 3;
  QPointer<QWidget> Page;
  QPointer<QAbstractButton> Refresh;
  QTimer *Timer;
  int RetriesRemaining = MaxRetries;
  bool Dispatching = false;
};
