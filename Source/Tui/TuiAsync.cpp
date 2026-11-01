// ============================================================
// TUI 异步桥实现：投递队列 + Qt 唤醒 + 同步 HTTP 辅助。
// （unity 包含进 AegisNT.cpp，全局作用域）
// ============================================================

#include "TuiAsync.h"

namespace AegisNT::Tui {

namespace {

std::mutex &QueueMutex() {
  static std::mutex Mutex;
  return Mutex;
}

std::deque<std::function<void()>> &Queue() {
  static std::deque<std::function<void()>> Tasks;
  return Tasks;
}

std::atomic<int> &PendingTasks() {
  static std::atomic<int> Count{0};
  return Count;
}

} // namespace

void TuiPost(std::function<void()> Fn) {
  if (!Fn)
    return;
  {
    std::lock_guard<std::mutex> Lock(QueueMutex());
    Queue().push_back(std::move(Fn));
  }
  // 没有帧循环了：用一次 queued invokeMethod 让主线程排空队列。
  // 重复投递无害，DrainPostedTasks 是幂等的。
  QMetaObject::invokeMethod(
      qApp, [] { DrainPostedTasks(); }, Qt::QueuedConnection);
}

void DrainPostedTasks() {
  for (;;) {
    std::function<void()> Task;
    {
      std::lock_guard<std::mutex> Lock(QueueMutex());
      if (Queue().empty())
        return;
      Task = std::move(Queue().front());
      Queue().pop_front();
    }
    if (Task)
      Task();
  }
}

bool TuiBusy() { return PendingTasks().load() > 0; }

int TuiPendingTaskCount() { return PendingTasks().load(); }

bool WaitForTuiTasks(int TimeoutMs) {
  if (!TuiBusy())
    return true;
  if (TimeoutMs <= 0)
    return false;
  QEventLoop Loop;
  QTimer Poll;
  QTimer Deadline;
  Deadline.setSingleShot(true);
  QObject::connect(&Poll, &QTimer::timeout, &Loop, [&] {
    if (!TuiBusy())
      Loop.quit();
  });
  QObject::connect(&Deadline, &QTimer::timeout, &Loop, &QEventLoop::quit);
  Poll.start(20);
  Deadline.start(TimeoutMs);
  Loop.exec();
  return !TuiBusy();
}

void TuiAsyncBegin() { PendingTasks().fetch_add(1); }

void TuiAsyncEnd() { PendingTasks().fetch_sub(1); }

void TuiAsyncVoid(std::function<void()> Work, std::function<void()> OnDone) {
  TuiAsyncBegin();
  std::thread([Work = std::move(Work), OnDone = std::move(OnDone)] {
    if (Work)
      Work();
    TuiPost([OnDone = std::move(OnDone)] {
      if (OnDone)
        OnDone();
      TuiAsyncEnd();
    });
  }).detach();
}

namespace {

// 与 PostJsonRequestBlocking 同样的做法：本地 QNetworkAccessManager +
// QEventLoop 同步等待。仅在 worker 线程调用。
bool HttpJson(const QString &Path, const QByteArray &Payload,
              const QString &BearerToken, bool Post, int TimeoutMs,
              QJsonObject *Response, QString *Error) {
  const QString Base = AuthServerAddress();
  QNetworkAccessManager Manager;
  QNetworkRequest Request(QUrl(Base + Path));
  Request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
  if (!BearerToken.isEmpty())
    Request.setRawHeader("Authorization", ("Bearer " + BearerToken).toUtf8());
  Request.setTransferTimeout(TimeoutMs);

  QNetworkReply *Reply =
      Post ? Manager.post(Request, Payload) : Manager.get(Request);
  QEventLoop Loop;
  QObject::connect(Reply, &QNetworkReply::finished, &Loop, &QEventLoop::quit);
  Loop.exec();

  const bool Ok = Reply->error() == QNetworkReply::NoError;
  if (Ok) {
    if (Response)
      *Response = QJsonDocument::fromJson(Reply->readAll()).object();
  } else if (Error) {
    *Error = Reply->errorString();
  }
  Reply->deleteLater();
  return Ok;
}

} // namespace

bool HttpPostJson(const QString &Path, const QJsonObject &Body, int TimeoutMs,
                  QJsonObject *Response, QString *Error) {
  return HttpJson(Path, QJsonDocument(Body).toJson(), QString(), true,
                  TimeoutMs, Response, Error);
}

bool HttpGetJson(const QString &Path, const QString &BearerToken,
                 int TimeoutMs, QJsonObject *Response, QString *Error) {
  return HttpJson(Path, QByteArray(), BearerToken, false, TimeoutMs, Response,
                  Error);
}

} // namespace AegisNT::Tui
