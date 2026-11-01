#pragma once
// ============================================================
// TUI 异步与线程桥：worker 线程只投递，UI 线程独占页面状态。
// ------------------------------------------------------------
// 与 GUI 页面的模式完全一致：耗时调用在 std::thread 上执行，结果
// 通过投递队列回到 UI 线程。页面绝不在 worker 线程上碰表格/对话框。
// ============================================================

#include "TuiPlatform.h"

#include <atomic>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>

namespace AegisNT::Tui {

// 线程安全：入队后用 Qt queued invoke 唤醒事件循环。
void TuiPost(std::function<void()> Fn);

// 仅 UI 线程：排空投递队列。
void DrainPostedTasks();

// 进行中的异步任务数（状态栏 busy N）。
bool TuiBusy();
int TuiPendingTaskCount();
// Main-thread bounded wait; processes completion callbacks while stdin stays
// with the command. False means the result is still loading after TimeoutMs.
bool WaitForTuiTasks(int TimeoutMs);
void TuiAsyncBegin();
void TuiAsyncEnd();

// 在后台线程执行 Work，完成后在 UI 线程回调 OnDone。
template <class T>
void TuiAsync(std::function<T()> Work, std::function<void(T)> OnDone) {
  auto Result = std::make_shared<T>();
  TuiAsyncBegin();
  std::thread([Work = std::move(Work), OnDone = std::move(OnDone), Result] {
    *Result = Work();
    TuiPost([Result, OnDone = std::move(OnDone)] {
      if (OnDone)
        OnDone(std::move(*Result));
      TuiAsyncEnd();
    });
  }).detach();
}

void TuiAsyncVoid(std::function<void()> Work, std::function<void()> OnDone);

// HTTP：同步阻塞（内部跑 QEventLoop），必须在 worker 线程调用。
bool HttpPostJson(const QString &Path, const QJsonObject &Body, int TimeoutMs,
                  QJsonObject *Response, QString *Error);
bool HttpGetJson(const QString &Path, const QString &BearerToken,
                 int TimeoutMs, QJsonObject *Response, QString *Error);

} // namespace AegisNT::Tui
