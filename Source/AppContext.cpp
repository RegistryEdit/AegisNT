// ============================================================
// 应用上下文的单例实现与事件监听器分发：
// 监听器返回 false 即被移除（一次性监听）。
// ============================================================
#include "AppContext.h"

namespace AegisNT {

AppContext &ApplicationContext() {
  static AppContext Context;
  return Context;
}

void NotifyAccountSessionChanged() {
  auto &Listeners = ApplicationContext().AccountSessionListeners;
  for (auto It = Listeners.begin(); It != Listeners.end();) {
    if ((*It)())
      ++It;
    else
      It = Listeners.erase(It);
  }
}

void NotifyUserTitleChanged(const QString &UserName, const QString &Title) {
  auto &Listeners = ApplicationContext().UserTitleChangedListeners;
  for (auto It = Listeners.begin(); It != Listeners.end();) {
    if ((*It)(UserName, Title))
      ++It;
    else
      It = Listeners.erase(It);
  }
}

} // namespace AegisNT
