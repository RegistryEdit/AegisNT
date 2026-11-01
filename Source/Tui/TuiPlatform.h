#pragma once
// ============================================================
// TUI 平台头：所有控制台前端源文件的第一包含项。
// ------------------------------------------------------------
// 头文件在全局作用域包含；实现文件在匿名 namespace 关闭后 unity 包含。
// 显式声明标准库依赖，支持独立单测；不要在匿名 namespace 内首次包含。
// ============================================================

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace AegisNT::Tui {

using Clock = std::chrono::steady_clock;
using Ms = std::chrono::milliseconds;

// 当前时间戳（毫秒），页面计时器统一用它做增量判断。
inline int64_t NowMs() {
  return std::chrono::duration_cast<Ms>(Clock::now().time_since_epoch())
      .count();
}

} // namespace AegisNT::Tui
