#pragma once
// ============================================================
// 前端间同步：GUI 与内置控制台共用同一份状态，不镜像数据。
// ------------------------------------------------------------
// 共享：ApplicationContext（账号会话、模块单跑锁、驱动句柄、转录）、
// Data/Config.json、所有后端调用。
// 各自持有：表格缓存、光标、筛选框。
// 变更方递增 SyncGeneration，另一端下一个 tick 发现变化即刷新当前页。
// ============================================================

#include "TuiPlatform.h"

#include <atomic>
#include <cstdint>

namespace AegisNT::Tui {

// 任一前端发生状态变更时自增。
std::atomic<uint64_t> &SyncGeneration();

// 标记一次变更（自增 + 唤醒控制台循环）。任一线程可调用。
void MarkMutated();

// 每个页面的水位；返回该页上次见到的代数。
uint64_t LastSeenGeneration(int PageIndex);
void SetLastSeenGeneration(int PageIndex, uint64_t Generation);

// 是否已有控制台前端在运行（RunConsoleMode 或 GUI 内置 surface）。
bool ConsoleSurfaceActive();
void SetConsoleSurfaceActive(bool Active);

} // namespace AegisNT::Tui
