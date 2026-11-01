// ============================================================
// 前端间同步实现：代数计数 + 页面水位。
// （unity 包含进 AegisNT.cpp，全局作用域）
// ============================================================

#include "TuiSync.h"

#include "TuiAsync.h"

#include <array>

namespace AegisNT::Tui {

namespace {

constexpr int KMaxTrackedPages = 32;

std::atomic<uint64_t> &Generation() {
  static std::atomic<uint64_t> Value{0};
  return Value;
}

std::array<std::atomic<uint64_t>, KMaxTrackedPages> &Watermarks() {
  static std::array<std::atomic<uint64_t>, KMaxTrackedPages> Values{};
  return Values;
}

std::atomic_bool &SurfaceActive() {
  static std::atomic_bool Value{false};
  return Value;
}

} // namespace

std::atomic<uint64_t> &SyncGeneration() { return Generation(); }

void MarkMutated() {
  Generation().fetch_add(1, std::memory_order_relaxed);
  if (ConsoleSurfaceActive())
    TuiPost([] {});
}

uint64_t LastSeenGeneration(int PageIndex) {
  if (PageIndex < 0 || PageIndex >= KMaxTrackedPages)
    return 0;
  return Watermarks()[static_cast<size_t>(PageIndex)].load(
      std::memory_order_relaxed);
}

void SetLastSeenGeneration(int PageIndex, uint64_t Generation) {
  if (PageIndex < 0 || PageIndex >= KMaxTrackedPages)
    return;
  Watermarks()[static_cast<size_t>(PageIndex)].store(
      Generation, std::memory_order_relaxed);
}

bool ConsoleSurfaceActive() { return SurfaceActive().load(); }

void SetConsoleSurfaceActive(bool Active) { SurfaceActive() = Active; }

} // namespace AegisNT::Tui
