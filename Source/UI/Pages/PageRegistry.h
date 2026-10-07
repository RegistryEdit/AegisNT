// ============================================================
// 页面注册表：侧边栏 24 个页面的标题/副标题/图标定义，
// 主窗口据此生成导航项与懒加载容器。
// ============================================================
#pragma once

#include <QFluent/FluentIcon.h>

#include <array>

namespace AegisNT {

struct PageDefinition {
  const char *Title;
  const char *Subtitle;
  Fluent::IconType Icon;
};

const std::array<PageDefinition, 25> &PageDefinitions();

} // namespace AegisNT
